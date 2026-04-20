#![forbid(unsafe_code)]

//! DRDYNVC static virtual channel processor -- MS-RDPEDYC 3.1
//!
//! `DrdynvcClient` implements `SvcProcessor` to handle the DRDYNVC SVC,
//! managing DVC capability negotiation, channel create/close, and data dispatch.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_bulk::zgfx::ZgfxDecompressor;
use justrdp_core::{AsAny, ReadCursor};
use justrdp_svc::{
    ChannelName, CompressionCondition, SvcMessage, SvcProcessor, SvcResult, DRDYNVC,
};

use crate::pdu::{self, DvcPdu, CAPS_VERSION_3, CREATION_STATUS_OK};
use crate::reassembly::DvcReassembler;
use crate::{DvcError, DvcProcessor, DvcResult};

/// Maximum DVC version we support.
const MAX_SUPPORTED_VERSION: u16 = CAPS_VERSION_3;

/// Maximum number of simultaneously open DVC channels.
const MAX_ACTIVE_CHANNELS: usize = 256;

/// HRESULT for failed channel creation (no registered processor).
/// MS-RDPEDYC 2.2.2.2: CreationStatus is HRESULT; E_FAIL (0x80004005) signals
/// no registered listener for the requested channel name.
const CREATION_STATUS_NO_LISTENER: i32 = -2147467259; // 0x80004005 = E_FAIL

/// Client-side DRDYNVC processor.
///
/// Implements `SvcProcessor` for the `drdynvc` static virtual channel.
/// Manages dynamic virtual channel lifecycle: capability negotiation,
/// channel creation/closing, and data routing to registered `DvcProcessor`s.
pub struct DrdynvcClient {
    /// Registered DVC processors, keyed by channel name.
    processors: BTreeMap<String, Box<dyn DvcProcessor>>,
    /// Active channels: channel_id → channel_name.
    active_channels: BTreeMap<u32, String>,
    /// Per-channel reassembly state.
    reassemblers: BTreeMap<u32, DvcReassembler>,
    /// Per-channel ZGFX Lite decompressors for compressed DVC data (v3).
    decompressors: BTreeMap<u32, ZgfxDecompressor>,
    /// Negotiated version (0 = not yet negotiated).
    negotiated_version: u16,
}

impl DrdynvcClient {
    /// Create a new DRDYNVC client processor.
    pub fn new() -> Self {
        Self {
            processors: BTreeMap::new(),
            active_channels: BTreeMap::new(),
            reassemblers: BTreeMap::new(),
            decompressors: BTreeMap::new(),
            negotiated_version: 0,
        }
    }

    /// Register a DVC processor.
    pub fn register(&mut self, processor: Box<dyn DvcProcessor>) {
        let name = String::from(processor.channel_name());
        self.processors.insert(name, processor);
    }

    /// Get the negotiated DVC version (0 if not yet negotiated).
    pub fn negotiated_version(&self) -> u16 {
        self.negotiated_version
    }

    /// Process a parsed DVC PDU and produce response SVC messages.
    fn process_pdu(&mut self, pdu: DvcPdu) -> DvcResult<Vec<SvcMessage>> {
        match pdu {
            DvcPdu::CapabilitiesRequest { version, .. } => {
                // Respond with the min of server version and our max supported.
                let negotiated = version.min(MAX_SUPPORTED_VERSION);
                self.negotiated_version = negotiated;
                let response = pdu::encode_caps_response(negotiated);
                Ok(vec![SvcMessage::new(response)])
            }

            DvcPdu::CreateRequest {
                channel_id,
                channel_name,
                priority: _,
            } => {
                if let Some(proc) = self.processors.get_mut(&channel_name) {
                    // Reject if too many channels are already open.
                    if !self.active_channels.contains_key(&channel_id)
                        && self.active_channels.len() >= MAX_ACTIVE_CHANNELS
                    {
                        return Ok(vec![SvcMessage::new(pdu::encode_create_response(
                            channel_id,
                            CREATION_STATUS_NO_LISTENER,
                        ))]);
                    }

                    // Close prior instance if this channel_id was already open.
                    if self.active_channels.contains_key(&channel_id) {
                        proc.close(channel_id);
                    }

                    // Accept the channel.
                    self.active_channels
                        .insert(channel_id, channel_name.clone());
                    self.reassemblers
                        .insert(channel_id, DvcReassembler::new());
                    // Create a per-channel decompressor for v3 compressed data.
                    if self.negotiated_version >= CAPS_VERSION_3 {
                        self.decompressors
                            .insert(channel_id, ZgfxDecompressor::new_lite());
                    }

                    let start_messages = proc.start(channel_id)?;

                    // Send CreateResponse(OK) first, then any start messages.
                    let mut responses = vec![SvcMessage::new(pdu::encode_create_response(
                        channel_id,
                        CREATION_STATUS_OK,
                    ))];

                    for msg in start_messages {
                        responses.push(SvcMessage::new(pdu::encode_data(channel_id, &msg.data)));
                    }

                    Ok(responses)
                } else {
                    // No listener — reject.
                    Ok(vec![SvcMessage::new(pdu::encode_create_response(
                        channel_id,
                        CREATION_STATUS_NO_LISTENER,
                    ))])
                }
            }

            DvcPdu::DataFirst {
                channel_id,
                total_length,
                data,
            } => self.handle_data_fragment(channel_id, Some(total_length), &data),

            DvcPdu::Data { channel_id, data } => {
                self.handle_data_fragment(channel_id, None, &data)
            }

            DvcPdu::DataFirstCompressed {
                channel_id,
                total_length,
                data,
            } => {
                let decompressed = self.decompress_chunk(channel_id, &data)?;
                self.handle_data_fragment(channel_id, Some(total_length), &decompressed)
            }

            DvcPdu::DataCompressed { channel_id, data } => {
                let decompressed = self.decompress_chunk(channel_id, &data)?;
                self.handle_data_fragment(channel_id, None, &decompressed)
            }

            DvcPdu::Close { channel_id } => {
                // Only echo close for channels we actually have open.
                if let Some(name) = self.active_channels.remove(&channel_id) {
                    if let Some(proc) = self.processors.get_mut(&name) {
                        proc.close(channel_id);
                    }
                    self.reassemblers.remove(&channel_id);
                    self.decompressors.remove(&channel_id);
                    Ok(vec![SvcMessage::new(pdu::encode_close(channel_id))])
                } else {
                    // Unknown channel — ignore per MS-RDPEDYC 3.1.5.1.4.
                    Ok(vec![])
                }
            }
            DvcPdu::SoftSyncRequest { .. } => {
                // The PDU is decoded so the client doesn't drop the connection,
                // but multitransport-aware routing isn't wired up yet — without
                // a Soft-Sync Response, MS-RDPEDYC §3.2.5.3.1 mandates that all
                // DVC data continues over the DRDYNVC SVC, which is exactly the
                // current behavior. Routing migration lands with §10.3 Commit E.
                Ok(vec![])
            }
            DvcPdu::SoftSyncResponse { .. } => {
                // Server-bound PDU; receiving it on the client side is a
                // protocol violation.
                Err(DvcError::Protocol(String::from(
                    "unexpected DYNVC_SOFT_SYNC_RESPONSE on client",
                )))
            }
        }
    }

    /// Feed a data fragment into reassembly and dispatch if complete.
    fn handle_data_fragment(
        &mut self,
        channel_id: u32,
        total_length: Option<u32>,
        data: &[u8],
    ) -> DvcResult<Vec<SvcMessage>> {
        let reassembler = match self.reassemblers.get_mut(&channel_id) {
            Some(r) => r,
            None => return Ok(vec![]),
        };
        let complete = match total_length {
            Some(len) => reassembler.data_first(len, data)?,
            None => reassembler.data(data)?,
        };
        if let Some(payload) = complete {
            self.dispatch_data(channel_id, &payload)
        } else {
            Ok(vec![])
        }
    }

    /// Decompress a compressed DVC data chunk using the per-channel ZGFX Lite decompressor.
    fn decompress_chunk(&mut self, channel_id: u32, data: &[u8]) -> DvcResult<Vec<u8>> {
        let decompressor = self.decompressors.get_mut(&channel_id).ok_or_else(|| {
            DvcError::Protocol(String::from("compressed data on channel without decompressor"))
        })?;
        let mut output = Vec::new();
        decompressor
            .decompress(data, &mut output)
            .map_err(|e| DvcError::Protocol(alloc::format!("DVC decompression failed: {e:?}")))?;
        Ok(output)
    }

    /// Dispatch complete data to the registered processor.
    fn dispatch_data(&mut self, channel_id: u32, payload: &[u8]) -> DvcResult<Vec<SvcMessage>> {
        let name = match self.active_channels.get(&channel_id) {
            Some(n) => n.clone(),
            None => return Ok(vec![]),
        };
        let proc = match self.processors.get_mut(&name) {
            Some(p) => p,
            None => return Ok(vec![]),
        };

        let responses = proc.process(channel_id, payload)?;
        let mut messages = Vec::new();
        for msg in responses {
            messages.push(SvcMessage::new(pdu::encode_data(channel_id, &msg.data)));
        }
        Ok(messages)
    }

    /// Send data on an open DVC channel from the application side.
    ///
    /// Use this when a `DvcProcessor` produces a message outside of the normal
    /// server-initiated flow (e.g., `DisplayControlClient::take_pending_message()`).
    /// Returns an `SvcMessage` ready to be sent on the `drdynvc` static channel.
    ///
    /// Returns `Err` if `channel_id` is not currently open.
    pub fn send_on_channel(&mut self, channel_id: u32, data: &[u8]) -> DvcResult<SvcMessage> {
        if !self.active_channels.contains_key(&channel_id) {
            return Err(DvcError::Protocol(String::from(
                "send_on_channel: channel not open",
            )));
        }
        Ok(SvcMessage::new(pdu::encode_data(channel_id, data)))
    }

    /// Look up the channel ID for a registered processor by name.
    ///
    /// Returns `None` if no channel with that name is currently open.
    pub fn channel_id_by_name(&self, name: &str) -> Option<u32> {
        self.active_channels
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .map(|(&id, _)| id)
    }
}

impl Default for DrdynvcClient {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for DrdynvcClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DrdynvcClient")
            .field("negotiated_version", &self.negotiated_version)
            .field("active_channels", &self.active_channels.len())
            .field("processors", &self.processors.len())
            .finish()
    }
}

impl AsAny for DrdynvcClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl SvcProcessor for DrdynvcClient {
    fn channel_name(&self) -> ChannelName {
        DRDYNVC
    }

    fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
        // The DRDYNVC channel waits for the server's DYNVC_CAPS.
        // No initial messages to send.
        Ok(vec![])
    }

    fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
        let mut src = ReadCursor::new(payload);
        let mut all_responses = Vec::new();

        // MS-RDPEDYC allows multiple DVC PDUs in a single SVC payload.
        while src.remaining() > 0 {
            let pdu = pdu::decode_dvc_pdu(&mut src)
                .map_err(justrdp_svc::SvcError::Decode)?;
            let responses = self.process_pdu(pdu)
                .map_err(|e| match e {
                    DvcError::Decode(d) => justrdp_svc::SvcError::Decode(d),
                    DvcError::Encode(e) => justrdp_svc::SvcError::Encode(e),
                    DvcError::Protocol(s) => justrdp_svc::SvcError::Protocol(s),
                })?;
            all_responses.extend(responses);
        }

        Ok(all_responses)
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::Never
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DvcMessage;

    /// A simple echo DVC processor for testing.
    #[derive(Debug)]
    struct EchoDvcProcessor;

    impl AsAny for EchoDvcProcessor {
        fn as_any(&self) -> &dyn core::any::Any { self }
        fn as_any_mut(&mut self) -> &mut dyn core::any::Any { self }
    }

    impl DvcProcessor for EchoDvcProcessor {
        fn channel_name(&self) -> &str { "testdvc" }

        fn start(&mut self, _channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
            Ok(vec![])
        }

        fn process(&mut self, _channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
            Ok(vec![DvcMessage::new(payload.to_vec())])
        }

        fn close(&mut self, _channel_id: u32) {}
    }

    #[test]
    fn caps_negotiation_v1() {
        let mut client = DrdynvcClient::new();
        let caps = [0x50, 0x00, 0x01, 0x00]; // CAPS_VERSION_1
        let responses = client.process(&caps).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(&responses[0].data, &[0x50, 0x00, 0x01, 0x00]); // echo v1
        assert_eq!(client.negotiated_version(), 1);
    }

    #[test]
    fn caps_negotiation_v3_clamped() {
        let mut client = DrdynvcClient::new();
        // Server sends v3 with priority charges.
        let caps: [u8; 12] = [
            0x50, 0x00, 0x03, 0x00,
            0xA8, 0x03, 0xCC, 0x0C,
            0xA2, 0x24, 0x55, 0x55,
        ];
        let responses = client.process(&caps).unwrap();
        assert_eq!(client.negotiated_version(), 3);
        // Response is 4 bytes with version=3.
        assert_eq!(&responses[0].data, &[0x50, 0x00, 0x03, 0x00]);
    }

    #[test]
    fn create_request_accepted() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));
        // Negotiate first.
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();

        // CreateRequest: channel_id=3, name="testdvc"
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        let responses = client.process(&create_req).unwrap();
        assert_eq!(responses.len(), 1);
        // CreateResponse with status=0 (OK).
        assert_eq!(&responses[0].data, &[0x10, 0x03, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn create_request_rejected_no_listener() {
        let mut client = DrdynvcClient::new();
        // No processor registered for "unknown".
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();

        let create_req = [0x10, 0x03, 0x75, 0x6E, 0x6B, 0x00]; // "unk\0"
        let responses = client.process(&create_req).unwrap();
        assert_eq!(responses.len(), 1);
        // CreationStatus should be negative (E_FAIL).
        let status_bytes = &responses[0].data[2..6];
        let status = i32::from_le_bytes(status_bytes.try_into().unwrap());
        assert!(status < 0);
    }

    #[test]
    fn data_single_echo() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        // Create channel 3.
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();

        // Send Data on channel 3: "hello"
        let data_pdu = [0x30, 0x03, b'h', b'e', b'l', b'l', b'o'];
        let responses = client.process(&data_pdu).unwrap();
        assert_eq!(responses.len(), 1);
        // Echo processor returns "hello" wrapped as Data PDU.
        let mut src = ReadCursor::new(&responses[0].data);
        let pdu = pdu::decode_dvc_pdu(&mut src).unwrap();
        match pdu {
            DvcPdu::Data { channel_id, data } => {
                assert_eq!(channel_id, 3);
                assert_eq!(data, b"hello");
            }
            _ => panic!("expected Data PDU"),
        }
    }

    #[test]
    fn data_first_reassembly() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();

        // DataFirst: channel=3, total_length=6, data="AAA"
        let data_first = pdu::encode_data_first(3, 6, b"AAA");
        let responses = client.process(&data_first).unwrap();
        assert!(responses.is_empty()); // not complete yet

        // Data: channel=3, data="BBB"
        let data = pdu::encode_data(3, b"BBB");
        let responses = client.process(&data).unwrap();
        assert_eq!(responses.len(), 1); // echo of "AAABBB"
    }

    #[test]
    fn close_echoed() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();

        // Close channel 3.
        let close = [0x40, 0x03];
        let responses = client.process(&close).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(&responses[0].data, &[0x40, 0x03]); // echo close
    }

    #[test]
    fn close_unknown_channel_no_response() {
        let mut client = DrdynvcClient::new();
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        // Close channel 99 which was never created — should be ignored.
        let close = pdu::encode_close(99);
        let responses = client.process(&close).unwrap();
        assert!(responses.is_empty());
    }

    #[test]
    fn duplicate_create_request_resets_reassembler() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();

        // First CreateRequest for channel 3.
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();

        // Start a DataFirst that won't complete.
        let data_first = pdu::encode_data_first(3, 100, b"partial");
        client.process(&data_first).unwrap();

        // Duplicate CreateRequest for channel 3 — should reset state.
        let responses = client.process(&create_req).unwrap();
        assert_eq!(responses.len(), 1); // new CreateResponse(OK)

        // New data on the channel should work independently (no leftover from prior assembly).
        let data = pdu::encode_data(3, b"fresh");
        let responses = client.process(&data).unwrap();
        assert_eq!(responses.len(), 1);
        // Echo processor echoes "fresh".
        let mut src = ReadCursor::new(&responses[0].data);
        let pdu = pdu::decode_dvc_pdu(&mut src).unwrap();
        match pdu {
            DvcPdu::Data { data, .. } => assert_eq!(data, b"fresh"),
            _ => panic!("expected Data"),
        }
    }

    #[test]
    fn send_on_channel_open_channel() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));

        // Negotiate caps
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        // CreateRequest: channel_id=3, name="testdvc"
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();

        // Send data proactively
        let msg = client.send_on_channel(3, b"hello").unwrap();
        let mut src = ReadCursor::new(&msg.data);
        let decoded = pdu::decode_dvc_pdu(&mut src).unwrap();
        match decoded {
            DvcPdu::Data { channel_id, data } => {
                assert_eq!(channel_id, 3);
                assert_eq!(data, b"hello");
            }
            _ => panic!("expected Data"),
        }
    }

    #[test]
    fn send_on_channel_closed_channel_returns_error() {
        let mut client = DrdynvcClient::new();
        assert!(client.send_on_channel(99, b"data").is_err());
    }

    #[test]
    fn channel_id_by_name_lookup() {
        let mut client = DrdynvcClient::new();
        client.register(Box::new(EchoDvcProcessor));

        // Not open yet
        assert_eq!(client.channel_id_by_name("testdvc"), None);

        // Negotiate + open channel
        client.process(&[0x50, 0x00, 0x01, 0x00]).unwrap();
        let create_req = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        client.process(&create_req).unwrap();

        assert_eq!(client.channel_id_by_name("testdvc"), Some(3));
        assert_eq!(client.channel_id_by_name("nonexistent"), None);
    }

    #[test]
    fn soft_sync_request_no_op_response() {
        // Soft-Sync routing isn't wired up yet; the client must accept the
        // PDU and stay silent (per §3.2.5.3.1, no Response = stay on SVC).
        let mut client = DrdynvcClient::new();
        let req = pdu::encode_soft_sync_request(
            pdu::SOFT_SYNC_TCP_FLUSHED | pdu::SOFT_SYNC_CHANNEL_LIST_PRESENT,
            &[pdu::SoftSyncChannelList {
                tunnel_type: pdu::TUNNELTYPE_UDPFECR,
                dvc_ids: vec![3],
            }],
        );
        let responses = client.process(&req).expect("Soft-Sync Request must decode");
        assert!(responses.is_empty(), "no Response is sent yet (Commit E will wire routing)");
    }

    #[test]
    fn soft_sync_response_from_server_rejected() {
        // Server-bound PDU received by the client → protocol error.
        let mut client = DrdynvcClient::new();
        let resp = pdu::encode_soft_sync_response(&[pdu::TUNNELTYPE_UDPFECR]);
        let err = client.process(&resp).expect_err("must reject client-only PDU");
        match err {
            justrdp_svc::SvcError::Protocol(_) => {}
            other => panic!("expected SvcError::Protocol, got {other:?}"),
        }
    }
}
