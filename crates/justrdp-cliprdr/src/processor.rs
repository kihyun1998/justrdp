#![forbid(unsafe_code)]

//! Clipboard channel processor -- SVC integration.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_svc::{
    ChannelName, CompressionCondition, SvcClientProcessor, SvcMessage, SvcProcessor, SvcResult,
    CLIPRDR,
};

use crate::backend::{CliprdrBackend, FormatDataResponse, FormatListResponse};
use crate::pdu::{
    ClipboardCapsPdu, ClipboardHeader, ClipboardMsgType,
    FileContentsRequestPdu, FileContentsResponsePdu, FormatDataRequestPdu,
    FormatDataResponsePdu, FormatListPdu, FormatListResponsePdu, GeneralCapabilityFlags,
    GeneralCapabilitySet, LockClipDataPdu, LongFormatName, ShortFormatName, TempDirectoryPdu,
    UnlockClipDataPdu, CB_CAPS_VERSION_2,
};

/// Client-side clipboard channel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliprdrState {
    /// Waiting for server capabilities.
    WaitingForServerCaps,
    /// Received server caps, waiting for monitor ready.
    WaitingForMonitorReady,
    /// Initialization complete, ready for data exchange.
    Initialized,
}

/// Client-side clipboard channel processor.
///
/// Implements [`SvcProcessor`] to handle the CLIPRDR virtual channel.
pub struct CliprdrClient {
    state: CliprdrState,
    backend: Box<dyn CliprdrBackend>,
    /// Our capability flags to advertise.
    local_flags: GeneralCapabilityFlags,
    /// Negotiated capability flags (intersection of local and remote).
    negotiated_flags: GeneralCapabilityFlags,
    /// Optional temporary directory path.
    temp_dir: Option<String>,
    /// Format ID of the most recent outgoing FormatDataRequest, used to
    /// correlate the response with the requested format for dispatch.
    pending_format_data_request: Option<u32>,
}

impl AsAny for CliprdrClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl core::fmt::Debug for CliprdrClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CliprdrClient")
            .field("state", &self.state)
            .field("local_flags", &self.local_flags)
            .field("negotiated_flags", &self.negotiated_flags)
            .finish()
    }
}

impl CliprdrClient {
    /// Create a new clipboard client processor.
    pub fn new(backend: Box<dyn CliprdrBackend>) -> Self {
        Self {
            state: CliprdrState::WaitingForServerCaps,
            backend,
            local_flags: GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
                .union(GeneralCapabilityFlags::STREAM_FILECLIP_ENABLED)
                .union(GeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS)
                .union(GeneralCapabilityFlags::CAN_LOCK_CLIPDATA)
                .union(GeneralCapabilityFlags::HUGE_FILE_SUPPORT_ENABLED),
            negotiated_flags: GeneralCapabilityFlags::NONE,
            temp_dir: None,
            pending_format_data_request: None,
        }
    }

    /// Set the temporary directory path.
    pub fn with_temp_dir(mut self, path: String) -> Self {
        self.temp_dir = Some(path);
        self
    }

    /// Set the local capability flags.
    pub fn with_flags(mut self, flags: GeneralCapabilityFlags) -> Self {
        self.local_flags = flags;
        self
    }

    /// Whether long format names are negotiated.
    pub fn use_long_format_names(&self) -> bool {
        self.negotiated_flags
            .contains(GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES)
    }

    /// Encode a PDU into an SvcMessage.
    fn encode_pdu<T: Encode>(pdu: &T) -> SvcResult<SvcMessage> {
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor)?;
        Ok(SvcMessage::new(buf))
    }

    /// Build the client's initial messages (caps + optional temp dir + empty format list).
    ///
    /// Per MS-RDPECLIP 1.3.2.1, the client MUST send a Format List PDU as part
    /// of the initialization sequence after capabilities and optional temp dir.
    fn build_init_response(&self) -> SvcResult<Vec<SvcMessage>> {
        let mut messages = Vec::new();

        // Send our capabilities.
        let caps = ClipboardCapsPdu::new(GeneralCapabilitySet::new(
            CB_CAPS_VERSION_2,
            self.local_flags,
        ));
        messages.push(Self::encode_pdu(&caps)?);

        // Send temporary directory if set.
        if let Some(ref path) = self.temp_dir {
            let temp = TempDirectoryPdu::new(path.clone());
            messages.push(Self::encode_pdu(&temp)?);
        }

        // Send an empty format list to complete initialization.
        // MS-RDPECLIP 1.3.2.1: client MUST send Format List after caps.
        let format_list = self.build_format_list_message(&[])?;
        messages.push(format_list);

        Ok(messages)
    }

    /// Handle a received clipboard PDU.
    fn handle_pdu(
        &mut self,
        header: &ClipboardHeader,
        body: &mut ReadCursor<'_>,
    ) -> SvcResult<Vec<SvcMessage>> {
        // Reject data-exchange PDUs before the handshake is complete.
        if self.state != CliprdrState::Initialized {
            match header.msg_type {
                ClipboardMsgType::ClipCaps | ClipboardMsgType::MonitorReady => {}
                _ => return Ok(Vec::new()),
            }
        }

        match header.msg_type {
            ClipboardMsgType::ClipCaps => {
                let caps = ClipboardCapsPdu::decode(body)?;
                let remote_flags = caps.general.general_flags;
                // Negotiate: intersection of local and remote flags.
                self.negotiated_flags = GeneralCapabilityFlags::from_bits(
                    self.local_flags.bits() & remote_flags.bits(),
                );

                if self.state == CliprdrState::WaitingForServerCaps {
                    self.state = CliprdrState::WaitingForMonitorReady;
                }
                Ok(Vec::new())
            }

            ClipboardMsgType::MonitorReady => {
                if self.state == CliprdrState::WaitingForMonitorReady {
                    self.state = CliprdrState::Initialized;
                    // Send our caps, optional temp dir, and an empty format list
                    // to complete the initialization sequence per MS-RDPECLIP 1.3.2.1.
                    self.build_init_response()
                } else {
                    // Ignore duplicate MonitorReady to prevent capability re-negotiation.
                    Ok(Vec::new())
                }
            }

            ClipboardMsgType::FormatList => {
                let pdu = FormatListPdu::decode_body(
                    body,
                    self.use_long_format_names(),
                    header.msg_flags,
                    header.data_len,
                )?;

                // Convert to uniform LongFormatName representation for the backend.
                let formats = match &pdu {
                    FormatListPdu::Long(entries) => entries.clone(),
                    FormatListPdu::Short { entries, .. } => entries
                        .iter()
                        .map(|e| LongFormatName::new(e.format_id, String::new()))
                        .collect(),
                };

                // Backend errors are degraded to Fail — the client must always
                // respond to a format list even if the backend is broken.
                // This is intentionally different from on_file_contents_request,
                // which propagates errors to produce a typed failure PDU.
                let response = self
                    .backend
                    .on_format_list(&formats)
                    .unwrap_or(FormatListResponse::Fail);

                let resp_pdu = match response {
                    FormatListResponse::Ok => FormatListResponsePdu::ok(),
                    FormatListResponse::Fail => FormatListResponsePdu::fail(),
                };
                Ok(alloc::vec![Self::encode_pdu(&resp_pdu)?])
            }

            ClipboardMsgType::FormatListResponse => {
                // MS-RDPECLIP 1.3.2.1: check if the server accepted our format list.
                let resp = FormatListResponsePdu::decode_from_flags(header.msg_flags);
                if !resp.accepted {
                    // Server rejected our format list. Per spec, subsequent data
                    // requests for this format list may fail. Log and continue —
                    // there is no recovery action for the client.
                }
                Ok(Vec::new())
            }

            ClipboardMsgType::FormatDataRequest => {
                let request = FormatDataRequestPdu::decode_body(body)?;
                // Backend errors are degraded to Fail (see on_format_list comment).
                let response = self
                    .backend
                    .on_format_data_request(request.requested_format_id)
                    .unwrap_or(FormatDataResponse::Fail);

                let resp_pdu = match response {
                    FormatDataResponse::Ok(data) => FormatDataResponsePdu::Ok(data),
                    FormatDataResponse::Fail => FormatDataResponsePdu::Fail,
                };
                Ok(alloc::vec![Self::encode_pdu(&resp_pdu)?])
            }

            ClipboardMsgType::FormatDataResponse => {
                let resp = FormatDataResponsePdu::decode_body(
                    body,
                    header.msg_flags,
                    header.data_len,
                )?;
                let (data, is_success) = match &resp {
                    FormatDataResponsePdu::Ok(d) => (d.as_slice(), true),
                    FormatDataResponsePdu::Fail => (&[][..], false),
                };
                let format_id = self.pending_format_data_request.take();
                self.backend.on_format_data_response(data, is_success, format_id);
                Ok(Vec::new())
            }

            ClipboardMsgType::FileContentsRequest => {
                let request = FileContentsRequestPdu::decode_body(body, header.data_len)?;
                let response = self.backend.on_file_contents_request(&request);

                let resp_pdu = match response {
                    Ok(resp) => resp,
                    Err(_) => FileContentsResponsePdu::fail(request.stream_id),
                };
                Ok(alloc::vec![Self::encode_pdu(&resp_pdu)?])
            }

            ClipboardMsgType::FileContentsResponse => {
                let response = FileContentsResponsePdu::decode_body(
                    body,
                    header.msg_flags,
                    header.data_len,
                )?;
                self.backend.on_file_contents_response(&response);
                Ok(Vec::new())
            }

            ClipboardMsgType::LockClipData => {
                let lock = LockClipDataPdu::decode_body(body)?;
                self.backend.on_lock(lock.clip_data_id);
                Ok(Vec::new())
            }

            ClipboardMsgType::UnlockClipData => {
                let unlock = UnlockClipDataPdu::decode_body(body)?;
                self.backend.on_unlock(unlock.clip_data_id);
                Ok(Vec::new())
            }

            ClipboardMsgType::TempDirectory => {
                // Server should not send this; ignore.
                Ok(Vec::new())
            }
        }
    }
}

impl SvcProcessor for CliprdrClient {
    fn channel_name(&self) -> ChannelName {
        CLIPRDR
    }

    fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
        // Client waits for server to send capabilities first.
        Ok(Vec::new())
    }

    fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
        let mut cursor = ReadCursor::new(payload);
        let header = ClipboardHeader::decode(&mut cursor)?;
        self.handle_pdu(&header, &mut cursor)
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }
}

impl SvcClientProcessor for CliprdrClient {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use justrdp_core::{Encode, WriteCursor};
    use crate::pdu::{
        ClipboardCapsPdu, ClipboardHeader, ClipboardMsgFlags, ClipboardMsgType,
        GeneralCapabilityFlags, GeneralCapabilitySet, CB_CAPS_VERSION_2,
    };

    /// A minimal backend that records calls for test assertions.
    struct MockBackend {
        format_list_called: bool,
        format_data_request_id: Option<u32>,
        format_data_response_data: Option<Vec<u8>>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                format_list_called: false,
                format_data_request_id: None,
                format_data_response_data: None,
            }
        }
    }

    impl crate::CliprdrBackend for MockBackend {
        fn on_format_list(&mut self, _formats: &[LongFormatName]) -> crate::ClipboardResult<crate::FormatListResponse> {
            self.format_list_called = true;
            Ok(crate::FormatListResponse::Ok)
        }

        fn on_format_data_request(&mut self, format_id: u32) -> crate::ClipboardResult<crate::FormatDataResponse> {
            self.format_data_request_id = Some(format_id);
            Ok(crate::FormatDataResponse::Ok(vec![0x42]))
        }

        fn on_format_data_response(&mut self, data: &[u8], _is_success: bool, _format_id: Option<u32>) {
            self.format_data_response_data = Some(data.to_vec());
        }

        // on_file_contents_request, on_file_contents_response, on_lock, on_unlock
        // use default trait implementations.
    }

    /// Encode a PDU to bytes.
    fn encode_pdu(pdu: &impl Encode) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        buf
    }

    /// Build server Caps PDU bytes with given flags.
    fn server_caps_bytes(flags: GeneralCapabilityFlags) -> Vec<u8> {
        let caps = ClipboardCapsPdu::new(GeneralCapabilitySet::new(CB_CAPS_VERSION_2, flags));
        encode_pdu(&caps)
    }

    /// Build Monitor Ready PDU bytes.
    fn monitor_ready_bytes() -> Vec<u8> {
        let header = ClipboardHeader::new(
            ClipboardMsgType::MonitorReady,
            ClipboardMsgFlags::NONE,
            0,
        );
        encode_pdu(&header)
    }

    /// Build Format List Response PDU bytes with given flags.
    fn format_list_response_bytes(flags: ClipboardMsgFlags) -> Vec<u8> {
        let header = ClipboardHeader::new(
            ClipboardMsgType::FormatListResponse,
            flags,
            0,
        );
        encode_pdu(&header)
    }

    fn new_client() -> CliprdrClient {
        CliprdrClient::new(Box::new(MockBackend::new()))
    }

    /// Complete the handshake: send server Caps → MonitorReady.
    /// Returns the init response messages from MonitorReady.
    fn complete_handshake(client: &mut CliprdrClient) -> Vec<SvcMessage> {
        let caps = server_caps_bytes(GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES);
        client.process(&caps).unwrap();
        let ready = monitor_ready_bytes();
        client.process(&ready).unwrap()
    }

    #[test]
    fn initialization_sequence() {
        let mut client = new_client();

        // 1. Server sends Caps
        let caps = server_caps_bytes(
            GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
                .union(GeneralCapabilityFlags::STREAM_FILECLIP_ENABLED),
        );
        let msgs = client.process(&caps).unwrap();
        assert!(msgs.is_empty(), "no response to server caps");

        // 2. Server sends Monitor Ready → client responds with caps + format list
        let ready = monitor_ready_bytes();
        let msgs = client.process(&ready).unwrap();
        // Client should send: Caps PDU + empty Format List PDU (at minimum 2 messages)
        assert!(msgs.len() >= 2, "expected at least 2 init messages, got {}", msgs.len());
    }

    #[test]
    fn capability_flag_negotiation() {
        let mut client = new_client();

        // Server offers only USE_LONG_FORMAT_NAMES
        let caps = server_caps_bytes(GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES);
        client.process(&caps).unwrap();

        // Negotiated = local AND remote
        assert!(client.use_long_format_names());

        // Client local_flags includes STREAM_FILECLIP_ENABLED, but server doesn't
        assert!(!client.negotiated_flags.contains(GeneralCapabilityFlags::STREAM_FILECLIP_ENABLED));
    }

    #[test]
    fn data_exchange_rejected_before_initialization() {
        let mut client = new_client();

        // Send a FormatDataRequest before handshake — should be silently dropped
        let header = ClipboardHeader::new(
            ClipboardMsgType::FormatDataRequest,
            ClipboardMsgFlags::NONE,
            4,
        );
        let mut buf = encode_pdu(&header);
        buf.extend_from_slice(&0x0001u32.to_le_bytes()); // requested format ID

        let msgs = client.process(&buf).unwrap();
        assert!(msgs.is_empty(), "data exchange before init should be dropped");
    }

    #[test]
    fn duplicate_monitor_ready_ignored() {
        let mut client = new_client();

        // Complete handshake
        let init_msgs = complete_handshake(&mut client);
        assert!(!init_msgs.is_empty());

        // Duplicate MonitorReady → should be ignored
        let ready = monitor_ready_bytes();
        let msgs = client.process(&ready).unwrap();
        assert!(msgs.is_empty(), "duplicate MonitorReady should be ignored");
    }

    #[test]
    fn format_list_response_ok_accepted() {
        let mut client = new_client();
        complete_handshake(&mut client);

        let resp = format_list_response_bytes(ClipboardMsgFlags::CB_RESPONSE_OK);
        let msgs = client.process(&resp).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn format_list_response_fail_handled() {
        let mut client = new_client();
        complete_handshake(&mut client);

        // Server rejects our format list — should not panic or error
        let resp = format_list_response_bytes(ClipboardMsgFlags::CB_RESPONSE_FAIL);
        let msgs = client.process(&resp).unwrap();
        assert!(msgs.is_empty());
    }
}

// Public API for sending clipboard data proactively.
impl CliprdrClient {
    /// Build a format list message to send to the server.
    ///
    /// Call this when the local clipboard content changes.
    /// Respects the negotiated format name length variant.
    pub fn build_format_list(&self, formats: &[LongFormatName]) -> SvcResult<SvcMessage> {
        self.build_format_list_message(formats)
    }

    /// Internal: build a format list SvcMessage respecting negotiated flags.
    ///
    /// MS-RDPECLIP 2.2.3.1: If CB_USE_LONG_FORMAT_NAMES is set by both sides,
    /// use Long Format Name variant; otherwise use Short Format Name variant.
    fn build_format_list_message(&self, formats: &[LongFormatName]) -> SvcResult<SvcMessage> {
        let pdu = if self.use_long_format_names() {
            FormatListPdu::Long(formats.to_vec())
        } else {
            let entries = formats
                .iter()
                .map(|f| ShortFormatName::new(f.format_id))
                .collect();
            FormatListPdu::Short {
                ascii_names: false,
                entries,
            }
        };
        Self::encode_pdu_with_header(&pdu)
    }

    /// Build a format data request message.
    ///
    /// Stores the format_id so the response can be correlated with the request.
    pub fn build_format_data_request(&mut self, format_id: u32) -> SvcResult<SvcMessage> {
        self.pending_format_data_request = Some(format_id);
        let pdu = FormatDataRequestPdu::new(format_id);
        Self::encode_pdu(&pdu)
    }

    /// Build a lock clipboard data message.
    pub fn build_lock(&self, clip_data_id: u32) -> SvcResult<SvcMessage> {
        let pdu = LockClipDataPdu::new(clip_data_id);
        Self::encode_pdu(&pdu)
    }

    /// Build an unlock clipboard data message.
    pub fn build_unlock(&self, clip_data_id: u32) -> SvcResult<SvcMessage> {
        let pdu = UnlockClipDataPdu::new(clip_data_id);
        Self::encode_pdu(&pdu)
    }

    /// Build a file contents request (SIZE) message.
    pub fn build_file_size_request(
        &self,
        stream_id: u32,
        lindex: i32,
    ) -> SvcResult<SvcMessage> {
        let pdu = FileContentsRequestPdu::size_request(stream_id, lindex);
        Self::encode_pdu(&pdu)
    }

    /// Build a file contents request (RANGE) message.
    pub fn build_file_range_request(
        &self,
        stream_id: u32,
        lindex: i32,
        offset: u64,
        bytes_requested: u32,
    ) -> SvcResult<SvcMessage> {
        let pdu = FileContentsRequestPdu::range_request(stream_id, lindex, offset, bytes_requested);
        Self::encode_pdu(&pdu)
    }

    /// Encode a format list PDU with its header.
    fn encode_pdu_with_header(pdu: &FormatListPdu) -> SvcResult<SvcMessage> {
        let mut buf = alloc::vec![0u8; pdu.full_size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode_full(&mut cursor)?;
        Ok(SvcMessage::new(buf))
    }
}
