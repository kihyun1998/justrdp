#![forbid(unsafe_code)]

//! Server-side host for the DRDYNVC SVC -- mirror of [`DrdynvcClient`]
//! from the server's perspective.
//!
//! The server side of MS-RDPEDYC drives capability negotiation and
//! initiates DVC creation. Once a channel is open, data flows in both
//! directions; this struct surfaces that traffic to a per-channel
//! processor or returns it raw to the caller.
//!
//! # Lifecycle
//!
//! 1. Server enters Phase 11 with a list of channels it wants to open.
//! 2. Caller invokes [`DrdynvcServer::initialize_capabilities`] and
//!    sends the returned bytes on the DRDYNVC SVC.
//! 3. Client responds with a Capabilities Response; caller invokes
//!    [`DrdynvcServer::process_caps_response`] to record the
//!    negotiated version.
//! 4. For each channel the server wants to open, caller calls
//!    [`DrdynvcServer::open_channel`] and sends the bytes.
//! 5. Client responds with a Create Response per channel; caller
//!    invokes [`DrdynvcServer::process_create_response`] which marks
//!    the channel as open or removes it on negative status.
//! 6. Inbound data PDUs go through [`DrdynvcServer::process_inbound`]
//!    which reassembles fragments and returns complete payloads.
//! 7. Outbound data goes through [`DrdynvcServer::send_data`].

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::ReadCursor;

use crate::pdu::{
    decode_caps_response, decode_dvc_pdu, encode_caps_request, encode_close,
    encode_create_request, encode_data, encode_data_compressed, encode_data_first,
    encode_data_first_compressed, DvcPdu, CAPS_VERSION_3, CREATION_STATUS_OK,
};
use justrdp_bulk::zgfx::{ZgfxCompressor, ZgfxError};
use crate::reassembly::DvcReassembler;
use crate::{DvcError, DvcResult};

/// State of a server-initiated dynamic virtual channel.
#[derive(Debug)]
struct ChannelState {
    name: String,
    /// Has the client confirmed channel creation with success status?
    open: bool,
    reassembler: DvcReassembler,
}

/// Server-side DRDYNVC host.
///
/// Tracks per-channel reassembly state and the negotiated DVC version.
/// Does not perform I/O -- callers wrap the produced bytes in their
/// own SVC framing and ship them to the wire.
#[derive(Debug)]
pub struct DrdynvcServer {
    /// Highest DVC version this server supports. Sent in the
    /// CapabilitiesRequest. Default is `CAPS_VERSION_3` (the latest
    /// version this codebase implements end-to-end).
    advertised_version: u16,
    /// Negotiated version after the client's Capabilities Response.
    /// `0` until negotiation completes.
    negotiated_version: u16,
    /// Per-channel state, keyed by channel ID.
    channels: BTreeMap<u32, ChannelState>,
    /// Highest channel ID ever seen in `open_channel`. Used to enforce
    /// the monotonicity invariant from MS-RDPEDYC §3.1.1 ("channel IDs
    /// MUST be monotonically increasing"). A caller that reuses or
    /// reverses IDs is almost certainly buggy and can cause routing
    /// desync against peers that cache the previous binding.
    last_channel_id: u32,
}

impl DrdynvcServer {
    /// Create a server with the default advertised version (v3).
    pub fn new() -> Self {
        Self::with_version(CAPS_VERSION_3)
    }

    /// Create a server that will advertise a specific DVC version. Use
    /// this to force-pin v1 / v2 for compatibility testing.
    pub fn with_version(version: u16) -> Self {
        Self {
            advertised_version: version,
            negotiated_version: 0,
            channels: BTreeMap::new(),
            last_channel_id: 0,
        }
    }

    /// Returns the version negotiated with the client, or `0` if the
    /// Capabilities Response has not been processed yet.
    pub fn negotiated_version(&self) -> u16 {
        self.negotiated_version
    }

    /// Returns whether channel `channel_id` is open and ready for data.
    pub fn is_channel_open(&self, channel_id: u32) -> bool {
        self.channels.get(&channel_id).is_some_and(|c| c.open)
    }

    /// List the channels currently tracked by this server, including
    /// pending CreateRequests that the client has not yet acked.
    pub fn channels(&self) -> impl Iterator<Item = (u32, &str)> {
        self.channels.iter().map(|(id, c)| (*id, c.name.as_str()))
    }

    // ── Capability negotiation ─────────────────────────────────────────

    /// Build the Capabilities Request PDU bytes (server → client).
    /// MS-RDPEDYC §3.2.5.1.1: server sends this first, advertising its
    /// highest supported version. For v2/v3 the four `priority_charges`
    /// values are inlined per §2.2.1.1.2.
    pub fn initialize_capabilities(&self) -> DvcResult<Vec<u8>> {
        let charges = if self.advertised_version >= crate::pdu::CAPS_VERSION_2 {
            // Default priority charges: equal weight across all four
            // priority classes. Real servers tune these for traffic
            // shaping; the values here match what FreeRDP uses by
            // default.
            Some([0x0000, 0x0000, 0x0000, 0x0000])
        } else {
            None
        };
        // `encode_caps_request` returns an error only on (version,
        // charges) mismatches. Our self.advertised_version and our
        // own matching `charges` selection above can never misalign,
        // so the `?` here is a safety-net for future refactors.
        Ok(encode_caps_request(self.advertised_version, charges)?)
    }

    /// Process a Capabilities Response from the client. The client
    /// echoes back its highest supported version `<= advertised_version`.
    ///
    /// Uses [`decode_caps_response`] rather than the general
    /// [`decode_dvc_pdu`] because the wire shapes diverge: server →
    /// client Capabilities **Request** carries 8 bytes of priority
    /// charges for v2/v3, but client → server Capabilities **Response**
    /// is always 4 bytes (Header + Pad + Version) regardless of version
    /// (MS-RDPEDYC §2.2.1.2). Feeding a real v2 response through
    /// `decode_dvc_pdu` would over-read 8 bytes and fail.
    pub fn process_caps_response(&mut self, bytes: &[u8]) -> DvcResult<()> {
        let version = decode_caps_response(bytes)?;
        if version > self.advertised_version {
            return Err(DvcError::Protocol(alloc::format!(
                "client advertised version {version} > server advertised version {}",
                self.advertised_version
            )));
        }
        self.negotiated_version = version;
        Ok(())
    }

    // ── Channel lifecycle ──────────────────────────────────────────────

    /// Build a Create Request PDU bytes for `channel_name` with the
    /// given `channel_id`. Caller is responsible for picking unique IDs;
    /// MS-RDPEDYC §3.1.1 requires monotonically increasing values >= 1.
    /// Subsequent calls for the same `channel_id` overwrite the in-flight
    /// channel and start a new reassembler -- callers should not reuse
    /// IDs while a channel is in flight.
    pub fn open_channel(
        &mut self,
        channel_id: u32,
        channel_name: &str,
        priority: u8,
    ) -> DvcResult<Vec<u8>> {
        if channel_id == 0 {
            return Err(DvcError::Protocol(alloc::string::String::from(
                "channel_id 0 is reserved",
            )));
        }
        // MS-RDPEDYC §3.1.1 invariant: channel IDs must be
        // monotonically increasing. Reject anything at or below the
        // high-water mark (which includes channels that were opened
        // then closed -- those IDs are retired, not reusable).
        if channel_id <= self.last_channel_id {
            return Err(DvcError::Protocol(alloc::format!(
                "channel_id {channel_id} violates monotonicity (last assigned \
                 was {})",
                self.last_channel_id
            )));
        }
        // Also refuse to overwrite an existing live channel even if the
        // ID happens to satisfy monotonicity (defence in depth against
        // manual state-machine misuse).
        if self.channels.contains_key(&channel_id) {
            return Err(DvcError::Protocol(alloc::format!(
                "channel_id {channel_id} is already in use"
            )));
        }
        self.channels.insert(
            channel_id,
            ChannelState {
                name: alloc::string::String::from(channel_name),
                open: false,
                reassembler: DvcReassembler::new(),
            },
        );
        self.last_channel_id = channel_id;
        Ok(encode_create_request(channel_id, channel_name, priority))
    }

    /// Process a Create Response PDU from the client. Returns
    /// `Ok(true)` when the channel was successfully created (status =
    /// 0), `Ok(false)` when the client rejected the channel (status !=
    /// 0; the channel is removed from the tracking table). Errors only
    /// when the wire bytes are not a valid Create Response or refer to
    /// a channel ID we never asked the client to open.
    pub fn process_create_response(&mut self, bytes: &[u8]) -> DvcResult<bool> {
        // Manually decode CMD_CREATE-with-creation_status. The existing
        // `decode_dvc_pdu` only handles server→client CreateRequest
        // (which has the channel name); the response wire format is
        // `Header + ChannelId + creationStatus(i32 LE)`.
        let mut cursor = ReadCursor::new(bytes);
        let header = cursor.read_u8("DVC::header")?;
        let (cmd, _sp, cb_id) = crate::pdu::decode_header(header);
        if cmd != crate::pdu::CMD_CREATE {
            return Err(DvcError::Protocol(alloc::string::String::from(
                "expected CMD_CREATE PDU as Create Response",
            )));
        }
        let channel_id = crate::pdu::read_channel_id(&mut cursor, cb_id)?;
        let status = cursor.read_i32_le("DVC::creationStatus")?;

        let entry = self.channels.get_mut(&channel_id).ok_or_else(|| {
            DvcError::Protocol(alloc::format!(
                "Create Response for unknown channel_id {channel_id}"
            ))
        })?;
        if status == CREATION_STATUS_OK {
            entry.open = true;
            Ok(true)
        } else {
            // Negative status: drop the channel from our tracking table
            // so future data PDUs for this ID are rejected. The channel
            // ID is **retired, not reusable**: `last_channel_id` is
            // never decremented, so a subsequent `open_channel` with
            // the same ID would hit the monotonicity guard. Callers
            // must use the next monotonically higher ID for any retry.
            self.channels.remove(&channel_id);
            Ok(false)
        }
    }

    /// Build a Close PDU bytes (server → client) and remove the channel
    /// from local tracking. Returns the encoded bytes for the caller to
    /// send on the SVC.
    pub fn close_channel(&mut self, channel_id: u32) -> DvcResult<Vec<u8>> {
        if self.channels.remove(&channel_id).is_none() {
            return Err(DvcError::Protocol(alloc::format!(
                "close_channel: unknown channel_id {channel_id}"
            )));
        }
        Ok(encode_close(channel_id))
    }

    // ── Data path ──────────────────────────────────────────────────────

    /// Encode `payload` as a single DYNVC_DATA PDU (no fragmentation).
    /// Caller is responsible for keeping the payload below the SVC chunk
    /// size limit (typically `vc_chunk_size` from VirtualChannelCapability,
    /// default 1600 bytes minus the DVC header overhead).
    pub fn send_data(&self, channel_id: u32, payload: &[u8]) -> DvcResult<Vec<u8>> {
        if !self.is_channel_open(channel_id) {
            return Err(DvcError::Protocol(alloc::format!(
                "send_data: channel_id {channel_id} is not open"
            )));
        }
        Ok(encode_data(channel_id, payload))
    }

    /// Encode `payload` as a DYNVC_DATA_FIRST PDU. Use when the total
    /// payload exceeds one chunk; follow up with [`send_data`] for the
    /// remaining chunks (whose `data` is the next slice).
    pub fn send_data_first(
        &self,
        channel_id: u32,
        total_length: u32,
        first_chunk: &[u8],
    ) -> DvcResult<Vec<u8>> {
        if !self.is_channel_open(channel_id) {
            return Err(DvcError::Protocol(alloc::format!(
                "send_data_first: channel_id {channel_id} is not open"
            )));
        }
        Ok(encode_data_first(channel_id, total_length, first_chunk))
    }

    /// Encode `compressed_payload` as a single DYNVC_DATA_COMPRESSED
    /// PDU (MS-RDPEDYC §2.2.3.4).
    ///
    /// `compressed_payload` MUST already be the bulk-encoded
    /// `RDP_SEGMENTED_DATA` form produced by
    /// [`ZgfxCompressor::compress`]. The receiving DVC layer will run
    /// it through [`ZgfxDecompressor`](justrdp_bulk::zgfx::ZgfxDecompressor)
    /// before delivering to the channel processor.
    ///
    /// For an automatic compress-or-fallback wrapper that consults a
    /// size threshold, see
    /// [`send_data_with_compression_fallback`](Self::send_data_with_compression_fallback).
    pub fn send_data_compressed(
        &self,
        channel_id: u32,
        compressed_payload: &[u8],
    ) -> DvcResult<Vec<u8>> {
        if !self.is_channel_open(channel_id) {
            return Err(DvcError::Protocol(alloc::format!(
                "send_data_compressed: channel_id {channel_id} is not open"
            )));
        }
        Ok(encode_data_compressed(channel_id, compressed_payload))
    }

    /// Encode `compressed_first_chunk` as a DYNVC_DATA_FIRST_COMPRESSED
    /// PDU (MS-RDPEDYC §2.2.3.3). Follow up with
    /// [`send_data_compressed`](Self::send_data_compressed) for the
    /// remaining chunks; `total_length` is the byte total of the
    /// reassembled (still-compressed) payload across every chunk.
    pub fn send_data_first_compressed(
        &self,
        channel_id: u32,
        total_length: u32,
        compressed_first_chunk: &[u8],
    ) -> DvcResult<Vec<u8>> {
        if !self.is_channel_open(channel_id) {
            return Err(DvcError::Protocol(alloc::format!(
                "send_data_first_compressed: channel_id {channel_id} is not open"
            )));
        }
        Ok(encode_data_first_compressed(
            channel_id,
            total_length,
            compressed_first_chunk,
        ))
    }

    /// Compress `payload` via `compressor` and emit either a
    /// `DYNVC_DATA_COMPRESSED` (when the compressed form saves at
    /// least `min_savings_bytes` over the raw form) or a plain
    /// `DYNVC_DATA` otherwise.
    ///
    /// Use this when the application is willing to defer the
    /// compress-or-skip decision to the framework. Pass
    /// `min_savings_bytes = 0` to take any saving (including a
    /// 1-byte win); pass a larger value to require the compressed
    /// payload be meaningfully smaller before paying the
    /// decompression cost on the receiver. The current
    /// [`ZgfxCompressor`] is pass-through (no LZ77), so in practice
    /// this helper always returns the uncompressed branch -- the seam
    /// exists so applications can opt in cleanly once real
    /// compression lands.
    ///
    /// Returns the encoded DVC PDU bytes. On compression error the
    /// helper returns the underlying [`ZgfxError`] wrapped in
    /// [`DvcError::Protocol`].
    pub fn send_data_with_compression_fallback(
        &self,
        channel_id: u32,
        payload: &[u8],
        compressor: &mut ZgfxCompressor,
        min_savings_bytes: usize,
    ) -> DvcResult<Vec<u8>> {
        if !self.is_channel_open(channel_id) {
            return Err(DvcError::Protocol(alloc::format!(
                "send_data_with_compression_fallback: channel_id {channel_id} is not open"
            )));
        }
        let mut compressed = Vec::with_capacity(payload.len());
        compressor
            .compress(payload, &mut compressed)
            .map_err(zgfx_error_to_dvc)?;
        if payload.len() >= compressed.len().saturating_add(min_savings_bytes) {
            Ok(encode_data_compressed(channel_id, &compressed))
        } else {
            Ok(encode_data(channel_id, payload))
        }
    }

    /// Process an inbound DVC PDU from the client. Reassembles
    /// fragments and returns `Some((channel_id, payload))` when a
    /// complete client message is available, or `None` when more
    /// fragments are still needed. Returns an error for unsupported PDU
    /// types or for channels that have not been opened.
    ///
    /// Compressed data PDUs are surfaced as an error -- decompression
    /// requires `justrdp-bulk` and is out of scope for this skeleton.
    pub fn process_inbound(
        &mut self,
        bytes: &[u8],
    ) -> DvcResult<Option<(u32, Vec<u8>)>> {
        let mut cursor = ReadCursor::new(bytes);
        let pdu = decode_dvc_pdu(&mut cursor)?;
        match pdu {
            DvcPdu::Data { channel_id, data } => {
                let entry = self.channels.get_mut(&channel_id).ok_or_else(|| {
                    DvcError::Protocol(alloc::format!(
                        "Data PDU for unknown channel_id {channel_id}"
                    ))
                })?;
                if !entry.open {
                    return Err(DvcError::Protocol(alloc::format!(
                        "Data PDU for unopened channel_id {channel_id}"
                    )));
                }
                let complete = entry.reassembler.data(&data)?;
                Ok(complete.map(|payload| (channel_id, payload)))
            }
            DvcPdu::DataFirst {
                channel_id,
                total_length,
                data,
            } => {
                let entry = self.channels.get_mut(&channel_id).ok_or_else(|| {
                    DvcError::Protocol(alloc::format!(
                        "DataFirst PDU for unknown channel_id {channel_id}"
                    ))
                })?;
                if !entry.open {
                    return Err(DvcError::Protocol(alloc::format!(
                        "DataFirst PDU for unopened channel_id {channel_id}"
                    )));
                }
                let complete = entry.reassembler.data_first(total_length, &data)?;
                Ok(complete.map(|payload| (channel_id, payload)))
            }
            DvcPdu::Close { channel_id } => {
                self.channels.remove(&channel_id);
                Ok(None)
            }
            DvcPdu::DataFirstCompressed { .. } | DvcPdu::DataCompressed { .. } => Err(
                DvcError::Protocol(alloc::string::String::from(
                    "compressed DVC data PDUs are not yet supported on the server side",
                )),
            ),
            DvcPdu::CapabilitiesRequest { .. } => Err(DvcError::Protocol(
                alloc::string::String::from(
                    "client sent CapabilitiesRequest -- use process_caps_response instead",
                ),
            )),
            DvcPdu::CreateRequest { .. } => Err(DvcError::Protocol(alloc::string::String::from(
                "client sent CreateRequest -- only the server initiates channel creation",
            ))),
            DvcPdu::SoftSyncRequest { .. } => Err(DvcError::Protocol(
                alloc::string::String::from(
                    "client sent SoftSyncRequest -- only the server initiates Soft-Sync",
                ),
            )),
            DvcPdu::SoftSyncResponse { .. } => Err(DvcError::Protocol(
                alloc::string::String::from(
                    "SoftSyncResponse handling is not yet implemented on the server side",
                ),
            )),
        }
    }
}

impl Default for DrdynvcServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Translate a [`ZgfxError`] into a [`DvcError::Protocol`] variant
/// with the underlying error preserved in the message string.
fn zgfx_error_to_dvc(e: ZgfxError) -> DvcError {
    DvcError::Protocol(alloc::format!("ZGFX compression failed: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{encode_caps_response, encode_create_response};

    #[test]
    fn capability_negotiation_round_trip() {
        let server = DrdynvcServer::new();
        let req = server.initialize_capabilities().unwrap();
        // Wire shape: header(0x50) + pad(0) + version(0x0003 LE) + 8 bytes of charges = 12 bytes.
        assert_eq!(req.len(), 12);
        assert_eq!(req[0], 0x50); // CMD_CAPS << 4
        assert_eq!(&req[2..4], &[0x03, 0x00]);
    }

    #[test]
    fn initialize_capabilities_v1_emits_4_byte_request() {
        let server = DrdynvcServer::with_version(1);
        let req = server.initialize_capabilities().unwrap();
        assert_eq!(req.len(), 4);
        assert_eq!(req[0], 0x50);
        assert_eq!(&req[2..4], &[0x01, 0x00]);
    }

    #[test]
    fn encode_caps_request_rejects_v2_without_charges() {
        use crate::pdu::encode_caps_request;
        assert!(encode_caps_request(2, None).is_err());
    }

    #[test]
    fn encode_caps_request_rejects_v1_with_charges() {
        use crate::pdu::encode_caps_request;
        assert!(encode_caps_request(1, Some([0, 0, 0, 0])).is_err());
    }

    #[test]
    fn decode_caps_response_rejects_nonzero_sp_or_cb_id() {
        use crate::pdu::decode_caps_response;
        // Header byte 0x51 = CMD_CAPS(5) << 4 | cb_id=1 -- spec violation.
        let bad = [0x51, 0x00, 0x01, 0x00];
        assert!(decode_caps_response(&bad).is_err());
        // Header byte 0x54 = CMD_CAPS(5) << 4 | sp=1<<2 -- spec violation.
        let bad = [0x54, 0x00, 0x01, 0x00];
        assert!(decode_caps_response(&bad).is_err());
        // Header byte 0x50 = valid.
        let ok = [0x50, 0x00, 0x01, 0x00];
        assert_eq!(decode_caps_response(&ok).unwrap(), 1);
    }

    #[test]
    fn process_caps_response_records_negotiated_version_v1() {
        let mut server = DrdynvcServer::new();
        let _ = server.initialize_capabilities().unwrap();
        // Client picks v1 -- 4-byte wire shape (header + pad + version).
        let resp = encode_caps_response(1);
        assert_eq!(resp.len(), 4);
        server.process_caps_response(&resp).unwrap();
        assert_eq!(server.negotiated_version(), 1);
    }

    #[test]
    fn process_caps_response_accepts_v2_without_charges() {
        // MS-RDPEDYC §2.2.1.2: v2/v3 Capabilities *Response* is still
        // 4 bytes on the wire -- priority charges are only in the
        // server → client Request. A real client response feeding
        // through `process_caps_response` must not demand charges.
        let mut server = DrdynvcServer::new();
        let resp = encode_caps_response(2);
        assert_eq!(resp.len(), 4);
        server.process_caps_response(&resp).unwrap();
        assert_eq!(server.negotiated_version(), 2);
    }

    #[test]
    fn process_caps_response_rejects_higher_than_advertised() {
        let mut server = DrdynvcServer::with_version(2);
        let resp = encode_caps_response(3);
        let err = server.process_caps_response(&resp).unwrap_err();
        match err {
            DvcError::Protocol(msg) => assert!(msg.contains("advertised version 2")),
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn open_channel_then_create_response_marks_open() {
        let mut server = DrdynvcServer::new();
        let _ = server.open_channel(7, "graphics", 0).unwrap();
        assert!(!server.is_channel_open(7));
        let resp = encode_create_response(7, CREATION_STATUS_OK);
        assert!(server.process_create_response(&resp).unwrap());
        assert!(server.is_channel_open(7));
    }

    #[test]
    fn negative_create_response_drops_channel() {
        let mut server = DrdynvcServer::new();
        let _ = server.open_channel(8, "snd", 1).unwrap();
        let resp = encode_create_response(8, -1); // any non-zero
        assert!(!server.process_create_response(&resp).unwrap());
        // Channel removed from tracking.
        assert!(!server.is_channel_open(8));
        assert!(server.channels().find(|(id, _)| *id == 8).is_none());
    }

    #[test]
    fn open_channel_rejects_channel_id_zero() {
        let mut server = DrdynvcServer::new();
        let err = server.open_channel(0, "x", 0).unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn channel_id_is_retired_after_negative_create_response() {
        // Regression for the doc-comment contradiction: after the
        // client rejects a CreateRequest, the channel ID must be
        // retired (not reusable) because `last_channel_id` is never
        // decremented. A caller attempting to reuse the same ID must
        // hit the monotonicity guard.
        let mut server = DrdynvcServer::new();
        let _ = server.open_channel(8, "snd", 1).unwrap();
        let reject = encode_create_response(8, -1); // negative status
        assert!(!server.process_create_response(&reject).unwrap());
        // Same ID rejected by the monotonicity guard:
        let err = server.open_channel(8, "snd", 1).unwrap_err();
        assert!(matches!(err, DvcError::Protocol(msg) if msg.contains("monotonicity")));
        // A higher ID still works.
        let _ = server.open_channel(9, "snd", 1).unwrap();
    }

    #[test]
    fn open_channel_enforces_monotonicity() {
        let mut server = DrdynvcServer::new();
        let _ = server.open_channel(10, "a", 0).unwrap();
        // Below the high-water mark -- rejected.
        let err = server.open_channel(5, "b", 0).unwrap_err();
        assert!(matches!(err, DvcError::Protocol(msg) if msg.contains("monotonicity")));
        // Equal to the high-water mark -- also rejected (IDs are
        // retired, not reusable).
        let err = server.open_channel(10, "c", 0).unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
        // Above the high-water mark -- accepted.
        let _ = server.open_channel(11, "d", 0).unwrap();
    }

    #[test]
    fn process_create_response_for_unknown_channel_errors() {
        let mut server = DrdynvcServer::new();
        let resp = encode_create_response(9, CREATION_STATUS_OK);
        let err = server.process_create_response(&resp).unwrap_err();
        match err {
            DvcError::Protocol(msg) => assert!(msg.contains("unknown channel_id 9")),
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn send_data_requires_open_channel() {
        let server = DrdynvcServer::new();
        let err = server.send_data(7, b"hello").unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn send_data_after_open_succeeds() {
        let mut server = DrdynvcServer::new();
        let _ = server.open_channel(7, "g", 0).unwrap();
        let _ = server.process_create_response(&encode_create_response(7, 0)).unwrap();
        let bytes = server.send_data(7, b"hello").unwrap();
        // Wire shape: header(0x30) + cb_id varint(0x07) + payload.
        assert_eq!(bytes[0], 0x30);
        assert_eq!(bytes[1], 0x07);
        assert_eq!(&bytes[2..], b"hello");
    }

    #[test]
    fn process_inbound_data_round_trip_through_reassembly() {
        use crate::pdu::encode_data;
        let mut server = DrdynvcServer::new();
        let _ = server.open_channel(7, "g", 0).unwrap();
        let _ = server.process_create_response(&encode_create_response(7, 0)).unwrap();
        let inbound = encode_data(7, b"world");
        let res = server.process_inbound(&inbound).unwrap();
        assert_eq!(res, Some((7, b"world".to_vec())));
    }

    #[test]
    fn process_inbound_data_for_unopened_channel_errors() {
        use crate::pdu::encode_data;
        let mut server = DrdynvcServer::new();
        let _ = server.open_channel(7, "g", 0).unwrap();
        // Did NOT receive create response, so channel is not open.
        let inbound = encode_data(7, b"x");
        let err = server.process_inbound(&inbound).unwrap_err();
        match err {
            DvcError::Protocol(msg) => assert!(msg.contains("unopened")),
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn close_channel_emits_close_pdu_and_drops_state() {
        let mut server = DrdynvcServer::new();
        let _ = server.open_channel(7, "g", 0).unwrap();
        let bytes = server.close_channel(7).unwrap();
        // Wire shape: header(0x40) + cb_id varint(0x07).
        assert_eq!(bytes[0], 0x40);
        assert_eq!(bytes[1], 0x07);
        assert!(server.channels().next().is_none());
    }

    #[test]
    fn inbound_close_pdu_drops_channel() {
        let mut server = DrdynvcServer::new();
        let _ = server.open_channel(7, "g", 0).unwrap();
        let _ = server.process_create_response(&encode_create_response(7, 0)).unwrap();
        let res = server.process_inbound(&encode_close(7)).unwrap();
        assert_eq!(res, None);
        assert!(!server.is_channel_open(7));
    }

    // ── Compressed DVC framing (§11.2b-4 Commit 2) ──────────────

    use crate::pdu::{decode_dvc_pdu, DvcPdu};
    use alloc::vec;
    use justrdp_core::ReadCursor;

    fn open_server_with_channel(channel_id: u32) -> DrdynvcServer {
        let mut server = DrdynvcServer::new();
        let _ = server.open_channel(channel_id, "graphics", 0).unwrap();
        let _ = server
            .process_create_response(&encode_create_response(channel_id, CREATION_STATUS_OK))
            .unwrap();
        assert!(server.is_channel_open(channel_id));
        server
    }

    #[test]
    fn send_data_compressed_emits_dynvc_data_compressed() {
        let server = open_server_with_channel(7);
        let payload = vec![0xCC; 64];
        let bytes = server.send_data_compressed(7, &payload).unwrap();

        // Decode and verify the cmd_id is CMD_DATA_COMPRESSED (0x07).
        let mut cur = ReadCursor::new(&bytes);
        match decode_dvc_pdu(&mut cur).unwrap() {
            DvcPdu::DataCompressed { channel_id, data } => {
                assert_eq!(channel_id, 7);
                assert_eq!(data, payload);
            }
            other => panic!("expected DataCompressed, got {other:?}"),
        }
    }

    #[test]
    fn send_data_compressed_rejects_unknown_channel() {
        let server = DrdynvcServer::new();
        assert!(server.send_data_compressed(99, &[0xAB]).is_err());
    }

    #[test]
    fn send_data_first_compressed_emits_dynvc_data_first_compressed() {
        let server = open_server_with_channel(7);
        let chunk = vec![0xDD; 16];
        let bytes = server
            .send_data_first_compressed(7, 1024, &chunk)
            .unwrap();
        let mut cur = ReadCursor::new(&bytes);
        match decode_dvc_pdu(&mut cur).unwrap() {
            DvcPdu::DataFirstCompressed {
                channel_id,
                total_length,
                data,
            } => {
                assert_eq!(channel_id, 7);
                assert_eq!(total_length, 1024);
                assert_eq!(data, chunk);
            }
            other => panic!("expected DataFirstCompressed, got {other:?}"),
        }
    }

    #[test]
    fn send_data_first_compressed_rejects_unknown_channel() {
        let server = DrdynvcServer::new();
        assert!(server
            .send_data_first_compressed(99, 100, &[0xAB])
            .is_err());
    }

    #[test]
    fn fallback_emits_uncompressed_when_no_savings() {
        // Pass-through ZgfxCompressor adds 2 bytes of header overhead
        // for a SINGLE segment, so for any sane payload the compressed
        // form is strictly larger -> fallback fires (uncompressed).
        let server = open_server_with_channel(7);
        let mut compressor = ZgfxCompressor::new();
        let payload = vec![0xEE; 128];
        let bytes = server
            .send_data_with_compression_fallback(7, &payload, &mut compressor, 0)
            .unwrap();
        let mut cur = ReadCursor::new(&bytes);
        match decode_dvc_pdu(&mut cur).unwrap() {
            DvcPdu::Data { channel_id, data } => {
                assert_eq!(channel_id, 7);
                assert_eq!(data, payload);
            }
            other => panic!("expected uncompressed Data, got {other:?}"),
        }
    }

    #[test]
    fn fallback_threshold_blocks_marginal_savings() {
        // Even if ZGFX did save N bytes, requiring `min_savings_bytes
        // = N+1` still falls back. We can't easily produce a real
        // saving with the pass-through compressor, but we can verify
        // the threshold gating at the API level by setting an
        // unreachable threshold and confirming the uncompressed
        // branch fires.
        let server = open_server_with_channel(7);
        let mut compressor = ZgfxCompressor::new();
        let payload = vec![0u8; 1024];
        let bytes = server
            .send_data_with_compression_fallback(
                7,
                &payload,
                &mut compressor,
                usize::MAX, // demand impossible savings
            )
            .unwrap();
        let mut cur = ReadCursor::new(&bytes);
        assert!(matches!(
            decode_dvc_pdu(&mut cur).unwrap(),
            DvcPdu::Data { .. },
        ));
    }

    #[test]
    fn fallback_rejects_unknown_channel_before_compressing() {
        let server = DrdynvcServer::new();
        let mut compressor = ZgfxCompressor::new();
        assert!(server
            .send_data_with_compression_fallback(99, &[0xAB], &mut compressor, 0)
            .is_err());
    }

    #[test]
    fn compressed_pdus_roundtrip_through_decode() {
        // Encode → decode roundtrip for both compressed variants.
        let server = open_server_with_channel(7);
        let single_payload = vec![0x11; 32];
        let single_bytes = server.send_data_compressed(7, &single_payload).unwrap();
        let first_payload = vec![0x22; 64];
        let first_bytes = server
            .send_data_first_compressed(7, 200, &first_payload)
            .unwrap();

        let mut c1 = ReadCursor::new(&single_bytes);
        match decode_dvc_pdu(&mut c1).unwrap() {
            DvcPdu::DataCompressed { data, .. } => assert_eq!(data, single_payload),
            _ => panic!(),
        }
        let mut c2 = ReadCursor::new(&first_bytes);
        match decode_dvc_pdu(&mut c2).unwrap() {
            DvcPdu::DataFirstCompressed {
                total_length, data, ..
            } => {
                assert_eq!(total_length, 200);
                assert_eq!(data, first_payload);
            }
            _ => panic!(),
        }
    }
}
