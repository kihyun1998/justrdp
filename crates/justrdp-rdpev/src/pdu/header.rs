//! `SHARED_MSG_HEADER` (MS-RDPEV §2.2.1).
//!
//! Every TSMF PDU starts with one of two header shapes:
//!
//! ```text
//!   Request / interface manipulation (12 bytes):
//!     +0  u32 LE  InterfaceId  (InterfaceValue [29:0] | Mask [31:30])
//!     +4  u32 LE  MessageId
//!     +8  u32 LE  FunctionId
//!
//!   Response (8 bytes):
//!     +0  u32 LE  InterfaceId  (Mask = STREAM_ID_STUB)
//!     +4  u32 LE  MessageId    (echoed from request)
//! ```
//!
//! The `Mask` bits in the upper two bits of `InterfaceId` discriminate
//! the two layouts:
//!
//! - `STREAM_ID_PROXY (0x40000000)` -- request, FunctionId present
//! - `STREAM_ID_NONE (0x00000000)` -- interface manipulation, FunctionId present
//! - `STREAM_ID_STUB (0x80000000)` -- response, FunctionId absent
//!
//! AMBIGUITY (spec §2.2.1 vs annotated wire examples in §4): the spec
//! prose says "FunctionId MUST be present in all packets except response
//! packets," but the example wire dumps for responses end exactly at
//! MessageId+4. We follow the wire examples: response headers are 8
//! bytes, FunctionId is literally absent on the wire.

use justrdp_core::{DecodeError, DecodeResult, EncodeResult, ReadCursor, WriteCursor};

use crate::constants::{pack_interface_id, unpack_interface_id, FunctionId, InterfaceValue, Mask};

/// Wire size of a request / interface-manipulation header.
pub const REQUEST_HEADER_SIZE: usize = 12;

/// Wire size of a response header.
pub const RESPONSE_HEADER_SIZE: usize = 8;

/// Strongly-typed view of a `SHARED_MSG_HEADER` carrying enough
/// context to dispatch the payload.
///
/// `function_id` is `None` exactly when `mask == Mask::Stub` (i.e., the
/// header is a response). For requests and interface-manipulation
/// messages it is always `Some`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedMsgHeader {
    /// 30-bit `InterfaceValue` (lower bits of the on-wire `InterfaceId`).
    pub interface_value: InterfaceValue,
    /// 2-bit `Mask` (upper bits of `InterfaceId`). Determines whether
    /// `function_id` is on the wire.
    pub mask: Mask,
    /// Correlation id; responses echo the request's value.
    pub message_id: u32,
    /// Present on requests / interface-manipulation, absent on responses.
    pub function_id: Option<FunctionId>,
}

impl SharedMsgHeader {
    /// Builds a request header (`Mask = STREAM_ID_PROXY`).
    pub fn request(interface_value: InterfaceValue, message_id: u32, function_id: FunctionId) -> Self {
        Self {
            interface_value,
            mask: Mask::Proxy,
            message_id,
            function_id: Some(function_id),
        }
    }

    /// Builds a response header (`Mask = STREAM_ID_STUB`, FunctionId omitted).
    pub fn response(interface_value: InterfaceValue, message_id: u32) -> Self {
        Self {
            interface_value,
            mask: Mask::Stub,
            message_id,
            function_id: None,
        }
    }

    /// Builds an interface-manipulation header (`Mask = STREAM_ID_NONE`).
    pub fn interface_manipulation(
        interface_value: InterfaceValue,
        message_id: u32,
        function_id: FunctionId,
    ) -> Self {
        Self {
            interface_value,
            mask: Mask::None,
            message_id,
            function_id: Some(function_id),
        }
    }

    /// Wire size in bytes -- 12 for requests and interface-manipulation,
    /// 8 for responses.
    pub fn wire_size(&self) -> usize {
        if self.function_id.is_some() {
            REQUEST_HEADER_SIZE
        } else {
            RESPONSE_HEADER_SIZE
        }
    }

    /// True if this header is a response (Mask = STUB).
    pub fn is_response(&self) -> bool {
        matches!(self.mask, Mask::Stub)
    }
}

const CTX: &str = "MS-RDPEV::SharedMsgHeader";

/// Encodes a `SHARED_MSG_HEADER`. Writes 12 bytes when
/// `function_id.is_some()`, 8 bytes otherwise. The destination must
/// have at least `header.wire_size()` bytes available.
///
/// This function does **not** validate that the (mask, function_id)
/// combination is consistent (e.g., it will let you write a
/// `STREAM_ID_PROXY` header with `function_id = None`). Higher-level
/// builders are responsible for picking sane shapes -- the
/// [`SharedMsgHeader::request`], [`SharedMsgHeader::response`], and
/// [`SharedMsgHeader::interface_manipulation`] constructors do this
/// for you.
pub fn encode_header(dst: &mut WriteCursor<'_>, header: &SharedMsgHeader) -> EncodeResult<()> {
    let raw_iface = pack_interface_id(header.interface_value.to_u32(), header.mask);
    dst.write_u32_le(raw_iface, CTX)?;
    dst.write_u32_le(header.message_id, CTX)?;
    if let Some(fid) = header.function_id {
        dst.write_u32_le(fid.to_u32(), CTX)?;
    }
    Ok(())
}

/// Decodes a request / interface-manipulation header (12 bytes,
/// FunctionId always present).
///
/// Errors if the source contains fewer than 12 bytes or if the on-wire
/// `Mask` is `STREAM_ID_STUB` (responses must be decoded with
/// [`decode_response_header`] -- they have no FunctionId).
pub fn decode_request_header(src: &mut ReadCursor<'_>) -> DecodeResult<SharedMsgHeader> {
    let raw_iface = src.read_u32_le(CTX)?;
    let message_id = src.read_u32_le(CTX)?;
    let (iv_raw, mask) = unpack_interface_id(raw_iface);
    if matches!(mask, Mask::Stub) {
        // A 12-byte read on a STUB header would consume the start of
        // the next payload field as a phantom FunctionId. Refuse.
        return Err(DecodeError::invalid_value(CTX, "Mask"));
    }
    let raw_fid = src.read_u32_le(CTX)?;
    Ok(SharedMsgHeader {
        interface_value: InterfaceValue::from_u32(iv_raw),
        mask,
        message_id,
        function_id: Some(FunctionId::from_raw(iv_raw, raw_fid)),
    })
}

/// Decodes a response header (8 bytes, no FunctionId).
///
/// Errors if the on-wire `Mask` is not `STREAM_ID_STUB` -- callers that
/// don't yet know whether the next PDU is a request or a response
/// should peek the InterfaceId word themselves and dispatch via
/// [`decode_header_auto`].
pub fn decode_response_header(src: &mut ReadCursor<'_>) -> DecodeResult<SharedMsgHeader> {
    let raw_iface = src.read_u32_le(CTX)?;
    let message_id = src.read_u32_le(CTX)?;
    let (iv_raw, mask) = unpack_interface_id(raw_iface);
    if !matches!(mask, Mask::Stub) {
        return Err(DecodeError::invalid_value(CTX, "Mask"));
    }
    Ok(SharedMsgHeader {
        interface_value: InterfaceValue::from_u32(iv_raw),
        mask,
        message_id,
        function_id: None,
    })
}

/// Peeks the first 4 bytes of `src` to decide whether the upcoming
/// header is a request (12 bytes) or a response (8 bytes), then
/// dispatches to the appropriate decoder. Useful for the top-level
/// channel reader, which doesn't know the message shape until it sees
/// the Mask bits.
///
/// On success, advances `src` past the header. On failure (short
/// input, unknown mask), `src` may have been advanced by up to 8
/// bytes -- callers should treat the cursor as poisoned and surface
/// the error to the channel layer.
pub fn decode_header_auto(src: &mut ReadCursor<'_>) -> DecodeResult<SharedMsgHeader> {
    if src.remaining() < RESPONSE_HEADER_SIZE {
        return Err(DecodeError::invalid_value(CTX, "header underflow"));
    }
    // Peek the first u32 without consuming it.
    let peek = src.peek_remaining();
    let raw_iface = u32::from_le_bytes([peek[0], peek[1], peek[2], peek[3]]);
    let mask = Mask::from_interface_id(raw_iface);
    match mask {
        Mask::Stub => decode_response_header(src),
        Mask::Proxy | Mask::None => decode_request_header(src),
        Mask::Other(_) => Err(DecodeError::invalid_value(CTX, "Mask")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        function_id as f, interface_value::CLIENT_NOTIFICATIONS, interface_value::SERVER_DATA,
    };
    use alloc::vec;
    use alloc::vec::Vec;

    fn encode_to_vec(header: &SharedMsgHeader) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; header.wire_size()];
        let mut cur = WriteCursor::new(&mut buf);
        encode_header(&mut cur, header).unwrap();
        assert_eq!(cur.pos(), header.wire_size());
        buf
    }

    #[test]
    fn roundtrip_set_channel_params_request_header() {
        // Wire vector from spec §4 / checklist §11.1:
        //   00 00 00 40  InterfaceId (SERVER_DATA | PROXY)
        //   00 00 00 00  MessageId
        //   01 01 00 00  SET_CHANNEL_PARAMS (0x00000101)
        let h = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            0,
            FunctionId::SetChannelParams,
        );
        let bytes = encode_to_vec(&h);
        assert_eq!(
            bytes,
            [
                0x00, 0x00, 0x00, 0x40, // InterfaceId
                0x00, 0x00, 0x00, 0x00, // MessageId
                0x01, 0x01, 0x00, 0x00, // FunctionId
            ]
        );
        let mut r = ReadCursor::new(&bytes);
        let decoded = decode_request_header(&mut r).unwrap();
        assert_eq!(decoded, h);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn roundtrip_exchange_capabilities_response_header() {
        // Wire vector from spec §4 / checklist §11.3:
        //   00 00 00 80  InterfaceId (SERVER_DATA | STUB)
        //   00 00 00 00  MessageId
        // (no FunctionId)
        let h = SharedMsgHeader::response(InterfaceValue::ServerData, 0);
        let bytes = encode_to_vec(&h);
        assert_eq!(
            bytes,
            [
                0x00, 0x00, 0x00, 0x80, // InterfaceId
                0x00, 0x00, 0x00, 0x00, // MessageId
            ]
        );
        assert_eq!(bytes.len(), RESPONSE_HEADER_SIZE);
        let mut r = ReadCursor::new(&bytes);
        let decoded = decode_response_header(&mut r).unwrap();
        assert_eq!(decoded, h);
        assert!(decoded.function_id.is_none());
    }

    #[test]
    fn playback_ack_uses_client_notifications_interface() {
        // PLAYBACK_ACK is opcode 0x100 on InterfaceValue=1 (Client
        // Notifications), so InterfaceId on the wire is 0x40000001.
        let h = SharedMsgHeader::request(
            InterfaceValue::ClientNotifications,
            42,
            FunctionId::PlaybackAck,
        );
        let bytes = encode_to_vec(&h);
        assert_eq!(
            &bytes[0..4],
            &[0x01, 0x00, 0x00, 0x40],
            "InterfaceValue=1 packed with Mask=PROXY = 0x40000001"
        );

        let mut r = ReadCursor::new(&bytes);
        let decoded = decode_request_header(&mut r).unwrap();
        assert_eq!(decoded.interface_value, InterfaceValue::ClientNotifications);
        assert_eq!(decoded.function_id, Some(FunctionId::PlaybackAck));
        assert_eq!(decoded.message_id, 42);
    }

    #[test]
    fn auto_decode_dispatches_request_vs_response() {
        // Request → 12 bytes, FunctionId present
        let req_bytes = encode_to_vec(&SharedMsgHeader::request(
            InterfaceValue::ServerData,
            0,
            FunctionId::OnNewPresentation,
        ));
        let mut r = ReadCursor::new(&req_bytes);
        let h = decode_header_auto(&mut r).unwrap();
        assert_eq!(h.function_id, Some(FunctionId::OnNewPresentation));
        assert_eq!(r.pos(), REQUEST_HEADER_SIZE);

        // Response → 8 bytes, FunctionId absent
        let rsp_bytes = encode_to_vec(&SharedMsgHeader::response(InterfaceValue::ServerData, 7));
        let mut r = ReadCursor::new(&rsp_bytes);
        let h = decode_header_auto(&mut r).unwrap();
        assert!(h.function_id.is_none());
        assert_eq!(h.message_id, 7);
        assert_eq!(r.pos(), RESPONSE_HEADER_SIZE);
    }

    #[test]
    fn decode_request_header_rejects_stub_mask() {
        // 8-byte response prefix with PROXY-style attempt → must fail
        // because the trailing FunctionId read will succeed on garbage.
        let bytes = [
            0x00, 0x00, 0x00, 0x80, // STUB
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x00, 0x00, 0x00, 0x00, // garbage fid
        ];
        let mut r = ReadCursor::new(&bytes);
        assert!(decode_request_header(&mut r).is_err());
    }

    #[test]
    fn decode_response_header_rejects_proxy_mask() {
        let bytes = [
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
        ];
        let mut r = ReadCursor::new(&bytes);
        assert!(decode_response_header(&mut r).is_err());
    }

    #[test]
    fn auto_decode_underflow() {
        let bytes = [0x00u8, 0x00, 0x00];
        let mut r = ReadCursor::new(&bytes);
        assert!(decode_header_auto(&mut r).is_err());
    }

    #[test]
    fn message_id_wraparound_roundtrip() {
        // u32 wrap-around in MessageId is legal -- the spec does not
        // forbid it and the correlation table must handle it. Verify
        // that 0xFFFFFFFF round-trips cleanly.
        let h = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            0xFFFF_FFFF,
            FunctionId::SetChannelParams,
        );
        let bytes = encode_to_vec(&h);
        let mut r = ReadCursor::new(&bytes);
        let decoded = decode_request_header(&mut r).unwrap();
        assert_eq!(decoded.message_id, 0xFFFF_FFFF);
    }

    #[test]
    fn unknown_function_id_preserved_round_trip() {
        // The dispatch layer uses FunctionId::Other for forward-compat;
        // the encode side should write the original raw bytes back.
        let h = SharedMsgHeader {
            interface_value: InterfaceValue::Other(0x12),
            mask: Mask::Proxy,
            message_id: 1,
            function_id: Some(FunctionId::Other {
                interface_value: 0x12,
                function_id: 0xCAFEBABE,
            }),
        };
        let bytes = encode_to_vec(&h);
        let mut r = ReadCursor::new(&bytes);
        let decoded = decode_request_header(&mut r).unwrap();
        assert_eq!(
            decoded.function_id,
            Some(FunctionId::Other {
                interface_value: 0x12,
                function_id: 0xCAFEBABE,
            })
        );
    }

    #[test]
    fn known_constant_values_match_spec() {
        // Sanity: catch typos in the constant table.
        assert_eq!(f::SET_CHANNEL_PARAMS, 0x101);
        assert_eq!(f::ON_SAMPLE, 0x103);
        assert_eq!(f::ON_NEW_PRESENTATION, 0x105);
        assert_eq!(f::CHECK_FORMAT_SUPPORT_REQ, 0x108);
        assert_eq!(f::SET_SOURCE_VIDEO_RECT, 0x116);
        assert_eq!(f::PLAYBACK_ACK, 0x100);
        assert_eq!(SERVER_DATA, 0);
        assert_eq!(CLIENT_NOTIFICATIONS, 1);
    }
}
