//! Generic device-channel responses (MS-RDPECAM §2.2.3.1 / §2.2.3.2).
//!
//! [`SuccessResponse`] and [`ErrorResponse`] are the two terminal answers a
//! client sends on the per-device DVC in response to any server request
//! that expects an acknowledgement (Activate, Deactivate, StartStreams,
//! StopStreams, SetPropertyValue). Device activation and stream-list PDUs
//! will live alongside them in Group 2B.

use justrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use crate::constants::{
    ErrorCode, MSG_ACTIVATE_DEVICE_REQUEST, MSG_DEACTIVATE_DEVICE_REQUEST, MSG_ERROR_RESPONSE,
    MSG_SUCCESS_RESPONSE,
};
use crate::pdu::header::{decode_header, encode_header, expect_message_id, HEADER_SIZE};

// ── SuccessResponse (§2.2.3.1) — 2 bytes fixed ──

/// Acknowledges a server request that completed successfully.
///
/// The body is empty; only the 2-byte `SHARED_MSG_HEADER` appears on the
/// wire. `version` is stored so that a round-trip is byte-exact regardless
/// of whether the negotiated version was 1 or 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuccessResponse {
    pub version: u8,
}

impl SuccessResponse {
    /// Wire size of the fixed-format `SuccessResponse` PDU.
    pub const WIRE_SIZE: usize = HEADER_SIZE;

    pub fn new(version: u8) -> Self {
        Self { version }
    }
}

impl Encode for SuccessResponse {
    fn name(&self) -> &'static str {
        "CAM::SuccessResponse"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        encode_header(dst, self.version, MSG_SUCCESS_RESPONSE, self.name())
    }
}

impl<'de> Decode<'de> for SuccessResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::SuccessResponse";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_SUCCESS_RESPONSE, CTX)?;
        Ok(Self { version })
    }
}

// ── ErrorResponse (§2.2.3.2) — 6 bytes fixed ──

/// Reports a protocol or runtime error for a prior device-channel request.
///
/// Wire layout is `version (1) | message_id (1) | error_code (u32 LE)`.
/// [`ErrorCode::Other`] preserves raw unknown values across round-trips so
/// future spec additions do not cause this decoder to spuriously reject a
/// message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorResponse {
    pub version: u8,
    pub error_code: ErrorCode,
}

impl ErrorResponse {
    /// Wire size of the fixed-format `ErrorResponse` PDU.
    pub const WIRE_SIZE: usize = HEADER_SIZE + 4;

    pub fn new(version: u8, error_code: ErrorCode) -> Self {
        Self { version, error_code }
    }
}

impl Encode for ErrorResponse {
    fn name(&self) -> &'static str {
        "CAM::ErrorResponse"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        encode_header(dst, self.version, MSG_ERROR_RESPONSE, self.name())?;
        dst.write_u32_le(self.error_code.to_u32(), self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for ErrorResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::ErrorResponse";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_ERROR_RESPONSE, CTX)?;
        let raw = src.read_u32_le(CTX)?;
        Ok(Self {
            version,
            error_code: ErrorCode::from_u32(raw),
        })
    }
}

// ── ActivateDeviceRequest (§2.2.3.3) — 2 bytes fixed ──

/// Server asks the client to activate a camera device. The client answers
/// with [`SuccessResponse`] (on completion) or [`ErrorResponse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivateDeviceRequest {
    pub version: u8,
}

impl ActivateDeviceRequest {
    pub const WIRE_SIZE: usize = HEADER_SIZE;

    pub fn new(version: u8) -> Self {
        Self { version }
    }
}

impl Encode for ActivateDeviceRequest {
    fn name(&self) -> &'static str {
        "CAM::ActivateDeviceRequest"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        encode_header(dst, self.version, MSG_ACTIVATE_DEVICE_REQUEST, self.name())
    }
}

impl<'de> Decode<'de> for ActivateDeviceRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::ActivateDeviceRequest";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_ACTIVATE_DEVICE_REQUEST, CTX)?;
        Ok(Self { version })
    }
}

// ── DeactivateDeviceRequest (§2.2.3.4) — 2 bytes fixed ──

/// Server asks the client to deactivate a camera device. The client frees
/// its device resources only after sending [`SuccessResponse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeactivateDeviceRequest {
    pub version: u8,
}

impl DeactivateDeviceRequest {
    pub const WIRE_SIZE: usize = HEADER_SIZE;

    pub fn new(version: u8) -> Self {
        Self { version }
    }
}

impl Encode for DeactivateDeviceRequest {
    fn name(&self) -> &'static str {
        "CAM::DeactivateDeviceRequest"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        encode_header(dst, self.version, MSG_DEACTIVATE_DEVICE_REQUEST, self.name())
    }
}

impl<'de> Decode<'de> for DeactivateDeviceRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::DeactivateDeviceRequest";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_DEACTIVATE_DEVICE_REQUEST, CTX)?;
        Ok(Self { version })
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{VERSION_1, VERSION_2};
    use alloc::vec::Vec;

    fn encode<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = alloc::vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        assert_eq!(w.pos(), pdu.size(), "encode size mismatch for {}", pdu.name());
        buf
    }

    #[test]
    fn success_response_roundtrip_v1() {
        let pdu = SuccessResponse::new(VERSION_1);
        let bytes = encode(&pdu);
        assert_eq!(bytes, [VERSION_1, MSG_SUCCESS_RESPONSE]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(SuccessResponse::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn success_response_roundtrip_v2() {
        let pdu = SuccessResponse::new(VERSION_2);
        let bytes = encode(&pdu);
        assert_eq!(bytes, [VERSION_2, MSG_SUCCESS_RESPONSE]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(SuccessResponse::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn success_response_rejects_wrong_message_id() {
        let bytes = [VERSION_1, 0x02];
        let mut r = ReadCursor::new(&bytes);
        assert!(SuccessResponse::decode(&mut r).is_err());
    }

    #[test]
    fn error_response_roundtrip_known_codes() {
        for code in [
            ErrorCode::UnexpectedError,
            ErrorCode::InvalidMessage,
            ErrorCode::NotInitialized,
            ErrorCode::InvalidRequest,
            ErrorCode::InvalidStreamNumber,
            ErrorCode::InvalidMediaType,
            ErrorCode::OutOfMemory,
            ErrorCode::ItemNotFound,
            ErrorCode::SetNotFound,
            ErrorCode::OperationNotSupported,
        ] {
            let pdu = ErrorResponse::new(VERSION_2, code);
            let bytes = encode(&pdu);
            assert_eq!(bytes.len(), ErrorResponse::WIRE_SIZE);
            assert_eq!(bytes[0], VERSION_2);
            assert_eq!(bytes[1], MSG_ERROR_RESPONSE);
            assert_eq!(
                u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
                code.to_u32()
            );
            let mut r = ReadCursor::new(&bytes);
            assert_eq!(ErrorResponse::decode(&mut r).unwrap(), pdu);
        }
    }

    #[test]
    fn error_response_preserves_unknown_code() {
        // A future spec revision picks 0xDEADBEEF as a new error value.
        // Decoder must accept it as `Other(..)` and re-encode byte-identically.
        let bytes = [
            VERSION_2,
            MSG_ERROR_RESPONSE,
            0xEF,
            0xBE,
            0xAD,
            0xDE,
        ];
        let mut r = ReadCursor::new(&bytes);
        let decoded = ErrorResponse::decode(&mut r).unwrap();
        assert_eq!(decoded.error_code, ErrorCode::Other(0xDEAD_BEEF));
        assert_eq!(encode(&decoded), bytes);
    }

    #[test]
    fn error_response_rejects_wrong_message_id() {
        let bytes = [VERSION_2, 0x01, 0x00, 0x00, 0x00, 0x00];
        let mut r = ReadCursor::new(&bytes);
        assert!(ErrorResponse::decode(&mut r).is_err());
    }

    #[test]
    fn error_response_rejects_short_buffer() {
        // Only header bytes present -- u32 read must fail.
        let bytes = [VERSION_1, MSG_ERROR_RESPONSE];
        let mut r = ReadCursor::new(&bytes);
        assert!(ErrorResponse::decode(&mut r).is_err());
    }

    #[test]
    fn error_code_v2_only_classification() {
        assert!(!ErrorCode::UnexpectedError.is_v2_only());
        assert!(!ErrorCode::InvalidMessage.is_v2_only());
        assert!(ErrorCode::ItemNotFound.is_v2_only());
        assert!(ErrorCode::SetNotFound.is_v2_only());
        assert!(ErrorCode::OperationNotSupported.is_v2_only());
    }

    #[test]
    fn error_code_u32_roundtrip_all_known() {
        for raw in 0x01u32..=0x0A {
            assert_eq!(ErrorCode::from_u32(raw).to_u32(), raw);
        }
    }

    #[test]
    fn activate_device_request_roundtrip() {
        let pdu = ActivateDeviceRequest::new(VERSION_2);
        let bytes = encode(&pdu);
        assert_eq!(bytes, [VERSION_2, MSG_ACTIVATE_DEVICE_REQUEST]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(ActivateDeviceRequest::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn activate_device_request_rejects_wrong_message_id() {
        let bytes = [VERSION_2, 0x08];
        let mut r = ReadCursor::new(&bytes);
        assert!(ActivateDeviceRequest::decode(&mut r).is_err());
    }

    #[test]
    fn deactivate_device_request_roundtrip() {
        let pdu = DeactivateDeviceRequest::new(VERSION_1);
        let bytes = encode(&pdu);
        assert_eq!(bytes, [VERSION_1, MSG_DEACTIVATE_DEVICE_REQUEST]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(DeactivateDeviceRequest::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn deactivate_device_request_rejects_wrong_message_id() {
        let bytes = [VERSION_1, 0x07];
        let mut r = ReadCursor::new(&bytes);
        assert!(DeactivateDeviceRequest::decode(&mut r).is_err());
    }
}
