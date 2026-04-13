//! Sample capture PDUs (MS-RDPECAM §2.2.3.11 – §2.2.3.15):
//!
//! - [`StartStreamsRequest`] -- server tells the client which streams to run
//!   and in what format.
//! - [`StopStreamsRequest`]  -- stop every stream on the device.
//! - [`SampleRequest`]       -- server asks for one frame from a given stream.
//! - [`SampleResponse`]      -- client delivers the captured frame payload.
//! - [`SampleErrorResponse`] -- client returns an error instead of a sample.
//!
//! Per-frame flow is request/response: the server issues exactly one
//! `SampleRequest` at a time per stream, and the client replies with
//! exactly one `SampleResponse` or `SampleErrorResponse`. Unsolicited
//! sample responses are silently discarded (spec §8, last bullet).

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{
    ErrorCode, MSG_SAMPLE_ERROR_RESPONSE, MSG_SAMPLE_REQUEST, MSG_SAMPLE_RESPONSE,
    MSG_START_STREAMS_REQUEST, MSG_STOP_STREAMS_REQUEST,
};
use crate::pdu::header::{decode_header, encode_header, expect_message_id, HEADER_SIZE};
use crate::pdu::stream::{MediaTypeDescription, MAX_STREAMS};

// ── Safety caps (checklist §10) ──

/// Maximum accepted sample payload: 4 MiB.
///
/// Uncompressed 1920×1080 RGB32 is 8 MiB; H264/MJPG compressed frames for
/// the same resolution come in well under 4 MiB in practice. Capping at
/// 4 MiB keeps a hostile peer from pinning large buffers on the decode
/// side while still admitting every realistic camera.
pub const MAX_SAMPLE_BYTES: usize = 4 * 1024 * 1024;

// ── StartStreamInfo (§2.2.3.11.1) — 27 bytes each ──

/// One row of [`StartStreamsRequest::infos`]: a stream index plus the
/// exact `MEDIA_TYPE_DESCRIPTION` the server is instructing the client to
/// produce for that stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartStreamInfo {
    pub stream_index: u8,
    pub media_type: MediaTypeDescription,
}

impl StartStreamInfo {
    /// Wire size of a single `START_STREAM_INFO` (1 + 26).
    pub const WIRE_SIZE: usize = 1 + MediaTypeDescription::WIRE_SIZE;

    fn encode(&self, dst: &mut WriteCursor<'_>, ctx: &'static str) -> EncodeResult<()> {
        dst.write_u8(self.stream_index, ctx)?;
        self.media_type.encode_inner(dst, ctx)
    }

    fn decode(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<Self> {
        let stream_index = src.read_u8(ctx)?;
        let media_type = MediaTypeDescription::decode_inner(src, ctx)?;
        Ok(Self { stream_index, media_type })
    }
}

// ── StartStreamsRequest (§2.2.3.11) — variable ──

/// Server asks the client to begin producing samples for the listed
/// streams, each in a specific media type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartStreamsRequest {
    pub version: u8,
    pub infos: Vec<StartStreamInfo>,
}

impl StartStreamsRequest {
    fn wire_size(&self) -> usize {
        HEADER_SIZE + self.infos.len() * StartStreamInfo::WIRE_SIZE
    }
}

impl Encode for StartStreamsRequest {
    fn name(&self) -> &'static str {
        "CAM::StartStreamsRequest"
    }

    fn size(&self) -> usize {
        self.wire_size()
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::StartStreamsRequest";
        if self.infos.len() > MAX_STREAMS {
            return Err(EncodeError::invalid_value(CTX, "infos.len() > MAX_STREAMS"));
        }
        encode_header(dst, self.version, MSG_START_STREAMS_REQUEST, CTX)?;
        for info in &self.infos {
            info.encode(dst, CTX)?;
        }
        Ok(())
    }
}

impl<'de> Decode<'de> for StartStreamsRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::StartStreamsRequest";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_START_STREAMS_REQUEST, CTX)?;
        let remaining = src.remaining();
        if remaining % StartStreamInfo::WIRE_SIZE != 0 {
            return Err(DecodeError::invalid_value(
                CTX,
                "payload length not a multiple of 27",
            ));
        }
        let count = remaining / StartStreamInfo::WIRE_SIZE;
        if count > MAX_STREAMS {
            return Err(DecodeError::invalid_value(CTX, "info count > MAX_STREAMS"));
        }
        let mut infos = Vec::with_capacity(count);
        for _ in 0..count {
            infos.push(StartStreamInfo::decode(src, CTX)?);
        }
        Ok(Self { version, infos })
    }
}

// ── StopStreamsRequest (§2.2.3.12) — 2 bytes fixed ──

/// Stops every stream that is currently running on this device channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopStreamsRequest {
    pub version: u8,
}

impl StopStreamsRequest {
    pub const WIRE_SIZE: usize = HEADER_SIZE;

    pub fn new(version: u8) -> Self {
        Self { version }
    }
}

impl Encode for StopStreamsRequest {
    fn name(&self) -> &'static str {
        "CAM::StopStreamsRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        encode_header(dst, self.version, MSG_STOP_STREAMS_REQUEST, self.name())
    }
}

impl<'de> Decode<'de> for StopStreamsRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::StopStreamsRequest";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_STOP_STREAMS_REQUEST, CTX)?;
        Ok(Self { version })
    }
}

// ── SampleRequest (§2.2.3.13) — 3 bytes fixed ──

/// Server asks for exactly one sample from a given stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleRequest {
    pub version: u8,
    pub stream_index: u8,
}

impl SampleRequest {
    pub const WIRE_SIZE: usize = HEADER_SIZE + 1;

    pub fn new(version: u8, stream_index: u8) -> Self {
        Self { version, stream_index }
    }
}

impl Encode for SampleRequest {
    fn name(&self) -> &'static str {
        "CAM::SampleRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::SampleRequest";
        encode_header(dst, self.version, MSG_SAMPLE_REQUEST, CTX)?;
        dst.write_u8(self.stream_index, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for SampleRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::SampleRequest";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_SAMPLE_REQUEST, CTX)?;
        let stream_index = src.read_u8(CTX)?;
        Ok(Self { version, stream_index })
    }
}

// ── SampleResponse (§2.2.3.14) — variable ──

/// Delivers a single captured sample. `sample` is the opaque codec
/// payload; its interpretation depends on the `Format` selected via
/// [`StartStreamsRequest`].
///
/// The wire layout has no explicit length prefix for the sample itself --
/// the frame is everything after the 3-byte prefix. The DVC framework
/// hands the decoder a slice that is exactly one message long, so the
/// sample length is derived as `cursor.remaining()` after the header and
/// stream index have been consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleResponse {
    pub version: u8,
    pub stream_index: u8,
    pub sample: Vec<u8>,
}

impl SampleResponse {
    /// Minimum wire size (zero-length sample).
    pub const MIN_WIRE_SIZE: usize = HEADER_SIZE + 1;

    fn wire_size(&self) -> usize {
        Self::MIN_WIRE_SIZE + self.sample.len()
    }
}

impl Encode for SampleResponse {
    fn name(&self) -> &'static str {
        "CAM::SampleResponse"
    }

    fn size(&self) -> usize {
        self.wire_size()
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::SampleResponse";
        if self.sample.len() > MAX_SAMPLE_BYTES {
            return Err(EncodeError::invalid_value(CTX, "sample.len() > cap"));
        }
        encode_header(dst, self.version, MSG_SAMPLE_RESPONSE, CTX)?;
        dst.write_u8(self.stream_index, CTX)?;
        dst.write_slice(&self.sample, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for SampleResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::SampleResponse";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_SAMPLE_RESPONSE, CTX)?;
        let stream_index = src.read_u8(CTX)?;
        let len = src.remaining();
        if len > MAX_SAMPLE_BYTES {
            return Err(DecodeError::invalid_value(CTX, "sample length > cap"));
        }
        let slice = src.read_slice(len, CTX)?;
        Ok(Self {
            version,
            stream_index,
            sample: slice.to_vec(),
        })
    }
}

// ── SampleErrorResponse (§2.2.3.15) — 7 bytes fixed ──

/// Delivered instead of [`SampleResponse`] when capturing the frame failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleErrorResponse {
    pub version: u8,
    pub stream_index: u8,
    pub error_code: ErrorCode,
}

impl SampleErrorResponse {
    pub const WIRE_SIZE: usize = HEADER_SIZE + 1 + 4;

    pub fn new(version: u8, stream_index: u8, error_code: ErrorCode) -> Self {
        Self { version, stream_index, error_code }
    }
}

impl Encode for SampleErrorResponse {
    fn name(&self) -> &'static str {
        "CAM::SampleErrorResponse"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::SampleErrorResponse";
        encode_header(dst, self.version, MSG_SAMPLE_ERROR_RESPONSE, CTX)?;
        dst.write_u8(self.stream_index, CTX)?;
        dst.write_u32_le(self.error_code.to_u32(), CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for SampleErrorResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::SampleErrorResponse";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_SAMPLE_ERROR_RESPONSE, CTX)?;
        let stream_index = src.read_u8(CTX)?;
        let raw = src.read_u32_le(CTX)?;
        Ok(Self {
            version,
            stream_index,
            error_code: ErrorCode::from_u32(raw),
        })
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::VERSION_2;
    use crate::pdu::stream::{media_type_flags, MediaFormat};

    fn encode<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = alloc::vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        assert_eq!(w.pos(), pdu.size());
        buf
    }

    fn spec_h264_1920x1080() -> MediaTypeDescription {
        MediaTypeDescription {
            format: MediaFormat::H264,
            width: 1920,
            height: 1080,
            frame_rate_numerator: 30,
            frame_rate_denominator: 1,
            pixel_aspect_ratio_numerator: 1,
            pixel_aspect_ratio_denominator: 1,
            flags: media_type_flags::DECODING_REQUIRED,
        }
    }

    #[test]
    fn start_streams_request_spec_sample() {
        // Spec §4.5.1: single stream, index 0, H264 1920×1080@30fps, DecodingRequired.
        let pdu = StartStreamsRequest {
            version: VERSION_2,
            infos: alloc::vec![StartStreamInfo {
                stream_index: 0,
                media_type: spec_h264_1920x1080(),
            }],
        };
        let bytes = encode(&pdu);
        assert_eq!(bytes.len(), 2 + StartStreamInfo::WIRE_SIZE);
        assert_eq!(&bytes[..2], &[0x02, 0x0f]);
        assert_eq!(bytes[2], 0x00); // stream_index
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(StartStreamsRequest::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn start_streams_request_zero_infos() {
        let pdu = StartStreamsRequest {
            version: VERSION_2,
            infos: Vec::new(),
        };
        assert_eq!(encode(&pdu), [0x02, 0x0f]);
    }

    #[test]
    fn start_streams_rejects_partial_element() {
        // Header + 26 bytes (missing 1 byte for the trailing info row).
        let mut bytes: Vec<u8> = alloc::vec![0x02, 0x0f];
        bytes.extend(core::iter::repeat_n(0u8, 26));
        let mut r = ReadCursor::new(&bytes);
        assert!(StartStreamsRequest::decode(&mut r).is_err());
    }

    #[test]
    fn start_streams_rejects_over_cap() {
        let mut bytes: Vec<u8> = alloc::vec![0x02, 0x0f];
        bytes.extend(core::iter::repeat_n(
            0u8,
            (MAX_STREAMS + 1) * StartStreamInfo::WIRE_SIZE,
        ));
        let mut r = ReadCursor::new(&bytes);
        assert!(StartStreamsRequest::decode(&mut r).is_err());
    }

    #[test]
    fn stop_streams_request_roundtrip() {
        let pdu = StopStreamsRequest::new(VERSION_2);
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x02, 0x10]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(StopStreamsRequest::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn sample_request_roundtrip() {
        let pdu = SampleRequest::new(VERSION_2, 7);
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x02, 0x11, 0x07]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(SampleRequest::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn sample_response_roundtrip_nonempty() {
        let pdu = SampleResponse {
            version: VERSION_2,
            stream_index: 1,
            sample: alloc::vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x02, 0x12, 0x01, 0xDE, 0xAD, 0xBE, 0xEF]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(SampleResponse::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn sample_response_zero_length_sample_allowed() {
        let pdu = SampleResponse {
            version: VERSION_2,
            stream_index: 0,
            sample: Vec::new(),
        };
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x02, 0x12, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(SampleResponse::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn sample_response_encode_rejects_over_cap() {
        let pdu = SampleResponse {
            version: VERSION_2,
            stream_index: 0,
            sample: alloc::vec![0u8; MAX_SAMPLE_BYTES + 1],
        };
        let mut buf: Vec<u8> = alloc::vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        assert!(pdu.encode(&mut w).is_err());
    }

    #[test]
    fn sample_error_response_roundtrip() {
        let pdu = SampleErrorResponse::new(VERSION_2, 2, ErrorCode::InvalidStreamNumber);
        let bytes = encode(&pdu);
        assert_eq!(bytes.len(), SampleErrorResponse::WIRE_SIZE);
        assert_eq!(&bytes[..3], &[0x02, 0x13, 0x02]);
        assert_eq!(
            u32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]),
            ErrorCode::InvalidStreamNumber.to_u32()
        );
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(SampleErrorResponse::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn sample_error_response_preserves_unknown_code() {
        let pdu = SampleErrorResponse::new(VERSION_2, 0, ErrorCode::Other(0x1234_5678));
        let bytes = encode(&pdu);
        let mut r = ReadCursor::new(&bytes);
        let decoded = SampleErrorResponse::decode(&mut r).unwrap();
        assert_eq!(decoded.error_code, ErrorCode::Other(0x1234_5678));
    }
}
