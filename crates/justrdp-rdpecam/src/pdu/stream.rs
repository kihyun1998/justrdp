//! Stream enumeration and media-type negotiation PDUs (MS-RDPECAM §2.2.3.5
//! – §2.2.3.10).
//!
//! These messages drive the per-device channel from the moment the camera
//! is activated up to the point the server knows which streams exist and
//! which format each stream will produce:
//!
//! - [`StreamListRequest`] / [`StreamListResponse`]   -- discover streams
//! - [`MediaTypeListRequest`] / [`MediaTypeListResponse`] -- enumerate formats
//! - [`CurrentMediaTypeRequest`] / [`CurrentMediaTypeResponse`] -- query the
//!   format the client would use if streaming started right now
//!
//! The three `*Response` PDUs are variable-length arrays with no count
//! prefix: the wire encoding relies on the DVC framework to hand the
//! decoder the exact message payload, and the element count is derived
//! from `(payload_len - 2) / element_size`. `(payload_len - 2) %
//! element_size != 0` is a protocol error (spec §8 validation rule).

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{
    MSG_CURRENT_MEDIA_TYPE_REQUEST, MSG_CURRENT_MEDIA_TYPE_RESPONSE, MSG_MEDIA_TYPE_LIST_REQUEST,
    MSG_MEDIA_TYPE_LIST_RESPONSE, MSG_STREAM_LIST_REQUEST, MSG_STREAM_LIST_RESPONSE,
};
use crate::pdu::header::{decode_header, encode_header, expect_message_id, HEADER_SIZE};

// ── Safety caps (checklist §10) ──

/// Maximum number of streams a client may advertise per camera device.
///
/// Real cameras ship 1–4 streams; 32 is a comfortable ceiling that still
/// bounds decode-time allocation against a malicious peer.
pub const MAX_STREAMS: usize = 32;

/// Maximum number of media types advertised per stream.
///
/// Prevents OOM from a peer claiming an unbounded format list.
pub const MAX_MEDIA_TYPES_PER_STREAM: usize = 512;

// ── MediaFormat (§2.2.3.8.1 / checklist §5.1) ──

/// `Format` byte of `MEDIA_TYPE_DESCRIPTION`. Unknown values decode as
/// [`MediaFormat::Other`] so the decoder is forward-compatible with future
/// codec additions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaFormat {
    H264,
    Mjpg,
    Yuy2,
    Nv12,
    I420,
    Rgb24,
    Rgb32,
    Other(u8),
}

impl MediaFormat {
    pub const H264_RAW: u8 = 0x01;
    pub const MJPG_RAW: u8 = 0x02;
    pub const YUY2_RAW: u8 = 0x03;
    pub const NV12_RAW: u8 = 0x04;
    pub const I420_RAW: u8 = 0x05;
    pub const RGB24_RAW: u8 = 0x06;
    pub const RGB32_RAW: u8 = 0x07;

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            Self::H264_RAW => Self::H264,
            Self::MJPG_RAW => Self::Mjpg,
            Self::YUY2_RAW => Self::Yuy2,
            Self::NV12_RAW => Self::Nv12,
            Self::I420_RAW => Self::I420,
            Self::RGB24_RAW => Self::Rgb24,
            Self::RGB32_RAW => Self::Rgb32,
            other => Self::Other(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::H264 => Self::H264_RAW,
            Self::Mjpg => Self::MJPG_RAW,
            Self::Yuy2 => Self::YUY2_RAW,
            Self::Nv12 => Self::NV12_RAW,
            Self::I420 => Self::I420_RAW,
            Self::Rgb24 => Self::RGB24_RAW,
            Self::Rgb32 => Self::RGB32_RAW,
            Self::Other(raw) => raw,
        }
    }
}

// ── FrameSourceTypes (§2.2.3.6.1 / checklist §5.2) ──

/// `FrameSourceTypes` u16 LE bitmask on [`StreamDescription`].
pub mod frame_source_types {
    pub const COLOR: u16 = 0x0001;
    pub const INFRARED: u16 = 0x0002;
    pub const CUSTOM: u16 = 0x0008;
    /// Union of all bits the spec currently defines.
    pub const KNOWN: u16 = COLOR | INFRARED | CUSTOM;
}

// ── StreamCategory (§2.2.3.6.1 / checklist §5.3) ──

/// Only `Capture` is defined in the published spec; callers should accept
/// unknown values and pass them through so an old client does not reject a
/// stream category the spec may add later.
pub const STREAM_CATEGORY_CAPTURE: u8 = 0x01;

// ── MediaTypeFlags (§2.2.3.8.1 / checklist §5.4) ──

/// `Flags` byte of [`MediaTypeDescription`].
pub mod media_type_flags {
    pub const DECODING_REQUIRED: u8 = 0x01;
    pub const BOTTOM_UP_IMAGE: u8 = 0x02;
    pub const KNOWN: u8 = DECODING_REQUIRED | BOTTOM_UP_IMAGE;
}

// ── StreamDescription (§2.2.3.6.1) — 5 bytes fixed ──

/// Describes one stream produced by a camera device. Stream index is its
/// 0-based position inside [`StreamListResponse::streams`]; later PDUs
/// reference streams by index, never by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDescription {
    /// Bitmask -- see [`frame_source_types`].
    pub frame_source_types: u16,
    pub stream_category: u8,
    /// `1` if this stream is currently selected by the client, `0` otherwise.
    pub selected: u8,
    /// `1` if the stream can be shared across multiple consumers.
    pub can_be_shared: u8,
}

impl StreamDescription {
    /// Wire size of a single `STREAM_DESCRIPTION`.
    pub const WIRE_SIZE: usize = 5;

    fn encode(&self, dst: &mut WriteCursor<'_>, ctx: &'static str) -> EncodeResult<()> {
        dst.write_u16_le(self.frame_source_types, ctx)?;
        dst.write_u8(self.stream_category, ctx)?;
        dst.write_u8(self.selected, ctx)?;
        dst.write_u8(self.can_be_shared, ctx)?;
        Ok(())
    }

    fn decode(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<Self> {
        Ok(Self {
            frame_source_types: src.read_u16_le(ctx)?,
            stream_category: src.read_u8(ctx)?,
            selected: src.read_u8(ctx)?,
            can_be_shared: src.read_u8(ctx)?,
        })
    }
}

// ── MediaTypeDescription (§2.2.3.8.1) — 26 bytes fixed ──

/// Full description of a single media type advertised by a stream.
///
/// The decoder preserves unknown `format` values via [`MediaFormat::Other`]
/// so a future spec version is not rejected out of hand, but it DOES
/// enforce one structural invariant: `frame_rate_denominator != 0`
/// (spec §8 validation rule; division by zero would otherwise poison
/// anyone computing the effective frame rate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaTypeDescription {
    pub format: MediaFormat,
    pub width: u32,
    pub height: u32,
    pub frame_rate_numerator: u32,
    pub frame_rate_denominator: u32,
    pub pixel_aspect_ratio_numerator: u32,
    pub pixel_aspect_ratio_denominator: u32,
    /// Bitmask -- see [`media_type_flags`].
    pub flags: u8,
}

impl MediaTypeDescription {
    /// Wire size of a single `MEDIA_TYPE_DESCRIPTION`.
    pub const WIRE_SIZE: usize = 26;

    pub(crate) fn encode_inner(
        &self,
        dst: &mut WriteCursor<'_>,
        ctx: &'static str,
    ) -> EncodeResult<()> {
        if self.frame_rate_denominator == 0 {
            return Err(EncodeError::invalid_value(ctx, "frame_rate_denominator == 0"));
        }
        if self.pixel_aspect_ratio_denominator == 0 {
            return Err(EncodeError::invalid_value(
                ctx,
                "pixel_aspect_ratio_denominator == 0",
            ));
        }
        dst.write_u8(self.format.to_u8(), ctx)?;
        dst.write_u32_le(self.width, ctx)?;
        dst.write_u32_le(self.height, ctx)?;
        dst.write_u32_le(self.frame_rate_numerator, ctx)?;
        dst.write_u32_le(self.frame_rate_denominator, ctx)?;
        dst.write_u32_le(self.pixel_aspect_ratio_numerator, ctx)?;
        dst.write_u32_le(self.pixel_aspect_ratio_denominator, ctx)?;
        dst.write_u8(self.flags, ctx)?;
        Ok(())
    }

    pub(crate) fn decode_inner(
        src: &mut ReadCursor<'_>,
        ctx: &'static str,
    ) -> DecodeResult<Self> {
        let format = MediaFormat::from_u8(src.read_u8(ctx)?);
        let width = src.read_u32_le(ctx)?;
        let height = src.read_u32_le(ctx)?;
        let frame_rate_numerator = src.read_u32_le(ctx)?;
        let frame_rate_denominator = src.read_u32_le(ctx)?;
        if frame_rate_denominator == 0 {
            return Err(DecodeError::invalid_value(ctx, "frame_rate_denominator == 0"));
        }
        let pixel_aspect_ratio_numerator = src.read_u32_le(ctx)?;
        let pixel_aspect_ratio_denominator = src.read_u32_le(ctx)?;
        // Mirror the frame-rate guard above: a zero denominator would
        // make every downstream consumer that computes the effective
        // pixel aspect ratio panic on debug builds or wrap silently in
        // release, turning a server-controlled byte into a remotely
        // triggerable client defect.
        if pixel_aspect_ratio_denominator == 0 {
            return Err(DecodeError::invalid_value(
                ctx,
                "pixel_aspect_ratio_denominator == 0",
            ));
        }
        let flags = src.read_u8(ctx)?;
        Ok(Self {
            format,
            width,
            height,
            frame_rate_numerator,
            frame_rate_denominator,
            pixel_aspect_ratio_numerator,
            pixel_aspect_ratio_denominator,
            flags,
        })
    }
}

// ── StreamListRequest (§2.2.3.5) — 2 bytes fixed ──

/// Server asks the client to describe its streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamListRequest {
    pub version: u8,
}

impl StreamListRequest {
    pub const WIRE_SIZE: usize = HEADER_SIZE;

    pub fn new(version: u8) -> Self {
        Self { version }
    }
}

impl Encode for StreamListRequest {
    fn name(&self) -> &'static str {
        "CAM::StreamListRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        encode_header(dst, self.version, MSG_STREAM_LIST_REQUEST, self.name())
    }
}

impl<'de> Decode<'de> for StreamListRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::StreamListRequest";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_STREAM_LIST_REQUEST, CTX)?;
        Ok(Self { version })
    }
}

// ── StreamListResponse (§2.2.3.6) — variable ──

/// Client's reply carrying the enumeration of streams on this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamListResponse {
    pub version: u8,
    pub streams: Vec<StreamDescription>,
}

impl StreamListResponse {
    fn wire_size(&self) -> usize {
        HEADER_SIZE + self.streams.len() * StreamDescription::WIRE_SIZE
    }
}

impl Encode for StreamListResponse {
    fn name(&self) -> &'static str {
        "CAM::StreamListResponse"
    }

    fn size(&self) -> usize {
        self.wire_size()
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::StreamListResponse";
        if self.streams.len() > MAX_STREAMS {
            return Err(EncodeError::invalid_value(CTX, "streams.len() > MAX_STREAMS"));
        }
        encode_header(dst, self.version, MSG_STREAM_LIST_RESPONSE, CTX)?;
        for s in &self.streams {
            s.encode(dst, CTX)?;
        }
        Ok(())
    }
}

impl<'de> Decode<'de> for StreamListResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::StreamListResponse";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_STREAM_LIST_RESPONSE, CTX)?;
        let remaining = src.remaining();
        if remaining % StreamDescription::WIRE_SIZE != 0 {
            return Err(DecodeError::invalid_value(
                CTX,
                "payload length not a multiple of 5",
            ));
        }
        let count = remaining / StreamDescription::WIRE_SIZE;
        if count > MAX_STREAMS {
            return Err(DecodeError::invalid_value(CTX, "stream count > MAX_STREAMS"));
        }
        let mut streams = Vec::with_capacity(count);
        for _ in 0..count {
            streams.push(StreamDescription::decode(src, CTX)?);
        }
        Ok(Self { version, streams })
    }
}

// ── MediaTypeListRequest (§2.2.3.7) — 3 bytes fixed ──

/// Server asks the client for every media type the given stream supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaTypeListRequest {
    pub version: u8,
    pub stream_index: u8,
}

impl MediaTypeListRequest {
    pub const WIRE_SIZE: usize = HEADER_SIZE + 1;

    pub fn new(version: u8, stream_index: u8) -> Self {
        Self { version, stream_index }
    }
}

impl Encode for MediaTypeListRequest {
    fn name(&self) -> &'static str {
        "CAM::MediaTypeListRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::MediaTypeListRequest";
        encode_header(dst, self.version, MSG_MEDIA_TYPE_LIST_REQUEST, CTX)?;
        dst.write_u8(self.stream_index, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for MediaTypeListRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::MediaTypeListRequest";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_MEDIA_TYPE_LIST_REQUEST, CTX)?;
        let stream_index = src.read_u8(CTX)?;
        Ok(Self { version, stream_index })
    }
}

// ── MediaTypeListResponse (§2.2.3.8) — variable ──

/// Client's reply carrying every media type the stream supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaTypeListResponse {
    pub version: u8,
    pub media_types: Vec<MediaTypeDescription>,
}

impl MediaTypeListResponse {
    fn wire_size(&self) -> usize {
        HEADER_SIZE + self.media_types.len() * MediaTypeDescription::WIRE_SIZE
    }
}

impl Encode for MediaTypeListResponse {
    fn name(&self) -> &'static str {
        "CAM::MediaTypeListResponse"
    }

    fn size(&self) -> usize {
        self.wire_size()
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::MediaTypeListResponse";
        if self.media_types.len() > MAX_MEDIA_TYPES_PER_STREAM {
            return Err(EncodeError::invalid_value(CTX, "media_types.len() cap"));
        }
        encode_header(dst, self.version, MSG_MEDIA_TYPE_LIST_RESPONSE, CTX)?;
        for m in &self.media_types {
            m.encode_inner(dst, CTX)?;
        }
        Ok(())
    }
}

impl<'de> Decode<'de> for MediaTypeListResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::MediaTypeListResponse";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_MEDIA_TYPE_LIST_RESPONSE, CTX)?;
        let remaining = src.remaining();
        if remaining % MediaTypeDescription::WIRE_SIZE != 0 {
            return Err(DecodeError::invalid_value(
                CTX,
                "payload length not a multiple of 26",
            ));
        }
        let count = remaining / MediaTypeDescription::WIRE_SIZE;
        if count > MAX_MEDIA_TYPES_PER_STREAM {
            return Err(DecodeError::invalid_value(
                CTX,
                "media type count > cap",
            ));
        }
        let mut media_types = Vec::with_capacity(count);
        for _ in 0..count {
            media_types.push(MediaTypeDescription::decode_inner(src, CTX)?);
        }
        Ok(Self { version, media_types })
    }
}

// ── CurrentMediaTypeRequest (§2.2.3.9) — 3 bytes fixed ──

/// Server asks for the media type the named stream would produce right
/// now. Format identical to [`MediaTypeListRequest`] except for MessageId.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentMediaTypeRequest {
    pub version: u8,
    pub stream_index: u8,
}

impl CurrentMediaTypeRequest {
    pub const WIRE_SIZE: usize = HEADER_SIZE + 1;

    pub fn new(version: u8, stream_index: u8) -> Self {
        Self { version, stream_index }
    }
}

impl Encode for CurrentMediaTypeRequest {
    fn name(&self) -> &'static str {
        "CAM::CurrentMediaTypeRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::CurrentMediaTypeRequest";
        encode_header(dst, self.version, MSG_CURRENT_MEDIA_TYPE_REQUEST, CTX)?;
        dst.write_u8(self.stream_index, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for CurrentMediaTypeRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::CurrentMediaTypeRequest";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_CURRENT_MEDIA_TYPE_REQUEST, CTX)?;
        let stream_index = src.read_u8(CTX)?;
        Ok(Self { version, stream_index })
    }
}

// ── CurrentMediaTypeResponse (§2.2.3.10) — 28 bytes fixed ──

/// Client reply with the current media type for the requested stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentMediaTypeResponse {
    pub version: u8,
    pub media_type: MediaTypeDescription,
}

impl CurrentMediaTypeResponse {
    pub const WIRE_SIZE: usize = HEADER_SIZE + MediaTypeDescription::WIRE_SIZE;

    pub fn new(version: u8, media_type: MediaTypeDescription) -> Self {
        Self { version, media_type }
    }
}

impl Encode for CurrentMediaTypeResponse {
    fn name(&self) -> &'static str {
        "CAM::CurrentMediaTypeResponse"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::CurrentMediaTypeResponse";
        encode_header(dst, self.version, MSG_CURRENT_MEDIA_TYPE_RESPONSE, CTX)?;
        self.media_type.encode_inner(dst, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for CurrentMediaTypeResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::CurrentMediaTypeResponse";
        let (version, message_id) = decode_header(src, CTX)?;
        expect_message_id(message_id, MSG_CURRENT_MEDIA_TYPE_RESPONSE, CTX)?;
        let media_type = MediaTypeDescription::decode_inner(src, CTX)?;
        Ok(Self { version, media_type })
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::VERSION_2;

    fn encode<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = alloc::vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        assert_eq!(w.pos(), pdu.size(), "size() != encoded");
        buf
    }

    // ── MediaFormat ──

    #[test]
    fn media_format_roundtrip_all_known() {
        for raw in 0x01u8..=0x07 {
            assert_eq!(MediaFormat::from_u8(raw).to_u8(), raw);
        }
    }

    #[test]
    fn media_format_preserves_unknown() {
        assert_eq!(MediaFormat::from_u8(0xFE), MediaFormat::Other(0xFE));
        assert_eq!(MediaFormat::Other(0xFE).to_u8(), 0xFE);
    }

    // ── StreamDescription / StreamListResponse ──

    #[test]
    fn stream_list_response_spec_sample() {
        // Spec §4.4.4: `02 0a 01 00 01 01 01 01 00 01 00 01`
        // 2 streams, Color category, stream[0] Selected=1, stream[1] Selected=0.
        let bytes: [u8; 12] = [
            0x02, 0x0a,
            0x01, 0x00, 0x01, 0x01, 0x01,
            0x01, 0x00, 0x01, 0x00, 0x01,
        ];
        let mut r = ReadCursor::new(&bytes);
        let pdu = StreamListResponse::decode(&mut r).unwrap();
        assert_eq!(pdu.version, VERSION_2);
        assert_eq!(pdu.streams.len(), 2);
        assert_eq!(pdu.streams[0].frame_source_types, frame_source_types::COLOR);
        assert_eq!(pdu.streams[0].stream_category, STREAM_CATEGORY_CAPTURE);
        assert_eq!(pdu.streams[0].selected, 1);
        assert_eq!(pdu.streams[0].can_be_shared, 1);
        assert_eq!(pdu.streams[1].selected, 0);
        // Roundtrip.
        assert_eq!(encode(&pdu), bytes);
    }

    #[test]
    fn stream_list_response_zero_streams() {
        let pdu = StreamListResponse {
            version: VERSION_2,
            streams: Vec::new(),
        };
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x02, 0x0a]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(StreamListResponse::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn stream_list_response_rejects_odd_payload_length() {
        // Header + 3 bytes -- not a multiple of 5.
        let bytes = [0x02u8, 0x0a, 0x00, 0x00, 0x00];
        let mut r = ReadCursor::new(&bytes);
        assert!(StreamListResponse::decode(&mut r).is_err());
    }

    #[test]
    fn stream_list_response_rejects_count_over_cap() {
        // Header + (MAX_STREAMS + 1) × 5 zero bytes.
        let mut bytes: Vec<u8> = alloc::vec![0x02, 0x0a];
        bytes.extend(core::iter::repeat_n(0u8, (MAX_STREAMS + 1) * 5));
        let mut r = ReadCursor::new(&bytes);
        assert!(StreamListResponse::decode(&mut r).is_err());
    }

    #[test]
    fn stream_list_response_accepts_count_at_cap() {
        let pdu = StreamListResponse {
            version: VERSION_2,
            streams: alloc::vec![StreamDescription {
                frame_source_types: frame_source_types::COLOR,
                stream_category: STREAM_CATEGORY_CAPTURE,
                selected: 1,
                can_be_shared: 0,
            }; MAX_STREAMS],
        };
        let bytes = encode(&pdu);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(StreamListResponse::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn stream_list_request_roundtrip() {
        let pdu = StreamListRequest::new(VERSION_2);
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x02, 0x09]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(StreamListRequest::decode(&mut r).unwrap(), pdu);
    }

    // ── MediaTypeDescription / MediaTypeListResponse ──

    fn spec_h264_1920x1080_30fps() -> MediaTypeDescription {
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
    fn media_type_list_response_spec_sample_4_entries() {
        // Spec §4.4.6: 4 H264 entries at 640x480, 800x600, 1280x720, 1920x1080.
        let pdu = MediaTypeListResponse {
            version: VERSION_2,
            media_types: alloc::vec![
                MediaTypeDescription {
                    format: MediaFormat::H264,
                    width: 640,
                    height: 480,
                    frame_rate_numerator: 30,
                    frame_rate_denominator: 1,
                    pixel_aspect_ratio_numerator: 1,
                    pixel_aspect_ratio_denominator: 1,
                    flags: media_type_flags::DECODING_REQUIRED,
                },
                MediaTypeDescription {
                    format: MediaFormat::H264,
                    width: 800,
                    height: 600,
                    frame_rate_numerator: 30,
                    frame_rate_denominator: 1,
                    pixel_aspect_ratio_numerator: 1,
                    pixel_aspect_ratio_denominator: 1,
                    flags: media_type_flags::DECODING_REQUIRED,
                },
                MediaTypeDescription {
                    format: MediaFormat::H264,
                    width: 1280,
                    height: 720,
                    frame_rate_numerator: 30,
                    frame_rate_denominator: 1,
                    pixel_aspect_ratio_numerator: 1,
                    pixel_aspect_ratio_denominator: 1,
                    flags: media_type_flags::DECODING_REQUIRED,
                },
                spec_h264_1920x1080_30fps(),
            ],
        };
        let bytes = encode(&pdu);
        // 2 (header) + 4 * 26 = 106 bytes.
        assert_eq!(bytes.len(), 2 + 4 * 26);
        assert_eq!(&bytes[..2], &[0x02, 0x0c]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(MediaTypeListResponse::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn media_type_list_response_zero_entries() {
        let pdu = MediaTypeListResponse {
            version: VERSION_2,
            media_types: Vec::new(),
        };
        assert_eq!(encode(&pdu), [0x02, 0x0c]);
    }

    #[test]
    fn media_type_list_response_rejects_partial_element() {
        // Header + 25 bytes -- 25 % 26 != 0.
        let mut bytes: Vec<u8> = alloc::vec![0x02, 0x0c];
        bytes.extend(core::iter::repeat_n(0u8, 25));
        let mut r = ReadCursor::new(&bytes);
        assert!(MediaTypeListResponse::decode(&mut r).is_err());
    }

    #[test]
    fn media_type_description_encode_rejects_zero_denominator() {
        let bad = MediaTypeDescription {
            format: MediaFormat::Yuy2,
            width: 640,
            height: 480,
            frame_rate_numerator: 30,
            frame_rate_denominator: 0,
            pixel_aspect_ratio_numerator: 1,
            pixel_aspect_ratio_denominator: 1,
            flags: 0,
        };
        let mut buf: Vec<u8> = alloc::vec![0u8; MediaTypeDescription::WIRE_SIZE];
        let mut w = WriteCursor::new(&mut buf);
        assert!(bad.encode_inner(&mut w, "test").is_err());
    }

    #[test]
    fn media_type_description_encode_rejects_zero_pixel_aspect_ratio_denominator() {
        let bad = MediaTypeDescription {
            format: MediaFormat::Yuy2,
            width: 640,
            height: 480,
            frame_rate_numerator: 30,
            frame_rate_denominator: 1,
            pixel_aspect_ratio_numerator: 1,
            pixel_aspect_ratio_denominator: 0,
            flags: 0,
        };
        let mut buf: Vec<u8> = alloc::vec![0u8; MediaTypeDescription::WIRE_SIZE];
        let mut w = WriteCursor::new(&mut buf);
        assert!(bad.encode_inner(&mut w, "test").is_err());
    }

    #[test]
    fn media_type_description_decode_rejects_zero_pixel_aspect_ratio_denominator() {
        let mut buf: Vec<u8> = alloc::vec![0u8; MediaTypeDescription::WIRE_SIZE];
        buf[0] = MediaFormat::H264_RAW;
        buf[1..5].copy_from_slice(&640u32.to_le_bytes());
        buf[5..9].copy_from_slice(&480u32.to_le_bytes());
        buf[9..13].copy_from_slice(&30u32.to_le_bytes());
        buf[13..17].copy_from_slice(&1u32.to_le_bytes());
        buf[17..21].copy_from_slice(&1u32.to_le_bytes());
        buf[21..25].copy_from_slice(&0u32.to_le_bytes()); // zero PAR denom
        buf[25] = 0;
        let mut r = ReadCursor::new(&buf);
        assert!(MediaTypeDescription::decode_inner(&mut r, "test").is_err());
    }

    #[test]
    fn media_type_description_decode_rejects_zero_denominator() {
        // Valid layout but frame_rate_denominator = 0.
        let mut buf: Vec<u8> = alloc::vec![0u8; MediaTypeDescription::WIRE_SIZE];
        buf[0] = MediaFormat::H264_RAW;
        buf[1..5].copy_from_slice(&640u32.to_le_bytes());
        buf[5..9].copy_from_slice(&480u32.to_le_bytes());
        buf[9..13].copy_from_slice(&30u32.to_le_bytes());
        buf[13..17].copy_from_slice(&0u32.to_le_bytes());
        buf[17..21].copy_from_slice(&1u32.to_le_bytes());
        buf[21..25].copy_from_slice(&1u32.to_le_bytes());
        buf[25] = 0;
        let mut r = ReadCursor::new(&buf);
        assert!(MediaTypeDescription::decode_inner(&mut r, "test").is_err());
    }

    #[test]
    fn media_type_list_request_roundtrip() {
        let pdu = MediaTypeListRequest::new(VERSION_2, 3);
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x02, 0x0b, 0x03]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(MediaTypeListRequest::decode(&mut r).unwrap(), pdu);
    }

    // ── CurrentMediaType Req/Resp ──

    #[test]
    fn current_media_type_request_roundtrip() {
        let pdu = CurrentMediaTypeRequest::new(VERSION_2, 0);
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x02, 0x0d, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(CurrentMediaTypeRequest::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn current_media_type_response_roundtrip() {
        let pdu = CurrentMediaTypeResponse::new(VERSION_2, spec_h264_1920x1080_30fps());
        let bytes = encode(&pdu);
        assert_eq!(bytes.len(), CurrentMediaTypeResponse::WIRE_SIZE);
        assert_eq!(&bytes[..2], &[0x02, 0x0e]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(CurrentMediaTypeResponse::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn current_media_type_response_rejects_wrong_message_id() {
        let mut bytes: Vec<u8> = alloc::vec![0x02, 0x0c];
        bytes.extend(core::iter::repeat_n(0u8, 26));
        // Fix the denominator so a later step does not fail earlier for a
        // different reason.
        bytes[2 + 13..2 + 17].copy_from_slice(&1u32.to_le_bytes());
        let mut r = ReadCursor::new(&bytes);
        assert!(CurrentMediaTypeResponse::decode(&mut r).is_err());
    }
}
