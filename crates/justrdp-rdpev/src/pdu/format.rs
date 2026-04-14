//! Format negotiation PDUs and the `TS_AM_MEDIA_TYPE` substructure
//! (MS-RDPEV §2.2.7, §2.2.5.2.2, §2.2.5.2.3).
//!
//! `TS_AM_MEDIA_TYPE` is the DirectShow-derived format descriptor that
//! every TSMF-carried stream announces. The 64-byte fixed header
//! contains three GUIDs (`MajorType`, `SubType`, `FormatType`) plus
//! flags and a sample-size hint, followed by an opaque format blob
//! (`pbFormat`) whose interpretation depends on `FormatType` (typically
//! a `WAVEFORMATEX` for audio or a `VIDEOINFOHEADER` for video).
//!
//! [`CheckFormatSupportReq`] / [`CheckFormatSupportRsp`] is the second
//! request/response pair in the TSMF protocol that needs MessageId
//! correlation: the server may pipeline several format checks with
//! different ids before reading the answers, so the host dispatch
//! layer keeps a small `MessageId → expected response` table.
//!
//! ## DoS cap (checklist §10)
//!
//! [`MAX_FORMAT_BYTES`] (64 KiB) bounds the `pbFormat` blob. All
//! standard DirectShow format types are well under 1 KiB; the cap is
//! generous headroom that still bounds decode-time allocation.

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{FunctionId, InterfaceValue, Mask};
use crate::pdu::guid::{decode_guid, encode_guid, Guid};
use crate::pdu::header::{
    decode_request_header, decode_response_header, encode_header, SharedMsgHeader,
    REQUEST_HEADER_SIZE, RESPONSE_HEADER_SIZE,
};

// ── DoS cap (checklist §10) ─────────────────────────────────────────

/// Maximum bytes in a `TS_AM_MEDIA_TYPE.pbFormat` blob.
///
/// All standard DirectShow format types (`WAVEFORMATEX`,
/// `VIDEOINFOHEADER`, `VIDEOINFOHEADER2`, `MPEG2VIDEOINFO`) are well
/// under 1 KiB. 64 KiB is generous forward-compat headroom and
/// bounds decode-time allocation against a malicious peer that claims
/// `cbFormat = 0xFFFFFFFF`.
pub const MAX_FORMAT_BYTES: usize = 65_536;

// ── TS_AM_MEDIA_TYPE (§2.2.7) ───────────────────────────────────────

/// Wire size of the fixed header portion of `TS_AM_MEDIA_TYPE`
/// (everything before `pbFormat`).
pub const TS_AM_MEDIA_TYPE_FIXED_SIZE: usize = 64;

/// DirectShow-derived format descriptor. The three GUIDs are passed
/// verbatim from the server's media pipeline; we treat them as opaque
/// 16-byte identifiers because TSMF makes no semantic decisions on
/// them at the wire layer.
///
/// `b_fixed_size_samples` and `b_temporal_compression` are spec'd as
/// "0 or 1" but we accept any u32 to stay forward-compatible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsAmMediaType {
    pub major_type: Guid,
    pub sub_type: Guid,
    /// 0 = variable-size samples, 1 = fixed-size samples (spec §2.2.7).
    pub b_fixed_size_samples: u32,
    /// 0 = uncompressed/I-frame only, 1 = temporally compressed.
    pub b_temporal_compression: u32,
    /// Hint used when `b_fixed_size_samples == 1`.
    pub sample_size: u32,
    pub format_type: Guid,
    /// Format-specific payload (`WAVEFORMATEX`, `VIDEOINFOHEADER`, ...).
    /// Bounded by [`MAX_FORMAT_BYTES`].
    pub pb_format: Vec<u8>,
}

impl TsAmMediaType {
    /// Wire size = 64 fixed + `pb_format.len()`.
    pub fn wire_size(&self) -> usize {
        TS_AM_MEDIA_TYPE_FIXED_SIZE + self.pb_format.len()
    }

    pub(crate) fn encode_inner(
        &self,
        dst: &mut WriteCursor<'_>,
        ctx: &'static str,
    ) -> EncodeResult<()> {
        if self.pb_format.len() > MAX_FORMAT_BYTES {
            return Err(EncodeError::invalid_value(ctx, "cbFormat too large"));
        }
        encode_guid(dst, &self.major_type, ctx)?;
        encode_guid(dst, &self.sub_type, ctx)?;
        dst.write_u32_le(self.b_fixed_size_samples, ctx)?;
        dst.write_u32_le(self.b_temporal_compression, ctx)?;
        dst.write_u32_le(self.sample_size, ctx)?;
        encode_guid(dst, &self.format_type, ctx)?;
        dst.write_u32_le(self.pb_format.len() as u32, ctx)?;
        dst.write_slice(&self.pb_format, ctx)?;
        Ok(())
    }

    pub(crate) fn decode_inner(
        src: &mut ReadCursor<'_>,
        ctx: &'static str,
    ) -> DecodeResult<Self> {
        let major_type = decode_guid(src, ctx)?;
        let sub_type = decode_guid(src, ctx)?;
        let b_fixed_size_samples = src.read_u32_le(ctx)?;
        let b_temporal_compression = src.read_u32_le(ctx)?;
        let sample_size = src.read_u32_le(ctx)?;
        let format_type = decode_guid(src, ctx)?;
        let cb_format = src.read_u32_le(ctx)?;
        if cb_format as usize > MAX_FORMAT_BYTES {
            return Err(DecodeError::invalid_value(ctx, "cbFormat too large"));
        }
        if (cb_format as usize) > src.remaining() {
            return Err(DecodeError::invalid_value(ctx, "cbFormat underflow"));
        }
        let pb_format = src.read_slice(cb_format as usize, ctx)?.to_vec();
        Ok(Self {
            major_type,
            sub_type,
            b_fixed_size_samples,
            b_temporal_compression,
            sample_size,
            format_type,
            pb_format,
        })
    }

    /// Sanity-check helper for the fixed-header offsets (§2.2.7).
    /// Used only by tests.
    #[cfg(test)]
    fn check_offsets() {
        // MajorType@0, SubType@16, bFixed@32, bTemp@36, SampleSize@40,
        // FormatType@44, cbFormat@60, pbFormat@64.
        assert_eq!(TS_AM_MEDIA_TYPE_FIXED_SIZE, 16 + 16 + 4 + 4 + 4 + 16 + 4);
    }
}

// ── CheckFormatSupportReq (§2.2.5.2.2) ──────────────────────────────

/// Server asks the client whether a given media format can be played
/// on a particular platform. The answer ([`CheckFormatSupportRsp`])
/// is correlated by `message_id`.
///
/// `num_media_type` is, despite the name, a **byte count** of the
/// serialized `TS_AM_MEDIA_TYPE` (per spec §2.2.5.2.2), not an element
/// count -- and it MUST equal `64 + cbFormat`. The decoder validates
/// this invariant and rejects mismatched messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckFormatSupportReq {
    pub message_id: u32,
    /// `TSMM_PLATFORM_COOKIE_*` -- which platform the server prefers.
    pub platform_cookie: u32,
    /// 0 = try alternative platforms if preferred fails;
    /// 1 = SHOULD NOT use alternatives.
    pub no_rollover_flags: u32,
    pub media_type: TsAmMediaType,
}

impl CheckFormatSupportReq {
    /// Payload bytes (everything after the 12-byte header).
    fn payload_size(&self) -> usize {
        4 + 4 + 4 + self.media_type.wire_size()
    }
}

impl Encode for CheckFormatSupportReq {
    fn name(&self) -> &'static str {
        "MS-RDPEV::CheckFormatSupportReq"
    }
    fn size(&self) -> usize {
        REQUEST_HEADER_SIZE + self.payload_size()
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::CheckFormatSupportReq,
        );
        encode_header(dst, &header)?;
        dst.write_u32_le(self.platform_cookie, self.name())?;
        dst.write_u32_le(self.no_rollover_flags, self.name())?;
        let mt_size = self.media_type.wire_size();
        if mt_size > u32::MAX as usize {
            return Err(EncodeError::invalid_value(self.name(), "numMediaType overflow"));
        }
        dst.write_u32_le(mt_size as u32, self.name())?;
        self.media_type.encode_inner(dst, self.name())
    }
}

impl<'de> Decode<'de> for CheckFormatSupportReq {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::CheckFormatSupportReq";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::CheckFormatSupportReq)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let platform_cookie = src.read_u32_le(CTX)?;
        let no_rollover_flags = src.read_u32_le(CTX)?;
        let num_media_type = src.read_u32_le(CTX)? as usize;
        // numMediaType MUST equal the on-wire size of TS_AM_MEDIA_TYPE
        // (64 fixed + cbFormat). Validate against the cap before
        // attempting the inner decode -- and remember the boundary so
        // we can re-check after the inner decoder consumes its bytes.
        if num_media_type < TS_AM_MEDIA_TYPE_FIXED_SIZE {
            return Err(DecodeError::invalid_value(CTX, "numMediaType too small"));
        }
        let claimed_pb_format = num_media_type - TS_AM_MEDIA_TYPE_FIXED_SIZE;
        if claimed_pb_format > MAX_FORMAT_BYTES {
            return Err(DecodeError::invalid_value(CTX, "numMediaType too large"));
        }
        if num_media_type > src.remaining() {
            return Err(DecodeError::invalid_value(CTX, "numMediaType underflow"));
        }
        let pos_before = src.pos();
        let media_type = TsAmMediaType::decode_inner(src, CTX)?;
        if src.pos() - pos_before != num_media_type {
            // The inner decoder read a different number of bytes than
            // the outer length prefix promised — this is a structure
            // size mismatch (validation rule §9). Refuse.
            return Err(DecodeError::invalid_value(CTX, "numMediaType != 64 + cbFormat"));
        }
        Ok(Self {
            message_id: header.message_id,
            platform_cookie,
            no_rollover_flags,
            media_type,
        })
    }
}

// ── CheckFormatSupportRsp (§2.2.5.2.3) ──────────────────────────────

/// Client's verdict on a [`CheckFormatSupportReq`]. `message_id` MUST
/// echo the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckFormatSupportRsp {
    pub message_id: u32,
    /// 0 = unsupported, 1 = supported.
    pub format_supported: u32,
    /// Set only when `format_supported == 1`; otherwise undefined per
    /// spec. We pass it through verbatim.
    pub platform_cookie: u32,
    pub result: u32,
}

impl CheckFormatSupportRsp {
    pub const PAYLOAD_SIZE: usize = 12;
    pub const WIRE_SIZE: usize = RESPONSE_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for CheckFormatSupportRsp {
    fn name(&self) -> &'static str {
        "MS-RDPEV::CheckFormatSupportRsp"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::response(InterfaceValue::ServerData, self.message_id);
        encode_header(dst, &header)?;
        dst.write_u32_le(self.format_supported, self.name())?;
        dst.write_u32_le(self.platform_cookie, self.name())?;
        dst.write_u32_le(self.result, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for CheckFormatSupportRsp {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::CheckFormatSupportRsp";
        let header = decode_response_header(src)?;
        if header.interface_value != InterfaceValue::ServerData {
            return Err(DecodeError::invalid_value(CTX, "header interface"));
        }
        let format_supported = src.read_u32_le(CTX)?;
        let platform_cookie = src.read_u32_le(CTX)?;
        let result = src.read_u32_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            format_supported,
            platform_cookie,
            result,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{platform_cookie, S_OK};
    use alloc::vec;

    fn encode_to_vec<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        assert_eq!(cur.pos(), pdu.size(), "size() mismatch for {}", pdu.name());
        buf
    }

    fn dummy_media_type(pb_format_len: usize) -> TsAmMediaType {
        TsAmMediaType {
            major_type: Guid([0xAA; 16]),
            sub_type: Guid([0xBB; 16]),
            b_fixed_size_samples: 1,
            b_temporal_compression: 0,
            sample_size: 4096,
            format_type: Guid([0xCC; 16]),
            pb_format: vec![0xDDu8; pb_format_len],
        }
    }

    #[test]
    fn fixed_offsets_are_correct() {
        TsAmMediaType::check_offsets();
    }

    #[test]
    fn ts_am_media_type_inner_roundtrip_with_format_blob() {
        let mt = dummy_media_type(48);
        let mut buf: Vec<u8> = vec![0u8; mt.wire_size()];
        let mut cur = WriteCursor::new(&mut buf);
        mt.encode_inner(&mut cur, "test").unwrap();
        assert_eq!(cur.pos(), mt.wire_size());
        assert_eq!(buf.len(), 64 + 48);

        let mut r = ReadCursor::new(&buf);
        let back = TsAmMediaType::decode_inner(&mut r, "test").unwrap();
        assert_eq!(back, mt);
    }

    #[test]
    fn ts_am_media_type_zero_pb_format_is_legal() {
        let mt = dummy_media_type(0);
        assert_eq!(mt.wire_size(), 64);
        let mut buf: Vec<u8> = vec![0u8; mt.wire_size()];
        let mut cur = WriteCursor::new(&mut buf);
        mt.encode_inner(&mut cur, "test").unwrap();
        let mut r = ReadCursor::new(&buf);
        let back = TsAmMediaType::decode_inner(&mut r, "test").unwrap();
        assert_eq!(back, mt);
        assert!(back.pb_format.is_empty());
    }

    #[test]
    fn ts_am_media_type_encode_rejects_oversize_pb_format() {
        let mt = dummy_media_type(MAX_FORMAT_BYTES + 1);
        let mut buf: Vec<u8> = vec![0u8; mt.wire_size()];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(mt.encode_inner(&mut cur, "test").is_err());
    }

    #[test]
    fn ts_am_media_type_decode_rejects_oversize_cb_format() {
        // Hand-roll a fixed header with cbFormat = MAX + 1.
        let mut bytes: Vec<u8> = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0u8; 16]); // MajorType
        bytes.extend_from_slice(&[0u8; 16]); // SubType
        bytes.extend_from_slice(&0u32.to_le_bytes()); // bFixed
        bytes.extend_from_slice(&0u32.to_le_bytes()); // bTemp
        bytes.extend_from_slice(&0u32.to_le_bytes()); // SampleSize
        bytes.extend_from_slice(&[0u8; 16]); // FormatType
        bytes.extend_from_slice(&((MAX_FORMAT_BYTES as u32) + 1).to_le_bytes()); // cbFormat
        let mut r = ReadCursor::new(&bytes);
        assert!(TsAmMediaType::decode_inner(&mut r, "test").is_err());
    }

    #[test]
    fn check_format_support_req_roundtrip() {
        let req = CheckFormatSupportReq {
            message_id: 7,
            platform_cookie: platform_cookie::MF,
            no_rollover_flags: 0,
            media_type: dummy_media_type(16),
        };
        let bytes = encode_to_vec(&req);
        // 12 header + 4 cookie + 4 no_rollover + 4 numMediaType + 64 fixed + 16 pbFormat
        assert_eq!(bytes.len(), 12 + 4 + 4 + 4 + 64 + 16);

        let mut r = ReadCursor::new(&bytes);
        let decoded = CheckFormatSupportReq::decode(&mut r).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn check_format_support_req_writes_correct_num_media_type() {
        let req = CheckFormatSupportReq {
            message_id: 0,
            platform_cookie: platform_cookie::DSHOW,
            no_rollover_flags: 0,
            media_type: dummy_media_type(16),
        };
        let bytes = encode_to_vec(&req);
        // Bytes [12..16] = platform_cookie, [16..20] = no_rollover,
        // [20..24] = numMediaType.
        let num_media_type =
            u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]) as usize;
        assert_eq!(num_media_type, 64 + 16);
    }

    #[test]
    fn check_format_support_req_decode_rejects_num_media_type_mismatch() {
        // Build a valid byte stream, then bump numMediaType so it claims
        // more than the inner TsAmMediaType actually consumes. The
        // decoder must catch the mismatch.
        let req = CheckFormatSupportReq {
            message_id: 0,
            platform_cookie: platform_cookie::MF,
            no_rollover_flags: 0,
            media_type: dummy_media_type(0),
        };
        let mut bytes = encode_to_vec(&req);
        // numMediaType lives at offset 20..24. Increase it by 4: claim
        // 4 more bytes than we'll actually deliver. The buffer is too
        // short for the claim, so the cap-check / underflow path
        // catches it before the structure-size mismatch path -- both
        // are valid rejections.
        let claimed = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]) + 4;
        bytes[20..24].copy_from_slice(&claimed.to_le_bytes());
        let mut r = ReadCursor::new(&bytes);
        assert!(CheckFormatSupportReq::decode(&mut r).is_err());
    }

    #[test]
    fn check_format_support_req_decode_rejects_num_media_type_too_small() {
        // numMediaType < 64 is impossible (no room for the fixed header).
        let mut bytes: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x08, 0x01, 0x00, 0x00, // FunctionId = CHECK_FORMAT_SUPPORT_REQ
            0x00, 0x00, 0x00, 0x00, // platform_cookie
            0x00, 0x00, 0x00, 0x00, // no_rollover
            0x10, 0x00, 0x00, 0x00, // numMediaType = 16 (way too small)
        ];
        // Pad with junk so the decoder gets past the cursor underflow
        // check and reaches the size sanity check.
        bytes.extend_from_slice(&[0u8; 16]);
        let mut r = ReadCursor::new(&bytes);
        assert!(CheckFormatSupportReq::decode(&mut r).is_err());
    }

    #[test]
    fn check_format_support_rsp_matches_spec_wire_vector() {
        // Spec §4 §11.6, total 20 bytes:
        //   00 00 00 80  STUB
        //   00 00 00 00  MessageId
        //   01 00 00 00  FormatSupported = 1
        //   01 00 00 00  PlatformCookie = MF
        //   00 00 00 00  Result = S_OK
        let rsp = CheckFormatSupportRsp {
            message_id: 0,
            format_supported: 1,
            platform_cookie: platform_cookie::MF,
            result: S_OK,
        };
        let bytes = encode_to_vec(&rsp);
        assert_eq!(bytes.len(), 20);
        assert_eq!(
            bytes,
            [
                0x00, 0x00, 0x00, 0x80, // STUB
                0x00, 0x00, 0x00, 0x00, // MessageId
                0x01, 0x00, 0x00, 0x00, // FormatSupported
                0x01, 0x00, 0x00, 0x00, // PlatformCookie = MF
                0x00, 0x00, 0x00, 0x00, // Result = S_OK
            ]
        );

        let mut r = ReadCursor::new(&bytes);
        let decoded = CheckFormatSupportRsp::decode(&mut r).unwrap();
        assert_eq!(decoded, rsp);
    }

    #[test]
    fn check_format_support_rsp_unsupported_path_round_trips() {
        // FormatSupported = 0 means PlatformCookie is undefined per
        // spec. We pass it through verbatim.
        let rsp = CheckFormatSupportRsp {
            message_id: 99,
            format_supported: 0,
            platform_cookie: 0,
            result: S_OK,
        };
        let bytes = encode_to_vec(&rsp);
        let mut r = ReadCursor::new(&bytes);
        let decoded = CheckFormatSupportRsp::decode(&mut r).unwrap();
        assert_eq!(decoded, rsp);
    }

    #[test]
    fn pipeline_correlation_distinct_message_ids_round_trip() {
        // The server may send several CHECK_FORMAT_SUPPORT_REQs with
        // distinct MessageIds before reading the answers; verify that
        // the field survives the round trip on the request side too.
        for &mid in &[1u32, 2, 3, 0xFFFF_FFFF] {
            let req = CheckFormatSupportReq {
                message_id: mid,
                platform_cookie: platform_cookie::MF,
                no_rollover_flags: 0,
                media_type: dummy_media_type(0),
            };
            let bytes = encode_to_vec(&req);
            let mut r = ReadCursor::new(&bytes);
            let decoded = CheckFormatSupportReq::decode(&mut r).unwrap();
            assert_eq!(decoded.message_id, mid);
        }
    }

    #[test]
    fn check_format_support_req_rejects_wrong_function_id() {
        let bytes = [
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x05, 0x01, 0x00, 0x00, // ON_NEW_PRESENTATION (wrong)
            0x00, 0x00, 0x00, 0x00, // PlatformCookie
            0x00, 0x00, 0x00, 0x00, // NoRollover
            0x40, 0x00, 0x00, 0x00, // numMediaType = 64
        ];
        let mut r = ReadCursor::new(&bytes);
        assert!(CheckFormatSupportReq::decode(&mut r).is_err());
    }
}
