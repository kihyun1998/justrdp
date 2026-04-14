//! Stream management PDUs (MS-RDPEV §2.2.5.2.4, §2.2.5.2.7).
//!
//! After a presentation is announced (`OnNewPresentation`) and each
//! candidate format is approved (`CheckFormatSupportReq/Rsp`), the
//! server installs the streams via [`AddStream`] and tears them down
//! via [`RemoveStream`]. Both PDUs use the Server Data interface
//! (`InterfaceValue=0`) and a `STREAM_ID_PROXY` mask.
//!
//! [`AddStream`] embeds a [`TsAmMediaType`] and re-uses the same
//! `numMediaType` byte-count invariant the format-negotiation PDUs use:
//! the prefix MUST equal `64 + cbFormat`. The decoder rejects
//! mismatches up front so a confused server cannot smuggle stray bytes
//! between the media type and the next message on the channel.

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{FunctionId, InterfaceValue, Mask};
use crate::pdu::format::{TsAmMediaType, MAX_FORMAT_BYTES, TS_AM_MEDIA_TYPE_FIXED_SIZE};
use crate::pdu::guid::{decode_guid, encode_guid, Guid, GUID_SIZE};
use crate::pdu::header::{
    decode_request_header, encode_header, SharedMsgHeader, REQUEST_HEADER_SIZE,
};

// ── AddStream (§2.2.5.2.4) ──────────────────────────────────────────

/// Server installs a stream within an existing presentation. The
/// client must store the `(presentation_id, stream_id) → media_type`
/// mapping so subsequent `OnSample` PDUs can be routed to the correct
/// decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddStream {
    pub message_id: u32,
    pub presentation_id: Guid,
    pub stream_id: u32,
    pub media_type: TsAmMediaType,
}

impl AddStream {
    fn payload_size(&self) -> usize {
        GUID_SIZE + 4 + 4 + self.media_type.wire_size()
    }
}

impl Encode for AddStream {
    fn name(&self) -> &'static str {
        "MS-RDPEV::AddStream"
    }
    fn size(&self) -> usize {
        REQUEST_HEADER_SIZE + self.payload_size()
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::AddStream,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        dst.write_u32_le(self.stream_id, self.name())?;
        let mt_size = self.media_type.wire_size();
        if mt_size > u32::MAX as usize {
            return Err(EncodeError::invalid_value(self.name(), "numMediaType overflow"));
        }
        dst.write_u32_le(mt_size as u32, self.name())?;
        self.media_type.encode_inner(dst, self.name())
    }
}

impl<'de> Decode<'de> for AddStream {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::AddStream";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::AddStream)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let stream_id = src.read_u32_le(CTX)?;
        let num_media_type = src.read_u32_le(CTX)? as usize;
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
            return Err(DecodeError::invalid_value(
                CTX,
                "numMediaType != 64 + cbFormat",
            ));
        }
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            stream_id,
            media_type,
        })
    }
}

// ── RemoveStream (§2.2.5.2.7) ───────────────────────────────────────

/// Server tears down a single stream within a presentation. The
/// client MUST free all per-stream resources for the
/// `(presentation_id, stream_id)` pair on receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoveStream {
    pub message_id: u32,
    pub presentation_id: Guid,
    pub stream_id: u32,
}

impl RemoveStream {
    pub const PAYLOAD_SIZE: usize = GUID_SIZE + 4;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for RemoveStream {
    fn name(&self) -> &'static str {
        "MS-RDPEV::RemoveStream"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::RemoveStream,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        dst.write_u32_le(self.stream_id, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for RemoveStream {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::RemoveStream";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::RemoveStream)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let stream_id = src.read_u32_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            stream_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn encode_to_vec<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        assert_eq!(cur.pos(), pdu.size(), "size() mismatch for {}", pdu.name());
        buf
    }

    fn dummy_media_type(pb_format_len: usize) -> TsAmMediaType {
        TsAmMediaType {
            major_type: Guid([0x11; 16]),
            sub_type: Guid([0x22; 16]),
            b_fixed_size_samples: 0,
            b_temporal_compression: 1,
            sample_size: 0,
            format_type: Guid([0x33; 16]),
            pb_format: vec![0x44u8; pb_format_len],
        }
    }

    const PRES: Guid = Guid([
        0x9f, 0x04, 0x86, 0xe0, 0x26, 0xd9, 0xae, 0x45, 0x8c, 0x0f, 0x3e, 0x05, 0x6a, 0xf3, 0xf7,
        0xd4,
    ]);

    #[test]
    fn add_stream_full_layout_with_format_blob() {
        let pdu = AddStream {
            message_id: 0,
            presentation_id: PRES,
            stream_id: 1,
            media_type: dummy_media_type(32),
        };
        let bytes = encode_to_vec(&pdu);
        // 12 header + 16 GUID + 4 StreamId + 4 numMediaType + 64 fixed + 32 pbFormat
        assert_eq!(bytes.len(), 12 + 16 + 4 + 4 + 64 + 32);

        // First 12 bytes: header with FunctionId = ADD_STREAM (0x102).
        assert_eq!(
            &bytes[..12],
            &[
                0x00, 0x00, 0x00, 0x40, // PROXY
                0x00, 0x00, 0x00, 0x00, // MessageId
                0x02, 0x01, 0x00, 0x00, // FunctionId = 0x102
            ]
        );
        // GUID at [12..28], StreamId at [28..32], numMediaType at [32..36].
        assert_eq!(&bytes[12..28], PRES.as_bytes());
        assert_eq!(&bytes[28..32], &[0x01, 0x00, 0x00, 0x00]);
        let num_media_type =
            u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]) as usize;
        assert_eq!(num_media_type, 64 + 32);

        let mut r = ReadCursor::new(&bytes);
        let decoded = AddStream::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn add_stream_zero_pb_format_round_trips() {
        let pdu = AddStream {
            message_id: 7,
            presentation_id: PRES,
            stream_id: 0,
            media_type: dummy_media_type(0),
        };
        let bytes = encode_to_vec(&pdu);
        let mut r = ReadCursor::new(&bytes);
        let decoded = AddStream::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn add_stream_decode_rejects_num_media_type_too_small() {
        let mut bytes: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x02, 0x01, 0x00, 0x00, // FunctionId
        ];
        bytes.extend_from_slice(PRES.as_bytes());
        bytes.extend_from_slice(&[0u8; 4]); // StreamId
        bytes.extend_from_slice(&16u32.to_le_bytes()); // numMediaType = 16 (too small)
        bytes.extend_from_slice(&[0u8; 64]);
        let mut r = ReadCursor::new(&bytes);
        assert!(AddStream::decode(&mut r).is_err());
    }

    #[test]
    fn add_stream_decode_rejects_num_media_type_size_mismatch() {
        // Build a valid stream, then bump numMediaType by 4 so it
        // claims more bytes than the inner decoder will consume.
        let pdu = AddStream {
            message_id: 0,
            presentation_id: PRES,
            stream_id: 0,
            media_type: dummy_media_type(0),
        };
        let mut bytes = encode_to_vec(&pdu);
        // numMediaType lives at offset 32..36 (12 hdr + 16 guid + 4 sid).
        let claimed = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]) + 4;
        bytes[32..36].copy_from_slice(&claimed.to_le_bytes());
        let mut r = ReadCursor::new(&bytes);
        assert!(AddStream::decode(&mut r).is_err());
    }

    #[test]
    fn add_stream_rejects_wrong_function_id() {
        let mut bytes: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x05, 0x01, 0x00, 0x00, // ON_NEW_PRESENTATION (wrong)
        ];
        bytes.extend_from_slice(PRES.as_bytes());
        bytes.extend_from_slice(&[0u8; 4]);
        bytes.extend_from_slice(&64u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        let mut r = ReadCursor::new(&bytes);
        assert!(AddStream::decode(&mut r).is_err());
    }

    #[test]
    fn remove_stream_roundtrip() {
        let pdu = RemoveStream {
            message_id: 9,
            presentation_id: PRES,
            stream_id: 3,
        };
        let bytes = encode_to_vec(&pdu);
        // 12 header + 16 GUID + 4 StreamId
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes.len(), RemoveStream::WIRE_SIZE);
        assert_eq!(
            &bytes[..12],
            &[
                0x00, 0x00, 0x00, 0x40, // PROXY
                0x09, 0x00, 0x00, 0x00, // MessageId = 9
                0x15, 0x01, 0x00, 0x00, // FunctionId = REMOVE_STREAM (0x115)
            ]
        );
        assert_eq!(&bytes[12..28], PRES.as_bytes());
        assert_eq!(&bytes[28..32], &[0x03, 0x00, 0x00, 0x00]);

        let mut r = ReadCursor::new(&bytes);
        let decoded = RemoveStream::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn remove_stream_rejects_wrong_function_id() {
        let mut bytes: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x16, 0x01, 0x00, 0x00, // SET_SOURCE_VIDEO_RECT (0x116, off-by-one neighbour)
        ];
        bytes.extend_from_slice(PRES.as_bytes());
        bytes.extend_from_slice(&[0u8; 4]);
        let mut r = ReadCursor::new(&bytes);
        assert!(RemoveStream::decode(&mut r).is_err());
    }
}
