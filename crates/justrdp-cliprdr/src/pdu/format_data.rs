#![forbid(unsafe_code)]

//! Format Data Request/Response PDU -- MS-RDPECLIP 2.2.5.1, 2.2.5.2

use alloc::vec::Vec;

use justrdp_core::{Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeResult, EncodeResult};

use super::header::{ClipboardHeader, ClipboardMsgFlags, ClipboardMsgType, CLIPBOARD_HEADER_SIZE};

/// Format Data Request PDU -- MS-RDPECLIP 2.2.5.1
///
/// 12 bytes total: 8-byte header + 4-byte format ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatDataRequestPdu {
    /// The requested clipboard format ID.
    pub requested_format_id: u32,
}

impl FormatDataRequestPdu {
    /// Create a new format data request.
    pub fn new(requested_format_id: u32) -> Self {
        Self {
            requested_format_id,
        }
    }
}

impl Encode for FormatDataRequestPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = ClipboardHeader::new(
            ClipboardMsgType::FormatDataRequest,
            ClipboardMsgFlags::NONE,
            4,
        );
        header.encode(dst)?;
        dst.write_u32_le(
            self.requested_format_id,
            "FormatDataRequestPdu::requestedFormatId",
        )?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "FormatDataRequestPdu"
    }

    fn size(&self) -> usize {
        CLIPBOARD_HEADER_SIZE + 4
    }
}

impl FormatDataRequestPdu {
    /// Decode from cursor after the clipboard header has been read.
    pub fn decode_body(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let requested_format_id =
            src.read_u32_le("FormatDataRequestPdu::requestedFormatId")?;
        Ok(Self {
            requested_format_id,
        })
    }
}

/// Format Data Response PDU -- MS-RDPECLIP 2.2.5.2
///
/// Header + variable data on success, header only on failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatDataResponsePdu {
    /// Successful response with clipboard data.
    Ok(Vec<u8>),
    /// Failed response (no data).
    Fail,
}

impl FormatDataResponsePdu {
    fn data_len(&self) -> u32 {
        match self {
            Self::Ok(data) => data.len() as u32,
            Self::Fail => 0,
        }
    }
}

impl Encode for FormatDataResponsePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let flags = match self {
            Self::Ok(_) => ClipboardMsgFlags::CB_RESPONSE_OK,
            Self::Fail => ClipboardMsgFlags::CB_RESPONSE_FAIL,
        };
        let header = ClipboardHeader::new(
            ClipboardMsgType::FormatDataResponse,
            flags,
            self.data_len(),
        );
        header.encode(dst)?;
        if let Self::Ok(data) = self {
            dst.write_slice(data, "FormatDataResponsePdu::requestedFormatData")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "FormatDataResponsePdu"
    }

    fn size(&self) -> usize {
        CLIPBOARD_HEADER_SIZE + self.data_len() as usize
    }
}

impl FormatDataResponsePdu {
    /// Decode from cursor after the clipboard header has been read.
    pub fn decode_body(
        src: &mut ReadCursor<'_>,
        msg_flags: ClipboardMsgFlags,
        data_len: u32,
    ) -> DecodeResult<Self> {
        let is_ok = msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_OK);
        if is_ok && data_len > 0 {
            let data = src
                .read_slice(data_len as usize, "FormatDataResponsePdu::requestedFormatData")?
                .to_vec();
            Ok(Self::Ok(data))
        } else {
            Ok(Self::Fail)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_core::Decode;
    use super::super::header::ClipboardHeader;

    #[test]
    fn format_data_request_roundtrip() {
        let pdu = FormatDataRequestPdu::new(0x000D); // CF_UNICODETEXT
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = ClipboardHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, ClipboardMsgType::FormatDataRequest);
        assert_eq!(header.data_len, 4);
        let format_id = cursor.read_u32_le("requestedFormatId").unwrap();
        assert_eq!(format_id, 0x000D);
    }

    #[test]
    fn format_data_response_ok_roundtrip() {
        let data = alloc::vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
        let pdu = FormatDataResponsePdu::Ok(data.clone());
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = ClipboardHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, ClipboardMsgType::FormatDataResponse);
        assert!(header.msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_OK));
        assert_eq!(header.data_len, 5);
        let payload = cursor.read_slice(header.data_len as usize, "data").unwrap();
        assert_eq!(payload, &data[..]);
    }

    #[test]
    fn format_data_response_fail() {
        let pdu = FormatDataResponsePdu::Fail;
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = ClipboardHeader::decode(&mut cursor).unwrap();
        assert!(header
            .msg_flags
            .contains(ClipboardMsgFlags::CB_RESPONSE_FAIL));
        assert_eq!(header.data_len, 0);
    }
}
