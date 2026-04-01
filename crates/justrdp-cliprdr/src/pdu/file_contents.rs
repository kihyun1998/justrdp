#![forbid(unsafe_code)]

//! File Contents Request/Response PDU -- MS-RDPECLIP 2.2.5.3, 2.2.5.4

use alloc::vec::Vec;

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{DecodeResult, EncodeResult};
use justrdp_core::Encode;

use super::header::{ClipboardHeader, ClipboardMsgFlags, ClipboardMsgType, CLIPBOARD_HEADER_SIZE};

/// File contents operation type -- MS-RDPECLIP 2.2.5.3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileContentsFlags(u32);

impl FileContentsFlags {
    /// Request the file size (response is 8-byte u64 LE).
    pub const SIZE: Self = Self(0x0000_0001);
    /// Request a byte range of the file.
    pub const RANGE: Self = Self(0x0000_0002);

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Get raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// File Contents Request PDU -- MS-RDPECLIP 2.2.5.3
///
/// 32 bytes (without clipDataId) or 36 bytes (with clipDataId).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileContentsRequestPdu {
    /// Caller-assigned stream ID (echoed in response).
    pub stream_id: u32,
    /// Zero-based index into the file list.
    pub lindex: i32,
    /// Operation type: SIZE or RANGE.
    pub dw_flags: FileContentsFlags,
    /// Low 32 bits of byte offset (must be 0 for SIZE).
    pub n_position_low: u32,
    /// High 32 bits of byte offset (must be 0 for SIZE).
    pub n_position_high: u32,
    /// Bytes to read (must be 8 for SIZE).
    pub cb_requested: u32,
    /// Optional clip data ID (present only when lock/unlock is negotiated).
    pub clip_data_id: Option<u32>,
}

impl FileContentsRequestPdu {
    /// Create a SIZE request.
    pub fn size_request(stream_id: u32, lindex: i32) -> Self {
        Self {
            stream_id,
            lindex,
            dw_flags: FileContentsFlags::SIZE,
            n_position_low: 0,
            n_position_high: 0,
            cb_requested: 8,
            clip_data_id: None,
        }
    }

    /// Create a RANGE request.
    pub fn range_request(
        stream_id: u32,
        lindex: i32,
        offset: u64,
        cb_requested: u32,
    ) -> Self {
        Self {
            stream_id,
            lindex,
            dw_flags: FileContentsFlags::RANGE,
            n_position_low: offset as u32,
            n_position_high: (offset >> 32) as u32,
            cb_requested,
            clip_data_id: None,
        }
    }

    /// Set the clip data ID (for lock/unlock support).
    pub fn with_clip_data_id(mut self, id: u32) -> Self {
        self.clip_data_id = Some(id);
        self
    }

    /// Data length (after header): 24 or 28 bytes.
    fn data_len(&self) -> u32 {
        if self.clip_data_id.is_some() {
            28
        } else {
            24
        }
    }
}

impl Encode for FileContentsRequestPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = ClipboardHeader::new(
            ClipboardMsgType::FileContentsRequest,
            ClipboardMsgFlags::NONE,
            self.data_len(),
        );
        header.encode(dst)?;
        dst.write_u32_le(self.stream_id, "FileContentsRequestPdu::streamId")?;
        dst.write_i32_le(self.lindex, "FileContentsRequestPdu::lindex")?;
        dst.write_u32_le(self.dw_flags.bits(), "FileContentsRequestPdu::dwFlags")?;
        dst.write_u32_le(self.n_position_low, "FileContentsRequestPdu::nPositionLow")?;
        dst.write_u32_le(
            self.n_position_high,
            "FileContentsRequestPdu::nPositionHigh",
        )?;
        dst.write_u32_le(self.cb_requested, "FileContentsRequestPdu::cbRequested")?;
        if let Some(id) = self.clip_data_id {
            dst.write_u32_le(id, "FileContentsRequestPdu::clipDataId")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "FileContentsRequestPdu"
    }

    fn size(&self) -> usize {
        CLIPBOARD_HEADER_SIZE + self.data_len() as usize
    }
}

impl FileContentsRequestPdu {
    /// Decode from cursor after the clipboard header has been read.
    ///
    /// `data_len` from the header determines whether clipDataId is present.
    pub fn decode_body(src: &mut ReadCursor<'_>, data_len: u32) -> DecodeResult<Self> {
        let stream_id = src.read_u32_le("FileContentsRequestPdu::streamId")?;
        let lindex = src.read_i32_le("FileContentsRequestPdu::lindex")?;
        let dw_flags =
            FileContentsFlags::from_bits(src.read_u32_le("FileContentsRequestPdu::dwFlags")?);
        let n_position_low = src.read_u32_le("FileContentsRequestPdu::nPositionLow")?;
        let n_position_high = src.read_u32_le("FileContentsRequestPdu::nPositionHigh")?;
        let cb_requested = src.read_u32_le("FileContentsRequestPdu::cbRequested")?;

        // clipDataId is present if dataLen == 28 (vs 24)
        let clip_data_id = if data_len >= 28 {
            Some(src.read_u32_le("FileContentsRequestPdu::clipDataId")?)
        } else {
            None
        };

        Ok(Self {
            stream_id,
            lindex,
            dw_flags,
            n_position_low,
            n_position_high,
            cb_requested,
            clip_data_id,
        })
    }
}

/// File Contents Response PDU -- MS-RDPECLIP 2.2.5.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileContentsResponsePdu {
    /// Successful response.
    Ok {
        /// Stream ID matching the request.
        stream_id: u32,
        /// Response data: 8-byte u64 LE for SIZE, raw bytes for RANGE.
        data: Vec<u8>,
    },
    /// Failed response.
    Fail {
        /// Stream ID matching the request.
        stream_id: u32,
    },
}

impl FileContentsResponsePdu {
    /// Create a SIZE response (8-byte u64 LE).
    pub fn size_response(stream_id: u32, file_size: u64) -> Self {
        Self::Ok {
            stream_id,
            data: file_size.to_le_bytes().to_vec(),
        }
    }

    /// Create a RANGE response with raw file bytes.
    pub fn range_response(stream_id: u32, data: Vec<u8>) -> Self {
        Self::Ok { stream_id, data }
    }

    /// Create a failed response.
    pub fn fail(stream_id: u32) -> Self {
        Self::Fail { stream_id }
    }
}

impl Encode for FileContentsResponsePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let (flags, stream_id, data_len) = match self {
            Self::Ok { stream_id, data } => {
                (ClipboardMsgFlags::CB_RESPONSE_OK, *stream_id, 4 + data.len() as u32)
            }
            Self::Fail { stream_id } => {
                (ClipboardMsgFlags::CB_RESPONSE_FAIL, *stream_id, 4)
            }
        };

        let header = ClipboardHeader::new(
            ClipboardMsgType::FileContentsResponse,
            flags,
            data_len,
        );
        header.encode(dst)?;
        dst.write_u32_le(stream_id, "FileContentsResponsePdu::streamId")?;
        if let Self::Ok { data, .. } = self {
            dst.write_slice(data, "FileContentsResponsePdu::requestedFileContentsData")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "FileContentsResponsePdu"
    }

    fn size(&self) -> usize {
        match self {
            Self::Ok { data, .. } => CLIPBOARD_HEADER_SIZE + 4 + data.len(),
            Self::Fail { .. } => CLIPBOARD_HEADER_SIZE + 4,
        }
    }
}

impl FileContentsResponsePdu {
    /// Decode from cursor after the clipboard header has been read.
    pub fn decode_body(
        src: &mut ReadCursor<'_>,
        msg_flags: ClipboardMsgFlags,
        data_len: u32,
    ) -> DecodeResult<Self> {
        let stream_id = src.read_u32_le("FileContentsResponsePdu::streamId")?;
        let is_ok = msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_OK);
        if is_ok && data_len > 4 {
            let payload_len = data_len as usize - 4;
            let data = src
                .read_slice(payload_len, "FileContentsResponsePdu::data")?
                .to_vec();
            Ok(Self::Ok { stream_id, data })
        } else {
            Ok(Self::Fail { stream_id })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_core::{Decode, ReadCursor};
    use super::super::header::ClipboardHeader;

    #[test]
    fn file_contents_request_size_roundtrip() {
        // MS-RDPECLIP 4.4.3.1
        let expected_bytes: Vec<u8> = alloc::vec![
            0x08, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, // header
            0x02, 0x00, 0x00, 0x00, // streamId=2
            0x01, 0x00, 0x00, 0x00, // lindex=1
            0x01, 0x00, 0x00, 0x00, // dwFlags=FILECONTENTS_SIZE
            0x00, 0x00, 0x00, 0x00, // nPositionLow=0
            0x00, 0x00, 0x00, 0x00, // nPositionHigh=0
            0x08, 0x00, 0x00, 0x00, // cbRequested=8
        ];

        let pdu = FileContentsRequestPdu::size_request(2, 1);
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        assert_eq!(buf, expected_bytes);

        // Decode
        let mut cursor = ReadCursor::new(&expected_bytes[CLIPBOARD_HEADER_SIZE..]);
        let decoded = FileContentsRequestPdu::decode_body(&mut cursor, 0x18).unwrap();
        assert_eq!(decoded.stream_id, 2);
        assert_eq!(decoded.lindex, 1);
        assert_eq!(decoded.dw_flags, FileContentsFlags::SIZE);
        assert_eq!(decoded.cb_requested, 8);
        assert_eq!(decoded.clip_data_id, None);
    }

    #[test]
    fn file_contents_request_range_roundtrip() {
        // MS-RDPECLIP 4.4.3.2
        let expected_bytes: Vec<u8> = alloc::vec![
            0x08, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, // header
            0x02, 0x00, 0x00, 0x00, // streamId=2
            0x01, 0x00, 0x00, 0x00, // lindex=1
            0x02, 0x00, 0x00, 0x00, // dwFlags=FILECONTENTS_RANGE
            0x00, 0x00, 0x00, 0x00, // nPositionLow=0
            0x00, 0x00, 0x00, 0x00, // nPositionHigh=0
            0x00, 0x00, 0x01, 0x00, // cbRequested=65536
        ];

        let pdu = FileContentsRequestPdu::range_request(2, 1, 0, 65536);
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        assert_eq!(buf, expected_bytes);
    }

    #[test]
    fn file_contents_response_size() {
        let pdu = FileContentsResponsePdu::size_response(2, 1024);
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = ClipboardHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, ClipboardMsgType::FileContentsResponse);
        assert!(header.msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_OK));
        assert_eq!(header.data_len, 12); // 4 (streamId) + 8 (u64 size)
    }

    #[test]
    fn file_contents_response_fail() {
        let pdu = FileContentsResponsePdu::fail(5);
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = ClipboardHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, ClipboardMsgType::FileContentsResponse);
        assert!(header.msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_FAIL));
        // dataLen = 4 (streamId only, no data payload)
        assert_eq!(header.data_len, 4);
        let stream_id = cursor.read_u32_le("streamId").unwrap();
        assert_eq!(stream_id, 5);
        assert_eq!(cursor.remaining(), 0);
    }
}
