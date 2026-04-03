#![forbid(unsafe_code)]

//! Lock/Unlock Clipboard Data PDU -- MS-RDPECLIP 2.2.4.1, 2.2.4.2

use justrdp_core::{DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use super::header::{ClipboardHeader, ClipboardMsgFlags, ClipboardMsgType, CLIPBOARD_HEADER_SIZE};

/// Lock Clipboard Data PDU -- MS-RDPECLIP 2.2.4.1
///
/// 12 bytes total: 8-byte header + 4-byte clipDataId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockClipDataPdu {
    /// ID used to tag file stream data for later retrieval.
    pub clip_data_id: u32,
}

impl LockClipDataPdu {
    /// Create a new lock PDU.
    pub fn new(clip_data_id: u32) -> Self {
        Self { clip_data_id }
    }
}

impl Encode for LockClipDataPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = ClipboardHeader::new(
            ClipboardMsgType::LockClipData,
            ClipboardMsgFlags::NONE,
            4,
        );
        header.encode(dst)?;
        dst.write_u32_le(self.clip_data_id, "LockClipDataPdu::clipDataId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "LockClipDataPdu"
    }

    fn size(&self) -> usize {
        CLIPBOARD_HEADER_SIZE + 4
    }
}

impl LockClipDataPdu {
    /// Decode from cursor after the clipboard header has been read.
    pub fn decode_body(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let clip_data_id = src.read_u32_le("LockClipDataPdu::clipDataId")?;
        Ok(Self { clip_data_id })
    }
}

/// Unlock Clipboard Data PDU -- MS-RDPECLIP 2.2.4.2
///
/// 12 bytes total: 8-byte header + 4-byte clipDataId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockClipDataPdu {
    /// MUST match a prior Lock PDU's clipDataId.
    pub clip_data_id: u32,
}

impl UnlockClipDataPdu {
    /// Create a new unlock PDU.
    pub fn new(clip_data_id: u32) -> Self {
        Self { clip_data_id }
    }
}

impl Encode for UnlockClipDataPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = ClipboardHeader::new(
            ClipboardMsgType::UnlockClipData,
            ClipboardMsgFlags::NONE,
            4,
        );
        header.encode(dst)?;
        dst.write_u32_le(self.clip_data_id, "UnlockClipDataPdu::clipDataId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "UnlockClipDataPdu"
    }

    fn size(&self) -> usize {
        CLIPBOARD_HEADER_SIZE + 4
    }
}

impl UnlockClipDataPdu {
    /// Decode from cursor after the clipboard header has been read.
    pub fn decode_body(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let clip_data_id = src.read_u32_le("UnlockClipDataPdu::clipDataId")?;
        Ok(Self { clip_data_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_core::Decode;

    use super::super::header::ClipboardHeader;

    #[test]
    fn lock_pdu_roundtrip() {
        let pdu = LockClipDataPdu::new(42);
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = ClipboardHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, ClipboardMsgType::LockClipData);
        assert_eq!(header.data_len, 4);
        let clip_data_id = cursor.read_u32_le("clipDataId").unwrap();
        assert_eq!(clip_data_id, 42);
    }

    #[test]
    fn unlock_pdu_roundtrip() {
        let pdu = UnlockClipDataPdu::new(42);
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = ClipboardHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, ClipboardMsgType::UnlockClipData);
        assert_eq!(header.data_len, 4);
        let clip_data_id = cursor.read_u32_le("clipDataId").unwrap();
        assert_eq!(clip_data_id, 42);
    }

    #[test]
    fn lock_pdu_wire_format() {
        let pdu = LockClipDataPdu::new(0x01);
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        // msgType=0x000A, msgFlags=0x0000, dataLen=0x00000004, clipDataId=0x00000001
        assert_eq!(
            buf,
            alloc::vec![
                0x0A, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00,
            ]
        );
    }
}
