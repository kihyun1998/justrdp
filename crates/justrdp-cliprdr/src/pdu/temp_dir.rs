#![forbid(unsafe_code)]

//! Client Temporary Directory PDU -- MS-RDPECLIP 2.2.2.3

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};
use justrdp_core::Encode;

use super::header::{ClipboardHeader, ClipboardMsgFlags, ClipboardMsgType, CLIPBOARD_HEADER_SIZE};

/// Temporary directory path buffer size (260 UTF-16LE code units = 520 bytes).
const TEMP_DIR_BUFFER_SIZE: usize = 520;

/// Client Temporary Directory PDU -- MS-RDPECLIP 2.2.2.3
///
/// 528 bytes total: 8-byte header + 520-byte path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempDirectoryPdu {
    /// Absolute local path for temporary clipboard files.
    pub temp_dir: String,
}

impl TempDirectoryPdu {
    /// Create a new temporary directory PDU.
    pub fn new(temp_dir: String) -> Self {
        Self { temp_dir }
    }

    /// Create an empty temporary directory PDU (signals no temp dir).
    pub fn empty() -> Self {
        Self {
            temp_dir: String::new(),
        }
    }
}

impl Encode for TempDirectoryPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = ClipboardHeader::new(
            ClipboardMsgType::TempDirectory,
            ClipboardMsgFlags::NONE,
            TEMP_DIR_BUFFER_SIZE as u32,
        );
        header.encode(dst)?;

        // Encode path as UTF-16LE into 520-byte buffer.
        let mut buf = [0u8; TEMP_DIR_BUFFER_SIZE];
        let mut offset = 0;
        for code_unit in self.temp_dir.encode_utf16() {
            if offset + 2 > TEMP_DIR_BUFFER_SIZE - 2 {
                break;
            }
            buf[offset] = code_unit as u8;
            buf[offset + 1] = (code_unit >> 8) as u8;
            offset += 2;
        }
        dst.write_slice(&buf, "TempDirectoryPdu::wszTempDir")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TempDirectoryPdu"
    }

    fn size(&self) -> usize {
        CLIPBOARD_HEADER_SIZE + TEMP_DIR_BUFFER_SIZE
    }
}

impl TempDirectoryPdu {
    /// Decode from cursor after the clipboard header has been read.
    pub fn decode_body(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let dir_bytes = src.read_slice(TEMP_DIR_BUFFER_SIZE, "TempDirectoryPdu::wszTempDir")?;

        let mut code_units = Vec::new();
        for chunk in dir_bytes.chunks_exact(2) {
            let cu = u16::from_le_bytes([chunk[0], chunk[1]]);
            if cu == 0 {
                break;
            }
            code_units.push(cu);
        }

        let temp_dir = String::from_utf16(&code_units).map_err(|_| {
            DecodeError::invalid_value("TempDirectoryPdu", "wszTempDir")
        })?;

        Ok(Self { temp_dir })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_dir_roundtrip() {
        let pdu = TempDirectoryPdu::new(String::from("c:\\temp\\clipdata"));
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        assert_eq!(buf.len(), 528); // 8 + 520

        // Skip header, decode body
        let mut cursor = ReadCursor::new(&buf[CLIPBOARD_HEADER_SIZE..]);
        let decoded = TempDirectoryPdu::decode_body(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn temp_dir_empty() {
        let pdu = TempDirectoryPdu::empty();
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf[CLIPBOARD_HEADER_SIZE..]);
        let decoded = TempDirectoryPdu::decode_body(&mut cursor).unwrap();
        assert_eq!(decoded.temp_dir, "");
    }
}
