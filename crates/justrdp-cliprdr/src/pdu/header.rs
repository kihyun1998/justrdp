#![forbid(unsafe_code)]

//! CLIPRDR_HEADER -- MS-RDPECLIP 2.2.1
//!
//! 8-byte header present in all clipboard PDUs.

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};
use justrdp_core::{Decode, Encode};

/// Clipboard PDU header size in bytes.
pub const CLIPBOARD_HEADER_SIZE: usize = 8;

/// Clipboard PDU message type -- MS-RDPECLIP 2.2.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ClipboardMsgType {
    /// Server Monitor Ready PDU.
    MonitorReady = 0x0001,
    /// Format List PDU.
    FormatList = 0x0002,
    /// Format List Response PDU.
    FormatListResponse = 0x0003,
    /// Format Data Request PDU.
    FormatDataRequest = 0x0004,
    /// Format Data Response PDU.
    FormatDataResponse = 0x0005,
    /// Client Temporary Directory PDU.
    TempDirectory = 0x0006,
    /// Clipboard Capabilities PDU.
    ClipCaps = 0x0007,
    /// File Contents Request PDU.
    FileContentsRequest = 0x0008,
    /// File Contents Response PDU.
    FileContentsResponse = 0x0009,
    /// Lock Clipboard Data PDU.
    LockClipData = 0x000A,
    /// Unlock Clipboard Data PDU.
    UnlockClipData = 0x000B,
}

impl ClipboardMsgType {
    /// Try to convert a u16 value to a ClipboardMsgType.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::MonitorReady),
            0x0002 => Some(Self::FormatList),
            0x0003 => Some(Self::FormatListResponse),
            0x0004 => Some(Self::FormatDataRequest),
            0x0005 => Some(Self::FormatDataResponse),
            0x0006 => Some(Self::TempDirectory),
            0x0007 => Some(Self::ClipCaps),
            0x0008 => Some(Self::FileContentsRequest),
            0x0009 => Some(Self::FileContentsResponse),
            0x000A => Some(Self::LockClipData),
            0x000B => Some(Self::UnlockClipData),
            _ => None,
        }
    }
}

/// Clipboard PDU message flags -- MS-RDPECLIP 2.2.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardMsgFlags(u16);

impl ClipboardMsgFlags {
    /// No flags set.
    pub const NONE: Self = Self(0x0000);
    /// Request completed successfully.
    pub const CB_RESPONSE_OK: Self = Self(0x0001);
    /// Request failed.
    pub const CB_RESPONSE_FAIL: Self = Self(0x0002);
    /// Format names are ASCII-8 encoded (short format names only).
    pub const CB_ASCII_NAMES: Self = Self(0x0004);

    /// Create from raw u16 value.
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Get the raw u16 value.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Check if a specific flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Common header for all clipboard PDUs -- MS-RDPECLIP 2.2.1
///
/// ```text
/// ┌────────────┬────────────┬────────────┐
/// │ msgType    │ msgFlags   │ dataLen    │
/// │ (2 bytes)  │ (2 bytes)  │ (4 bytes)  │
/// └────────────┴────────────┴────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardHeader {
    /// PDU type identifier.
    pub msg_type: ClipboardMsgType,
    /// Message flags.
    pub msg_flags: ClipboardMsgFlags,
    /// Byte count of data following this header.
    pub data_len: u32,
}

impl ClipboardHeader {
    /// Create a new clipboard header.
    pub fn new(msg_type: ClipboardMsgType, msg_flags: ClipboardMsgFlags, data_len: u32) -> Self {
        Self {
            msg_type,
            msg_flags,
            data_len,
        }
    }
}

impl Encode for ClipboardHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.msg_type as u16, "ClipboardHeader::msgType")?;
        dst.write_u16_le(self.msg_flags.bits(), "ClipboardHeader::msgFlags")?;
        dst.write_u32_le(self.data_len, "ClipboardHeader::dataLen")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ClipboardHeader"
    }

    fn size(&self) -> usize {
        CLIPBOARD_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for ClipboardHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let raw_type = src.read_u16_le("ClipboardHeader::msgType")?;
        let msg_type = ClipboardMsgType::from_u16(raw_type).ok_or_else(|| {
            DecodeError::invalid_value("ClipboardHeader", "msgType")
        })?;
        let msg_flags = ClipboardMsgFlags::from_bits(src.read_u16_le("ClipboardHeader::msgFlags")?);
        let data_len = src.read_u32_le("ClipboardHeader::dataLen")?;

        Ok(Self {
            msg_type,
            msg_flags,
            data_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = ClipboardHeader::new(
            ClipboardMsgType::ClipCaps,
            ClipboardMsgFlags::NONE,
            0x10,
        );
        let mut buf = [0u8; CLIPBOARD_HEADER_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClipboardHeader::decode(&mut cursor).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn header_monitor_ready() {
        // MS-RDPECLIP 4.1.2
        let bytes = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let header = ClipboardHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, ClipboardMsgType::MonitorReady);
        assert_eq!(header.msg_flags, ClipboardMsgFlags::NONE);
        assert_eq!(header.data_len, 0);
    }
}
