#![forbid(unsafe_code)]

//! Format List PDU -- MS-RDPECLIP 2.2.3.1
//! Format List Response PDU -- MS-RDPECLIP 2.2.3.2

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeError, EncodeResult};
use justrdp_core::{Decode, Encode};

use super::header::{ClipboardHeader, ClipboardMsgFlags, ClipboardMsgType, CLIPBOARD_HEADER_SIZE};

/// Short format name entry size (4 + 32 bytes) -- MS-RDPECLIP 2.2.3.1.1.1
const SHORT_FORMAT_NAME_SIZE: usize = 36;

/// Short format name -- MS-RDPECLIP 2.2.3.1.1.1
///
/// Fixed 36-byte entry: 4-byte format ID + 32-byte name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortFormatName {
    /// Clipboard format ID.
    pub format_id: u32,
    /// Format name (max 32 bytes, null-terminated).
    pub format_name: [u8; 32],
}

impl ShortFormatName {
    /// Create with a format ID and no name.
    pub fn new(format_id: u32) -> Self {
        Self {
            format_id,
            format_name: [0u8; 32],
        }
    }
}

impl Encode for ShortFormatName {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.format_id, "ShortFormatName::formatId")?;
        dst.write_slice(&self.format_name, "ShortFormatName::formatName")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ShortFormatName"
    }

    fn size(&self) -> usize {
        SHORT_FORMAT_NAME_SIZE
    }
}

impl<'de> Decode<'de> for ShortFormatName {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let format_id = src.read_u32_le("ShortFormatName::formatId")?;
        let name_bytes = src.read_slice(32, "ShortFormatName::formatName")?;
        let mut format_name = [0u8; 32];
        format_name.copy_from_slice(name_bytes);
        Ok(Self {
            format_id,
            format_name,
        })
    }
}

/// Long format name -- MS-RDPECLIP 2.2.3.1.2.1
///
/// Variable-length entry: 4-byte format ID + null-terminated UTF-16LE string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongFormatName {
    /// Clipboard format ID.
    pub format_id: u32,
    /// Format name as a Rust string (empty string if no name).
    pub format_name: String,
}

impl LongFormatName {
    /// Create a long format name entry.
    pub fn new(format_id: u32, format_name: String) -> Self {
        Self {
            format_id,
            format_name,
        }
    }

    /// Size of the UTF-16LE encoded name including null terminator.
    fn name_wire_size(&self) -> usize {
        // Each char → 1 or 2 UTF-16 code units (2 bytes each), plus null terminator (2 bytes).
        let code_units: usize = self.format_name.chars().map(|c| c.len_utf16()).sum();
        (code_units + 1) * 2
    }
}

impl Encode for LongFormatName {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.format_id, "LongFormatName::formatId")?;
        // Encode name as UTF-16LE with null terminator.
        for code_unit in self.format_name.encode_utf16() {
            dst.write_u16_le(code_unit, "LongFormatName::wszFormatName")?;
        }
        // Null terminator.
        dst.write_u16_le(0, "LongFormatName::wszFormatName::null")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "LongFormatName"
    }

    fn size(&self) -> usize {
        4 + self.name_wire_size()
    }
}

impl<'de> Decode<'de> for LongFormatName {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let format_id = src.read_u32_le("LongFormatName::formatId")?;

        // Read UTF-16LE code units until null terminator.
        // Cap at 256 code units to prevent unbounded allocation from malformed data.
        const MAX_FORMAT_NAME_CODE_UNITS: usize = 256;
        let mut code_units = Vec::new();
        loop {
            let cu = src.read_u16_le("LongFormatName::wszFormatName")?;
            if cu == 0 {
                break;
            }
            if code_units.len() >= MAX_FORMAT_NAME_CODE_UNITS {
                return Err(DecodeError::invalid_value(
                    "LongFormatName",
                    "wszFormatName too long",
                ));
            }
            code_units.push(cu);
        }

        let format_name = String::from_utf16(&code_units).map_err(|_| {
            DecodeError::invalid_value("LongFormatName", "wszFormatName")
        })?;

        Ok(Self {
            format_id,
            format_name,
        })
    }
}

/// Format List PDU -- MS-RDPECLIP 2.2.3.1
///
/// Can contain either short (36-byte fixed) or long (variable) format names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatListPdu {
    /// Short format name variant (used when long format names are not negotiated).
    Short {
        /// Whether names are ASCII (true) or UTF-16LE (false).
        ascii_names: bool,
        /// List of short format name entries.
        entries: Vec<ShortFormatName>,
    },
    /// Long format name variant (used when both endpoints set CB_USE_LONG_FORMAT_NAMES).
    Long(Vec<LongFormatName>),
}

impl FormatListPdu {
    /// Data length (after the 8-byte clipboard header).
    fn data_len(&self) -> usize {
        match self {
            Self::Short { entries, .. } => entries.len() * SHORT_FORMAT_NAME_SIZE,
            Self::Long(entries) => entries.iter().map(|e| e.size()).sum(),
        }
    }

    /// Encode this PDU including the clipboard header.
    pub fn encode_full(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let flags = match self {
            Self::Short { ascii_names: true, .. } => ClipboardMsgFlags::CB_ASCII_NAMES,
            _ => ClipboardMsgFlags::NONE,
        };
        let data_len = u32::try_from(self.data_len())
            .map_err(|_| EncodeError::invalid_value("FormatListPdu", "dataLen too large"))?;
        let header = ClipboardHeader::new(
            ClipboardMsgType::FormatList,
            flags,
            data_len,
        );
        header.encode(dst)?;
        self.encode(dst)?;
        Ok(())
    }

    /// Total wire size including the 8-byte header.
    pub fn full_size(&self) -> usize {
        CLIPBOARD_HEADER_SIZE + self.data_len()
    }
}

impl Encode for FormatListPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        match self {
            Self::Short { entries, .. } => entries.iter().try_for_each(|e| e.encode(dst)),
            Self::Long(entries) => entries.iter().try_for_each(|e| e.encode(dst)),
        }
    }

    fn name(&self) -> &'static str {
        "FormatListPdu"
    }

    fn size(&self) -> usize {
        self.data_len()
    }
}

impl FormatListPdu {
    /// Decode a format list PDU body from the cursor.
    ///
    /// `use_long_format_names`: whether both endpoints negotiated long format names.
    /// `msg_flags`: the flags from the clipboard header.
    /// `data_len`: the data length from the clipboard header.
    pub fn decode_body(
        src: &mut ReadCursor<'_>,
        use_long_format_names: bool,
        msg_flags: ClipboardMsgFlags,
        data_len: u32,
    ) -> DecodeResult<Self> {
        // Cap data_len to prevent amplified allocation from untrusted header.
        // 8 192 short entries × 36 bytes = 294 912 bytes ≈ 288 KiB.
        const MAX_SHORT_FORMAT_ENTRIES: u32 = 8_192;
        const MAX_FORMAT_LIST_DATA_LEN: u32 = MAX_SHORT_FORMAT_ENTRIES * SHORT_FORMAT_NAME_SIZE as u32;
        if data_len > MAX_FORMAT_LIST_DATA_LEN {
            return Err(DecodeError::invalid_value(
                "FormatListPdu",
                "dataLen too large",
            ));
        }
        let data_len = data_len as usize;

        if use_long_format_names {
            // Read exactly data_len bytes and decode within that boundary
            // to prevent overreading into the next PDU.
            // Note: Each LongFormatName has a minimum wire size of 6 bytes
            // (formatId:4 + null terminator:2), so MAX_FORMAT_LIST_DATA_LEN
            // caps this at ~49 152 entries. No separate entry count limit needed.
            let data = src.read_slice(data_len, "FormatListPdu::longFormatData")?;
            let mut sub = ReadCursor::new(data);
            let mut entries = Vec::new();
            while sub.remaining() > 0 {
                entries.push(LongFormatName::decode(&mut sub)?);
            }
            Ok(Self::Long(entries))
        } else {
            let count = data_len / SHORT_FORMAT_NAME_SIZE;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                entries.push(ShortFormatName::decode(src)?);
            }
            let ascii_names = msg_flags.contains(ClipboardMsgFlags::CB_ASCII_NAMES);
            Ok(Self::Short {
                ascii_names,
                entries,
            })
        }
    }
}

/// Format List Response PDU -- MS-RDPECLIP 2.2.3.2
///
/// Simple 8-byte PDU: header only, no data payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatListResponsePdu {
    /// Whether the format list was accepted.
    pub accepted: bool,
}

impl FormatListResponsePdu {
    /// Create a successful response.
    pub fn ok() -> Self {
        Self { accepted: true }
    }

    /// Create a failed response.
    pub fn fail() -> Self {
        Self { accepted: false }
    }
}

impl FormatListResponsePdu {
    /// Decode from the clipboard header flags.
    ///
    /// The response PDU has no body; the accept/reject state is encoded
    /// in the header's `msgFlags` field.
    pub fn decode_from_flags(msg_flags: ClipboardMsgFlags) -> Self {
        Self {
            accepted: msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_OK),
        }
    }
}

impl Encode for FormatListResponsePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let flags = if self.accepted {
            ClipboardMsgFlags::CB_RESPONSE_OK
        } else {
            ClipboardMsgFlags::CB_RESPONSE_FAIL
        };
        let header = ClipboardHeader::new(ClipboardMsgType::FormatListResponse, flags, 0);
        header.encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "FormatListResponsePdu"
    }

    fn size(&self) -> usize {
        CLIPBOARD_HEADER_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_format_name_roundtrip() {
        let entry = LongFormatName::new(0x0000_C004, String::from("Native"));
        let mut buf = alloc::vec![0u8; entry.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        entry.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = LongFormatName::decode(&mut cursor).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn long_format_name_empty_name() {
        let entry = LongFormatName::new(0x03, String::new());
        let mut buf = alloc::vec![0u8; entry.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        entry.encode(&mut cursor).unwrap();
        // format_id(4) + null terminator(2) = 6 bytes
        assert_eq!(buf.len(), 6);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = LongFormatName::decode(&mut cursor).unwrap();
        assert_eq!(decoded.format_name, "");
        assert_eq!(decoded.format_id, 0x03);
    }

    #[test]
    fn format_list_long_spec_test_vector() {
        // MS-RDPECLIP 4.1.5 -- Format List with Long Format Names
        let bytes: Vec<u8> = alloc::vec![
            0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, // header
            0x04, 0xC0, 0x00, 0x00, // formatId=0xC004
            0x4E, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00,
            0x76, 0x00, 0x65, 0x00, 0x00, 0x00, // "Native" + null
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // formatId=3, empty name
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // formatId=8, empty name
            0x11, 0x00, 0x00, 0x00, 0x00, 0x00, // formatId=17, empty name
        ];

        let mut cursor = ReadCursor::new(&bytes);
        let header = ClipboardHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, ClipboardMsgType::FormatList);
        assert_eq!(header.data_len, 0x24);

        let pdu =
            FormatListPdu::decode_body(&mut cursor, true, header.msg_flags, header.data_len)
                .unwrap();

        match &pdu {
            FormatListPdu::Long(entries) => {
                assert_eq!(entries.len(), 4);
                assert_eq!(entries[0].format_id, 0xC004);
                assert_eq!(entries[0].format_name, "Native");
                assert_eq!(entries[1].format_id, 0x03);
                assert_eq!(entries[1].format_name, "");
                assert_eq!(entries[2].format_id, 0x08);
                assert_eq!(entries[3].format_id, 0x11);
            }
            _ => panic!("expected Long variant"),
        }

        // Roundtrip
        let mut out = alloc::vec![0u8; pdu.full_size()];
        let mut cursor = WriteCursor::new(&mut out);
        pdu.encode_full(&mut cursor).unwrap();
        assert_eq!(out, bytes);
    }

    #[test]
    fn format_list_response_roundtrip() {
        for is_ok in [true, false] {
            let pdu = if is_ok {
                FormatListResponsePdu::ok()
            } else {
                FormatListResponsePdu::fail()
            };
            let mut buf = alloc::vec![0u8; pdu.size()];
            let mut cursor = WriteCursor::new(&mut buf);
            pdu.encode(&mut cursor).unwrap();

            let mut cursor = ReadCursor::new(&buf);
            let header = ClipboardHeader::decode(&mut cursor).unwrap();
            assert_eq!(header.msg_type, ClipboardMsgType::FormatListResponse);
            assert_eq!(header.data_len, 0);
            if is_ok {
                assert!(header.msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_OK));
            } else {
                assert!(header
                    .msg_flags
                    .contains(ClipboardMsgFlags::CB_RESPONSE_FAIL));
            }
        }
    }

    #[test]
    fn format_list_response_spec_bytes() {
        // Success: 03 00 01 00 00 00 00 00
        let pdu = FormatListResponsePdu::ok();
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        assert_eq!(buf, alloc::vec![0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Failure: 03 00 02 00 00 00 00 00
        let pdu = FormatListResponsePdu::fail();
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        assert_eq!(buf, alloc::vec![0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn short_format_name_roundtrip() {
        let entry = ShortFormatName::new(0x0001);
        let mut buf = alloc::vec![0u8; entry.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        entry.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ShortFormatName::decode(&mut cursor).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn short_format_list_roundtrip() {
        let pdu = FormatListPdu::Short {
            ascii_names: false,
            entries: alloc::vec![
                ShortFormatName::new(0x0001), // CF_TEXT
                ShortFormatName::new(0x000D), // CF_UNICODETEXT
            ],
        };

        let mut buf = alloc::vec![0u8; pdu.full_size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode_full(&mut cursor).unwrap();

        // Verify header
        let mut cursor = ReadCursor::new(&buf);
        let header = ClipboardHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, ClipboardMsgType::FormatList);
        assert_eq!(header.msg_flags, ClipboardMsgFlags::NONE);
        assert_eq!(header.data_len as usize, 2 * SHORT_FORMAT_NAME_SIZE);

        // Decode body
        let decoded = FormatListPdu::decode_body(
            &mut cursor,
            false, // short format names
            header.msg_flags,
            header.data_len,
        )
        .unwrap();

        assert_eq!(pdu, decoded);
    }

    #[test]
    fn short_format_list_ascii_names_flag() {
        let pdu = FormatListPdu::Short {
            ascii_names: true,
            entries: alloc::vec![ShortFormatName::new(0x0001)],
        };

        let mut buf = alloc::vec![0u8; pdu.full_size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode_full(&mut cursor).unwrap();

        // Verify CB_ASCII_NAMES flag is set in header
        let mut cursor = ReadCursor::new(&buf);
        let header = ClipboardHeader::decode(&mut cursor).unwrap();
        assert!(header.msg_flags.contains(ClipboardMsgFlags::CB_ASCII_NAMES));

        // Decode body with ascii_names
        let decoded = FormatListPdu::decode_body(
            &mut cursor,
            false,
            header.msg_flags,
            header.data_len,
        )
        .unwrap();

        match decoded {
            FormatListPdu::Short { ascii_names, entries } => {
                assert!(ascii_names);
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].format_id, 0x0001);
            }
            _ => panic!("expected Short variant"),
        }
    }
}
