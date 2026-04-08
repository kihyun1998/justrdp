//! Common clipboard format utilities shared across all platforms.
//!
//! Handles RDP clipboard format ID mapping and UTF-16LE ↔ UTF-8 conversion.

use justrdp_cliprdr::pdu::LongFormatName;
use justrdp_cliprdr::{ClipboardResult, FormatListResponse};

// Standard clipboard format IDs -- MS-RDPECLIP 2.2.1
pub const CF_TEXT: u32 = 0x0001;
pub const CF_UNICODETEXT: u32 = 0x000D;

/// Maximum clipboard data size to decode (4 MiB).
const MAX_CLIPBOARD_DECODE_BYTES: usize = 4 * 1024 * 1024;

/// Convert RDP clipboard data to a UTF-8 string.
///
/// - `CF_UNICODETEXT`: data is UTF-16LE (with or without null terminator)
/// - `CF_TEXT`: data is ASCII/ANSI (with or without null terminator)
///
/// Returns `None` if data exceeds 4 MiB or is invalid.
pub fn rdp_to_utf8(data: &[u8], format_id: u32) -> Option<String> {
    if data.len() > MAX_CLIPBOARD_DECODE_BYTES {
        return None;
    }

    match format_id {
        CF_UNICODETEXT => {
            if data.len() % 2 != 0 {
                return None;
            }
            let code_units: Vec<u16> = data
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            // Strip trailing null(s)
            let end = code_units
                .iter()
                .position(|&u| u == 0)
                .unwrap_or(code_units.len());
            String::from_utf16(&code_units[..end]).ok()
        }
        CF_TEXT => {
            // Strip trailing null
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            // Treat as Latin-1/ASCII. Replace C1 control chars (0x80-0x9F)
            // with U+FFFD to prevent invisible control character injection.
            Some(
                data[..end]
                    .iter()
                    .map(|&b| {
                        if (0x80..=0x9F).contains(&b) {
                            '\u{FFFD}'
                        } else {
                            b as char
                        }
                    })
                    .collect(),
            )
        }
        _ => None,
    }
}

/// Convert a UTF-8 string to RDP clipboard data.
///
/// - `CF_UNICODETEXT`: encodes as null-terminated UTF-16LE
/// - `CF_TEXT`: encodes as null-terminated ASCII (non-ASCII chars replaced with '?')
pub fn utf8_to_rdp(text: &str, format_id: u32) -> Option<Vec<u8>> {
    match format_id {
        CF_UNICODETEXT => {
            let mut buf = Vec::new();
            for code_unit in text.encode_utf16() {
                buf.extend_from_slice(&code_unit.to_le_bytes());
            }
            // Null terminator
            buf.extend_from_slice(&[0x00, 0x00]);
            Some(buf)
        }
        CF_TEXT => {
            let mut buf: Vec<u8> = text
                .chars()
                .map(|c| if c.is_ascii() { c as u8 } else { b'?' })
                .collect();
            buf.push(0); // null terminator
            Some(buf)
        }
        _ => None,
    }
}

/// Check if a format ID is a text format we support.
pub fn is_text_format(format_id: u32) -> bool {
    matches!(format_id, CF_TEXT | CF_UNICODETEXT)
}

/// Decode RDP clipboard bytes into UTF-8, auto-detecting the format.
///
/// Tries `CF_UNICODETEXT` first when the buffer length is even (UTF-16LE
/// requires byte pairs), then falls back to `CF_TEXT`.
pub fn rdp_bytes_to_utf8(data: &[u8]) -> Option<String> {
    if data.len() % 2 == 0 {
        rdp_to_utf8(data, CF_UNICODETEXT).or_else(|| rdp_to_utf8(data, CF_TEXT))
    } else {
        rdp_to_utf8(data, CF_TEXT)
    }
}

/// Accept a format list if it contains any text format we support.
pub fn accept_text_format_list(formats: &[LongFormatName]) -> ClipboardResult<FormatListResponse> {
    if formats.iter().any(|f| is_text_format(f.format_id)) {
        Ok(FormatListResponse::Ok)
    } else {
        Ok(FormatListResponse::Fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdp_to_utf8_unicode() {
        // "Hello" in UTF-16LE + null
        let data = [
            0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00, 0x00,
        ];
        assert_eq!(rdp_to_utf8(&data, CF_UNICODETEXT).unwrap(), "Hello");
    }

    #[test]
    fn rdp_to_utf8_unicode_no_null() {
        let data = [0x48, 0x00, 0x69, 0x00]; // "Hi"
        assert_eq!(rdp_to_utf8(&data, CF_UNICODETEXT).unwrap(), "Hi");
    }

    #[test]
    fn rdp_to_utf8_text() {
        let data = b"Hello\0";
        assert_eq!(rdp_to_utf8(data, CF_TEXT).unwrap(), "Hello");
    }

    #[test]
    fn rdp_to_utf8_text_c1_control_filtered() {
        // 0x85 is a C1 control char (NEL), should be replaced with U+FFFD
        let data = [b'A', 0x85, b'B', 0x00];
        let result = rdp_to_utf8(&data, CF_TEXT).unwrap();
        assert_eq!(result, "A\u{FFFD}B");
    }

    #[test]
    fn rdp_to_utf8_text_latin1_preserved() {
        // 0xE9 = é (Latin-1 Supplement, not a C1 control)
        let data = [0xE9, 0x00];
        let result = rdp_to_utf8(&data, CF_TEXT).unwrap();
        assert_eq!(result, "é");
    }

    #[test]
    fn rdp_to_utf8_oversized_rejected() {
        let data = vec![0u8; 5 * 1024 * 1024]; // 5 MiB > 4 MiB limit
        assert!(rdp_to_utf8(&data, CF_TEXT).is_none());
    }

    #[test]
    fn rdp_to_utf8_odd_bytes() {
        let data = [0x48, 0x00, 0x65]; // odd length
        assert!(rdp_to_utf8(&data, CF_UNICODETEXT).is_none());
    }

    #[test]
    fn utf8_to_rdp_unicode() {
        let data = utf8_to_rdp("Hi", CF_UNICODETEXT).unwrap();
        // "Hi" = [0x48, 0x00, 0x69, 0x00] + null [0x00, 0x00]
        assert_eq!(data, vec![0x48, 0x00, 0x69, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn utf8_to_rdp_text() {
        let data = utf8_to_rdp("Hi", CF_TEXT).unwrap();
        assert_eq!(data, vec![b'H', b'i', 0]);
    }

    #[test]
    fn utf8_to_rdp_unsupported() {
        assert!(utf8_to_rdp("test", 0x9999).is_none());
    }

    #[test]
    fn roundtrip_unicode() {
        let original = "Hello, 세계! 🌍";
        let rdp_data = utf8_to_rdp(original, CF_UNICODETEXT).unwrap();
        let back = rdp_to_utf8(&rdp_data, CF_UNICODETEXT).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn is_text_format_check() {
        assert!(is_text_format(CF_TEXT));
        assert!(is_text_format(CF_UNICODETEXT));
        assert!(!is_text_format(0x0008)); // CF_DIB
    }
}
