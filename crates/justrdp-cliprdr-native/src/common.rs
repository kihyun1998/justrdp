//! Common clipboard format utilities shared across all platforms.
//!
//! Handles RDP clipboard format ID mapping and UTF-16LE ↔ UTF-8 conversion.

use justrdp_cliprdr::pdu::LongFormatName;
use justrdp_cliprdr::{ClipboardResult, FormatListResponse};

// Standard clipboard format IDs -- MS-RDPECLIP 2.2.1
pub const CF_TEXT: u32 = 0x0001;
pub const CF_DIB: u32 = 0x0008;
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

/// Check if a format ID is an image format we support.
pub fn is_image_format(format_id: u32) -> bool {
    format_id == CF_DIB
}

/// Check if a format ID is any format we support (text or image).
pub fn is_supported_format(format_id: u32) -> bool {
    is_text_format(format_id) || is_image_format(format_id)
}

/// Minimum size of a BITMAPINFOHEADER (MS-WMF 2.2.2.3).
const BITMAPINFOHEADER_SIZE: usize = 40;

/// Convert RDP CF_DIB data to BMP file data.
///
/// CF_DIB = BITMAPINFOHEADER + pixel data.
/// BMP = BITMAPFILEHEADER (14 bytes) + BITMAPINFOHEADER + pixel data.
pub fn dib_to_bmp(dib: &[u8]) -> Option<Vec<u8>> {
    if dib.len() < BITMAPINFOHEADER_SIZE {
        return None;
    }

    let bi_size = u32::from_le_bytes(dib[0..4].try_into().ok()?);
    if (bi_size as usize) < BITMAPINFOHEADER_SIZE {
        return None;
    }

    let file_size = (14 + dib.len()) as u32;
    let data_offset = 14 + bi_size;

    let mut bmp = Vec::with_capacity(14 + dib.len());
    // BITMAPFILEHEADER (14 bytes)
    bmp.extend_from_slice(&[0x42, 0x4D]); // 'BM' signature
    bmp.extend_from_slice(&file_size.to_le_bytes());
    bmp.extend_from_slice(&[0, 0, 0, 0]); // reserved
    bmp.extend_from_slice(&data_offset.to_le_bytes());
    // DIB data (BITMAPINFOHEADER + pixels)
    bmp.extend_from_slice(dib);

    Some(bmp)
}

/// Convert BMP file data to RDP CF_DIB data.
///
/// Strips the 14-byte BITMAPFILEHEADER, leaving BITMAPINFOHEADER + pixels.
pub fn bmp_to_dib(bmp: &[u8]) -> Option<Vec<u8>> {
    if bmp.len() < 14 + BITMAPINFOHEADER_SIZE {
        return None;
    }
    // Verify BMP signature
    if bmp[0] != 0x42 || bmp[1] != 0x4D {
        return None;
    }
    Some(bmp[14..].to_vec())
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

/// Accept a format list if it contains any supported format (text or image).
pub fn accept_supported_format_list(
    formats: &[LongFormatName],
) -> ClipboardResult<FormatListResponse> {
    if formats.iter().any(|f| is_supported_format(f.format_id)) {
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
        assert!(!is_text_format(CF_DIB));
    }

    #[test]
    fn is_image_format_check() {
        assert!(is_image_format(CF_DIB));
        assert!(!is_image_format(CF_TEXT));
        assert!(!is_image_format(CF_UNICODETEXT));
    }

    #[test]
    fn is_supported_format_check() {
        assert!(is_supported_format(CF_TEXT));
        assert!(is_supported_format(CF_UNICODETEXT));
        assert!(is_supported_format(CF_DIB));
        assert!(!is_supported_format(0x9999));
    }

    #[test]
    fn dib_to_bmp_roundtrip() {
        // Create a minimal valid DIB (BITMAPINFOHEADER, 1x1 pixel, 24-bit)
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes()); // biSize
        dib.extend_from_slice(&1i32.to_le_bytes()); // biWidth
        dib.extend_from_slice(&1i32.to_le_bytes()); // biHeight
        dib.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
        dib.extend_from_slice(&24u16.to_le_bytes()); // biBitCount
        dib.extend_from_slice(&0u32.to_le_bytes()); // biCompression (BI_RGB)
        dib.extend_from_slice(&4u32.to_le_bytes()); // biSizeImage
        dib.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
        dib.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant
        dib.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]); // 1 pixel BGR + padding

        let bmp = dib_to_bmp(&dib).unwrap();
        assert_eq!(bmp[0], 0x42); // 'B'
        assert_eq!(bmp[1], 0x4D); // 'M'
        assert_eq!(bmp.len(), 14 + dib.len());

        // Roundtrip: BMP back to DIB
        let recovered = bmp_to_dib(&bmp).unwrap();
        assert_eq!(recovered, dib);
    }

    #[test]
    fn dib_to_bmp_too_short() {
        assert!(dib_to_bmp(&[0; 39]).is_none()); // Less than BITMAPINFOHEADER
    }

    #[test]
    fn bmp_to_dib_invalid_signature() {
        let mut data = vec![0u8; 54]; // 14 + 40
        data[0] = 0x00; // Wrong signature
        assert!(bmp_to_dib(&data).is_none());
    }

    #[test]
    fn bmp_to_dib_too_short() {
        assert!(bmp_to_dib(&[0x42, 0x4D]).is_none()); // Just signature, no data
    }
}
