//! Common clipboard format utilities shared across all platforms.
//!
//! Handles RDP clipboard format ID mapping and UTF-16LE ↔ UTF-8 conversion.

use justrdp_cliprdr::pdu::LongFormatName;
use justrdp_cliprdr::{ClipboardResult, FormatListResponse};

// Standard clipboard format IDs -- MS-RDPECLIP 2.2.1
pub const CF_TEXT: u32 = 0x0001;
pub const CF_DIB: u32 = 0x0008;
pub const CF_UNICODETEXT: u32 = 0x000D;

/// Maximum clipboard data size (4 MiB). Applied to both read and decode paths.
pub(crate) const MAX_CLIPBOARD_BYTES: usize = 4 * 1024 * 1024;

/// Convert RDP clipboard data to a UTF-8 string.
///
/// - `CF_UNICODETEXT`: data is UTF-16LE (with or without null terminator)
/// - `CF_TEXT`: data is ASCII/ANSI (with or without null terminator)
///
/// Returns `None` if data exceeds 4 MiB or is invalid.
pub fn rdp_to_utf8(data: &[u8], format_id: u32) -> Option<String> {
    if data.len() > MAX_CLIPBOARD_BYTES {
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

/// Valid biBitCount values for a BITMAPINFOHEADER.
const VALID_BIT_COUNTS: &[u16] = &[0, 1, 4, 8, 16, 24, 32];

/// Check if `data` looks like a valid CF_DIB payload.
///
/// Validates: minimum size, biSize fits in data, biBitCount is a valid value.
/// This avoids false positives from text data being misidentified as DIB.
pub fn looks_like_dib(data: &[u8]) -> bool {
    if data.len() < BITMAPINFOHEADER_SIZE {
        return false;
    }
    let bi_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if (bi_size as usize) < BITMAPINFOHEADER_SIZE || (bi_size as usize) > data.len() {
        return false;
    }
    // Validate biBitCount (offset 14-15 in BITMAPINFOHEADER)
    let bit_count = u16::from_le_bytes([data[14], data[15]]);
    VALID_BIT_COUNTS.contains(&bit_count)
}

/// Compute the color table size in bytes for a DIB header.
///
/// For biBitCount <= 8, the color table has `biClrUsed` entries (or
/// `1 << biBitCount` if biClrUsed is 0). Each entry is 4 bytes (RGBQUAD).
fn color_table_size(dib: &[u8]) -> Option<u32> {
    if dib.len() < BITMAPINFOHEADER_SIZE {
        return Some(0);
    }
    let bit_count = u16::from_le_bytes([dib[14], dib[15]]);
    if bit_count > 8 {
        return Some(0); // No color table for 16/24/32-bit
    }
    let clr_used = u32::from_le_bytes([dib[32], dib[33], dib[34], dib[35]]);
    let entries = if clr_used > 0 {
        clr_used
    } else if bit_count > 0 {
        1u32 << bit_count
    } else {
        0
    };
    entries.checked_mul(4) // Each RGBQUAD is 4 bytes
}

/// Convert RDP CF_DIB data to BMP file data.
///
/// CF_DIB = BITMAPINFOHEADER [+ color table] + pixel data.
/// BMP = BITMAPFILEHEADER (14 bytes) + BITMAPINFOHEADER [+ color table] + pixel data.
pub fn dib_to_bmp(dib: &[u8]) -> Option<Vec<u8>> {
    if dib.len() < BITMAPINFOHEADER_SIZE {
        return None;
    }

    let bi_size = u32::from_le_bytes(dib[0..4].try_into().ok()?);
    if (bi_size as usize) < BITMAPINFOHEADER_SIZE || (bi_size as usize) > dib.len() {
        return None;
    }

    let ct_size = color_table_size(dib)?;
    let file_size = u32::try_from(dib.len()).ok()?.checked_add(14)?;
    let data_offset = 14u32.checked_add(bi_size)?.checked_add(ct_size)?;

    let mut bmp = Vec::with_capacity(14 + dib.len());
    // BITMAPFILEHEADER (14 bytes)
    bmp.extend_from_slice(&[0x42, 0x4D]); // 'BM' signature
    bmp.extend_from_slice(&file_size.to_le_bytes());
    bmp.extend_from_slice(&[0, 0, 0, 0]); // reserved
    bmp.extend_from_slice(&data_offset.to_le_bytes());
    // DIB data (BITMAPINFOHEADER + [color table +] pixels)
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

    #[test]
    fn dib_to_bmp_palettized_8bit() {
        // 8-bit palettized DIB with 256 color table entries.
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes()); // biSize
        dib.extend_from_slice(&2i32.to_le_bytes()); // biWidth
        dib.extend_from_slice(&1i32.to_le_bytes()); // biHeight
        dib.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
        dib.extend_from_slice(&8u16.to_le_bytes()); // biBitCount = 8
        dib.extend_from_slice(&0u32.to_le_bytes()); // biCompression (BI_RGB)
        dib.extend_from_slice(&4u32.to_le_bytes()); // biSizeImage
        dib.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
        dib.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
        dib.extend_from_slice(&256u32.to_le_bytes()); // biClrUsed = 256
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant
        // Color table: 256 * 4 = 1024 bytes
        dib.extend(std::iter::repeat(0u8).take(1024));
        // Pixel data: 2 pixels + 2 padding = 4 bytes
        dib.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);

        let bmp = dib_to_bmp(&dib).unwrap();
        // bfOffBits = 14 (file header) + 40 (info header) + 1024 (color table) = 1078
        let bf_off_bits = u32::from_le_bytes(bmp[10..14].try_into().unwrap());
        assert_eq!(bf_off_bits, 1078);

        // Roundtrip
        let recovered = bmp_to_dib(&bmp).unwrap();
        assert_eq!(recovered, dib);
    }

    #[test]
    fn dib_to_bmp_palettized_4bit_implicit() {
        // 4-bit palettized DIB with biClrUsed=0 (implicit 16-entry color table).
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes()); // biSize
        dib.extend_from_slice(&4i32.to_le_bytes()); // biWidth
        dib.extend_from_slice(&1i32.to_le_bytes()); // biHeight
        dib.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
        dib.extend_from_slice(&4u16.to_le_bytes()); // biBitCount = 4
        dib.extend_from_slice(&0u32.to_le_bytes()); // biCompression
        dib.extend_from_slice(&4u32.to_le_bytes()); // biSizeImage
        dib.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
        dib.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed = 0 (implicit)
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant
        // Color table: 16 entries * 4 = 64 bytes
        dib.extend(std::iter::repeat(0u8).take(64));
        // Pixel data: 4 pixels (2 bytes) + 2 padding = 4 bytes
        dib.extend_from_slice(&[0x12, 0x34, 0x00, 0x00]);

        let bmp = dib_to_bmp(&dib).unwrap();
        // bfOffBits = 14 + 40 + 64 = 118
        let bf_off_bits = u32::from_le_bytes(bmp[10..14].try_into().unwrap());
        assert_eq!(bf_off_bits, 118);
    }

    #[test]
    fn color_table_overflow_rejected() {
        // biClrUsed = 0x40000001 would overflow entries*4. Should return None.
        let mut dib = vec![0u8; 44];
        dib[0..4].copy_from_slice(&40u32.to_le_bytes()); // biSize
        dib[14..16].copy_from_slice(&8u16.to_le_bytes()); // biBitCount = 8
        dib[32..36].copy_from_slice(&0x4000_0001u32.to_le_bytes()); // biClrUsed overflow
        assert!(dib_to_bmp(&dib).is_none());
    }

    #[test]
    fn looks_like_dib_valid_24bit() {
        let mut dib = vec![0u8; 44]; // 40 header + 4 pixels
        dib[0..4].copy_from_slice(&40u32.to_le_bytes()); // biSize
        dib[14..16].copy_from_slice(&24u16.to_le_bytes()); // biBitCount
        assert!(looks_like_dib(&dib));
    }

    #[test]
    fn looks_like_dib_rejects_text() {
        // "Hello" in UTF-16LE — bi_size = u32 of [0x48, 0x00, 0x65, 0x00] = 6619208
        let data = b"H\x00e\x00l\x00l\x00o\x00 \x00w\x00o\x00r\x00l\x00d\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        // bi_size = 6619208 which is > data.len(), so biSize check fails
        assert!(!looks_like_dib(data));
    }

    #[test]
    fn looks_like_dib_rejects_invalid_bitcount() {
        let mut dib = vec![0u8; 44];
        dib[0..4].copy_from_slice(&40u32.to_le_bytes()); // biSize
        dib[14..16].copy_from_slice(&13u16.to_le_bytes()); // biBitCount = 13 (invalid)
        assert!(!looks_like_dib(&dib));
    }

    #[test]
    fn looks_like_dib_too_short() {
        assert!(!looks_like_dib(&[0u8; 39]));
    }

    #[test]
    fn accept_supported_format_list_with_dib() {
        let formats = vec![LongFormatName {
            format_id: CF_DIB,
            format_name: String::new(),
        }];
        let result = accept_supported_format_list(&formats).unwrap();
        assert_eq!(result, FormatListResponse::Ok);
    }

    #[test]
    fn accept_supported_format_list_rejects_unsupported() {
        let formats = vec![LongFormatName {
            format_id: 0x9999,
            format_name: String::new(),
        }];
        let result = accept_supported_format_list(&formats).unwrap();
        assert_eq!(result, FormatListResponse::Fail);
    }
}
