#![forbid(unsafe_code)]

//! Base64URL encoding/decoding (RFC 4648 §5).
//!
//! URL-safe Base64 with no padding, used for JWS/JWK in RDSAAD authentication.

use alloc::vec::Vec;

/// Base64URL alphabet (RFC 4648 §5).
const ENCODE_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes to Base64URL without padding.
pub fn encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((data.len() + 2) / 3 * 4);
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ENCODE_TABLE[((triple >> 18) & 0x3F) as usize]);
        out.push(ENCODE_TABLE[((triple >> 12) & 0x3F) as usize]);

        if chunk.len() > 1 {
            out.push(ENCODE_TABLE[((triple >> 6) & 0x3F) as usize]);
        }
        if chunk.len() > 2 {
            out.push(ENCODE_TABLE[(triple & 0x3F) as usize]);
        }
    }

    out
}

/// Encode bytes to Base64URL as a UTF-8 string (no padding).
pub fn encode_string(data: &[u8]) -> alloc::string::String {
    // SAFETY: ENCODE_TABLE only contains ASCII characters
    let bytes = encode(data);
    // All bytes are ASCII, so this is valid UTF-8
    alloc::string::String::from_utf8(bytes).unwrap_or_default()
}

/// Decode Base64URL bytes. Tolerates both padded and unpadded input.
pub fn decode(data: &[u8]) -> Option<Vec<u8>> {
    // Strip padding if present
    let data = if data.ends_with(b"==") {
        &data[..data.len() - 2]
    } else if data.ends_with(b"=") {
        &data[..data.len() - 1]
    } else {
        data
    };

    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        let val = decode_char(byte)?;
        buf = (buf << 6) | val as u32;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Some(out)
}

/// Decode a single Base64URL character to its 6-bit value.
fn decode_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty() {
        assert_eq!(encode(b""), b"");
    }

    #[test]
    fn encode_one_byte() {
        // 'f' = 0x66 → base64url "Zg"
        assert_eq!(encode(b"f"), b"Zg");
    }

    #[test]
    fn encode_two_bytes() {
        // 'fo' → "Zm8"
        assert_eq!(encode(b"fo"), b"Zm8");
    }

    #[test]
    fn encode_three_bytes() {
        // 'foo' → "Zm9v"
        assert_eq!(encode(b"foo"), b"Zm9v");
    }

    #[test]
    fn encode_rfc4648_vectors() {
        // RFC 4648 §10 test vectors (same as standard base64 but with -_ instead of +/)
        assert_eq!(encode(b""), b"");
        assert_eq!(encode(b"f"), b"Zg");
        assert_eq!(encode(b"fo"), b"Zm8");
        assert_eq!(encode(b"foo"), b"Zm9v");
        assert_eq!(encode(b"foob"), b"Zm9vYg");
        assert_eq!(encode(b"fooba"), b"Zm9vYmE");
        assert_eq!(encode(b"foobar"), b"Zm9vYmFy");
    }

    #[test]
    fn decode_rfc4648_vectors() {
        assert_eq!(decode(b"").unwrap(), b"");
        assert_eq!(decode(b"Zg").unwrap(), b"f");
        assert_eq!(decode(b"Zm8").unwrap(), b"fo");
        assert_eq!(decode(b"Zm9v").unwrap(), b"foo");
        assert_eq!(decode(b"Zm9vYg").unwrap(), b"foob");
        assert_eq!(decode(b"Zm9vYmE").unwrap(), b"fooba");
        assert_eq!(decode(b"Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn decode_with_padding() {
        // Tolerates standard padding
        assert_eq!(decode(b"Zg==").unwrap(), b"f");
        assert_eq!(decode(b"Zm8=").unwrap(), b"fo");
    }

    #[test]
    fn decode_invalid_char() {
        assert!(decode(b"Zg!@").is_none());
    }

    #[test]
    fn roundtrip() {
        let data = b"Hello, Base64URL! \x00\xFF\x80";
        let encoded = encode(data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn url_safe_chars() {
        // Bytes that would produce + and / in standard base64
        // should produce - and _ in base64url
        let data = [0xFB, 0xFF, 0xFE]; // produces +//+ in standard base64
        let encoded = encode(&data);
        assert!(!encoded.contains(&b'+'));
        assert!(!encoded.contains(&b'/'));
        // Should contain - or _ instead
        let encoded_str = core::str::from_utf8(&encoded).unwrap();
        assert!(encoded_str.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn encode_string_produces_valid_utf8() {
        let s = encode_string(b"test data for JWT");
        assert!(!s.is_empty());
        // Should be valid UTF-8 (all ASCII)
        assert!(s.is_ascii());
    }
}
