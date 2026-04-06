#![forbid(unsafe_code)]

//! TPKT (RFC 1006) -- TCP framing for ISO transport.
//!
//! Every RDP slow-path PDU is wrapped in a 4-byte TPKT header:
//! ```text
//! ┌─────────┬──────────┬──────────────────┐
//! │ version │ reserved │ length (16-bit)  │
//! │  (0x03) │  (0x00)  │ (incl. header)   │
//! └─────────┴──────────┴──────────────────┘
//! ```

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult, PduHint};

/// TPKT protocol version.
pub const TPKT_VERSION: u8 = 3;

/// TPKT header size in bytes.
pub const TPKT_HEADER_SIZE: usize = 4;

/// Maximum TPKT packet length (u16::MAX).
pub const TPKT_MAX_LENGTH: usize = 65535;

/// TPKT header (RFC 1006).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpktHeader {
    /// Total packet length including this 4-byte header.
    pub length: u16,
}

impl TpktHeader {
    /// Create a new TPKT header with the given total length.
    pub fn new(length: u16) -> Self {
        Self { length }
    }

    /// Create a TPKT header for a payload of the given size.
    ///
    /// Panics if `payload_len + TPKT_HEADER_SIZE` exceeds `u16::MAX`.
    pub fn for_payload(payload_len: usize) -> Self {
        let total = payload_len + TPKT_HEADER_SIZE;
        assert!(total <= TPKT_MAX_LENGTH, "TPKT payload too large: {total} > {TPKT_MAX_LENGTH}");
        Self {
            length: total as u16,
        }
    }

    /// Returns the payload length (total length minus header).
    pub fn payload_length(&self) -> usize {
        (self.length as usize).saturating_sub(TPKT_HEADER_SIZE)
    }
}

impl Encode for TpktHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(TPKT_VERSION, "TpktHeader::version")?;
        dst.write_u8(0, "TpktHeader::reserved")?;
        dst.write_u16_be(self.length, "TpktHeader::length")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TpktHeader"
    }

    fn size(&self) -> usize {
        TPKT_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for TpktHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let version = src.read_u8("TpktHeader::version")?;
        if version != TPKT_VERSION {
            return Err(DecodeError::unexpected_value(
                "TpktHeader",
                "version",
                "expected 3",
            ));
        }

        let _reserved = src.read_u8("TpktHeader::reserved")?;
        let length = src.read_u16_be("TpktHeader::length")?;

        if (length as usize) < TPKT_HEADER_SIZE {
            return Err(DecodeError::invalid_value("TpktHeader", "length"));
        }

        Ok(Self { length })
    }
}

/// PduHint implementation for TPKT -- determines PDU boundaries.
pub struct TpktHint;

impl PduHint for TpktHint {
    fn find_size(&self, bytes: &[u8]) -> Option<(bool, usize)> {
        if bytes.is_empty() {
            return None;
        }

        // Check if this is a fast-path PDU (first byte != 0x03)
        if bytes[0] != TPKT_VERSION {
            return fast_path_find_size(bytes);
        }

        // TPKT: need at least 4 bytes for the header
        if bytes.len() < TPKT_HEADER_SIZE {
            return None;
        }

        // TPKT: length is big-endian u16 at bytes[2..4]
        let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        Some((false, length))
    }
}

/// Determine the size of a fast-path PDU.
///
/// Fast-path header:
/// - byte 0: action (2 bits) | numEvents (4 bits) | flags (2 bits)
/// - byte 1: length1 (if bit 7 clear: 7-bit length; if set: 15-bit length with byte 2)
fn fast_path_find_size(bytes: &[u8]) -> Option<(bool, usize)> {
    if bytes.len() < 2 {
        return None;
    }

    let length1 = bytes[1];
    if length1 & 0x80 == 0 {
        // Single-byte length (7 bits)
        Some((true, length1 as usize))
    } else {
        // Two-byte length (15 bits)
        if bytes.len() < 3 {
            return None;
        }
        let length = (((length1 & 0x7F) as usize) << 8) | (bytes[2] as usize);
        Some((true, length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpkt_roundtrip() {
        let header = TpktHeader::new(42);
        let mut buf = [0u8; 4];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = TpktHeader::decode(&mut cursor).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn tpkt_for_payload() {
        let header = TpktHeader::for_payload(100);
        assert_eq!(header.length, 104);
        assert_eq!(header.payload_length(), 100);
    }

    #[test]
    fn tpkt_invalid_version() {
        let buf = [0x04, 0x00, 0x00, 0x04];
        let mut cursor = ReadCursor::new(&buf);
        assert!(TpktHeader::decode(&mut cursor).is_err());
    }

    #[test]
    fn tpkt_hint_slow_path() {
        let hint = TpktHint;
        let buf = [0x03, 0x00, 0x00, 0x2A]; // TPKT, length=42
        assert_eq!(hint.find_size(&buf), Some((false, 42)));
    }

    #[test]
    fn tpkt_hint_fast_path_short() {
        let hint = TpktHint;
        let buf = [0x00, 0x10]; // fast-path, length=16
        assert_eq!(hint.find_size(&buf), Some((true, 16)));
    }

    #[test]
    fn tpkt_hint_fast_path_long() {
        let hint = TpktHint;
        let buf = [0x00, 0x80 | 0x01, 0x00]; // fast-path, length=256
        assert_eq!(hint.find_size(&buf), Some((true, 256)));
    }

    #[test]
    fn tpkt_hint_not_enough() {
        let hint = TpktHint;
        let buf = [0x03, 0x00];
        assert_eq!(hint.find_size(&buf), None);
    }

    #[test]
    fn tpkt_length_too_small() {
        // Length = 2, which is less than TPKT_HEADER_SIZE (4)
        let buf = [0x03, 0x00, 0x00, 0x02];
        let mut cursor = ReadCursor::new(&buf);
        assert!(TpktHeader::decode(&mut cursor).is_err());
    }

    #[test]
    fn tpkt_hint_empty() {
        let hint = TpktHint;
        assert_eq!(hint.find_size(&[]), None);
    }

    #[test]
    fn tpkt_wire_format_known_answer() {
        // Verify exact wire bytes (catches endianness bugs that roundtrip misses)
        let header = TpktHeader::new(0x002A); // length=42
        let mut buf = [0u8; 4];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor).unwrap();
        assert_eq!(&buf, &[0x03, 0x00, 0x00, 0x2A]); // version=3, reserved=0, length BE
    }

    #[test]
    fn tpkt_minimum_valid_length() {
        // length == 4 (header only, zero payload)
        let buf = [0x03, 0x00, 0x00, 0x04];
        let mut cursor = ReadCursor::new(&buf);
        let header = TpktHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.length, 4);
        assert_eq!(header.payload_length(), 0);
    }

    #[test]
    fn tpkt_hint_fast_path_long_partial() {
        // bit 7 set → two-byte form, but only 2 bytes available (need 3)
        let hint = TpktHint;
        let buf = [0x00, 0x81];
        assert_eq!(hint.find_size(&buf), None);
    }

    #[test]
    fn tpkt_hint_fast_path_one_byte() {
        let hint = TpktHint;
        assert_eq!(hint.find_size(&[0x00]), None);
    }
}
