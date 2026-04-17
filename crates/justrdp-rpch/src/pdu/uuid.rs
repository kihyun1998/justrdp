#![forbid(unsafe_code)]

//! DCE "mixed-endian" UUID wire format (MS-RPCE §2.2.2.1 /
//! C706 Appendix A).
//!
//! RPC transmits UUIDs with their first three fields in the host
//! byte order declared by the PDU's `packed_drep` label (always
//! little-endian for MS traffic) and their last 8-byte field in raw
//! big-endian. This "mixed endian" layout — **not** plain
//! little-endian — is the single most common interop bug in
//! third-party RPC stacks, so we model the UUID as its own type and
//! never let callers emit the 16 bytes by hand.

extern crate alloc;

use justrdp_core::{DecodeResult, EncodeResult, ReadCursor, WriteCursor};

/// A 128-bit UUID encoded in the DCE "mixed endian" wire format.
///
/// Byte layout on the wire (C706 §14.1):
///
/// | Offset | Size | Field       | Endianness |
/// |--------|------|-------------|------------|
/// | 0      | 4    | `Data1`     | little     |
/// | 4      | 2    | `Data2`     | little     |
/// | 6      | 2    | `Data3`     | little     |
/// | 8      | 8    | `Data4`     | big        |
///
/// For MS-RPCE traffic the PDU-header DREP always declares little
/// endian, so the first three fields are little; the last 8 bytes
/// are big-endian regardless of DREP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RpcUuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl RpcUuid {
    /// All-zero UUID (the "nil UUID").
    pub const NIL: Self = Self {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };

    /// Fixed wire size of an encoded UUID.
    pub const SIZE: usize = 16;

    /// Construct from the canonical string representation — shape
    /// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. Panics if `s` is not
    /// a valid UUID; intended for compile-time constants. For
    /// fallible parsing use [`RpcUuid::parse`].
    pub fn from_str_unchecked(s: &str) -> Self {
        Self::parse(s).expect("invalid UUID literal")
    }

    /// Fallibly parse the canonical 36-character UUID form.
    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 36 {
            return None;
        }
        if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
            return None;
        }
        let data1 = parse_hex_u32(&b[0..8])?;
        let data2 = parse_hex_u16(&b[9..13])?;
        let data3 = parse_hex_u16(&b[14..18])?;
        let mut data4 = [0u8; 8];
        for (i, chunk) in [&b[19..21], &b[21..23]].iter().enumerate() {
            data4[i] = parse_hex_u8(chunk)?;
        }
        for i in 0..6 {
            let start = 24 + i * 2;
            data4[2 + i] = parse_hex_u8(&b[start..start + 2])?;
        }
        Some(Self {
            data1,
            data2,
            data3,
            data4,
        })
    }

    /// Encode the UUID as 16 bytes in DCE mixed-endian order.
    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.data1, "uuid.data1")?;
        dst.write_u16_le(self.data2, "uuid.data2")?;
        dst.write_u16_le(self.data3, "uuid.data3")?;
        dst.write_slice(&self.data4, "uuid.data4")?;
        Ok(())
    }

    /// Decode 16 bytes in DCE mixed-endian order.
    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let data1 = src.read_u32_le("uuid.data1")?;
        let data2 = src.read_u16_le("uuid.data2")?;
        let data3 = src.read_u16_le("uuid.data3")?;
        let data4_slice = src.read_slice(8, "uuid.data4")?;
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(data4_slice);
        Ok(Self {
            data1,
            data2,
            data3,
            data4,
        })
    }
}

fn parse_hex_u32(s: &[u8]) -> Option<u32> {
    let mut out = 0u32;
    for &c in s {
        out = out.checked_shl(4)?;
        out |= hex_nibble(c)? as u32;
    }
    Some(out)
}

fn parse_hex_u16(s: &[u8]) -> Option<u16> {
    let mut out = 0u16;
    for &c in s {
        out = out.checked_shl(4)?;
        out |= hex_nibble(c)? as u16;
    }
    Some(out)
}

fn parse_hex_u8(s: &[u8]) -> Option<u8> {
    if s.len() != 2 {
        return None;
    }
    Some((hex_nibble(s[0])? << 4) | hex_nibble(s[1])?)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // NDR 2.0 transfer syntax UUID — canonical reference value from
    // C706 Appendix I. Serves as a known-good vector for mixed-endian
    // encoding.
    const NDR20: &str = "8a885d04-1ceb-11c9-9fe8-08002b104860";

    #[test]
    fn parse_ndr20() {
        let u = RpcUuid::parse(NDR20).unwrap();
        assert_eq!(u.data1, 0x8a88_5d04);
        assert_eq!(u.data2, 0x1ceb);
        assert_eq!(u.data3, 0x11c9);
        assert_eq!(u.data4, [0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60]);
    }

    #[test]
    fn encode_ndr20_mixed_endian() {
        let u = RpcUuid::parse(NDR20).unwrap();
        let mut buf = [0u8; 16];
        let mut w = WriteCursor::new(&mut buf);
        u.encode(&mut w).unwrap();
        assert_eq!(
            buf,
            [
                0x04, 0x5D, 0x88, 0x8A, // Data1 LE
                0xEB, 0x1C, //             Data2 LE
                0xC9, 0x11, //             Data3 LE
                0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60, // Data4 BE
            ]
        );
    }

    #[test]
    fn decode_ndr20_roundtrip() {
        let u = RpcUuid::parse(NDR20).unwrap();
        let mut buf = [0u8; 16];
        let mut w = WriteCursor::new(&mut buf);
        u.encode(&mut w).unwrap();

        let mut r = ReadCursor::new(&buf);
        let got = RpcUuid::decode(&mut r).unwrap();
        assert_eq!(got, u);
    }

    #[test]
    fn nil_uuid_encodes_zero() {
        let mut buf = [0u8; 16];
        let mut w = WriteCursor::new(&mut buf);
        RpcUuid::NIL.encode(&mut w).unwrap();
        assert_eq!(buf, [0; 16]);
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(RpcUuid::parse("short").is_none());
        assert!(
            RpcUuid::parse("8a885d04-1ceb-11c9-9fe8-08002b10486").is_none(),
            "35 chars"
        );
    }

    #[test]
    fn parse_rejects_bad_hyphens() {
        // Hyphen at wrong position.
        assert!(RpcUuid::parse("8a885d041-1ceb-11c9-9fe-08002b104860").is_none());
    }

    #[test]
    fn parse_rejects_non_hex() {
        assert!(RpcUuid::parse("8a885d04-1ceb-11c9-9fe8-08002b10486g").is_none());
    }

    #[test]
    fn parse_accepts_uppercase() {
        let lo = RpcUuid::parse("8a885d04-1ceb-11c9-9fe8-08002b104860").unwrap();
        let up = RpcUuid::parse("8A885D04-1CEB-11C9-9FE8-08002B104860").unwrap();
        assert_eq!(lo, up);
    }

    #[test]
    fn from_str_unchecked_matches_parse() {
        let u = RpcUuid::from_str_unchecked(NDR20);
        assert_eq!(u, RpcUuid::parse(NDR20).unwrap());
    }
}
