#![forbid(unsafe_code)]

//! PER (Packed Encoding Rules) subset for MCS Domain PDUs.
//!
//! RDP uses aligned PER for most MCS PDUs after Connect Initial/Response.
//! Only the subset needed by T.125 domain PDUs is implemented here.
//!
//! Key concepts:
//! - Values are packed tightly (no tag bytes like BER)
//! - Lengths use "length determinant" encoding
//! - Integers are constrained (known range → fewer bits)

use justrdp_core::{DecodeError, DecodeResult, EncodeResult, ReadCursor, WriteCursor};

// ── Length Determinant ──

/// Compute PER length determinant size.
pub fn per_length_size(length: usize) -> usize {
    if length < 0x80 {
        1
    } else {
        2
    }
}

/// Write a PER length determinant.
pub fn write_length(dst: &mut WriteCursor<'_>, length: usize, ctx: &'static str) -> EncodeResult<()> {
    if length < 0x80 {
        dst.write_u8(length as u8, ctx)?;
    } else if length < 0x4000 {
        dst.write_u16_be((length as u16) | 0x8000, ctx)?;
    } else {
        return Err(justrdp_core::EncodeError::other(ctx, "PER length too large"));
    }
    Ok(())
}

/// Read a PER length determinant.
pub fn read_length(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<usize> {
    let first = src.read_u8(ctx)?;
    if first < 0x80 {
        Ok(first as usize)
    } else {
        let second = src.read_u8(ctx)?;
        let length = (((first & 0x7F) as usize) << 8) | (second as usize);
        Ok(length)
    }
}

// ── Choice index ──

/// Write a PER CHOICE index (1 byte for < 256 alternatives).
pub fn write_choice(dst: &mut WriteCursor<'_>, index: u8, ctx: &'static str) -> EncodeResult<()> {
    dst.write_u8(index, ctx)
}

/// Read a PER CHOICE index.
pub fn read_choice(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<u8> {
    src.read_u8(ctx)
}

// ── Integer (constrained whole number) ──

/// Size of a PER constrained INTEGER (u16) on wire.
pub fn sizeof_integer_u16(value: u16) -> usize {
    if value < 0x4000 { 2 } else { 4 }
}

/// Write a PER constrained INTEGER (u16).
///
/// For values < 0x4000 (14 bits): write 2 bytes BE (high 2 bits clear = short form).
/// For values >= 0x4000: write 0x40 marker + length(1) + value(2).
/// The 0x40 prefix (bit 14 set, bit 15 clear) signals long form per PER conventions.
pub fn write_integer_u16(dst: &mut WriteCursor<'_>, value: u16, ctx: &'static str) -> EncodeResult<()> {
    if value < 0x4000 {
        // Short form: 2 bytes BE, high 2 bits are 0
        dst.write_u16_be(value, ctx)?;
    } else {
        // Long form: 0x40 marker + 0x02 (length=2) + value(2 bytes BE)
        dst.write_u8(0x40, ctx)?; // bit 14 set = long form
        dst.write_u8(0x02, ctx)?; // length = 2 bytes
        dst.write_u16_be(value, ctx)?;
    }
    Ok(())
}

/// Read a PER constrained INTEGER (u16).
///
/// Short form: first byte has bit 7+6 both clear → read 2 bytes BE as u16.
/// Long form: first byte has bit 6 set (0x40) → read length(1) + value(2).
pub fn read_integer_u16(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<u16> {
    let first = src.read_u8(ctx)?;
    if first & 0xC0 == 0 {
        // Short form: combine first byte with second byte
        let second = src.read_u8(ctx)?;
        Ok(u16::from_be_bytes([first, second]))
    } else {
        // Long form: first byte is marker (0x40), next is length, then value
        let len = src.read_u8(ctx)?;
        if len != 0x02 {
            return Err(DecodeError::invalid_value(ctx, "PER integer unexpected length"));
        }
        let value = src.read_u16_be(ctx)?;
        Ok(value)
    }
}

// ── Enumerated ──

/// Write a PER ENUMERATED value (1 byte for < 256 values).
pub fn write_enumerated(dst: &mut WriteCursor<'_>, value: u8, ctx: &'static str) -> EncodeResult<()> {
    dst.write_u8(value, ctx)
}

/// Read a PER ENUMERATED value.
pub fn read_enumerated(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<u8> {
    src.read_u8(ctx)
}

// ── Number of set bits (for selection/optional) ──

/// Write PER selection bits (padding + optional bit field).
///
/// Used for SEQUENCE optional field presence. In MCS, this is typically
/// a byte with padding bits followed by optional-presence bits.
pub fn write_selection(dst: &mut WriteCursor<'_>, value: u8, ctx: &'static str) -> EncodeResult<()> {
    dst.write_u8(value, ctx)
}

/// Read PER selection bits.
pub fn read_selection(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<u8> {
    src.read_u8(ctx)
}

// ── Octet String (variable length) ──

/// Size of a PER OCTET STRING (length determinant + data).
pub fn sizeof_octet_string(data_len: usize) -> usize {
    per_length_size(data_len) + data_len
}

/// Write a PER OCTET STRING.
pub fn write_octet_string(dst: &mut WriteCursor<'_>, data: &[u8], ctx: &'static str) -> EncodeResult<()> {
    write_length(dst, data.len(), ctx)?;
    dst.write_slice(data, ctx)?;
    Ok(())
}

/// Read a PER OCTET STRING.
pub fn read_octet_string<'a>(src: &mut ReadCursor<'a>, ctx: &'static str) -> DecodeResult<&'a [u8]> {
    let length = read_length(src, ctx)?;
    src.read_slice(length, ctx)
}

// ── Padding ──

/// Write PER padding (for byte alignment).
pub fn write_padding(dst: &mut WriteCursor<'_>, count: usize, ctx: &'static str) -> EncodeResult<()> {
    dst.write_zeros(count, ctx)
}

/// Read and skip PER padding.
pub fn read_padding(src: &mut ReadCursor<'_>, count: usize, ctx: &'static str) -> DecodeResult<()> {
    src.skip(count, ctx)
}

// ── Numeric String (simplified for domain params) ──

/// Write a PER numeric string of known length.
/// RDP uses this for simple fixed strings like "1" in ConferenceCreateRequest.
pub fn write_numeric_string(dst: &mut WriteCursor<'_>, value: &[u8], ctx: &'static str) -> EncodeResult<()> {
    // Length (1 byte for the number of characters minus 1)
    write_length(dst, value.len(), ctx)?;
    // Packed: 4 bits per digit, so 2 digits per byte
    let mut i = 0;
    while i < value.len() {
        let high = (value[i] - b'0') & 0x0F;
        let low = if i + 1 < value.len() {
            (value[i + 1] - b'0') & 0x0F
        } else {
            0
        };
        dst.write_u8((high << 4) | low, ctx)?;
        i += 2;
    }
    Ok(())
}

/// Compute size of a PER numeric string.
pub fn sizeof_numeric_string(len: usize) -> usize {
    per_length_size(len) + (len + 1) / 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_short_roundtrip() {
        let mut buf = [0u8; 1];
        let mut cursor = WriteCursor::new(&mut buf);
        write_length(&mut cursor, 0x7F, "test").unwrap();

        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(read_length(&mut cursor, "test").unwrap(), 0x7F);
    }

    #[test]
    fn length_long_roundtrip() {
        let mut buf = [0u8; 2];
        let mut cursor = WriteCursor::new(&mut buf);
        write_length(&mut cursor, 0x100, "test").unwrap();

        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(read_length(&mut cursor, "test").unwrap(), 0x100);
    }

    #[test]
    fn choice_roundtrip() {
        let mut buf = [0u8; 1];
        let mut cursor = WriteCursor::new(&mut buf);
        write_choice(&mut cursor, 14, "test").unwrap();

        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(read_choice(&mut cursor, "test").unwrap(), 14);
    }

    #[test]
    fn integer_u16_short_form_roundtrip() {
        for &val in &[0u16, 1, 100, 0x3FFF] {
            let mut buf = [0u8; 2];
            let mut cursor = WriteCursor::new(&mut buf);
            write_integer_u16(&mut cursor, val, "test").unwrap();

            let mut cursor = ReadCursor::new(&buf);
            assert_eq!(read_integer_u16(&mut cursor, "test").unwrap(), val);
        }
    }

    #[test]
    fn integer_u16_long_form_roundtrip() {
        for &val in &[0x4000u16, 0x4001, 0x8000, 0xFFFF] {
            let mut buf = [0u8; 4];
            let mut cursor = WriteCursor::new(&mut buf);
            write_integer_u16(&mut cursor, val, "test").unwrap();

            let mut cursor = ReadCursor::new(&buf);
            assert_eq!(read_integer_u16(&mut cursor, "test").unwrap(), val,
                "long form roundtrip failed for {val:#06x}");
        }
    }

    #[test]
    fn enumerated_roundtrip() {
        let mut buf = [0u8; 1];
        let mut cursor = WriteCursor::new(&mut buf);
        write_enumerated(&mut cursor, 3, "test").unwrap();

        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(read_enumerated(&mut cursor, "test").unwrap(), 3);
    }

    #[test]
    fn octet_string_roundtrip() {
        let data = b"MCS test data";
        let size = sizeof_octet_string(data.len());
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        write_octet_string(&mut cursor, data, "test").unwrap();

        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(read_octet_string(&mut cursor, "test").unwrap(), data);
    }

    #[test]
    fn per_integer_u16_known_answer_wire_bytes() {
        // Short form max: 0x3FFF → [0x3F, 0xFF]
        let mut buf = [0u8; 2];
        write_integer_u16(&mut WriteCursor::new(&mut buf), 0x3FFF, "t").unwrap();
        assert_eq!(&buf, &[0x3F, 0xFF]);

        // Long form min: 0x4000 → [0x40, 0x02, 0x40, 0x00]
        let mut buf = [0u8; 4];
        write_integer_u16(&mut WriteCursor::new(&mut buf), 0x4000, "t").unwrap();
        assert_eq!(&buf, &[0x40, 0x02, 0x40, 0x00]);

        // Long form max: 0xFFFF → [0x40, 0x02, 0xFF, 0xFF]
        let mut buf = [0u8; 4];
        write_integer_u16(&mut WriteCursor::new(&mut buf), 0xFFFF, "t").unwrap();
        assert_eq!(&buf, &[0x40, 0x02, 0xFF, 0xFF]);
    }

    #[test]
    fn sizeof_integer_u16_correct() {
        assert_eq!(sizeof_integer_u16(0), 2);
        assert_eq!(sizeof_integer_u16(0x3FFF), 2);
        assert_eq!(sizeof_integer_u16(0x4000), 4);
        assert_eq!(sizeof_integer_u16(0xFFFF), 4);
    }
}
