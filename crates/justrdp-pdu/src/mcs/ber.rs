#![forbid(unsafe_code)]

//! BER (Basic Encoding Rules) subset for MCS Connect Initial/Response.
//!
//! RDP uses BER for the MCS Connect Initial and Connect Response PDUs.
//! Only the subset needed by T.125 is implemented here (not full ASN.1 BER).
//!
//! BER TLV format:
//! ```text
//! ┌─────┬────────┬───────┐
//! │ Tag │ Length │ Value │
//! └─────┴────────┴───────┘
//! ```

use justrdp_core::{DecodeError, DecodeResult, EncodeResult, ReadCursor, WriteCursor};

// ── Tag constants ──

/// BOOLEAN tag.
pub const TAG_BOOLEAN: u8 = 0x01;
/// INTEGER tag.
pub const TAG_INTEGER: u8 = 0x02;
/// OCTET STRING tag.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// OBJECT IDENTIFIER tag.
pub const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
/// ENUMERATED tag.
pub const TAG_ENUMERATED: u8 = 0x0A;
/// SEQUENCE (constructed) tag.
pub const TAG_SEQUENCE: u8 = 0x30;

/// Application tag mask (bit 6 = constructed, bits 7-8 = application class).
pub const TAG_APPLICATION_CONSTRUCTED: u8 = 0x60;

// ── Length encoding ──

/// Compute BER length field size for a given content length.
pub fn ber_length_size(length: usize) -> usize {
    if length < 0x80 {
        1 // short form
    } else if length <= 0xFF {
        2 // long form, 1 byte
    } else {
        3 // long form, 2 bytes
    }
}

/// Write a BER length field.
pub fn write_length(dst: &mut WriteCursor<'_>, length: usize, ctx: &'static str) -> EncodeResult<()> {
    if length < 0x80 {
        dst.write_u8(length as u8, ctx)?;
    } else if length <= 0xFF {
        dst.write_u8(0x81, ctx)?;
        dst.write_u8(length as u8, ctx)?;
    } else if length <= u16::MAX as usize {
        dst.write_u8(0x82, ctx)?;
        dst.write_u16_be(length as u16, ctx)?;
    } else {
        return Err(justrdp_core::EncodeError::other(ctx, "BER length exceeds u16::MAX"));
    }
    Ok(())
}

/// Read a BER length field.
pub fn read_length(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<usize> {
    let first = src.read_u8(ctx)?;
    if first < 0x80 {
        Ok(first as usize)
    } else {
        let num_bytes = (first & 0x7F) as usize;
        match num_bytes {
            1 => Ok(src.read_u8(ctx)? as usize),
            2 => Ok(src.read_u16_be(ctx)? as usize),
            _ => Err(DecodeError::unsupported(ctx, "BER length > 2 bytes")),
        }
    }
}

// ── Tag read/write ──

/// Write a BER tag byte.
pub fn write_tag(dst: &mut WriteCursor<'_>, tag: u8, ctx: &'static str) -> EncodeResult<()> {
    dst.write_u8(tag, ctx)
}

/// Read and validate a BER tag byte.
pub fn read_tag(src: &mut ReadCursor<'_>, expected: u8, ctx: &'static str) -> DecodeResult<()> {
    let tag = src.read_u8(ctx)?;
    if tag != expected {
        return Err(DecodeError::unexpected_value(ctx, "tag", "unexpected BER tag"));
    }
    Ok(())
}

/// Read a BER tag byte without validation.
pub fn read_tag_raw(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<u8> {
    src.read_u8(ctx)
}

// ── Integer ──

/// Compute the minimum number of bytes needed to encode a signed integer.
fn int_byte_count(value: i64) -> usize {
    if value >= -128 && value <= 127 {
        1
    } else if value >= -32768 && value <= 32767 {
        2
    } else if value >= -8_388_608 && value <= 8_388_607 {
        3
    } else {
        4
    }
}

/// Size of a BER-encoded INTEGER (tag + length + value).
pub fn sizeof_integer(value: i64) -> usize {
    let byte_count = int_byte_count(value);
    1 + ber_length_size(byte_count) + byte_count
}

/// Write a BER INTEGER.
pub fn write_integer(dst: &mut WriteCursor<'_>, value: i64, ctx: &'static str) -> EncodeResult<()> {
    let byte_count = int_byte_count(value);
    write_tag(dst, TAG_INTEGER, ctx)?;
    write_length(dst, byte_count, ctx)?;

    // Write value bytes in big-endian order
    let bytes = value.to_be_bytes(); // 8 bytes
    let start = 8 - byte_count;
    dst.write_slice(&bytes[start..], ctx)?;
    Ok(())
}

/// Read a BER INTEGER as i64.
pub fn read_integer(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<i64> {
    read_tag(src, TAG_INTEGER, ctx)?;
    let length = read_length(src, ctx)?;

    if length == 0 || length > 8 {
        return Err(DecodeError::invalid_value(ctx, "integer length"));
    }

    let data = src.read_slice(length, ctx)?;

    // Sign-extend
    let negative = data[0] & 0x80 != 0;
    let mut result: i64 = if negative { -1 } else { 0 };
    for &byte in data {
        result = (result << 8) | (byte as i64);
    }

    Ok(result)
}

/// Read a BER INTEGER as u32 (convenience for positive values).
pub fn read_integer_u32(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<u32> {
    let value = read_integer(src, ctx)?;
    if value < 0 || value > u32::MAX as i64 {
        return Err(DecodeError::invalid_value(ctx, "integer out of u32 range"));
    }
    Ok(value as u32)
}

/// Read a BER INTEGER as u16.
pub fn read_integer_u16(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<u16> {
    let value = read_integer(src, ctx)?;
    if value < 0 || value > u16::MAX as i64 {
        return Err(DecodeError::invalid_value(ctx, "integer out of u16 range"));
    }
    Ok(value as u16)
}

// ── Enumerated ──

/// Size of a BER-encoded ENUMERATED.
pub fn sizeof_enumerated() -> usize {
    // Always 1-byte value: tag(1) + length(1) + value(1) = 3
    3
}

/// Write a BER ENUMERATED (single byte value).
pub fn write_enumerated(dst: &mut WriteCursor<'_>, value: u8, ctx: &'static str) -> EncodeResult<()> {
    write_tag(dst, TAG_ENUMERATED, ctx)?;
    write_length(dst, 1, ctx)?;
    dst.write_u8(value, ctx)?;
    Ok(())
}

/// Read a BER ENUMERATED.
pub fn read_enumerated(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<u8> {
    read_tag(src, TAG_ENUMERATED, ctx)?;
    let length = read_length(src, ctx)?;
    if length != 1 {
        return Err(DecodeError::invalid_value(ctx, "enumerated length"));
    }
    src.read_u8(ctx)
}

// ── Boolean ──

/// Size of a BER-encoded BOOLEAN: tag(1) + length(1) + value(1) = 3.
pub fn sizeof_boolean() -> usize {
    3
}

/// Write a BER BOOLEAN.
pub fn write_boolean(dst: &mut WriteCursor<'_>, value: bool, ctx: &'static str) -> EncodeResult<()> {
    write_tag(dst, TAG_BOOLEAN, ctx)?;
    write_length(dst, 1, ctx)?;
    dst.write_u8(if value { 0xFF } else { 0x00 }, ctx)?;
    Ok(())
}

/// Read a BER BOOLEAN.
pub fn read_boolean(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<bool> {
    read_tag(src, TAG_BOOLEAN, ctx)?;
    let length = read_length(src, ctx)?;
    if length != 1 {
        return Err(DecodeError::invalid_value(ctx, "boolean length"));
    }
    let val = src.read_u8(ctx)?;
    Ok(val != 0)
}

// ── Octet String ──

/// Size of a BER-encoded OCTET STRING.
pub fn sizeof_octet_string(data_len: usize) -> usize {
    1 + ber_length_size(data_len) + data_len
}

/// Write a BER OCTET STRING.
pub fn write_octet_string(dst: &mut WriteCursor<'_>, data: &[u8], ctx: &'static str) -> EncodeResult<()> {
    write_tag(dst, TAG_OCTET_STRING, ctx)?;
    write_length(dst, data.len(), ctx)?;
    dst.write_slice(data, ctx)?;
    Ok(())
}

/// Read a BER OCTET STRING, returning the raw bytes.
pub fn read_octet_string<'a>(src: &mut ReadCursor<'a>, ctx: &'static str) -> DecodeResult<&'a [u8]> {
    read_tag(src, TAG_OCTET_STRING, ctx)?;
    let length = read_length(src, ctx)?;
    src.read_slice(length, ctx)
}

// ── Object Identifier ──

/// T.124 ITU-T OID: { itu-t(0) recommendation(0) t(20) 124 version(0) 1 }.
/// Used as the key in GCC Conference Create Request/Response.
pub const MCS_OID: &[u8] = &[0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01];

/// Size of a BER-encoded OBJECT IDENTIFIER.
pub fn sizeof_object_identifier(oid: &[u8]) -> usize {
    1 + ber_length_size(oid.len()) + oid.len()
}

/// Write a BER OBJECT IDENTIFIER.
pub fn write_object_identifier(dst: &mut WriteCursor<'_>, oid: &[u8], ctx: &'static str) -> EncodeResult<()> {
    write_tag(dst, TAG_OBJECT_IDENTIFIER, ctx)?;
    write_length(dst, oid.len(), ctx)?;
    dst.write_slice(oid, ctx)?;
    Ok(())
}

/// Read a BER OBJECT IDENTIFIER.
pub fn read_object_identifier<'a>(src: &mut ReadCursor<'a>, ctx: &'static str) -> DecodeResult<&'a [u8]> {
    read_tag(src, TAG_OBJECT_IDENTIFIER, ctx)?;
    let length = read_length(src, ctx)?;
    src.read_slice(length, ctx)
}

// ── Sequence / Constructed helpers ──

/// Size of a BER SEQUENCE wrapper (tag + length).
pub fn sizeof_sequence(content_len: usize) -> usize {
    1 + ber_length_size(content_len) + content_len
}

/// Write a BER SEQUENCE tag + length (caller writes content after).
pub fn write_sequence_tag(dst: &mut WriteCursor<'_>, content_len: usize, ctx: &'static str) -> EncodeResult<()> {
    write_tag(dst, TAG_SEQUENCE, ctx)?;
    write_length(dst, content_len, ctx)?;
    Ok(())
}

/// Read a BER SEQUENCE tag + length, returning the content length.
pub fn read_sequence_tag(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<usize> {
    read_tag(src, TAG_SEQUENCE, ctx)?;
    read_length(src, ctx)
}

/// Write an application-constructed tag + length.
///
/// Only supports tag numbers 0-30 (single-byte BER tag).
/// For tag numbers > 30, use `write_high_tag` instead.
pub fn write_application_tag(
    dst: &mut WriteCursor<'_>,
    tag_number: u8,
    content_len: usize,
    ctx: &'static str,
) -> EncodeResult<()> {
    if tag_number > 30 {
        return Err(justrdp_core::EncodeError::other(ctx, "tag > 30, use write_high_tag instead"));
    }
    let tag = TAG_APPLICATION_CONSTRUCTED | tag_number;
    write_tag(dst, tag, ctx)?;
    write_length(dst, content_len, ctx)?;
    Ok(())
}

/// Read an application-constructed tag + length.
pub fn read_application_tag(
    src: &mut ReadCursor<'_>,
    expected_number: u8,
    ctx: &'static str,
) -> DecodeResult<usize> {
    let expected_tag = TAG_APPLICATION_CONSTRUCTED | expected_number;
    read_tag(src, expected_tag, ctx)?;
    read_length(src, ctx)
}

/// Size of an application-constructed tag + length wrapper.
///
/// Only supports tag numbers 0-30 (single-byte BER tag).
pub fn sizeof_application_tag(content_len: usize) -> usize {
    1 + ber_length_size(content_len) + content_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_short_form() {
        let mut buf = [0u8; 1];
        let mut cursor = WriteCursor::new(&mut buf);
        write_length(&mut cursor, 0x7F, "test").unwrap();
        assert_eq!(buf[0], 0x7F);

        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(read_length(&mut cursor, "test").unwrap(), 0x7F);
    }

    #[test]
    fn length_long_form_1byte() {
        let mut buf = [0u8; 2];
        let mut cursor = WriteCursor::new(&mut buf);
        write_length(&mut cursor, 0x80, "test").unwrap();
        assert_eq!(&buf, &[0x81, 0x80]);

        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(read_length(&mut cursor, "test").unwrap(), 0x80);
    }

    #[test]
    fn length_long_form_2bytes() {
        let mut buf = [0u8; 3];
        let mut cursor = WriteCursor::new(&mut buf);
        write_length(&mut cursor, 0x0100, "test").unwrap();
        assert_eq!(&buf, &[0x82, 0x01, 0x00]);

        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(read_length(&mut cursor, "test").unwrap(), 0x0100);
    }

    #[test]
    fn integer_positive_roundtrip() {
        for &val in &[0i64, 1, 127, 128, 255, 256, 32767, 65535, 100_000] {
            let size = sizeof_integer(val);
            let mut buf = alloc::vec![0u8; size];
            let mut cursor = WriteCursor::new(&mut buf);
            write_integer(&mut cursor, val, "test").unwrap();

            let mut cursor = ReadCursor::new(&buf);
            let decoded = read_integer(&mut cursor, "test").unwrap();
            assert_eq!(decoded, val, "failed for value {}", val);
        }
    }

    #[test]
    fn integer_negative_roundtrip() {
        for &val in &[-1i64, -128, -129, -32768] {
            let size = sizeof_integer(val);
            let mut buf = alloc::vec![0u8; size];
            let mut cursor = WriteCursor::new(&mut buf);
            write_integer(&mut cursor, val, "test").unwrap();

            let mut cursor = ReadCursor::new(&buf);
            let decoded = read_integer(&mut cursor, "test").unwrap();
            assert_eq!(decoded, val, "failed for value {}", val);
        }
    }

    #[test]
    fn boolean_roundtrip() {
        for &val in &[true, false] {
            let mut buf = [0u8; 3];
            let mut cursor = WriteCursor::new(&mut buf);
            write_boolean(&mut cursor, val, "test").unwrap();

            let mut cursor = ReadCursor::new(&buf);
            assert_eq!(read_boolean(&mut cursor, "test").unwrap(), val);
        }
    }

    #[test]
    fn enumerated_roundtrip() {
        let mut buf = [0u8; 3];
        let mut cursor = WriteCursor::new(&mut buf);
        write_enumerated(&mut cursor, 42, "test").unwrap();

        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(read_enumerated(&mut cursor, "test").unwrap(), 42);
    }

    #[test]
    fn octet_string_roundtrip() {
        let data = b"hello RDP";
        let size = sizeof_octet_string(data.len());
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        write_octet_string(&mut cursor, data, "test").unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = read_octet_string(&mut cursor, "test").unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn object_identifier_roundtrip() {
        let size = sizeof_object_identifier(MCS_OID);
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        write_object_identifier(&mut cursor, MCS_OID, "test").unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = read_object_identifier(&mut cursor, "test").unwrap();
        assert_eq!(decoded, MCS_OID);
    }

    #[test]
    fn sequence_tag_roundtrip() {
        let content_len = 100;
        let mut buf = [0u8; 3]; // tag + 2-byte length
        let mut cursor = WriteCursor::new(&mut buf);
        write_sequence_tag(&mut cursor, content_len, "test").unwrap();

        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(read_sequence_tag(&mut cursor, "test").unwrap(), content_len);
    }

    #[test]
    fn application_tag_roundtrip() {
        let mut buf = [0u8; 4];
        let mut cursor = WriteCursor::new(&mut buf);
        write_application_tag(&mut cursor, 1, 256, "test").unwrap();
        assert_eq!(buf[0], 0x61); // 0x60 | 1

        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(read_application_tag(&mut cursor, 1, "test").unwrap(), 256);
    }

    #[test]
    fn wrong_tag_error() {
        let buf = [TAG_BOOLEAN, 0x01, 0xFF];
        let mut cursor = ReadCursor::new(&buf);
        // Try to read as INTEGER (wrong tag)
        assert!(read_integer(&mut cursor, "test").is_err());
    }

    #[test]
    fn read_length_unsupported_3byte() {
        // 0x83 = 3 bytes follow (unsupported)
        let buf = [0x83, 0x00, 0x01, 0x00];
        let mut cursor = ReadCursor::new(&buf);
        assert!(read_length(&mut cursor, "test").is_err());
    }

    #[test]
    fn read_integer_zero_length() {
        let buf = [TAG_INTEGER, 0x00]; // INTEGER with length=0
        let mut cursor = ReadCursor::new(&buf);
        assert!(read_integer(&mut cursor, "test").is_err());
    }

    #[test]
    fn read_integer_overlength() {
        let buf = [TAG_INTEGER, 0x09, 0,0,0,0,0,0,0,0,0]; // length=9 > 8
        let mut cursor = ReadCursor::new(&buf);
        assert!(read_integer(&mut cursor, "test").is_err());
    }

    #[test]
    fn ber_length_zero() {
        let mut buf = [0u8; 1];
        let mut cursor = WriteCursor::new(&mut buf);
        write_length(&mut cursor, 0, "test").unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(read_length(&mut cursor, "test").unwrap(), 0);
    }
}
