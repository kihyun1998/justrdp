//! ALIGNED PER (Packed Encoding Rules, X.691) primitives — the encoding T.125 MCS domain PDUs
//! and the T.124 GCC Conference Create wrappers use (plan.md §3 Layer 1). Only the shapes RDP
//! needs are implemented: the 1/2-byte length determinant, constrained u16 (offset from a base),
//! the length-prefixed unconstrained u32, single-byte CHOICE/ENUMERATED, OBJECT IDENTIFIER,
//! OCTET STRING with a minimum, and the packed NumericString.
//!
//! Wire-format reference: ironrdp-pdu `per.rs` (the differential oracle) — byte-compatible by
//! construction so the differential tests can compare against it.

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// Read a PER length determinant: one byte below 0x80, else two bytes with the top bit set
/// (`0x80 | hi, lo` — 14-bit max).
pub fn read_length(cur: &mut ReadCursor<'_>) -> Result<u16, DecodeError> {
    let a = cur.read_u8()?;
    if a & 0x80 != 0 {
        let b = cur.read_u8()?;
        Ok((u16::from(a & !0x80) << 8) + u16::from(b))
    } else {
        Ok(u16::from(a))
    }
}

/// Write a PER length determinant (see [`read_length`]).
pub fn write_length(out: &mut Vec<u8>, length: u16) {
    if length > 0x7F {
        out.extend_from_slice(&(length | 0x8000).to_be_bytes());
    } else {
        out.push(length as u8);
    }
}

/// Size in bytes of the length determinant for `length`.
pub fn sizeof_length(length: usize) -> usize {
    if length > 0x7F { 2 } else { 1 }
}

/// Read a CHOICE index byte (the MCS DomainMCSPDU tag byte, etc.).
pub fn read_choice(cur: &mut ReadCursor<'_>) -> Result<u8, DecodeError> {
    cur.read_u8()
}

/// Write a CHOICE index byte.
pub fn write_choice(out: &mut Vec<u8>, choice: u8) {
    out.push(choice);
}

/// Read an ENUMERATED value, rejecting values at or above `count`.
pub fn read_enum(cur: &mut ReadCursor<'_>, count: u8) -> Result<u8, DecodeError> {
    let v = cur.read_u8()?;
    if v >= count {
        return Err(DecodeError::InvalidField {
            field: "per.enumerated",
            reason: "enumerated value outside the expected range",
        });
    }
    Ok(v)
}

/// Write an ENUMERATED value.
pub fn write_enum(out: &mut Vec<u8>, enumerated: u8) {
    out.push(enumerated);
}

/// Read a constrained integer encoded as a big-endian u16 offset from `base` (e.g. a T.125
/// UserId, base 1001).
pub fn read_u16(cur: &mut ReadCursor<'_>, base: u16) -> Result<u16, DecodeError> {
    let v = cur.read_u16_be()?;
    base.checked_add(v).ok_or(DecodeError::InvalidField {
        field: "per.u16",
        reason: "constrained integer overflows its base",
    })
}

/// Write a constrained integer as a big-endian u16 offset from `base`.
pub fn write_u16(out: &mut Vec<u8>, value: u16, base: u16) -> Result<(), DecodeError> {
    let offset = value.checked_sub(base).ok_or(DecodeError::InvalidField {
        field: "per.u16",
        reason: "constrained integer below its base",
    })?;
    out.extend_from_slice(&offset.to_be_bytes());
    Ok(())
}

/// Read an unconstrained INTEGER (0..MAX): a length determinant followed by 0/1/2/4 big-endian
/// bytes.
pub fn read_u32(cur: &mut ReadCursor<'_>) -> Result<u32, DecodeError> {
    let length = read_length(cur)?;
    match length {
        0 => Ok(0),
        1 => Ok(u32::from(cur.read_u8()?)),
        2 => Ok(u32::from(cur.read_u16_be()?)),
        4 => cur.read_u32_be(),
        _ => Err(DecodeError::InvalidField {
            field: "per.u32",
            reason: "INTEGER length is not 0, 1, 2, or 4",
        }),
    }
}

/// Write an unconstrained INTEGER (0..MAX) in its minimal 1/2/4-byte form.
pub fn write_u32(out: &mut Vec<u8>, value: u32) {
    if value <= 0xFF {
        write_length(out, 1);
        out.push(value as u8);
    } else if value <= 0xFFFF {
        write_length(out, 2);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else {
        write_length(out, 4);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// Read an OBJECT IDENTIFIER, returning the six arcs (the first packed byte expands into two).
pub fn read_object_id(cur: &mut ReadCursor<'_>) -> Result<[u8; 6], DecodeError> {
    let length = read_length(cur)?;
    if length != 5 {
        return Err(DecodeError::InvalidField {
            field: "per.object_id",
            reason: "OBJECT IDENTIFIER length is not 5",
        });
    }
    let packed = cur.read_u8()?;
    let mut arcs = [0u8; 6];
    arcs[0] = packed / 40;
    arcs[1] = packed % 40;
    for arc in arcs.iter_mut().skip(2) {
        *arc = cur.read_u8()?;
    }
    Ok(arcs)
}

/// Write an OBJECT IDENTIFIER from six arcs (the first two pack into one byte).
pub fn write_object_id(out: &mut Vec<u8>, arcs: [u8; 6]) {
    write_length(out, 5);
    out.push(arcs[0] * 40 + arcs[1]);
    out.extend_from_slice(&arcs[2..]);
}

/// Read an OCTET STRING whose length determinant is offset by `min` (SIZE constraint lower
/// bound). Returns the `min + determinant` bytes.
pub fn read_octet_string<'a>(
    cur: &mut ReadCursor<'a>,
    min: usize,
) -> Result<&'a [u8], DecodeError> {
    let length = read_length(cur)?;
    cur.read_slice(min + usize::from(length))
}

/// Write an OCTET STRING with a SIZE lower bound of `min` (the determinant encodes
/// `len - min`).
pub fn write_octet_string(
    out: &mut Vec<u8>,
    octets: &[u8],
    min: usize,
) -> Result<(), DecodeError> {
    let excess = octets.len().checked_sub(min).ok_or(DecodeError::InvalidField {
        field: "per.octet_string",
        reason: "octet string shorter than its SIZE lower bound",
    })?;
    let excess = u16::try_from(excess).map_err(|_| DecodeError::InvalidField {
        field: "per.octet_string",
        reason: "octet string too long for a PER length determinant",
    })?;
    write_length(out, excess);
    out.extend_from_slice(octets);
    Ok(())
}

/// Skip a NumericString with SIZE lower bound `min` (two digits pack per byte). The T.124
/// conference name is the only NumericString RDP carries and its value is ignored.
pub fn read_numeric_string(cur: &mut ReadCursor<'_>, min: u16) -> Result<(), DecodeError> {
    let length = read_length(cur)?;
    let packed = usize::from((length + min).div_ceil(2));
    cur.read_slice(packed)?;
    Ok(())
}

/// Write a NumericString with SIZE lower bound `min`: digits packed two per byte, each digit
/// stored as `(ascii - '0') % 10` in a nibble.
pub fn write_numeric_string(
    out: &mut Vec<u8>,
    digits: &[u8],
    min: usize,
) -> Result<(), DecodeError> {
    let excess = digits.len().checked_sub(min).ok_or(DecodeError::InvalidField {
        field: "per.numeric_string",
        reason: "numeric string shorter than its SIZE lower bound",
    })?;
    write_length(out, excess as u16);
    for pair in digits.chunks(2) {
        let hi = (pair[0].wrapping_sub(0x30)) % 10;
        let lo = (pair.get(1).copied().unwrap_or(0x30).wrapping_sub(0x30)) % 10;
        out.push((hi << 4) | lo);
    }
    Ok(())
}

/// Write `n` zero padding bytes.
pub fn write_padding(out: &mut Vec<u8>, n: usize) {
    out.extend(std::iter::repeat_n(0u8, n));
}

/// Skip `n` padding bytes.
pub fn read_padding(cur: &mut ReadCursor<'_>, n: usize) -> Result<(), DecodeError> {
    cur.read_slice(n)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_round_trips_in_short_and_long_form() {
        let mut out = Vec::new();
        write_length(&mut out, 0x7F);
        write_length(&mut out, 0x80);
        assert_eq!(out, vec![0x7F, 0x80, 0x80]);

        let mut cur = ReadCursor::new(&out, "t");
        assert_eq!(read_length(&mut cur).unwrap(), 0x7F);
        assert_eq!(read_length(&mut cur).unwrap(), 0x80);
    }

    #[test]
    fn u32_uses_minimal_length_prefixed_form() {
        let mut out = Vec::new();
        write_u32(&mut out, 0); // [0x01, 0x00]
        write_u32(&mut out, 0xABCD); // [0x02, 0xAB, 0xCD]
        write_u32(&mut out, 0x0001_0000); // [0x04, 0x00, 0x01, 0x00, 0x00]
        assert_eq!(
            out,
            vec![0x01, 0x00, 0x02, 0xAB, 0xCD, 0x04, 0x00, 0x01, 0x00, 0x00]
        );

        let mut cur = ReadCursor::new(&out, "t");
        assert_eq!(read_u32(&mut cur).unwrap(), 0);
        assert_eq!(read_u32(&mut cur).unwrap(), 0xABCD);
        assert_eq!(read_u32(&mut cur).unwrap(), 0x0001_0000);
    }

    #[test]
    fn constrained_u16_offsets_from_its_base() {
        let mut out = Vec::new();
        write_u16(&mut out, 1007, 1001).unwrap(); // T.125 UserId base
        assert_eq!(out, vec![0x00, 0x06]);
        let mut cur = ReadCursor::new(&out, "t");
        assert_eq!(read_u16(&mut cur, 1001).unwrap(), 1007);

        // Below the base is invalid.
        let mut bad = Vec::new();
        assert!(write_u16(&mut bad, 5, 1001).is_err());
    }

    #[test]
    fn object_id_packs_the_first_two_arcs() {
        // The T.124 key: { 0 0 20 124 0 1 }.
        let mut out = Vec::new();
        write_object_id(&mut out, [0, 0, 20, 124, 0, 1]);
        assert_eq!(out, vec![0x05, 0x00, 0x14, 0x7C, 0x00, 0x01]);
        let mut cur = ReadCursor::new(&out, "t");
        assert_eq!(read_object_id(&mut cur).unwrap(), [0, 0, 20, 124, 0, 1]);
    }

    #[test]
    fn numeric_string_packs_two_digits_per_byte() {
        // The T.124 conference name "1" with SIZE >= 1: determinant 0, then '1' and an implied
        // '0' packed into 0x10.
        let mut out = Vec::new();
        write_numeric_string(&mut out, b"1", 1).unwrap();
        assert_eq!(out, vec![0x00, 0x10]);
        let mut cur = ReadCursor::new(&out, "t");
        read_numeric_string(&mut cur, 1).unwrap();
        assert_eq!(cur.remaining(), 0);
    }

    #[test]
    fn octet_string_honours_its_size_lower_bound() {
        // "Duca" with min 4: determinant 0 then the 4 bytes verbatim.
        let mut out = Vec::new();
        write_octet_string(&mut out, b"Duca", 4).unwrap();
        assert_eq!(out, vec![0x00, b'D', b'u', b'c', b'a']);
        let mut cur = ReadCursor::new(&out, "t");
        assert_eq!(read_octet_string(&mut cur, 4).unwrap(), b"Duca");
    }
}
