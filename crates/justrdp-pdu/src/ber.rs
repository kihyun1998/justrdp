//! BER (Basic Encoding Rules, X.690) primitives — the encoding T.125 uses for the MCS
//! Connect-Initial / Connect-Response PDUs (plan.md §3 Layer 1). Only the shapes those two PDUs
//! need: APPLICATION and SEQUENCE constructed tags, INTEGER, BOOLEAN, ENUMERATED, and
//! OCTET STRING, with the definite short/long length forms.
//!
//! Wire-format reference: ironrdp-pdu `ber.rs` (the differential oracle) — byte-compatible by
//! construction, including its choice of length forms (1 byte ≤ 0x7F, `0x81` form ≤ 0xFF,
//! `0x82` form above).

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

const CLASS_APPLICATION: u8 = 0x40;
const CLASS_UNIVERSAL: u8 = 0x00;
const PC_CONSTRUCT: u8 = 0x20;
const PC_PRIMITIVE: u8 = 0x00;
const TAG_MASK: u8 = 0x1F;

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_ENUMERATED: u8 = 0x0A;
const TAG_SEQUENCE: u8 = 0x10;

/// Write a BER definite length (short form ≤ 0x7F, else `0x81`/`0x82` long forms).
pub fn write_length(out: &mut Vec<u8>, length: u16) {
    if length > 0xFF {
        out.push(0x82);
        out.extend_from_slice(&length.to_be_bytes());
    } else if length > 0x7F {
        out.push(0x81);
        out.push(length as u8);
    } else {
        out.push(length as u8);
    }
}

/// Read a BER definite length (short or 1/2-byte long form).
pub fn read_length(cur: &mut ReadCursor<'_>) -> Result<u16, DecodeError> {
    let byte = cur.read_u8()?;
    if byte & 0x80 != 0 {
        match byte & !0x80 {
            1 => Ok(u16::from(cur.read_u8()?)),
            2 => cur.read_u16_be(),
            _ => Err(DecodeError::InvalidField {
                field: "ber.length",
                reason: "length-of-length is not 1 or 2",
            }),
        }
    } else {
        Ok(u16::from(byte))
    }
}

/// Write a constructed APPLICATION tag (`[APPLICATION n]`) with the BER length of its contents.
/// Tag numbers above 0x1E use the two-byte high-tag-number form (Connect-Initial is 101).
pub fn write_application_tag(out: &mut Vec<u8>, tagnum: u8, length: u16) {
    if tagnum > 0x1E {
        out.push(CLASS_APPLICATION | PC_CONSTRUCT | TAG_MASK);
        out.push(tagnum);
    } else {
        out.push(CLASS_APPLICATION | PC_CONSTRUCT | (TAG_MASK & tagnum));
    }
    write_length(out, length);
}

/// Read a constructed APPLICATION tag, checking the tag number, returning the content length.
pub fn read_application_tag(cur: &mut ReadCursor<'_>, tagnum: u8) -> Result<u16, DecodeError> {
    let identifier = cur.read_u8()?;
    if tagnum > 0x1E {
        if identifier != CLASS_APPLICATION | PC_CONSTRUCT | TAG_MASK {
            return Err(DecodeError::InvalidField {
                field: "ber.application_tag",
                reason: "expected the high-tag-number APPLICATION identifier",
            });
        }
        if cur.read_u8()? != tagnum {
            return Err(DecodeError::InvalidField {
                field: "ber.application_tag",
                reason: "unexpected APPLICATION tag number",
            });
        }
    } else if identifier != CLASS_APPLICATION | PC_CONSTRUCT | (TAG_MASK & tagnum) {
        return Err(DecodeError::InvalidField {
            field: "ber.application_tag",
            reason: "unexpected APPLICATION identifier",
        });
    }
    read_length(cur)
}

/// Write a constructed SEQUENCE tag with the BER length of its contents.
pub fn write_sequence_tag(out: &mut Vec<u8>, length: u16) {
    out.push(CLASS_UNIVERSAL | PC_CONSTRUCT | TAG_SEQUENCE);
    write_length(out, length);
}

/// Read a constructed SEQUENCE tag, returning the content length.
pub fn read_sequence_tag(cur: &mut ReadCursor<'_>) -> Result<u16, DecodeError> {
    if cur.read_u8()? != CLASS_UNIVERSAL | PC_CONSTRUCT | TAG_SEQUENCE {
        return Err(DecodeError::InvalidField {
            field: "ber.sequence_tag",
            reason: "expected a constructed SEQUENCE identifier",
        });
    }
    read_length(cur)
}

/// Write an INTEGER in its minimal unsigned big-endian form (1–4 content bytes, matching the
/// oracle's thresholds: an extra leading byte appears when the high bit would be set).
pub fn write_integer(out: &mut Vec<u8>, value: u32) {
    out.push(CLASS_UNIVERSAL | PC_PRIMITIVE | TAG_INTEGER);
    if value < 0x80 {
        write_length(out, 1);
        out.push(value as u8);
    } else if value < 0x8000 {
        write_length(out, 2);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 0x0080_0000 {
        write_length(out, 3);
        out.push((value >> 16) as u8);
        out.extend_from_slice(&((value & 0xFFFF) as u16).to_be_bytes());
    } else {
        write_length(out, 4);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// Read an INTEGER of 1–4 content bytes as an unsigned value.
pub fn read_integer(cur: &mut ReadCursor<'_>) -> Result<u32, DecodeError> {
    if cur.read_u8()? != CLASS_UNIVERSAL | PC_PRIMITIVE | TAG_INTEGER {
        return Err(DecodeError::InvalidField {
            field: "ber.integer",
            reason: "expected an INTEGER identifier",
        });
    }
    let length = read_length(cur)?;
    match length {
        1 => Ok(u32::from(cur.read_u8()?)),
        2 => Ok(u32::from(cur.read_u16_be()?)),
        3 => {
            let hi = cur.read_u8()?;
            let lo = cur.read_u16_be()?;
            Ok((u32::from(hi) << 16) | u32::from(lo))
        }
        4 => cur.read_u32_be(),
        _ => Err(DecodeError::InvalidField {
            field: "ber.integer",
            reason: "INTEGER length is not 1–4 bytes",
        }),
    }
}

/// Write a BOOLEAN (`0xFF` true / `0x00` false, per the DER canonical values).
pub fn write_bool(out: &mut Vec<u8>, value: bool) {
    out.push(CLASS_UNIVERSAL | PC_PRIMITIVE | TAG_BOOLEAN);
    write_length(out, 1);
    out.push(if value { 0xFF } else { 0x00 });
}

/// Read a BOOLEAN.
pub fn read_bool(cur: &mut ReadCursor<'_>) -> Result<bool, DecodeError> {
    if cur.read_u8()? != CLASS_UNIVERSAL | PC_PRIMITIVE | TAG_BOOLEAN {
        return Err(DecodeError::InvalidField {
            field: "ber.boolean",
            reason: "expected a BOOLEAN identifier",
        });
    }
    if read_length(cur)? != 1 {
        return Err(DecodeError::InvalidField {
            field: "ber.boolean",
            reason: "BOOLEAN content is not 1 byte",
        });
    }
    Ok(cur.read_u8()? != 0)
}

/// Write an ENUMERATED with a single content byte.
pub fn write_enumerated(out: &mut Vec<u8>, value: u8) {
    out.push(CLASS_UNIVERSAL | PC_PRIMITIVE | TAG_ENUMERATED);
    write_length(out, 1);
    out.push(value);
}

/// Read an ENUMERATED, rejecting values at or above `count`.
pub fn read_enumerated(cur: &mut ReadCursor<'_>, count: u8) -> Result<u8, DecodeError> {
    if cur.read_u8()? != CLASS_UNIVERSAL | PC_PRIMITIVE | TAG_ENUMERATED {
        return Err(DecodeError::InvalidField {
            field: "ber.enumerated",
            reason: "expected an ENUMERATED identifier",
        });
    }
    if read_length(cur)? != 1 {
        return Err(DecodeError::InvalidField {
            field: "ber.enumerated",
            reason: "ENUMERATED content is not 1 byte",
        });
    }
    let v = cur.read_u8()?;
    if v >= count {
        return Err(DecodeError::InvalidField {
            field: "ber.enumerated",
            reason: "enumerated value outside the expected range",
        });
    }
    Ok(v)
}

/// Write an OCTET STRING tag + length (the contents follow separately).
pub fn write_octet_string_tag(out: &mut Vec<u8>, length: u16) {
    out.push(CLASS_UNIVERSAL | PC_PRIMITIVE | TAG_OCTET_STRING);
    write_length(out, length);
}

/// Write a complete OCTET STRING (tag, length, contents).
pub fn write_octet_string(out: &mut Vec<u8>, value: &[u8]) {
    write_octet_string_tag(out, value.len() as u16);
    out.extend_from_slice(value);
}

/// Read an OCTET STRING tag, returning the content length (the caller reads the contents).
pub fn read_octet_string_tag(cur: &mut ReadCursor<'_>) -> Result<u16, DecodeError> {
    if cur.read_u8()? != CLASS_UNIVERSAL | PC_PRIMITIVE | TAG_OCTET_STRING {
        return Err(DecodeError::InvalidField {
            field: "ber.octet_string",
            reason: "expected an OCTET STRING identifier",
        });
    }
    read_length(cur)
}

/// Read a complete OCTET STRING, returning its contents.
pub fn read_octet_string<'a>(cur: &mut ReadCursor<'a>) -> Result<&'a [u8], DecodeError> {
    let length = read_octet_string_tag(cur)?;
    cur.read_slice(usize::from(length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_tag_uses_the_0x82_long_form_above_0xff() {
        // Mirrors the oracle's own unit vector: SEQUENCE of length 0x100.
        let mut out = Vec::new();
        write_sequence_tag(&mut out, 0x100);
        assert_eq!(out, vec![0x30, 0x82, 0x01, 0x00]);
        let mut cur = ReadCursor::new(&out, "t");
        assert_eq!(read_sequence_tag(&mut cur).unwrap(), 0x100);
    }

    #[test]
    fn application_tag_above_0x1e_uses_the_high_tag_number_form() {
        // Connect-Initial is [APPLICATION 101]: 0x7F 0x65 <length>.
        let mut out = Vec::new();
        write_application_tag(&mut out, 0x65, 0x0F);
        assert_eq!(out, vec![0x7F, 0x65, 0x0F]);
        let mut cur = ReadCursor::new(&out, "t");
        assert_eq!(read_application_tag(&mut cur, 0x65).unwrap(), 0x0F);
    }

    #[test]
    fn integer_round_trips_across_its_width_thresholds() {
        for value in [
            0u32,
            0x7F,
            0x80,
            0x7FFF,
            0x8000,
            0x007F_FFFF,
            0x0080_0000,
            u32::MAX,
        ] {
            let mut out = Vec::new();
            write_integer(&mut out, value);
            let mut cur = ReadCursor::new(&out, "t");
            assert_eq!(read_integer(&mut cur).unwrap(), value, "value {value:#X}");
            assert_eq!(cur.remaining(), 0);
        }
    }

    #[test]
    fn bool_and_enumerated_and_octet_string_round_trip() {
        let mut out = Vec::new();
        write_bool(&mut out, true);
        write_enumerated(&mut out, 0);
        write_octet_string(&mut out, &[0x01]);
        assert_eq!(
            out,
            vec![0x01, 0x01, 0xFF, 0x0A, 0x01, 0x00, 0x04, 0x01, 0x01]
        );

        let mut cur = ReadCursor::new(&out, "t");
        assert!(read_bool(&mut cur).unwrap());
        assert_eq!(read_enumerated(&mut cur, 16).unwrap(), 0);
        assert_eq!(read_octet_string(&mut cur).unwrap(), &[0x01]);
    }
}
