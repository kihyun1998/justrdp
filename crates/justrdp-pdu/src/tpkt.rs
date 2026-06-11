//! TPKT framing (RFC 1006). A 4-byte header `[version=3, reserved=0, length_be(u16)]` prefixes
//! every slow-path RDP PDU; the length counts the header *plus* the payload.

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// TPKT version byte — always 3 for RDP (RFC 1006 / TPKT over TCP).
const VERSION: u8 = 3;
/// Size of the TPKT header in bytes.
pub const HEADER_LEN: usize = 4;

/// Wrap `payload` in a TPKT frame: the 4-byte RFC 1006 header followed by the payload.
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let total = (HEADER_LEN + payload.len()) as u16;
    let [len_hi, len_lo] = total.to_be_bytes();
    let mut framed = Vec::with_capacity(total as usize);
    framed.extend_from_slice(&[VERSION, 0x00, len_hi, len_lo]);
    framed.extend_from_slice(payload);
    framed
}

/// Read one TPKT frame from the front of `buf` and return its payload (the bytes after the
/// 4-byte header). The payload borrows `buf`; the whole frame occupies
/// `HEADER_LEN + payload.len()` bytes, which the caller consumes.
pub fn decode(buf: &[u8]) -> Result<&[u8], DecodeError> {
    let mut cur = ReadCursor::new(buf, "tpkt");
    if cur.read_u8()? != VERSION {
        return Err(DecodeError::InvalidField {
            field: "tpkt.version",
            reason: "expected 3",
        });
    }
    cur.read_u8()?; // reserved
    let total = cur.read_u16_be()? as usize;
    let payload_len = total
        .checked_sub(HEADER_LEN)
        .ok_or(DecodeError::InvalidField {
            field: "tpkt.length",
            reason: "shorter than the 4-byte header",
        })?;
    cur.read_slice(payload_len)
}

/// Peek the total length (header included) of the TPKT frame at the front of `buf`, without
/// consuming anything. Returns `NotEnoughBytes` while the 4-byte header is incomplete — the
/// sans-IO "wait for more" signal a frame-assembly loop keys off.
pub fn frame_len(buf: &[u8]) -> Result<usize, DecodeError> {
    let mut cur = ReadCursor::new(buf, "tpkt");
    if cur.read_u8()? != VERSION {
        return Err(DecodeError::InvalidField {
            field: "tpkt.version",
            reason: "expected 3",
        });
    }
    cur.read_u8()?; // reserved
    let total = cur.read_u16_be()? as usize;
    if total < HEADER_LEN {
        return Err(DecodeError::InvalidField {
            field: "tpkt.length",
            reason: "shorter than the 4-byte header",
        });
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DecodeError;

    #[test]
    fn frame_len_peeks_total_length_without_needing_the_payload() {
        // Only the header has arrived; the frame totals 19 bytes.
        let header = [0x03, 0x00, 0x00, 0x13];
        assert_eq!(frame_len(&header).unwrap(), 19);
        // Fewer than 4 bytes: wait.
        assert!(matches!(
            frame_len(&header[..3]).unwrap_err(),
            DecodeError::NotEnoughBytes { .. }
        ));
        // A non-TPKT first byte is malformed, not a partial frame.
        assert!(matches!(
            frame_len(&[0x16, 0x03, 0x01, 0x00]).unwrap_err(),
            DecodeError::InvalidField { .. }
        ));
    }

    #[test]
    fn encode_wraps_payload_with_rfc1006_header() {
        let payload = [0xAA, 0xBB, 0xCC];
        let framed = encode(&payload);
        // version=3, reserved=0, length=7 (4 header + 3 payload) big-endian, then payload.
        assert_eq!(framed, vec![0x03, 0x00, 0x00, 0x07, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decode_extracts_payload_from_complete_frame() {
        let framed = [0x03, 0x00, 0x00, 0x07, 0xAA, 0xBB, 0xCC];
        let payload = decode(&framed).unwrap();
        assert_eq!(payload, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decode_reports_not_enough_bytes_for_partial_frame() {
        // The header declares a total length of 7, but only 5 bytes have arrived. The decoder
        // must signal NotEnoughBytes (the sans-IO "wait for more" signal), not panic. The exact
        // needed/got counts are an implementation detail of the cursor, so assert the variant.
        let partial = [0x03, 0x00, 0x00, 0x07, 0xAA];
        let err = decode(&partial).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::NotEnoughBytes {
                context: "tpkt",
                ..
            }
        ));
    }
}
