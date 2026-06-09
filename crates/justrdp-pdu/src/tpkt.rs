//! TPKT framing (RFC 1006). A 4-byte header `[version=3, reserved=0, length_be(u16)]` prefixes
//! every slow-path RDP PDU; the length counts the header *plus* the payload.

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
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::NotEnoughBytes {
            context: "tpkt header",
            needed: HEADER_LEN,
            got: buf.len(),
        });
    }
    if buf[0] != VERSION {
        return Err(DecodeError::InvalidField {
            field: "tpkt.version",
            reason: "expected 3",
        });
    }
    let total = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < total {
        return Err(DecodeError::NotEnoughBytes {
            context: "tpkt frame",
            needed: total,
            got: buf.len(),
        });
    }
    Ok(&buf[HEADER_LEN..total])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DecodeError;

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
        // The header declares a total length of 7, but only 5 bytes have arrived.
        let partial = [0x03, 0x00, 0x00, 0x07, 0xAA];
        let err = decode(&partial).unwrap_err();
        assert_eq!(
            err,
            DecodeError::NotEnoughBytes {
                context: "tpkt frame",
                needed: 7,
                got: 5,
            }
        );
    }
}
