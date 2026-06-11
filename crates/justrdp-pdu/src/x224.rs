//! X.224 (ISO 8073 / RFC 905) TPDU layer — only the Connection Request / Connection Confirm
//! TPDUs RDP uses during security negotiation. RDP carries its `RDP_NEG_REQ` / `RDP_NEG_RSP`
//! structures in the TPDU *variable part*, so they are counted in the LI byte.

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// Connection Request TPDU code (client → server).
pub const CONNECTION_REQUEST: u8 = 0xE0;
/// Connection Confirm TPDU code (server → client).
pub const CONNECTION_CONFIRM: u8 = 0xD0;

/// Bytes after the LI octet in a CR/CC TPDU before the variable part: code(1) + DST-REF(2) +
/// SRC-REF(2) + class(1).
const FIXED_PART_LEN: usize = 6;

/// Encode an X.224 Connection Request TPDU carrying `variable` (e.g. an `RDP_NEG_REQ`) as its
/// variable part. Returns the raw TPDU bytes; the caller wraps them in TPKT.
pub fn encode_connection_request(variable: &[u8]) -> Vec<u8> {
    let li = (FIXED_PART_LEN + variable.len()) as u8;
    let mut tpdu = Vec::with_capacity(1 + FIXED_PART_LEN + variable.len());
    tpdu.extend_from_slice(&[
        li,
        CONNECTION_REQUEST,
        0x00,
        0x00, // DST-REF
        0x00,
        0x00, // SRC-REF
        0x00, // class 0 / options
    ]);
    tpdu.extend_from_slice(variable);
    tpdu
}

/// Decode an X.224 Connection Confirm TPDU and return its variable part (e.g. the `RDP_NEG_RSP`
/// bytes). The SRC-REF the server fills in is ignored — RDP does not use it.
pub fn decode_connection_confirm(tpdu: &[u8]) -> Result<&[u8], DecodeError> {
    let mut cur = ReadCursor::new(tpdu, "x224 connection confirm");
    let li = cur.read_u8()? as usize;
    if cur.read_u8()? != CONNECTION_CONFIRM {
        return Err(DecodeError::InvalidField {
            field: "x224.code",
            reason: "expected Connection Confirm (0xD0)",
        });
    }
    // Skip the rest of the fixed part (DST-REF, SRC-REF, class) — the code byte is already read.
    cur.read_slice(FIXED_PART_LEN - 1)?;
    // LI counts the fixed part plus the variable part; the remainder is the variable part.
    let variable_len = li
        .checked_sub(FIXED_PART_LEN)
        .ok_or(DecodeError::InvalidField {
            field: "x224.li",
            reason: "shorter than the fixed TPDU header",
        })?;
    cur.read_slice(variable_len)
}

/// Data TPDU code (class 0, with EOT).
pub const DATA: u8 = 0xF0;
/// The end-of-TSDU mark in the DT TPDU's number field.
const EOT: u8 = 0x80;
/// A class-0 Data TPDU header: LI=2, code 0xF0, EOT.
const DATA_HEADER: [u8; 3] = [0x02, DATA, EOT];

/// Encode an X.224 Data (DT) TPDU carrying `user_data` (e.g. an MCS PDU). Returns the raw TPDU
/// bytes; the caller wraps them in TPKT.
pub fn encode_data(user_data: &[u8]) -> Vec<u8> {
    let mut tpdu = Vec::with_capacity(DATA_HEADER.len() + user_data.len());
    tpdu.extend_from_slice(&DATA_HEADER);
    tpdu.extend_from_slice(user_data);
    tpdu
}

/// Decode an X.224 Data TPDU and return its user data (e.g. the MCS PDU bytes).
pub fn decode_data(tpdu: &[u8]) -> Result<&[u8], DecodeError> {
    let mut cur = ReadCursor::new(tpdu, "x224 data");
    let li = cur.read_u8()?;
    if li != 2 {
        return Err(DecodeError::InvalidField {
            field: "x224.li",
            reason: "expected LI = 2 for a class-0 Data TPDU",
        });
    }
    if cur.read_u8()? != DATA {
        return Err(DecodeError::InvalidField {
            field: "x224.code",
            reason: "expected Data (0xF0)",
        });
    }
    cur.read_u8()?; // TPDU-NR + EOT
    cur.read_slice(cur.remaining())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_tpdu_round_trips_user_data() {
        let tpdu = encode_data(&[0xAA, 0xBB]);
        assert_eq!(tpdu, vec![0x02, 0xF0, 0x80, 0xAA, 0xBB]);
        assert_eq!(decode_data(&tpdu).unwrap(), &[0xAA, 0xBB]);
    }

    #[test]
    fn decode_data_rejects_a_connection_confirm() {
        let err = decode_data(&[0x06, 0xD0, 0x00, 0x00, 0x00, 0x00]).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidField { .. }));
    }

    #[test]
    fn encode_connection_request_frames_variable_part() {
        let variable = [0x01, 0x02, 0x03]; // stand-in for RDP_NEG_REQ
        let tpdu = encode_connection_request(&variable);
        assert_eq!(
            tpdu,
            vec![
                0x09, // LI = 6 fixed + 3 variable
                0xE0, // Connection Request
                0x00, 0x00, // DST-REF
                0x00, 0x00, // SRC-REF
                0x00, // class 0
                0x01, 0x02, 0x03, // variable part
            ]
        );
    }

    #[test]
    fn decode_connection_confirm_returns_variable_part() {
        let tpdu = [
            0x09, // LI = 6 fixed + 3 variable
            0xD0, // Connection Confirm
            0x00, 0x00, // DST-REF
            0x12, 0x34, // SRC-REF (server-chosen; ignored)
            0x00, // class 0
            0xAA, 0xBB, 0xCC, // variable part (e.g. RDP_NEG_RSP)
        ];
        let variable = decode_connection_confirm(&tpdu).unwrap();
        assert_eq!(variable, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decode_connection_confirm_rejects_wrong_tpdu_code() {
        // 0xE0 is a Connection *Request*, not a Confirm.
        let tpdu = [0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00];
        let err = decode_connection_confirm(&tpdu).unwrap_err();
        assert_eq!(
            err,
            DecodeError::InvalidField {
                field: "x224.code",
                reason: "expected Connection Confirm (0xD0)",
            }
        );
    }
}
