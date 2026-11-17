//! X.224 (ISO 8073 / RFC 905) TPDU layer — the Connection Request / Connection Confirm TPDUs
//! RDP uses during security negotiation, the class-0 Data TPDU every later PDU rides, and the
//! Disconnect Request a server may end the connection with. RDP carries its `RDP_NEG_REQ` /
//! `RDP_NEG_RSP` structures in the TPDU *variable part*, so they are counted in the LI byte.

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

/// Disconnect Request TPDU code (X.224 13.5.3).
pub const DISCONNECT_REQUEST: u8 = 0x80;

/// Bytes after the LI octet in a DR TPDU before the variable part: code(1) + DST-REF(2) +
/// SRC-REF(2) + reason(1) (X.224 13.5.3).
const DR_FIXED_PART_LEN: usize = 6;

/// The LI value X.224 13.2.1 reserves for extensions.
const LI_RESERVED: u8 = 0xFF;

/// A decoded X.224 Disconnect Request TPDU (X.224 13.5): the peer is ending the transport
/// connection. DST-REF, SRC-REF, the variable part and any user data are not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisconnectRequest {
    /// The `REASON` octet (X.224 13.5.3 d), as sent; values outside the enumeration are kept.
    pub reason: u8,
}

impl DisconnectRequest {
    /// True if `tpdu` carries the Disconnect Request code in its code octet — the pre-test the
    /// connect machine and the session loop make before decoding a Data TPDU.
    pub fn matches(tpdu: &[u8]) -> bool {
        tpdu.get(1) == Some(&DISCONNECT_REQUEST)
    }

    /// Decode a Disconnect Request TPDU. The header LI declares must be present and hold the
    /// fixed part; bytes after it are not read.
    pub fn decode(tpdu: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(tpdu, "x224 disconnect request");
        let li = cur.read_u8()?;
        if cur.read_u8()? != DISCONNECT_REQUEST {
            return Err(DecodeError::InvalidField {
                field: "x224.code",
                reason: "expected Disconnect Request (0x80)",
            });
        }
        if li == LI_RESERVED {
            return Err(DecodeError::InvalidField {
                field: "x224.li",
                reason: "255 is reserved",
            });
        }
        let variable_len =
            usize::from(li)
                .checked_sub(DR_FIXED_PART_LEN)
                .ok_or(DecodeError::InvalidField {
                    field: "x224.li",
                    reason: "shorter than the Disconnect Request fixed part",
                })?;
        cur.read_slice(4)?; // DST-REF + SRC-REF
        let reason = cur.read_u8()?;
        cur.read_slice(variable_len)?;
        Ok(Self { reason })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // ADR-0008 / issue #97 — the no-panic robustness property for a server-controlled PDU
        // parser, added with this module's fuzz target (#200). Both entry points take a
        // server-framed TPDU and return an interior slice computed from its length indicator:
        // `decode_connection_confirm` on the connect path, `decode_data` on every session PDU
        // after it. Malformed bytes must surface as a typed `DecodeError`, never a panic /
        // overflow / OOB. Reaching the end without unwinding IS the assertion.
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn decode_connection_confirm_never_panics_on_arbitrary_input(
            tpdu in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = decode_connection_confirm(&tpdu);
        }

        #[test]
        fn decode_data_never_panics_on_arbitrary_input(
            tpdu in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = decode_data(&tpdu);
        }

        #[test]
        fn disconnect_request_decode_never_panics_on_arbitrary_input(
            tpdu in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = DisconnectRequest::matches(&tpdu);
            let _ = DisconnectRequest::decode(&tpdu);
        }
    }

    /// A class-0 DR TPDU (X.224 13.5) with `reason` and `variable` as its variable part.
    fn disconnect_request(reason: u8, variable: &[u8]) -> Vec<u8> {
        let mut tpdu = vec![
            (6 + variable.len()) as u8, // LI = fixed part + variable part
            0x80,                       // DR
            0x00,
            0x00, // DST-REF
            0x12,
            0x34, // SRC-REF
            reason,
        ];
        tpdu.extend_from_slice(variable);
        tpdu
    }

    #[test]
    fn disconnect_request_reads_the_reason_octet() {
        for reason in [0x00, 0x80, 0x85, 0xFF] {
            let tpdu = disconnect_request(reason, &[]);
            assert!(DisconnectRequest::matches(&tpdu));
            assert_eq!(
                DisconnectRequest::decode(&tpdu),
                Ok(DisconnectRequest { reason })
            );
        }
    }

    #[test]
    fn disconnect_request_skips_its_variable_part_and_trailing_bytes() {
        // Additional-information parameter (code 0xE0, length 2) in the variable part.
        let mut tpdu = disconnect_request(0x81, &[0xE0, 0x02, 0xAA, 0xBB]);
        assert_eq!(
            DisconnectRequest::decode(&tpdu),
            Ok(DisconnectRequest { reason: 0x81 })
        );
        tpdu.extend_from_slice(&[0x01, 0x02]); // user data, which class 0 forbids
        assert_eq!(
            DisconnectRequest::decode(&tpdu),
            Ok(DisconnectRequest { reason: 0x81 })
        );
    }

    #[test]
    fn a_truncated_disconnect_request_is_a_decode_error() {
        let tpdu = disconnect_request(0x80, &[0xE0, 0x02, 0xAA, 0xBB]);
        // Every prefix: the header LI declares is not all there.
        for len in 0..tpdu.len() {
            assert!(
                DisconnectRequest::decode(&tpdu[..len]).is_err(),
                "a {len}-byte prefix decoded"
            );
        }
    }

    #[test]
    fn a_disconnect_request_whose_li_cannot_hold_the_fixed_part_is_a_decode_error() {
        // LI = 5 covers code, DST-REF and SRC-REF but not the reason, which follows anyway.
        let tpdu = [0x05, 0x80, 0x00, 0x00, 0x00, 0x00, 0x80];
        assert!(DisconnectRequest::matches(&tpdu));
        assert_eq!(
            DisconnectRequest::decode(&tpdu),
            Err(DecodeError::InvalidField {
                field: "x224.li",
                reason: "shorter than the Disconnect Request fixed part",
            })
        );
    }

    #[test]
    fn a_disconnect_request_with_the_reserved_li_is_a_decode_error() {
        let mut tpdu = vec![0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x80];
        tpdu.resize(1 + 255, 0);
        assert_eq!(
            DisconnectRequest::decode(&tpdu),
            Err(DecodeError::InvalidField {
                field: "x224.li",
                reason: "255 is reserved",
            })
        );
    }

    #[test]
    fn other_tpdu_codes_are_not_a_disconnect_request() {
        // Data, Connection Confirm, Disconnect Confirm (0xC0, not used in class 0).
        for tpdu in [
            encode_data(&[0x21, 0x80]),
            vec![0x06, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x06, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00],
        ] {
            assert!(!DisconnectRequest::matches(&tpdu), "{tpdu:02x?}");
            assert_eq!(
                DisconnectRequest::decode(&tpdu).unwrap_err(),
                DecodeError::InvalidField {
                    field: "x224.code",
                    reason: "expected Disconnect Request (0x80)",
                },
                "{tpdu:02x?}"
            );
        }
    }

    #[test]
    fn decode_data_still_rejects_a_disconnect_request() {
        assert!(decode_data(&disconnect_request(0x80, &[])).is_err());
    }

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
