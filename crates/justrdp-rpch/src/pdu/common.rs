#![forbid(unsafe_code)]

//! 16-byte common connection-oriented PDU header (C706 §12.6.3,
//! MS-RPCE §2.2.2.4).

extern crate alloc;

use justrdp_core::{DecodeError, DecodeResult, EncodeResult, ReadCursor, WriteCursor};

// =============================================================================
// Constants
// =============================================================================

/// Fixed wire size of the common header (C706 §12.6.3).
pub const COMMON_HEADER_SIZE: usize = 16;

/// `rpc_vers` value required by C706 §12.6.3 and MS-RPCE §2.2.2.4.
pub const RPC_VERS: u8 = 5;
/// `rpc_vers_minor` value required by MS-RPCE §2.2.2.4 (always 0).
pub const RPC_VERS_MINOR: u8 = 0;

/// `packed_drep[4]` used by every MS-RPCE CO PDU (MS-RPCE §3.1.1.5.3.1):
/// integer = little-endian (`0x10` high nibble), char = ASCII (low
/// nibble `0`), float = IEEE 754 (`0x00`), two reserved zero bytes.
pub const DREP_DEFAULT: [u8; 4] = [0x10, 0x00, 0x00, 0x00];

// `PFC_*` flag bits (C706 §12.6.3.1).
pub const PFC_FIRST_FRAG: u8 = 0x01;
pub const PFC_LAST_FRAG: u8 = 0x02;
pub const PFC_PENDING_CANCEL: u8 = 0x04;
/// Reserved bit (C706 §12.6.3.1 names it `PFC_RESERVED_1`).
pub const PFC_RESERVED_1: u8 = 0x08;
pub const PFC_CONC_MPX: u8 = 0x10;
pub const PFC_DID_NOT_EXECUTE: u8 = 0x20;
pub const PFC_MAYBE: u8 = 0x40;
pub const PFC_OBJECT_UUID: u8 = 0x80;

// =============================================================================
// Common header
// =============================================================================

/// Common 16-byte CO PDU header (C706 §12.6.3).
///
/// The `frag_length` and `auth_length` fields are computed by the PDU
/// encoder after it knows its own serialized length, so they are not
/// stored here. The caller writes the header *after* the body has
/// been measured and passes the totals to [`CommonHeader::encode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonHeader {
    /// One of the `*_PTYPE` constants in sibling modules.
    pub ptype: u8,
    /// Bitwise-OR of the `PFC_*` flag constants above.
    pub pfc_flags: u8,
    /// Per-call monotonic call identifier. RTS PDUs MUST set this
    /// to zero (MS-RPCH §2.2.3.1).
    pub call_id: u32,
}

impl CommonHeader {
    /// Encode the header with the caller-provided `frag_length` and
    /// `auth_length` (which depend on the PDU body and trailer).
    ///
    /// `frag_length` must equal the total wire size of the PDU
    /// (header + body + optional auth trailer) and `auth_length`
    /// must equal the size of the `auth_value` field only (not
    /// including the 8-byte trailer header).
    pub fn encode(
        &self,
        dst: &mut WriteCursor<'_>,
        frag_length: u16,
        auth_length: u16,
    ) -> EncodeResult<()> {
        dst.write_u8(RPC_VERS, "rpc_vers")?;
        dst.write_u8(RPC_VERS_MINOR, "rpc_vers_minor")?;
        dst.write_u8(self.ptype, "PTYPE")?;
        dst.write_u8(self.pfc_flags, "pfc_flags")?;
        dst.write_slice(&DREP_DEFAULT, "packed_drep")?;
        dst.write_u16_le(frag_length, "frag_length")?;
        dst.write_u16_le(auth_length, "auth_length")?;
        dst.write_u32_le(self.call_id, "call_id")?;
        Ok(())
    }

    /// Decode the 16-byte header and return it along with the
    /// declared `frag_length` and `auth_length`.
    ///
    /// Validates that `rpc_vers == 5`, `rpc_vers_minor == 0`,
    /// `packed_drep == DREP_DEFAULT`, and that `frag_length` is at
    /// least `COMMON_HEADER_SIZE`. Rejects any deviation because MS
    /// clients and servers never emit other values (MS-RPCE
    /// §3.1.1.5.3.1) — accepting them would hide real bugs.
    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<(Self, u16, u16)> {
        let rpc_vers = src.read_u8("rpc_vers")?;
        if rpc_vers != RPC_VERS {
            return Err(DecodeError::invalid_value("CommonHeader", "rpc_vers"));
        }
        let rpc_vers_minor = src.read_u8("rpc_vers_minor")?;
        if rpc_vers_minor != RPC_VERS_MINOR {
            return Err(DecodeError::invalid_value(
                "CommonHeader",
                "rpc_vers_minor",
            ));
        }
        let ptype = src.read_u8("PTYPE")?;
        let pfc_flags = src.read_u8("pfc_flags")?;
        let drep = src.read_slice(4, "packed_drep")?;
        if drep != DREP_DEFAULT {
            return Err(DecodeError::invalid_value(
                "CommonHeader",
                "packed_drep",
            ));
        }
        let frag_length = src.read_u16_le("frag_length")?;
        if (frag_length as usize) < COMMON_HEADER_SIZE {
            return Err(DecodeError::invalid_value(
                "CommonHeader",
                "frag_length",
            ));
        }
        let auth_length = src.read_u16_le("auth_length")?;
        let call_id = src.read_u32_le("call_id")?;
        Ok((
            Self {
                ptype,
                pfc_flags,
                call_id,
            },
            frag_length,
            auth_length,
        ))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_common_header() {
        let hdr = CommonHeader {
            ptype: 0x0B,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 0x1234_5678,
        };
        let mut buf = [0u8; COMMON_HEADER_SIZE];
        let mut w = WriteCursor::new(&mut buf);
        hdr.encode(&mut w, 100, 0).unwrap();
        assert_eq!(w.pos(), COMMON_HEADER_SIZE);

        let mut r = ReadCursor::new(&buf);
        let (got, frag, auth) = CommonHeader::decode(&mut r).unwrap();
        assert_eq!(got, hdr);
        assert_eq!(frag, 100);
        assert_eq!(auth, 0);
    }

    #[test]
    fn exact_wire_bytes() {
        // BIND with PFC_FIRST|PFC_LAST, call_id=1, frag=200, auth=0.
        let hdr = CommonHeader {
            ptype: 0x0B,
            pfc_flags: 0x03,
            call_id: 1,
        };
        let mut buf = [0u8; COMMON_HEADER_SIZE];
        let mut w = WriteCursor::new(&mut buf);
        hdr.encode(&mut w, 200, 0).unwrap();
        assert_eq!(
            buf,
            [
                0x05, // rpc_vers
                0x00, // rpc_vers_minor
                0x0B, // PTYPE = BIND
                0x03, // pfc_flags
                0x10, 0x00, 0x00, 0x00, // packed_drep
                0xC8, 0x00, // frag_length = 200 LE
                0x00, 0x00, // auth_length
                0x01, 0x00, 0x00, 0x00, // call_id = 1
            ]
        );
    }

    #[test]
    fn reject_wrong_rpc_vers() {
        let mut buf = [0u8; COMMON_HEADER_SIZE];
        buf[0] = 4; // invalid
        let mut r = ReadCursor::new(&buf);
        assert!(CommonHeader::decode(&mut r).is_err());
    }

    #[test]
    fn reject_wrong_drep() {
        let mut buf = [0u8; COMMON_HEADER_SIZE];
        buf[0] = RPC_VERS;
        buf[1] = 0;
        buf[2] = 0x0B;
        buf[3] = 0;
        // Wrong DREP (big-endian integer):
        buf[4] = 0x00;
        // Valid frag_length so the error is specifically about DREP.
        buf[8] = 0x10;
        buf[9] = 0x00;
        let mut r = ReadCursor::new(&buf);
        assert!(CommonHeader::decode(&mut r).is_err());
    }

    #[test]
    fn reject_frag_length_below_header_size() {
        let mut buf = [0u8; COMMON_HEADER_SIZE];
        buf[0] = RPC_VERS;
        buf[2] = 0x0B;
        buf[4..8].copy_from_slice(&DREP_DEFAULT);
        buf[8] = 10; // frag_length = 10, too small
        let mut r = ReadCursor::new(&buf);
        assert!(CommonHeader::decode(&mut r).is_err());
    }
}
