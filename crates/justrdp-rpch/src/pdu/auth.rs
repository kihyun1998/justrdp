#![forbid(unsafe_code)]

//! Security trailer (`auth_verifier`) used by every
//! authenticated CO PDU (MS-RPCE §2.2.1.1.7).
//!
//! The trailer sits at the tail of the PDU, immediately after any
//! stub_data has been padded to a 4-byte boundary, and its position
//! is computed by the outer PDU encoder as
//! `frag_length - auth_length - 8`.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{DecodeResult, EncodeResult, ReadCursor, WriteCursor};

// =============================================================================
// auth_type values (MS-RPCE §2.2.1.1.7)
// =============================================================================

pub const RPC_C_AUTHN_NONE: u8 = 0x00;
/// SPNEGO.
pub const RPC_C_AUTHN_GSS_NEGOTIATE: u8 = 0x09;
/// NTLM.
pub const RPC_C_AUTHN_WINNT: u8 = 0x0A;
/// Kerberos.
pub const RPC_C_AUTHN_GSS_KERBEROS: u8 = 0x10;

// =============================================================================
// auth_level values (MS-RPCE §2.2.1.1.7)
// =============================================================================

pub const RPC_C_AUTHN_LEVEL_NONE: u8 = 0x01;
pub const RPC_C_AUTHN_LEVEL_CONNECT: u8 = 0x02;
pub const RPC_C_AUTHN_LEVEL_CALL: u8 = 0x03;
pub const RPC_C_AUTHN_LEVEL_PKT: u8 = 0x04;
pub const RPC_C_AUTHN_LEVEL_INTEGRITY: u8 = 0x05;
pub const RPC_C_AUTHN_LEVEL_PRIVACY: u8 = 0x06;

// =============================================================================
// Security trailer
// =============================================================================

/// Fixed size of the auth_verifier header that precedes `auth_value`.
pub const SECURITY_TRAILER_HEADER_SIZE: usize = 8;

/// The 8-byte auth_verifier header followed by a variable-length
/// `auth_value` blob (e.g. an NTLM message, a Kerberos AP-REQ or
/// AP-REP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityTrailer {
    /// One of the `RPC_C_AUTHN_*` constants above.
    pub auth_type: u8,
    /// One of the `RPC_C_AUTHN_LEVEL_*` constants above.
    pub auth_level: u8,
    /// Number of zero bytes inserted at the **end of `stub_data`**
    /// (or of the PDU body for PDUs that carry no stub) to 4-byte
    /// align the start of this trailer. Never includes any padding
    /// inside `auth_value` itself.
    pub auth_pad_length: u8,
    /// The security context identifier. MS clients typically use
    /// `0x00000000` for the first context on an association.
    pub auth_context_id: u32,
    /// Opaque SSP-specific message (NTLM NEGOTIATE / CHALLENGE /
    /// AUTHENTICATE, Kerberos AP blob, etc.).
    pub auth_value: Vec<u8>,
}

impl SecurityTrailer {
    /// Byte size of this trailer on the wire (header + value).
    pub fn size(&self) -> usize {
        SECURITY_TRAILER_HEADER_SIZE + self.auth_value.len()
    }

    /// Size of the `auth_value` field; this is what goes in the
    /// common header's `auth_length` field (MS-RPCE §2.2.2.4).
    pub fn auth_length(&self) -> u16 {
        self.auth_value.len() as u16
    }

    /// Encode the 8-byte header followed by `auth_value`.
    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(self.auth_type, "auth_type")?;
        dst.write_u8(self.auth_level, "auth_level")?;
        dst.write_u8(self.auth_pad_length, "auth_pad_length")?;
        // auth_reserved MUST be zero (MS-RPCE §2.2.1.1.7).
        dst.write_u8(0, "auth_reserved")?;
        dst.write_u32_le(self.auth_context_id, "auth_context_id")?;
        dst.write_slice(&self.auth_value, "auth_value")?;
        Ok(())
    }

    /// Decode an auth_verifier whose `auth_value` is exactly
    /// `auth_length` bytes long (as declared by the containing PDU's
    /// common header).
    pub fn decode(src: &mut ReadCursor<'_>, auth_length: u16) -> DecodeResult<Self> {
        let auth_type = src.read_u8("auth_type")?;
        let auth_level = src.read_u8("auth_level")?;
        let auth_pad_length = src.read_u8("auth_pad_length")?;
        let _reserved = src.read_u8("auth_reserved")?;
        // Per MS-RPCE §2.2.1.1.7 the reserved byte MUST be zero. We
        // accept non-zero values silently — some proxies are lazy,
        // and the safety-critical checks are on auth_type/level.
        let auth_context_id = src.read_u32_le("auth_context_id")?;
        let auth_value = src
            .read_slice(auth_length as usize, "auth_value")?
            .to_vec();
        Ok(Self {
            auth_type,
            auth_level,
            auth_pad_length,
            auth_context_id,
            auth_value,
        })
    }

    /// Number of zero bytes to append to stub_data so that the next
    /// written byte (the start of this trailer) is 4-byte aligned
    /// relative to the beginning of the PDU.
    ///
    /// `body_end` is the offset from the start of the PDU where
    /// stub_data ended (i.e. the absolute position of the next byte
    /// to be written). This is the number stored in the trailer's
    /// `auth_pad_length` field.
    pub fn pad_length_for(body_end: usize) -> u8 {
        let misalign = body_end & 0x3;
        if misalign == 0 {
            0
        } else {
            (4 - misalign) as u8
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn pad_length_boundary_cases() {
        assert_eq!(SecurityTrailer::pad_length_for(0), 0);
        assert_eq!(SecurityTrailer::pad_length_for(1), 3);
        assert_eq!(SecurityTrailer::pad_length_for(2), 2);
        assert_eq!(SecurityTrailer::pad_length_for(3), 1);
        assert_eq!(SecurityTrailer::pad_length_for(4), 0);
        assert_eq!(SecurityTrailer::pad_length_for(99), 1);
    }

    #[test]
    fn trailer_roundtrip() {
        let t = SecurityTrailer {
            auth_type: RPC_C_AUTHN_WINNT,
            auth_level: RPC_C_AUTHN_LEVEL_CONNECT,
            auth_pad_length: 2,
            auth_context_id: 0x1234_5678,
            auth_value: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let mut buf = vec![0u8; t.size()];
        let mut w = WriteCursor::new(&mut buf);
        t.encode(&mut w).unwrap();
        assert_eq!(w.pos(), t.size());

        let mut r = ReadCursor::new(&buf);
        let got = SecurityTrailer::decode(&mut r, 4).unwrap();
        assert_eq!(got, t);
    }

    #[test]
    fn trailer_exact_bytes() {
        let t = SecurityTrailer {
            auth_type: 0x0A,
            auth_level: 0x02,
            auth_pad_length: 0,
            auth_context_id: 0x0000_0000,
            auth_value: vec![0x01, 0x02, 0x03],
        };
        let mut buf = vec![0u8; t.size()];
        let mut w = WriteCursor::new(&mut buf);
        t.encode(&mut w).unwrap();
        assert_eq!(
            buf,
            vec![
                0x0A, // auth_type
                0x02, // auth_level
                0x00, // auth_pad_length
                0x00, // auth_reserved
                0x00, 0x00, 0x00, 0x00, // auth_context_id LE
                0x01, 0x02, 0x03, // auth_value
            ]
        );
    }

    #[test]
    fn auth_length_matches_value_len() {
        let t = SecurityTrailer {
            auth_type: 0,
            auth_level: 0,
            auth_pad_length: 0,
            auth_context_id: 0,
            auth_value: vec![0; 256],
        };
        assert_eq!(t.auth_length(), 256);
        assert_eq!(t.size(), 264);
    }

    #[test]
    fn zero_length_auth_value() {
        let t = SecurityTrailer {
            auth_type: RPC_C_AUTHN_NONE,
            auth_level: RPC_C_AUTHN_LEVEL_NONE,
            auth_pad_length: 0,
            auth_context_id: 0,
            auth_value: vec![],
        };
        let mut buf = vec![0u8; t.size()];
        let mut w = WriteCursor::new(&mut buf);
        t.encode(&mut w).unwrap();
        assert_eq!(w.pos(), 8);

        let mut r = ReadCursor::new(&buf);
        let got = SecurityTrailer::decode(&mut r, 0).unwrap();
        assert_eq!(got, t);
    }
}
