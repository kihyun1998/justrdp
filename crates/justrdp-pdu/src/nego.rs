//! RDP security-negotiation structures (MS-RDPBCGR 2.2.1.1.1 / 2.2.1.2.1). The client sends an
//! `RDP_NEG_REQ` inside the X.224 Connection Request advertising which transport security
//! protocols it supports; the server replies with an `RDP_NEG_RSP` (selected protocol) or an
//! `RDP_NEG_FAILURE` (why it refused).

/// The set of transport security protocols a client advertises / a server selects, as the
/// `requestedProtocols` / `selectedProtocol` bitmask. A hand-rolled bitflag newtype keeps
/// `justrdp-pdu` dependency-free (ADR-0001 Amendment). Note: legacy RC4 "Standard RDP Security"
/// (`PROTOCOL_RDP` = 0x0000) is deliberately absent — justrdp never offers it (ADR-0002).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityProtocol(u32);

impl SecurityProtocol {
    /// TLS 1.x (`PROTOCOL_SSL`).
    pub const SSL: Self = Self(0x0000_0001);
    /// CredSSP / NLA (`PROTOCOL_HYBRID`).
    pub const HYBRID: Self = Self(0x0000_0002);
    /// CredSSP with Early User Authorization (`PROTOCOL_HYBRID_EX`).
    pub const HYBRID_EX: Self = Self(0x0000_0008);

    /// The raw bitmask value.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Build from a raw bitmask (e.g. a decoded `selectedProtocol`).
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// True if every bit in `other` is set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for SecurityProtocol {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// `TYPE_RDP_NEG_REQ` — the type byte of an `RDP_NEG_REQ`.
const TYPE_RDP_NEG_REQ: u8 = 0x01;
/// `TYPE_RDP_CORRELATION_INFO` — the type byte of an `RDP_NEG_CORRELATION_INFO`.
const TYPE_RDP_CORRELATION_INFO: u8 = 0x06;
/// `RDP_NEG_REQ` flag `CORRELATION_INFO_PRESENT` (2.2.1.1.1): an `RDP_NEG_CORRELATION_INFO`
/// follows the request.
pub const CORRELATION_INFO_PRESENT: u8 = 0x08;

/// An `RDP_NEG_REQ` (MS-RDPBCGR 2.2.1.1.1): the client's advertised security protocols, carried
/// in the X.224 Connection Request variable part, followed by an `RDP_NEG_CORRELATION_INFO`
/// (2.2.1.1.2) when a correlation id is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegRequest {
    /// Protocols the client supports (`requestedProtocols`).
    pub requested_protocols: SecurityProtocol,
    /// `RDP_NEG_REQ` flags (e.g. restricted-admin); 0 for a plain request.
    /// [`CORRELATION_INFO_PRESENT`] is set from [`Self::correlation_id`], whatever this holds.
    pub flags: u8,
    /// The `correlationId` of the `RDP_NEG_CORRELATION_INFO` that follows the request.
    pub correlation_id: Option<[u8; 16]>,
}

impl NegRequest {
    /// Size of an `RDP_NEG_REQ` on the wire (fixed by the spec).
    pub const ENCODED_LEN: usize = 8;
    /// Size of an `RDP_NEG_CORRELATION_INFO` on the wire (fixed by the spec).
    pub const CORRELATION_INFO_LEN: usize = 36;

    /// A plain request advertising `protocols` with no flags set and no correlation id.
    pub fn new(protocols: SecurityProtocol) -> Self {
        Self {
            requested_protocols: protocols,
            flags: 0,
            correlation_id: None,
        }
    }

    /// Encode the request, and the correlation info after it when a correlation id is set.
    pub fn encode(&self) -> Vec<u8> {
        let flags = match self.correlation_id {
            Some(_) => self.flags | CORRELATION_INFO_PRESENT,
            None => self.flags & !CORRELATION_INFO_PRESENT,
        };
        let mut out = Vec::with_capacity(Self::ENCODED_LEN + Self::CORRELATION_INFO_LEN);
        out.extend_from_slice(&[TYPE_RDP_NEG_REQ, flags]);
        out.extend_from_slice(&(Self::ENCODED_LEN as u16).to_le_bytes());
        out.extend_from_slice(&self.requested_protocols.bits().to_le_bytes());
        if let Some(id) = self.correlation_id {
            out.extend_from_slice(&[TYPE_RDP_CORRELATION_INFO, 0x00]);
            out.extend_from_slice(&(Self::CORRELATION_INFO_LEN as u16).to_le_bytes());
            out.extend_from_slice(&id);
            out.extend_from_slice(&[0; 16]); // reserved
        }
        out
    }
}

/// `TYPE_RDP_NEG_RSP` — the type byte of an `RDP_NEG_RSP`.
const TYPE_RDP_NEG_RSP: u8 = 0x02;
/// `TYPE_RDP_NEG_FAILURE` — the type byte of an `RDP_NEG_FAILURE`.
const TYPE_RDP_NEG_FAILURE: u8 = 0x03;

/// A reason the server refused every advertised protocol (`RDP_NEG_FAILURE.failureCode`,
/// MS-RDPBCGR 2.2.1.2.2). Kept as a newtype so unknown codes survive a round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegFailureCode(pub u32);

impl NegFailureCode {
    /// The server requires SSL/TLS but the client did not offer it.
    pub const SSL_REQUIRED_BY_SERVER: Self = Self(0x0000_0001);
    /// The server forbids SSL/TLS.
    pub const SSL_NOT_ALLOWED_BY_SERVER: Self = Self(0x0000_0002);
    /// The server has no certificate available for SSL/TLS.
    pub const SSL_CERT_NOT_ON_SERVER: Self = Self(0x0000_0003);
    /// The advertised flags were inconsistent.
    pub const INCONSISTENT_FLAGS: Self = Self(0x0000_0004);
    /// The server requires CredSSP/NLA (HYBRID) but the client did not offer it.
    pub const HYBRID_REQUIRED_BY_SERVER: Self = Self(0x0000_0005);
}

/// The server's response inside the X.224 Connection Confirm: either it selected one protocol
/// (`RDP_NEG_RSP`) or it refused them all (`RDP_NEG_FAILURE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegResponse {
    /// The single protocol the server chose.
    Selected(SecurityProtocol),
    /// The server refused; carries the failure code.
    Failure(NegFailureCode),
}

impl NegResponse {
    /// Decode a negotiation response from the Connection Confirm variable part (the 8-byte
    /// `RDP_NEG_RSP` / `RDP_NEG_FAILURE`).
    pub fn decode(variable: &[u8]) -> Result<Self, crate::error::DecodeError> {
        let mut cur = crate::cursor::ReadCursor::new(variable, "rdp negotiation response");
        let ty = cur.read_u8()?;
        cur.read_slice(3)?; // flags (1) + length (2) — fixed, unused
        let value = cur.read_u32_le()?;
        match ty {
            TYPE_RDP_NEG_RSP => Ok(NegResponse::Selected(SecurityProtocol::from_bits(value))),
            TYPE_RDP_NEG_FAILURE => Ok(NegResponse::Failure(NegFailureCode(value))),
            _ => Err(crate::error::DecodeError::InvalidField {
                field: "rdp_neg.type",
                reason: "expected RDP_NEG_RSP or RDP_NEG_FAILURE",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DecodeError;
    use proptest::prelude::*;

    proptest! {
        // ADR-0008 / issue #97 — the no-panic robustness property for a server-controlled PDU
        // parser, added with this module's fuzz target (#200). `NegResponse::decode` reads the
        // server's answer out of the Connection-Confirm variable part — the PDU that decides which
        // security protocol the session uses, parsed before any of it is authenticated. Malformed
        // bytes must surface as a typed `DecodeError`, never a panic / overflow / OOB. Reaching
        // the end without unwinding IS the assertion.
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn neg_response_decode_never_panics_on_arbitrary_input(
            variable in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = NegResponse::decode(&variable);
        }
    }

    #[test]
    fn decode_neg_response_reads_selected_protocol() {
        // RDP_NEG_RSP selecting HYBRID (0x02).
        let variable = [0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00];
        let resp = NegResponse::decode(&variable).unwrap();
        assert_eq!(resp, NegResponse::Selected(SecurityProtocol::HYBRID));
    }

    #[test]
    fn decode_neg_response_reads_failure_code() {
        // RDP_NEG_FAILURE with HYBRID_REQUIRED_BY_SERVER (0x05).
        let variable = [0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00];
        let resp = NegResponse::decode(&variable).unwrap();
        assert_eq!(
            resp,
            NegResponse::Failure(NegFailureCode::HYBRID_REQUIRED_BY_SERVER)
        );
    }

    #[test]
    fn decode_neg_response_needs_eight_bytes() {
        let truncated = [0x02, 0x00, 0x08, 0x00, 0x02];
        let err = NegResponse::decode(&truncated).unwrap_err();
        assert!(matches!(err, DecodeError::NotEnoughBytes { .. }));
    }

    /// `CORRELATION_INFO_PRESENT` and the 36-byte `RDP_NEG_CORRELATION_INFO` (2.2.1.1.2) go out
    /// together: the flag in the request, the structure right after it.
    #[test]
    fn a_correlation_id_sets_the_flag_and_follows_the_request() {
        let id = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xF0, 0x01,
        ];
        let req = NegRequest {
            correlation_id: Some(id),
            ..NegRequest::new(SecurityProtocol::HYBRID_EX)
        };
        let mut expected = vec![
            0x01, // TYPE_RDP_NEG_REQ
            0x08, // flags: CORRELATION_INFO_PRESENT
            0x08, 0x00, // length = 8
            0x08, 0x00, 0x00, 0x00, // requestedProtocols = HYBRID_EX
            0x06, // TYPE_RDP_CORRELATION_INFO
            0x00, // flags
            0x24, 0x00, // length = 36
        ];
        expected.extend_from_slice(&id);
        expected.extend_from_slice(&[0; 16]); // reserved
        assert_eq!(req.encode(), expected);
    }

    /// `CORRELATION_INFO_PRESENT` set by hand without a correlation id is not sent: 2.2.1.1
    /// forbids the flag without the structure.
    #[test]
    fn the_correlation_flag_without_an_id_is_cleared() {
        let req = NegRequest {
            flags: CORRELATION_INFO_PRESENT | 0x01,
            ..NegRequest::new(SecurityProtocol::HYBRID)
        };
        assert_eq!(
            req.encode(),
            [0x01, 0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn neg_request_encodes_advertised_protocols() {
        let req = NegRequest::new(
            SecurityProtocol::SSL | SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX,
        );
        assert_eq!(
            req.encode(),
            [
                0x01, // TYPE_RDP_NEG_REQ
                0x00, // flags
                0x08, 0x00, // length = 8 (little-endian)
                0x0B, 0x00, 0x00, 0x00, // requestedProtocols = SSL|HYBRID|HYBRID_EX (LE)
            ]
        );
    }
}
