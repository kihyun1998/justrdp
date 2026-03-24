#![forbid(unsafe_code)]

//! X.224 (ISO 8073 Class 0) -- Connection-oriented transport.
//!
//! RDP uses X.224 for connection initiation (CR/CC) and data framing (DT).
//!
//! ## PDU Types
//! - **Connection Request (CR)** -- Client → Server, carries negotiation data
//! - **Connection Confirm (CC)** -- Server → Client, carries selected protocol
//! - **Data Transfer (DT)** -- Wraps all post-negotiation slow-path data
//! - **Disconnect Request (DR)** -- Graceful disconnect

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

/// X.224 TPDU type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TpduCode {
    /// Connection Request
    ConnectionRequest = 0xE0,
    /// Connection Confirm
    ConnectionConfirm = 0xD0,
    /// Disconnect Request
    DisconnectRequest = 0x80,
    /// Data Transfer
    DataTransfer = 0xF0,
    /// Error
    Error = 0x70,
}

impl TpduCode {
    /// Parse a TPDU code from a byte (upper 4 bits).
    pub fn from_byte(byte: u8) -> DecodeResult<Self> {
        match byte & 0xF0 {
            0xE0 => Ok(TpduCode::ConnectionRequest),
            0xD0 => Ok(TpduCode::ConnectionConfirm),
            0x80 => Ok(TpduCode::DisconnectRequest),
            0xF0 => Ok(TpduCode::DataTransfer),
            0x70 => Ok(TpduCode::Error),
            _ => Err(DecodeError::unexpected_value(
                "TpduCode",
                "code",
                "unknown TPDU type",
            )),
        }
    }
}

/// X.224 Data Transfer TPDU (DT).
///
/// Minimal 3-byte header used for all post-negotiation slow-path data:
/// ```text
/// ┌──────┬──────────┬─────┐
/// │ LI=2 │ DT(0xF0) │ EOT │
/// └──────┴──────────┴─────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataTransfer;

/// Data Transfer header size.
pub const DATA_TRANSFER_HEADER_SIZE: usize = 3;

impl Encode for DataTransfer {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(2, "DataTransfer::length_indicator")?; // LI = 2
        dst.write_u8(TpduCode::DataTransfer as u8, "DataTransfer::code")?;
        dst.write_u8(0x80, "DataTransfer::eot")?; // EOT = 1 (last data unit)
        Ok(())
    }

    fn name(&self) -> &'static str {
        "X224DataTransfer"
    }

    fn size(&self) -> usize {
        DATA_TRANSFER_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for DataTransfer {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let li = src.read_u8("DataTransfer::length_indicator")?;
        if li != 2 {
            return Err(DecodeError::unexpected_value(
                "DataTransfer",
                "length_indicator",
                "expected 2",
            ));
        }

        let code = src.read_u8("DataTransfer::code")?;
        if TpduCode::from_byte(code)? != TpduCode::DataTransfer {
            return Err(DecodeError::unexpected_value(
                "DataTransfer",
                "code",
                "expected 0xF0",
            ));
        }

        let _eot = src.read_u8("DataTransfer::eot")?;
        Ok(DataTransfer)
    }
}

// ── Negotiation types ──

/// Security protocol flags for RDP negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityProtocol(u32);

impl SecurityProtocol {
    /// Standard RDP security (RC4-based, legacy).
    pub const RDP: Self = Self(0x0000_0000);
    /// TLS 1.0/1.1/1.2 security.
    pub const SSL: Self = Self(0x0000_0001);
    /// CredSSP (NLA) -- TLS + SPNEGO (NTLM/Kerberos).
    pub const HYBRID: Self = Self(0x0000_0002);
    /// RDSTLS security.
    pub const RDSTLS: Self = Self(0x0000_0004);
    /// CredSSP with Early User Authorization.
    pub const HYBRID_EX: Self = Self(0x0000_0008);
    /// Azure AD authentication.
    pub const AAD: Self = Self(0x0000_0010);

    /// Create from raw bits.
    pub fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Get the raw bits.
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Check if a specific protocol flag is set.
    pub fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two protocol flag sets.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Negotiation request type byte.
pub const NEGO_REQUEST_TYPE: u8 = 0x01;
/// Negotiation response type byte.
pub const NEGO_RESPONSE_TYPE: u8 = 0x02;
/// Negotiation failure type byte.
pub const NEGO_FAILURE_TYPE: u8 = 0x03;

/// RDP Negotiation Request (sent inside X.224 Connection Request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationRequest {
    /// Requested security protocols.
    pub protocols: SecurityProtocol,
}

impl NegotiationRequest {
    /// Size of the negotiation request structure.
    pub const SIZE: usize = 8;

    /// Create a new negotiation request.
    pub fn new(protocols: SecurityProtocol) -> Self {
        Self { protocols }
    }
}

impl Encode for NegotiationRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(NEGO_REQUEST_TYPE, "NegotiationRequest::type")?;
        dst.write_u8(0x00, "NegotiationRequest::flags")?; // flags
        dst.write_u16_le(8, "NegotiationRequest::length")?; // length = 8
        dst.write_u32_le(self.protocols.bits(), "NegotiationRequest::protocols")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "NegotiationRequest"
    }

    fn size(&self) -> usize {
        Self::SIZE
    }
}

impl<'de> Decode<'de> for NegotiationRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let req_type = src.read_u8("NegotiationRequest::type")?;
        if req_type != NEGO_REQUEST_TYPE {
            return Err(DecodeError::unexpected_value(
                "NegotiationRequest",
                "type",
                "expected 0x01",
            ));
        }
        let _flags = src.read_u8("NegotiationRequest::flags")?;
        let _length = src.read_u16_le("NegotiationRequest::length")?;
        let protocols = src.read_u32_le("NegotiationRequest::protocols")?;

        Ok(Self {
            protocols: SecurityProtocol::from_bits(protocols),
        })
    }
}

/// Server negotiation response flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiationResponseFlags(u8);

impl NegotiationResponseFlags {
    /// No flags set.
    pub const NONE: Self = Self(0x00);
    /// Extended Client Data Blocks supported.
    pub const EXTENDED_CLIENT_DATA: Self = Self(0x01);
    /// Graphics Pipeline Extension supported.
    pub const DYNVC_GFX: Self = Self(0x02);
    /// Restricted Admin mode supported.
    pub const RESTRICTED_ADMIN: Self = Self(0x08);
    /// Redirected Authentication supported.
    pub const REDIRECTED_AUTH: Self = Self(0x10);

    /// Create from raw bits.
    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Get the raw bits.
    pub fn bits(&self) -> u8 {
        self.0
    }

    /// Check if a specific flag is set.
    pub fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// RDP Negotiation Response (sent inside X.224 Connection Confirm).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationResponse {
    /// Server flags.
    pub flags: NegotiationResponseFlags,
    /// Selected security protocol.
    pub protocol: SecurityProtocol,
}

impl NegotiationResponse {
    /// Size of the negotiation response structure.
    pub const SIZE: usize = 8;
}

impl Encode for NegotiationResponse {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(NEGO_RESPONSE_TYPE, "NegotiationResponse::type")?;
        dst.write_u8(self.flags.bits(), "NegotiationResponse::flags")?;
        dst.write_u16_le(8, "NegotiationResponse::length")?;
        dst.write_u32_le(self.protocol.bits(), "NegotiationResponse::protocol")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "NegotiationResponse"
    }

    fn size(&self) -> usize {
        Self::SIZE
    }
}

impl<'de> Decode<'de> for NegotiationResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let resp_type = src.read_u8("NegotiationResponse::type")?;
        if resp_type != NEGO_RESPONSE_TYPE {
            return Err(DecodeError::unexpected_value(
                "NegotiationResponse",
                "type",
                "expected 0x02",
            ));
        }
        let flags = src.read_u8("NegotiationResponse::flags")?;
        let _length = src.read_u16_le("NegotiationResponse::length")?;
        let protocol = src.read_u32_le("NegotiationResponse::protocol")?;

        Ok(Self {
            flags: NegotiationResponseFlags::from_bits(flags),
            protocol: SecurityProtocol::from_bits(protocol),
        })
    }
}

/// Negotiation failure codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NegotiationFailureCode {
    /// Server requires TLS.
    SslRequiredByServer = 0x0000_0001,
    /// Server does not allow TLS.
    SslNotAllowedByServer = 0x0000_0002,
    /// No certificate on server.
    SslCertNotOnServer = 0x0000_0003,
    /// Inconsistent negotiation flags.
    InconsistentFlags = 0x0000_0004,
    /// Server requires NLA (CredSSP).
    HybridRequiredByServer = 0x0000_0005,
    /// Server requires TLS with user authentication.
    SslWithUserAuthRequired = 0x0000_0006,
}

impl NegotiationFailureCode {
    /// Parse from a u32 value.
    pub fn from_u32(val: u32) -> DecodeResult<Self> {
        match val {
            0x01 => Ok(Self::SslRequiredByServer),
            0x02 => Ok(Self::SslNotAllowedByServer),
            0x03 => Ok(Self::SslCertNotOnServer),
            0x04 => Ok(Self::InconsistentFlags),
            0x05 => Ok(Self::HybridRequiredByServer),
            0x06 => Ok(Self::SslWithUserAuthRequired),
            _ => Err(DecodeError::unexpected_value(
                "NegotiationFailureCode",
                "code",
                "unknown failure code",
            )),
        }
    }
}

/// RDP Negotiation Failure (sent inside X.224 Connection Confirm on failure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationFailure {
    /// The failure code.
    pub code: NegotiationFailureCode,
}

impl NegotiationFailure {
    /// Size of the negotiation failure structure.
    pub const SIZE: usize = 8;
}

impl Encode for NegotiationFailure {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(NEGO_FAILURE_TYPE, "NegotiationFailure::type")?;
        dst.write_u8(0x00, "NegotiationFailure::flags")?;
        dst.write_u16_le(8, "NegotiationFailure::length")?;
        dst.write_u32_le(self.code as u32, "NegotiationFailure::code")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "NegotiationFailure"
    }

    fn size(&self) -> usize {
        Self::SIZE
    }
}

impl<'de> Decode<'de> for NegotiationFailure {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let fail_type = src.read_u8("NegotiationFailure::type")?;
        if fail_type != NEGO_FAILURE_TYPE {
            return Err(DecodeError::unexpected_value(
                "NegotiationFailure",
                "type",
                "expected 0x03",
            ));
        }
        let _flags = src.read_u8("NegotiationFailure::flags")?;
        let _length = src.read_u16_le("NegotiationFailure::length")?;
        let code_val = src.read_u32_le("NegotiationFailure::code")?;
        let code = NegotiationFailureCode::from_u32(code_val)?;

        Ok(Self { code })
    }
}

/// X.224 Connection Request (CR) TPDU.
///
/// Sent by the client to initiate an RDP connection. May contain:
/// - A routing token or cookie (for load balancing)
/// - A negotiation request (requested security protocols)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequest {
    /// Optional cookie (e.g., "Cookie: mstshash=username\r\n").
    #[cfg(feature = "alloc")]
    pub cookie: Option<alloc::string::String>,
    /// Negotiation request (security protocol selection).
    pub negotiation: Option<NegotiationRequest>,
}

/// X.224 Connection Confirm (CC) TPDU.
///
/// Sent by the server in response to a Connection Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfirm {
    /// Negotiation response (selected protocol) or failure.
    pub negotiation: Option<ConnectionConfirmNegotiation>,
}

/// The negotiation part of a Connection Confirm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionConfirmNegotiation {
    /// Successful negotiation.
    Response(NegotiationResponse),
    /// Failed negotiation.
    Failure(NegotiationFailure),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_transfer_roundtrip() {
        let dt = DataTransfer;
        let mut buf = [0u8; 3];
        let mut cursor = WriteCursor::new(&mut buf);
        dt.encode(&mut cursor).unwrap();
        assert_eq!(&buf, &[0x02, 0xF0, 0x80]);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DataTransfer::decode(&mut cursor).unwrap();
        assert_eq!(decoded, DataTransfer);
    }

    #[test]
    fn negotiation_request_roundtrip() {
        let req = NegotiationRequest::new(SecurityProtocol::SSL.union(SecurityProtocol::HYBRID));
        let mut buf = [0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        req.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = NegotiationRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.protocols.bits(), req.protocols.bits());
        assert!(decoded.protocols.contains(SecurityProtocol::SSL));
        assert!(decoded.protocols.contains(SecurityProtocol::HYBRID));
    }

    #[test]
    fn negotiation_response_roundtrip() {
        let resp = NegotiationResponse {
            flags: NegotiationResponseFlags::EXTENDED_CLIENT_DATA,
            protocol: SecurityProtocol::HYBRID,
        };
        let mut buf = [0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        resp.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = NegotiationResponse::decode(&mut cursor).unwrap();
        assert_eq!(decoded.protocol, SecurityProtocol::HYBRID);
        assert!(decoded.flags.contains(NegotiationResponseFlags::EXTENDED_CLIENT_DATA));
    }

    #[test]
    fn negotiation_failure_roundtrip() {
        let fail = NegotiationFailure {
            code: NegotiationFailureCode::HybridRequiredByServer,
        };
        let mut buf = [0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        fail.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = NegotiationFailure::decode(&mut cursor).unwrap();
        assert_eq!(decoded.code, NegotiationFailureCode::HybridRequiredByServer);
    }

    #[test]
    fn security_protocol_flags() {
        let proto = SecurityProtocol::SSL.union(SecurityProtocol::HYBRID);
        assert!(proto.contains(SecurityProtocol::SSL));
        assert!(proto.contains(SecurityProtocol::HYBRID));
        assert!(!proto.contains(SecurityProtocol::AAD));
        assert_eq!(proto.bits(), 0x03);
    }
}
