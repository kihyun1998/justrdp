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

/// Negotiation Request flags (MS-RDPBCGR 2.2.1.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiationRequestFlags(u8);

impl NegotiationRequestFlags {
    /// No flags.
    pub const NONE: Self = Self(0x00);
    /// Restricted Admin Mode Required.
    /// When set, the server must support Restricted Admin Mode.
    pub const RESTRICTED_ADMIN_MODE_REQUIRED: Self = Self(0x01);
    /// Redirected Authentication Mode Required.
    pub const REDIRECTED_AUTHENTICATION_MODE_REQUIRED: Self = Self(0x02);
    /// Correlation Info Present.
    pub const CORRELATION_INFO_PRESENT: Self = Self(0x08);

    pub fn bits(&self) -> u8 { self.0 }
    pub fn from_bits(bits: u8) -> Self { Self(bits) }
    pub fn contains(&self, other: Self) -> bool { (self.0 & other.0) == other.0 }
    pub fn union(self, other: Self) -> Self { Self(self.0 | other.0) }
}

/// RDP Negotiation Request (sent inside X.224 Connection Request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationRequest {
    /// Requested security protocols.
    pub protocols: SecurityProtocol,
    /// Request flags.
    pub flags: NegotiationRequestFlags,
}

impl NegotiationRequest {
    /// Size of the negotiation request structure.
    pub const SIZE: usize = 8;

    /// Create a new negotiation request.
    pub fn new(protocols: SecurityProtocol) -> Self {
        Self { protocols, flags: NegotiationRequestFlags::NONE }
    }

    /// Create a negotiation request with flags.
    pub fn with_flags(protocols: SecurityProtocol, flags: NegotiationRequestFlags) -> Self {
        Self { protocols, flags }
    }
}

impl Encode for NegotiationRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(NEGO_REQUEST_TYPE, "NegotiationRequest::type")?;
        dst.write_u8(self.flags.bits(), "NegotiationRequest::flags")?;
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
        let flags = src.read_u8("NegotiationRequest::flags")?;
        let _length = src.read_u16_le("NegotiationRequest::length")?;
        let protocols = src.read_u32_le("NegotiationRequest::protocols")?;

        Ok(Self {
            protocols: SecurityProtocol::from_bits(protocols),
            flags: NegotiationRequestFlags::from_bits(flags),
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
    /// Reserved (0x04).
    pub const RESERVED: Self = Self(0x04);
    /// Restricted Admin mode supported (MS-RDPBCGR 2.2.1.2.1).
    pub const RESTRICTED_ADMIN: Self = Self(0x08);
    /// Redirected Authentication supported (MS-RDPBCGR 2.2.1.2.1).
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
    /// Server requires Entra ID (Azure AD) authentication (MS-RDPBCGR 2.2.1.2.2).
    EntraAuthRequiredByServer = 0x0000_0007,
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
            0x07 => Ok(Self::EntraAuthRequiredByServer),
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

/// Fixed header size for X.224 CR/CC/DR TPDUs (LI + code + dst-ref + src-ref + class).
const X224_FIXED_HEADER_SIZE: usize = 7;

/// Cookie prefix in Connection Request.
const COOKIE_PREFIX: &[u8] = b"Cookie: mstshash=";

/// Routing token prefix (MS Terminal Services).
const ROUTING_TOKEN_PREFIX: &[u8] = b"Cookie: msts=";

/// Cookie/token line terminator.
const CR_LF: &[u8] = b"\r\n";

/// The connection-level data carried in an X.224 Connection Request variable field.
///
/// Per MS-RDPBCGR 2.2.1.1, the variable data can contain either:
/// - A cookie: `"Cookie: mstshash=<value>\r\n"`
/// - A routing token: `"Cookie: msts=<value>\r\n"`
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionRequestData {
    /// RDP cookie (`mstshash=<value>`). Only the value part is stored.
    Cookie(alloc::string::String),
    /// Routing token (`msts=<value>`). Raw value bytes.
    RoutingToken(alloc::vec::Vec<u8>),
}

/// X.224 Connection Request (CR) TPDU.
///
/// Sent by the client to initiate an RDP connection. May contain:
/// - A routing token or cookie (for load balancing)
/// - A negotiation request (requested security protocols)
///
/// Wire format:
/// ```text
/// ┌────┬──────┬─────────┬─────────┬───────┬──────────────┬─────────────┐
/// │ LI │ 0xE0 │ DST-REF │ SRC-REF │ CLASS │ cookie/token │ nego req    │
/// │ 1B │  1B  │   2B    │   2B    │  1B   │  variable    │ 8B (opt)    │
/// └────┴──────┴─────────┴─────────┴───────┴──────────────┴─────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequest {
    /// Optional cookie or routing token.
    #[cfg(feature = "alloc")]
    pub data: Option<ConnectionRequestData>,
    /// Negotiation request (security protocol selection).
    pub negotiation: Option<NegotiationRequest>,
}

impl ConnectionRequest {
    /// Create a connection request with negotiation only.
    pub fn new(negotiation: Option<NegotiationRequest>) -> Self {
        Self {
            #[cfg(feature = "alloc")]
            data: None,
            negotiation,
        }
    }

    /// Create a connection request with cookie and negotiation.
    #[cfg(feature = "alloc")]
    pub fn with_cookie(cookie: alloc::string::String, negotiation: Option<NegotiationRequest>) -> Self {
        Self {
            data: Some(ConnectionRequestData::Cookie(cookie)),
            negotiation,
        }
    }

    /// Create a connection request with routing token and negotiation.
    #[cfg(feature = "alloc")]
    pub fn with_routing_token(token: alloc::vec::Vec<u8>, negotiation: Option<NegotiationRequest>) -> Self {
        Self {
            data: Some(ConnectionRequestData::RoutingToken(token)),
            negotiation,
        }
    }

    /// Compute the variable-length portion size (cookie/token + negotiation).
    fn variable_size(&self) -> usize {
        let mut size = 0;
        #[cfg(feature = "alloc")]
        match &self.data {
            Some(ConnectionRequestData::Cookie(cookie)) => {
                // "Cookie: mstshash=" + cookie + "\r\n"
                size += COOKIE_PREFIX.len() + cookie.len() + CR_LF.len();
            }
            Some(ConnectionRequestData::RoutingToken(token)) => {
                // "Cookie: msts=" + token + "\r\n"
                size += ROUTING_TOKEN_PREFIX.len() + token.len() + CR_LF.len();
            }
            None => {}
        }
        if self.negotiation.is_some() {
            size += NegotiationRequest::SIZE;
        }
        size
    }
}

impl Encode for ConnectionRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // LI = total size - 1 (LI byte itself is excluded)
        let li_val = X224_FIXED_HEADER_SIZE - 1 + self.variable_size();
        let li = u8::try_from(li_val).map_err(|_| {
            justrdp_core::EncodeError::other("ConnectionRequest::li", "LI exceeds 255")
        })?;
        dst.write_u8(li, "ConnectionRequest::li")?;
        dst.write_u8(TpduCode::ConnectionRequest as u8, "ConnectionRequest::code")?;
        dst.write_u16_be(0, "ConnectionRequest::dst_ref")?; // DST-REF = 0
        dst.write_u16_be(0, "ConnectionRequest::src_ref")?; // SRC-REF = 0
        dst.write_u8(0, "ConnectionRequest::class")?; // Class 0

        #[cfg(feature = "alloc")]
        match &self.data {
            Some(ConnectionRequestData::Cookie(cookie)) => {
                dst.write_slice(COOKIE_PREFIX, "ConnectionRequest::cookie_prefix")?;
                dst.write_slice(cookie.as_bytes(), "ConnectionRequest::cookie")?;
                dst.write_slice(CR_LF, "ConnectionRequest::cookie_crlf")?;
            }
            Some(ConnectionRequestData::RoutingToken(token)) => {
                dst.write_slice(ROUTING_TOKEN_PREFIX, "ConnectionRequest::token_prefix")?;
                dst.write_slice(token, "ConnectionRequest::routing_token")?;
                dst.write_slice(CR_LF, "ConnectionRequest::token_crlf")?;
            }
            None => {}
        }

        if let Some(ref nego) = self.negotiation {
            nego.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "X224ConnectionRequest"
    }

    fn size(&self) -> usize {
        X224_FIXED_HEADER_SIZE + self.variable_size()
    }
}

#[cfg(feature = "alloc")]
impl<'de> Decode<'de> for ConnectionRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let li = src.read_u8("ConnectionRequest::li")? as usize;
        let start_pos = src.pos();

        let code = src.read_u8("ConnectionRequest::code")?;
        if TpduCode::from_byte(code)? != TpduCode::ConnectionRequest {
            return Err(DecodeError::unexpected_value(
                "ConnectionRequest",
                "code",
                "expected 0xE0",
            ));
        }

        let _dst_ref = src.read_u16_be("ConnectionRequest::dst_ref")?;
        let _src_ref = src.read_u16_be("ConnectionRequest::src_ref")?;
        let _class = src.read_u8("ConnectionRequest::class")?;

        // Remaining bytes within LI
        let consumed = src.pos() - start_pos;
        let remaining_in_li = li.saturating_sub(consumed);

        let mut data = None;
        let mut negotiation = None;

        if remaining_in_li > 0 {
            let var_data = src.peek_remaining();
            let var_data = if var_data.len() > remaining_in_li {
                &var_data[..remaining_in_li]
            } else {
                var_data
            };

            // Check for cookie ("Cookie: mstshash=...") or routing token ("Cookie: msts=...")
            if var_data.starts_with(COOKIE_PREFIX) {
                if let Some(crlf_pos) = find_crlf(var_data) {
                    let value = &var_data[COOKIE_PREFIX.len()..crlf_pos];
                    data = Some(ConnectionRequestData::Cookie(
                        alloc::string::String::from_utf8_lossy(value).into_owned(),
                    ));
                    src.skip(crlf_pos + CR_LF.len(), "ConnectionRequest::cookie")?;
                }
            } else if var_data.starts_with(ROUTING_TOKEN_PREFIX) {
                if let Some(crlf_pos) = find_crlf(var_data) {
                    let value = &var_data[ROUTING_TOKEN_PREFIX.len()..crlf_pos];
                    data = Some(ConnectionRequestData::RoutingToken(value.into()));
                    src.skip(crlf_pos + CR_LF.len(), "ConnectionRequest::routing_token")?;
                }
            }

            // Check if negotiation request follows
            let consumed_now = src.pos() - start_pos;
            let left = li.saturating_sub(consumed_now);
            if left >= NegotiationRequest::SIZE {
                negotiation = Some(NegotiationRequest::decode(src)?);

                // Skip Correlation Info if present (36 bytes, MS-RDPBCGR 2.2.1.1.2)
                if let Some(ref nego) = negotiation {
                    if nego.flags.contains(NegotiationRequestFlags::CORRELATION_INFO_PRESENT) {
                        let consumed_after = src.pos() - start_pos;
                        let left_after = li.saturating_sub(consumed_after);
                        if left_after >= 36 {
                            src.skip(36, "ConnectionRequest::correlationInfo")?;
                        }
                    }
                }
            }
        }

        Ok(Self { data, negotiation })
    }
}

/// X.224 Connection Confirm (CC) TPDU.
///
/// Sent by the server in response to a Connection Request.
///
/// Wire format:
/// ```text
/// ┌────┬──────┬─────────┬─────────┬───────┬─────────────────────┐
/// │ LI │ 0xD0 │ DST-REF │ SRC-REF │ CLASS │ nego resp/failure   │
/// │ 1B │  1B  │   2B    │   2B    │  1B   │ 8B (opt)            │
/// └────┴──────┴─────────┴─────────┴───────┴─────────────────────┘
/// ```
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

impl ConnectionConfirm {
    /// Create a connection confirm with a negotiation response.
    pub fn success(response: NegotiationResponse) -> Self {
        Self {
            negotiation: Some(ConnectionConfirmNegotiation::Response(response)),
        }
    }

    /// Create a connection confirm with a negotiation failure.
    pub fn failure(failure: NegotiationFailure) -> Self {
        Self {
            negotiation: Some(ConnectionConfirmNegotiation::Failure(failure)),
        }
    }

    /// Create a connection confirm with no negotiation data (legacy RDP security).
    pub fn legacy() -> Self {
        Self { negotiation: None }
    }

    fn variable_size(&self) -> usize {
        match &self.negotiation {
            Some(ConnectionConfirmNegotiation::Response(_)) => NegotiationResponse::SIZE,
            Some(ConnectionConfirmNegotiation::Failure(_)) => NegotiationFailure::SIZE,
            None => 0,
        }
    }
}

impl Encode for ConnectionConfirm {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let li_val = X224_FIXED_HEADER_SIZE - 1 + self.variable_size();
        let li = u8::try_from(li_val).map_err(|_| {
            justrdp_core::EncodeError::other("ConnectionConfirm::li", "LI exceeds 255")
        })?;
        dst.write_u8(li, "ConnectionConfirm::li")?;
        dst.write_u8(TpduCode::ConnectionConfirm as u8, "ConnectionConfirm::code")?;
        dst.write_u16_be(0, "ConnectionConfirm::dst_ref")?;
        dst.write_u16_be(0, "ConnectionConfirm::src_ref")?;
        dst.write_u8(0, "ConnectionConfirm::class")?;

        match &self.negotiation {
            Some(ConnectionConfirmNegotiation::Response(resp)) => resp.encode(dst)?,
            Some(ConnectionConfirmNegotiation::Failure(fail)) => fail.encode(dst)?,
            None => {}
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "X224ConnectionConfirm"
    }

    fn size(&self) -> usize {
        X224_FIXED_HEADER_SIZE + self.variable_size()
    }
}

impl<'de> Decode<'de> for ConnectionConfirm {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let li = src.read_u8("ConnectionConfirm::li")? as usize;
        let start_pos = src.pos();

        let code = src.read_u8("ConnectionConfirm::code")?;
        if TpduCode::from_byte(code)? != TpduCode::ConnectionConfirm {
            return Err(DecodeError::unexpected_value(
                "ConnectionConfirm",
                "code",
                "expected 0xD0",
            ));
        }

        let _dst_ref = src.read_u16_be("ConnectionConfirm::dst_ref")?;
        let _src_ref = src.read_u16_be("ConnectionConfirm::src_ref")?;
        let _class = src.read_u8("ConnectionConfirm::class")?;

        let consumed = src.pos() - start_pos;
        let remaining_in_li = li.saturating_sub(consumed);

        let negotiation = if remaining_in_li >= 8 {
            let nego_type = src.peek_u8("ConnectionConfirm::nego_type")?;
            match nego_type {
                NEGO_RESPONSE_TYPE => {
                    Some(ConnectionConfirmNegotiation::Response(NegotiationResponse::decode(src)?))
                }
                NEGO_FAILURE_TYPE => {
                    Some(ConnectionConfirmNegotiation::Failure(NegotiationFailure::decode(src)?))
                }
                _ => {
                    return Err(DecodeError::unexpected_value(
                        "ConnectionConfirm",
                        "negotiation_type",
                        "expected 0x02 or 0x03",
                    ));
                }
            }
        } else {
            None
        };

        Ok(Self { negotiation })
    }
}

/// X.224 Disconnect Request (DR) TPDU.
///
/// Wire format:
/// ```text
/// ┌────┬──────┬─────────┬─────────┬────────┐
/// │ LI │ 0x80 │ DST-REF │ SRC-REF │ REASON │
/// │ 1B │  1B  │   2B    │   2B    │   1B   │
/// └────┴──────┴─────────┴─────────┴────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisconnectRequest {
    /// Disconnect reason code.
    pub reason: DisconnectReason,
}

/// X.224 disconnect reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DisconnectReason {
    /// Not specified.
    NotSpecified = 0,
    /// Congestion at TSAP.
    CongestionAtTsap = 1,
    /// Session entity not attached to TSAP.
    SessionNotAttached = 2,
    /// Address unknown.
    AddressUnknown = 3,
}

impl DisconnectReason {
    /// Parse from a byte value.
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::CongestionAtTsap,
            2 => Self::SessionNotAttached,
            3 => Self::AddressUnknown,
            _ => Self::NotSpecified,
        }
    }
}

/// Disconnect Request header size (LI + code + dst-ref + src-ref + reason = 7).
pub const DISCONNECT_REQUEST_SIZE: usize = 7;

impl DisconnectRequest {
    /// Create a new disconnect request.
    pub fn new(reason: DisconnectReason) -> Self {
        Self { reason }
    }
}

impl Encode for DisconnectRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(6, "DisconnectRequest::li")?; // LI = 6 (7 - 1)
        dst.write_u8(TpduCode::DisconnectRequest as u8, "DisconnectRequest::code")?;
        dst.write_u16_be(0, "DisconnectRequest::dst_ref")?;
        dst.write_u16_be(0, "DisconnectRequest::src_ref")?;
        dst.write_u8(self.reason as u8, "DisconnectRequest::reason")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "X224DisconnectRequest"
    }

    fn size(&self) -> usize {
        DISCONNECT_REQUEST_SIZE
    }
}

impl<'de> Decode<'de> for DisconnectRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let _li = src.read_u8("DisconnectRequest::li")?;
        let code = src.read_u8("DisconnectRequest::code")?;
        if TpduCode::from_byte(code)? != TpduCode::DisconnectRequest {
            return Err(DecodeError::unexpected_value(
                "DisconnectRequest",
                "code",
                "expected 0x80",
            ));
        }
        let _dst_ref = src.read_u16_be("DisconnectRequest::dst_ref")?;
        let _src_ref = src.read_u16_be("DisconnectRequest::src_ref")?;
        let reason = src.read_u8("DisconnectRequest::reason")?;

        Ok(Self {
            reason: DisconnectReason::from_u8(reason),
        })
    }
}

/// Find the position of "\r\n" in a byte slice.
fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == CR_LF)
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
        assert_eq!(decoded.flags, NegotiationRequestFlags::NONE);
    }

    #[test]
    fn negotiation_request_restricted_admin_flag() {
        let req = NegotiationRequest::with_flags(
            SecurityProtocol::HYBRID,
            NegotiationRequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED,
        );
        let mut buf = [0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        req.encode(&mut cursor).unwrap();

        // flags byte is at offset 1
        assert_eq!(buf[1], 0x01);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = NegotiationRequest::decode(&mut cursor).unwrap();
        assert!(decoded.flags.contains(NegotiationRequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED));
        assert!(decoded.protocols.contains(SecurityProtocol::HYBRID));
    }

    #[test]
    fn negotiation_request_redirected_auth_flag() {
        let req = NegotiationRequest::with_flags(
            SecurityProtocol::RDSTLS,
            NegotiationRequestFlags::REDIRECTED_AUTHENTICATION_MODE_REQUIRED,
        );
        let mut buf = [0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        req.encode(&mut cursor).unwrap();

        assert_eq!(buf[1], 0x02);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = NegotiationRequest::decode(&mut cursor).unwrap();
        assert!(decoded.flags.contains(NegotiationRequestFlags::REDIRECTED_AUTHENTICATION_MODE_REQUIRED));
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

    // ── Connection Request tests ──

    #[test]
    fn connection_request_with_cookie_and_nego_roundtrip() {
        let cr = ConnectionRequest::with_cookie(
            "testuser".into(),
            Some(NegotiationRequest::new(SecurityProtocol::HYBRID)),
        );

        let size = cr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        cr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConnectionRequest::decode(&mut cursor).unwrap();
        match &decoded.data {
            Some(ConnectionRequestData::Cookie(c)) => assert_eq!(c, "testuser"),
            other => panic!("expected Cookie, got {:?}", other),
        }
        assert!(decoded.negotiation.is_some());
        assert_eq!(
            decoded.negotiation.unwrap().protocols,
            SecurityProtocol::HYBRID,
        );
    }

    #[test]
    fn connection_request_with_routing_token_roundtrip() {
        let token = b"12345678.PC01.domain.com".to_vec();
        let cr = ConnectionRequest::with_routing_token(
            token.clone(),
            Some(NegotiationRequest::new(SecurityProtocol::SSL)),
        );

        let size = cr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        cr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConnectionRequest::decode(&mut cursor).unwrap();
        match &decoded.data {
            Some(ConnectionRequestData::RoutingToken(t)) => assert_eq!(t, &token),
            other => panic!("expected RoutingToken, got {:?}", other),
        }
        assert_eq!(
            decoded.negotiation.unwrap().protocols,
            SecurityProtocol::SSL,
        );
    }

    #[test]
    fn connection_request_nego_only_roundtrip() {
        let cr = ConnectionRequest::new(Some(NegotiationRequest::new(
            SecurityProtocol::SSL.union(SecurityProtocol::HYBRID),
        )));

        let size = cr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        cr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConnectionRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.data, None);
        assert!(decoded.negotiation.is_some());
        let proto = decoded.negotiation.unwrap().protocols;
        assert!(proto.contains(SecurityProtocol::SSL));
        assert!(proto.contains(SecurityProtocol::HYBRID));
    }

    #[test]
    fn connection_request_minimal_roundtrip() {
        let cr = ConnectionRequest::new(None);

        let size = cr.size();
        assert_eq!(size, X224_FIXED_HEADER_SIZE);
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        cr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConnectionRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.data, None);
        assert_eq!(decoded.negotiation, None);
    }

    // ── Connection Confirm tests ──

    #[test]
    fn connection_confirm_success_roundtrip() {
        let cc = ConnectionConfirm::success(NegotiationResponse {
            flags: NegotiationResponseFlags::EXTENDED_CLIENT_DATA,
            protocol: SecurityProtocol::HYBRID,
        });

        let size = cc.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        cc.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConnectionConfirm::decode(&mut cursor).unwrap();
        match decoded.negotiation {
            Some(ConnectionConfirmNegotiation::Response(resp)) => {
                assert_eq!(resp.protocol, SecurityProtocol::HYBRID);
                assert!(resp.flags.contains(NegotiationResponseFlags::EXTENDED_CLIENT_DATA));
            }
            other => panic!("expected Response, got {:?}", other),
        }
    }

    #[test]
    fn connection_confirm_failure_roundtrip() {
        let cc = ConnectionConfirm::failure(NegotiationFailure {
            code: NegotiationFailureCode::HybridRequiredByServer,
        });

        let size = cc.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        cc.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConnectionConfirm::decode(&mut cursor).unwrap();
        match decoded.negotiation {
            Some(ConnectionConfirmNegotiation::Failure(f)) => {
                assert_eq!(f.code, NegotiationFailureCode::HybridRequiredByServer);
            }
            other => panic!("expected Failure, got {:?}", other),
        }
    }

    #[test]
    fn connection_confirm_legacy_roundtrip() {
        let cc = ConnectionConfirm::legacy();

        let size = cc.size();
        assert_eq!(size, X224_FIXED_HEADER_SIZE);
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        cc.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConnectionConfirm::decode(&mut cursor).unwrap();
        assert_eq!(decoded.negotiation, None);
    }

    // ── Disconnect Request tests ──

    #[test]
    fn disconnect_request_roundtrip() {
        let dr = DisconnectRequest::new(DisconnectReason::CongestionAtTsap);

        let mut buf = [0u8; DISCONNECT_REQUEST_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        dr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DisconnectRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.reason, DisconnectReason::CongestionAtTsap);
    }

    #[test]
    fn disconnect_request_not_specified() {
        let dr = DisconnectRequest::new(DisconnectReason::NotSpecified);

        let mut buf = [0u8; DISCONNECT_REQUEST_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        dr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DisconnectRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.reason, DisconnectReason::NotSpecified);
    }

    // ── Error path tests ──

    #[test]
    fn connection_request_truncated_header() {
        // Only 3 bytes - not enough for the fixed header after LI
        let buf = [0x06, 0xE0, 0x00];
        let mut cursor = ReadCursor::new(&buf);
        assert!(ConnectionRequest::decode(&mut cursor).is_err());
    }

    #[test]
    fn connection_request_wrong_tpdu_code() {
        // Valid LI but wrong code (0xD0 = CC instead of CR)
        let buf = [0x06, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&buf);
        assert!(ConnectionRequest::decode(&mut cursor).is_err());
    }

    #[test]
    fn connection_confirm_wrong_tpdu_code() {
        // Valid LI but wrong code (0xE0 = CR instead of CC)
        let buf = [0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&buf);
        assert!(ConnectionConfirm::decode(&mut cursor).is_err());
    }

    #[test]
    fn connection_confirm_invalid_nego_type() {
        // Valid CC header + 8 bytes of invalid negotiation type (0xFF)
        let mut buf = [0u8; 15];
        buf[0] = 0x0E; // LI = 14
        buf[1] = 0xD0; // CC code
        // dst-ref, src-ref, class = 0
        buf[7] = 0xFF; // invalid negotiation type
        let mut cursor = ReadCursor::new(&buf);
        assert!(ConnectionConfirm::decode(&mut cursor).is_err());
    }

    #[test]
    fn disconnect_request_wrong_tpdu_code() {
        let buf = [0x06, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&buf);
        assert!(DisconnectRequest::decode(&mut cursor).is_err());
    }

    #[test]
    fn disconnect_request_truncated() {
        // Only 4 bytes - need 7
        let buf = [0x06, 0x80, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&buf);
        assert!(DisconnectRequest::decode(&mut cursor).is_err());
    }

    #[test]
    fn data_transfer_wrong_li() {
        // LI should be 2, but we give 3
        let buf = [0x03, 0xF0, 0x80];
        let mut cursor = ReadCursor::new(&buf);
        assert!(DataTransfer::decode(&mut cursor).is_err());
    }

    #[test]
    fn data_transfer_wrong_code() {
        let buf = [0x02, 0xE0, 0x80];
        let mut cursor = ReadCursor::new(&buf);
        assert!(DataTransfer::decode(&mut cursor).is_err());
    }

    #[test]
    fn negotiation_request_wrong_type() {
        let buf = [0xFF, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&buf);
        assert!(NegotiationRequest::decode(&mut cursor).is_err());
    }

    #[test]
    fn negotiation_response_wrong_type() {
        let buf = [0xFF, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&buf);
        assert!(NegotiationResponse::decode(&mut cursor).is_err());
    }

    #[test]
    fn negotiation_failure_unknown_code() {
        // Valid type byte but unknown failure code 0xFF
        let buf = [0x03, 0x00, 0x08, 0x00, 0xFF, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&buf);
        assert!(NegotiationFailure::decode(&mut cursor).is_err());
    }

    #[test]
    fn tpdu_code_unknown() {
        // 0x50 is not a valid TPDU code
        assert!(TpduCode::from_byte(0x50).is_err());
    }

    #[test]
    fn negotiation_failure_all_codes_roundtrip() {
        use NegotiationFailureCode::*;
        let codes = [
            SslRequiredByServer, SslNotAllowedByServer, SslCertNotOnServer,
            InconsistentFlags, HybridRequiredByServer, SslWithUserAuthRequired,
            EntraAuthRequiredByServer,
        ];
        for code in codes {
            let fail = NegotiationFailure { code };
            let mut buf = [0u8; 8];
            let mut w = WriteCursor::new(&mut buf);
            fail.encode(&mut w).unwrap();
            let decoded = NegotiationFailure::decode(&mut ReadCursor::new(&buf)).unwrap();
            assert_eq!(decoded.code, code);
        }
    }

    #[test]
    fn disconnect_request_all_reasons_roundtrip() {
        use DisconnectReason::*;
        for reason in [NotSpecified, CongestionAtTsap, SessionNotAttached, AddressUnknown] {
            let dr = DisconnectRequest::new(reason);
            let mut buf = [0u8; DISCONNECT_REQUEST_SIZE];
            let mut w = WriteCursor::new(&mut buf);
            dr.encode(&mut w).unwrap();
            let decoded = DisconnectRequest::decode(&mut ReadCursor::new(&buf)).unwrap();
            assert_eq!(decoded.reason, reason);
        }
    }

    #[test]
    fn disconnect_reason_unknown_byte_maps_to_not_specified() {
        let buf = [0x06, 0x80, 0x00, 0x00, 0x00, 0x00, 0xFF]; // reason=0xFF
        let decoded = DisconnectRequest::decode(&mut ReadCursor::new(&buf)).unwrap();
        assert_eq!(decoded.reason, DisconnectReason::NotSpecified);
    }

    #[test]
    fn negotiation_response_flags_restricted_admin_value() {
        // Verify RESTRICTED_ADMIN = 0x08, REDIRECTED_AUTH = 0x10 per MS-RDPBCGR 2.2.1.2.1
        assert_eq!(NegotiationResponseFlags::RESTRICTED_ADMIN.bits(), 0x08);
        assert_eq!(NegotiationResponseFlags::REDIRECTED_AUTH.bits(), 0x10);
        assert_eq!(NegotiationResponseFlags::RESERVED.bits(), 0x04);
    }

}
