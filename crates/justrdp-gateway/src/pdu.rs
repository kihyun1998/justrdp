#![forbid(unsafe_code)]

//! MS-TSGU HTTP Transport PDU types (§2.2.10).
//!
//! Wire-format PDUs carried inside the `RDG_IN_DATA` / `RDG_OUT_DATA`
//! HTTP chunked streams that make up the Remote Desktop Gateway
//! HTTP transport.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

// =============================================================================
// HTTP_PACKET_TYPE (MS-TSGU §2.2.5.3.3)
// =============================================================================

/// Client → server handshake over the IN channel. §2.2.10.10
pub const PKT_TYPE_HANDSHAKE_REQUEST: u16 = 0x0001;
/// Server → client handshake over the OUT channel. §2.2.10.11
pub const PKT_TYPE_HANDSHAKE_RESPONSE: u16 = 0x0002;
/// Extended-auth exchange (SSPI/NTLM, smart card, PAA). §2.2.5.3.2
pub const PKT_TYPE_EXTENDED_AUTH_MSG: u16 = 0x0003;
/// Client → server tunnel create. §2.2.10.18
pub const PKT_TYPE_TUNNEL_CREATE: u16 = 0x0004;
/// Server → client tunnel response. §2.2.10.20
pub const PKT_TYPE_TUNNEL_RESPONSE: u16 = 0x0005;
/// Client → server tunnel authorization. §2.2.10.14
pub const PKT_TYPE_TUNNEL_AUTH: u16 = 0x0006;
/// Server → client tunnel authorization response. §2.2.10.16
pub const PKT_TYPE_TUNNEL_AUTH_RESPONSE: u16 = 0x0007;
/// Client → server channel create. §2.2.10.2
pub const PKT_TYPE_CHANNEL_CREATE: u16 = 0x0008;
/// Server → client channel response. §2.2.10.4
pub const PKT_TYPE_CHANNEL_RESPONSE: u16 = 0x0009;
/// Data packet wrapping RDP traffic. §2.2.10.6
pub const PKT_TYPE_DATA: u16 = 0x000A;
/// Server → client informational service message. §2.2.10.13
pub const PKT_TYPE_SERVICE_MESSAGE: u16 = 0x000B;
/// Server → client reauthentication trigger. §2.2.10.7
pub const PKT_TYPE_REAUTH_MESSAGE: u16 = 0x000C;
/// Bidirectional keepalive. §2.2.10.8
pub const PKT_TYPE_KEEPALIVE: u16 = 0x000D;
/// Close channel request. §2.2.10.12
pub const PKT_TYPE_CLOSE_CHANNEL: u16 = 0x0010;
/// Close channel response. §2.2.10.12
pub const PKT_TYPE_CLOSE_CHANNEL_RESPONSE: u16 = 0x0011;

// =============================================================================
// HTTP_PACKET_HEADER (MS-TSGU §2.2.10.9)
// =============================================================================

/// Wire size of `HTTP_PACKET_HEADER` in bytes. §2.2.10.9
pub const PACKET_HEADER_SIZE: usize = 8;

/// `HTTP_PACKET_HEADER` — 8-byte common header that prefixes every
/// MS-TSGU HTTP Transport PDU. §2.2.10.9
///
/// `packet_length` is the wire byte count of the **entire** packet,
/// including this header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpPacketHeader {
    pub packet_type: u16,
    /// Reserved; MUST be 0x0000 on encode, ignored on decode.
    pub reserved: u16,
    pub packet_length: u32,
}

impl HttpPacketHeader {
    pub const fn new(packet_type: u16, packet_length: u32) -> Self {
        Self {
            packet_type,
            reserved: 0,
            packet_length,
        }
    }
}

impl Encode for HttpPacketHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.packet_type, "HttpPacketHeader.packetType")?;
        dst.write_u16_le(0, "HttpPacketHeader.reserved")?;
        dst.write_u32_le(self.packet_length, "HttpPacketHeader.packetLength")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "HttpPacketHeader"
    }

    fn size(&self) -> usize {
        PACKET_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for HttpPacketHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let packet_type = src.read_u16_le("HttpPacketHeader.packetType")?;
        let reserved = src.read_u16_le("HttpPacketHeader.reserved")?;
        let packet_length = src.read_u32_le("HttpPacketHeader.packetLength")?;
        if (packet_length as usize) < PACKET_HEADER_SIZE {
            return Err(DecodeError::invalid_value(
                "HttpPacketHeader",
                "packetLength",
            ));
        }
        Ok(Self {
            packet_type,
            reserved,
            packet_length,
        })
    }
}

// =============================================================================
// HTTP_UNICODE_STRING (MS-TSGU §2.2.10.22)
// =============================================================================

/// `HTTP_UNICODE_STRING` — length-prefixed UTF-16LE string. §2.2.10.22
///
/// Wire format: `cbLen` (u16 LE, byte count) followed by `cbLen` bytes
/// of UTF-16LE data. `cbLen` is in **bytes**, not UTF-16 code units, so
/// the 11-character hostname `"RDG-Client1"` has `cbLen = 22`. There is
/// no null terminator.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpUnicodeString {
    /// Raw UTF-16LE bytes. Length must fit in a `u16`.
    pub data: Vec<u8>,
}

impl HttpUnicodeString {
    /// Build from a UTF-8 `&str`, encoding as UTF-16LE.
    pub fn encode_str(s: &str) -> Self {
        let mut data = Vec::with_capacity(s.len() * 2);
        for unit in s.encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        Self { data }
    }

    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }

    /// Total wire size including the 2-byte `cbLen` prefix.
    pub fn wire_size(&self) -> usize {
        2 + self.data.len()
    }

    pub fn cb_len(&self) -> u16 {
        self.data.len() as u16
    }
}

impl Encode for HttpUnicodeString {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.data.len() > u16::MAX as usize {
            return Err(EncodeError::invalid_value(
                "HttpUnicodeString",
                "cbLen",
            ));
        }
        dst.write_u16_le(self.data.len() as u16, "HttpUnicodeString.cbLen")?;
        dst.write_slice(&self.data, "HttpUnicodeString.str")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "HttpUnicodeString"
    }

    fn size(&self) -> usize {
        self.wire_size()
    }
}

impl<'de> Decode<'de> for HttpUnicodeString {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cb = src.read_u16_le("HttpUnicodeString.cbLen")? as usize;
        let bytes = src.read_slice(cb, "HttpUnicodeString.str")?;
        Ok(Self {
            data: bytes.to_vec(),
        })
    }
}

// =============================================================================
// HTTP_byte_BLOB (MS-TSGU §2.2.10.1)
// =============================================================================

/// `HTTP_byte_BLOB` — length-prefixed opaque byte sequence. §2.2.10.1
///
/// Used for PAA cookies, Statement-of-Health payloads, reauth cookies,
/// and UDP authentication cookies. Wire format: `cbLen` (u16 LE) +
/// `cbLen` opaque bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpByteBlob {
    pub blob: Vec<u8>,
}

impl HttpByteBlob {
    pub fn new(blob: Vec<u8>) -> Self {
        Self { blob }
    }

    pub fn empty() -> Self {
        Self { blob: Vec::new() }
    }

    pub fn wire_size(&self) -> usize {
        2 + self.blob.len()
    }

    pub fn cb_len(&self) -> u16 {
        self.blob.len() as u16
    }
}

impl Encode for HttpByteBlob {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.blob.len() > u16::MAX as usize {
            return Err(EncodeError::invalid_value("HttpByteBlob", "cbLen"));
        }
        dst.write_u16_le(self.blob.len() as u16, "HttpByteBlob.cbLen")?;
        dst.write_slice(&self.blob, "HttpByteBlob.blob")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "HttpByteBlob"
    }

    fn size(&self) -> usize {
        self.wire_size()
    }
}

impl<'de> Decode<'de> for HttpByteBlob {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cb = src.read_u16_le("HttpByteBlob.cbLen")? as usize;
        let blob = src.read_slice(cb, "HttpByteBlob.blob")?.to_vec();
        Ok(Self { blob })
    }
}

// =============================================================================
// HTTP_EXTENDED_AUTH (MS-TSGU §2.2.5.3.2)
// =============================================================================

pub const HTTP_EXTENDED_AUTH_NONE: u16 = 0x0000;
pub const HTTP_EXTENDED_AUTH_SC: u16 = 0x0001;
pub const HTTP_EXTENDED_AUTH_PAA: u16 = 0x0002;
pub const HTTP_EXTENDED_AUTH_SSPI_NTLM: u16 = 0x0004;

// =============================================================================
// Common HRESULT codes referenced by MS-TSGU (§2.2.6)
// =============================================================================

/// `S_OK` — success.
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `HRESULT_FROM_WIN32(ERROR_GRACEFUL_DISCONNECT)` — clean client-initiated
/// close. §2.2.6. Windows RD Gateway sends this HRESULT form (not the raw
/// Win32 code `0x04CA`) in the `statusCode` field of a CloseChannel PDU.
pub const ERROR_GRACEFUL_DISCONNECT: u32 = 0x8007_04CA;
/// `E_PROXY_QUARANTINE_ACCESSDENIED` — NAP policy reject but proceed. §2.2.6
pub const E_PROXY_QUARANTINE_ACCESSDENIED: u32 = 0x8007_59ED;

// =============================================================================
// HTTP_HANDSHAKE_REQUEST_PACKET (MS-TSGU §2.2.10.10)
// =============================================================================

/// Wire size of `HTTP_HANDSHAKE_REQUEST_PACKET`. §2.2.10.10
pub const HANDSHAKE_REQUEST_SIZE: usize = 14;

/// `HTTP_HANDSHAKE_REQUEST_PACKET` (§2.2.10.10).
///
/// Sent by the client on the IN channel as the very first PDU after
/// HTTP authentication completes. `client_version` is legacy/unused and
/// MUST be `0x0000` on the wire; a value is still exposed here for
/// diagnostic purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeRequestPdu {
    /// RDGHTTP major version. MUST be 1.
    pub ver_major: u8,
    /// RDGHTTP minor version. MUST be 0.
    pub ver_minor: u8,
    /// Client OS version — unused, MUST be 0x0000 on the wire.
    pub client_version: u16,
    /// `HTTP_EXTENDED_AUTH` bitmask (§2.2.5.3.2).
    pub extended_auth: u16,
}

impl HandshakeRequestPdu {
    pub const fn new(extended_auth: u16) -> Self {
        Self {
            ver_major: 1,
            ver_minor: 0,
            client_version: 0,
            extended_auth,
        }
    }

    fn header(&self) -> HttpPacketHeader {
        HttpPacketHeader::new(PKT_TYPE_HANDSHAKE_REQUEST, HANDSHAKE_REQUEST_SIZE as u32)
    }
}

impl Encode for HandshakeRequestPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        self.header().encode(dst)?;
        dst.write_u8(self.ver_major, "HandshakeRequest.verMajor")?;
        dst.write_u8(self.ver_minor, "HandshakeRequest.verMinor")?;
        dst.write_u16_le(self.client_version, "HandshakeRequest.clientVersion")?;
        dst.write_u16_le(self.extended_auth, "HandshakeRequest.extendedAuth")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "HandshakeRequestPdu"
    }

    fn size(&self) -> usize {
        HANDSHAKE_REQUEST_SIZE
    }
}

impl<'de> Decode<'de> for HandshakeRequestPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        if hdr.packet_type != PKT_TYPE_HANDSHAKE_REQUEST {
            return Err(DecodeError::invalid_value(
                "HandshakeRequest",
                "packetType",
            ));
        }
        if hdr.packet_length as usize != HANDSHAKE_REQUEST_SIZE {
            return Err(DecodeError::invalid_value(
                "HandshakeRequest",
                "packetLength",
            ));
        }
        let ver_major = src.read_u8("HandshakeRequest.verMajor")?;
        let ver_minor = src.read_u8("HandshakeRequest.verMinor")?;
        let client_version = src.read_u16_le("HandshakeRequest.clientVersion")?;
        let extended_auth = src.read_u16_le("HandshakeRequest.extendedAuth")?;
        Ok(Self {
            ver_major,
            ver_minor,
            client_version,
            extended_auth,
        })
    }
}

// =============================================================================
// HTTP_HANDSHAKE_RESPONSE_PACKET (MS-TSGU §2.2.10.11)
// =============================================================================

/// Wire size of `HTTP_HANDSHAKE_RESPONSE_PACKET`. §2.2.10.11
pub const HANDSHAKE_RESPONSE_SIZE: usize = 18;

/// `HTTP_HANDSHAKE_RESPONSE_PACKET` (§2.2.10.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeResponsePdu {
    /// HRESULT; 0 = success.
    pub error_code: u32,
    pub ver_major: u8,
    pub ver_minor: u8,
    /// Server OS version — unused, always 0x0000.
    pub server_version: u16,
    /// Server advertisement of supported `HTTP_EXTENDED_AUTH` bits.
    pub extended_auth: u16,
}

impl HandshakeResponsePdu {
    pub const fn ok(extended_auth: u16) -> Self {
        Self {
            error_code: STATUS_SUCCESS,
            ver_major: 1,
            ver_minor: 0,
            server_version: 0,
            extended_auth,
        }
    }

    fn header(&self) -> HttpPacketHeader {
        HttpPacketHeader::new(PKT_TYPE_HANDSHAKE_RESPONSE, HANDSHAKE_RESPONSE_SIZE as u32)
    }
}

impl Encode for HandshakeResponsePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        self.header().encode(dst)?;
        dst.write_u32_le(self.error_code, "HandshakeResponse.errorCode")?;
        dst.write_u8(self.ver_major, "HandshakeResponse.verMajor")?;
        dst.write_u8(self.ver_minor, "HandshakeResponse.verMinor")?;
        dst.write_u16_le(self.server_version, "HandshakeResponse.serverVersion")?;
        dst.write_u16_le(self.extended_auth, "HandshakeResponse.extendedAuth")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "HandshakeResponsePdu"
    }

    fn size(&self) -> usize {
        HANDSHAKE_RESPONSE_SIZE
    }
}

impl<'de> Decode<'de> for HandshakeResponsePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        if hdr.packet_type != PKT_TYPE_HANDSHAKE_RESPONSE {
            return Err(DecodeError::invalid_value(
                "HandshakeResponse",
                "packetType",
            ));
        }
        if hdr.packet_length as usize != HANDSHAKE_RESPONSE_SIZE {
            return Err(DecodeError::invalid_value(
                "HandshakeResponse",
                "packetLength",
            ));
        }
        let error_code = src.read_u32_le("HandshakeResponse.errorCode")?;
        let ver_major = src.read_u8("HandshakeResponse.verMajor")?;
        let ver_minor = src.read_u8("HandshakeResponse.verMinor")?;
        let server_version = src.read_u16_le("HandshakeResponse.serverVersion")?;
        let extended_auth = src.read_u16_le("HandshakeResponse.extendedAuth")?;
        Ok(Self {
            error_code,
            ver_major,
            ver_minor,
            server_version,
            extended_auth,
        })
    }
}

// =============================================================================
// HTTP_KEEPALIVE_PACKET (MS-TSGU §2.2.10.8)
// =============================================================================

/// Wire size of `HTTP_KEEPALIVE_PACKET` (header only). §2.2.10.8
pub const KEEPALIVE_SIZE: usize = 8;

/// `HTTP_KEEPALIVE_PACKET` (§2.2.10.8).
///
/// Zero-payload ping sent by either side to keep reverse proxies from
/// timing out the long-lived IN/OUT connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeepalivePdu;

impl Encode for KeepalivePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        HttpPacketHeader::new(PKT_TYPE_KEEPALIVE, KEEPALIVE_SIZE as u32).encode(dst)
    }

    fn name(&self) -> &'static str {
        "KeepalivePdu"
    }

    fn size(&self) -> usize {
        KEEPALIVE_SIZE
    }
}

impl<'de> Decode<'de> for KeepalivePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        if hdr.packet_type != PKT_TYPE_KEEPALIVE {
            return Err(DecodeError::invalid_value("Keepalive", "packetType"));
        }
        if hdr.packet_length as usize != KEEPALIVE_SIZE {
            return Err(DecodeError::invalid_value("Keepalive", "packetLength"));
        }
        Ok(Self)
    }
}

// =============================================================================
// HTTP_REAUTH_MESSAGE (MS-TSGU §2.2.10.7)
// =============================================================================

/// Wire size of `HTTP_REAUTH_MESSAGE`. §2.2.10.7
pub const REAUTH_MESSAGE_SIZE: usize = 16;

/// `HTTP_REAUTH_MESSAGE` (§2.2.10.7).
///
/// Server → client trigger asking the client to perform a re-auth by
/// sending a fresh `HTTP_TUNNEL_PACKET` with `FIELD_REAUTH` set and
/// this `reauth_tunnel_context` echoed back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReauthMessagePdu {
    pub reauth_tunnel_context: u64,
}

impl ReauthMessagePdu {
    pub const fn new(ctx: u64) -> Self {
        Self {
            reauth_tunnel_context: ctx,
        }
    }
}

impl Encode for ReauthMessagePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        HttpPacketHeader::new(PKT_TYPE_REAUTH_MESSAGE, REAUTH_MESSAGE_SIZE as u32).encode(dst)?;
        dst.write_u64_le(self.reauth_tunnel_context, "ReauthMessage.context")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ReauthMessagePdu"
    }

    fn size(&self) -> usize {
        REAUTH_MESSAGE_SIZE
    }
}

impl<'de> Decode<'de> for ReauthMessagePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        if hdr.packet_type != PKT_TYPE_REAUTH_MESSAGE {
            return Err(DecodeError::invalid_value("ReauthMessage", "packetType"));
        }
        if hdr.packet_length as usize != REAUTH_MESSAGE_SIZE {
            return Err(DecodeError::invalid_value("ReauthMessage", "packetLength"));
        }
        let ctx = src.read_u64_le("ReauthMessage.context")?;
        Ok(Self {
            reauth_tunnel_context: ctx,
        })
    }
}

// =============================================================================
// HTTP_CLOSE_PACKET (MS-TSGU §2.2.10.12)
// =============================================================================

/// Wire size of `HTTP_CLOSE_PACKET`. §2.2.10.12
pub const CLOSE_CHANNEL_SIZE: usize = 12;

/// Role of a `CloseChannelPdu` — which direction of the close exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseChannelKind {
    /// `PKT_TYPE_CLOSE_CHANNEL` = 0x0010. §2.2.10.12
    Request,
    /// `PKT_TYPE_CLOSE_CHANNEL_RESPONSE` = 0x0011. §2.2.10.12
    Response,
}

impl CloseChannelKind {
    pub const fn packet_type(self) -> u16 {
        match self {
            Self::Request => PKT_TYPE_CLOSE_CHANNEL,
            Self::Response => PKT_TYPE_CLOSE_CHANNEL_RESPONSE,
        }
    }

    pub const fn from_packet_type(t: u16) -> Option<Self> {
        match t {
            PKT_TYPE_CLOSE_CHANNEL => Some(Self::Request),
            PKT_TYPE_CLOSE_CHANNEL_RESPONSE => Some(Self::Response),
            _ => None,
        }
    }
}

/// `HTTP_CLOSE_PACKET` (§2.2.10.12).
///
/// Shared wire format for close request (`PKT_TYPE_CLOSE_CHANNEL`) and
/// close response (`PKT_TYPE_CLOSE_CHANNEL_RESPONSE`); the two differ
/// only in the header's `packet_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseChannelPdu {
    pub kind: CloseChannelKind,
    /// HRESULT — 0 on clean close; `ERROR_GRACEFUL_DISCONNECT` when
    /// sent by a client as a courtesy shutdown.
    pub status_code: u32,
}

impl CloseChannelPdu {
    pub const fn request(status_code: u32) -> Self {
        Self {
            kind: CloseChannelKind::Request,
            status_code,
        }
    }

    pub const fn response(status_code: u32) -> Self {
        Self {
            kind: CloseChannelKind::Response,
            status_code,
        }
    }
}

impl Encode for CloseChannelPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        HttpPacketHeader::new(self.kind.packet_type(), CLOSE_CHANNEL_SIZE as u32).encode(dst)?;
        dst.write_u32_le(self.status_code, "CloseChannel.statusCode")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CloseChannelPdu"
    }

    fn size(&self) -> usize {
        CLOSE_CHANNEL_SIZE
    }
}

impl<'de> Decode<'de> for CloseChannelPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        let kind = CloseChannelKind::from_packet_type(hdr.packet_type)
            .ok_or_else(|| DecodeError::invalid_value("CloseChannel", "packetType"))?;
        if hdr.packet_length as usize != CLOSE_CHANNEL_SIZE {
            return Err(DecodeError::invalid_value("CloseChannel", "packetLength"));
        }
        let status_code = src.read_u32_le("CloseChannel.statusCode")?;
        Ok(Self { kind, status_code })
    }
}

// =============================================================================
// HTTP_CAPABILITY_TYPE (MS-TSGU §2.2.5.3)
// =============================================================================

pub const HTTP_CAPABILITY_TYPE_QUAR_SOH: u32 = 0x0000_0001;
pub const HTTP_CAPABILITY_IDLE_TIMEOUT: u32 = 0x0000_0002;
pub const HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN: u32 = 0x0000_0004;
pub const HTTP_CAPABILITY_MESSAGING_SERVICE_MSG: u32 = 0x0000_0008;
pub const HTTP_CAPABILITY_REAUTH: u32 = 0x0000_0010;
pub const HTTP_CAPABILITY_UDP_TRANSPORT: u32 = 0x0000_0020;

// =============================================================================
// HTTP_TUNNEL_PACKET_FIELDS_PRESENT_FLAGS (MS-TSGU §2.2.5.3.6)
// =============================================================================

pub const HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE: u16 = 0x0001;
pub const HTTP_TUNNEL_PACKET_FIELD_REAUTH: u16 = 0x0002;

// =============================================================================
// HTTP_TUNNEL_PACKET (MS-TSGU §2.2.10.18, §2.2.10.19)
// =============================================================================

/// Wire size of the fixed portion of `HTTP_TUNNEL_PACKET`. §2.2.10.18
pub const TUNNEL_CREATE_FIXED_SIZE: usize = 16;

/// `HTTP_TUNNEL_PACKET` + `HTTP_TUNNEL_PACKET_OPTIONAL` (§§2.2.10.18–19).
///
/// Client → server TunnelCreate. The optional struct is absent when
/// `fields_present == 0`. When any flag is set, `reauth_tunnel_context`
/// is **always** present (8 bytes) regardless of which flag is set —
/// it precedes `paa_cookie` in the optional struct. When the reauth
/// flag is not set, the u64 is written as `0` and its value is ignored
/// on decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelCreatePdu {
    pub caps_flags: u32,
    pub fields_present: u16,
    /// Present (as 8 bytes) whenever `fields_present != 0`. Ignored
    /// unless `HTTP_TUNNEL_PACKET_FIELD_REAUTH` is set.
    pub reauth_tunnel_context: u64,
    /// Present only when `HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE` is set.
    pub paa_cookie: Option<HttpByteBlob>,
}

impl TunnelCreatePdu {
    /// Build a normal (non-PAA, non-reauth) TunnelCreate.
    pub fn normal(caps_flags: u32) -> Self {
        Self {
            caps_flags,
            fields_present: 0,
            reauth_tunnel_context: 0,
            paa_cookie: None,
        }
    }

    /// Build a TunnelCreate carrying a PAA cookie.
    pub fn with_paa_cookie(caps_flags: u32, cookie: HttpByteBlob) -> Self {
        Self {
            caps_flags,
            fields_present: HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE,
            reauth_tunnel_context: 0,
            paa_cookie: Some(cookie),
        }
    }

    /// Build a TunnelCreate carrying a reauth tunnel context handle.
    pub fn with_reauth(caps_flags: u32, reauth_tunnel_context: u64) -> Self {
        Self {
            caps_flags,
            fields_present: HTTP_TUNNEL_PACKET_FIELD_REAUTH,
            reauth_tunnel_context,
            paa_cookie: None,
        }
    }

    fn optional_size(&self) -> usize {
        if self.fields_present == 0 {
            0
        } else {
            let mut n = 8; // reauth_tunnel_context is always present
            if self.fields_present & HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE != 0 {
                n += self
                    .paa_cookie
                    .as_ref()
                    .map(|c| c.wire_size())
                    .unwrap_or(2);
            }
            n
        }
    }
}

impl Encode for TunnelCreatePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        HttpPacketHeader::new(PKT_TYPE_TUNNEL_CREATE, self.size() as u32).encode(dst)?;
        dst.write_u32_le(self.caps_flags, "TunnelCreate.capsFlags")?;
        dst.write_u16_le(self.fields_present, "TunnelCreate.fieldsPresent")?;
        dst.write_u16_le(0, "TunnelCreate.reserved")?;
        if self.fields_present != 0 {
            dst.write_u64_le(
                self.reauth_tunnel_context,
                "TunnelCreate.reauthTunnelContext",
            )?;
            if self.fields_present & HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE != 0 {
                match &self.paa_cookie {
                    Some(c) => c.encode(dst)?,
                    None => HttpByteBlob::empty().encode(dst)?,
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TunnelCreatePdu"
    }

    fn size(&self) -> usize {
        TUNNEL_CREATE_FIXED_SIZE + self.optional_size()
    }
}

impl<'de> Decode<'de> for TunnelCreatePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        if hdr.packet_type != PKT_TYPE_TUNNEL_CREATE {
            return Err(DecodeError::invalid_value("TunnelCreate", "packetType"));
        }
        let caps_flags = src.read_u32_le("TunnelCreate.capsFlags")?;
        let fields_present = src.read_u16_le("TunnelCreate.fieldsPresent")?;
        let _reserved = src.read_u16_le("TunnelCreate.reserved")?;

        let (reauth_tunnel_context, paa_cookie) = if fields_present == 0 {
            (0, None)
        } else {
            let ctx = src.read_u64_le("TunnelCreate.reauthTunnelContext")?;
            let cookie = if fields_present & HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE != 0 {
                Some(HttpByteBlob::decode(src)?)
            } else {
                None
            };
            (ctx, cookie)
        };

        let pdu = Self {
            caps_flags,
            fields_present,
            reauth_tunnel_context,
            paa_cookie,
        };
        if hdr.packet_length as usize != pdu.size() {
            return Err(DecodeError::invalid_value("TunnelCreate", "packetLength"));
        }
        Ok(pdu)
    }
}

// =============================================================================
// HTTP_TUNNEL_RESPONSE_FIELDS_PRESENT_FLAGS (MS-TSGU §2.2.5.3.8)
// =============================================================================

pub const HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID: u16 = 0x0001;
pub const HTTP_TUNNEL_RESPONSE_FIELD_CAPS: u16 = 0x0002;
pub const HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ: u16 = 0x0004;
/// Note: bit 0x0008 is unassigned; CONSENT_MSG jumps to 0x0010. §2.2.5.3.8
pub const HTTP_TUNNEL_RESPONSE_FIELD_CONSENT_MSG: u16 = 0x0010;

// =============================================================================
// HTTP_TUNNEL_RESPONSE (MS-TSGU §2.2.10.20, §2.2.10.21)
// =============================================================================

/// Wire size of the fixed portion of `HTTP_TUNNEL_RESPONSE`. §2.2.10.20
pub const TUNNEL_RESPONSE_FIXED_SIZE: usize = 18;

/// `HTTP_TUNNEL_RESPONSE` + `HTTP_TUNNEL_RESPONSE_OPTIONAL` (§§2.2.10.20–21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelResponsePdu {
    pub server_version: u16,
    /// HRESULT; 0 = success. Check before reading optional fields.
    pub status_code: u32,
    pub fields_present: u16,
    /// Populated only when `HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID` set.
    pub tunnel_id: u32,
    /// Populated only when `HTTP_TUNNEL_RESPONSE_FIELD_CAPS` set.
    pub caps_flags: u32,
    /// 16-byte nonce; populated only when `FIELD_SOH_REQ` set.
    pub nonce: [u8; 16],
    /// DER server cert blob; populated only when `FIELD_SOH_REQ` set.
    pub server_cert: HttpUnicodeString,
    /// Admin consent text; populated only when `FIELD_CONSENT_MSG` set.
    pub consent_msg: HttpUnicodeString,
}

impl TunnelResponsePdu {
    /// Success response carrying a tunnel id and negotiated caps flags.
    pub fn ok(server_version: u16, tunnel_id: u32, caps_flags: u32) -> Self {
        Self {
            server_version,
            status_code: STATUS_SUCCESS,
            fields_present: HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID
                | HTTP_TUNNEL_RESPONSE_FIELD_CAPS,
            tunnel_id,
            caps_flags,
            nonce: [0; 16],
            server_cert: HttpUnicodeString::empty(),
            consent_msg: HttpUnicodeString::empty(),
        }
    }

    fn optional_size(&self) -> usize {
        let mut n = 0;
        if self.fields_present & HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID != 0 {
            n += 4;
        }
        if self.fields_present & HTTP_TUNNEL_RESPONSE_FIELD_CAPS != 0 {
            n += 4;
        }
        if self.fields_present & HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ != 0 {
            n += 16 + self.server_cert.wire_size();
        }
        if self.fields_present & HTTP_TUNNEL_RESPONSE_FIELD_CONSENT_MSG != 0 {
            n += self.consent_msg.wire_size();
        }
        n
    }
}

impl Encode for TunnelResponsePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        HttpPacketHeader::new(PKT_TYPE_TUNNEL_RESPONSE, self.size() as u32).encode(dst)?;
        dst.write_u16_le(self.server_version, "TunnelResponse.serverVersion")?;
        dst.write_u32_le(self.status_code, "TunnelResponse.statusCode")?;
        dst.write_u16_le(self.fields_present, "TunnelResponse.fieldsPresent")?;
        dst.write_u16_le(0, "TunnelResponse.reserved")?;
        if self.fields_present & HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID != 0 {
            dst.write_u32_le(self.tunnel_id, "TunnelResponse.tunnelId")?;
        }
        if self.fields_present & HTTP_TUNNEL_RESPONSE_FIELD_CAPS != 0 {
            dst.write_u32_le(self.caps_flags, "TunnelResponse.capsFlags")?;
        }
        if self.fields_present & HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ != 0 {
            dst.write_slice(&self.nonce, "TunnelResponse.nonce")?;
            self.server_cert.encode(dst)?;
        }
        if self.fields_present & HTTP_TUNNEL_RESPONSE_FIELD_CONSENT_MSG != 0 {
            self.consent_msg.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TunnelResponsePdu"
    }

    fn size(&self) -> usize {
        TUNNEL_RESPONSE_FIXED_SIZE + self.optional_size()
    }
}

impl<'de> Decode<'de> for TunnelResponsePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        if hdr.packet_type != PKT_TYPE_TUNNEL_RESPONSE {
            return Err(DecodeError::invalid_value("TunnelResponse", "packetType"));
        }
        let server_version = src.read_u16_le("TunnelResponse.serverVersion")?;
        let status_code = src.read_u32_le("TunnelResponse.statusCode")?;
        let fields_present = src.read_u16_le("TunnelResponse.fieldsPresent")?;
        let _reserved = src.read_u16_le("TunnelResponse.reserved")?;

        let mut tunnel_id = 0u32;
        if fields_present & HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID != 0 {
            tunnel_id = src.read_u32_le("TunnelResponse.tunnelId")?;
        }
        let mut caps_flags = 0u32;
        if fields_present & HTTP_TUNNEL_RESPONSE_FIELD_CAPS != 0 {
            caps_flags = src.read_u32_le("TunnelResponse.capsFlags")?;
        }
        let mut nonce = [0u8; 16];
        let mut server_cert = HttpUnicodeString::empty();
        if fields_present & HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ != 0 {
            let slice = src.read_slice(16, "TunnelResponse.nonce")?;
            nonce.copy_from_slice(slice);
            server_cert = HttpUnicodeString::decode(src)?;
        }
        let mut consent_msg = HttpUnicodeString::empty();
        if fields_present & HTTP_TUNNEL_RESPONSE_FIELD_CONSENT_MSG != 0 {
            consent_msg = HttpUnicodeString::decode(src)?;
        }

        let pdu = Self {
            server_version,
            status_code,
            fields_present,
            tunnel_id,
            caps_flags,
            nonce,
            server_cert,
            consent_msg,
        };
        if hdr.packet_length as usize != pdu.size() {
            return Err(DecodeError::invalid_value(
                "TunnelResponse",
                "packetLength",
            ));
        }
        Ok(pdu)
    }
}

// =============================================================================
// HTTP_TUNNEL_AUTH_FIELDS_PRESENT_FLAGS (MS-TSGU §2.2.5.3.4)
// =============================================================================

pub const HTTP_TUNNEL_AUTH_FIELD_SOH: u16 = 0x0001;

// =============================================================================
// HTTP_TUNNEL_AUTH_PACKET (MS-TSGU §2.2.10.14, §2.2.10.15)
// =============================================================================

/// Wire size of the fixed portion of `HTTP_TUNNEL_AUTH_PACKET`. §2.2.10.14
pub const TUNNEL_AUTH_FIXED_SIZE: usize = 12;

/// `HTTP_TUNNEL_AUTH_PACKET` + `HTTP_TUNNEL_AUTH_PACKET_OPTIONAL` (§§2.2.10.14–15).
///
/// The `clientName` field in the optional portion is a raw UTF-16LE
/// byte sequence whose length is given by `cbClientName` in the fixed
/// header (the IDL definition is `[size_is(cbClientName/2)] wchar_t*`,
/// so there is no embedded length prefix — `cbClientName` is the
/// authoritative length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelAuthPdu {
    pub fields_present: u16,
    /// UTF-16LE bytes; length = `cbClientName` on the wire.
    pub client_name: Vec<u8>,
    /// Statement-of-Health blob; present only when `FIELD_SOH` is set.
    pub statement_of_health: Option<HttpByteBlob>,
}

impl TunnelAuthPdu {
    /// Build a normal (no-SoH) TunnelAuth with the given client name
    /// (UTF-8 `&str`, encoded as UTF-16LE on the wire).
    pub fn new(client_name: &str) -> Self {
        let s = HttpUnicodeString::encode_str(client_name);
        Self {
            fields_present: 0,
            client_name: s.data,
            statement_of_health: None,
        }
    }

    pub fn with_statement_of_health(client_name: &str, soh: HttpByteBlob) -> Self {
        let s = HttpUnicodeString::encode_str(client_name);
        Self {
            fields_present: HTTP_TUNNEL_AUTH_FIELD_SOH,
            client_name: s.data,
            statement_of_health: Some(soh),
        }
    }

    fn optional_size(&self) -> usize {
        let mut n = self.client_name.len();
        if self.fields_present & HTTP_TUNNEL_AUTH_FIELD_SOH != 0 {
            n += self
                .statement_of_health
                .as_ref()
                .map(|b| b.wire_size())
                .unwrap_or(2);
        }
        n
    }
}

impl Encode for TunnelAuthPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.client_name.len() > u16::MAX as usize {
            return Err(EncodeError::invalid_value("TunnelAuth", "cbClientName"));
        }
        HttpPacketHeader::new(PKT_TYPE_TUNNEL_AUTH, self.size() as u32).encode(dst)?;
        dst.write_u16_le(self.fields_present, "TunnelAuth.fieldsPresent")?;
        dst.write_u16_le(
            self.client_name.len() as u16,
            "TunnelAuth.cbClientName",
        )?;
        dst.write_slice(&self.client_name, "TunnelAuth.clientName")?;
        if self.fields_present & HTTP_TUNNEL_AUTH_FIELD_SOH != 0 {
            match &self.statement_of_health {
                Some(b) => b.encode(dst)?,
                None => HttpByteBlob::empty().encode(dst)?,
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TunnelAuthPdu"
    }

    fn size(&self) -> usize {
        TUNNEL_AUTH_FIXED_SIZE + self.optional_size()
    }
}

impl<'de> Decode<'de> for TunnelAuthPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        if hdr.packet_type != PKT_TYPE_TUNNEL_AUTH {
            return Err(DecodeError::invalid_value("TunnelAuth", "packetType"));
        }
        let fields_present = src.read_u16_le("TunnelAuth.fieldsPresent")?;
        let cb_client_name = src.read_u16_le("TunnelAuth.cbClientName")? as usize;
        let client_name = src
            .read_slice(cb_client_name, "TunnelAuth.clientName")?
            .to_vec();
        let statement_of_health = if fields_present & HTTP_TUNNEL_AUTH_FIELD_SOH != 0 {
            Some(HttpByteBlob::decode(src)?)
        } else {
            None
        };
        let pdu = Self {
            fields_present,
            client_name,
            statement_of_health,
        };
        if hdr.packet_length as usize != pdu.size() {
            return Err(DecodeError::invalid_value("TunnelAuth", "packetLength"));
        }
        Ok(pdu)
    }
}

// =============================================================================
// HTTP_TUNNEL_AUTH_RESPONSE_FIELDS_PRESENT_FLAGS (MS-TSGU §2.2.5.3.5)
// =============================================================================

pub const HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS: u16 = 0x0001;
pub const HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT: u16 = 0x0002;
pub const HTTP_TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE: u16 = 0x0004;

// =============================================================================
// HTTP_TUNNEL_REDIR_FLAGS (MS-TSGU §2.2.5.3.7)
// =============================================================================

pub const HTTP_TUNNEL_REDIR_ENABLE_ALL: u32 = 0x8000_0000;
pub const HTTP_TUNNEL_REDIR_DISABLE_ALL: u32 = 0x4000_0000;
pub const HTTP_TUNNEL_REDIR_DISABLE_DRIVE: u32 = 0x0000_0001;
pub const HTTP_TUNNEL_REDIR_DISABLE_PRINTER: u32 = 0x0000_0002;
pub const HTTP_TUNNEL_REDIR_DISABLE_PORT: u32 = 0x0000_0004;
pub const HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD: u32 = 0x0000_0008;
pub const HTTP_TUNNEL_REDIR_DISABLE_PNP: u32 = 0x0000_0010;

// =============================================================================
// HTTP_TUNNEL_AUTH_RESPONSE (MS-TSGU §2.2.10.16, §2.2.10.17)
// =============================================================================

/// Wire size of the fixed portion of `HTTP_TUNNEL_AUTH_RESPONSE`. §2.2.10.16
pub const TUNNEL_AUTH_RESPONSE_FIXED_SIZE: usize = 16;

/// `HTTP_TUNNEL_AUTH_RESPONSE` + `HTTP_TUNNEL_AUTH_RESPONSE_OPTIONAL`
/// (§§2.2.10.16–17).
///
/// `idle_timeout_minutes` unit is **minutes**, not seconds. A value of
/// zero means no idle timeout. `error_code` may be `S_OK` or
/// `E_PROXY_QUARANTINE_ACCESSDENIED` — both indicate the client should
/// continue to channel creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelAuthResponsePdu {
    pub error_code: u32,
    pub fields_present: u16,
    /// `HTTP_TUNNEL_REDIR_FLAGS` bitmask (§2.2.5.3.7). Populated only
    /// when `FIELD_REDIR_FLAGS` is set.
    pub redir_flags: u32,
    /// Idle timeout in **minutes**. 0 = no timeout. Populated only when
    /// `FIELD_IDLE_TIMEOUT` is set.
    pub idle_timeout_minutes: u32,
    /// SoH response blob; populated only when `FIELD_SOH_RESPONSE` set.
    pub soh_response: Option<HttpByteBlob>,
}

impl TunnelAuthResponsePdu {
    /// Success response carrying redirection flags and idle timeout.
    pub fn ok(redir_flags: u32, idle_timeout_minutes: u32) -> Self {
        Self {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS
                | HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT,
            redir_flags,
            idle_timeout_minutes,
            soh_response: None,
        }
    }

    fn optional_size(&self) -> usize {
        let mut n = 0;
        if self.fields_present & HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS != 0 {
            n += 4;
        }
        if self.fields_present & HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT != 0 {
            n += 4;
        }
        if self.fields_present & HTTP_TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE != 0 {
            n += self
                .soh_response
                .as_ref()
                .map(|b| b.wire_size())
                .unwrap_or(2);
        }
        n
    }
}

impl Encode for TunnelAuthResponsePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        HttpPacketHeader::new(PKT_TYPE_TUNNEL_AUTH_RESPONSE, self.size() as u32).encode(dst)?;
        dst.write_u32_le(self.error_code, "TunnelAuthResponse.errorCode")?;
        dst.write_u16_le(self.fields_present, "TunnelAuthResponse.fieldsPresent")?;
        dst.write_u16_le(0, "TunnelAuthResponse.reserved")?;
        if self.fields_present & HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS != 0 {
            dst.write_u32_le(self.redir_flags, "TunnelAuthResponse.redirFlags")?;
        }
        if self.fields_present & HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT != 0 {
            dst.write_u32_le(
                self.idle_timeout_minutes,
                "TunnelAuthResponse.idleTimeout",
            )?;
        }
        if self.fields_present & HTTP_TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE != 0 {
            match &self.soh_response {
                Some(b) => b.encode(dst)?,
                None => HttpByteBlob::empty().encode(dst)?,
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TunnelAuthResponsePdu"
    }

    fn size(&self) -> usize {
        TUNNEL_AUTH_RESPONSE_FIXED_SIZE + self.optional_size()
    }
}

impl<'de> Decode<'de> for TunnelAuthResponsePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        if hdr.packet_type != PKT_TYPE_TUNNEL_AUTH_RESPONSE {
            return Err(DecodeError::invalid_value(
                "TunnelAuthResponse",
                "packetType",
            ));
        }
        let error_code = src.read_u32_le("TunnelAuthResponse.errorCode")?;
        let fields_present = src.read_u16_le("TunnelAuthResponse.fieldsPresent")?;
        let _reserved = src.read_u16_le("TunnelAuthResponse.reserved")?;

        let mut redir_flags = 0u32;
        if fields_present & HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS != 0 {
            redir_flags = src.read_u32_le("TunnelAuthResponse.redirFlags")?;
        }
        let mut idle_timeout_minutes = 0u32;
        if fields_present & HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT != 0 {
            idle_timeout_minutes = src.read_u32_le("TunnelAuthResponse.idleTimeout")?;
        }
        let soh_response = if fields_present & HTTP_TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE != 0 {
            Some(HttpByteBlob::decode(src)?)
        } else {
            None
        };

        let pdu = Self {
            error_code,
            fields_present,
            redir_flags,
            idle_timeout_minutes,
            soh_response,
        };
        if hdr.packet_length as usize != pdu.size() {
            return Err(DecodeError::invalid_value(
                "TunnelAuthResponse",
                "packetLength",
            ));
        }
        Ok(pdu)
    }
}

// =============================================================================
// HTTP_CHANNEL_PACKET (MS-TSGU §2.2.10.2, §2.2.10.3)
// =============================================================================

/// Wire size of the fixed portion of `HTTP_CHANNEL_PACKET`. §2.2.10.2
pub const CHANNEL_CREATE_FIXED_SIZE: usize = 14;

/// Only transport protocol permitted by the spec (TCP). §2.2.10.2
pub const RDG_CHANNEL_PROTOCOL_TCP: u16 = 3;

/// Maximum number of primary resources per `HTTP_CHANNEL_PACKET`. §2.2.10.2
pub const CHANNEL_MAX_RESOURCES: usize = 50;
/// Maximum number of alternate resources per `HTTP_CHANNEL_PACKET`. §2.2.10.2
pub const CHANNEL_MAX_ALT_RESOURCES: usize = 3;

/// `HTTP_CHANNEL_PACKET` + `HTTP_CHANNEL_PACKET_VARIABLE` (§§2.2.10.2–3).
///
/// Client → server channel create. Targets are given as `HTTP_UNICODE_STRING`
/// hostnames; the spec permits 1–50 primary resources and 0–3 alternate
/// resources. `protocol` MUST be `RDG_CHANNEL_PROTOCOL_TCP` (3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelCreatePdu {
    pub resources: Vec<HttpUnicodeString>,
    pub alt_resources: Vec<HttpUnicodeString>,
    pub port: u16,
    pub protocol: u16,
}

impl ChannelCreatePdu {
    pub fn new(hostname: &str, port: u16) -> Self {
        Self {
            resources: alloc::vec![HttpUnicodeString::encode_str(hostname)],
            alt_resources: Vec::new(),
            port,
            protocol: RDG_CHANNEL_PROTOCOL_TCP,
        }
    }

    fn variable_size(&self) -> usize {
        self.resources.iter().map(|r| r.wire_size()).sum::<usize>()
            + self
                .alt_resources
                .iter()
                .map(|r| r.wire_size())
                .sum::<usize>()
    }
}

impl Encode for ChannelCreatePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.resources.is_empty() || self.resources.len() > CHANNEL_MAX_RESOURCES {
            return Err(EncodeError::invalid_value(
                "ChannelCreate",
                "numResources",
            ));
        }
        if self.alt_resources.len() > CHANNEL_MAX_ALT_RESOURCES {
            return Err(EncodeError::invalid_value(
                "ChannelCreate",
                "numAltResources",
            ));
        }
        HttpPacketHeader::new(PKT_TYPE_CHANNEL_CREATE, self.size() as u32).encode(dst)?;
        dst.write_u8(self.resources.len() as u8, "ChannelCreate.numResources")?;
        dst.write_u8(
            self.alt_resources.len() as u8,
            "ChannelCreate.numAltResources",
        )?;
        dst.write_u16_le(self.port, "ChannelCreate.port")?;
        dst.write_u16_le(self.protocol, "ChannelCreate.protocol")?;
        for r in &self.resources {
            r.encode(dst)?;
        }
        for r in &self.alt_resources {
            r.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ChannelCreatePdu"
    }

    fn size(&self) -> usize {
        CHANNEL_CREATE_FIXED_SIZE + self.variable_size()
    }
}

impl<'de> Decode<'de> for ChannelCreatePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        if hdr.packet_type != PKT_TYPE_CHANNEL_CREATE {
            return Err(DecodeError::invalid_value("ChannelCreate", "packetType"));
        }
        let num_resources = src.read_u8("ChannelCreate.numResources")? as usize;
        let num_alt_resources = src.read_u8("ChannelCreate.numAltResources")? as usize;
        let port = src.read_u16_le("ChannelCreate.port")?;
        let protocol = src.read_u16_le("ChannelCreate.protocol")?;
        if num_resources == 0 || num_resources > CHANNEL_MAX_RESOURCES {
            return Err(DecodeError::invalid_value(
                "ChannelCreate",
                "numResources",
            ));
        }
        if num_alt_resources > CHANNEL_MAX_ALT_RESOURCES {
            return Err(DecodeError::invalid_value(
                "ChannelCreate",
                "numAltResources",
            ));
        }
        if protocol != RDG_CHANNEL_PROTOCOL_TCP {
            return Err(DecodeError::invalid_value("ChannelCreate", "protocol"));
        }
        let mut resources = Vec::with_capacity(num_resources);
        for _ in 0..num_resources {
            resources.push(HttpUnicodeString::decode(src)?);
        }
        let mut alt_resources = Vec::with_capacity(num_alt_resources);
        for _ in 0..num_alt_resources {
            alt_resources.push(HttpUnicodeString::decode(src)?);
        }
        let pdu = Self {
            resources,
            alt_resources,
            port,
            protocol,
        };
        if hdr.packet_length as usize != pdu.size() {
            return Err(DecodeError::invalid_value(
                "ChannelCreate",
                "packetLength",
            ));
        }
        Ok(pdu)
    }
}

// =============================================================================
// HTTP_CHANNEL_RESPONSE_FIELDS_PRESENT_FLAGS (MS-TSGU §2.2.5.3.1)
// =============================================================================

pub const HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID: u16 = 0x0001;
pub const HTTP_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE: u16 = 0x0002;
pub const HTTP_CHANNEL_RESPONSE_FIELD_UDPPORT: u16 = 0x0004;

// =============================================================================
// HTTP_CHANNEL_RESPONSE (MS-TSGU §2.2.10.4, §2.2.10.5)
// =============================================================================

/// Wire size of the fixed portion of `HTTP_CHANNEL_RESPONSE`. §2.2.10.4
pub const CHANNEL_RESPONSE_FIXED_SIZE: usize = 16;

/// `HTTP_CHANNEL_RESPONSE` + `HTTP_CHANNEL_RESPONSE_OPTIONAL` (§§2.2.10.4–5).
///
/// Optional fields are serialised in bit-value order per §2.2.10.5:
/// `channelId` (0x0001) → `authnCookie` (0x0002) → `udpPort` (0x0004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelResponsePdu {
    pub error_code: u32,
    pub fields_present: u16,
    /// Populated only when `FIELD_CHANNELID` is set.
    pub channel_id: u32,
    /// Populated only when `FIELD_UDPPORT` is set.
    pub udp_port: u16,
    /// Populated only when `FIELD_AUTHNCOOKIE` is set.
    pub authn_cookie: Option<HttpByteBlob>,
}

impl ChannelResponsePdu {
    /// Success response carrying a channel id.
    pub fn ok(channel_id: u32) -> Self {
        Self {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
            channel_id,
            udp_port: 0,
            authn_cookie: None,
        }
    }

    fn optional_size(&self) -> usize {
        let mut n = 0;
        if self.fields_present & HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID != 0 {
            n += 4;
        }
        if self.fields_present & HTTP_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE != 0 {
            n += self
                .authn_cookie
                .as_ref()
                .map(|b| b.wire_size())
                .unwrap_or(2);
        }
        if self.fields_present & HTTP_CHANNEL_RESPONSE_FIELD_UDPPORT != 0 {
            n += 2;
        }
        n
    }
}

impl Encode for ChannelResponsePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        HttpPacketHeader::new(PKT_TYPE_CHANNEL_RESPONSE, self.size() as u32).encode(dst)?;
        dst.write_u32_le(self.error_code, "ChannelResponse.errorCode")?;
        dst.write_u16_le(self.fields_present, "ChannelResponse.fieldsPresent")?;
        dst.write_u16_le(0, "ChannelResponse.reserved")?;
        if self.fields_present & HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID != 0 {
            dst.write_u32_le(self.channel_id, "ChannelResponse.channelId")?;
        }
        if self.fields_present & HTTP_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE != 0 {
            match &self.authn_cookie {
                Some(b) => b.encode(dst)?,
                None => HttpByteBlob::empty().encode(dst)?,
            }
        }
        if self.fields_present & HTTP_CHANNEL_RESPONSE_FIELD_UDPPORT != 0 {
            dst.write_u16_le(self.udp_port, "ChannelResponse.udpPort")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ChannelResponsePdu"
    }

    fn size(&self) -> usize {
        CHANNEL_RESPONSE_FIXED_SIZE + self.optional_size()
    }
}

impl<'de> Decode<'de> for ChannelResponsePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        if hdr.packet_type != PKT_TYPE_CHANNEL_RESPONSE {
            return Err(DecodeError::invalid_value(
                "ChannelResponse",
                "packetType",
            ));
        }
        let error_code = src.read_u32_le("ChannelResponse.errorCode")?;
        let fields_present = src.read_u16_le("ChannelResponse.fieldsPresent")?;
        let _reserved = src.read_u16_le("ChannelResponse.reserved")?;

        let mut channel_id = 0u32;
        if fields_present & HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID != 0 {
            channel_id = src.read_u32_le("ChannelResponse.channelId")?;
        }
        let authn_cookie = if fields_present & HTTP_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE != 0 {
            Some(HttpByteBlob::decode(src)?)
        } else {
            None
        };
        let mut udp_port = 0u16;
        if fields_present & HTTP_CHANNEL_RESPONSE_FIELD_UDPPORT != 0 {
            udp_port = src.read_u16_le("ChannelResponse.udpPort")?;
        }

        let pdu = Self {
            error_code,
            fields_present,
            channel_id,
            udp_port,
            authn_cookie,
        };
        if hdr.packet_length as usize != pdu.size() {
            return Err(DecodeError::invalid_value(
                "ChannelResponse",
                "packetLength",
            ));
        }
        Ok(pdu)
    }
}

// =============================================================================
// HTTP_DATA_PACKET (MS-TSGU §2.2.10.6)
// =============================================================================

/// Wire size of a zero-payload `HTTP_DATA_PACKET`. §2.2.10.6
pub const DATA_PACKET_MIN_SIZE: usize = 10;

/// `HTTP_DATA_PACKET` (§2.2.10.6).
///
/// Wraps an RDP PDU (X.224 TPDU onward) inside the HTTP Transport
/// tunnel. Maximum payload is `u16::MAX` bytes per packet; larger
/// RDP PDUs must be fragmented by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPdu {
    pub data: Vec<u8>,
}

impl DataPdu {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl Encode for DataPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.data.len() > u16::MAX as usize {
            return Err(EncodeError::invalid_value("Data", "cbDataLen"));
        }
        HttpPacketHeader::new(PKT_TYPE_DATA, self.size() as u32).encode(dst)?;
        dst.write_u16_le(self.data.len() as u16, "Data.cbDataLen")?;
        dst.write_slice(&self.data, "Data.data")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DataPdu"
    }

    fn size(&self) -> usize {
        DATA_PACKET_MIN_SIZE + self.data.len()
    }
}

impl<'de> Decode<'de> for DataPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        if hdr.packet_type != PKT_TYPE_DATA {
            return Err(DecodeError::invalid_value("Data", "packetType"));
        }
        let cb = src.read_u16_le("Data.cbDataLen")? as usize;
        let data = src.read_slice(cb, "Data.data")?.to_vec();
        let pdu = Self { data };
        if hdr.packet_length as usize != pdu.size() {
            return Err(DecodeError::invalid_value("Data", "packetLength"));
        }
        Ok(pdu)
    }
}

// =============================================================================
// HTTP_SERVICE_MESSAGE (MS-TSGU §2.2.10.13)
// =============================================================================

/// Wire size of an empty `HTTP_SERVICE_MESSAGE`. §2.2.10.13
pub const SERVICE_MESSAGE_MIN_SIZE: usize = 10;

/// `HTTP_SERVICE_MESSAGE` (§2.2.10.13).
///
/// Server → client informational text. The spec gives no encoding for
/// `message`; Windows uses UTF-16LE, third-party servers may use UTF-8
/// or Latin-1. Treat as opaque bytes and decode at the display layer.
/// Only sent when `HTTP_CAPABILITY_MESSAGING_SERVICE_MSG` was negotiated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMessagePdu {
    pub message: Vec<u8>,
}

impl ServiceMessagePdu {
    pub fn new(message: Vec<u8>) -> Self {
        Self { message }
    }
}

impl Encode for ServiceMessagePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.message.len() > u16::MAX as usize {
            return Err(EncodeError::invalid_value(
                "ServiceMessage",
                "cbMessageLen",
            ));
        }
        HttpPacketHeader::new(PKT_TYPE_SERVICE_MESSAGE, self.size() as u32).encode(dst)?;
        dst.write_u16_le(self.message.len() as u16, "ServiceMessage.cbMessageLen")?;
        dst.write_slice(&self.message, "ServiceMessage.message")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ServiceMessagePdu"
    }

    fn size(&self) -> usize {
        SERVICE_MESSAGE_MIN_SIZE + self.message.len()
    }
}

impl<'de> Decode<'de> for ServiceMessagePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = HttpPacketHeader::decode(src)?;
        if hdr.packet_type != PKT_TYPE_SERVICE_MESSAGE {
            return Err(DecodeError::invalid_value("ServiceMessage", "packetType"));
        }
        let cb = src.read_u16_le("ServiceMessage.cbMessageLen")? as usize;
        let message = src.read_slice(cb, "ServiceMessage.message")?.to_vec();
        let pdu = Self { message };
        if hdr.packet_length as usize != pdu.size() {
            return Err(DecodeError::invalid_value(
                "ServiceMessage",
                "packetLength",
            ));
        }
        Ok(pdu)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn encode_vec<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        assert_eq!(cur.pos(), pdu.size(), "size() must match encode() output");
        buf
    }

    // ---------- HttpPacketHeader ----------

    #[test]
    fn packet_header_roundtrip() {
        let hdr = HttpPacketHeader::new(PKT_TYPE_KEEPALIVE, 8);
        let bytes = encode_vec(&hdr);
        assert_eq!(bytes, [0x0D, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00]);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = HttpPacketHeader::decode(&mut cur).unwrap();
        assert_eq!(decoded, hdr);
        assert_eq!(cur.pos(), PACKET_HEADER_SIZE);
    }

    #[test]
    fn packet_header_rejects_short_length() {
        // packetLength = 7 < 8 (header itself) → malformed.
        let bytes = [0x0D, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00];
        let mut cur = ReadCursor::new(&bytes);
        assert!(HttpPacketHeader::decode(&mut cur).is_err());
    }

    #[test]
    fn packet_header_accepts_nonzero_reserved_on_decode() {
        // Forward-compat: reserved bytes are ignored on the wire.
        let bytes = [0x0D, 0x00, 0xFF, 0xFF, 0x08, 0x00, 0x00, 0x00];
        let mut cur = ReadCursor::new(&bytes);
        let hdr = HttpPacketHeader::decode(&mut cur).unwrap();
        assert_eq!(hdr.packet_type, PKT_TYPE_KEEPALIVE);
        assert_eq!(hdr.packet_length, 8);
    }

    #[test]
    fn packet_header_encode_forces_reserved_zero() {
        // Even if the struct holds a non-zero reserved, encode must emit 0.
        let hdr = HttpPacketHeader {
            packet_type: PKT_TYPE_KEEPALIVE,
            reserved: 0xCAFE,
            packet_length: 8,
        };
        let bytes = encode_vec(&hdr);
        assert_eq!(&bytes[2..4], &[0x00, 0x00]);
    }

    // ---------- HttpUnicodeString ----------

    #[test]
    fn unicode_string_cblen_is_bytes_not_chars() {
        // "RDG-Client1" — 11 ASCII chars → 22 UTF-16LE bytes per §6/MS-TSGU interop
        let s = HttpUnicodeString::encode_str("RDG-Client1");
        assert_eq!(s.cb_len(), 22);
        assert_eq!(s.wire_size(), 24);
        let bytes = encode_vec(&s);
        assert_eq!(&bytes[0..2], &[22, 0]);
        // 'R' = 0x52 LE, 'D' = 0x44 LE
        assert_eq!(&bytes[2..6], &[0x52, 0x00, 0x44, 0x00]);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = HttpUnicodeString::decode(&mut cur).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn unicode_string_empty_roundtrip() {
        let s = HttpUnicodeString::empty();
        let bytes = encode_vec(&s);
        assert_eq!(bytes, [0, 0]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(HttpUnicodeString::decode(&mut cur).unwrap(), s);
    }

    #[test]
    fn unicode_string_non_ascii() {
        // U+00E9 "é" → 0xE9 0x00; U+1F600 (surrogate pair) → 0x3D D8 00 DE
        let s = HttpUnicodeString::encode_str("é");
        assert_eq!(s.cb_len(), 2);
        assert_eq!(s.data, [0xE9, 0x00]);
        let s2 = HttpUnicodeString::encode_str("\u{1F600}");
        assert_eq!(s2.cb_len(), 4);
        assert_eq!(s2.data, [0x3D, 0xD8, 0x00, 0xDE]);
    }

    // ---------- HttpByteBlob ----------

    #[test]
    fn byte_blob_roundtrip() {
        let b = HttpByteBlob::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let bytes = encode_vec(&b);
        assert_eq!(bytes, [4, 0, 0xDE, 0xAD, 0xBE, 0xEF]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(HttpByteBlob::decode(&mut cur).unwrap(), b);
    }

    #[test]
    fn byte_blob_empty_roundtrip() {
        let b = HttpByteBlob::empty();
        let bytes = encode_vec(&b);
        assert_eq!(bytes, [0, 0]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(HttpByteBlob::decode(&mut cur).unwrap(), b);
    }

    // ---------- HandshakeRequestPdu ----------

    #[test]
    fn handshake_request_roundtrip() {
        let pdu = HandshakeRequestPdu::new(HTTP_EXTENDED_AUTH_NONE);
        let bytes = encode_vec(&pdu);
        assert_eq!(bytes.len(), HANDSHAKE_REQUEST_SIZE);
        // packetType LE
        assert_eq!(&bytes[0..2], &[0x01, 0x00]);
        // packetLength LE = 14
        assert_eq!(&bytes[4..8], &[0x0E, 0x00, 0x00, 0x00]);
        // verMajor=1, verMinor=0, clientVersion=0, extendedAuth=0
        assert_eq!(&bytes[8..], &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(HandshakeRequestPdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn handshake_request_with_extended_auth() {
        let pdu = HandshakeRequestPdu::new(HTTP_EXTENDED_AUTH_PAA);
        let bytes = encode_vec(&pdu);
        assert_eq!(&bytes[12..14], &[0x02, 0x00]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(HandshakeRequestPdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn handshake_request_rejects_wrong_type() {
        // Flip packetType to keepalive.
        let mut bytes = encode_vec(&HandshakeRequestPdu::new(HTTP_EXTENDED_AUTH_NONE));
        bytes[0] = PKT_TYPE_KEEPALIVE as u8;
        let mut cur = ReadCursor::new(&bytes);
        assert!(HandshakeRequestPdu::decode(&mut cur).is_err());
    }

    #[test]
    fn handshake_request_rejects_wrong_length() {
        let mut bytes = encode_vec(&HandshakeRequestPdu::new(HTTP_EXTENDED_AUTH_NONE));
        bytes[4] = 0x10; // 16 instead of 14
        let mut cur = ReadCursor::new(&bytes);
        assert!(HandshakeRequestPdu::decode(&mut cur).is_err());
    }

    // ---------- HandshakeResponsePdu ----------

    #[test]
    fn handshake_response_roundtrip() {
        let pdu = HandshakeResponsePdu::ok(HTTP_EXTENDED_AUTH_PAA);
        let bytes = encode_vec(&pdu);
        assert_eq!(bytes.len(), HANDSHAKE_RESPONSE_SIZE);
        assert_eq!(&bytes[0..2], &[0x02, 0x00]);
        assert_eq!(&bytes[4..8], &[0x12, 0x00, 0x00, 0x00]); // 18
        assert_eq!(&bytes[8..12], &[0, 0, 0, 0]); // errorCode = 0
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(HandshakeResponsePdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn handshake_response_preserves_error_code() {
        let pdu = HandshakeResponsePdu {
            error_code: 0x8007_59D8,
            ver_major: 1,
            ver_minor: 0,
            server_version: 0,
            extended_auth: 0,
        };
        let bytes = encode_vec(&pdu);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(HandshakeResponsePdu::decode(&mut cur).unwrap(), pdu);
    }

    // ---------- KeepalivePdu ----------

    #[test]
    fn keepalive_roundtrip() {
        let pdu = KeepalivePdu;
        let bytes = encode_vec(&pdu);
        assert_eq!(bytes, [0x0D, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(KeepalivePdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn keepalive_rejects_wrong_length() {
        let bytes = [0x0D, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00];
        let mut cur = ReadCursor::new(&bytes);
        assert!(KeepalivePdu::decode(&mut cur).is_err());
    }

    // ---------- ReauthMessagePdu ----------

    #[test]
    fn reauth_message_roundtrip() {
        let pdu = ReauthMessagePdu::new(0x1122_3344_5566_7788);
        let bytes = encode_vec(&pdu);
        assert_eq!(bytes.len(), REAUTH_MESSAGE_SIZE);
        assert_eq!(&bytes[0..2], &[0x0C, 0x00]);
        assert_eq!(&bytes[4..8], &[0x10, 0x00, 0x00, 0x00]); // 16
        assert_eq!(
            &bytes[8..16],
            &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(ReauthMessagePdu::decode(&mut cur).unwrap(), pdu);
    }

    // ---------- CloseChannelPdu ----------

    #[test]
    fn close_channel_request_roundtrip() {
        let pdu = CloseChannelPdu::request(ERROR_GRACEFUL_DISCONNECT);
        let bytes = encode_vec(&pdu);
        assert_eq!(bytes.len(), CLOSE_CHANNEL_SIZE);
        assert_eq!(&bytes[0..2], &[0x10, 0x00]);
        assert_eq!(&bytes[4..8], &[0x0C, 0x00, 0x00, 0x00]); // 12
        // HRESULT_FROM_WIN32(ERROR_GRACEFUL_DISCONNECT) = 0x8007_04CA, LE on wire.
        assert_eq!(&bytes[8..12], &[0xCA, 0x04, 0x07, 0x80]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(CloseChannelPdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn close_channel_response_roundtrip() {
        let pdu = CloseChannelPdu::response(STATUS_SUCCESS);
        let bytes = encode_vec(&pdu);
        assert_eq!(&bytes[0..2], &[0x11, 0x00]);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = CloseChannelPdu::decode(&mut cur).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(decoded.kind, CloseChannelKind::Response);
    }

    #[test]
    fn close_channel_rejects_unknown_type() {
        let bytes = [0x0F, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0, 0, 0, 0];
        let mut cur = ReadCursor::new(&bytes);
        assert!(CloseChannelPdu::decode(&mut cur).is_err());
    }

    // ---------- TunnelCreatePdu ----------

    #[test]
    fn tunnel_create_normal_roundtrip() {
        let pdu = TunnelCreatePdu::normal(
            HTTP_CAPABILITY_TYPE_QUAR_SOH
                | HTTP_CAPABILITY_IDLE_TIMEOUT
                | HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN
                | HTTP_CAPABILITY_MESSAGING_SERVICE_MSG
                | HTTP_CAPABILITY_REAUTH
                | HTTP_CAPABILITY_UDP_TRANSPORT,
        );
        assert_eq!(pdu.size(), TUNNEL_CREATE_FIXED_SIZE);
        let bytes = encode_vec(&pdu);
        // packetType = 4
        assert_eq!(&bytes[0..2], &[0x04, 0x00]);
        // packetLength = 16
        assert_eq!(&bytes[4..8], &[0x10, 0x00, 0x00, 0x00]);
        // capsFlags = 0x3F
        assert_eq!(&bytes[8..12], &[0x3F, 0x00, 0x00, 0x00]);
        // fieldsPresent = 0, reserved = 0
        assert_eq!(&bytes[12..16], &[0, 0, 0, 0]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(TunnelCreatePdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn tunnel_create_with_paa_cookie_roundtrip() {
        let cookie = HttpByteBlob::new(vec![1, 2, 3, 4, 5]);
        let pdu = TunnelCreatePdu::with_paa_cookie(HTTP_CAPABILITY_REAUTH, cookie.clone());
        // 16 fixed + 8 reauthCtx + 2+5 cookie = 31
        assert_eq!(pdu.size(), 16 + 8 + 2 + 5);
        let bytes = encode_vec(&pdu);
        // fieldsPresent = 0x0001
        assert_eq!(&bytes[12..14], &[0x01, 0x00]);
        // reauthTunnelContext = 0 (still present even though FIELD_REAUTH not set)
        assert_eq!(&bytes[16..24], &[0, 0, 0, 0, 0, 0, 0, 0]);
        // cookie cbLen=5, bytes 1..5
        assert_eq!(&bytes[24..26], &[5, 0]);
        assert_eq!(&bytes[26..31], &[1, 2, 3, 4, 5]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(TunnelCreatePdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn tunnel_create_with_reauth_roundtrip() {
        let pdu = TunnelCreatePdu::with_reauth(0, 0xAABB_CCDD_EEFF_0011);
        assert_eq!(pdu.size(), 16 + 8);
        let bytes = encode_vec(&pdu);
        // fieldsPresent = 0x0002
        assert_eq!(&bytes[12..14], &[0x02, 0x00]);
        // reauthTunnelContext LE
        assert_eq!(
            &bytes[16..24],
            &[0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]
        );
        let mut cur = ReadCursor::new(&bytes);
        let decoded = TunnelCreatePdu::decode(&mut cur).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(decoded.reauth_tunnel_context, 0xAABB_CCDD_EEFF_0011);
    }

    #[test]
    fn tunnel_create_both_flags() {
        let mut pdu = TunnelCreatePdu::with_paa_cookie(
            HTTP_CAPABILITY_REAUTH,
            HttpByteBlob::new(vec![0xAA; 3]),
        );
        pdu.fields_present |= HTTP_TUNNEL_PACKET_FIELD_REAUTH;
        pdu.reauth_tunnel_context = 0x1234_5678_9ABC_DEF0;
        let bytes = encode_vec(&pdu);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(TunnelCreatePdu::decode(&mut cur).unwrap(), pdu);
    }

    // ---------- TunnelResponsePdu ----------

    #[test]
    fn tunnel_response_ok_roundtrip() {
        let pdu = TunnelResponsePdu::ok(0x0001, 0x1122_3344, 0x3F);
        // 18 + 4 + 4 = 26
        assert_eq!(pdu.size(), 18 + 4 + 4);
        let bytes = encode_vec(&pdu);
        assert_eq!(&bytes[0..2], &[0x05, 0x00]);
        assert_eq!(&bytes[4..8], &[0x1A, 0x00, 0x00, 0x00]); // 26
        // serverVersion
        assert_eq!(&bytes[8..10], &[0x01, 0x00]);
        // statusCode = 0
        assert_eq!(&bytes[10..14], &[0, 0, 0, 0]);
        // fieldsPresent = 0x0003 (TUNNEL_ID|CAPS)
        assert_eq!(&bytes[14..16], &[0x03, 0x00]);
        // tunnelId LE
        assert_eq!(&bytes[18..22], &[0x44, 0x33, 0x22, 0x11]);
        // capsFlags
        assert_eq!(&bytes[22..26], &[0x3F, 0, 0, 0]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(TunnelResponsePdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn tunnel_response_empty_optional_roundtrip() {
        let pdu = TunnelResponsePdu {
            server_version: 0,
            status_code: 0,
            fields_present: 0,
            tunnel_id: 0,
            caps_flags: 0,
            nonce: [0; 16],
            server_cert: HttpUnicodeString::empty(),
            consent_msg: HttpUnicodeString::empty(),
        };
        assert_eq!(pdu.size(), TUNNEL_RESPONSE_FIXED_SIZE);
        let bytes = encode_vec(&pdu);
        assert_eq!(bytes.len(), 18);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(TunnelResponsePdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn tunnel_response_all_optional_fields() {
        let pdu = TunnelResponsePdu {
            server_version: 5,
            status_code: 0,
            fields_present: HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID
                | HTTP_TUNNEL_RESPONSE_FIELD_CAPS
                | HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ
                | HTTP_TUNNEL_RESPONSE_FIELD_CONSENT_MSG,
            tunnel_id: 0xDEAD_BEEF,
            caps_flags: 0x3F,
            nonce: [0x11; 16],
            server_cert: HttpUnicodeString::encode_str("cert"),
            consent_msg: HttpUnicodeString::encode_str("policy"),
        };
        let bytes = encode_vec(&pdu);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = TunnelResponsePdu::decode(&mut cur).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn tunnel_response_consent_msg_bit_is_0x0010_not_0x0008() {
        let pdu = TunnelResponsePdu {
            server_version: 0,
            status_code: 0,
            fields_present: HTTP_TUNNEL_RESPONSE_FIELD_CONSENT_MSG,
            tunnel_id: 0,
            caps_flags: 0,
            nonce: [0; 16],
            server_cert: HttpUnicodeString::empty(),
            consent_msg: HttpUnicodeString::encode_str("ok"),
        };
        let bytes = encode_vec(&pdu);
        // fieldsPresent LE must be 0x10 0x00
        assert_eq!(&bytes[14..16], &[0x10, 0x00]);
    }

    // ---------- TunnelAuthPdu ----------

    #[test]
    fn tunnel_auth_normal_roundtrip() {
        let pdu = TunnelAuthPdu::new("RDG-Client1");
        // 12 fixed + 22 bytes client name = 34
        assert_eq!(pdu.size(), 12 + 22);
        let bytes = encode_vec(&pdu);
        assert_eq!(&bytes[0..2], &[0x06, 0x00]);
        assert_eq!(&bytes[4..8], &[0x22, 0x00, 0x00, 0x00]); // 34
        // fieldsPresent = 0
        assert_eq!(&bytes[8..10], &[0, 0]);
        // cbClientName = 22
        assert_eq!(&bytes[10..12], &[22, 0]);
        // First two UTF-16LE chars
        assert_eq!(&bytes[12..16], &[0x52, 0x00, 0x44, 0x00]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(TunnelAuthPdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn tunnel_auth_with_soh_roundtrip() {
        let pdu = TunnelAuthPdu::with_statement_of_health(
            "host",
            HttpByteBlob::new(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        );
        // 12 + 8 (host UTF-16LE) + 2 + 4 (SoH blob) = 26
        assert_eq!(pdu.size(), 12 + 8 + 2 + 4);
        let bytes = encode_vec(&pdu);
        assert_eq!(&bytes[8..10], &[0x01, 0x00]); // FIELD_SOH
        assert_eq!(&bytes[10..12], &[0x08, 0x00]); // cbClientName = 8
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(TunnelAuthPdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn tunnel_auth_empty_client_name() {
        let pdu = TunnelAuthPdu::new("");
        assert_eq!(pdu.size(), 12);
        let bytes = encode_vec(&pdu);
        assert_eq!(&bytes[10..12], &[0, 0]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(TunnelAuthPdu::decode(&mut cur).unwrap(), pdu);
    }

    // ---------- TunnelAuthResponsePdu ----------

    #[test]
    fn tunnel_auth_response_ok_roundtrip() {
        let pdu = TunnelAuthResponsePdu::ok(HTTP_TUNNEL_REDIR_DISABLE_ALL, 30);
        assert_eq!(pdu.size(), 16 + 4 + 4);
        let bytes = encode_vec(&pdu);
        assert_eq!(&bytes[0..2], &[0x07, 0x00]);
        assert_eq!(&bytes[4..8], &[0x18, 0x00, 0x00, 0x00]); // 24
        assert_eq!(&bytes[12..14], &[0x03, 0x00]); // fieldsPresent
        // redirFlags = 0x4000_0000 LE
        assert_eq!(&bytes[16..20], &[0x00, 0x00, 0x00, 0x40]);
        // idleTimeout = 30
        assert_eq!(&bytes[20..24], &[30, 0, 0, 0]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(TunnelAuthResponsePdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn tunnel_auth_response_empty_optional() {
        let pdu = TunnelAuthResponsePdu {
            error_code: STATUS_SUCCESS,
            fields_present: 0,
            redir_flags: 0,
            idle_timeout_minutes: 0,
            soh_response: None,
        };
        assert_eq!(pdu.size(), 16);
        let bytes = encode_vec(&pdu);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(TunnelAuthResponsePdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn tunnel_auth_response_with_soh() {
        let pdu = TunnelAuthResponsePdu {
            error_code: E_PROXY_QUARANTINE_ACCESSDENIED,
            fields_present: HTTP_TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE,
            redir_flags: 0,
            idle_timeout_minutes: 0,
            soh_response: Some(HttpByteBlob::new(vec![0xAB, 0xCD])),
        };
        let bytes = encode_vec(&pdu);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(TunnelAuthResponsePdu::decode(&mut cur).unwrap(), pdu);
    }

    // ---------- ChannelCreatePdu ----------

    #[test]
    fn channel_create_single_resource_roundtrip() {
        let pdu = ChannelCreatePdu::new("target.example.com", 3389);
        // 14 fixed + 2+36 (18 chars UTF-16LE)
        assert_eq!(pdu.size(), 14 + 2 + 36);
        let bytes = encode_vec(&pdu);
        assert_eq!(&bytes[0..2], &[0x08, 0x00]);
        // numResources=1, numAltResources=0
        assert_eq!(bytes[8], 1);
        assert_eq!(bytes[9], 0);
        // port = 3389 = 0x0D3D LE
        assert_eq!(&bytes[10..12], &[0x3D, 0x0D]);
        // protocol = 3
        assert_eq!(&bytes[12..14], &[0x03, 0x00]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(ChannelCreatePdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn channel_create_with_alt_resources() {
        let pdu = ChannelCreatePdu {
            resources: alloc::vec![HttpUnicodeString::encode_str("primary")],
            alt_resources: alloc::vec![
                HttpUnicodeString::encode_str("alt1"),
                HttpUnicodeString::encode_str("alt2"),
            ],
            port: 3389,
            protocol: RDG_CHANNEL_PROTOCOL_TCP,
        };
        let bytes = encode_vec(&pdu);
        assert_eq!(bytes[8], 1);
        assert_eq!(bytes[9], 2);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(ChannelCreatePdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn channel_create_rejects_wrong_protocol() {
        let mut bytes = encode_vec(&ChannelCreatePdu::new("h", 3389));
        bytes[12] = 0x04; // force protocol != 3
        let mut cur = ReadCursor::new(&bytes);
        assert!(ChannelCreatePdu::decode(&mut cur).is_err());
    }

    #[test]
    fn channel_create_rejects_zero_resources() {
        let pdu = ChannelCreatePdu {
            resources: Vec::new(),
            alt_resources: Vec::new(),
            port: 3389,
            protocol: RDG_CHANNEL_PROTOCOL_TCP,
        };
        let mut buf = vec![0u8; pdu.size() + 10];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(pdu.encode(&mut cur).is_err());
    }

    // ---------- ChannelResponsePdu ----------

    #[test]
    fn channel_response_ok_roundtrip() {
        let pdu = ChannelResponsePdu::ok(0x1234_5678);
        assert_eq!(pdu.size(), 16 + 4);
        let bytes = encode_vec(&pdu);
        assert_eq!(&bytes[0..2], &[0x09, 0x00]);
        assert_eq!(&bytes[12..14], &[0x01, 0x00]); // fieldsPresent = CHANNELID
        assert_eq!(&bytes[16..20], &[0x78, 0x56, 0x34, 0x12]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(ChannelResponsePdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn channel_response_with_udp_side_channel() {
        let pdu = ChannelResponsePdu {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID
                | HTTP_CHANNEL_RESPONSE_FIELD_UDPPORT
                | HTTP_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE,
            channel_id: 42,
            udp_port: 3391,
            authn_cookie: Some(HttpByteBlob::new(vec![0xAA, 0xBB, 0xCC])),
        };
        // 16 + 4 + 2 + (2+3) = 27
        assert_eq!(pdu.size(), 16 + 4 + 2 + 5);
        let bytes = encode_vec(&pdu);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(ChannelResponsePdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn channel_response_empty_optional() {
        let pdu = ChannelResponsePdu {
            error_code: 0x8007_59DA,
            fields_present: 0,
            channel_id: 0,
            udp_port: 0,
            authn_cookie: None,
        };
        assert_eq!(pdu.size(), 16);
        let bytes = encode_vec(&pdu);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(ChannelResponsePdu::decode(&mut cur).unwrap(), pdu);
    }

    // ---------- DataPdu ----------

    #[test]
    fn data_pdu_roundtrip() {
        let pdu = DataPdu::new(vec![0x03, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80]);
        assert_eq!(pdu.size(), 10 + 7);
        let bytes = encode_vec(&pdu);
        assert_eq!(&bytes[0..2], &[0x0A, 0x00]);
        assert_eq!(&bytes[4..8], &[0x11, 0x00, 0x00, 0x00]); // 17
        assert_eq!(&bytes[8..10], &[0x07, 0x00]);
        assert_eq!(&bytes[10..], &[0x03, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(DataPdu::decode(&mut cur).unwrap(), pdu);
    }

    #[test]
    fn data_pdu_zero_payload_is_valid() {
        let pdu = DataPdu::new(Vec::new());
        assert_eq!(pdu.size(), 10);
        let bytes = encode_vec(&pdu);
        assert_eq!(bytes.len(), 10);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(DataPdu::decode(&mut cur).unwrap(), pdu);
    }

    // ---------- ServiceMessagePdu ----------

    #[test]
    fn service_message_roundtrip() {
        let utf16 = HttpUnicodeString::encode_str("hello");
        let pdu = ServiceMessagePdu::new(utf16.data.clone());
        assert_eq!(pdu.size(), 10 + 10);
        let bytes = encode_vec(&pdu);
        assert_eq!(&bytes[0..2], &[0x0B, 0x00]);
        assert_eq!(&bytes[8..10], &[0x0A, 0x00]);
        let mut cur = ReadCursor::new(&bytes);
        assert_eq!(ServiceMessagePdu::decode(&mut cur).unwrap(), pdu);
    }
}
