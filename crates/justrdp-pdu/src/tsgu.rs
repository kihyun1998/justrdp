//! RD Gateway HTTP transport packets (MS-TSGU 2.2.10): the binary packets an RDG client and
//! server exchange inside the HTTP or WebSocket body once the channels are open. Each packet
//! starts with an `HTTP_PACKET_HEADER` whose `packetLength` covers the whole packet.
//!
//! [`Packet::decode`] reads one packet from the front of a buffer and [`Packet::encode`] writes
//! one. Extended auth (2.2.10.7), reauth (2.2.10.12) and service messages (2.2.10.13) decode as
//! [`Packet::Other`] with their body unparsed.

use crate::cursor::{ReadCursor, utf16_string};
use crate::error::DecodeError;

/// `PKT_TYPE_HANDSHAKE_REQUEST` (2.2.5.3.3).
pub const PKT_TYPE_HANDSHAKE_REQUEST: u16 = 0x1;
/// `PKT_TYPE_HANDSHAKE_RESPONSE`.
pub const PKT_TYPE_HANDSHAKE_RESPONSE: u16 = 0x2;
/// `PKT_TYPE_EXTENDED_AUTH_MSG`.
pub const PKT_TYPE_EXTENDED_AUTH_MSG: u16 = 0x3;
/// `PKT_TYPE_TUNNEL_CREATE`.
pub const PKT_TYPE_TUNNEL_CREATE: u16 = 0x4;
/// `PKT_TYPE_TUNNEL_RESPONSE`.
pub const PKT_TYPE_TUNNEL_RESPONSE: u16 = 0x5;
/// `PKT_TYPE_TUNNEL_AUTH`.
pub const PKT_TYPE_TUNNEL_AUTH: u16 = 0x6;
/// `PKT_TYPE_TUNNEL_AUTH_RESPONSE`.
pub const PKT_TYPE_TUNNEL_AUTH_RESPONSE: u16 = 0x7;
/// `PKT_TYPE_CHANNEL_CREATE`.
pub const PKT_TYPE_CHANNEL_CREATE: u16 = 0x8;
/// `PKT_TYPE_CHANNEL_RESPONSE`.
pub const PKT_TYPE_CHANNEL_RESPONSE: u16 = 0x9;
/// `PKT_TYPE_DATA`.
pub const PKT_TYPE_DATA: u16 = 0xA;
/// `PKT_TYPE_SERVICE_MESSAGE`.
pub const PKT_TYPE_SERVICE_MESSAGE: u16 = 0xB;
/// `PKT_TYPE_REAUTH_MESSAGE`.
pub const PKT_TYPE_REAUTH_MESSAGE: u16 = 0xC;
/// `PKT_TYPE_KEEPALIVE`.
pub const PKT_TYPE_KEEPALIVE: u16 = 0xD;
/// `PKT_TYPE_CLOSE_CHANNEL`.
pub const PKT_TYPE_CLOSE_CHANNEL: u16 = 0x10;
/// `PKT_TYPE_CLOSE_CHANNEL_RESPONSE`.
pub const PKT_TYPE_CLOSE_CHANNEL_RESPONSE: u16 = 0x11;

/// `HTTP_EXTENDED_AUTH_NONE` (2.2.5.3.2).
pub const HTTP_EXTENDED_AUTH_NONE: u16 = 0x00;
/// `HTTP_EXTENDED_AUTH_SC`: smart card authentication.
pub const HTTP_EXTENDED_AUTH_SC: u16 = 0x01;
/// `HTTP_EXTENDED_AUTH_PAA`: pluggable authentication.
pub const HTTP_EXTENDED_AUTH_PAA: u16 = 0x02;
/// `HTTP_EXTENDED_AUTH_SSPI_NTLM`: NTLM through the extended authentication sequence.
pub const HTTP_EXTENDED_AUTH_SSPI_NTLM: u16 = 0x04;

/// `HTTP_CAPABILITY_TYPE_QUAR_SOH` (2.2.5.3.9).
pub const HTTP_CAPABILITY_TYPE_QUAR_SOH: u32 = 0x1;
/// `HTTP_CAPABILITY_IDLE_TIMEOUT`.
pub const HTTP_CAPABILITY_IDLE_TIMEOUT: u32 = 0x2;
/// `HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN`.
pub const HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN: u32 = 0x4;
/// `HTTP_CAPABILITY_MESSAGING_SERVICE_MSG`.
pub const HTTP_CAPABILITY_MESSAGING_SERVICE_MSG: u32 = 0x8;
/// `HTTP_CAPABILITY_REAUTH`.
pub const HTTP_CAPABILITY_REAUTH: u32 = 0x10;
/// `HTTP_CAPABILITY_UDP_TRANSPORT`.
pub const HTTP_CAPABILITY_UDP_TRANSPORT: u32 = 0x20;

/// `HTTP_TUNNEL_REDIR_ENABLE_ALL` (2.2.5.3.7).
pub const HTTP_TUNNEL_REDIR_ENABLE_ALL: u32 = 0x8000_0000;
/// `HTTP_TUNNEL_REDIR_DISABLE_ALL`.
pub const HTTP_TUNNEL_REDIR_DISABLE_ALL: u32 = 0x4000_0000;
/// `HTTP_TUNNEL_REDIR_DISABLE_DRIVE`.
pub const HTTP_TUNNEL_REDIR_DISABLE_DRIVE: u32 = 0x1;
/// `HTTP_TUNNEL_REDIR_DISABLE_PRINTER`.
pub const HTTP_TUNNEL_REDIR_DISABLE_PRINTER: u32 = 0x2;
/// `HTTP_TUNNEL_REDIR_DISABLE_PORT`.
pub const HTTP_TUNNEL_REDIR_DISABLE_PORT: u32 = 0x4;
/// `HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD`.
pub const HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD: u32 = 0x8;
/// `HTTP_TUNNEL_REDIR_DISABLE_PNP`.
pub const HTTP_TUNNEL_REDIR_DISABLE_PNP: u32 = 0x10;

/// `HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE` (2.2.5.3.6).
const TUNNEL_FIELD_PAA_COOKIE: u16 = 0x1;
/// `HTTP_TUNNEL_PACKET_FIELD_REAUTH` (2.2.5.3.6).
const TUNNEL_FIELD_REAUTH: u16 = 0x2;
/// `HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID` (2.2.5.3.8).
const TUNNEL_RESPONSE_FIELD_TUNNEL_ID: u16 = 0x1;
/// `HTTP_TUNNEL_RESPONSE_FIELD_CAPS`.
const TUNNEL_RESPONSE_FIELD_CAPS: u16 = 0x2;
/// `HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ`: the nonce and serverCert fields.
const TUNNEL_RESPONSE_FIELD_SOH_REQ: u16 = 0x4;
/// `HTTP_TUNNEL_RESPONSE_FIELD_CONSENT_MSG`.
const TUNNEL_RESPONSE_FIELD_CONSENT_MSG: u16 = 0x10;
/// `HTTP_TUNNEL_AUTH_FIELD_SOH` (2.2.5.3.4).
const TUNNEL_AUTH_FIELD_SOH: u16 = 0x1;
/// `HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS` (2.2.5.3.5).
const TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS: u16 = 0x1;
/// `HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT`.
const TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT: u16 = 0x2;
/// `HTTP_TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE`.
const TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE: u16 = 0x4;
/// `HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID` (2.2.5.3.1).
const CHANNEL_RESPONSE_FIELD_CHANNELID: u16 = 0x1;
/// `HTTP_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE`.
const CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE: u16 = 0x2;
/// `HTTP_CHANNEL_RESPONSE_FIELD_UDPPORT`.
const CHANNEL_RESPONSE_FIELD_UDPPORT: u16 = 0x4;

/// The size of `HTTP_PACKET_HEADER` (2.2.10.9).
pub const HEADER_LEN: usize = 8;

/// `HTTP_PACKET_HEADER` (2.2.10.9). `packetLength` counts the header and the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    /// `packetType`, one of the `PKT_TYPE_*` constants.
    pub packet_type: u16,
    /// `packetLength`: the whole packet, header included.
    pub packet_length: u32,
}

impl PacketHeader {
    /// Decode the header at the front of `buf`, which is enough to know how long the packet is.
    /// `NotEnoughBytes` while fewer than [`HEADER_LEN`] bytes are present; `InvalidField` when
    /// `packetLength` does not cover the header.
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(buf, "HTTP_PACKET_HEADER");
        let packet_type = cur.read_u16_le()?;
        let _reserved = cur.read_u16_le()?;
        let packet_length = cur.read_u32_le()?;
        if packet_length < HEADER_LEN as u32 {
            return Err(DecodeError::InvalidField {
                field: "HTTP_PACKET_HEADER.packetLength",
                reason: "shorter than the 8-byte header",
            });
        }
        Ok(Self {
            packet_type,
            packet_length,
        })
    }
}

/// A packet that cannot be encoded because a field is longer than its length prefix admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// `field` holds `len` units and its length prefix admits at most `max`.
    TooLong {
        /// The field whose length prefix overflows.
        field: &'static str,
        /// The field's length.
        len: usize,
        /// The largest length the prefix admits.
        max: usize,
    },
    /// [`Packet::Other`] was given a `packetType` this module decodes into its own variant.
    ParsedType {
        /// The `packetType`.
        packet_type: u16,
    },
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EncodeError::TooLong { field, len, max } => {
                write!(
                    f,
                    "{field} is {len} long, and its length prefix admits {max}"
                )
            }
            EncodeError::ParsedType { packet_type } => write!(
                f,
                "packet type {packet_type:#x} has its own variant and cannot be sent as Other"
            ),
        }
    }
}

impl core::error::Error for EncodeError {}

/// `HTTP_UNICODE_STRING` (2.2.10.22): the `str` bytes behind a `u16` `cbLen`, kept as sent.
/// The senders write UTF-16LE, and a terminating NUL is part of the bytes when the sender wrote
/// one.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UnicodeString(Vec<u8>);

impl UnicodeString {
    /// `s` as UTF-16LE followed by a NUL unit.
    pub fn from_str_nul(s: &str) -> Self {
        Self(utf16le_nul(s))
    }

    /// The string's bytes exactly as given.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes as they travel in `str`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The text up to the first NUL unit, with an unpaired surrogate as U+FFFD and a trailing
    /// odd byte dropped.
    pub fn to_string_lossy(&self) -> String {
        utf16_string(&self.0)
    }
}

impl core::fmt::Debug for UnicodeString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "UnicodeString({:?})", self.to_string_lossy())
    }
}

/// The `PAACookie` of `HTTP_TUNNEL_PACKET_OPTIONAL` (2.2.10.19): the contents of its
/// `HTTP_byte_BLOB`. Its `Debug` prints the length and never the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct PaaCookie(Vec<u8>);

impl PaaCookie {
    /// `token` as UTF-16LE followed by a NUL unit, the layout `mstsc.exe` sends.
    pub fn from_token(token: &str) -> Self {
        Self(utf16le_nul(token))
    }

    /// The blob exactly as given.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes as they travel in the blob.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for PaaCookie {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PaaCookie")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// `HTTP_HANDSHAKE_REQUEST_PACKET` (2.2.10.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeRequest {
    /// `verMajor`.
    pub ver_major: u8,
    /// `verMinor`.
    pub ver_minor: u8,
    /// `clientVersion`; the spec requires zero.
    pub client_version: u16,
    /// `ExtendedAuth`, `HTTP_EXTENDED_AUTH_*` flags (2.2.5.3.2).
    pub extended_auth: u16,
}

/// `HTTP_HANDSHAKE_RESPONSE_PACKET` (2.2.10.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeResponse {
    /// `errorCode`, an HRESULT.
    pub error_code: u32,
    /// `verMajor`.
    pub ver_major: u8,
    /// `verMinor`.
    pub ver_minor: u8,
    /// `serverVersion`; the spec requires zero.
    pub server_version: u16,
    /// `ExtendedAuth`, `HTTP_EXTENDED_AUTH_*` flags (2.2.5.3.2).
    pub extended_auth: u16,
}

/// `HTTP_TUNNEL_PACKET` (2.2.10.18) with its `HTTP_TUNNEL_PACKET_OPTIONAL` (2.2.10.19).
/// `fieldsPresent` is the set of optional fields that are `Some`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelCreate {
    /// `capsFlags`, `HTTP_CAPABILITY_*` flags (2.2.5.3.9).
    pub caps_flags: u32,
    /// `reauthTunnelContext`, present under `HTTP_TUNNEL_PACKET_FIELD_REAUTH` (0x2).
    pub reauth_tunnel_context: Option<u64>,
    /// `PAACookie`, present under `HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE` (0x1).
    pub paa_cookie: Option<PaaCookie>,
}

/// The `nonce` and `serverCert` of `HTTP_TUNNEL_RESPONSE_OPTIONAL` (2.2.10.21), present together
/// under `HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SohRequest {
    /// `nonce`: a GUID in its 16-byte wire form.
    pub nonce: [u8; 16],
    /// `serverCert`.
    pub server_cert: UnicodeString,
}

/// `HTTP_TUNNEL_RESPONSE` (2.2.10.20) with its `HTTP_TUNNEL_RESPONSE_OPTIONAL` (2.2.10.21).
/// `fieldsPresent` is the set of optional fields that are `Some`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelResponse {
    /// `serverVersion`.
    pub server_version: u16,
    /// `statusCode`.
    pub status_code: u32,
    /// `tunnelId`.
    pub tunnel_id: Option<u32>,
    /// `capsFlags`, the capabilities the server negotiated.
    pub caps_flags: Option<u32>,
    /// `nonce` and `serverCert`.
    pub soh_request: Option<SohRequest>,
    /// `consentMsg`.
    pub consent_msg: Option<UnicodeString>,
}

/// `HTTP_TUNNEL_AUTH_PACKET` (2.2.10.14) with its `HTTP_TUNNEL_AUTH_PACKET_OPTIONAL` (2.2.10.15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelAuth {
    /// `clientName`, behind `cbClientName`.
    pub client_name: UnicodeString,
    /// `statementOfHealth`, present under `HTTP_TUNNEL_AUTH_FIELD_SOH`.
    pub statement_of_health: Option<Vec<u8>>,
}

/// `HTTP_TUNNEL_AUTH_RESPONSE` (2.2.10.16) with its `HTTP_TUNNEL_AUTH_RESPONSE_OPTIONAL`
/// (2.2.10.17). `fieldsPresent` is the set of optional fields that are `Some`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelAuthResponse {
    /// `errorCode`, an HRESULT.
    pub error_code: u32,
    /// `redirFlags`, `HTTP_TUNNEL_REDIR_*` flags (2.2.5.3.7).
    pub redir_flags: Option<u32>,
    /// `idleTimeout`, in minutes.
    pub idle_timeout: Option<u32>,
    /// `SoHResponse`.
    pub soh_response: Option<Vec<u8>>,
}

/// `HTTP_CHANNEL_PACKET` (2.2.10.2) with its `HTTP_CHANNEL_PACKET_VARIABLE` (2.2.10.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelCreate {
    /// `pResource`; `numResources` is its length (the spec allows 1 to 50).
    pub resources: Vec<UnicodeString>,
    /// `pAltResources`; `numAltResources` is its length (the spec allows 0 to 3).
    pub alt_resources: Vec<UnicodeString>,
    /// `port` on the target server.
    pub port: u16,
    /// `protocol`; the spec requires 3.
    pub protocol: u16,
}

/// `HTTP_CHANNEL_RESPONSE` (2.2.10.4) with its `HTTP_CHANNEL_RESPONSE_OPTIONAL` (2.2.10.5).
/// `fieldsPresent` is the set of optional fields that are `Some`; on the wire they follow in
/// the order channelId, udpPort, authnCookie. Its `Debug` prints the authnCookie's length and
/// never its bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct ChannelResponse {
    /// `errorCode`, an HRESULT.
    pub error_code: u32,
    /// `channelId`.
    pub channel_id: Option<u32>,
    /// `udpPort`.
    pub udp_port: Option<u16>,
    /// `authnCookie`.
    pub authn_cookie: Option<Vec<u8>>,
}

impl core::fmt::Debug for ChannelResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChannelResponse")
            .field("error_code", &self.error_code)
            .field("channel_id", &self.channel_id)
            .field("udp_port", &self.udp_port)
            .field(
                "authn_cookie",
                &self
                    .authn_cookie
                    .as_ref()
                    .map(|cookie| Redacted(cookie.len())),
            )
            .finish()
    }
}

/// A secret's length, printed in place of its bytes.
struct Redacted(usize);

impl core::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Redacted")
            .field("len", &self.0)
            .finish_non_exhaustive()
    }
}

/// One RDG HTTP transport packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet<'a> {
    /// `HTTP_HANDSHAKE_REQUEST_PACKET` (2.2.10.10).
    HandshakeRequest(HandshakeRequest),
    /// `HTTP_HANDSHAKE_RESPONSE_PACKET` (2.2.10.11).
    HandshakeResponse(HandshakeResponse),
    /// `HTTP_TUNNEL_PACKET` (2.2.10.18).
    TunnelCreate(TunnelCreate),
    /// `HTTP_TUNNEL_RESPONSE` (2.2.10.20).
    TunnelResponse(TunnelResponse),
    /// `HTTP_TUNNEL_AUTH_PACKET` (2.2.10.14).
    TunnelAuth(TunnelAuth),
    /// `HTTP_TUNNEL_AUTH_RESPONSE` (2.2.10.16).
    TunnelAuthResponse(TunnelAuthResponse),
    /// `HTTP_CHANNEL_PACKET` (2.2.10.2).
    ChannelCreate(ChannelCreate),
    /// `HTTP_CHANNEL_RESPONSE` (2.2.10.4).
    ChannelResponse(ChannelResponse),
    /// `HTTP_DATA_PACKET` (2.2.10.6): the `data` bytes.
    Data(&'a [u8]),
    /// `HTTP_KEEPALIVE_PACKET` (2.2.10.8).
    KeepAlive,
    /// `HTTP_CLOSE_PACKET` (2.2.10.23) with `PKT_TYPE_CLOSE_CHANNEL`.
    CloseChannel {
        /// `statusCode`, an HRESULT.
        status_code: u32,
    },
    /// `HTTP_CLOSE_PACKET` (2.2.10.23) with `PKT_TYPE_CLOSE_CHANNEL_RESPONSE`.
    CloseChannelResponse {
        /// `statusCode`, an HRESULT.
        status_code: u32,
    },
    /// Any other packet type, with the body after the header unparsed.
    Other {
        /// `packetType`.
        packet_type: u16,
        /// The bytes after the header, up to `packetLength`.
        body: &'a [u8],
    },
}

impl<'a> Packet<'a> {
    /// Decode the packet at the front of `buf`. The packet occupies the
    /// [`PacketHeader::packet_length`] bytes the header declares; bytes after it are not read,
    /// and neither are body bytes after the packet's last field.
    ///
    /// `NotEnoughBytes` means `buf` holds less than the whole packet. A field that runs past
    /// `packetLength` is `InvalidField`.
    pub fn decode(buf: &'a [u8]) -> Result<Self, DecodeError> {
        let header = PacketHeader::decode(buf)?;
        let total = header.packet_length as usize;
        if buf.len() < total {
            return Err(DecodeError::NotEnoughBytes {
                context: "HTTP_PACKET_HEADER.packetLength",
                needed: total,
                got: buf.len(),
            });
        }
        let body = &buf[HEADER_LEN..total];
        decode_body(header.packet_type, body).map_err(|e| match e {
            DecodeError::NotEnoughBytes { context, .. } => DecodeError::InvalidField {
                field: context,
                reason: "a field runs past packetLength",
            },
            other => other,
        })
    }

    /// The packet's `packetType`.
    pub fn packet_type(&self) -> u16 {
        match self {
            Packet::HandshakeRequest(_) => PKT_TYPE_HANDSHAKE_REQUEST,
            Packet::HandshakeResponse(_) => PKT_TYPE_HANDSHAKE_RESPONSE,
            Packet::TunnelCreate(_) => PKT_TYPE_TUNNEL_CREATE,
            Packet::TunnelResponse(_) => PKT_TYPE_TUNNEL_RESPONSE,
            Packet::TunnelAuth(_) => PKT_TYPE_TUNNEL_AUTH,
            Packet::TunnelAuthResponse(_) => PKT_TYPE_TUNNEL_AUTH_RESPONSE,
            Packet::ChannelCreate(_) => PKT_TYPE_CHANNEL_CREATE,
            Packet::ChannelResponse(_) => PKT_TYPE_CHANNEL_RESPONSE,
            Packet::Data(_) => PKT_TYPE_DATA,
            Packet::KeepAlive => PKT_TYPE_KEEPALIVE,
            Packet::CloseChannel { .. } => PKT_TYPE_CLOSE_CHANNEL,
            Packet::CloseChannelResponse { .. } => PKT_TYPE_CLOSE_CHANNEL_RESPONSE,
            Packet::Other { packet_type, .. } => *packet_type,
        }
    }

    /// Encode the whole packet, header included, with `reserved` fields zero.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut body = Vec::new();
        match self {
            Packet::HandshakeRequest(p) => {
                body.push(p.ver_major);
                body.push(p.ver_minor);
                put_u16(&mut body, p.client_version);
                put_u16(&mut body, p.extended_auth);
            }
            Packet::HandshakeResponse(p) => {
                put_u32(&mut body, p.error_code);
                body.push(p.ver_major);
                body.push(p.ver_minor);
                put_u16(&mut body, p.server_version);
                put_u16(&mut body, p.extended_auth);
            }
            Packet::TunnelCreate(p) => {
                let mut fields = 0;
                if p.reauth_tunnel_context.is_some() {
                    fields |= TUNNEL_FIELD_REAUTH;
                }
                if p.paa_cookie.is_some() {
                    fields |= TUNNEL_FIELD_PAA_COOKIE;
                }
                put_u32(&mut body, p.caps_flags);
                put_u16(&mut body, fields);
                put_u16(&mut body, 0); // reserved
                if let Some(context) = p.reauth_tunnel_context {
                    body.extend_from_slice(&context.to_le_bytes());
                }
                if let Some(cookie) = &p.paa_cookie {
                    put_blob(&mut body, "PAACookie", cookie.as_bytes())?;
                }
            }
            Packet::TunnelResponse(p) => {
                let mut fields = 0;
                if p.tunnel_id.is_some() {
                    fields |= TUNNEL_RESPONSE_FIELD_TUNNEL_ID;
                }
                if p.caps_flags.is_some() {
                    fields |= TUNNEL_RESPONSE_FIELD_CAPS;
                }
                if p.soh_request.is_some() {
                    fields |= TUNNEL_RESPONSE_FIELD_SOH_REQ;
                }
                if p.consent_msg.is_some() {
                    fields |= TUNNEL_RESPONSE_FIELD_CONSENT_MSG;
                }
                put_u16(&mut body, p.server_version);
                put_u32(&mut body, p.status_code);
                put_u16(&mut body, fields);
                put_u16(&mut body, 0); // reserved
                if let Some(id) = p.tunnel_id {
                    put_u32(&mut body, id);
                }
                if let Some(caps) = p.caps_flags {
                    put_u32(&mut body, caps);
                }
                if let Some(soh) = &p.soh_request {
                    body.extend_from_slice(&soh.nonce);
                    put_blob(&mut body, "serverCert", soh.server_cert.as_bytes())?;
                }
                if let Some(msg) = &p.consent_msg {
                    put_blob(&mut body, "consentMsg", msg.as_bytes())?;
                }
            }
            Packet::TunnelAuth(p) => {
                let fields = if p.statement_of_health.is_some() {
                    TUNNEL_AUTH_FIELD_SOH
                } else {
                    0
                };
                put_u16(&mut body, fields);
                put_blob(&mut body, "clientName", p.client_name.as_bytes())?;
                if let Some(soh) = &p.statement_of_health {
                    put_blob(&mut body, "statementOfHealth", soh)?;
                }
            }
            Packet::TunnelAuthResponse(p) => {
                let mut fields = 0;
                if p.redir_flags.is_some() {
                    fields |= TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS;
                }
                if p.idle_timeout.is_some() {
                    fields |= TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT;
                }
                if p.soh_response.is_some() {
                    fields |= TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE;
                }
                put_u32(&mut body, p.error_code);
                put_u16(&mut body, fields);
                put_u16(&mut body, 0); // reserved
                if let Some(flags) = p.redir_flags {
                    put_u32(&mut body, flags);
                }
                if let Some(timeout) = p.idle_timeout {
                    put_u32(&mut body, timeout);
                }
                if let Some(soh) = &p.soh_response {
                    put_blob(&mut body, "SoHResponse", soh)?;
                }
            }
            Packet::ChannelCreate(p) => {
                body.push(count_u8("numResources", p.resources.len())?);
                body.push(count_u8("numAltResources", p.alt_resources.len())?);
                put_u16(&mut body, p.port);
                put_u16(&mut body, p.protocol);
                for name in &p.resources {
                    put_blob(&mut body, "pResource", name.as_bytes())?;
                }
                for name in &p.alt_resources {
                    put_blob(&mut body, "pAltResources", name.as_bytes())?;
                }
            }
            Packet::ChannelResponse(p) => {
                let mut fields = 0;
                if p.channel_id.is_some() {
                    fields |= CHANNEL_RESPONSE_FIELD_CHANNELID;
                }
                if p.udp_port.is_some() {
                    fields |= CHANNEL_RESPONSE_FIELD_UDPPORT;
                }
                if p.authn_cookie.is_some() {
                    fields |= CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE;
                }
                put_u32(&mut body, p.error_code);
                put_u16(&mut body, fields);
                put_u16(&mut body, 0); // reserved
                if let Some(id) = p.channel_id {
                    put_u32(&mut body, id);
                }
                if let Some(port) = p.udp_port {
                    put_u16(&mut body, port);
                }
                if let Some(cookie) = &p.authn_cookie {
                    put_blob(&mut body, "authnCookie", cookie)?;
                }
            }
            Packet::Data(data) => put_blob(&mut body, "data", data)?,
            Packet::KeepAlive => {}
            Packet::CloseChannel { status_code } | Packet::CloseChannelResponse { status_code } => {
                put_u32(&mut body, *status_code);
            }
            Packet::Other {
                packet_type,
                body: raw,
            } => {
                if !matches!(decode_body(*packet_type, &[]), Ok(Packet::Other { .. })) {
                    return Err(EncodeError::ParsedType {
                        packet_type: *packet_type,
                    });
                }
                body.extend_from_slice(raw);
            }
        }
        let total = HEADER_LEN + body.len();
        let packet_length = u32::try_from(total).map_err(|_| EncodeError::TooLong {
            field: "packetLength",
            len: total,
            max: u32::MAX as usize,
        })?;
        let mut out = Vec::with_capacity(total);
        put_u16(&mut out, self.packet_type());
        put_u16(&mut out, 0); // reserved
        put_u32(&mut out, packet_length);
        out.extend_from_slice(&body);
        Ok(out)
    }
}

fn decode_body(packet_type: u16, body: &[u8]) -> Result<Packet<'_>, DecodeError> {
    Ok(match packet_type {
        PKT_TYPE_HANDSHAKE_REQUEST => {
            let mut cur = ReadCursor::new(body, "HTTP_HANDSHAKE_REQUEST_PACKET");
            Packet::HandshakeRequest(HandshakeRequest {
                ver_major: cur.read_u8()?,
                ver_minor: cur.read_u8()?,
                client_version: cur.read_u16_le()?,
                extended_auth: cur.read_u16_le()?,
            })
        }
        PKT_TYPE_HANDSHAKE_RESPONSE => {
            let mut cur = ReadCursor::new(body, "HTTP_HANDSHAKE_RESPONSE_PACKET");
            Packet::HandshakeResponse(HandshakeResponse {
                error_code: cur.read_u32_le()?,
                ver_major: cur.read_u8()?,
                ver_minor: cur.read_u8()?,
                server_version: cur.read_u16_le()?,
                extended_auth: cur.read_u16_le()?,
            })
        }
        PKT_TYPE_TUNNEL_CREATE => {
            let mut cur = ReadCursor::new(body, "HTTP_TUNNEL_PACKET");
            let caps_flags = cur.read_u32_le()?;
            let fields = cur.read_u16_le()?;
            let _reserved = cur.read_u16_le()?;
            let reauth_tunnel_context = if fields & TUNNEL_FIELD_REAUTH != 0 {
                Some(read_u64_le(&mut cur)?)
            } else {
                None
            };
            let paa_cookie = if fields & TUNNEL_FIELD_PAA_COOKIE != 0 {
                Some(PaaCookie(read_blob(&mut cur)?.to_vec()))
            } else {
                None
            };
            Packet::TunnelCreate(TunnelCreate {
                caps_flags,
                reauth_tunnel_context,
                paa_cookie,
            })
        }
        PKT_TYPE_TUNNEL_RESPONSE => {
            let mut cur = ReadCursor::new(body, "HTTP_TUNNEL_RESPONSE");
            let server_version = cur.read_u16_le()?;
            let status_code = cur.read_u32_le()?;
            let fields = cur.read_u16_le()?;
            let _reserved = cur.read_u16_le()?;
            let tunnel_id = if fields & TUNNEL_RESPONSE_FIELD_TUNNEL_ID != 0 {
                Some(cur.read_u32_le()?)
            } else {
                None
            };
            let caps_flags = if fields & TUNNEL_RESPONSE_FIELD_CAPS != 0 {
                Some(cur.read_u32_le()?)
            } else {
                None
            };
            let soh_request = if fields & TUNNEL_RESPONSE_FIELD_SOH_REQ != 0 {
                let nonce = <[u8; 16]>::try_from(cur.read_slice(16)?).map_err(|_| {
                    DecodeError::InvalidField {
                        field: "HTTP_TUNNEL_RESPONSE_OPTIONAL.nonce",
                        reason: "not 16 bytes",
                    }
                })?;
                Some(SohRequest {
                    nonce,
                    server_cert: read_unicode_string(&mut cur)?,
                })
            } else {
                None
            };
            let consent_msg = if fields & TUNNEL_RESPONSE_FIELD_CONSENT_MSG != 0 {
                Some(read_unicode_string(&mut cur)?)
            } else {
                None
            };
            Packet::TunnelResponse(TunnelResponse {
                server_version,
                status_code,
                tunnel_id,
                caps_flags,
                soh_request,
                consent_msg,
            })
        }
        PKT_TYPE_TUNNEL_AUTH => {
            let mut cur = ReadCursor::new(body, "HTTP_TUNNEL_AUTH_PACKET");
            let fields = cur.read_u16_le()?;
            let client_name = read_unicode_string(&mut cur)?;
            let statement_of_health = if fields & TUNNEL_AUTH_FIELD_SOH != 0 {
                Some(read_blob(&mut cur)?.to_vec())
            } else {
                None
            };
            Packet::TunnelAuth(TunnelAuth {
                client_name,
                statement_of_health,
            })
        }
        PKT_TYPE_TUNNEL_AUTH_RESPONSE => {
            let mut cur = ReadCursor::new(body, "HTTP_TUNNEL_AUTH_RESPONSE");
            let error_code = cur.read_u32_le()?;
            let fields = cur.read_u16_le()?;
            let _reserved = cur.read_u16_le()?;
            let redir_flags = if fields & TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS != 0 {
                Some(cur.read_u32_le()?)
            } else {
                None
            };
            let idle_timeout = if fields & TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT != 0 {
                Some(cur.read_u32_le()?)
            } else {
                None
            };
            let soh_response = if fields & TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE != 0 {
                Some(read_blob(&mut cur)?.to_vec())
            } else {
                None
            };
            Packet::TunnelAuthResponse(TunnelAuthResponse {
                error_code,
                redir_flags,
                idle_timeout,
                soh_response,
            })
        }
        PKT_TYPE_CHANNEL_CREATE => {
            let mut cur = ReadCursor::new(body, "HTTP_CHANNEL_PACKET");
            let num_resources = cur.read_u8()?;
            let num_alt_resources = cur.read_u8()?;
            let port = cur.read_u16_le()?;
            let protocol = cur.read_u16_le()?;
            let mut resources = Vec::new();
            for _ in 0..num_resources {
                resources.push(read_unicode_string(&mut cur)?);
            }
            let mut alt_resources = Vec::new();
            for _ in 0..num_alt_resources {
                alt_resources.push(read_unicode_string(&mut cur)?);
            }
            Packet::ChannelCreate(ChannelCreate {
                resources,
                alt_resources,
                port,
                protocol,
            })
        }
        PKT_TYPE_CHANNEL_RESPONSE => {
            let mut cur = ReadCursor::new(body, "HTTP_CHANNEL_RESPONSE");
            let error_code = cur.read_u32_le()?;
            let fields = cur.read_u16_le()?;
            let _reserved = cur.read_u16_le()?;
            let channel_id = if fields & CHANNEL_RESPONSE_FIELD_CHANNELID != 0 {
                Some(cur.read_u32_le()?)
            } else {
                None
            };
            let udp_port = if fields & CHANNEL_RESPONSE_FIELD_UDPPORT != 0 {
                Some(cur.read_u16_le()?)
            } else {
                None
            };
            let authn_cookie = if fields & CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE != 0 {
                Some(read_blob(&mut cur)?.to_vec())
            } else {
                None
            };
            Packet::ChannelResponse(ChannelResponse {
                error_code,
                channel_id,
                udp_port,
                authn_cookie,
            })
        }
        PKT_TYPE_DATA => {
            let mut cur = ReadCursor::new(body, "HTTP_DATA_PACKET");
            Packet::Data(read_blob(&mut cur)?)
        }
        PKT_TYPE_KEEPALIVE => Packet::KeepAlive,
        PKT_TYPE_CLOSE_CHANNEL => {
            let mut cur = ReadCursor::new(body, "HTTP_CLOSE_PACKET");
            Packet::CloseChannel {
                status_code: cur.read_u32_le()?,
            }
        }
        PKT_TYPE_CLOSE_CHANNEL_RESPONSE => {
            let mut cur = ReadCursor::new(body, "HTTP_CLOSE_PACKET");
            Packet::CloseChannelResponse {
                status_code: cur.read_u32_le()?,
            }
        }
        packet_type => Packet::Other { packet_type, body },
    })
}

/// `s` as UTF-16LE followed by a NUL unit.
fn utf16le_nul(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(core::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// A `u16` length followed by that many bytes: `HTTP_byte_BLOB` (2.2.10.1), and the same shape
/// for `HTTP_UNICODE_STRING` (2.2.10.22) and `HTTP_DATA_PACKET`'s `cbDataLen`/`data`.
fn read_blob<'a>(cur: &mut ReadCursor<'a>) -> Result<&'a [u8], DecodeError> {
    let len = cur.read_u16_le()?;
    cur.read_slice(usize::from(len))
}

fn read_unicode_string(cur: &mut ReadCursor<'_>) -> Result<UnicodeString, DecodeError> {
    Ok(UnicodeString(read_blob(cur)?.to_vec()))
}

fn read_u64_le(cur: &mut ReadCursor<'_>) -> Result<u64, DecodeError> {
    let low = cur.read_u32_le()?;
    let high = cur.read_u32_le()?;
    Ok(u64::from(high) << 32 | u64::from(low))
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Write `bytes` behind its `u16` length.
fn put_blob(out: &mut Vec<u8>, field: &'static str, bytes: &[u8]) -> Result<(), EncodeError> {
    let len = u16::try_from(bytes.len()).map_err(|_| EncodeError::TooLong {
        field,
        len: bytes.len(),
        max: usize::from(u16::MAX),
    })?;
    put_u16(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn count_u8(field: &'static str, count: usize) -> Result<u8, EncodeError> {
    u8::try_from(count).map_err(|_| EncodeError::TooLong {
        field,
        len: count,
        max: usize::from(u8::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode `bytes` to `expected`, and encode `expected` back to `bytes`.
    fn assert_both_ways(bytes: &[u8], expected: Packet<'_>) {
        assert_eq!(Packet::decode(bytes).unwrap(), expected, "decode");
        assert_eq!(expected.encode().unwrap(), bytes, "encode");
    }

    /// MS-TSGU 4.2.1 step 11 (verMajor 1, verMinor 0) with the `extendedAuth` mstsc sends for
    /// PAA (`0x2`, observed on #613).
    const HANDSHAKE_REQUEST: [u8; 14] = [
        0x01, 0x00, // packetType PKT_TYPE_HANDSHAKE_REQUEST
        0x00, 0x00, // reserved
        0x0E, 0x00, 0x00, 0x00, // packetLength 14
        0x01, // verMajor
        0x00, // verMinor
        0x00, 0x00, // clientVersion
        0x02, 0x00, // ExtendedAuth HTTP_EXTENDED_AUTH_PAA
    ];

    #[test]
    fn handshake_request_matches_the_spec_layout() {
        let expected = HandshakeRequest {
            ver_major: 1,
            ver_minor: 0,
            client_version: 0,
            extended_auth: HTTP_EXTENDED_AUTH_PAA,
        };
        assert_both_ways(&HANDSHAKE_REQUEST, Packet::HandshakeRequest(expected));
    }

    /// 4.2.1 step 12: errorCode 0, version 1.0, ExtendedAuth PAA | SC.
    #[test]
    fn handshake_response_matches_the_spec_layout() {
        let bytes = [
            0x02, 0x00, // packetType PKT_TYPE_HANDSHAKE_RESPONSE
            0x00, 0x00, // reserved
            0x12, 0x00, 0x00, 0x00, // packetLength 18
            0x00, 0x00, 0x00, 0x00, // errorCode
            0x01, // verMajor
            0x00, // verMinor
            0x00, 0x00, // serverVersion
            0x03, 0x00, // ExtendedAuth PAA | SC
        ];
        assert_both_ways(
            &bytes,
            Packet::HandshakeResponse(HandshakeResponse {
                error_code: 0,
                ver_major: 1,
                ver_minor: 0,
                server_version: 0,
                extended_auth: HTTP_EXTENDED_AUTH_PAA | HTTP_EXTENDED_AUTH_SC,
            }),
        );
    }

    /// 4.2.1 step 13: capsFlags 0x3F, fieldsPresent 0.
    #[test]
    fn tunnel_create_without_optional_fields_matches_the_spec_layout() {
        let bytes = [
            0x04, 0x00, // packetType PKT_TYPE_TUNNEL_CREATE
            0x00, 0x00, // reserved
            0x10, 0x00, 0x00, 0x00, // packetLength 16
            0x3F, 0x00, 0x00, 0x00, // capsFlags
            0x00, 0x00, // fieldsPresent
            0x00, 0x00, // reserved
        ];
        assert_both_ways(
            &bytes,
            Packet::TunnelCreate(TunnelCreate {
                caps_flags: 0x3F,
                reauth_tunnel_context: None,
                paa_cookie: None,
            }),
        );
    }

    /// The tunnel create mstsc sends with a PAA cookie (#613): capsFlags 0x3F, fieldsPresent
    /// `HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE` (0x1, 2.2.5.3.6), and the cookie as UTF-16LE with
    /// a terminating NUL.
    const TUNNEL_CREATE_WITH_COOKIE: [u8; 24] = [
        0x04, 0x00, // packetType PKT_TYPE_TUNNEL_CREATE
        0x00, 0x00, // reserved
        0x18, 0x00, 0x00, 0x00, // packetLength 24
        0x3F, 0x00, 0x00, 0x00, // capsFlags
        0x01, 0x00, // fieldsPresent PAA_COOKIE
        0x00, 0x00, // reserved
        0x06, 0x00, // PAACookie.cbLen
        b'a', 0x00, b'b', 0x00, 0x00, 0x00, // "ab" NUL
    ];

    #[test]
    fn tunnel_create_with_a_paa_cookie_matches_what_mstsc_sends() {
        assert_both_ways(
            &TUNNEL_CREATE_WITH_COOKIE,
            Packet::TunnelCreate(TunnelCreate {
                caps_flags: 0x3F,
                reauth_tunnel_context: None,
                paa_cookie: Some(PaaCookie::from_token("ab")),
            }),
        );
    }

    /// 2.2.10.19 orders reauthTunnelContext before PAACookie, each under its own bit.
    #[test]
    fn tunnel_create_puts_the_reauth_context_before_the_cookie() {
        let bytes = [
            0x04, 0x00, // packetType PKT_TYPE_TUNNEL_CREATE
            0x00, 0x00, // reserved
            0x1C, 0x00, 0x00, 0x00, // packetLength 28
            0x00, 0x00, 0x00, 0x00, // capsFlags
            0x03, 0x00, // fieldsPresent PAA_COOKIE | REAUTH
            0x00, 0x00, // reserved
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // reauthTunnelContext
            0x02, 0x00, // PAACookie.cbLen
            0xAA, 0xBB, // PAACookie.blob
        ];
        assert_both_ways(
            &bytes,
            Packet::TunnelCreate(TunnelCreate {
                caps_flags: 0,
                reauth_tunnel_context: Some(0x0102_0304_0506_0708),
                paa_cookie: Some(PaaCookie::from_bytes(vec![0xAA, 0xBB])),
            }),
        );
    }

    #[test]
    fn a_udp_authn_cookie_debug_prints_its_length_and_not_its_bytes() {
        let response = ChannelResponse {
            error_code: 0,
            channel_id: Some(1),
            udp_port: Some(3391),
            authn_cookie: Some(vec![0xDE, 0xAD]),
        };
        let printed = format!("{response:?}");
        assert!(printed.contains("len: 2"), "{printed}");
        assert!(printed.contains("3391"), "{printed}");
        assert!(!printed.contains("222"), "{printed}"); // 0xDE
        assert!(!printed.contains("173"), "{printed}"); // 0xAD
    }

    /// `Other` carries only types this module leaves unparsed: one of the parsed types would
    /// decode back as its own variant.
    #[test]
    fn other_refuses_a_packet_type_that_has_its_own_variant() {
        for packet_type in [
            PKT_TYPE_DATA,
            PKT_TYPE_KEEPALIVE,
            PKT_TYPE_HANDSHAKE_REQUEST,
        ] {
            assert_eq!(
                Packet::Other {
                    packet_type,
                    body: &[0x01, 0x00, 0x41],
                }
                .encode()
                .unwrap_err(),
                EncodeError::ParsedType { packet_type }
            );
        }
        assert!(
            Packet::Other {
                packet_type: PKT_TYPE_REAUTH_MESSAGE,
                body: &[0; 8],
            }
            .encode()
            .is_ok()
        );
    }

    #[test]
    fn a_paa_cookie_debug_prints_its_length_and_not_its_bytes() {
        let cookie = PaaCookie::from_token("Zq");
        let printed = format!(
            "{:?}",
            Packet::TunnelCreate(TunnelCreate {
                caps_flags: 0,
                reauth_tunnel_context: None,
                paa_cookie: Some(cookie),
            })
        );
        assert!(printed.contains("len: 6"), "{printed}");
        assert!(!printed.contains("Zq"), "{printed}");
        assert!(!printed.contains("90"), "{printed}"); // 'Z' = 0x5A = 90
        assert!(!printed.contains("113"), "{printed}"); // 'q' = 0x71 = 113
    }

    /// 4.2.1 step 14: statusCode 0, fieldsPresent TUNNEL_ID | CAPS, tunnelId 6, capsFlags 0x3F.
    /// The scenario leaves serverVersion unset; 1 is filled in.
    #[test]
    fn tunnel_response_matches_the_spec_layout() {
        let bytes = [
            0x05, 0x00, // packetType PKT_TYPE_TUNNEL_RESPONSE
            0x00, 0x00, // reserved
            0x1A, 0x00, 0x00, 0x00, // packetLength 26
            0x01, 0x00, // serverVersion
            0x00, 0x00, 0x00, 0x00, // statusCode
            0x03, 0x00, // fieldsPresent TUNNEL_ID | CAPS
            0x00, 0x00, // reserved
            0x06, 0x00, 0x00, 0x00, // tunnelId
            0x3F, 0x00, 0x00, 0x00, // capsFlags
        ];
        assert_both_ways(
            &bytes,
            Packet::TunnelResponse(TunnelResponse {
                server_version: 1,
                status_code: 0,
                tunnel_id: Some(6),
                caps_flags: Some(0x3F),
                soh_request: None,
                consent_msg: None,
            }),
        );
    }

    /// Every optional field of 2.2.10.21 in order, so the last one (consentMsg) is only
    /// reachable by walking the 16-byte nonce and the serverCert before it. The nonce is the
    /// GUID from 4.2.1 step 1 in its MS-DTYP 2.3.4.2 wire form.
    #[test]
    fn tunnel_response_walks_every_optional_field_in_order() {
        let bytes = [
            0x05, 0x00, // packetType PKT_TYPE_TUNNEL_RESPONSE
            0x00, 0x00, // reserved
            0x34, 0x00, 0x00, 0x00, // packetLength 52
            0x01, 0x00, // serverVersion
            0x00, 0x00, 0x00, 0x00, // statusCode
            0x17, 0x00, // fieldsPresent TUNNEL_ID | CAPS | SOH_REQ | CONSENT_MSG
            0x00, 0x00, // reserved
            0x06, 0x00, 0x00, 0x00, // tunnelId
            0x3F, 0x00, 0x00, 0x00, // capsFlags
            0xD8, 0x92, 0x8F, 0x95, 0x20, 0xDA, 0x7A, 0x46, // nonce
            0xBB, 0xE3, 0x65, 0xE7, 0xE9, 0xB4, 0xED, 0xCF, //
            0x02, 0x00, // serverCert.cbLen
            b'C', 0x00, // "C"
            0x04, 0x00, // consentMsg.cbLen
            b'O', 0x00, b'K', 0x00, // "OK"
        ];
        assert_both_ways(
            &bytes,
            Packet::TunnelResponse(TunnelResponse {
                server_version: 1,
                status_code: 0,
                tunnel_id: Some(6),
                caps_flags: Some(0x3F),
                soh_request: Some(SohRequest {
                    nonce: [
                        0xD8, 0x92, 0x8F, 0x95, 0x20, 0xDA, 0x7A, 0x46, 0xBB, 0xE3, 0x65, 0xE7,
                        0xE9, 0xB4, 0xED, 0xCF,
                    ],
                    server_cert: UnicodeString::from_bytes(vec![b'C', 0]),
                }),
                consent_msg: Some(UnicodeString::from_bytes(vec![b'O', 0, b'K', 0])),
            }),
        );
    }

    /// 4.2.1 step 15: cbClientName 22, clientName "RDG-Client1" (11 UTF-16 units, no NUL).
    #[test]
    fn tunnel_auth_matches_the_spec_layout() {
        let mut bytes = vec![
            0x06, 0x00, // packetType PKT_TYPE_TUNNEL_AUTH
            0x00, 0x00, // reserved
            0x22, 0x00, 0x00, 0x00, // packetLength 34
            0x00, 0x00, // fieldsPresent
            0x16, 0x00, // cbClientName 22
        ];
        for c in b"RDG-Client1" {
            bytes.extend_from_slice(&[*c, 0x00]);
        }
        let packet = Packet::decode(&bytes).unwrap();
        let Packet::TunnelAuth(auth) = &packet else {
            panic!("expected a tunnel auth, got {packet:?}");
        };
        assert_eq!(auth.client_name.to_string_lossy(), "RDG-Client1");
        assert_eq!(auth.statement_of_health, None);
        assert_eq!(packet.encode().unwrap(), bytes);
    }

    /// 2.2.10.15: statementOfHealth follows clientName under HTTP_TUNNEL_AUTH_FIELD_SOH.
    #[test]
    fn tunnel_auth_carries_the_statement_of_health_after_the_name() {
        let bytes = [
            0x06, 0x00, // packetType PKT_TYPE_TUNNEL_AUTH
            0x00, 0x00, // reserved
            0x13, 0x00, 0x00, 0x00, // packetLength 19
            0x01, 0x00, // fieldsPresent SOH
            0x04, 0x00, // cbClientName
            b'P', 0x00, b'C', 0x00, // "PC"
            0x01, 0x00, // statementOfHealth.cbLen
            0x5A, // statementOfHealth.blob
        ];
        assert_both_ways(
            &bytes,
            Packet::TunnelAuth(TunnelAuth {
                client_name: UnicodeString::from_bytes(vec![b'P', 0, b'C', 0]),
                statement_of_health: Some(vec![0x5A]),
            }),
        );
    }

    /// 4.2.1 step 16: errorCode S_OK, fieldsPresent REDIR_FLAGS | IDLE_TIMEOUT, both zero.
    #[test]
    fn tunnel_auth_response_matches_the_spec_layout() {
        let bytes = [
            0x07, 0x00, // packetType PKT_TYPE_TUNNEL_AUTH_RESPONSE
            0x00, 0x00, // reserved
            0x18, 0x00, 0x00, 0x00, // packetLength 24
            0x00, 0x00, 0x00, 0x00, // errorCode
            0x03, 0x00, // fieldsPresent REDIR_FLAGS | IDLE_TIMEOUT
            0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, // redirFlags
            0x00, 0x00, 0x00, 0x00, // idleTimeout
        ];
        assert_both_ways(
            &bytes,
            Packet::TunnelAuthResponse(TunnelAuthResponse {
                error_code: 0,
                redir_flags: Some(0),
                idle_timeout: Some(0),
                soh_response: None,
            }),
        );
    }

    /// 2.2.10.17 order with distinct values, so a swapped redirFlags/idleTimeout shows, and the
    /// SoHResponse only reachable after both.
    #[test]
    fn tunnel_auth_response_walks_every_optional_field_in_order() {
        let bytes = [
            0x07, 0x00, // packetType PKT_TYPE_TUNNEL_AUTH_RESPONSE
            0x00, 0x00, // reserved
            0x1B, 0x00, 0x00, 0x00, // packetLength 27
            0x00, 0x00, 0x00, 0x00, // errorCode
            0x07, 0x00, // fieldsPresent REDIR_FLAGS | IDLE_TIMEOUT | SOH_RESPONSE
            0x00, 0x00, // reserved
            0x08, 0x00, 0x00, 0x40, // redirFlags DISABLE_ALL | DISABLE_CLIPBOARD
            0x1E, 0x00, 0x00, 0x00, // idleTimeout 30
            0x01, 0x00, // SoHResponse.cbLen
            0x77, // SoHResponse.blob
        ];
        assert_both_ways(
            &bytes,
            Packet::TunnelAuthResponse(TunnelAuthResponse {
                error_code: 0,
                redir_flags: Some(
                    HTTP_TUNNEL_REDIR_DISABLE_ALL | HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD,
                ),
                idle_timeout: Some(30),
                soh_response: Some(vec![0x77]),
            }),
        );
    }

    /// 4.2.1 step 17: one resource, no alternatives, port 3389, protocol 3. The scenario does
    /// not name the resource; "srv" with a NUL is filled in.
    #[test]
    fn channel_create_matches_the_spec_layout() {
        let bytes = [
            0x08, 0x00, // packetType PKT_TYPE_CHANNEL_CREATE
            0x00, 0x00, // reserved
            0x18, 0x00, 0x00, 0x00, // packetLength 24
            0x01, // numResources
            0x00, // numAltResources
            0x3D, 0x0D, // port 3389
            0x03, 0x00, // protocol
            0x08, 0x00, // pResource[0].cbLen
            b's', 0x00, b'r', 0x00, b'v', 0x00, 0x00, 0x00, // "srv" NUL
        ];
        assert_both_ways(
            &bytes,
            Packet::ChannelCreate(ChannelCreate {
                resources: vec![UnicodeString::from_str_nul("srv")],
                alt_resources: vec![],
                port: 3389,
                protocol: 3,
            }),
        );
    }

    /// 2.2.10.3: the alternative resources follow every resource.
    #[test]
    fn channel_create_puts_alternative_resources_after_the_resources() {
        let bytes = [
            0x08, 0x00, // packetType PKT_TYPE_CHANNEL_CREATE
            0x00, 0x00, // reserved
            0x1A, 0x00, 0x00, 0x00, // packetLength 26
            0x02, // numResources
            0x01, // numAltResources
            0x3D, 0x0D, // port 3389
            0x03, 0x00, // protocol
            0x02, 0x00, b'a', 0x00, // pResource[0] "a"
            0x02, 0x00, b'b', 0x00, // pResource[1] "b"
            0x02, 0x00, b'c', 0x00, // pAltResources[0] "c"
        ];
        let name = |c: u8| UnicodeString::from_bytes(vec![c, 0]);
        assert_both_ways(
            &bytes,
            Packet::ChannelCreate(ChannelCreate {
                resources: vec![name(b'a'), name(b'b')],
                alt_resources: vec![name(b'c')],
                port: 3389,
                protocol: 3,
            }),
        );
    }

    /// 4.2.1 step 18: errorCode 0, every optional field, channelId 1, udpPort 3391, and an
    /// authnCookie of 1433 bytes (the scenario's "<encrypted blob>", filled with a pattern).
    #[test]
    fn channel_response_matches_the_spec_layout() {
        let cookie: Vec<u8> = (0..1433u32).map(|i| i as u8).collect();
        let mut bytes = vec![
            0x09, 0x00, // packetType PKT_TYPE_CHANNEL_RESPONSE
            0x00, 0x00, // reserved
            0xB1, 0x05, 0x00, 0x00, // packetLength 1457
            0x00, 0x00, 0x00, 0x00, // errorCode
            0x07, 0x00, // fieldsPresent CHANNELID | AUTHNCOOKIE | UDPPORT
            0x00, 0x00, // reserved
            0x01, 0x00, 0x00, 0x00, // channelId
            0x3F, 0x0D, // udpPort 3391
            0x99, 0x05, // authnCookie.cbLen 1433
        ];
        bytes.extend_from_slice(&cookie);
        assert_both_ways(
            &bytes,
            Packet::ChannelResponse(ChannelResponse {
                error_code: 0,
                channel_id: Some(1),
                udp_port: Some(3391),
                authn_cookie: Some(cookie),
            }),
        );
    }

    /// AUTHNCOOKIE is 0x2 and UDPPORT 0x4 (2.2.5.3.1): with 0x3 the cookie follows the
    /// channelId directly and no udpPort is read.
    #[test]
    fn channel_response_gates_the_cookie_on_0x2_and_the_port_on_0x4() {
        let bytes = [
            0x09, 0x00, // packetType PKT_TYPE_CHANNEL_RESPONSE
            0x00, 0x00, // reserved
            0x17, 0x00, 0x00, 0x00, // packetLength 23
            0x00, 0x00, 0x00, 0x00, // errorCode
            0x03, 0x00, // fieldsPresent CHANNELID | AUTHNCOOKIE
            0x00, 0x00, // reserved
            0x01, 0x00, 0x00, 0x00, // channelId
            0x01, 0x00, // authnCookie.cbLen
            0xC0, // authnCookie.blob
        ];
        assert_both_ways(
            &bytes,
            Packet::ChannelResponse(ChannelResponse {
                error_code: 0,
                channel_id: Some(1),
                udp_port: None,
                authn_cookie: Some(vec![0xC0]),
            }),
        );
    }

    /// 2.2.10.6, carrying the first bytes of a TPKT header.
    #[test]
    fn data_matches_the_spec_layout() {
        let bytes = [
            0x0A, 0x00, // packetType PKT_TYPE_DATA
            0x00, 0x00, // reserved
            0x0E, 0x00, 0x00, 0x00, // packetLength 14
            0x04, 0x00, // cbDataLen
            0x03, 0x00, 0x00, 0x13, // data
        ];
        assert_both_ways(&bytes, Packet::Data(&[0x03, 0x00, 0x00, 0x13]));
    }

    #[test]
    fn keep_alive_is_a_bare_header() {
        let bytes = [
            0x0D, 0x00, // packetType PKT_TYPE_KEEPALIVE
            0x00, 0x00, // reserved
            0x08, 0x00, 0x00, 0x00, // packetLength 8
        ];
        assert_both_ways(&bytes, Packet::KeepAlive);
    }

    /// 2.2.10.23 under both packet types, with a status code in each.
    #[test]
    fn close_and_close_response_carry_a_status_code() {
        let close = [
            0x10, 0x00, // packetType PKT_TYPE_CLOSE_CHANNEL
            0x00, 0x00, // reserved
            0x0C, 0x00, 0x00, 0x00, // packetLength 12
            0x05, 0x40, 0x00, 0x80, // statusCode 0x80004005
        ];
        assert_both_ways(
            &close,
            Packet::CloseChannel {
                status_code: 0x8000_4005,
            },
        );
        let response = [
            0x11, 0x00, // packetType PKT_TYPE_CLOSE_CHANNEL_RESPONSE
            0x00, 0x00, // reserved
            0x0C, 0x00, 0x00, 0x00, // packetLength 12
            0x00, 0x00, 0x00, 0x00, // statusCode
        ];
        assert_both_ways(&response, Packet::CloseChannelResponse { status_code: 0 });
    }

    /// A service message (2.2.10.13) is left to the caller with its body.
    #[test]
    fn an_unparsed_packet_type_keeps_its_body() {
        let bytes = [
            0x0B, 0x00, // packetType PKT_TYPE_SERVICE_MESSAGE
            0x00, 0x00, // reserved
            0x0B, 0x00, 0x00, 0x00, // packetLength 11
            0x01, 0x00, 0x7A, // body
        ];
        assert_both_ways(
            &bytes,
            Packet::Other {
                packet_type: PKT_TYPE_SERVICE_MESSAGE,
                body: &[0x01, 0x00, 0x7A],
            },
        );
    }

    #[test]
    fn the_packet_ends_at_packet_length() {
        let mut bytes = HANDSHAKE_REQUEST.to_vec();
        bytes.extend_from_slice(&[0x0D, 0x00]); // the start of the next packet
        assert!(matches!(
            Packet::decode(&bytes).unwrap(),
            Packet::HandshakeRequest(_)
        ));
        assert_eq!(PacketHeader::decode(&bytes).unwrap().packet_length, 14);
    }

    #[test]
    fn a_short_header_or_packet_asks_for_more_bytes() {
        assert_eq!(
            Packet::decode(&HANDSHAKE_REQUEST[..7]).unwrap_err(),
            DecodeError::NotEnoughBytes {
                context: "HTTP_PACKET_HEADER",
                needed: 4,
                got: 3,
            }
        );
        assert_eq!(
            Packet::decode(&HANDSHAKE_REQUEST[..13]).unwrap_err(),
            DecodeError::NotEnoughBytes {
                context: "HTTP_PACKET_HEADER.packetLength",
                needed: 14,
                got: 13,
            }
        );
    }

    #[test]
    fn a_packet_length_inside_the_header_is_refused() {
        let bytes = [0x0D, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00];
        assert_eq!(
            PacketHeader::decode(&bytes).unwrap_err(),
            DecodeError::InvalidField {
                field: "HTTP_PACKET_HEADER.packetLength",
                reason: "shorter than the 8-byte header",
            }
        );
        assert!(Packet::decode(&bytes).is_err());
    }

    /// A complete packet whose field overruns `packetLength` is malformed, not partial: it must
    /// not read as "wait for more bytes", and the bytes after the packet must not be read.
    #[test]
    fn a_field_past_packet_length_is_invalid_not_partial() {
        let mut bytes = TUNNEL_CREATE_WITH_COOKIE.to_vec();
        bytes[16] = 0x07; // PAACookie.cbLen 7, one past the packet
        bytes.push(0x00); // a byte after the packet that would satisfy it
        assert_eq!(
            Packet::decode(&bytes).unwrap_err(),
            DecodeError::InvalidField {
                field: "HTTP_TUNNEL_PACKET",
                reason: "a field runs past packetLength",
            }
        );
    }

    /// A body cut at every length short of its fixed fields is an error, for each parsed type.
    #[test]
    fn every_parsed_type_refuses_a_body_cut_short() {
        let full = [
            (PKT_TYPE_HANDSHAKE_REQUEST, 6),
            (PKT_TYPE_HANDSHAKE_RESPONSE, 10),
            (PKT_TYPE_TUNNEL_CREATE, 8),
            (PKT_TYPE_TUNNEL_RESPONSE, 10),
            (PKT_TYPE_TUNNEL_AUTH, 4),
            (PKT_TYPE_TUNNEL_AUTH_RESPONSE, 8),
            (PKT_TYPE_CHANNEL_CREATE, 6),
            (PKT_TYPE_CHANNEL_RESPONSE, 8),
            (PKT_TYPE_DATA, 2),
            (PKT_TYPE_CLOSE_CHANNEL, 4),
            (PKT_TYPE_CLOSE_CHANNEL_RESPONSE, 4),
        ];
        for (packet_type, fixed) in full {
            for cut in 0..fixed {
                let mut bytes = packet_type.to_le_bytes().to_vec();
                bytes.extend_from_slice(&[0, 0]);
                bytes.extend_from_slice(&((HEADER_LEN + cut) as u32).to_le_bytes());
                bytes.resize(HEADER_LEN + cut, 0);
                assert!(
                    matches!(
                        Packet::decode(&bytes),
                        Err(DecodeError::InvalidField { .. })
                    ),
                    "type {packet_type:#x} cut at {cut}"
                );
            }
            let mut bytes = packet_type.to_le_bytes().to_vec();
            bytes.extend_from_slice(&[0, 0]);
            bytes.extend_from_slice(&((HEADER_LEN + fixed) as u32).to_le_bytes());
            bytes.resize(HEADER_LEN + fixed, 0);
            assert!(
                Packet::decode(&bytes).is_ok(),
                "type {packet_type:#x} at its fixed size"
            );
        }
    }

    #[test]
    fn a_field_longer_than_its_prefix_is_an_encode_error() {
        let data = vec![0; 65536];
        assert_eq!(
            Packet::Data(&data).encode().unwrap_err(),
            EncodeError::TooLong {
                field: "data",
                len: 65536,
                max: 65535,
            }
        );
        let too_many = ChannelCreate {
            resources: vec![UnicodeString::default(); 256],
            alt_resources: vec![],
            port: 3389,
            protocol: 3,
        };
        assert_eq!(
            Packet::ChannelCreate(too_many).encode().unwrap_err(),
            EncodeError::TooLong {
                field: "numResources",
                len: 256,
                max: 255,
            }
        );
        assert!(Packet::Data(&data[..65535]).encode().is_ok());
    }

    use proptest::prelude::*;

    /// The packet types this module parses, plus one it leaves to the caller.
    const TYPES: [u16; 13] = [
        PKT_TYPE_HANDSHAKE_REQUEST,
        PKT_TYPE_HANDSHAKE_RESPONSE,
        PKT_TYPE_TUNNEL_CREATE,
        PKT_TYPE_TUNNEL_RESPONSE,
        PKT_TYPE_TUNNEL_AUTH,
        PKT_TYPE_TUNNEL_AUTH_RESPONSE,
        PKT_TYPE_CHANNEL_CREATE,
        PKT_TYPE_CHANNEL_RESPONSE,
        PKT_TYPE_DATA,
        PKT_TYPE_KEEPALIVE,
        PKT_TYPE_CLOSE_CHANNEL,
        PKT_TYPE_CLOSE_CHANNEL_RESPONSE,
        PKT_TYPE_SERVICE_MESSAGE,
    ];

    /// A packet with a known type most of the time, a `packetLength` that matches its body most
    /// of the time, and body bytes weighted towards zero and small values, so a `u16` length or
    /// a count often fits the body and a `fieldsPresent` often sets the low bits. Each field
    /// keeps an `any` arm, and a cut arm truncates the result.
    fn packet_bytes() -> impl Strategy<Value = Vec<u8>> {
        let body_byte = prop_oneof![2 => Just(0u8), 1 => 1u8..=8, 1 => any::<u8>()];
        (
            prop_oneof![4 => proptest::sample::select(TYPES.to_vec()), 1 => any::<u16>()],
            proptest::collection::vec(body_byte, 0..=96),
            prop_oneof![4 => Just(None), 1 => any::<u32>().prop_map(Some)],
            prop_oneof![4 => Just(None), 1 => any::<usize>().prop_map(Some)],
        )
            .prop_map(|(packet_type, body, length, cut)| {
                let length = length.unwrap_or((HEADER_LEN + body.len()) as u32);
                let mut bytes = packet_type.to_le_bytes().to_vec();
                bytes.extend_from_slice(&[0, 0]);
                bytes.extend_from_slice(&length.to_le_bytes());
                bytes.extend_from_slice(&body);
                if let Some(cut) = cut {
                    bytes.truncate(cut % (bytes.len() + 1));
                }
                bytes
            })
    }

    fn unicode_string() -> impl Strategy<Value = UnicodeString> {
        proptest::collection::vec(any::<u8>(), 0..=8).prop_map(UnicodeString::from_bytes)
    }

    fn blob() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..=8)
    }

    /// Every packet variant with arbitrary field values and every optional field on either side.
    fn packet_value() -> impl Strategy<Value = Packet<'static>> {
        prop_oneof![
            (any::<u8>(), any::<u8>(), any::<u16>(), any::<u16>()).prop_map(|(a, b, c, d)| {
                Packet::HandshakeRequest(HandshakeRequest {
                    ver_major: a,
                    ver_minor: b,
                    client_version: c,
                    extended_auth: d,
                })
            }),
            (
                any::<u32>(),
                any::<u8>(),
                any::<u8>(),
                any::<u16>(),
                any::<u16>()
            )
                .prop_map(|(e, a, b, c, d)| Packet::HandshakeResponse(
                    HandshakeResponse {
                        error_code: e,
                        ver_major: a,
                        ver_minor: b,
                        server_version: c,
                        extended_auth: d,
                    }
                )),
            (
                any::<u32>(),
                proptest::option::of(any::<u64>()),
                proptest::option::of(blob()),
            )
                .prop_map(|(caps_flags, reauth_tunnel_context, cookie)| {
                    Packet::TunnelCreate(TunnelCreate {
                        caps_flags,
                        reauth_tunnel_context,
                        paa_cookie: cookie.map(PaaCookie::from_bytes),
                    })
                }),
            (
                any::<u16>(),
                any::<u32>(),
                proptest::option::of(any::<u32>()),
                proptest::option::of(any::<u32>()),
                proptest::option::of((any::<[u8; 16]>(), unicode_string())),
                proptest::option::of(unicode_string()),
            )
                .prop_map(|(v, s, id, caps, soh, consent)| {
                    Packet::TunnelResponse(TunnelResponse {
                        server_version: v,
                        status_code: s,
                        tunnel_id: id,
                        caps_flags: caps,
                        soh_request: soh
                            .map(|(nonce, server_cert)| SohRequest { nonce, server_cert }),
                        consent_msg: consent,
                    })
                }),
            (unicode_string(), proptest::option::of(blob())).prop_map(|(name, soh)| {
                Packet::TunnelAuth(TunnelAuth {
                    client_name: name,
                    statement_of_health: soh,
                })
            }),
            (
                any::<u32>(),
                proptest::option::of(any::<u32>()),
                proptest::option::of(any::<u32>()),
                proptest::option::of(blob()),
            )
                .prop_map(|(e, r, i, s)| Packet::TunnelAuthResponse(
                    TunnelAuthResponse {
                        error_code: e,
                        redir_flags: r,
                        idle_timeout: i,
                        soh_response: s,
                    }
                )),
            (
                proptest::collection::vec(unicode_string(), 0..=4),
                proptest::collection::vec(unicode_string(), 0..=4),
                any::<u16>(),
                any::<u16>(),
            )
                .prop_map(|(resources, alt_resources, port, protocol)| {
                    Packet::ChannelCreate(ChannelCreate {
                        resources,
                        alt_resources,
                        port,
                        protocol,
                    })
                }),
            (
                any::<u32>(),
                proptest::option::of(any::<u32>()),
                proptest::option::of(any::<u16>()),
                proptest::option::of(blob()),
            )
                .prop_map(|(e, c, p, a)| Packet::ChannelResponse(ChannelResponse {
                    error_code: e,
                    channel_id: c,
                    udp_port: p,
                    authn_cookie: a,
                })),
            Just(Packet::Data(&[0x03, 0x00, 0x00, 0x13])),
            Just(Packet::KeepAlive),
            any::<u32>().prop_map(|status_code| Packet::CloseChannel { status_code }),
            any::<u32>().prop_map(|status_code| Packet::CloseChannelResponse { status_code }),
        ]
    }

    proptest! {
        // ADR-0008: the server-to-client packets arrive from a gateway the client does not
        // control, and their packetLength, cbLen, cbDataLen and counts are the gateway's.
        // Malformed bytes must surface as a typed `DecodeError`, never a panic / overflow / OOB.
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// Undirected bytes, which exercise the header: the bodies are driven by the two
        /// properties after it.
        #[test]
        fn decode_never_panics_on_arbitrary_input(
            bytes in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = Packet::decode(&bytes);
        }

        /// Whatever decodes re-encodes to a packet that decodes to the same value.
        #[test]
        fn decode_never_panics_and_what_decodes_round_trips(bytes in packet_bytes()) {
            if let Ok(packet) = Packet::decode(&bytes) {
                let encoded = packet.encode().unwrap();
                prop_assert_eq!(Packet::decode(&encoded).unwrap(), packet);
            }
        }

        /// A valid packet with up to three bytes overwritten and possibly cut short, so the
        /// optional fields after a nonce, a count or a length are reached with malformed values.
        #[test]
        fn decode_never_panics_on_a_corrupted_packet(
            packet in packet_value(),
            edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..=3),
            cut in proptest::option::of(any::<usize>()),
        ) {
            let mut bytes = packet.encode().unwrap();
            for (at, value) in edits {
                let at = at % bytes.len();
                bytes[at] = value;
            }
            if let Some(cut) = cut {
                bytes.truncate(cut % (bytes.len() + 1));
            }
            if let Ok(decoded) = Packet::decode(&bytes) {
                let encoded = decoded.encode().unwrap();
                prop_assert_eq!(Packet::decode(&encoded).unwrap(), decoded);
            }
        }

        /// Every packet value encodes to bytes that decode back to it.
        #[test]
        fn every_packet_encodes_to_bytes_that_decode_to_it(packet in packet_value()) {
            let encoded = packet.encode().unwrap();
            prop_assert_eq!(Packet::decode(&encoded).unwrap(), packet);
        }
    }
}
