#![no_std]
#![forbid(unsafe_code)]

//! Remote Desktop Gateway -- MS-TSGU
//!
//! Implements the Terminal Services Gateway tunnel used to carry RDP
//! traffic over HTTP(S), WebSocket, and (legacy) RPC-over-HTTP. This
//! crate provides the PDU layer and, eventually, the gateway-side
//! connector state machine; it is transport-agnostic and reuses
//! Phase 2 authentication (NTLM/Kerberos) from `justrdp-connector`.
//!
//! Step A (current): crate scaffolding + HTTP Transport PDUs.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
pub mod client;

#[cfg(feature = "alloc")]
pub mod http;

#[cfg(feature = "alloc")]
pub mod auth;

#[cfg(feature = "alloc")]
pub mod ws;

#[cfg(feature = "std")]
pub mod transport;

#[cfg(feature = "std")]
pub mod ws_transport;

#[cfg(feature = "std")]
pub use transport::{ConnectError, GatewayConnection};

#[cfg(feature = "std")]
pub use ws_transport::{MaskSource, WsConnectError, WsGatewayConnection};

#[cfg(feature = "alloc")]
pub use auth::{
    base64_decode, base64_encode, build_authorization_header, parse_www_authenticate, AuthScheme,
    NtlmAuthState, NtlmClient, NtlmCredentials, NtlmError, NtlmRandom,
};

#[cfg(feature = "alloc")]
pub use http::{
    encode_chunk, encode_final_chunk, format_guid_braces, ChunkError, ChunkedDecoder,
    PreambleSkipper, RdgHttpRequest, RdgMethod, DEFAULT_URL_PATH, HEADER_RDG_CONNECTION_ID,
    HEADER_RDG_CORRELATION_ID, HEADER_RDG_USER_ID, METHOD_RDG_IN_DATA, METHOD_RDG_OUT_DATA,
    OUT_CHANNEL_PREAMBLE_SIZE,
};

#[cfg(feature = "alloc")]
pub use client::{
    decode_data, find_packet_size, GatewayClient, GatewayClientConfig, GatewayClientState,
    GatewayError, GatewayResult, Written,
};

#[cfg(feature = "alloc")]
pub use pdu::{
    CloseChannelKind, CloseChannelPdu, HandshakeRequestPdu, HandshakeResponsePdu, HttpByteBlob,
    HttpPacketHeader, HttpUnicodeString, KeepalivePdu, ReauthMessagePdu, TunnelAuthPdu,
    ChannelCreatePdu, ChannelResponsePdu, DataPdu, ServiceMessagePdu, TunnelAuthResponsePdu,
    TunnelCreatePdu, TunnelResponsePdu, CHANNEL_CREATE_FIXED_SIZE, CHANNEL_MAX_ALT_RESOURCES,
    CHANNEL_MAX_RESOURCES, CHANNEL_RESPONSE_FIXED_SIZE, CLOSE_CHANNEL_SIZE, DATA_PACKET_MIN_SIZE,
    HTTP_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE, HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
    HTTP_CHANNEL_RESPONSE_FIELD_UDPPORT, RDG_CHANNEL_PROTOCOL_TCP, SERVICE_MESSAGE_MIN_SIZE,
    ERROR_GRACEFUL_DISCONNECT, E_PROXY_QUARANTINE_ACCESSDENIED, HANDSHAKE_REQUEST_SIZE,
    HANDSHAKE_RESPONSE_SIZE, HTTP_CAPABILITY_IDLE_TIMEOUT, HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN,
    HTTP_CAPABILITY_MESSAGING_SERVICE_MSG, HTTP_CAPABILITY_REAUTH, HTTP_CAPABILITY_TYPE_QUAR_SOH,
    HTTP_CAPABILITY_UDP_TRANSPORT, HTTP_EXTENDED_AUTH_NONE, HTTP_EXTENDED_AUTH_PAA,
    HTTP_EXTENDED_AUTH_SC, HTTP_EXTENDED_AUTH_SSPI_NTLM, HTTP_TUNNEL_AUTH_FIELD_SOH,
    HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT, HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS,
    HTTP_TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE, HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE,
    HTTP_TUNNEL_PACKET_FIELD_REAUTH, HTTP_TUNNEL_REDIR_DISABLE_ALL, HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD,
    HTTP_TUNNEL_REDIR_DISABLE_DRIVE, HTTP_TUNNEL_REDIR_DISABLE_PNP, HTTP_TUNNEL_REDIR_DISABLE_PORT,
    HTTP_TUNNEL_REDIR_DISABLE_PRINTER, HTTP_TUNNEL_REDIR_ENABLE_ALL,
    HTTP_TUNNEL_RESPONSE_FIELD_CAPS, HTTP_TUNNEL_RESPONSE_FIELD_CONSENT_MSG,
    HTTP_TUNNEL_RESPONSE_FIELD_SOH_REQ, HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID, KEEPALIVE_SIZE,
    PACKET_HEADER_SIZE, PKT_TYPE_CHANNEL_CREATE, PKT_TYPE_CHANNEL_RESPONSE,
    PKT_TYPE_CLOSE_CHANNEL, PKT_TYPE_CLOSE_CHANNEL_RESPONSE, PKT_TYPE_DATA,
    PKT_TYPE_EXTENDED_AUTH_MSG, PKT_TYPE_HANDSHAKE_REQUEST, PKT_TYPE_HANDSHAKE_RESPONSE,
    PKT_TYPE_KEEPALIVE, PKT_TYPE_REAUTH_MESSAGE, PKT_TYPE_SERVICE_MESSAGE, PKT_TYPE_TUNNEL_AUTH,
    PKT_TYPE_TUNNEL_AUTH_RESPONSE, PKT_TYPE_TUNNEL_CREATE, PKT_TYPE_TUNNEL_RESPONSE,
    REAUTH_MESSAGE_SIZE, STATUS_SUCCESS, TUNNEL_AUTH_FIXED_SIZE, TUNNEL_AUTH_RESPONSE_FIXED_SIZE,
    TUNNEL_CREATE_FIXED_SIZE, TUNNEL_RESPONSE_FIXED_SIZE,
};
