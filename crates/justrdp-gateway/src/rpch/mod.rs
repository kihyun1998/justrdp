#![forbid(unsafe_code)]

//! **TsProxy RPC interface** (MS-TSGU §3.1.4) — the legacy
//! RPC-over-HTTP API that Windows RD Gateway exposes on top of the
//! RPC-over-HTTP v2 tunnel provided by `justrdp-rpch`.
//!
//! Interface identity (MS-TSGU §1.9):
//!
//! - UUID: `44e265dd-7daf-42cd-8560-3cdb6e7a2729`
//! - Version: 1.3
//! - Transfer syntax: NDR 2.0
//!
//! # Module layout
//!
//! - [`types`] — every `TSG_*` structure and union from §2.2.9 with
//!   NDR encode/decode. All of the union arms needed for the
//!   minimum-viable-tunnel path are implemented; the messaging
//!   arms (`TSG_PACKET_MSG_*`, `TSG_PACKET_REAUTH`) are stubbed.
//! - [`methods`] — per-method argument marshallers / response
//!   unmarshallers, one for each of the 8 on-wire opnums. Also
//!   owns the non-NDR wire formats used by
//!   `TsProxySetupReceivePipe` (opnum 8) and `TsProxySendToServer`
//!   (opnum 9).
//! - [`errors`] — `E_PROXY_*` HRESULT constants and the
//!   `HRESULT_CODE()` low-word variants (DWORD path).
//! - [`client`] — `TsProxyClient` high-level wrapper driven by an
//!   `RpchTunnel`. Call-sequence enforcement (Start → Connected →
//!   Authorized → ChannelCreated → PipeCreated) lives here.
//!
//! # Scope not yet implemented
//!
//! - `TsProxyMakeTunnelCall` (opnum 3): consent / service message
//!   long-poll. Only needed when the server negotiates
//!   `TSG_MESSAGING_CAP_*` capabilities.
//! - `TSG_PACKET_REAUTH`: reauthentication flow. Out of scope until
//!   CredSSP re-auth is wired in.

pub mod client;
pub mod errors;
pub mod methods;
pub mod types;

pub use client::{TsProxyClient, TsProxyClientError};
pub use errors::{
    E_PROXY_ALREADYDISCONNECTED, E_PROXY_CAPABILITYMISMATCH,
    E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED, E_PROXY_COOKIE_BADPACKET, E_PROXY_INTERNALERROR,
    E_PROXY_NAP_ACCESSDENIED, E_PROXY_NOCERTAVAILABLE, E_PROXY_QUARANTINE_ACCESSDENIED,
    E_PROXY_RAP_ACCESSDENIED, E_PROXY_UNSUPPORTED_AUTHENTICATION_METHOD, ERROR_ACCESS_DENIED,
    ERROR_GRACEFUL_DISCONNECT, ERROR_SUCCESS, HRESULT_CODE_E_PROXY_CONNECTIONABORTED,
    HRESULT_CODE_E_PROXY_INTERNALERROR, HRESULT_CODE_E_PROXY_MAXCONNECTIONSREACHED,
    HRESULT_CODE_E_PROXY_NOTSUPPORTED, HRESULT_CODE_E_PROXY_SESSIONTIMEOUT,
    HRESULT_CODE_E_PROXY_TS_CONNECTFAILED,
};
pub use methods::{
    build_authorize_tunnel_stub, build_close_channel_stub, build_close_tunnel_stub,
    build_create_channel_stub, build_create_tunnel_stub, build_send_to_server_message,
    build_setup_receive_pipe_message, parse_authorize_tunnel_response, parse_close_channel_response,
    parse_close_tunnel_response, parse_create_channel_response, parse_create_tunnel_response,
    CreateChannelResponse, CreateTunnelResponse, OPNUM_TS_PROXY_AUTHORIZE_TUNNEL,
    OPNUM_TS_PROXY_CLOSE_CHANNEL, OPNUM_TS_PROXY_CLOSE_TUNNEL, OPNUM_TS_PROXY_CREATE_CHANNEL,
    OPNUM_TS_PROXY_CREATE_TUNNEL, OPNUM_TS_PROXY_MAKE_TUNNEL_CALL, OPNUM_TS_PROXY_SEND_TO_SERVER,
    OPNUM_TS_PROXY_SETUP_RECEIVE_PIPE,
};
pub use types::{
    ContextHandle, TsEndpointInfo, TsgNapCapability, TsgPacket, TsgPacketAuth,
    TsgPacketCapabilities, TsgPacketCapsResponse, TsgPacketHeader, TsgPacketQuarEncResponse,
    TsgPacketQuarRequest, TsgPacketResponse, TsgPacketVersionCaps, TsgRedirectionFlags,
    TSG_CAPABILITY_TYPE_NAP, TSG_COMPONENT_ID_TR, TSG_MESSAGING_CAP_CONSENT_SIGN,
    TSG_MESSAGING_CAP_REAUTH, TSG_MESSAGING_CAP_SERVICE_MSG, TSG_NAP_CAPABILITY_IDLE_TIMEOUT,
    TSG_NAP_CAPABILITY_QUAR_SOH, TSG_PACKET_TYPE_AUTH, TSG_PACKET_TYPE_CAPS_RESPONSE,
    TSG_PACKET_TYPE_HEADER, TSG_PACKET_TYPE_MESSAGE_PACKET, TSG_PACKET_TYPE_MSGREQUEST_PACKET,
    TSG_PACKET_TYPE_QUARCONFIGREQUEST, TSG_PACKET_TYPE_QUARENC_RESPONSE,
    TSG_PACKET_TYPE_QUARREQUEST, TSG_PACKET_TYPE_REAUTH, TSG_PACKET_TYPE_RESPONSE,
    TSG_PACKET_TYPE_VERSIONCAPS, TSPROXY_INTERFACE_UUID,
};
