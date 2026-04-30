#![forbid(unsafe_code)]

//! MS-TSGU (Remote Desktop Gateway) async transport family.
//!
//! Three Phase 1 transport variants (MS-TSGU §2.2.3.1):
//!
//! * **HTTP Transport** (`§2.2.3.1.1`) — two long-lived HTTP/1.1
//!   channels (RDG_OUT_DATA / RDG_IN_DATA), each authenticated via
//!   NTLMSSP HTTP-401 retry, MS-TSGU PDUs framed inside chunked
//!   bodies. Implemented by [`TsguHttpTransport`] (G3).
//! * **WebSocket Transport** (`§2.2.3.1.2`) — single TCP/TLS, HTTP/1.1
//!   `Upgrade: websocket` (with the same NTLM 401 retry), MS-TSGU
//!   PDUs carried as binary frames. Implemented by
//!   [`TsguWsTransport`] (G5).
//! * **RPC-over-HTTP** (legacy, `§3.4`) — paired IN/OUT TCP streams
//!   driving the TsProxy DCE/RPC interface. Implemented by
//!   [`TsguRpchTransport`] (G7-G9, separate sub-phase).
//!
//! All three expose [`WebTransport`](justrdp_async::WebTransport) so
//! [`WebClient::connect_via_gateway*`](justrdp_async::WebClient) can
//! run unmodified above them, with the inner RDP TLS / CredSSP
//! handshake nesting cleanly inside the outer gateway TLS.
//!
//! ## Threading model
//!
//! Plain async functions, no spawned tasks at this layer. The MS-TSGU
//! [`GatewayClient`](justrdp_gateway::GatewayClient) state machine is
//! pure no_std + alloc, so the same connector code that the blocking
//! tunnel drives can be reused as-is from async code — only the I/O
//! adapters in this module are runtime-specific.
//!
//! ## Status
//!
//! G1 (this commit): module skeleton, [`GatewayConfig`], outer TLS
//! connect helper. G2-G6 add the HTTP and WebSocket transport
//! families. G7-G9 add RPC-over-HTTP.

mod config;
pub(crate) mod connect;
pub(crate) mod error;
pub(crate) mod http_auth;
pub(crate) mod http_io;
pub(crate) mod http_transport;
pub(crate) mod inner_tls;
pub(crate) mod outer_tls;
pub(crate) mod random;
pub(crate) mod web_rw;
pub(crate) mod ws_auth;
pub(crate) mod ws_transport;

pub use config::GatewayConfig;
pub use connect::{connect_via_gateway, connect_via_gateway_ws};
pub use http_transport::TsguHttpTransport;
pub use inner_tls::{WebTransportTlsTransport, WebTransportTlsUpgrade};
pub use web_rw::WebTransportRw;
pub use ws_transport::TsguWsTransport;
