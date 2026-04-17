#![no_std]
#![forbid(unsafe_code)]

//! **MS-RPCE / MS-RPCH / NDR 2.0** marshaling for the RD Gateway
//! RPC-over-HTTP legacy transport (MS-TSGU §3.1).
//!
//! This crate is the low-level plumbing for the TsProxy RPC interface,
//! split into three orthogonal layers:
//!
//! - **[`ndr`]** — Network Data Representation v2.0 (C706 Chapter 14,
//!   MS-RPCE §2.2.5). Primitive types, alignment, pointers, arrays,
//!   wchar strings, structures, unions. No DCE/RPC knowledge.
//! - **[`pdu`]** (follow-up) — DCE/RPC connection-oriented PDUs from
//!   MS-RPCE §2.2.2 (BIND, BIND_ACK, REQUEST, RESPONSE, FAULT) plus
//!   RTS (MS-RPCH §2.2.3.5) for RPC-over-HTTP flow control.
//! - **[`http`]** (follow-up) — RPC-over-HTTP v2 dual-channel tunnel
//!   per MS-RPCH §3.2 (IN/OUT channels, CONN/A/B/C handshake,
//!   keepalive, channel recycling).
//!
//! TsProxy-specific IDL types (`TSG_PACKET*`, `TSENDPOINTINFO`,
//! `TsProxyCreateTunnel`, etc.) live in `justrdp-gateway::rpch` — this
//! crate owns the **generic** RPC-over-HTTP / NDR substrate that any
//! DCE/RPC interface would need.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod http;

#[cfg(feature = "alloc")]
pub mod ndr;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
pub mod tunnel;

#[cfg(feature = "std")]
pub mod blocking;

#[cfg(feature = "alloc")]
pub use ndr::{NdrDecoder, NdrEncoder, NdrError, NdrResult};

#[cfg(feature = "alloc")]
pub use http::{HttpError, HttpResponse, RpchChannel, RpchHttpRequest};

#[cfg(feature = "alloc")]
pub use tunnel::{
    HandshakeStage, OutboundAction, RpchTunnelConfig, RpchTunnelError, RpchTunnelState,
    peek_frag_length,
};

#[cfg(feature = "std")]
pub use blocking::{RpchTunnel, TunnelIoError};
