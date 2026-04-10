#![forbid(unsafe_code)]

//! # justrdp-blocking — Synchronous I/O Runtime
//!
//! This crate wraps the sans-I/O `justrdp-connector` + `justrdp-session` +
//! `justrdp-tls` stack with `std::net`-based blocking I/O and provides a
//! high-level [`RdpClient`] API. It is the *only* crate in the JustRDP
//! workspace allowed to own sockets.
//!
//! See roadmap §5.5 for the full scope. This is the scaffold commit:
//! the public API surface is defined and compiles, but most runtime
//! behavior is stubbed out pending follow-up commits covering:
//!
//! - TLS handshake wiring + `ServerCertVerifier` (roadmap §5.4)
//! - Post-handshake active-session pump
//! - Input helpers
//! - Auto-Reconnect runtime (roadmap §9.2)
//! - Session Redirection runtime (roadmap §9.3)
//! - License persistence (roadmap §9.15)
//!
//! # Quick example (target API — not yet functional)
//!
//! ```ignore
//! use justrdp_blocking::{RdpClient, RdpEvent};
//! use justrdp_connector::Config;
//!
//! let config = Config::builder().server("192.168.1.100:3389").build()?;
//! let mut client = RdpClient::connect(config)?;
//! while let Some(event) = client.next_event()? {
//!     match event {
//!         RdpEvent::GraphicsUpdate { .. } => { /* render */ }
//!         RdpEvent::Disconnected(_) => break,
//!         _ => {}
//!     }
//! }
//! ```

mod client;
mod error;
mod event;
mod reconnect;
mod transport;

pub use client::RdpClient;
pub use error::{ConnectError, RuntimeError};
pub use event::RdpEvent;
pub use reconnect::ReconnectPolicy;
