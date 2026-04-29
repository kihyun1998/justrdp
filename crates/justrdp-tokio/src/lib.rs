#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

//! Tokio runtime adapter for [`justrdp_blocking::RdpClient`].
//!
//! `AsyncRdpClient` wraps the synchronous `RdpClient` on a single
//! [`tokio::task::spawn_blocking`] worker, exposing the connect /
//! `next_event` / `send_*` / `disconnect` surface as `async fn`. The
//! crate exists so embedders running on tokio (Tauri, Iced/eframe with
//! a tokio bridge, axum gateways, tokio-bound TUIs) do not have to
//! re-implement the spawn_blocking + channel plumbing themselves.
//!
//! # Threading model
//!
//! Each session pins one worker on the tokio blocking pool. The worker
//! owns the [`RdpClient`] exclusively; commands flow in via an mpsc
//! channel and events flow out via another. The worker exits when:
//!
//! - a [`AsyncRdpClient::disconnect`] command is processed (graceful), or
//! - the command channel closes (caller dropped without `disconnect`), or
//! - the underlying connection drops (server-initiated or transport error).
//!
//! # Cancel-safety
//!
//! [`AsyncRdpClient::disconnect`] sends a graceful Disconnect command
//! that the worker processes between event reads. If the worker is
//! currently blocked inside [`RdpClient::next_event`] waiting for the
//! next server frame, the disconnect is processed when that read
//! returns (a server frame arrives, the connection drops, or — for
//! idle sessions — when TCP keep-alive fires). A more aggressive
//! half-close shutdown is tracked as a roadmap §5.6.2 follow-up.
//!
//! Dropping `AsyncRdpClient` without calling `disconnect` is sound but
//! does not preempt an in-flight `next_event`; the worker exits on its
//! next loop iteration once both channels are closed.
//!
//! [`RdpClient`]: justrdp_blocking::RdpClient
//! [`RdpClient::next_event`]: justrdp_blocking::RdpClient::next_event

mod client;
mod pump;

pub use client::AsyncRdpClient;

// Re-export the surface a tokio embedder needs so callers do not have
// to depend on `justrdp-blocking` / `justrdp-input` directly.
pub use justrdp_blocking::{ConnectError, RdpEvent, ReconnectPolicy, RuntimeError};
pub use justrdp_connector::{ArcCookie, Config};
pub use justrdp_input::{LockKeys, MouseButton, Scancode};
pub use justrdp_tls::ServerCertVerifier;
