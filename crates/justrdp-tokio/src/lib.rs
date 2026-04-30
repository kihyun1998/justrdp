#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

//! Tokio runtime adapter for JustRDP — pure-async client (v2) +
//! native transports + gateway transports.
//!
//! # `AsyncRdpClient` v2
//!
//! Pure async wrapper over [`WebClient`](justrdp_async::WebClient) +
//! [`ActiveSession`](justrdp_async::ActiveSession). v2 replaces v1's
//! `spawn_blocking` thread per session with a `tokio::spawn` task,
//! eliminating v1's "disconnect 지연 during in-flight next_event"
//! limitation.
//!
//! Public surface preserved byte-for-byte from v1 — embedders see no
//! breaking change.
//!
//! ## Threading model
//!
//! Each session pins one tokio task (NOT a blocking-pool thread). The
//! task owns the [`ActiveSession`](justrdp_async::ActiveSession)
//! exclusively; commands flow in via an mpsc channel and events flow
//! out via another. The task exits when:
//!
//! - a [`AsyncRdpClient::disconnect`] command is processed (graceful), or
//! - the command channel closes (caller dropped without `disconnect`), or
//! - `ActiveSession::next_events` returns an unrecoverable error, or
//! - the event channel's receiver was dropped.
//!
//! ## Cancel-safety
//!
//! [`AsyncRdpClient::disconnect`] sends a graceful Disconnect command.
//! The async pump uses `tokio::select!` to multiplex command receives
//! with event polls — when a Disconnect arrives mid-await of
//! `next_events`, the select cancels the pending future and
//! `session.shutdown()` runs immediately. v2 disconnect latency is
//! "scheduling tick" instead of v1's "next server frame or TCP
//! keepalive".
//!
//! Dropping `AsyncRdpClient` without calling `disconnect` is sound: the
//! pump observes its `cmd_rx` close and runs a best-effort
//! `session.shutdown()` before exiting.

extern crate alloc;

#[cfg(feature = "native-tcp")]
mod native_tcp;

#[cfg(feature = "native-tls")]
mod native_tls;

#[cfg(feature = "native-tls-os")]
mod native_tls_os;

#[cfg(feature = "native-nla")]
mod native_nla;

// v2 of `AsyncRdpClient` requires the full async stack (TCP + TLS +
// CredSSP). Gating these modules behind `native-nla` keeps minimal
// builds (e.g. embedders that only need the native_tls family for
// their own composition) free of the dependency.
#[cfg(feature = "native-nla")]
mod client;

#[cfg(feature = "native-nla")]
mod pump;

#[cfg(feature = "native-nla")]
mod translate;

#[cfg(feature = "native-nla")]
mod verifier_bridge;

#[cfg(feature = "gateway")]
pub mod gateway;

#[cfg(feature = "native-nla")]
pub use client::AsyncRdpClient;

#[cfg(feature = "native-tcp")]
pub use native_tcp::NativeTcpTransport;

#[cfg(feature = "native-tls")]
pub use native_tls::{NativeTlsTransport, NativeTlsUpgrade};

#[cfg(feature = "native-tls-os")]
pub use native_tls_os::{NativeTlsOsTransport, NativeTlsOsUpgrade};

#[cfg(feature = "native-nla")]
pub use native_nla::NativeCredsspDriver;

// Re-export the surface a tokio embedder needs so callers do not have
// to depend on `justrdp-blocking` / `justrdp-input` directly.
pub use justrdp_blocking::{ConnectError, RdpEvent, ReconnectPolicy, RuntimeError};
pub use justrdp_connector::{ArcCookie, Config};
pub use justrdp_input::{LockKeys, MouseButton, Scancode};
pub use justrdp_tls::ServerCertVerifier;
