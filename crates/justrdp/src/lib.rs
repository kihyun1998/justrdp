//! `justrdp` — a from-scratch, **sans-IO** RDP client library.
//!
//! The connect and session logic are pure state machines (bytes in → actions / bytes out); a thin
//! per-runtime adapter (`justrdp-tokio`, ~30 lines) drives the socket and supplies the frame-update
//! sink. This keeps the core testable offline, portable across runtimes, and host-agnostic.
//!
//! See ADR-0001 (sans-IO core), ADR-0002 (own the RDP protocol; depend on `rustls` + `sspi`),
//! ADR-0003 (phased codecs), and `docs/plan.md`.

pub mod connect;
pub mod tls;

pub use connect::{
    Action, ClientInfoConfig, ConnectConfig, ConnectError, ConnectStateMachine, Event, EventKind,
    McsConnectResult, StaticChannel,
};
