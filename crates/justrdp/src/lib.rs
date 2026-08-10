//! `justrdp` — a from-scratch, **sans-IO** RDP client library.
//!
//! The connect and session logic are pure state machines (bytes in → actions / bytes out); a
//! per-runtime adapter (`justrdp-tokio`) drives the socket and supplies the frame-update sink. The
//! *drive loop* itself is a few dozen lines — a match over [`connect::Action`] — and the rest of
//! the adapter is what deliberately does not belong in a sans-IO core: the TLS handshake, the
//! CredSSP token loop, per-stage timeouts and the session runners. This split keeps the core
//! testable offline, portable across runtimes, and host-agnostic.
//!
//! See ADR-0001 (sans-IO core), ADR-0002 (own the RDP protocol; depend on `rustls` + `sspi`),
//! ADR-0003 (phased codecs), and `docs/plan.md`.

pub mod connect;
pub mod cursor;
pub mod disconnect;
mod dvc;
mod egfx;
pub mod framebuffer;
pub mod input;
pub mod license_crypto;
pub mod session;
pub mod tls;

pub use connect::{
    Action, ActivationResult, ClientInfoConfig, ConnectConfig, ConnectError, ConnectStateMachine,
    Event, EventKind, LicenseConfig, LicenseEntropy, McsConnectResult, StaticChannel,
};
pub use cursor::{CursorEvent, CursorImage};
pub use disconnect::{DisconnectClass, DisconnectReason, ServerDisconnectCause};
pub use framebuffer::{FrameUpdate, Framebuffer};
pub use input::Scancode;
pub use justrdp_pdu::input::InputEvent;
pub use session::{ResizeError, SessionConfig, SessionError, SessionOutput, SessionStateMachine};
