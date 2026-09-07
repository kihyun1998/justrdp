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

/// The `fuzz/` lane's door into the EGFX graphics processor (#267) — **not host API**.
///
/// Compiled only under the `fuzzing` feature, which the workspace build never enables, so
/// nothing here widens the published surface. `egfx` and `dvc` stay private modules; this
/// re-exports the two items a libFuzzer target needs to drive
/// [`GraphicsProcessor`](fuzzing::GraphicsProcessor) the way the manager does.
///
/// **Drive the pair, in the manager's order.** `DvcProcessor::process` and
/// `DvcProcessor::flush_frames` are one contract: `dvc::Drdynvc::on_svc_payload` propagates a
/// processor error with `?`, and `session.rs`'s flush runs *after* that — so a `flush_frames`
/// on a payload whose `process` returned `Err` is a sequence the live path cannot produce.
/// Two server-controlled `u32`s (a `MapSurfaceToOutput` origin) are reachable only through the
/// second call, which is why exposing `process` alone would leave them undriven.
///
/// **`#[doc(hidden)]` is load-bearing, not tidiness.** docs.rs builds with `--all-features`
/// by default and this crate carries no `[package.metadata.docs.rs]`, so without it the module
/// would render in published documentation as though it were API — which is the one thing the
/// feature exists to avoid. The paragraph above would then be advisory where it has to be
/// structural.
#[doc(hidden)]
#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    pub use crate::dvc::{DvcProcessor, ProcessorOutput};
    pub use crate::egfx::GraphicsProcessor;
}
