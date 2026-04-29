#![forbid(unsafe_code)]
#![no_std]
#![doc = "Runtime-agnostic async core for JustRDP."]
#![doc = ""]
#![doc = "Hosts the [`WebTransport`] byte-pipe trait, the [`WebClient`]"]
#![doc = "connection driver, the [`ActiveSession`] post-handshake pump, and the"]
#![doc = "[`TlsUpgrade`] / [`CredsspDriver`] adapter traits — the shared substrate"]
#![doc = "that lets the same async client run unmodified on top of any byte"]
#![doc = "transport (browser WebSocket, native TCP+TLS, RD Gateway, WebRTC"]
#![doc = "DataChannel, …)."]
#![doc = ""]
#![doc = "Embedders normally consume one of the runtime-bound wrappers"]
#![doc = "(`justrdp-web` for browser/wasm, `justrdp-tokio` for native) instead"]
#![doc = "of depending on this crate directly."]

extern crate alloc;

mod driver;
mod error;
mod session;
mod transport;

pub use driver::{CredsspDriver, DriverError, TlsUpgrade, WebClient, MAX_HANDSHAKE_PDU_SIZE};
pub use error::{TransportError, TransportErrorKind};
pub use session::{ActiveSession, PointerEvent, SessionEvent};
pub use transport::WebTransport;
