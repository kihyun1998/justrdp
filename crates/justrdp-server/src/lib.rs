#![no_std]
#![forbid(unsafe_code)]
#![doc = "Extensible RDP server skeleton for JustRDP."]
#![doc = ""]
#![doc = "Wraps `justrdp-acceptor`'s connection-acceptance state machine and"]
#![doc = "provides the runtime seam for active-session display/input handlers."]
#![doc = "All network I/O is the caller's responsibility -- the crate emits and"]
#![doc = "consumes raw byte buffers, mirroring the `justrdp-connector` pattern"]
#![doc = "from the server perspective."]
#![doc = ""]
#![doc = "Roadmap §11.2a -- Core Server Skeleton (v1)."]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod config;
mod error;
mod server;

pub use config::{
    DEFAULT_CHANNEL_CHUNK_LENGTH, DEFAULT_MAX_BITMAP_FRAGMENT_SIZE, MAX_BITMAP_FRAGMENT_SIZE_LIMIT,
    MAX_CHANNEL_CHUNK_LENGTH, RdpServerConfig, RdpServerConfigBuilder,
};
pub use error::{ServerConfigError, ServerError, ServerErrorKind, ServerResult};
pub use server::RdpServer;

// Re-export the acceptor-side types the driver depends on so callers don't
// need to add `justrdp-acceptor` to their `Cargo.toml` just to drive the
// state machine.
pub use justrdp_acceptor::{AcceptanceResult, Sequence, ServerAcceptorState, Written};
