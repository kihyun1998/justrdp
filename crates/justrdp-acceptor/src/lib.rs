#![no_std]
#![forbid(unsafe_code)]
#![doc = "RDP server connection acceptance state machine for JustRDP."]
#![doc = ""]
#![doc = "This crate implements a no-I/O finite state machine that drives the"]
#![doc = "full RDP server connection sequence (MS-RDPBCGR 1.3.1.1, server side)."]
#![doc = "The caller is responsible for network I/O -- this crate only encodes/"]
#![doc = "decodes PDUs and manages the connection state."]
#![doc = ""]
#![doc = "Mirror of `justrdp-connector` from the server perspective."]

#[cfg(feature = "alloc")]
extern crate alloc;

mod acceptor;
mod config;
mod encode_helpers;
mod error;
mod result;
mod sequence;
mod state;

pub use acceptor::ServerAcceptor;
pub use config::{AcceptorConfig, AcceptorConfigBuilder};
pub use error::{AcceptorError, AcceptorErrorKind, AcceptorResult};
pub use result::{AcceptanceResult, Written};
pub use sequence::Sequence;
pub use state::ServerAcceptorState;
