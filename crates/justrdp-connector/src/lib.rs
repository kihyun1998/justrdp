#![no_std]
#![forbid(unsafe_code)]
#![doc = "RDP client connection state machine for JustRDP."]
#![doc = ""]
#![doc = "This crate implements a no-I/O finite state machine that drives the"]
#![doc = "full RDP client connection sequence (MS-RDPBCGR 1.3.1.1). The caller"]
#![doc = "is responsible for network I/O -- this crate only encodes/decodes PDUs"]
#![doc = "and manages the connection state."]

#[cfg(feature = "alloc")]
extern crate alloc;

mod config;
mod connector;
pub mod credssp;
mod encode_helpers;
mod error;
mod result;
mod sequence;
mod state;

pub use config::{Config, ConfigBuilder};
pub use connector::ClientConnector;
pub use credssp::{CredsspRandom, CredsspSequence, CredsspState};
pub use error::{ConnectorError, ConnectorErrorKind, ConnectorResult};
pub use result::{ConnectionResult, Written};
pub use sequence::Sequence;
pub use state::ClientConnectorState;
