#![no_std]
#![forbid(unsafe_code)]

//! Clipboard Redirection Virtual Channel -- MS-RDPECLIP
//!
//! Implements the Clipboard Virtual Channel Extension protocol for
//! clipboard sharing between RDP client and server.
//!
//! # Usage
//!
//! ```ignore
//! use justrdp_cliprdr::CliprdrClient;
//! use justrdp_svc::StaticChannelSet;
//!
//! let cliprdr = CliprdrClient::new(Box::new(MyClipboardBackend));
//! let mut channels = StaticChannelSet::new();
//! channels.insert(Box::new(cliprdr)).unwrap();
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
mod backend;
#[cfg(feature = "alloc")]
mod processor;

#[cfg(feature = "alloc")]
pub use backend::{
    CliprdrBackend, ClipboardError, ClipboardResult, FormatDataResponse, FormatListResponse,
};
#[cfg(feature = "alloc")]
pub use processor::CliprdrClient;
