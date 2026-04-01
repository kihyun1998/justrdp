#![no_std]
#![forbid(unsafe_code)]

//! Audio Output Virtual Channel -- MS-RDPEA
//!
//! Implements the RDPSND protocol for audio playback redirection
//! between RDP server and client.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
mod backend;
#[cfg(feature = "alloc")]
mod processor;

#[cfg(feature = "alloc")]
pub use backend::RdpsndBackend;
#[cfg(feature = "alloc")]
pub use processor::RdpsndClient;
