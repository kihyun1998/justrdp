#![no_std]
#![forbid(unsafe_code)]

//! Audio Output Virtual Channel -- MS-RDPEA
//!
//! Implements the RDPSND protocol for audio playback redirection
//! between RDP server and client.
//!
//! Supports both SVC (`"rdpsnd"`) and DVC (`AUDIO_PLAYBACK_DVC`,
//! `AUDIO_PLAYBACK_LOSSY_DVC`) transport modes.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
mod backend;
#[cfg(feature = "alloc")]
mod decoder;
#[cfg(feature = "alloc")]
mod engine;
#[cfg(feature = "alloc")]
mod processor;
#[cfg(feature = "alloc")]
mod processor_dvc;

#[cfg(feature = "alloc")]
pub use backend::RdpsndBackend;
#[cfg(feature = "alloc")]
pub use decoder::make_decoder;
#[cfg(feature = "alloc")]
pub use processor::RdpsndClient;
#[cfg(feature = "alloc")]
pub use processor_dvc::{RdpsndDvcClient, RdpsndLossyDvcClient};
