#![no_std]
#![forbid(unsafe_code)]

//! Audio Input Virtual Channel -- MS-RDPEAI
//!
//! Implements the RDPEAI protocol for audio input (microphone) redirection
//! over RDP using the `AUDIO_INPUT` dynamic virtual channel.
//!
//! # Usage
//!
//! ```ignore
//! use justrdp_rdpeai::AudioInputClient;
//! use justrdp_dvc::DrdynvcClient;
//!
//! let mut drdynvc = DrdynvcClient::new();
//! drdynvc.register(Box::new(AudioInputClient::new()));
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
mod client;

#[cfg(feature = "alloc")]
pub use client::AudioInputClient;

// Re-export AudioFormat from justrdp-rdpsnd for convenience.
#[cfg(feature = "alloc")]
pub use justrdp_rdpsnd::pdu::{AudioFormat, WaveFormatTag};

#[cfg(feature = "alloc")]
pub use pdu::{
    MSG_SNDIN_DATA, MSG_SNDIN_DATA_INCOMING, MSG_SNDIN_FORMATCHANGE, MSG_SNDIN_FORMATS,
    MSG_SNDIN_OPEN, MSG_SNDIN_OPEN_REPLY, MSG_SNDIN_VERSION, SNDIN_VERSION_1, SNDIN_VERSION_2,
};
