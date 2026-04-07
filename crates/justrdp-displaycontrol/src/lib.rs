#![no_std]
#![forbid(unsafe_code)]

//! Display Control Virtual Channel -- MS-RDPEDISP
//!
//! Implements the Display Control DVC for dynamic display resizing
//! and multi-monitor layout changes over RDP.
//!
//! # Usage
//!
//! ```ignore
//! use justrdp_displaycontrol::DisplayControlClient;
//! use justrdp_dvc::DrdynvcClient;
//!
//! let mut drdynvc = DrdynvcClient::new();
//! drdynvc.register(Box::new(DisplayControlClient::new()));
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
mod client;

#[cfg(feature = "alloc")]
pub use client::DisplayControlClient;

#[cfg(feature = "alloc")]
pub use pdu::{
    CapsPdu, MonitorLayoutEntry, MonitorLayoutPdu, MONITOR_PRIMARY, ORIENTATION_LANDSCAPE,
    ORIENTATION_LANDSCAPE_FLIPPED, ORIENTATION_PORTRAIT, ORIENTATION_PORTRAIT_FLIPPED,
};
