#![no_std]
#![forbid(unsafe_code)]

//! Remote Programs Virtual Channel (RAIL) -- MS-RDPERP
//!
//! Implements the RemoteApp protocol for launching and managing
//! remote applications over an RDP session.
//!
//! # Usage
//!
//! ```ignore
//! use justrdp_rail::RailClient;
//! use justrdp_svc::StaticChannelSet;
//!
//! let rail = RailClient::new(Box::new(MyRailBackend));
//! let mut channels = StaticChannelSet::new();
//! channels.insert(Box::new(rail)).unwrap();
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
pub use backend::RailBackend;
#[cfg(feature = "alloc")]
pub use processor::RailClient;
