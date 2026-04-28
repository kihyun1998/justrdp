#![no_std]
#![forbid(unsafe_code)]

//! Device Redirection Virtual Channel -- MS-RDPEFS
//!
//! Implements the File System Virtual Channel Extension protocol for
//! device redirection between RDP client and server.
//!
//! # Usage
//!
//! ```ignore
//! use justrdp_rdpdr::RdpdrClient;
//! use justrdp_svc::StaticChannelSet;
//!
//! let rdpdr = RdpdrClient::new(Box::new(MyDeviceBackend));
//! let mut channels = StaticChannelSet::new();
//! channels.insert(Box::new(rdpdr)).unwrap();
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;
#[cfg(feature = "alloc")]
pub mod scard;

#[cfg(feature = "alloc")]
mod backend;
#[cfg(feature = "alloc")]
mod processor;
#[cfg(feature = "alloc")]
mod server;

#[cfg(feature = "alloc")]
pub use backend::{CreateResponse, DeviceIoError, DeviceIoResult, FileHandle, RdpdrBackend};
#[cfg(feature = "alloc")]
pub use processor::RdpdrClient;
#[cfg(feature = "alloc")]
pub use server::{
    AnnouncedDevice, FilesystemServer, FilesystemServerConfig, RdpServerFilesystemHandler,
};
