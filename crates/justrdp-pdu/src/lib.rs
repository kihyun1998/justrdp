#![no_std]
#![forbid(unsafe_code)]
#![doc = "RDP Protocol Data Unit definitions for JustRDP."]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use justrdp_core::{self as core, Decode, Encode, ReadCursor, WriteCursor};
pub use justrdp_core::{DecodeError, DecodeResult, EncodeError, EncodeResult};

pub mod mcs;
pub mod pcb;
pub mod tpkt;
pub mod x224;
