#![no_std]
#![forbid(unsafe_code)]
#![doc = "RDP Protocol Data Unit definitions for JustRDP."]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use justrdp_core::{self as core, Decode, Encode, ReadCursor, WriteCursor};
pub use justrdp_core::{DecodeError, DecodeResult, EncodeError, EncodeResult};
pub use justrdp_derive::{Encode as DeriveEncode, Decode as DeriveDecode};

#[cfg(feature = "alloc")]
pub mod cms;
pub mod gcc;
#[cfg(feature = "alloc")]
pub mod kerberos;
pub mod mcs;
#[cfg(feature = "alloc")]
pub mod ntlm;
pub mod pcb;
pub mod rdp;
pub mod tpkt;
pub mod x224;
