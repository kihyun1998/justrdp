#![no_std]
#![forbid(unsafe_code)]
#![doc = "Bulk compression and decompression for JustRDP."]
#![doc = ""]
#![doc = "Implements MPPC 8K, MPPC 64K, NCRUSH, and XCRUSH algorithms."]

#[cfg(feature = "alloc")]
extern crate alloc;
