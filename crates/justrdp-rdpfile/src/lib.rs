#![no_std]
#![forbid(unsafe_code)]
#![doc = "RDP file (.rdp) parser and writer."]
#![doc = ""]
#![doc = "Parses the `key:type:value` text format used by mstsc.exe."]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod parser;

#[cfg(feature = "alloc")]
pub use parser::*;
