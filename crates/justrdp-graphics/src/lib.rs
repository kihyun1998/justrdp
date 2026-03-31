#![no_std]
#![forbid(unsafe_code)]
#![doc = "Bitmap codec implementations for JustRDP."]
#![doc = ""]
#![doc = "Implements Interleaved RLE (RDP 4.0/5.0), Planar, and RDP 6.0 codecs."]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod planar;

#[cfg(feature = "alloc")]
pub mod rfx;

#[cfg(feature = "alloc")]
pub mod rle;
