#![no_std]
#![forbid(unsafe_code)]
#![doc = "Bitmap codec implementations for JustRDP."]
#![doc = ""]
#![doc = "Codecs: Interleaved RLE (RDP 4.0/5.0), Planar (RDP 6.0 Bitmap Compression),"]
#![doc = "RemoteFX (RFX), NSCodec, ClearCodec, and Pointer decoding."]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod clearcodec;

#[cfg(feature = "alloc")]
pub mod nscodec;

#[cfg(feature = "alloc")]
pub mod planar;

#[cfg(feature = "alloc")]
pub mod pointer;

#[cfg(feature = "alloc")]
pub mod rfx;

#[cfg(feature = "alloc")]
pub mod rle;

#[cfg(feature = "alloc")]
pub mod utils;

#[cfg(feature = "alloc")]
pub mod avc;

// ── Public re-exports for primary types ──

#[cfg(feature = "alloc")]
pub use rle::{BitsPerPixel, RleDecompressor, RleError};

#[cfg(feature = "alloc")]
pub use planar::{PlanarCompressor, PlanarDecompressor, PlanarEncoderConfig, PlanarError};

#[cfg(feature = "alloc")]
pub use nscodec::{NsCodecDecompressor, NsCodecError};

#[cfg(feature = "alloc")]
pub use clearcodec::{ClearCodecDecoder, ClearCodecError};

#[cfg(feature = "alloc")]
pub use utils::{
    bgr_to_bgra, bgra_to_bgr, diff_tiles, scale_nearest, swap_rb_inplace, Rect,
};

#[cfg(feature = "alloc")]
pub use pointer::{decode_pointer, PointerCache, PointerError, PointerShape};

#[cfg(feature = "alloc")]
pub use avc::{
    AvcDecoder, AvcError, Yuv420Frame, Yuv444Planes,
    combine_avc444_planes, combine_avc444v2_planes,
    yuv420_to_bgra, yuv444_to_bgra,
};
