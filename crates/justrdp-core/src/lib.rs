#![no_std]
#![forbid(unsafe_code)]
#![doc = "Core encoding/decoding traits and cursor types for JustRDP."]
#![doc = ""]
#![doc = "This crate provides the foundational types used across all JustRDP crates:"]
#![doc = "- [`Encode`] and [`Decode`] traits for PDU serialization"]
#![doc = "- [`ReadCursor`] and [`WriteCursor`] for zero-copy byte manipulation"]
#![doc = "- [`WriteBuf`] for dynamically-sized write buffers"]
#![doc = "- Error types for encode/decode operations"]

#[cfg(feature = "alloc")]
extern crate alloc;

mod cursor;
mod encode;
mod error;

pub use cursor::{ReadCursor, WriteCursor};
pub use encode::{AsAny, Decode, DecodeOwned, Encode, IntoOwned};
pub use error::{DecodeError, DecodeErrorKind, DecodeResult, EncodeError, EncodeErrorKind, EncodeResult};

#[cfg(feature = "alloc")]
mod write_buf;
#[cfg(feature = "alloc")]
pub use write_buf::WriteBuf;

/// Hint for framing layer to determine PDU boundaries before full decode.
pub trait PduHint: Send + Sync {
    /// Attempt to determine the size of a PDU from the given bytes.
    ///
    /// Returns `Some((is_fast_path, total_size))` if enough bytes are available
    /// to determine the PDU boundary, or `None` if more bytes are needed.
    fn find_size(&self, bytes: &[u8]) -> Option<(bool, usize)>;
}

/// Helper function to encode a value into a new `Vec<u8>`.
#[cfg(feature = "alloc")]
pub fn encode_vec<T: Encode>(value: &T) -> EncodeResult<alloc::vec::Vec<u8>> {
    let size = value.size();
    let mut buf = alloc::vec![0u8; size];
    let mut cursor = WriteCursor::new(&mut buf);
    value.encode(&mut cursor)?;
    Ok(buf)
}

/// Helper function to decode a value from a byte slice.
pub fn decode<'de, T: Decode<'de>>(bytes: &'de [u8]) -> DecodeResult<T> {
    let mut cursor = ReadCursor::new(bytes);
    T::decode(&mut cursor)
}

/// Helper function to encode a value into an existing [`WriteBuf`].
#[cfg(feature = "alloc")]
pub fn encode_buf<T: Encode>(value: &T, buf: &mut WriteBuf) -> EncodeResult<usize> {
    let size = value.size();
    buf.ensure_capacity(size);
    let mut cursor = WriteCursor::new(buf.as_mut_slice());
    value.encode(&mut cursor)?;
    Ok(size)
}
