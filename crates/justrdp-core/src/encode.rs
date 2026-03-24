#![forbid(unsafe_code)]

use crate::cursor::{ReadCursor, WriteCursor};
use crate::error::{DecodeResult, EncodeResult};

/// Trait for types that can be encoded into a byte buffer.
///
/// All RDP PDUs implement this trait. Implementations must be deterministic:
/// encoding the same value must always produce the same bytes.
pub trait Encode {
    /// Encode this value into the given write cursor.
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()>;

    /// Returns the name of this PDU type (for error messages).
    fn name(&self) -> &'static str;

    /// Returns the exact number of bytes this value will occupy when encoded.
    ///
    /// This must be accurate -- the encoding logic relies on it for buffer sizing.
    fn size(&self) -> usize;
}

/// Trait for types that can be decoded from a byte buffer with zero-copy borrowing.
///
/// The lifetime `'de` ties the decoded value to the input buffer,
/// enabling zero-copy parsing of byte slices and strings.
pub trait Decode<'de>: Sized {
    /// Decode this value from the given read cursor.
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self>;
}

/// Trait for types that can be decoded without borrowing from the input.
///
/// Use this when the decoded value needs to outlive the input buffer
/// (e.g., when the decoded type owns all its data via `Vec` or `String`).
pub trait DecodeOwned: Sized {
    /// Decode this value from the given read cursor, producing an owned result.
    fn decode_owned(src: &mut ReadCursor<'_>) -> DecodeResult<Self>;
}

// Blanket impl: anything that implements Decode<'de> for all lifetimes also implements DecodeOwned.
impl<T> DecodeOwned for T
where
    T: for<'de> Decode<'de>,
{
    fn decode_owned(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        T::decode(src)
    }
}
