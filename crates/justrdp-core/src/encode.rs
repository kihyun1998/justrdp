#![forbid(unsafe_code)]

use core::any::Any;

use crate::cursor::{ReadCursor, WriteCursor};
use crate::error::{DecodeResult, EncodeResult};

/// Object-safe trait for downcasting trait objects to concrete types.
///
/// Implement this on any trait object that needs runtime type inspection
/// (e.g., dynamic PDU dispatch, channel processors).
pub trait AsAny: Any {
    /// Return `self` as `&dyn Any` for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Return `self` as `&mut dyn Any` for mutable downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

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

/// Trait for converting a borrowed type into its owned counterpart.
///
/// This enables zero-copy decode followed by optional conversion to an owned
/// type that no longer borrows from the input buffer.
pub trait IntoOwned {
    /// The owned version of this type.
    type Owned: 'static;

    /// Convert this (possibly borrowed) value into a fully owned value.
    fn into_owned(self) -> Self::Owned;
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
