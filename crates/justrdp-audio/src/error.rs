#![forbid(unsafe_code)]

//! Audio codec error types.

use core::fmt;

/// Audio codec error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioError {
    /// The audio format parameters are invalid.
    InvalidFormat(&'static str),
    /// The audio block data is malformed.
    InvalidBlock(&'static str),
    /// The output buffer is too small.
    BufferTooSmall {
        /// Samples needed.
        needed: usize,
        /// Samples available.
        available: usize,
    },
    /// The codec is not supported.
    UnsupportedCodec,
}

impl fmt::Display for AudioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "invalid audio format: {msg}"),
            Self::InvalidBlock(msg) => write!(f, "invalid audio block: {msg}"),
            Self::BufferTooSmall { needed, available } => {
                write!(f, "buffer too small: need {needed}, have {available}")
            }
            Self::UnsupportedCodec => write!(f, "unsupported audio codec"),
        }
    }
}

/// Result type for audio operations.
pub type AudioResult<T> = Result<T, AudioError>;
