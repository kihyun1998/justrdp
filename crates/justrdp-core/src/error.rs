#![forbid(unsafe_code)]

use core::fmt;

// ── Encode Errors ──

/// The kind of encoding error that occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeErrorKind {
    /// The output buffer is too small to hold the encoded data.
    NotEnoughSpace {
        /// Bytes needed to complete the encode.
        needed: usize,
        /// Bytes available in the buffer.
        available: usize,
    },
    /// A value is out of the valid range for the field.
    InvalidValue {
        /// Name of the field.
        field: &'static str,
    },
    /// A custom encoding error.
    Other {
        /// Description of the error.
        description: &'static str,
    },
}

/// An error that occurred during PDU encoding.
#[derive(Debug, Clone)]
pub struct EncodeError {
    /// The name of the PDU being encoded when the error occurred.
    pub context: &'static str,
    /// The kind of error.
    pub kind: EncodeErrorKind,
}

impl EncodeError {
    /// Create a new encode error.
    pub fn new(context: &'static str, kind: EncodeErrorKind) -> Self {
        Self { context, kind }
    }

    /// Create a "not enough space" error.
    pub fn not_enough_space(context: &'static str, needed: usize, available: usize) -> Self {
        Self::new(
            context,
            EncodeErrorKind::NotEnoughSpace { needed, available },
        )
    }

    /// Create an "invalid value" error.
    pub fn invalid_value(context: &'static str, field: &'static str) -> Self {
        Self::new(context, EncodeErrorKind::InvalidValue { field })
    }

    /// Create a custom error.
    pub fn other(context: &'static str, description: &'static str) -> Self {
        Self::new(context, EncodeErrorKind::Other { description })
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            EncodeErrorKind::NotEnoughSpace { needed, available } => {
                write!(
                    f,
                    "[{}] not enough space: needed {} bytes, {} available",
                    self.context, needed, available
                )
            }
            EncodeErrorKind::InvalidValue { field } => {
                write!(f, "[{}] invalid value for field '{}'", self.context, field)
            }
            EncodeErrorKind::Other { description } => {
                write!(f, "[{}] {}", self.context, description)
            }
        }
    }
}

/// Result type for encoding operations.
pub type EncodeResult<T> = Result<T, EncodeError>;

// ── Decode Errors ──

/// The kind of decoding error that occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeErrorKind {
    /// Not enough bytes in the input to complete decoding.
    NotEnoughBytes {
        /// Bytes needed.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
    /// An invalid value was encountered during decoding.
    InvalidValue {
        /// Name of the field.
        field: &'static str,
    },
    /// An unexpected value was encountered.
    UnexpectedValue {
        /// Name of the field.
        field: &'static str,
        /// The value that was encountered (as a human-readable string).
        got: &'static str,
    },
    /// An unsupported or unrecognized variant/version was encountered.
    Unsupported {
        /// Description of what is unsupported.
        description: &'static str,
    },
    /// A custom decoding error.
    Other {
        /// Description of the error.
        description: &'static str,
    },
}

/// An error that occurred during PDU decoding.
#[derive(Debug, Clone)]
pub struct DecodeError {
    /// The name of the PDU being decoded when the error occurred.
    pub context: &'static str,
    /// The kind of error.
    pub kind: DecodeErrorKind,
}

impl DecodeError {
    /// Create a new decode error.
    pub fn new(context: &'static str, kind: DecodeErrorKind) -> Self {
        Self { context, kind }
    }

    /// Create a "not enough bytes" error.
    pub fn not_enough_bytes(context: &'static str, needed: usize, available: usize) -> Self {
        Self::new(
            context,
            DecodeErrorKind::NotEnoughBytes { needed, available },
        )
    }

    /// Create an "invalid value" error.
    pub fn invalid_value(context: &'static str, field: &'static str) -> Self {
        Self::new(context, DecodeErrorKind::InvalidValue { field })
    }

    /// Create an "unexpected value" error.
    pub fn unexpected_value(context: &'static str, field: &'static str, got: &'static str) -> Self {
        Self::new(context, DecodeErrorKind::UnexpectedValue { field, got })
    }

    /// Create an "unsupported" error.
    pub fn unsupported(context: &'static str, description: &'static str) -> Self {
        Self::new(context, DecodeErrorKind::Unsupported { description })
    }

    /// Create a custom error.
    pub fn other(context: &'static str, description: &'static str) -> Self {
        Self::new(context, DecodeErrorKind::Other { description })
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            DecodeErrorKind::NotEnoughBytes { needed, available } => {
                write!(
                    f,
                    "[{}] not enough bytes: needed {}, {} available",
                    self.context, needed, available
                )
            }
            DecodeErrorKind::InvalidValue { field } => {
                write!(f, "[{}] invalid value for field '{}'", self.context, field)
            }
            DecodeErrorKind::UnexpectedValue { field, got } => {
                write!(
                    f,
                    "[{}] unexpected value for field '{}': {}",
                    self.context, field, got
                )
            }
            DecodeErrorKind::Unsupported { description } => {
                write!(f, "[{}] unsupported: {}", self.context, description)
            }
            DecodeErrorKind::Other { description } => {
                write!(f, "[{}] {}", self.context, description)
            }
        }
    }
}

/// Result type for decoding operations.
pub type DecodeResult<T> = Result<T, DecodeError>;

// ── Crypto Errors ──

/// An error from a cryptographic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Key size is invalid for the operation.
    InvalidKeySize,
    /// Input data length is invalid (not block-aligned, too short, etc.).
    InvalidDataLength,
    /// HMAC verification failed (authentication error).
    HmacVerifyFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeySize => write!(f, "invalid key size"),
            CryptoError::InvalidDataLength => write!(f, "invalid data length"),
            CryptoError::HmacVerifyFailed => write!(f, "HMAC verification failed"),
        }
    }
}

/// Result type for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>;
