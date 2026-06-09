//! Typed decode errors for the wire layer (plan.md §2). Kept deliberately small — variants are
//! added as PDUs that need them are implemented, not speculatively.

/// An error raised while decoding bytes into a typed PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer is shorter than the frame requires — the caller should read more and retry.
    /// This is the sans-IO "partial frame" signal, not a fatal error.
    NotEnoughBytes {
        /// What we were trying to decode when we ran out.
        context: &'static str,
        /// Bytes required to make progress.
        needed: usize,
        /// Bytes actually available.
        got: usize,
    },
    /// A field held a value outside its valid range.
    InvalidField {
        /// The field that failed validation.
        field: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::NotEnoughBytes {
                context,
                needed,
                got,
            } => write!(
                f,
                "not enough bytes decoding {context}: need {needed}, have {got}"
            ),
            DecodeError::InvalidField { field, reason } => {
                write!(f, "invalid field {field}: {reason}")
            }
        }
    }
}

impl core::error::Error for DecodeError {}
