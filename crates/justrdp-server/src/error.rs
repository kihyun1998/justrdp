#![forbid(unsafe_code)]

//! `justrdp-server` error types.

use core::fmt;

extern crate alloc;

use justrdp_acceptor::{AcceptorConfigError, AcceptorError};
use justrdp_core::{DecodeError, EncodeError};

/// Server error kind.
#[derive(Debug)]
pub enum ServerErrorKind {
    /// Wrapped error from the connection-acceptance phase.
    Acceptor(AcceptorError),
    /// PDU encoding error during the active session.
    Encode(EncodeError),
    /// PDU decoding error during the active session.
    Decode(DecodeError),
    /// PDU received that the active session does not allow at this point.
    UnexpectedPdu { expected: &'static str },
    /// The session has already been terminated and the API was called
    /// again. Used to make double-disconnects observable.
    AlreadyTerminated,
    /// Static-string protocol violation (mirrors `AcceptorErrorKind::General`).
    Protocol(&'static str),
    /// Runtime-formatted protocol violation.
    ProtocolOwned(alloc::string::String),
}

/// Server error returned by `justrdp-server` operations during the
/// **active session** phase. Errors during `accept()` are wrapped via
/// [`ServerErrorKind::Acceptor`].
#[derive(Debug)]
pub struct ServerError {
    pub kind: ServerErrorKind,
}

impl ServerError {
    pub fn protocol(msg: &'static str) -> Self {
        Self {
            kind: ServerErrorKind::Protocol(msg),
        }
    }

    pub fn protocol_owned(msg: alloc::string::String) -> Self {
        Self {
            kind: ServerErrorKind::ProtocolOwned(msg),
        }
    }

    pub fn unexpected(expected: &'static str) -> Self {
        Self {
            kind: ServerErrorKind::UnexpectedPdu { expected },
        }
    }

    pub fn already_terminated() -> Self {
        Self {
            kind: ServerErrorKind::AlreadyTerminated,
        }
    }
}

impl From<AcceptorError> for ServerError {
    fn from(e: AcceptorError) -> Self {
        Self {
            kind: ServerErrorKind::Acceptor(e),
        }
    }
}

impl From<EncodeError> for ServerError {
    fn from(e: EncodeError) -> Self {
        Self {
            kind: ServerErrorKind::Encode(e),
        }
    }
}

impl From<DecodeError> for ServerError {
    fn from(e: DecodeError) -> Self {
        Self {
            kind: ServerErrorKind::Decode(e),
        }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ServerErrorKind::Acceptor(e) => write!(f, "acceptor error: {e}"),
            ServerErrorKind::Encode(e) => write!(f, "encode error: {e}"),
            ServerErrorKind::Decode(e) => write!(f, "decode error: {e}"),
            ServerErrorKind::UnexpectedPdu { expected } => {
                write!(f, "unexpected PDU, expected: {expected}")
            }
            ServerErrorKind::AlreadyTerminated => write!(f, "session already terminated"),
            ServerErrorKind::Protocol(msg) => write!(f, "{msg}"),
            ServerErrorKind::ProtocolOwned(msg) => write!(f, "{msg}"),
        }
    }
}

/// Server result type.
pub type ServerResult<T> = Result<T, ServerError>;

/// Errors returned by `RdpServerConfigBuilder::build()`.
///
/// Kept separate from [`ServerError`] because misconfiguration is a
/// startup-time problem -- the caller usually wants to log it and exit
/// rather than handle it at the I/O layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerConfigError {
    /// `channel_chunk_length` is outside the legal MS-RDPBCGR range.
    ///
    /// The protocol fixes the maximum SVC chunk size at
    /// `CHANNEL_CHUNK_LENGTH = 1600` bytes (MS-RDPBCGR §2.2.7.1.10).
    /// Values below 8 leave no room for the `ChannelPduHeader`; values
    /// above 1600 bytes have been observed to be silently truncated by
    /// real Windows clients, so we reject them up-front.
    InvalidChannelChunkLength { value: usize },
    /// `max_bitmap_fragment_size` would exceed the fast-path 15-bit
    /// length field after accounting for outer headers.
    ///
    /// Fast-path output PDUs use a 15-bit length encoding capped at
    /// `0x7FFF = 32_767` bytes (MS-RDPBCGR §2.2.9.1.2). The chosen
    /// fragment size MUST leave room for the fast-path header and inner
    /// `FastPathOutputUpdate` framing; we conservatively cap it at
    /// `MAX_BITMAP_FRAGMENT_SIZE_LIMIT`.
    InvalidBitmapFragmentSize { value: usize, limit: usize },
    /// Forwarded validation failure from the wrapped
    /// [`AcceptorConfigError`].
    AcceptorConfig(AcceptorConfigError),
}

impl fmt::Display for ServerConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChannelChunkLength { value } => write!(
                f,
                "channel_chunk_length {value} is out of range \
                 (MS-RDPBCGR CHANNEL_CHUNK_LENGTH=1600 §2.2.7.1.10); \
                 must be between 8 and 1600 bytes inclusive"
            ),
            Self::InvalidBitmapFragmentSize { value, limit } => write!(
                f,
                "max_bitmap_fragment_size {value} exceeds limit {limit} \
                 (fast-path 15-bit length field cap, MS-RDPBCGR §2.2.9.1.2)"
            ),
            Self::AcceptorConfig(e) => write!(f, "{e}"),
        }
    }
}

impl From<AcceptorConfigError> for ServerConfigError {
    fn from(e: AcceptorConfigError) -> Self {
        Self::AcceptorConfig(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ServerError {}

#[cfg(feature = "std")]
impl std::error::Error for ServerConfigError {}
