#![forbid(unsafe_code)]

//! Acceptor error types.

use core::fmt;

extern crate alloc;

use justrdp_core::{DecodeError, EncodeError};
use justrdp_pdu::x224::NegotiationFailureCode;

/// Acceptor error kind.
#[derive(Debug)]
pub enum AcceptorErrorKind {
    /// PDU encoding error.
    Encode(EncodeError),
    /// PDU decoding error.
    Decode(DecodeError),
    /// Server emitted a `RDP_NEG_FAILURE` because no protocol could be
    /// negotiated. The state machine has transitioned to `NegotiationFailed`
    /// and the connection MUST be closed by the caller. The failure code
    /// is the same value embedded in the Connection Confirm PDU sent on
    /// the wire so the caller can log a coherent diagnostic.
    NegotiationFailed(NegotiationFailureCode),
    /// Unexpected PDU received for the current state.
    UnexpectedPdu { expected: &'static str },
    /// Called `step()` in a state that does not accept further input
    /// (e.g., terminal `Accepted` / `NegotiationFailed`).
    InvalidState,
    /// General protocol violation.
    General(&'static str),
    /// General protocol violation with a runtime-formatted message.
    GeneralOwned(alloc::string::String),
}

/// Acceptor error.
#[derive(Debug)]
pub struct AcceptorError {
    pub kind: AcceptorErrorKind,
}

impl AcceptorError {
    pub fn general(msg: &'static str) -> Self {
        Self {
            kind: AcceptorErrorKind::General(msg),
        }
    }

    pub fn general_owned(msg: alloc::string::String) -> Self {
        Self {
            kind: AcceptorErrorKind::GeneralOwned(msg),
        }
    }

    pub fn unexpected(expected: &'static str) -> Self {
        Self {
            kind: AcceptorErrorKind::UnexpectedPdu { expected },
        }
    }

    pub fn negotiation_failed(code: NegotiationFailureCode) -> Self {
        Self {
            kind: AcceptorErrorKind::NegotiationFailed(code),
        }
    }
}

impl From<EncodeError> for AcceptorError {
    fn from(e: EncodeError) -> Self {
        Self {
            kind: AcceptorErrorKind::Encode(e),
        }
    }
}

impl From<DecodeError> for AcceptorError {
    fn from(e: DecodeError) -> Self {
        Self {
            kind: AcceptorErrorKind::Decode(e),
        }
    }
}

impl fmt::Display for AcceptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            AcceptorErrorKind::Encode(e) => write!(f, "encode error: {e}"),
            AcceptorErrorKind::Decode(e) => write!(f, "decode error: {e}"),
            AcceptorErrorKind::NegotiationFailed(code) => {
                write!(f, "negotiation failed: {code:?}")
            }
            AcceptorErrorKind::UnexpectedPdu { expected } => {
                write!(f, "unexpected PDU, expected: {expected}")
            }
            AcceptorErrorKind::InvalidState => write!(f, "invalid acceptor state"),
            AcceptorErrorKind::General(msg) => write!(f, "{msg}"),
            AcceptorErrorKind::GeneralOwned(msg) => write!(f, "{msg}"),
        }
    }
}

/// Acceptor result type.
pub type AcceptorResult<T> = Result<T, AcceptorError>;
