#![forbid(unsafe_code)]

//! Connector error types.

use alloc::string::String;
use core::fmt;

use justrdp_core::{DecodeError, EncodeError};
use justrdp_pdu::mcs::ConnectResponseResult;
use justrdp_pdu::rdp::licensing::LicenseErrorCode;
use justrdp_pdu::x224::NegotiationFailureCode;

/// Connector error kind.
#[derive(Debug)]
pub enum ConnectorErrorKind {
    /// PDU encoding error.
    Encode(EncodeError),
    /// PDU decoding error.
    Decode(DecodeError),
    /// Server returned negotiation failure.
    NegotiationFailure(NegotiationFailureCode),
    /// MCS Connect Response was not successful.
    McsConnectFailure(ConnectResponseResult),
    /// MCS channel join was not confirmed.
    ChannelJoinFailure { channel_id: u16, result: u8 },
    /// Attach User Confirm failed.
    AttachUserFailure { result: u8 },
    /// Unexpected PDU received for the current state.
    UnexpectedPdu { expected: &'static str },
    /// Called step() in an invalid state.
    InvalidState,
    /// Licensing error from server.
    LicensingError(LicenseErrorCode),
    /// Server requested redirect to another host.
    ServerRedirect {
        /// Target hostname/IP from the redirect packet.
        target: String,
    },
    /// General protocol violation.
    General(&'static str),
}

/// Connector error with state context.
#[derive(Debug)]
pub struct ConnectorError {
    pub kind: ConnectorErrorKind,
}

impl ConnectorError {
    pub fn general(msg: &'static str) -> Self {
        Self {
            kind: ConnectorErrorKind::General(msg),
        }
    }

    pub fn unexpected(expected: &'static str) -> Self {
        Self {
            kind: ConnectorErrorKind::UnexpectedPdu { expected },
        }
    }
}

impl From<EncodeError> for ConnectorError {
    fn from(e: EncodeError) -> Self {
        Self {
            kind: ConnectorErrorKind::Encode(e),
        }
    }
}

impl From<DecodeError> for ConnectorError {
    fn from(e: DecodeError) -> Self {
        Self {
            kind: ConnectorErrorKind::Decode(e),
        }
    }
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ConnectorErrorKind::Encode(e) => write!(f, "encode error: {e}"),
            ConnectorErrorKind::Decode(e) => write!(f, "decode error: {e}"),
            ConnectorErrorKind::NegotiationFailure(code) => {
                write!(f, "negotiation failure: {code:?}")
            }
            ConnectorErrorKind::McsConnectFailure(result) => {
                write!(f, "MCS connect failure: {result:?}")
            }
            ConnectorErrorKind::ChannelJoinFailure { channel_id, result } => {
                write!(f, "channel join failure: channel={channel_id}, result={result}")
            }
            ConnectorErrorKind::AttachUserFailure { result } => {
                write!(f, "attach user failure: result={result}")
            }
            ConnectorErrorKind::UnexpectedPdu { expected } => {
                write!(f, "unexpected PDU, expected: {expected}")
            }
            ConnectorErrorKind::InvalidState => write!(f, "invalid connector state"),
            ConnectorErrorKind::LicensingError(code) => {
                write!(f, "licensing error: {code:?}")
            }
            ConnectorErrorKind::ServerRedirect { target } => {
                write!(f, "server redirect to: {target}")
            }
            ConnectorErrorKind::General(msg) => write!(f, "{msg}"),
        }
    }
}

/// Connector result type.
pub type ConnectorResult<T> = Result<T, ConnectorError>;
