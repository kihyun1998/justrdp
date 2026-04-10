#![forbid(unsafe_code)]

//! Error types for `justrdp-blocking`.

use std::fmt;
use std::io;

use justrdp_connector::ConnectorError;
use justrdp_session::SessionError;
use justrdp_tls::TlsError;

/// Errors returned during [`crate::RdpClient::connect`].
#[derive(Debug)]
pub enum ConnectError {
    /// Failed to resolve or open a TCP socket.
    Tcp(io::Error),
    /// TLS handshake or upgrade failed.
    Tls(TlsError),
    /// Connection state machine rejected a PDU or reached an error state.
    Connector(ConnectorError),
    /// Server closed the connection before reaching `Connected`.
    UnexpectedEof,
    /// Hit the runtime-defined read limit while framing a PDU (possible DoS).
    FrameTooLarge(usize),
    /// SVC channel registration or initial `start_all` failed
    /// (duplicate channel name, max channels exceeded, or processor
    /// returned an encode error from `start()`).
    ChannelSetup(String),
    /// Functionality not yet implemented in this scaffold.
    Unimplemented(&'static str),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(e) => write!(f, "TCP error: {e}"),
            Self::Tls(e) => write!(f, "TLS error: {e}"),
            Self::Connector(e) => write!(f, "connector error: {e:?}"),
            Self::UnexpectedEof => f.write_str("server closed connection during handshake"),
            Self::FrameTooLarge(n) => write!(f, "PDU frame too large: {n} bytes"),
            Self::ChannelSetup(msg) => write!(f, "SVC channel setup failed: {msg}"),
            Self::Unimplemented(what) => write!(f, "not implemented: {what}"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tcp(e) => Some(e),
            Self::Tls(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ConnectError {
    fn from(e: io::Error) -> Self {
        Self::Tcp(e)
    }
}

impl From<TlsError> for ConnectError {
    fn from(e: TlsError) -> Self {
        Self::Tls(e)
    }
}

impl From<ConnectorError> for ConnectError {
    fn from(e: ConnectorError) -> Self {
        Self::Connector(e)
    }
}

/// Errors returned during active-session operations.
#[derive(Debug)]
pub enum RuntimeError {
    /// Socket read/write failed.
    Io(io::Error),
    /// Session PDU processing failed.
    Session(SessionError),
    /// Frame too large.
    FrameTooLarge(usize),
    /// The session was disconnected; call [`crate::RdpClient::connect`] again.
    Disconnected,
    /// Functionality not yet implemented.
    Unimplemented(&'static str),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Session(e) => write!(f, "session error: {e:?}"),
            Self::FrameTooLarge(n) => write!(f, "frame too large: {n} bytes"),
            Self::Disconnected => f.write_str("session disconnected"),
            Self::Unimplemented(what) => write!(f, "not implemented: {what}"),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for RuntimeError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<SessionError> for RuntimeError {
    fn from(e: SessionError) -> Self {
        Self::Session(e)
    }
}
