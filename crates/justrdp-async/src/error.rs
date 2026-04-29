#![forbid(unsafe_code)]

use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    kind: TransportErrorKind,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportErrorKind {
    /// The peer closed the connection (clean or unclean).
    ConnectionClosed,
    /// Underlying I/O failure (WebSocket send error, ws.send threw, etc.).
    Io,
    /// Frame violated transport-level expectations (e.g. text frame where
    /// binary was required, malformed Close frame).
    Protocol,
    /// Operation was cancelled (future dropped, embedder-initiated abort).
    Cancelled,
    /// Anything else the transport implementation wants to surface.
    Other,
}

impl TransportError {
    pub fn new(kind: TransportErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn closed(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::ConnectionClosed, message)
    }

    pub fn io(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::Io, message)
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::Protocol, message)
    }

    pub fn cancelled(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::Cancelled, message)
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::Other, message)
    }

    pub fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl core::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn closed_helper_sets_kind() {
        let e = TransportError::closed("peer gone");
        assert_eq!(e.kind(), TransportErrorKind::ConnectionClosed);
        assert_eq!(e.message(), "peer gone");
    }

    #[test]
    fn display_includes_kind_and_message() {
        let e = TransportError::protocol("bad opcode");
        let s = e.to_string();
        assert!(s.contains("Protocol"));
        assert!(s.contains("bad opcode"));
    }

    #[test]
    fn equality_respects_both_fields() {
        let a = TransportError::io("x");
        let b = TransportError::io("x");
        let c = TransportError::io("y");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
