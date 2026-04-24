#![forbid(unsafe_code)]

//! `RdpServer` connection driver.
//!
//! Thin wrapper around [`justrdp_acceptor::ServerAcceptor`] that pairs the
//! handshake state machine with the post-accept runtime configuration
//! (`max_bitmap_fragment_size`, `channel_chunk_length`). The wrapper
//! implements [`Sequence`] so any caller-side pump that already drives a
//! `ServerAcceptor` can drive an `RdpServer` unchanged.
//!
//! ## Driver pattern (no I/O performed by this crate)
//!
//! ```text
//! let mut server = RdpServer::new(config);
//! let mut output = WriteBuf::new();
//! let mut buf: Vec<u8> = Vec::new();
//!
//! while !server.state().is_terminal() {
//!     match server.next_pdu_hint() {
//!         None => {
//!             // Send-only or external-delegation state: produce bytes.
//!             output.clear();
//!             server.step(&[], &mut output)?;
//!         }
//!         Some(hint) => {
//!             // Wait state: read until hint.find_size() returns Some(n).
//!             let n = read_until_complete(transport, hint, &mut buf)?;
//!             output.clear();
//!             server.step(&buf[..n], &mut output)?;
//!             buf.drain(..n);
//!         }
//!     }
//!     if !output.is_empty() {
//!         transport.write_all(output.as_slice())?;
//!     }
//! }
//! ```
//!
//! After `state().is_accepted()` is true, the driver should call
//! [`RdpServer::acceptance_result`] to inspect (or
//! [`RdpServer::take_acceptance_result`] to move) the negotiated values
//! before transitioning to the active-session stage.

use justrdp_acceptor::{
    AcceptanceResult, AcceptorResult, Sequence, ServerAcceptor, ServerAcceptorState,
};
use justrdp_core::{PduHint, WriteBuf};

use crate::config::RdpServerConfig;
use crate::error::{ServerError, ServerResult};

/// RDP server runtime that drives the connection-acceptance state machine
/// and (in subsequent commits) hosts the active-session loop.
pub struct RdpServer {
    acceptor: ServerAcceptor,
    config: RdpServerConfig,
}

impl RdpServer {
    /// Construct a new `RdpServer` from the supplied configuration.
    ///
    /// The wrapped [`ServerAcceptor`] starts in
    /// [`ServerAcceptorState::WaitConnectionRequest`] and the caller
    /// drives it via [`Sequence::next_pdu_hint`] / [`Sequence::step`].
    pub fn new(config: RdpServerConfig) -> Self {
        let acceptor = ServerAcceptor::new(config.acceptor_config.clone());
        Self { acceptor, config }
    }

    /// Borrow the runtime configuration.
    pub fn config(&self) -> &RdpServerConfig {
        &self.config
    }

    /// Borrow the wrapped acceptor (read-only). Useful for tests and for
    /// drivers that need to reach acceptor-specific helpers (e.g.
    /// `notify_tls_failed`, `selected_protocol`).
    pub fn acceptor(&self) -> &ServerAcceptor {
        &self.acceptor
    }

    /// Mutably borrow the wrapped acceptor. Drivers MUST go through
    /// [`Sequence::step`] to advance the state machine; this accessor is
    /// only for the external-delegation hooks (TLS / CredSSP completion
    /// notifications).
    pub fn acceptor_mut(&mut self) -> &mut ServerAcceptor {
        &mut self.acceptor
    }

    /// Whether the handshake reached the terminal `Accepted` state.
    pub fn is_accepted(&self) -> bool {
        self.acceptor.state().is_accepted()
    }

    /// Whether the handshake reached either terminal state
    /// (`Accepted` or `NegotiationFailed`).
    pub fn is_terminal(&self) -> bool {
        self.acceptor.state().is_terminal()
    }

    /// Borrow the [`AcceptanceResult`] when the handshake is in the
    /// `Accepted` terminal state. Returns `None` otherwise.
    pub fn acceptance_result(&self) -> Option<&AcceptanceResult> {
        match self.acceptor.state() {
            ServerAcceptorState::Accepted { result } => Some(result),
            _ => None,
        }
    }

    /// Move the [`AcceptanceResult`] out of the wrapper, consuming `self`.
    ///
    /// Returns `Err(ServerError::unexpected("Accepted"))` when the handshake
    /// has not reached `Accepted`. The `Acceptor` is dropped on success;
    /// callers transition into the active-session stage at this point.
    #[must_use = "the AcceptanceResult must be passed to ServerActiveStage::new \
                  -- discarding it drops the negotiated session state"]
    pub fn take_acceptance_result(self) -> ServerResult<(AcceptanceResult, RdpServerConfig)> {
        let RdpServer { acceptor, config } = self;
        // `ServerAcceptor` does not expose a move-out helper for the inner
        // state, so we walk the variant by reference and clone — the
        // `AcceptanceResult` is owned heap data that we must hand to the
        // post-accept stage, and cloning is required regardless of how the
        // wrapper is shaped. Drop the acceptor immediately afterwards so
        // the wire-side credentials live only as long as the active stage.
        match acceptor.state() {
            ServerAcceptorState::Accepted { result } => {
                let result = result.clone();
                drop(acceptor);
                Ok((result, config))
            }
            other => Err(ServerError::unexpected(other.name())),
        }
    }
}

impl Sequence for RdpServer {
    fn state(&self) -> &ServerAcceptorState {
        self.acceptor.state()
    }

    fn next_pdu_hint(&self) -> Option<&dyn PduHint> {
        self.acceptor.next_pdu_hint()
    }

    fn step(
        &mut self,
        input: &[u8],
        output: &mut WriteBuf,
    ) -> AcceptorResult<justrdp_acceptor::Written> {
        self.acceptor.step(input, output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    fn config_for_tests() -> RdpServerConfig {
        RdpServerConfig::builder().build().unwrap()
    }

    #[test]
    fn new_starts_in_wait_connection_request() {
        let s = RdpServer::new(config_for_tests());
        assert!(matches!(
            s.state(),
            ServerAcceptorState::WaitConnectionRequest
        ));
        assert!(!s.is_accepted());
        assert!(!s.is_terminal());
        assert!(s.acceptance_result().is_none());
    }

    #[test]
    fn next_pdu_hint_delegates_to_acceptor() {
        let s = RdpServer::new(config_for_tests());
        // WaitConnectionRequest expects a TPKT-framed Connection Request,
        // so the hint MUST be `Some(_)`.
        assert!(s.next_pdu_hint().is_some());
    }

    #[test]
    fn config_round_trips_through_constructor() {
        // `RdpServerConfig` no longer implements `PartialEq` because it
        // may embed an RSA private key via StandardSecurityConfig, so
        // we compare the visible scalar fields field-by-field instead.
        let cfg = RdpServerConfig::builder()
            .max_bitmap_fragment_size(1024)
            .channel_chunk_length(512)
            .build()
            .unwrap();
        let s = RdpServer::new(cfg.clone());
        let got = s.config();
        assert_eq!(got.max_bitmap_fragment_size, 1024);
        assert_eq!(got.channel_chunk_length, 512);
    }

    #[test]
    fn take_acceptance_result_errors_before_accept() {
        let s = RdpServer::new(config_for_tests());
        let err = s.take_acceptance_result().unwrap_err();
        let msg = alloc::format!("{err}");
        assert!(msg.contains("WaitConnectionRequest"), "got: {msg}");
    }

    #[test]
    fn step_delegates_invalid_input_to_acceptor_error() {
        // Garbage bytes against the WaitConnectionRequest hint — the
        // wrapper MUST surface the acceptor's decode error rather than
        // panicking or silently swallowing it.
        let mut s = RdpServer::new(config_for_tests());
        let mut out = WriteBuf::new();
        let result = s.step(&[0xFF; 4], &mut out);
        assert!(result.is_err());
    }
}
