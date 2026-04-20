#![forbid(unsafe_code)]

//! Server acceptor state machine states.

use crate::result::AcceptanceResult;

/// State of the RDP server connection-acceptance sequence.
///
/// Mirrors `ClientConnectorState` but from the server perspective. Phases
/// follow MS-RDPBCGR 1.3.1.1 from the side of the entity that *receives*
/// the X.224 Connection Request and *sends* the Confirm.
///
/// Convention:
/// - `Send*` states produce output (caller provides empty input `&[]`)
/// - `Wait*` states expect a complete client PDU as input
/// - External states (`TlsAccept`, `CredsspAccept`) hand off to the caller
///   to perform the actual handshake; `step()` is a no-op transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerAcceptorState {
    // ── Phase 1: Connection Initiation ──
    /// Wait for X.224 Connection Request from the client.
    WaitConnectionRequest,
    /// Send X.224 Connection Confirm (RDP_NEG_RSP or RDP_NEG_FAILURE).
    SendConnectionConfirm,

    // ── Phase 2: Security Upgrade (external) ──
    /// Caller performs the TLS server handshake, then signals completion.
    TlsAccept,

    // ── Phase 3: NLA/CredSSP (external; server side) ──
    /// Caller performs the server-side CredSSP exchange.
    CredsspAccept,

    // ── Phase 4: Basic Settings Exchange ──
    /// Wait for MCS Connect Initial with GCC client data.
    WaitMcsConnectInitial,
    /// Send MCS Connect Response with GCC server data.
    SendMcsConnectResponse,

    // ── Phase 5: Channel Connection ──
    /// Run the Erect Domain / Attach User / Channel Join handshake.
    ChannelConnection,

    // ── Phase 7: Secure Settings Exchange ──
    /// Wait for the Client Info PDU.
    WaitClientInfo,

    // ── Phase 9: Licensing ──
    /// Send the licensing response (Valid Client shortcut or Error Alert).
    SendLicense,

    // ── Phase 11: Capabilities Exchange ──
    /// Send the Demand Active PDU.
    SendDemandActive,
    /// Wait for the Confirm Active PDU.
    WaitConfirmActive,

    // ── Phase 12: Connection Finalization ──
    /// Run the Synchronize / Control / Font List / Font Map handshake.
    ConnectionFinalization,

    // ── Terminal ──
    /// Connection accepted successfully.
    Accepted {
        /// Acceptance result with negotiated protocol, channel IDs, etc.
        result: AcceptanceResult,
    },

    // ── Terminal (failure) ──
    /// Server emitted an `RDP_NEG_FAILURE` Connection Confirm and the
    /// connection MUST be torn down by the caller. The state machine
    /// stops advancing once this is reached.
    NegotiationFailed,
}

impl ServerAcceptorState {
    /// Returns a human-readable name for this state.
    pub fn name(&self) -> &'static str {
        match self {
            Self::WaitConnectionRequest => "WaitConnectionRequest",
            Self::SendConnectionConfirm => "SendConnectionConfirm",
            Self::TlsAccept => "TlsAccept",
            Self::CredsspAccept => "CredsspAccept",
            Self::WaitMcsConnectInitial => "WaitMcsConnectInitial",
            Self::SendMcsConnectResponse => "SendMcsConnectResponse",
            Self::ChannelConnection => "ChannelConnection",
            Self::WaitClientInfo => "WaitClientInfo",
            Self::SendLicense => "SendLicense",
            Self::SendDemandActive => "SendDemandActive",
            Self::WaitConfirmActive => "WaitConfirmActive",
            Self::ConnectionFinalization => "ConnectionFinalization",
            Self::Accepted { .. } => "Accepted",
            Self::NegotiationFailed => "NegotiationFailed",
        }
    }

    /// Whether this is a send state (acceptor produces output, no input needed).
    pub fn is_send_state(&self) -> bool {
        matches!(
            self,
            Self::SendConnectionConfirm
                | Self::TlsAccept
                | Self::CredsspAccept
                | Self::SendMcsConnectResponse
                | Self::SendLicense
                | Self::SendDemandActive
        )
    }

    /// Whether this is the terminal Accepted state.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    /// Whether this is the terminal failed-negotiation state.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::NegotiationFailed)
    }

    /// Whether the state machine has reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.is_accepted() || self.is_failed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_set_for_every_variant() {
        // Walk through the variants explicitly to catch missing entries when
        // new states are added in later commits.
        let variants = [
            ServerAcceptorState::WaitConnectionRequest,
            ServerAcceptorState::SendConnectionConfirm,
            ServerAcceptorState::TlsAccept,
            ServerAcceptorState::CredsspAccept,
            ServerAcceptorState::WaitMcsConnectInitial,
            ServerAcceptorState::SendMcsConnectResponse,
            ServerAcceptorState::ChannelConnection,
            ServerAcceptorState::WaitClientInfo,
            ServerAcceptorState::SendLicense,
            ServerAcceptorState::SendDemandActive,
            ServerAcceptorState::WaitConfirmActive,
            ServerAcceptorState::ConnectionFinalization,
            ServerAcceptorState::NegotiationFailed,
        ];
        for v in variants.iter() {
            assert!(!v.name().is_empty());
        }
    }

    #[test]
    fn send_states_are_classified_correctly() {
        assert!(ServerAcceptorState::SendConnectionConfirm.is_send_state());
        assert!(ServerAcceptorState::TlsAccept.is_send_state());
        assert!(ServerAcceptorState::CredsspAccept.is_send_state());
        assert!(ServerAcceptorState::SendMcsConnectResponse.is_send_state());
        assert!(ServerAcceptorState::SendLicense.is_send_state());
        assert!(ServerAcceptorState::SendDemandActive.is_send_state());

        assert!(!ServerAcceptorState::WaitConnectionRequest.is_send_state());
        assert!(!ServerAcceptorState::WaitMcsConnectInitial.is_send_state());
        assert!(!ServerAcceptorState::WaitClientInfo.is_send_state());
        assert!(!ServerAcceptorState::WaitConfirmActive.is_send_state());
        assert!(!ServerAcceptorState::ChannelConnection.is_send_state());
        assert!(!ServerAcceptorState::ConnectionFinalization.is_send_state());
        assert!(!ServerAcceptorState::NegotiationFailed.is_send_state());
    }

    #[test]
    fn terminal_states_are_classified_correctly() {
        assert!(ServerAcceptorState::NegotiationFailed.is_failed());
        assert!(ServerAcceptorState::NegotiationFailed.is_terminal());
        assert!(!ServerAcceptorState::NegotiationFailed.is_accepted());

        assert!(!ServerAcceptorState::WaitConnectionRequest.is_terminal());
    }
}
