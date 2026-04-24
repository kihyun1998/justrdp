//! End-to-end handshake integration test (§11.2d, first deliverable).
//!
//! Drives a [`ClientConnector`] against a [`ServerAcceptor`] in a single
//! process using in-memory byte queues. The `PROTOCOL_RDP` security
//! path is chosen so both sides skip TLS / CredSSP entirely -- this is
//! the "`NoopTlsUpgrader`" approach the roadmap calls for: rather than
//! faking TLS bytes we configure both peers to negotiate a path where
//! the TLS state is never entered.
//!
//! Standard-RDP-Security encryption (RC4 + MAC) is still a stub per
//! §11.2a and is wired up separately in §11.2a-stdsec; this file only
//! validates the state-machine plumbing end-to-end.

use justrdp_acceptor::{
    AcceptorConfig, Sequence as AcceptorSequence, ServerAcceptor, ServerAcceptorState,
};
use justrdp_connector::{
    ClientConnector, ClientConnectorState, Config, Sequence as ConnectorSequence,
};
use justrdp_core::WriteBuf;
use justrdp_pdu::x224::SecurityProtocol;

/// Upper bound on the number of drive iterations before declaring the
/// handshake deadlocked. Empirically the PROTOCOL_RDP path completes in
/// well under 100 iterations; `4096` gives slack without hiding real
/// infinite loops.
const DRIVE_ITERATIONS_CAP: usize = 4096;

/// Build a PROTOCOL_RDP-only client config. No TLS certificate or
/// credentials are exercised; the username / password are retained
/// because `Config::builder` requires them, but they are never used
/// in the absence of CredSSP/RDSTLS.
fn rdp_only_client_config() -> Config {
    Config::builder("test-user", "test-pass")
        .security_protocol(SecurityProtocol::RDP)
        .build()
}

/// Build a PROTOCOL_RDP-only acceptor config. `require_enhanced_security`
/// MUST be `false` here since the server is advertising only
/// `PROTOCOL_RDP`; otherwise the builder rejects the combination as a
/// downgrade hazard (which is the correct default for production but
/// unhelpful for this loopback).
fn rdp_only_acceptor_config() -> AcceptorConfig {
    AcceptorConfig::builder()
        .supported_protocols(SecurityProtocol::RDP)
        .require_enhanced_security(false)
        .build()
        .expect("PROTOCOL_RDP-only is a valid combination")
}

/// Result of one drive attempt on a `Sequence` implementor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepOutcome {
    /// State machine advanced (either emitted output or consumed input).
    Progressed,
    /// Wait state and the inbound buffer does not yet contain a full
    /// PDU -- caller should let the peer run to produce more bytes.
    WaitingForInput,
    /// Terminal state reached; no further steps meaningful.
    Terminal,
}

/// Drive the client one step.
fn step_client(
    client: &mut ClientConnector,
    inbound: &mut Vec<u8>,
    out: &mut WriteBuf,
    outbound: &mut Vec<u8>,
) -> StepOutcome {
    if client.state().is_connected() {
        return StepOutcome::Terminal;
    }
    match client.next_pdu_hint() {
        None => {
            // Send / external-delegation state: step with no input.
            out.clear();
            client
                .step(&[], out)
                .expect("client send-state step failed");
            outbound.extend_from_slice(out.as_slice());
            StepOutcome::Progressed
        }
        Some(hint) => {
            let Some((_is_pdu, n)) = hint.find_size(inbound) else {
                return StepOutcome::WaitingForInput;
            };
            if n == 0 {
                return StepOutcome::WaitingForInput;
            }
            out.clear();
            client
                .step(&inbound[..n], out)
                .expect("client wait-state step failed");
            inbound.drain(..n);
            outbound.extend_from_slice(out.as_slice());
            StepOutcome::Progressed
        }
    }
}

/// Drive the acceptor one step. Mirror of `step_client`.
fn step_acceptor(
    acceptor: &mut ServerAcceptor,
    inbound: &mut Vec<u8>,
    out: &mut WriteBuf,
    outbound: &mut Vec<u8>,
) -> StepOutcome {
    if acceptor.state().is_terminal() {
        return StepOutcome::Terminal;
    }
    match AcceptorSequence::next_pdu_hint(acceptor) {
        None => {
            out.clear();
            acceptor
                .step(&[], out)
                .expect("acceptor send-state step failed");
            outbound.extend_from_slice(out.as_slice());
            StepOutcome::Progressed
        }
        Some(hint) => {
            let Some((_is_pdu, n)) = hint.find_size(inbound) else {
                return StepOutcome::WaitingForInput;
            };
            if n == 0 {
                return StepOutcome::WaitingForInput;
            }
            out.clear();
            acceptor
                .step(&inbound[..n], out)
                .expect("acceptor wait-state step failed");
            inbound.drain(..n);
            outbound.extend_from_slice(out.as_slice());
            StepOutcome::Progressed
        }
    }
}

/// Drive client ↔ acceptor to the terminal Connected / Accepted pair.
///
/// Alternates calls to `step_client` and `step_acceptor`; each function
/// either emits bytes (if in a send state), consumes buffered input
/// (if in a wait state with a full PDU available), or reports that it
/// is waiting. The loop terminates when both peers are terminal; a
/// round with no progress on either side is treated as a deadlock
/// and raises a panic with diagnostic context.
fn drive_full_handshake(
    mut client: ClientConnector,
    mut acceptor: ServerAcceptor,
) -> (ClientConnector, ServerAcceptor) {
    let mut c2s: Vec<u8> = Vec::new();
    let mut s2c: Vec<u8> = Vec::new();
    let mut client_out = WriteBuf::new();
    let mut server_out = WriteBuf::new();

    for i in 0..DRIVE_ITERATIONS_CAP {
        let client_done = client.state().is_connected();
        let server_done = acceptor.state().is_accepted();
        if client_done && server_done {
            return (client, acceptor);
        }

        // Let each side make as much progress as possible this round.
        // A state machine may chain several send states back-to-back
        // (e.g. the client's finalization burst) without waiting for
        // peer input, so we loop until the step either waits or
        // terminates.
        let mut any_progress = false;
        loop {
            match step_client(&mut client, &mut s2c, &mut client_out, &mut c2s) {
                StepOutcome::Progressed => any_progress = true,
                StepOutcome::WaitingForInput | StepOutcome::Terminal => break,
            }
        }
        loop {
            match step_acceptor(&mut acceptor, &mut c2s, &mut server_out, &mut s2c) {
                StepOutcome::Progressed => any_progress = true,
                StepOutcome::WaitingForInput | StepOutcome::Terminal => break,
            }
        }

        if !any_progress {
            panic!(
                "handshake deadlocked at iteration {i}: \
                 client_state={:?} server_state={:?} \
                 c2s_buffered={}B s2c_buffered={}B",
                client.state(),
                acceptor.state(),
                c2s.len(),
                s2c.len(),
            );
        }
    }
    panic!(
        "handshake did not complete within {DRIVE_ITERATIONS_CAP} iterations \
         (client_state={:?} server_state={:?})",
        client.state(),
        acceptor.state(),
    );
}

#[test]
fn protocol_rdp_handshake_reaches_both_terminal_states() {
    // Sanity: starting states are as expected.
    let client = ClientConnector::new(rdp_only_client_config());
    let acceptor = ServerAcceptor::new(rdp_only_acceptor_config());
    assert!(matches!(
        client.state(),
        ClientConnectorState::ConnectionInitiationSendRequest
    ));
    assert!(matches!(
        acceptor.state(),
        ServerAcceptorState::WaitConnectionRequest
    ));

    let (client, acceptor) = drive_full_handshake(client, acceptor);

    assert!(
        client.state().is_connected(),
        "client did not reach Connected: {:?}",
        client.state()
    );
    assert!(
        acceptor.state().is_accepted(),
        "acceptor did not reach Accepted: {:?}",
        acceptor.state()
    );

    // Cross-verify the negotiated parameters look sane on both sides.
    let client_result = client.result().expect("Connected implies ConnectionResult");
    match acceptor.state() {
        ServerAcceptorState::Accepted { result } => {
            assert_eq!(
                result.io_channel_id, client_result.io_channel_id,
                "I/O channel ID MUST match on both sides"
            );
            assert_eq!(
                result.user_channel_id, client_result.user_channel_id,
                "user channel ID MUST match on both sides"
            );
            assert_eq!(
                result.share_id, client_result.share_id,
                "share_id MUST match on both sides"
            );
            assert_eq!(result.selected_protocol, SecurityProtocol::RDP);
        }
        other => panic!("unexpected acceptor state: {other:?}"),
    }
}
