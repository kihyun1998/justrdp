//! The sans-IO connection state machine (ADR-0001). It drives the RDP connect sequence by
//! consuming [`Event`]s (socket connected, bytes received) and emitting [`Action`]s (open the
//! socket, write bytes, proceed, fail) — never touching the socket itself. slice-1 covers the
//! first two stages: `tcp-connect` → `x224-negotiate`.

use justrdp_pdu::nego::{NegFailureCode, NegRequest, NegResponse, SecurityProtocol};
use justrdp_pdu::{tpkt, x224};

/// A side effect the host adapter must perform on the machine's behalf. The machine is pure; these
/// are its only outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Open the TCP socket to the server.
    Connect,
    /// Write these bytes to the socket.
    WriteBytes(Vec<u8>),
    /// The X.224 negotiation selected `selected`; the adapter must now upgrade the socket to TLS
    /// (rustls handshake) and hand the server's leaf certificate back via [`Event::TlsEstablished`].
    /// The TLS records themselves never enter this machine (plan.md §3 — the handshake runs outside
    /// the connect state machine).
    StartTls { selected: SecurityProtocol },
    /// The TLS upgrade is complete and the server's `subjectPublicKey` has been extracted; the
    /// adapter must now run the CredSSP token exchange (NLA), binding `pubKeyAuth` to
    /// `server_public_key`, and signal completion via [`Event::NlaComplete`]. The CredSSP records
    /// (`TSRequest`s) never enter this machine — `sspi` owns CredSSP and the adapter drives the loop
    /// (plan.md decision 10), exactly as the TLS handshake stays in the adapter.
    StartNla {
        /// The protocol the server chose in the X.224 Connection Confirm.
        selected: SecurityProtocol,
        /// The server's `subjectPublicKey` (DER `SubjectPublicKeyInfo`) for CredSSP to bind to.
        server_public_key: Vec<u8>,
    },
    /// HYBRID_EX only: the CredSSP exchange finished and the server will now send the 4-byte Early
    /// User Authorization Result PDU. The adapter must read it and deliver it via
    /// [`Event::EarlyUserAuthResult`]. (Failing to consume it desyncs capability exchange —
    /// plan.md §0.)
    AwaitEarlyUserAuth,
    /// Authentication succeeded (the CredSSP exchange, plus the HYBRID_EX Early User Authorization
    /// check when applicable); the connect sequence has reached the end of what this slice
    /// implements. Carries the negotiated protocol. MCS connect is the next slice.
    Authenticated {
        /// The protocol the server chose in the X.224 Connection Confirm.
        selected: SecurityProtocol,
    },
    /// The connect attempt failed; surface this error and tear down.
    FailWith(ConnectError),
}

/// An input handed to the machine by the host adapter.
///
/// Events are ordered: each one is valid only in the stage that requested it (e.g.
/// [`Event::TlsEstablished`] answers [`Action::StartTls`], [`Event::NlaComplete`] answers
/// [`Action::StartNla`]). Feeding an event the current stage does not expect is never undefined
/// behavior and never panics — the machine fails the connect with
/// [`ConnectError::UnexpectedEvent`], naming the stage and the offending event kind. This is the
/// contract third-party adapters (blocking, wasm, …) are held to; `justrdp-tokio` upholds it by
/// construction.
#[derive(Debug, Clone, Copy)]
pub enum Event<'a> {
    /// The TCP socket finished connecting.
    Connected,
    /// Bytes arrived from the socket.
    Received(&'a [u8]),
    /// The TLS handshake the adapter ran (after [`Action::StartTls`]) completed; carries the
    /// server's leaf certificate (DER) so the machine can extract its `subjectPublicKey`.
    TlsEstablished(&'a [u8]),
    /// The CredSSP token exchange the adapter ran (after [`Action::StartNla`]) completed
    /// successfully. For HYBRID_EX, the Early User Authorization Result PDU still follows on the
    /// wire (delivered next via [`Event::EarlyUserAuthResult`]).
    NlaComplete,
    /// HYBRID_EX only: the 4-byte Early User Authorization Result PDU the adapter read (after
    /// [`Action::AwaitEarlyUserAuth`]). Little-endian; the machine decodes grant/deny.
    EarlyUserAuthResult(&'a [u8]),
}

impl Event<'_> {
    /// The payload-free discriminant of this event, for [`ConnectError::UnexpectedEvent`].
    pub fn kind(&self) -> EventKind {
        match self {
            Event::Connected => EventKind::Connected,
            Event::Received(_) => EventKind::Received,
            Event::TlsEstablished(_) => EventKind::TlsEstablished,
            Event::NlaComplete => EventKind::NlaComplete,
            Event::EarlyUserAuthResult(_) => EventKind::EarlyUserAuthResult,
        }
    }
}

/// The kind of an [`Event`], without its payload (which may borrow from the adapter's buffers).
/// Carried by [`ConnectError::UnexpectedEvent`] to name the event that violated the ordering
/// contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// [`Event::Connected`].
    Connected,
    /// [`Event::Received`].
    Received,
    /// [`Event::TlsEstablished`].
    TlsEstablished,
    /// [`Event::NlaComplete`].
    NlaComplete,
    /// [`Event::EarlyUserAuthResult`].
    EarlyUserAuthResult,
}

/// Why a connect attempt failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// The server refused every advertised protocol (`RDP_NEG_FAILURE`).
    NegotiationFailed(NegFailureCode),
    /// The server selected a protocol the client never advertised.
    UnsupportedProtocol(SecurityProtocol),
    /// A malformed PDU arrived from the server.
    Decode(justrdp_pdu::DecodeError),
    /// The TLS upgrade failed: the server's certificate could not be parsed or its public key
    /// extracted. (Handshake-level failures surface at the adapter boundary.)
    TlsHandshake(crate::tls::TlsCertError),
    /// HYBRID_EX only: the server's Early User Authorization Result PDU denied access
    /// (`AUTHZ_ACCESS_DENIED`) — user authorization failed, so the connection must be dropped.
    EarlyUserAuthDenied,
    /// The adapter fed the machine an [`Event`] the current stage does not expect (the ordering
    /// contract on [`Event`]). Carries the stage label and the offending event kind. This is an
    /// adapter bug, not a server behavior — but it surfaces as a typed failure, never a panic.
    UnexpectedEvent {
        /// The connect-stage label the machine was in (as reported by
        /// [`ConnectStateMachine::stage`]).
        stage: &'static str,
        /// The kind of event that arrived.
        event: EventKind,
    },
}

/// The labeled connect sub-step the machine is in (CONTEXT.md "Connect Stage"). slice-1 stops at
/// `x224-negotiate`; later slices extend this set. Stages that follow the X.224 confirm carry the
/// server-selected protocol, so a stage being reachable proves the data it needs exists — no
/// `Option` to unwrap, no panic path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Before the socket is up — the machine has asked the adapter to `Connect`.
    TcpConnect,
    /// Socket is up; the X.224 security negotiation request has been sent, awaiting the confirm.
    X224Negotiate,
    /// X.224 selected a TLS-based protocol; the adapter is running the rustls handshake, after which
    /// it hands back the server certificate via [`Event::TlsEstablished`].
    TlsHandshake { selected: SecurityProtocol },
    /// TLS is up and the server's public key extracted; the adapter is running the CredSSP token
    /// exchange, completion signalled via [`Event::NlaComplete`].
    NlaCredssp { selected: SecurityProtocol },
    /// HYBRID_EX only: CredSSP finished and the adapter is reading the 4-byte Early User
    /// Authorization Result PDU. Still the `nla-credssp` stage to observers — the early-auth read
    /// is part of NLA, not a stage of its own (CONTEXT.md lists seven stages).
    EarlyUserAuth { selected: SecurityProtocol },
    /// Terminal: the machine emitted [`Action::Authenticated`] or [`Action::FailWith`] and will
    /// accept no further events (each yields [`ConnectError::UnexpectedEvent`]). Internal only —
    /// `last` is the label of the stage where the connect ended, and [`Stage::label`] keeps
    /// reporting it: CONTEXT.md's seven Connect Stages stay the complete observable set (no
    /// eighth label leaks to the host's `on_stage`), and after a failure `stage()` still names
    /// the stage that failed, preserving error attribution.
    Done { last: &'static str },
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Stage::TcpConnect => "tcp-connect",
            Stage::X224Negotiate => "x224-negotiate",
            Stage::TlsHandshake { .. } => "tls-handshake",
            Stage::NlaCredssp { .. } | Stage::EarlyUserAuth { .. } => "nla-credssp",
            Stage::Done { last } => last,
        }
    }

    /// The terminal state, remembering this stage's label as the last observable one.
    fn done(self) -> Stage {
        Stage::Done { last: self.label() }
    }
}

/// The sans-IO RDP connect state machine. Construct it with [`ConnectStateMachine::new`], kick it
/// off with [`ConnectStateMachine::start`], then feed it [`Event`]s; each call returns the
/// [`Action`]s the adapter must perform.
#[derive(Debug)]
pub struct ConnectStateMachine {
    requested: SecurityProtocol,
    stage: Stage,
}

impl ConnectStateMachine {
    /// Create a machine that will advertise `requested` in the X.224 security negotiation.
    pub fn new(requested: SecurityProtocol) -> Self {
        Self {
            requested,
            stage: Stage::TcpConnect,
        }
    }

    /// The current connect stage label, for diagnostics / progress UI.
    pub fn stage(&self) -> &'static str {
        self.stage.label()
    }

    /// Begin the connect sequence: ask the adapter to open the socket.
    pub fn start(&mut self) -> Vec<Action> {
        vec![Action::Connect]
    }

    /// Advance the machine with an input event, returning the actions to perform.
    ///
    /// Dispatch is on the (stage, event) pair: each stage accepts exactly the event it asked the
    /// adapter for, and every other combination fails the connect with
    /// [`ConnectError::UnexpectedEvent`] — see the ordering contract on [`Event`].
    pub fn process(&mut self, event: Event) -> Vec<Action> {
        match (self.stage, event) {
            (Stage::TcpConnect, Event::Connected) => {
                self.stage = Stage::X224Negotiate;
                let neg = NegRequest::new(self.requested).encode();
                let tpdu = x224::encode_connection_request(&neg);
                vec![Action::WriteBytes(tpkt::encode(&tpdu))]
            }
            (Stage::X224Negotiate, Event::Received(bytes)) => match decode_confirm(bytes) {
                Ok(NegResponse::Selected(selected))
                    if selected.bits() != 0 && self.requested.contains(selected) =>
                {
                    // The server picked a TLS-based protocol we advertised: remember it and ask the
                    // adapter to upgrade the socket. The machine advances to `tls-handshake` and
                    // waits for the resulting certificate.
                    self.stage = Stage::TlsHandshake { selected };
                    vec![Action::StartTls { selected }]
                }
                Ok(NegResponse::Selected(selected)) => {
                    self.fail(ConnectError::UnsupportedProtocol(selected))
                }
                Ok(NegResponse::Failure(code)) => {
                    self.fail(ConnectError::NegotiationFailed(code))
                }
                // A partial frame is not an error: wait for the adapter to deliver more bytes.
                Err(justrdp_pdu::DecodeError::NotEnoughBytes { .. }) => Vec::new(),
                // Any other malformed PDU is fatal.
                Err(e) => self.fail(ConnectError::Decode(e)),
            },
            (Stage::TlsHandshake { selected }, Event::TlsEstablished(cert_der)) => {
                match crate::tls::extract_subject_public_key(cert_der) {
                    Ok(server_public_key) => {
                        // TLS is up: hand off into NLA. The adapter runs the CredSSP token exchange
                        // (binding to this key); the machine advances to `nla-credssp` and waits for
                        // the adapter to report completion via `Event::NlaComplete`.
                        self.stage = Stage::NlaCredssp { selected };
                        vec![Action::StartNla {
                            selected,
                            server_public_key,
                        }]
                    }
                    Err(e) => self.fail(ConnectError::TlsHandshake(e)),
                }
            }
            (Stage::NlaCredssp { selected }, Event::NlaComplete) => {
                // HYBRID_EX appends a 4-byte Early User Authorization Result PDU after CredSSP; the
                // machine must consume it before MCS. Plain HYBRID/SSL authenticate immediately.
                if selected.contains(SecurityProtocol::HYBRID_EX) {
                    self.stage = Stage::EarlyUserAuth { selected };
                    vec![Action::AwaitEarlyUserAuth]
                } else {
                    self.stage = self.stage.done();
                    vec![Action::Authenticated { selected }]
                }
            }
            (Stage::EarlyUserAuth { selected }, Event::EarlyUserAuthResult(bytes)) => {
                // 4 bytes little-endian (MS-RDPBCGR 2.2.10.2). Only AUTHZ_SUCCESS grants access;
                // any other value — or a truncated buffer — is a malformed PDU.
                match bytes.get(..4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])) {
                    Some(AUTHZ_SUCCESS) => {
                        self.stage = self.stage.done();
                        vec![Action::Authenticated { selected }]
                    }
                    Some(AUTHZ_ACCESS_DENIED) => self.fail(ConnectError::EarlyUserAuthDenied),
                    _ => self.fail(ConnectError::Decode(
                        justrdp_pdu::DecodeError::InvalidField {
                            field: "authorizationResult",
                            reason: "unrecognized or truncated Early User Authorization Result PDU",
                        },
                    )),
                }
            }
            // Every other (stage, event) combination violates the ordering contract on `Event`:
            // an adapter bug, surfaced as a typed failure — never a panic, never silent.
            (stage, event) => self.fail(ConnectError::UnexpectedEvent {
                stage: stage.label(),
                event: event.kind(),
            }),
        }
    }

    /// Fail the connect: emit [`Action::FailWith`] and move to the terminal [`Stage::Done`], where
    /// every further event is itself an [`ConnectError::UnexpectedEvent`]. The label of the stage
    /// that failed is kept, so `stage()` still attributes the error to it.
    fn fail(&mut self, e: ConnectError) -> Vec<Action> {
        self.stage = self.stage.done();
        vec![Action::FailWith(e)]
    }
}

/// `AUTHZ_SUCCESS` — the HYBRID_EX Early User Authorization Result PDU value that grants the user
/// access (MS-RDPBCGR 2.2.10.2). Any other `authorizationResult` denies or is malformed.
const AUTHZ_SUCCESS: u32 = 0x0000_0000;
/// `AUTHZ_ACCESS_DENIED` — the Early User Authorization Result PDU value that denies access; the
/// client must drop the connection (MS-RDPBCGR 2.2.10.2).
const AUTHZ_ACCESS_DENIED: u32 = 0x0000_0005;

/// Decode a server Connection Confirm frame into its RDP negotiation response, peeling TPKT →
/// X.224 CC → `RDP_NEG_RSP`/`RDP_NEG_FAILURE`. Errors propagate so the caller can distinguish a
/// partial read ([`justrdp_pdu::DecodeError::NotEnoughBytes`]) from a malformed PDU.
fn decode_confirm(bytes: &[u8]) -> Result<NegResponse, justrdp_pdu::DecodeError> {
    let tpdu = tpkt::decode(bytes)?;
    let variable = x224::decode_connection_confirm(tpdu)?;
    NegResponse::decode(variable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requested() -> SecurityProtocol {
        SecurityProtocol::SSL | SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX
    }

    #[test]
    fn start_emits_connect_in_tcp_connect_stage() {
        let mut sm = ConnectStateMachine::new(requested());
        let actions = sm.start();
        assert_eq!(actions, vec![Action::Connect]);
        assert_eq!(sm.stage(), "tcp-connect");
    }

    #[test]
    fn connected_writes_connection_request_and_enters_x224_stage() {
        let mut sm = ConnectStateMachine::new(requested());
        sm.start();
        let actions = sm.process(Event::Connected);
        // The machine writes exactly one frame: TPKT( X.224 CR( RDP_NEG_REQ ) ) advertising
        // SSL|HYBRID|HYBRID_EX (0x0B). The wire format is fixed by MS-RDPBCGR, so the exact
        // bytes are the observable contract.
        assert_eq!(
            actions,
            vec![Action::WriteBytes(vec![
                0x03, 0x00, 0x00, 0x13, // TPKT: version, reserved, length = 19
                0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR: LI=14, code, refs, class
                0x01, 0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x00, // RDP_NEG_REQ: SSL|HYBRID|HYBRID_EX
            ])]
        );
        assert_eq!(sm.stage(), "x224-negotiate");
    }

    /// Wrap an 8-byte RDP negotiation structure in an X.224 Connection Confirm + TPKT, as a
    /// server would on the wire.
    fn wrap_confirm(nego: [u8; 8]) -> Vec<u8> {
        let mut cc = vec![0x0E, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00];
        cc.extend_from_slice(&nego);
        justrdp_pdu::tpkt::encode(&cc)
    }

    /// A Connection Confirm carrying an `RDP_NEG_RSP` selecting `selected`.
    fn connection_confirm(selected: SecurityProtocol) -> Vec<u8> {
        let [s0, s1, s2, s3] = selected.bits().to_le_bytes();
        wrap_confirm([0x02, 0x00, 0x08, 0x00, s0, s1, s2, s3])
    }

    /// A Connection Confirm carrying an `RDP_NEG_FAILURE` with `code`.
    fn connection_failure(code: NegFailureCode) -> Vec<u8> {
        let [c0, c1, c2, c3] = code.0.to_le_bytes();
        wrap_confirm([0x03, 0x00, 0x08, 0x00, c0, c1, c2, c3])
    }

    /// A machine driven to the `x224-negotiate` stage, ready to receive a confirm.
    fn negotiating() -> ConnectStateMachine {
        let mut sm = ConnectStateMachine::new(requested());
        sm.start();
        sm.process(Event::Connected);
        sm
    }

    #[test]
    fn received_confirm_emits_start_tls_and_enters_tls_handshake_stage() {
        let mut sm = negotiating();
        let confirm = connection_confirm(SecurityProtocol::HYBRID);
        let actions = sm.process(Event::Received(&confirm));
        // A valid confirm no longer ends the connect sequence: it hands off to the TLS upgrade. The
        // machine asks the adapter to start the handshake and moves into the `tls-handshake` stage.
        assert_eq!(
            actions,
            vec![Action::StartTls {
                selected: SecurityProtocol::HYBRID
            }]
        );
        assert_eq!(sm.stage(), "tls-handshake");
    }

    /// Drive a machine through the X.224 confirm into the `tls-handshake` stage, selecting `selected`.
    fn awaiting_tls(selected: SecurityProtocol) -> ConnectStateMachine {
        let mut sm = negotiating();
        sm.process(Event::Received(&connection_confirm(selected)));
        sm
    }

    /// Drive a machine through the TLS handshake into the `nla-credssp` stage (the adapter is now
    /// running the CredSSP token exchange), selecting `selected`. The certificate is a throwaway
    /// self-signed cert — only the stage transition matters here, not the extracted key.
    fn awaiting_nla(selected: SecurityProtocol) -> ConnectStateMachine {
        let mut sm = awaiting_tls(selected);
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        sm.process(Event::TlsEstablished(key.cert.der().as_ref()));
        sm
    }

    #[test]
    fn tls_established_emits_start_nla_and_enters_nla_credssp_stage() {
        let mut sm = awaiting_tls(SecurityProtocol::HYBRID);
        // The adapter ran the TLS handshake and hands back the server's leaf certificate. The
        // machine extracts its subjectPublicKey and hands off into NLA: it asks the adapter to run
        // the CredSSP token exchange (binding to that key) and advances to the `nla-credssp` stage.
        // The handshake no longer terminates the connect sequence (slice-2 stopped here; slice-3
        // continues — plan.md decision 10).
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = key.cert.der();

        let actions = sm.process(Event::TlsEstablished(cert_der.as_ref()));

        // The machine threads through whatever the extractor produces (the inner subjectPublicKey —
        // its exact form is tls.rs's contract, verified there); here we pin that StartNla carries it.
        let expected_key = crate::tls::extract_subject_public_key(cert_der.as_ref()).unwrap();
        assert_eq!(
            actions,
            vec![Action::StartNla {
                selected: SecurityProtocol::HYBRID,
                server_public_key: expected_key,
            }]
        );
        assert_eq!(sm.stage(), "nla-credssp");
    }

    #[test]
    fn nla_complete_without_hybrid_ex_emits_authenticated() {
        // On a plain HYBRID connection the CredSSP exchange is the end of authentication: when the
        // adapter reports it finished, the machine is authenticated (no HYBRID_EX early-auth PDU
        // follows). It reports the protocol the server selected.
        let mut sm = awaiting_nla(SecurityProtocol::HYBRID);
        let actions = sm.process(Event::NlaComplete);
        assert_eq!(
            actions,
            vec![Action::Authenticated {
                selected: SecurityProtocol::HYBRID
            }]
        );
    }

    /// Drive a HYBRID_EX machine to the point where it is waiting for the Early User Authorization
    /// Result PDU (CredSSP done, `AwaitEarlyUserAuth` emitted).
    fn awaiting_early_user_auth() -> ConnectStateMachine {
        let mut sm = awaiting_nla(SecurityProtocol::HYBRID_EX);
        sm.process(Event::NlaComplete);
        sm
    }

    #[test]
    fn early_user_auth_granted_emits_authenticated() {
        let mut sm = awaiting_early_user_auth();
        // AUTHZ_SUCCESS = 0x00000000, 4 bytes little-endian (MS-RDPBCGR 2.2.10.2).
        let actions = sm.process(Event::EarlyUserAuthResult(&[0x00, 0x00, 0x00, 0x00]));
        assert_eq!(
            actions,
            vec![Action::Authenticated {
                selected: SecurityProtocol::HYBRID_EX
            }]
        );
    }

    #[test]
    fn early_user_auth_denied_fails_with_early_user_auth_denied() {
        let mut sm = awaiting_early_user_auth();
        // AUTHZ_ACCESS_DENIED = 0x00000005: the server rejected the user. The client must drop the
        // connection (MS-RDPBCGR — "login to the remote session will not be possible").
        let actions = sm.process(Event::EarlyUserAuthResult(&[0x05, 0x00, 0x00, 0x00]));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::EarlyUserAuthDenied)]
        );
    }

    #[test]
    fn early_user_auth_unrecognized_code_fails_with_decode() {
        let mut sm = awaiting_early_user_auth();
        // Neither AUTHZ_SUCCESS (0) nor AUTHZ_ACCESS_DENIED (5): a malformed PDU, surfaced as a
        // decode error rather than silently treated as success.
        let actions = sm.process(Event::EarlyUserAuthResult(&[0x99, 0x00, 0x00, 0x00]));
        assert!(matches!(
            actions.as_slice(),
            [Action::FailWith(ConnectError::Decode(_))]
        ));
    }

    #[test]
    fn nla_complete_with_hybrid_ex_awaits_early_user_auth() {
        // HYBRID_EX adds a step: the server sends a 4-byte Early User Authorization Result PDU right
        // after CredSSP, before MCS (plan.md §0 — unconsumed, capability exchange desyncs). So on
        // NlaComplete the machine does not authenticate yet; it asks the adapter to read that PDU
        // and stays in `nla-credssp`.
        let mut sm = awaiting_nla(SecurityProtocol::HYBRID_EX);
        let actions = sm.process(Event::NlaComplete);
        assert_eq!(actions, vec![Action::AwaitEarlyUserAuth]);
        assert_eq!(sm.stage(), "nla-credssp");
    }

    #[test]
    fn tls_established_with_malformed_cert_fails_with_tls_handshake() {
        let mut sm = awaiting_tls(SecurityProtocol::HYBRID);
        // The handshake "completed" but the certificate the adapter handed back is not parseable.
        let actions = sm.process(Event::TlsEstablished(&[0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::TlsHandshake(
                crate::tls::TlsCertError::MalformedCertificate
            ))]
        );
    }

    #[test]
    fn received_confirm_selecting_unadvertised_protocol_fails() {
        let mut sm = negotiating();
        // RDSTLS (0x04) was never in our advertised SSL|HYBRID|HYBRID_EX set.
        let rdstls = SecurityProtocol::from_bits(0x04);
        let confirm = connection_confirm(rdstls);
        let actions = sm.process(Event::Received(&confirm));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::UnsupportedProtocol(rdstls))]
        );
    }

    #[test]
    fn received_confirm_selecting_standard_security_is_rejected() {
        let mut sm = negotiating();
        // PROTOCOL_RDP (0x00) = legacy RC4 Standard Security. It is a (trivial) subset of any
        // advertised set, so it must be rejected explicitly — justrdp never accepts it (ADR-0002).
        let standard = SecurityProtocol::from_bits(0x00);
        let confirm = connection_confirm(standard);
        let actions = sm.process(Event::Received(&confirm));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::UnsupportedProtocol(standard))]
        );
    }

    #[test]
    fn received_partial_frame_waits_for_more_bytes() {
        let mut sm = negotiating();
        let confirm = connection_confirm(SecurityProtocol::HYBRID);
        // Only the first 5 of 19 bytes have arrived — the machine must wait, not act.
        let actions = sm.process(Event::Received(&confirm[..5]));
        assert!(actions.is_empty());
        assert_eq!(sm.stage(), "x224-negotiate");
    }

    #[test]
    fn received_malformed_confirm_emits_failwith_decode() {
        let mut sm = negotiating();
        // A complete TPKT frame, but the X.224 code is a Connection *Request* (0xE0), not a
        // Confirm — a malformed response, distinct from a partial read.
        let mut cc = vec![0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00];
        cc.extend_from_slice(&[0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]);
        let frame = justrdp_pdu::tpkt::encode(&cc);
        let actions = sm.process(Event::Received(&frame));
        assert!(matches!(
            actions.as_slice(),
            [Action::FailWith(ConnectError::Decode(_))]
        ));
    }

    #[test]
    fn received_failure_emits_failwith_negotiation_failed() {
        let mut sm = negotiating();
        let failure = connection_failure(NegFailureCode::HYBRID_REQUIRED_BY_SERVER);
        let actions = sm.process(Event::Received(&failure));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::NegotiationFailed(
                NegFailureCode::HYBRID_REQUIRED_BY_SERVER
            ))]
        );
    }

    /// All event kinds, for the stage × event mismatch matrix.
    const ALL_EVENT_KINDS: [EventKind; 5] = [
        EventKind::Connected,
        EventKind::Received,
        EventKind::TlsEstablished,
        EventKind::NlaComplete,
        EventKind::EarlyUserAuthResult,
    ];

    /// A representative event of `kind`. Payloads are minimal — for a mismatched (stage, event)
    /// pair the machine must reject on the pairing alone, before looking at any payload.
    fn sample_event(kind: EventKind) -> Event<'static> {
        match kind {
            EventKind::Connected => Event::Connected,
            EventKind::Received => Event::Received(&[]),
            EventKind::TlsEstablished => Event::TlsEstablished(&[]),
            EventKind::NlaComplete => Event::NlaComplete,
            EventKind::EarlyUserAuthResult => Event::EarlyUserAuthResult(&[0, 0, 0, 0]),
        }
    }

    /// A machine driven to the terminal stage via the success path (Authenticated emitted).
    fn done_authenticated() -> ConnectStateMachine {
        let mut sm = awaiting_nla(SecurityProtocol::HYBRID);
        sm.process(Event::NlaComplete);
        sm
    }

    /// A machine driven to the terminal stage via the failure path (FailWith emitted).
    fn done_failed() -> ConnectStateMachine {
        let mut sm = negotiating();
        sm.process(Event::Received(&connection_failure(
            NegFailureCode::HYBRID_REQUIRED_BY_SERVER,
        )));
        sm
    }

    #[test]
    fn stage_mismatched_events_fail_with_unexpected_event() {
        // The full ordering-contract matrix: for every stage, every event the stage does not
        // expect yields FailWith(UnexpectedEvent { stage, event }) — never a panic, never a
        // silent misparse (e.g. Received after x224-negotiate used to be re-decoded as a confirm).
        type Make = fn() -> ConnectStateMachine;
        let stages: [(Make, &str, &[EventKind]); 7] = [
            (
                || ConnectStateMachine::new(requested()),
                "tcp-connect",
                &[EventKind::Connected],
            ),
            (negotiating, "x224-negotiate", &[EventKind::Received]),
            (
                || awaiting_tls(SecurityProtocol::HYBRID),
                "tls-handshake",
                &[EventKind::TlsEstablished],
            ),
            (
                || awaiting_nla(SecurityProtocol::HYBRID),
                "nla-credssp",
                &[EventKind::NlaComplete],
            ),
            (
                awaiting_early_user_auth,
                "nla-credssp",
                &[EventKind::EarlyUserAuthResult],
            ),
            // Terminal machines keep reporting the label of the stage where the connect ended —
            // no eighth "done" label is ever observable (CONTEXT.md lists seven Connect Stages).
            (done_authenticated, "nla-credssp", &[]),
            (done_failed, "x224-negotiate", &[]),
        ];

        for (make, label, expected) in stages {
            for kind in ALL_EVENT_KINDS {
                if expected.contains(&kind) {
                    continue;
                }
                let mut sm = make();
                assert_eq!(sm.stage(), label, "stage constructor drove to the wrong stage");
                let actions = sm.process(sample_event(kind));
                assert_eq!(
                    actions,
                    vec![Action::FailWith(ConnectError::UnexpectedEvent {
                        stage: label,
                        event: kind,
                    })],
                    "stage {label} fed {kind:?} must fail with UnexpectedEvent"
                );
                // The violation is terminal — but the label stays attributed to the stage where
                // the connect ended, so on_stage observers never see a label change here...
                assert_eq!(sm.stage(), label);
                // ...and any further event (even the stage's formerly-expected one) fails typed.
                let replay = sm.process(sample_event(kind));
                assert_eq!(
                    replay,
                    vec![Action::FailWith(ConnectError::UnexpectedEvent {
                        stage: label,
                        event: kind,
                    })],
                    "terminal machine in {label} fed {kind:?} again must stay failed"
                );
            }
        }
    }

    #[test]
    fn nla_complete_in_early_user_auth_substage_is_unexpected() {
        // Regression pin for a latent pre-typed-error bug: a duplicate NlaComplete while awaiting
        // the early-auth PDU used to re-emit AwaitEarlyUserAuth (double read). Both sub-states
        // share the "nla-credssp" label, so the matrix above covers this pair too — this test
        // documents the specific duplicate-event shape.
        let mut sm = awaiting_early_user_auth();
        let actions = sm.process(Event::NlaComplete);
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::UnexpectedEvent {
                stage: "nla-credssp",
                event: EventKind::NlaComplete,
            })]
        );
    }

    #[test]
    fn replay_after_authentication_is_unexpected() {
        // The terminal state accepts nothing: replaying the very event that authenticated must
        // fail typed, not re-emit Authenticated. The reported stage stays the one where the
        // connect ended (authentication completes inside nla-credssp).
        let mut sm = done_authenticated();
        let actions = sm.process(Event::NlaComplete);
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::UnexpectedEvent {
                stage: "nla-credssp",
                event: EventKind::NlaComplete,
            })]
        );
    }

    #[test]
    fn terminal_machine_keeps_the_last_canonical_stage_label() {
        // Termination is internal: stage() keeps attributing to the stage where the connect
        // ended — the failing stage after FailWith, the authenticating stage after Authenticated.
        // No "done" (or any other non-glossary) label is ever observable, so a host's on_stage
        // sees only CONTEXT.md's seven Connect Stage labels and error attribution survives.
        assert_eq!(done_failed().stage(), "x224-negotiate");
        assert_eq!(done_authenticated().stage(), "nla-credssp");
    }
}
