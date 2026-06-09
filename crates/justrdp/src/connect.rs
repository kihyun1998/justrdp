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
    /// The TLS upgrade is complete; the connect sequence may advance past `tls-handshake`. Carries
    /// the server-selected protocol and the server's `subjectPublicKey` (DER `SubjectPublicKeyInfo`)
    /// that CredSSP will bind to in the next slice.
    Proceed {
        /// The protocol the server chose in the X.224 Connection Confirm.
        selected: SecurityProtocol,
        /// The server's `subjectPublicKey` extracted from its TLS certificate (raw DER).
        server_public_key: Vec<u8>,
    },
    /// The connect attempt failed; surface this error and tear down.
    FailWith(ConnectError),
}

/// An input handed to the machine by the host adapter.
#[derive(Debug, Clone, Copy)]
pub enum Event<'a> {
    /// The TCP socket finished connecting.
    Connected,
    /// Bytes arrived from the socket.
    Received(&'a [u8]),
    /// The TLS handshake the adapter ran (after [`Action::StartTls`]) completed; carries the
    /// server's leaf certificate (DER) so the machine can extract its `subjectPublicKey`.
    TlsEstablished(&'a [u8]),
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
}

/// The labeled connect sub-step the machine is in (CONTEXT.md "Connect Stage"). slice-1 stops at
/// `x224-negotiate`; later slices extend this set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Before the socket is up — the machine has asked the adapter to `Connect`.
    TcpConnect,
    /// Socket is up; the X.224 security negotiation request has been sent, awaiting the confirm.
    X224Negotiate,
    /// X.224 selected a TLS-based protocol; the adapter is running the rustls handshake, after which
    /// it hands back the server certificate via [`Event::TlsEstablished`].
    TlsHandshake,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Stage::TcpConnect => "tcp-connect",
            Stage::X224Negotiate => "x224-negotiate",
            Stage::TlsHandshake => "tls-handshake",
        }
    }
}

/// The sans-IO RDP connect state machine. Construct it with [`ConnectStateMachine::new`], kick it
/// off with [`ConnectStateMachine::start`], then feed it [`Event`]s; each call returns the
/// [`Action`]s the adapter must perform.
#[derive(Debug)]
pub struct ConnectStateMachine {
    requested: SecurityProtocol,
    stage: Stage,
    /// The protocol the server selected in the X.224 confirm, remembered across the TLS handshake so
    /// it can be reported once the certificate arrives. `None` until the confirm is processed.
    negotiated: Option<SecurityProtocol>,
}

impl ConnectStateMachine {
    /// Create a machine that will advertise `requested` in the X.224 security negotiation.
    pub fn new(requested: SecurityProtocol) -> Self {
        Self {
            requested,
            stage: Stage::TcpConnect,
            negotiated: None,
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
    pub fn process(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::Connected => {
                self.stage = Stage::X224Negotiate;
                let neg = NegRequest::new(self.requested).encode();
                let tpdu = x224::encode_connection_request(&neg);
                vec![Action::WriteBytes(tpkt::encode(&tpdu))]
            }
            Event::Received(bytes) => match decode_confirm(bytes) {
                Ok(NegResponse::Selected(selected))
                    if selected.bits() != 0 && self.requested.contains(selected) =>
                {
                    // The server picked a TLS-based protocol we advertised: remember it and ask the
                    // adapter to upgrade the socket. The machine advances to `tls-handshake` and
                    // waits for the resulting certificate.
                    self.stage = Stage::TlsHandshake;
                    self.negotiated = Some(selected);
                    vec![Action::StartTls { selected }]
                }
                Ok(NegResponse::Selected(selected)) => {
                    vec![Action::FailWith(ConnectError::UnsupportedProtocol(selected))]
                }
                Ok(NegResponse::Failure(code)) => {
                    vec![Action::FailWith(ConnectError::NegotiationFailed(code))]
                }
                // A partial frame is not an error: wait for the adapter to deliver more bytes.
                Err(justrdp_pdu::DecodeError::NotEnoughBytes { .. }) => Vec::new(),
                // Any other malformed PDU is fatal.
                Err(e) => vec![Action::FailWith(ConnectError::Decode(e))],
            },
            Event::TlsEstablished(cert_der) => {
                let selected = self
                    .negotiated
                    .expect("TlsEstablished only follows a StartTls in the tls-handshake stage");
                match crate::tls::extract_subject_public_key(cert_der) {
                    Ok(server_public_key) => vec![Action::Proceed {
                        selected,
                        server_public_key,
                    }],
                    Err(e) => vec![Action::FailWith(ConnectError::TlsHandshake(e))],
                }
            }
        }
    }
}

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

    #[test]
    fn tls_established_emits_proceed_with_extracted_public_key() {
        let mut sm = awaiting_tls(SecurityProtocol::HYBRID);
        // The adapter ran the TLS handshake and hands back the server's leaf certificate. The
        // machine extracts its subjectPublicKey and reports the completed upgrade.
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = key.cert.der();

        let actions = sm.process(Event::TlsEstablished(cert_der.as_ref()));

        assert_eq!(
            actions,
            vec![Action::Proceed {
                selected: SecurityProtocol::HYBRID,
                server_public_key: key.key_pair.public_key_der(),
            }]
        );
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
}
