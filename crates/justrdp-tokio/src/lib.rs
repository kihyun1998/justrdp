//! `justrdp-tokio` — the thin Tokio I/O adapter that makes the sans-IO [`justrdp`] core real
//! (ADR-0001). It owns the socket; the state machine owns the protocol. The adapter drains the
//! machine's [`Action`]s (open the socket, write bytes, start TLS), feeds it [`Event`]s (connected,
//! bytes received, TLS established), and applies a per-stage timeout — surfacing the stage name on
//! failure.
//!
//! slice-2 drives the first three connect stages (`tcp-connect` → `x224-negotiate` →
//! `tls-handshake`). The TLS handshake itself runs here, not in the core: rustls is its own sans-IO
//! state machine, so shuttling its records through the connect machine would add nothing (plan.md
//! §3). The machine only sees the resulting server certificate, from which it extracts the
//! `subjectPublicKey`. Later slices extend the same loop through NLA, MCS, and activation.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use justrdp::{Action, ConnectError, ConnectStateMachine, Event};
use justrdp_pdu::nego::SecurityProtocol;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Timeout for the TCP dial.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for each post-TCP connect stage (X.224 round trip, TLS handshake, …). Per plan.md §11e
/// these share one bound, applied per stage rather than cumulatively.
const STAGE_TIMEOUT: Duration = Duration::from_secs(15);

/// A successful slice-2 connect: the server-selected transport security protocol, the server's
/// `subjectPublicKey` (for CredSSP binding in the next slice), and the live TLS stream.
#[derive(Debug)]
pub struct ConnectOutcome {
    /// The protocol the server chose in the X.224 Connection Confirm.
    pub selected: SecurityProtocol,
    /// The server's `subjectPublicKey` (DER `SubjectPublicKeyInfo`) extracted from its TLS
    /// certificate. CredSSP binds its `pubKeyAuth` to this in the NLA slice.
    pub server_public_key: Vec<u8>,
    /// The TLS-upgraded stream, positioned just after the handshake, ready for NLA.
    pub stream: TlsStream<TcpStream>,
}

/// Why the adapter-driven connect failed.
#[derive(Debug)]
pub enum ConnectFailure {
    /// A socket-level error.
    Io(io::Error),
    /// The protocol state machine rejected the exchange (includes a malformed server certificate,
    /// surfaced as [`ConnectError::TlsHandshake`]).
    Protocol(ConnectError),
    /// The rustls TLS handshake itself failed (e.g. the peer did not speak TLS, or no certificate
    /// was presented). Cert *parsing* failures arrive via [`ConnectFailure::Protocol`] instead.
    TlsHandshake {
        /// A human-readable description of the handshake failure.
        reason: String,
    },
    /// A connect stage exceeded its timeout; carries the stage name.
    Timeout {
        /// The stage that timed out (e.g. `"tcp-connect"`, `"tls-handshake"`).
        stage: &'static str,
    },
}

impl std::fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectFailure::Io(e) => write!(f, "i/o error: {e}"),
            ConnectFailure::Protocol(e) => write!(f, "protocol error: {e:?}"),
            ConnectFailure::TlsHandshake { reason } => write!(f, "TLS handshake failed: {reason}"),
            ConnectFailure::Timeout { stage } => write!(f, "timed out during stage {stage}"),
        }
    }
}

impl std::error::Error for ConnectFailure {}

impl From<io::Error> for ConnectFailure {
    fn from(e: io::Error) -> Self {
        ConnectFailure::Io(e)
    }
}

/// Connect to `addr`, run the X.224 security negotiation advertising `requested`, then upgrade the
/// socket to TLS. `on_stage` is called with each connect stage label as it is entered, for progress
/// UI / diagnostics.
///
/// Returns the negotiated protocol, the server's `subjectPublicKey`, and the live TLS stream.
#[tracing::instrument(
    skip(on_stage),
    fields(host = %addr.ip(), port = addr.port()),
    err,
)]
pub async fn connect(
    addr: SocketAddr,
    requested: SecurityProtocol,
    mut on_stage: impl FnMut(&str),
) -> Result<ConnectOutcome, ConnectFailure> {
    let mut sm = ConnectStateMachine::new(requested);
    let mut tcp: Option<TcpStream> = None;
    let mut tls: Option<TlsStream<TcpStream>> = None;
    let mut inbox: Vec<u8> = Vec::new();
    let mut readbuf = [0u8; 8192];
    let mut queue: VecDeque<Action> = sm.start().into();
    let mut announced = sm.stage();
    on_stage(announced);
    tracing::debug!(stage = announced, "entering connect stage");

    loop {
        while let Some(action) = queue.pop_front() {
            match action {
                Action::Connect => {
                    let s = with_stage_timeout(
                        "tcp-connect",
                        TCP_CONNECT_TIMEOUT,
                        TcpStream::connect(addr),
                    )
                    .await?;
                    tracing::debug!("tcp socket connected");
                    tcp = Some(s);
                    queue.extend(sm.process(Event::Connected));
                    announce_stage(&mut sm, &mut announced, &mut on_stage);
                }
                Action::WriteBytes(bytes) => {
                    let s = tcp.as_mut().expect("socket connected before write");
                    s.write_all(&bytes).await?;
                    tracing::debug!(bytes = bytes.len(), "wrote frame to socket");
                }
                Action::StartTls { selected } => {
                    // The handshake runs here, never in the core machine. We hand only the resulting
                    // peer certificate back to the machine, which extracts its subjectPublicKey.
                    let stream = tcp.take().expect("socket connected before TLS upgrade");
                    let connector = TlsConnector::from(Arc::new(client_config()));
                    let server_name = ServerName::IpAddress(addr.ip().into());
                    tracing::debug!(?selected, "starting TLS handshake");
                    let established = match tokio::time::timeout(
                        STAGE_TIMEOUT,
                        connector.connect(server_name, stream),
                    )
                    .await
                    {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            return Err(ConnectFailure::TlsHandshake {
                                reason: e.to_string(),
                            });
                        }
                        Err(_) => return Err(ConnectFailure::Timeout { stage: "tls-handshake" }),
                    };
                    let cert = established
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .ok_or_else(|| ConnectFailure::TlsHandshake {
                            reason: "server presented no certificate".to_string(),
                        })?
                        .clone();
                    tracing::debug!("tls handshake complete; extracting server public key");
                    queue.extend(sm.process(Event::TlsEstablished(cert.as_ref())));
                    tls = Some(established);
                    announce_stage(&mut sm, &mut announced, &mut on_stage);
                }
                Action::Proceed {
                    selected,
                    server_public_key,
                } => {
                    tracing::debug!(
                        ?selected,
                        key_len = server_public_key.len(),
                        "tls upgrade complete"
                    );
                    return Ok(ConnectOutcome {
                        selected,
                        server_public_key,
                        stream: tls.expect("tls established before proceed"),
                    });
                }
                Action::FailWith(e) => return Err(ConnectFailure::Protocol(e)),
            }
        }

        // The queue drained without a terminal action: the machine needs more bytes. This only
        // happens during the plaintext X.224 phase; once TLS starts, StartTls → Proceed drains the
        // queue without re-entering the read.
        let s = tcp.as_mut().expect("socket connected before read");
        let n = with_stage_timeout(sm.stage(), STAGE_TIMEOUT, s.read(&mut readbuf)).await?;
        if n == 0 {
            return Err(ConnectFailure::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "server closed connection during X.224 negotiation",
            )));
        }
        tracing::debug!(bytes = n, stage = sm.stage(), "read from socket");
        inbox.extend_from_slice(&readbuf[..n]);
        queue.extend(sm.process(Event::Received(&inbox)));
        announce_stage(&mut sm, &mut announced, &mut on_stage);
    }
}

/// Notify `on_stage` only when the machine's stage actually changed, so each connect stage is
/// announced exactly once.
fn announce_stage(
    sm: &mut ConnectStateMachine,
    announced: &mut &'static str,
    on_stage: &mut impl FnMut(&str),
) {
    if sm.stage() != *announced {
        *announced = sm.stage();
        on_stage(announced);
        tracing::debug!(stage = *announced, "entering connect stage");
    }
}

/// Await `fut` under the stage's timeout, mapping the outcome into a [`ConnectFailure`]: an I/O
/// error becomes `Io`, and an elapsed timeout becomes `Timeout { stage }`. Every connect stage
/// wraps its I/O through this single seam so the timeout/error policy lives in one place.
async fn with_stage_timeout<T>(
    stage: &'static str,
    dur: Duration,
    fut: impl Future<Output = io::Result<T>>,
) -> Result<T, ConnectFailure> {
    match tokio::time::timeout(dur, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(ConnectFailure::Io(e)),
        Err(_) => Err(ConnectFailure::Timeout { stage }),
    }
}

/// A rustls client config that accepts any server certificate. slice-2's policy is `validate=false`:
/// we extract the public key but do not yet verify the chain / name (CN/SAN, chain-of-trust, and
/// TOFU pinning are follow-up slices, per plan.md §22). The `ring` crypto provider is selected
/// explicitly so no process-default provider needs installing.
fn client_config() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default TLS protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { provider }))
        .with_no_client_auth()
}

/// A `ServerCertVerifier` that accepts every certificate and signature. Used only for slice-2's
/// extract-the-key-but-don't-validate policy; real validation arrives in a later slice.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tracing_test::traced_test;

    fn requested() -> SecurityProtocol {
        SecurityProtocol::SSL | SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX
    }

    #[tokio::test]
    async fn with_stage_timeout_passes_through_ready_value() {
        let out =
            with_stage_timeout("test", Duration::from_secs(1), async { Ok::<u8, io::Error>(42) })
                .await;
        assert!(matches!(out, Ok(42)));
    }

    #[tokio::test]
    async fn with_stage_timeout_maps_io_error_to_io() {
        let out: Result<u8, ConnectFailure> =
            with_stage_timeout("test", Duration::from_secs(1), async {
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
            })
            .await;
        assert!(matches!(out, Err(ConnectFailure::Io(_))));
    }

    #[tokio::test]
    async fn with_stage_timeout_maps_elapsed_to_timeout_with_stage() {
        // A future that never resolves must elapse and surface the stage name.
        let never = std::future::pending::<io::Result<u8>>();
        let out = with_stage_timeout("tls-handshake", Duration::from_millis(10), never).await;
        assert!(matches!(
            out,
            Err(ConnectFailure::Timeout {
                stage: "tls-handshake"
            })
        ));
    }

    /// A captured X.224 Connection Confirm carrying an 8-byte RDP negotiation structure.
    fn confirm_frame(nego: [u8; 8]) -> Vec<u8> {
        let mut cc = vec![0x0E, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00];
        cc.extend_from_slice(&nego);
        justrdp_pdu::tpkt::encode(&cc)
    }

    /// A rustls server config presenting `cert` / `key` (DER), accepting any client. Mirrors the
    /// client's explicit `ring` provider selection.
    fn server_config(cert: CertificateDer<'static>, key_pkcs8: Vec<u8>) -> rustls::ServerConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default TLS protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![cert],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8)),
            )
            .expect("self-signed cert and matching key form a valid single-cert config")
    }

    /// Spawn a one-shot mock RDP server on loopback: it reads the client's plaintext Connection
    /// Request, replies with a Connection Confirm carrying `nego`, then runs the TLS handshake with
    /// a throwaway self-signed cert. Returns the address and the server's expected
    /// `subjectPublicKey` (so the test can assert the client extracted exactly it).
    async fn mock_tls_server(nego: [u8; 8]) -> (SocketAddr, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let expected_spki = ck.key_pair.public_key_der();
        let cert = ck.cert.der().clone();
        let key = ck.key_pair.serialize_der();
        let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 64];
            let _ = sock.read(&mut scratch).await.unwrap(); // drain the plaintext Connection Request
            sock.write_all(&confirm_frame(nego)).await.unwrap(); // plaintext Connection Confirm
            let mut tls = acceptor.accept(sock).await.unwrap(); // TLS handshake
            let mut buf = [0u8; 1];
            let _ = tls.read(&mut buf).await; // hold the connection open until the client finishes
        });
        (addr, expected_spki)
    }

    #[tokio::test]
    async fn connect_completes_tls_and_returns_server_public_key() {
        // Server selects HYBRID (0x02), then completes the TLS handshake.
        let (addr, expected_spki) =
            mock_tls_server([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]).await;

        let mut stages = Vec::new();
        let outcome = connect(addr, requested(), |s| stages.push(s.to_string()))
            .await
            .unwrap();

        assert_eq!(outcome.selected, SecurityProtocol::HYBRID);
        // The extracted subjectPublicKey must be byte-identical to the server cert's own key.
        assert_eq!(outcome.server_public_key, expected_spki);
        assert_eq!(stages, vec!["tcp-connect", "x224-negotiate", "tls-handshake"]);
    }

    #[tokio::test]
    #[traced_test]
    async fn connect_logs_stage_transitions_including_tls_handshake() {
        let (addr, _) = mock_tls_server([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]).await;
        connect(addr, requested(), |_| {}).await.unwrap();

        // Every connect stage is named in the debug logs (criterion 14: observable transitions)...
        assert!(logs_contain("tcp-connect"), "tcp-connect stage not logged");
        assert!(logs_contain("x224-negotiate"), "x224-negotiate stage not logged");
        assert!(logs_contain("tls-handshake"), "tls-handshake stage not logged");
        // ...and byte counts are logged for the plaintext bytes written and read.
        assert!(logs_contain("bytes="), "byte counts not logged");
    }

    /// Spawn a server that completes X.224 but then speaks garbage instead of TLS, so the handshake
    /// fails. Returns the address.
    async fn mock_non_tls_server(nego: [u8; 8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 64];
            let _ = sock.read(&mut scratch).await.unwrap();
            sock.write_all(&confirm_frame(nego)).await.unwrap();
            // Not a TLS ServerHello — the client's rustls handshake must reject this.
            sock.write_all(b"this is not a tls record").await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn connect_surfaces_tls_handshake_failure() {
        let addr = mock_non_tls_server([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]).await;
        let err = connect(addr, requested(), |_| {}).await.unwrap_err();
        assert!(
            matches!(err, ConnectFailure::TlsHandshake { .. }),
            "expected a TLS handshake failure, got {err:?}"
        );
    }

    #[tokio::test]
    async fn connect_surfaces_server_negotiation_failure() {
        // Server refuses with RDP_NEG_FAILURE / HYBRID_REQUIRED_BY_SERVER (0x05) before any TLS.
        let addr = mock_non_tls_server([0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00]).await;

        let err = connect(addr, requested(), |_| {}).await.unwrap_err();
        assert!(
            matches!(
                err,
                ConnectFailure::Protocol(ConnectError::NegotiationFailed(_))
            ),
            "expected a protocol negotiation failure, got {err:?}"
        );
    }

    /// Real-VM acceptance test (ADR-0001 differential/real-VM harness). Ignored by default — run
    /// with `cargo test -p justrdp-tokio -- --ignored` against the live RDP test VM. Verifies the
    /// adapter completes X.224 negotiation **and** the TLS upgrade, extracting the server's
    /// subjectPublicKey.
    #[tokio::test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389"]
    async fn connect_completes_tls_against_real_vm() {
        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let req = requested();

        let outcome = connect(addr, req, |stage| eprintln!("stage: {stage}"))
            .await
            .expect("X.224 + TLS upgrade should complete against the real VM");

        eprintln!("server selected protocol: {:?}", outcome.selected);
        eprintln!(
            "extracted subjectPublicKey: {} bytes",
            outcome.server_public_key.len()
        );
        // The server must select exactly one protocol from the set we advertised...
        assert!(outcome.selected.bits() != 0);
        assert!(req.contains(outcome.selected));
        // ...and we must have extracted a non-empty public key from its TLS certificate.
        assert!(!outcome.server_public_key.is_empty());
    }
}
