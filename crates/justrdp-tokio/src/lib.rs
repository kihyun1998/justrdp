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
use sspi::credssp::{ClientMode, ClientState, CredSspClient, CredSspMode, TsRequest};
use sspi::generator::GeneratorState;
use sspi::negotiate::NegotiateConfig;
use sspi::ntlm::NtlmConfig;
use sspi::{AuthIdentity, Credentials as SspiCredentials, Secret, Username};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Timeout for the TCP dial.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for each post-TCP connect stage (X.224 round trip, TLS handshake, …). Per plan.md §11e
/// these share one bound, applied per stage rather than cumulatively.
const STAGE_TIMEOUT: Duration = Duration::from_secs(15);
/// Upper bound on a single CredSSP `TsRequest` we will buffer from the server. A real TSRequest is a
/// few KB at most (NTLM / SPNEGO tokens; Kerberos PACs are larger but still modest); this caps a
/// hostile or buggy server's BER length field so it cannot drive an unbounded allocation from the
/// `nla-credssp` read before the bytes are even validated.
const MAX_TS_REQUEST_LEN: usize = 64 * 1024;

/// A successful connect through NLA: the server-selected transport security protocol and the live,
/// authenticated TLS stream — positioned just after CredSSP (and the HYBRID_EX early-auth check),
/// ready for MCS connect in the next slice.
#[derive(Debug)]
pub struct ConnectOutcome {
    /// The protocol the server chose in the X.224 Connection Confirm.
    pub selected: SecurityProtocol,
    /// The TLS-upgraded, NLA-authenticated stream, ready for MCS.
    pub stream: TlsStream<TcpStream>,
}

/// Credentials for NLA (CredSSP / NTLM). The adapter converts these into an `sspi` auth identity and
/// drives the CredSSP exchange with them; they never enter the sans-IO core (no secrets in the pure
/// machine — plan.md decision 10).
#[derive(Clone)]
pub struct Credentials {
    /// The account name without domain, e.g. `"rdptest"`.
    pub username: String,
    /// The account password.
    pub password: String,
    /// The account's domain (NetBIOS or DNS), or `None` for a local / workgroup account.
    pub domain: Option<String>,
}

impl Credentials {
    /// Build the `sspi` auth identity the `CredSspClient` consumes. The `username` field may be a
    /// bare account name (with the domain supplied separately) or already qualified
    /// (`DOMAIN\user` / `user@domain`); an unparseable name surfaces as an [`ConnectFailure::Nla`]
    /// rather than a panic. The password is moved into an `sspi::Secret` so it is zeroized on drop
    /// and never logged.
    fn to_sspi(&self) -> Result<SspiCredentials, ConnectFailure> {
        let username = match self.domain.as_deref() {
            Some(domain) => Username::new(&self.username, Some(domain)),
            // No explicit domain: accept a qualified name, else treat it as a bare account.
            None => Username::parse(&self.username).or_else(|_| Username::new(&self.username, None)),
        }
        .map_err(|e| ConnectFailure::Nla {
            reason: format!("invalid username: {e}"),
        })?;
        Ok(SspiCredentials::AuthIdentity(AuthIdentity {
            username,
            password: Secret::new(self.password.clone()),
        }))
    }
}

// Credentials carry a secret; never derive Debug. A redacted impl keeps it usable in diagnostics.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("domain", &self.domain)
            .finish()
    }
}

/// The server endpoint to dial, preserving the host **exactly as the caller wrote it** — a DNS
/// name or an IP literal. Resolution to socket addresses happens at dial time; the original form
/// is kept because three consumers depend on it and must agree on the same name:
///
/// 1. **TLS SNI** — the rustls `ServerName` in the ClientHello (a DNS name when dialed by name).
/// 2. **CredSSP SPN** — `TERMSRV/<host>`. NTLM ignores it, but Kerberos can only obtain a service
///    ticket for the hostname form (#45).
/// 3. **Certificate validation** — chain/SAN verification (#36) checks the certificate against
///    the name the user intended to reach, not whatever it resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddr {
    /// Hostname or IP literal, as dialed.
    pub host: String,
    /// TCP port (RDP default 3389).
    pub port: u16,
}

impl ServerAddr {
    /// A server endpoint from a host (DNS name or IP literal) and port.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// The CredSSP service principal name for this server: `TERMSRV/<host>`, with the host in
    /// whatever form the caller dialed (hostname-based SPNs are what Kerberos requires — #45).
    fn credssp_spn(&self) -> String {
        format!("TERMSRV/{}", self.host)
    }
}

/// Dial by raw socket address: the host becomes the IP literal, so SNI and the SPN carry the IP —
/// the pre-[`ServerAddr`] behavior, kept for callers that genuinely only have an address.
impl From<SocketAddr> for ServerAddr {
    fn from(addr: SocketAddr) -> Self {
        Self {
            host: addr.ip().to_string(),
            port: addr.port(),
        }
    }
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
    /// NLA (CredSSP / NTLM) authentication failed: bad credentials, a malformed TSRequest, or an
    /// unsupported mechanism (e.g. the server demanded Kerberos, which needs a KDC round-trip this
    /// slice does not drive). A *denied* HYBRID_EX early-auth result is a protocol error
    /// ([`ConnectError::EarlyUserAuthDenied`]) and arrives via [`ConnectFailure::Protocol`] instead.
    Nla {
        /// A human-readable description of the authentication failure.
        reason: String,
    },
}

impl std::fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectFailure::Io(e) => write!(f, "i/o error: {e}"),
            ConnectFailure::Protocol(e) => write!(f, "protocol error: {e:?}"),
            ConnectFailure::TlsHandshake { reason } => write!(f, "TLS handshake failed: {reason}"),
            ConnectFailure::Timeout { stage } => write!(f, "timed out during stage {stage}"),
            ConnectFailure::Nla { reason } => write!(f, "NLA authentication failed: {reason}"),
        }
    }
}

impl std::error::Error for ConnectFailure {}

impl From<io::Error> for ConnectFailure {
    fn from(e: io::Error) -> Self {
        ConnectFailure::Io(e)
    }
}

/// Connect to `server`, run the X.224 security negotiation advertising `requested`, upgrade the
/// socket to TLS, then authenticate with `credentials` via NLA (CredSSP / NTLM). `on_stage` is
/// called with each connect stage label as it is entered, for progress UI / diagnostics.
///
/// `server` is anything convertible to a [`ServerAddr`]: pass a hostname-based `ServerAddr` to
/// carry the name through TLS SNI and the CredSSP SPN, or a plain `SocketAddr` for the IP-literal
/// behavior.
///
/// Returns the negotiated protocol and the authenticated TLS stream, ready for MCS. `credentials`
/// is `skip`ped from the tracing span so the password is never recorded.
pub async fn connect(
    server: impl Into<ServerAddr>,
    requested: SecurityProtocol,
    credentials: Credentials,
    on_stage: impl FnMut(&str),
) -> Result<ConnectOutcome, ConnectFailure> {
    connect_inner(server.into(), requested, credentials, on_stage).await
}

/// The monomorphic body of [`connect`], instrumented once the server identity is concrete.
#[tracing::instrument(
    name = "connect",
    skip(credentials, on_stage),
    fields(host = %server.host, port = server.port),
    err,
)]
async fn connect_inner(
    server: ServerAddr,
    requested: SecurityProtocol,
    credentials: Credentials,
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
                    // (host, port) resolves DNS names and parses IP literals alike; the original
                    // host string stays in `server` for SNI / SPN / validation.
                    let s = with_stage_timeout(
                        "tcp-connect",
                        TCP_CONNECT_TIMEOUT,
                        TcpStream::connect((server.host.as_str(), server.port)),
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
                    // SNI carries the host exactly as dialed: `ServerName` parses both DNS names
                    // and IP literals, so a hostname reaches the server (and #36's validation)
                    // instead of being flattened to whatever it resolved to.
                    let server_name = ServerName::try_from(server.host.clone()).map_err(|e| {
                        ConnectFailure::TlsHandshake {
                            reason: format!("invalid server name {:?} for SNI: {e}", server.host),
                        }
                    })?;
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
                Action::StartNla {
                    selected,
                    server_public_key,
                } => {
                    // CredSSP runs here, never in the core machine: `sspi` owns the token loop and
                    // we drive it over the TLS stream (plan.md decision 10). The core only sees the
                    // completion signal, plus — for HYBRID_EX — the early-auth result bytes.
                    let stream = tls.as_mut().expect("tls established before NLA");
                    tracing::debug!(
                        ?selected,
                        key_len = server_public_key.len(),
                        "starting CredSSP / NLA token exchange"
                    );
                    run_credssp(stream, server_public_key, &credentials, &server).await?;
                    tracing::debug!("CredSSP exchange complete");
                    queue.extend(sm.process(Event::NlaComplete));
                    announce_stage(&mut sm, &mut announced, &mut on_stage);
                }
                Action::AwaitEarlyUserAuth => {
                    // HYBRID_EX: the server sends a 4-byte Early User Authorization Result PDU right
                    // after CredSSP, before MCS. Read it (decrypted, off the TLS stream) and let the
                    // machine decode grant/deny.
                    let stream = tls.as_mut().expect("tls established before early-user-auth");
                    let mut pdu = [0u8; 4];
                    with_stage_timeout("nla-credssp", STAGE_TIMEOUT, stream.read_exact(&mut pdu))
                        .await?;
                    tracing::debug!("read HYBRID_EX Early User Authorization Result PDU");
                    queue.extend(sm.process(Event::EarlyUserAuthResult(&pdu)));
                    announce_stage(&mut sm, &mut announced, &mut on_stage);
                }
                Action::Authenticated { selected } => {
                    tracing::debug!(?selected, "NLA complete; connection authenticated");
                    return Ok(ConnectOutcome {
                        selected,
                        stream: tls.expect("tls established before authenticated"),
                    });
                }
                Action::FailWith(e) => return Err(ConnectFailure::Protocol(e)),
            }
        }

        // The queue drained without a terminal action: the machine needs more bytes. This only
        // happens during the plaintext X.224 phase; once TLS starts, the StartTls / StartNla arms
        // drive their own reads and drain the queue without re-entering the plaintext read.
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

/// Drive the CredSSP / NLA token exchange to completion over the (already TLS-upgraded) `stream`,
/// binding `pubKeyAuth` to `server_public_key` and delegating `credentials` once the SPNEGO/NTLM
/// handshake finalizes. `sspi` owns the protocol; we only shuttle its `TsRequest`s over TLS
/// (plan.md decision 10).
///
/// This slice drives **NTLM only** — but wrapped in SPNEGO (`ClientMode::Negotiate` with a package
/// list pinned to `ntlm`), which is what Windows servers expect ("per spec we should always use the
/// Negotiate security package in CredSSP"); a bare-NTLM token makes the server abort the TLS session
/// with a fatal `internal_error` alert (proven on the real VM). The package list excludes Kerberos /
/// PKU2U so `sspi` never yields a KDC network request; if it ever does (AD / Kerberos, a later
/// slice — plan.md §4 marks it optional), we surface it as an `Nla` failure rather than reach out.
async fn run_credssp(
    stream: &mut TlsStream<TcpStream>,
    server_public_key: Vec<u8>,
    credentials: &Credentials,
    server: &ServerAddr,
) -> Result<(), ConnectFailure> {
    let nla_err = |e: sspi::Error| ConnectFailure::Nla {
        reason: e.to_string(),
    };
    // The CredSSP SPN identifies the target service; RDP uses `TERMSRV/<host>`, with the host as
    // dialed (hostname when available — the form Kerberos will require, #45).
    let spn = server.credssp_spn();
    let client_computer_name =
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "justrdp".to_string());
    let negotiate = NegotiateConfig::new(
        Box::new(NtlmConfig::default()),
        // Pin to NTLM: enable ntlm, disable Kerberos and PKU2U so no KDC round-trip is attempted.
        Some("ntlm,!kerberos,!pku2u".to_string()),
        client_computer_name,
    );
    let mut client = CredSspClient::new(
        server_public_key,
        credentials.to_sspi()?,
        CredSspMode::WithCredentials,
        ClientMode::Negotiate(negotiate),
        spn,
    )
    .map_err(nla_err)?;

    // The client speaks first: process an empty TsRequest to get the initial token, then ping-pong
    // (Negotiate → Challenge → Authenticate → pubKeyAuth) until `FinalMessage` (the TSCredentials
    // delegation) is sent.
    let mut ts_request = TsRequest::default();
    loop {
        let mut generator = client.process(ts_request);
        let client_state = match generator.start() {
            GeneratorState::Completed(result) => result.map_err(nla_err)?,
            GeneratorState::Suspended(_network_request) => {
                return Err(ConnectFailure::Nla {
                    reason: "server requires a KDC round-trip (Kerberos); only NTLM is supported in \
                             this slice"
                        .to_string(),
                });
            }
        };
        match client_state {
            ClientState::ReplyNeeded(ts) => {
                write_ts_request(stream, &ts).await?;
                ts_request = read_ts_request(stream).await?;
            }
            ClientState::FinalMessage(ts) => {
                write_ts_request(stream, &ts).await?;
                return Ok(());
            }
        }
    }
}

/// Encode a `TsRequest` (BER) and write it to the TLS stream.
async fn write_ts_request(
    stream: &mut TlsStream<TcpStream>,
    ts: &TsRequest,
) -> Result<(), ConnectFailure> {
    let mut buf = Vec::with_capacity(ts.buffer_len() as usize);
    ts.encode_ts_request(&mut buf)
        .map_err(|e| ConnectFailure::Nla {
            reason: e.to_string(),
        })?;
    stream.write_all(&buf).await?;
    Ok(())
}

/// Read one BER-framed `TsRequest` from `reader`. A TSRequest is a DER `SEQUENCE` (`0x30`) whose
/// length prefix tells us exactly how many bytes to read, so we frame it precisely rather than
/// guessing a buffer size (TLS records may split a single TSRequest across reads). Generic over the
/// reader so the framing — including the length cap — is unit-testable in memory.
async fn read_ts_request<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<TsRequest, ConnectFailure> {
    let mut frame = Vec::with_capacity(64);
    // Tag + first length byte.
    let mut head = [0u8; 2];
    reader.read_exact(&mut head).await?;
    frame.extend_from_slice(&head);
    let content_len = if head[1] < 0x80 {
        // Short form: the length is the byte itself.
        head[1] as usize
    } else {
        // Long form: the low 7 bits give the number of big-endian length bytes that follow. Reject a
        // width that would overflow `usize` (no real TSRequest length needs more than 8 bytes).
        let n = (head[1] & 0x7f) as usize;
        if n > std::mem::size_of::<usize>() {
            return Err(ConnectFailure::Nla {
                reason: format!("TSRequest BER length field uses {n} bytes; refusing to parse"),
            });
        }
        let mut len_bytes = vec![0u8; n];
        reader.read_exact(&mut len_bytes).await?;
        frame.extend_from_slice(&len_bytes);
        len_bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize)
    };
    // Cap before allocating: a server-controlled length must not drive an unbounded allocation.
    if content_len > MAX_TS_REQUEST_LEN {
        return Err(ConnectFailure::Nla {
            reason: format!(
                "TSRequest length {content_len} exceeds the {MAX_TS_REQUEST_LEN}-byte cap"
            ),
        });
    }
    let mut content = vec![0u8; content_len];
    reader.read_exact(&mut content).await?;
    frame.extend_from_slice(&content);
    TsRequest::from_buffer(&frame).map_err(|e| ConnectFailure::Nla {
        reason: e.to_string(),
    })
}

/// A rustls client config that accepts any server certificate. slice-2's policy is `validate=false`:
/// we extract the public key but do not yet verify the chain / name (CN/SAN, chain-of-trust, and
/// TOFU pinning are follow-up slices, per plan.md §22). The `ring` crypto provider is selected
/// explicitly so no process-default provider needs installing. Default protocol versions (TLS 1.2
/// and 1.3) are kept — CredSSP/NLA over the same session was verified to work over TLS 1.3 against
/// the real VM (slice-3), so no version pin is needed.
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

    /// The on-wire BER bytes of a TSRequest carrying `n` bytes of `nego_tokens` — the exact framing
    /// `read_ts_request` must parse back (encoded by sspi, the same codec the real exchange uses).
    fn encoded_ts_request(n: usize) -> Vec<u8> {
        let ts = TsRequest {
            nego_tokens: Some(vec![0xAB; n]),
            ..TsRequest::default()
        };
        let mut buf = Vec::new();
        ts.encode_ts_request(&mut buf).unwrap();
        buf
    }

    #[tokio::test]
    async fn read_ts_request_round_trips_a_short_form_frame() {
        // A small TSRequest uses BER short-form length (< 0x80) — a single length byte.
        let bytes = encoded_ts_request(10);
        assert!(
            bytes[1] < 0x80,
            "expected short-form length for a small TSRequest, got {:#x}",
            bytes[1]
        );
        let mut reader: &[u8] = &bytes;
        let parsed = read_ts_request(&mut reader).await.unwrap();
        assert_eq!(parsed.nego_tokens, Some(vec![0xAB; 10]));
    }

    #[tokio::test]
    async fn read_ts_request_round_trips_a_long_form_frame() {
        // A TSRequest over 127 bytes forces BER long-form length, exercising the multi-byte parse.
        let bytes = encoded_ts_request(500);
        assert!(
            bytes[1] >= 0x80,
            "expected long-form length for a large TSRequest, got {:#x}",
            bytes[1]
        );
        let mut reader: &[u8] = &bytes;
        let parsed = read_ts_request(&mut reader).await.unwrap();
        assert_eq!(parsed.nego_tokens, Some(vec![0xAB; 500]));
    }

    #[tokio::test]
    async fn read_ts_request_rejects_a_length_over_the_cap() {
        // A hostile header claiming a 4-byte length of 0x00FF_FFFF (~16 MiB), far over the cap. The
        // cap must trip BEFORE any content is read or allocated — we supply only the 6 header bytes,
        // so reaching the content read would EOF instead of producing this clean rejection.
        let header = [0x30, 0x84, 0x00, 0xFF, 0xFF, 0xFF];
        let mut reader: &[u8] = &header;
        match &read_ts_request(&mut reader).await.unwrap_err() {
            ConnectFailure::Nla { reason } => {
                assert!(reason.contains("exceeds"), "unexpected reason: {reason}")
            }
            other => panic!("expected an over-cap Nla rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_ts_request_rejects_an_overwide_length_field() {
        // 0x80 | 0x10 = 16 length bytes — wider than `usize`; refuse rather than overflow the fold.
        let header = [0x30, 0x90];
        let mut reader: &[u8] = &header;
        match &read_ts_request(&mut reader).await.unwrap_err() {
            ConnectFailure::Nla { reason } => {
                assert!(reason.contains("refusing to parse"), "unexpected reason: {reason}")
            }
            other => panic!("expected an over-wide length rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_ts_request_surfaces_truncation_as_io() {
        // A valid header promising more content than is delivered: read_exact hits EOF mid-frame.
        let mut bytes = encoded_ts_request(10);
        bytes.truncate(bytes.len() - 5);
        let mut reader: &[u8] = &bytes;
        let err = read_ts_request(&mut reader).await.unwrap_err();
        assert!(matches!(err, ConnectFailure::Io(_)), "expected an Io EOF error, got {err:?}");
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

    /// Dummy credentials for the loopback mock tests. The mocks fail before or at the NLA boundary
    /// (they do not speak CredSSP), so the values never authenticate — they only satisfy the
    /// `connect` signature. The real-VM test supplies live credentials from the environment.
    fn test_credentials() -> Credentials {
        Credentials {
            username: "test".to_string(),
            password: "test".to_string(),
            domain: None,
        }
    }

    /// Spawn a one-shot mock RDP server on loopback: it reads the client's plaintext Connection
    /// Request, replies with a Connection Confirm carrying `nego`, runs the TLS handshake with a
    /// throwaway self-signed cert, then reads one byte and drops the connection. It deliberately does
    /// **not** speak CredSSP, so the client reaches the `nla-credssp` stage and then fails there —
    /// which is exactly what lets these tests assert the TLS→NLA handoff without a real NTLM peer.
    async fn mock_tls_server(nego: [u8; 8]) -> SocketAddr {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
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
            let _ = tls.read(&mut buf).await; // read one byte of the first TSRequest, then drop → close
        });
        addr
    }

    #[tokio::test]
    async fn connect_progresses_through_tls_into_nla() {
        // The mock completes X.224 + TLS but does not speak CredSSP. What we assert is the handoff:
        // the adapter extracts the server key, advances into `nla-credssp`, and only *then* fails —
        // proving TLS completed and the machine entered NLA before the (unauthenticatable) mock
        // closed the connection.
        let addr = mock_tls_server([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]).await;

        let mut stages = Vec::new();
        let err = connect(addr, requested(), test_credentials(), |s| {
            stages.push(s.to_string())
        })
        .await
        .unwrap_err();

        // TLS completed and the machine entered NLA before failing...
        assert_eq!(
            stages,
            vec!["tcp-connect", "x224-negotiate", "tls-handshake", "nla-credssp"]
        );
        // ...and the failure is at the NLA boundary (the mock closed instead of returning a
        // TSRequest), not a TLS- or negotiation-level failure.
        assert!(
            matches!(err, ConnectFailure::Io(_) | ConnectFailure::Nla { .. }),
            "expected an NLA-stage failure, got {err:?}"
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn connect_logs_stage_transitions_through_nla() {
        let addr = mock_tls_server([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]).await;
        // Fails at the NLA boundary (no real NTLM peer); we only care about the logged transitions.
        let _ = connect(addr, requested(), test_credentials(), |_| {}).await;

        // Every connect stage through NLA is named in the debug logs (criterion 14: observable
        // transitions)...
        assert!(logs_contain("tcp-connect"), "tcp-connect stage not logged");
        assert!(logs_contain("x224-negotiate"), "x224-negotiate stage not logged");
        assert!(logs_contain("tls-handshake"), "tls-handshake stage not logged");
        assert!(logs_contain("nla-credssp"), "nla-credssp stage not logged");
        // ...and byte counts are logged for the plaintext bytes written and read.
        assert!(logs_contain("bytes="), "byte counts not logged");
    }

    #[test]
    fn server_addr_from_socket_addr_is_the_ip_literal() {
        // The SocketAddr conversion is the legacy identity: host = IP literal, so SNI and SPN
        // carry the IP — exactly the pre-ServerAddr behavior.
        let sa: SocketAddr = "192.0.2.7:3389".parse().unwrap();
        assert_eq!(ServerAddr::from(sa), ServerAddr::new("192.0.2.7", 3389));
        assert_eq!(ServerAddr::from(sa).credssp_spn(), "TERMSRV/192.0.2.7");
    }

    #[test]
    fn credssp_spn_uses_the_host_as_dialed() {
        // Hostname in, hostname out: the SPN form Kerberos requires (#45).
        let server = ServerAddr::new("vm.example.test", 3389);
        assert_eq!(server.credssp_spn(), "TERMSRV/vm.example.test");
    }

    /// Like `mock_tls_server`, but also reports the SNI the client's ClientHello carried (or
    /// `None` — rustls omits the SNI extension for IP-literal server names per RFC 6066).
    async fn mock_tls_server_reporting_sni(
        nego: [u8; 8],
    ) -> (SocketAddr, tokio::sync::oneshot::Receiver<Option<String>>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = ck.key_pair.serialize_der();
        let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
        let (sni_tx, sni_rx) = tokio::sync::oneshot::channel();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 64];
            let _ = sock.read(&mut scratch).await.unwrap();
            sock.write_all(&confirm_frame(nego)).await.unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            let _ = sni_tx.send(tls.get_ref().1.server_name().map(str::to_owned));
            let mut buf = [0u8; 1];
            let _ = tls.read(&mut buf).await;
        });
        (addr, sni_rx)
    }

    #[tokio::test]
    async fn connect_by_hostname_sends_dns_sni() {
        // Dialing by name must put the *name* in the TLS ClientHello SNI — not the IP it resolved
        // to. The mock observes the SNI from its accepted ServerConnection.
        let (addr, sni_rx) =
            mock_tls_server_reporting_sni([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]).await;
        let server = ServerAddr::new("localhost", addr.port());

        let mut stages = Vec::new();
        let _ = connect(server, requested(), test_credentials(), |s| {
            stages.push(s.to_string())
        })
        .await;

        // The handshake completed with a DNS-name SNI...
        assert_eq!(sni_rx.await.unwrap().as_deref(), Some("localhost"));
        // ...and the connect drove through TLS into NLA before the mock dropped the session,
        // proving hostname dialing (DNS resolution included) works end-to-end.
        assert!(
            stages.contains(&"nla-credssp".to_string()),
            "expected to reach nla-credssp, got {stages:?}"
        );
    }

    #[tokio::test]
    async fn connect_by_socket_addr_sends_no_dns_sni() {
        // The IP path is unchanged: an IP-literal ServerName yields no SNI extension (RFC 6066
        // forbids literal IPs there), which is what the server observes as `None`.
        let (addr, sni_rx) =
            mock_tls_server_reporting_sni([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]).await;

        let _ = connect(addr, requested(), test_credentials(), |_| {}).await;

        assert_eq!(sni_rx.await.unwrap(), None);
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
        let err = connect(addr, requested(), test_credentials(), |_| {})
            .await
            .unwrap_err();
        assert!(
            matches!(err, ConnectFailure::TlsHandshake { .. }),
            "expected a TLS handshake failure, got {err:?}"
        );
    }

    #[tokio::test]
    async fn connect_surfaces_server_negotiation_failure() {
        // Server refuses with RDP_NEG_FAILURE / HYBRID_REQUIRED_BY_SERVER (0x05) before any TLS.
        let addr = mock_non_tls_server([0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00]).await;

        let err = connect(addr, requested(), test_credentials(), |_| {})
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ConnectFailure::Protocol(ConnectError::NegotiationFailed(_))
            ),
            "expected a protocol negotiation failure, got {err:?}"
        );
    }

    /// Real-VM acceptance test (ADR-0001 real-VM harness). Ignored by default — run with
    /// `cargo test -p justrdp-tokio -- --ignored` against the live RDP test VM, with the test
    /// account supplied via `JUSTRDP_TEST_USERNAME` / `JUSTRDP_TEST_PASSWORD` /
    /// `JUSTRDP_TEST_DOMAIN` (the latter optional) — so no credential is committed to the repo.
    /// Verifies the full connect sequence through NLA: X.224 → TLS → CredSSP authentication (and the
    /// HYBRID_EX early-auth check), ending in an authenticated stream ready for MCS.
    #[tokio::test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389 and JUSTRDP_TEST_* env vars"]
    async fn connect_authenticates_against_real_vm() {
        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let req = requested();
        let credentials = Credentials {
            username: std::env::var("JUSTRDP_TEST_USERNAME").expect("set JUSTRDP_TEST_USERNAME"),
            password: std::env::var("JUSTRDP_TEST_PASSWORD").expect("set JUSTRDP_TEST_PASSWORD"),
            domain: std::env::var("JUSTRDP_TEST_DOMAIN").ok(),
        };

        let mut stages = Vec::new();
        let result = connect(addr, req, credentials, |s| stages.push(s.to_string())).await;
        eprintln!("stages: {stages:?}");
        let outcome = result.expect("connect through NLA should authenticate against the real VM");

        eprintln!("server selected protocol: {:?}", outcome.selected);
        // The server must select exactly one protocol from the set we advertised...
        assert!(outcome.selected.bits() != 0);
        assert!(req.contains(outcome.selected));
        // ...and the connect sequence must have driven the full chain through NLA authentication.
        assert_eq!(stages.first().map(String::as_str), Some("tcp-connect"));
        assert!(
            stages.contains(&"nla-credssp".to_string()),
            "expected to reach the nla-credssp stage, got {stages:?}"
        );
    }
}
