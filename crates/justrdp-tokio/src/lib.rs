//! `justrdp-tokio` — the thin Tokio I/O adapter that makes the sans-IO [`justrdp`] core real
//! (ADR-0001). It owns the socket; the state machine owns the protocol. The adapter drains the
//! machine's [`Action`]s (open the socket, write bytes, start TLS), feeds it [`Event`]s (connected,
//! bytes received, TLS established), and applies a per-stage timeout — surfacing the stage name on
//! failure.
//!
//! The loop currently drives the connect sequence through `tcp-connect` → `x224-negotiate` →
//! `tls-handshake` → `nla-credssp` → the MCS/GCC half of `capability-exchange` (Connect-Initial,
//! channel join). The TLS handshake and the CredSSP token exchange run here, not in the core:
//! rustls and `sspi` are their own state machines, so shuttling their records through the
//! connect machine would add nothing (plan.md §3, decision 10). After [`Action::StartTls`] the
//! machine's writes and reads transparently ride the TLS stream ([`Transport`]).

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use justrdp::{
    Action, ActivationResult, ConnectConfig, ConnectError, ConnectStateMachine, CursorEvent,
    DisconnectReason, Event, FrameUpdate, InputEvent, LicenseEntropy, McsConnectResult,
    SessionError, SessionOutput, SessionStateMachine,
};
use rustls::pki_types::ServerName;
use sspi::credssp::{ClientMode, ClientState, CredSspClient, CredSspMode, TsRequest};
use sspi::generator::GeneratorState;
use sspi::negotiate::NegotiateConfig;
use sspi::ntlm::NtlmConfig;
use sspi::{AuthIdentity, Credentials as SspiCredentials, Secret, Username};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
// Re-exported so hosts cancel sessions without naming tokio-util themselves.
pub use tokio_util::sync::CancellationToken;

mod trust;
use trust::client_config;
pub use trust::{FilePinStore, MemoryPinStore, PinStore, TrustPolicy, pin_fingerprint};

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

/// A successful connect, all the way to **session-active**: the MCS channel topology, the
/// capability-exchange/activation results (negotiated desktop size, share ID, server
/// capabilities), and the live, authenticated TLS stream — ready for the session loop.
#[derive(Debug)]
pub struct ConnectOutcome {
    /// The MCS/GCC results: selected protocol, user/IO channel IDs, static channels,
    /// requested desktop size.
    pub mcs: McsConnectResult,
    /// The activation results: share ID, **negotiated** desktop size (allocate the framebuffer
    /// from this one), the server's capability sets, and any bytes that followed the Font Map
    /// in the same read (process them before reading the stream).
    pub activation: ActivationResult,
    /// The TLS-upgraded, NLA-authenticated stream, positioned just past the Font Map PDU.
    pub stream: TlsStream<TcpStream>,
}

/// Generate fresh per-connection licensing entropy ([`LicenseEntropy`]) from the process RNG
/// (rustls' ring provider — the same RNG the TLS handshake trusts; no new dependency). The
/// sans-IO core cannot produce randomness, so the adapter boundary owns this.
pub fn generate_license_entropy() -> io::Result<LicenseEntropy> {
    let rng = rustls::crypto::ring::default_provider().secure_random;
    let mut client_random = [0u8; 32];
    let mut premaster_secret = [0u8; 48];
    rng.fill(&mut client_random)
        .and_then(|()| rng.fill(&mut premaster_secret))
        .map_err(|e| {
            io::Error::other(format!("OS RNG failed generating license entropy: {e:?}"))
        })?;
    Ok(LicenseEntropy {
        client_random,
        premaster_secret,
    })
}

/// The connect-time transport: plaintext TCP until the X.224 negotiation completes, the TLS
/// stream after [`Action::StartTls`]. The machine's [`Action::WriteBytes`] and the read loop
/// always target whichever is current, so the MCS exchange transparently rides TLS.
enum Transport {
    /// Between `Connect` and the TLS upgrade.
    Tcp(TcpStream),
    /// From the TLS upgrade onward.
    Tls(Box<TlsStream<TcpStream>>),
    /// Transient state while the TLS upgrade owns the socket, and after the terminal action
    /// consumed the stream.
    Absent,
}

impl Transport {
    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Transport::Tcp(s) => s.write_all(bytes).await,
            Transport::Tls(s) => s.write_all(bytes).await,
            Transport::Absent => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "write before the socket is connected",
            )),
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Tcp(s) => s.read(buf).await,
            Transport::Tls(s) => s.read(buf).await,
            Transport::Absent => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "read before the socket is connected",
            )),
        }
    }

    fn tls_mut(&mut self) -> Option<&mut TlsStream<TcpStream>> {
        match self {
            Transport::Tls(s) => Some(s),
            _ => None,
        }
    }
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
            None => {
                Username::parse(&self.username).or_else(|_| Username::new(&self.username, None))
            }
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

/// Connect to `server` and drive the full connect sequence with `config`: X.224 security
/// negotiation, TLS upgrade, NLA (CredSSP) authentication with `credentials`, then the MCS/GCC
/// exchange and channel join. `on_stage` is called with each connect stage label as it is
/// entered, for progress UI / diagnostics.
///
/// `server` is anything convertible to a [`ServerAddr`]: pass a hostname-based `ServerAddr` to
/// carry the name through TLS SNI and the CredSSP SPN, or a plain `SocketAddr` for the
/// IP-literal behavior.
///
/// `config` carries the caller's GCC settings — including all twelve `earlyCapabilityFlags`,
/// which reach the wire verbatim (plan.md §0; nothing in justrdp hardcodes them).
///
/// Returns the MCS results (user channel, I/O channel, granted static channels) and the
/// authenticated TLS stream, ready for the Client Info PDU. `credentials` is `skip`ped from the
/// tracing span so the password is never recorded.
pub async fn connect(
    server: impl Into<ServerAddr>,
    config: ConnectConfig,
    credentials: Credentials,
    on_stage: impl FnMut(&str),
) -> Result<ConnectOutcome, ConnectFailure> {
    connect_inner(
        server.into(),
        config,
        credentials,
        on_stage,
        ConnectOptions::default(),
    )
    .await
}

/// The per-stage timeout policy for [`connect`]: how long the TCP dial may take, and how long
/// each subsequent connect stage (an X.224 round trip, the TLS handshake, each NLA/MCS read)
/// may sit idle before the connect fails with [`ConnectFailure::Timeout`] carrying the stage
/// name. [`connect`] uses [`ConnectTimeouts::default`] (10 s dial / 15 s per stage, plan.md
/// §11e); hosts with tighter UX budgets inject their own via [`connect_with_timeouts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTimeouts {
    /// Timeout for the TCP dial.
    pub tcp_connect: Duration,
    /// Timeout for each post-TCP connect stage, applied per stage rather than cumulatively.
    pub stage: Duration,
}

impl Default for ConnectTimeouts {
    fn default() -> Self {
        Self {
            tcp_connect: TCP_CONNECT_TIMEOUT,
            stage: STAGE_TIMEOUT,
        }
    }
}

/// [`connect`] with the caller's [`ConnectTimeouts`] instead of the defaults. The trust policy
/// stays the default ([`TrustPolicy::Chain`]); use [`connect_with_options`] to choose both.
pub async fn connect_with_timeouts(
    server: impl Into<ServerAddr>,
    config: ConnectConfig,
    credentials: Credentials,
    on_stage: impl FnMut(&str),
    timeouts: ConnectTimeouts,
) -> Result<ConnectOutcome, ConnectFailure> {
    let options = ConnectOptions {
        timeouts,
        ..ConnectOptions::default()
    };
    connect_inner(server.into(), config, credentials, on_stage, options).await
}

/// The adapter-level knobs for [`connect`] that are not protocol configuration: the per-stage
/// [`ConnectTimeouts`] and the server-certificate [`TrustPolicy`]. Protocol settings (GCC blocks,
/// requested security protocols, channels) stay in the sans-IO core's `ConnectConfig`; these
/// options exist only where the I/O actually happens.
///
/// `Default` is the safe configuration: default timeouts and **real certificate validation**
/// ([`TrustPolicy::Chain`]).
#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    /// Per-stage timeout policy.
    pub timeouts: ConnectTimeouts,
    /// How to decide whether the server's TLS certificate is trusted.
    pub trust: TrustPolicy,
}

/// [`connect`] with the caller's [`ConnectOptions`] (timeouts and trust policy) instead of the
/// defaults.
pub async fn connect_with_options(
    server: impl Into<ServerAddr>,
    config: ConnectConfig,
    credentials: Credentials,
    on_stage: impl FnMut(&str),
    options: ConnectOptions,
) -> Result<ConnectOutcome, ConnectFailure> {
    connect_inner(server.into(), config, credentials, on_stage, options).await
}

/// The monomorphic body of [`connect`], instrumented once the server identity is concrete.
#[tracing::instrument(
    name = "connect",
    skip(config, credentials, on_stage, options),
    fields(host = %server.host, port = server.port),
    err,
)]
async fn connect_inner(
    server: ServerAddr,
    config: ConnectConfig,
    credentials: Credentials,
    mut on_stage: impl FnMut(&str),
    options: ConnectOptions,
) -> Result<ConnectOutcome, ConnectFailure> {
    let timeouts = options.timeouts;
    let mut sm = ConnectStateMachine::new(config);
    let mut transport = Transport::Absent;
    let mut readbuf = [0u8; 8192];
    // Filled at the McsConnected milestone; consumed when SessionActive terminates the loop.
    let mut mcs: Option<McsConnectResult> = None;
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
                        timeouts.tcp_connect,
                        TcpStream::connect((server.host.as_str(), server.port)),
                    )
                    .await?;
                    tracing::debug!("tcp socket connected");
                    transport = Transport::Tcp(s);
                    queue.extend(sm.process(Event::Connected));
                    announce_stage(&mut sm, &mut announced, &mut on_stage);
                }
                Action::WriteBytes(bytes) => {
                    // Writes target whichever transport is current: plaintext TCP during X.224,
                    // the TLS stream from the upgrade onward (MCS rides TLS).
                    transport.write_all(&bytes).await?;
                    tracing::debug!(bytes = bytes.len(), "wrote frame to socket");
                }
                Action::StartTls { selected } => {
                    // The handshake runs here, never in the core machine. We hand only the resulting
                    // peer certificate back to the machine, which extracts its subjectPublicKey.
                    let Transport::Tcp(stream) =
                        std::mem::replace(&mut transport, Transport::Absent)
                    else {
                        return Err(ConnectFailure::Io(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "TLS upgrade requested without a connected plaintext socket",
                        )));
                    };
                    // The trust policy decides the verifier: Chain fails *here*, inside the
                    // handshake, when the cert is untrusted — NLA is never reached.
                    let tls_config = client_config(&options.trust, &server.host).map_err(|e| {
                        ConnectFailure::TlsHandshake {
                            reason: format!("building the TLS trust configuration: {e}"),
                        }
                    })?;
                    let connector = TlsConnector::from(Arc::new(tls_config));
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
                        timeouts.stage,
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
                        Err(_) => {
                            return Err(ConnectFailure::Timeout {
                                stage: "tls-handshake",
                            });
                        }
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
                    transport = Transport::Tls(Box::new(established));
                    announce_stage(&mut sm, &mut announced, &mut on_stage);
                }
                Action::StartNla {
                    selected,
                    server_public_key,
                } => {
                    // CredSSP runs here, never in the core machine: `sspi` owns the token loop and
                    // we drive it over the TLS stream (plan.md decision 10). The core only sees the
                    // completion signal, plus — for HYBRID_EX — the early-auth result bytes.
                    let stream = transport.tls_mut().ok_or_else(|| {
                        ConnectFailure::Io(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "NLA requested before the TLS upgrade",
                        ))
                    })?;
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
                    let stream = transport.tls_mut().ok_or_else(|| {
                        ConnectFailure::Io(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "early-user-auth read before the TLS upgrade",
                        ))
                    })?;
                    let mut pdu = [0u8; 4];
                    with_stage_timeout("nla-credssp", timeouts.stage, stream.read_exact(&mut pdu))
                        .await?;
                    tracing::debug!("read HYBRID_EX Early User Authorization Result PDU");
                    queue.extend(sm.process(Event::EarlyUserAuthResult(&pdu)));
                    announce_stage(&mut sm, &mut announced, &mut on_stage);
                }
                Action::McsConnected { result } => {
                    // A milestone, not the end: the machine continues through licensing,
                    // capability exchange, and activation on the same stream.
                    tracing::debug!(
                        user_channel = result.user_channel_id,
                        io_channel = result.io_channel_id,
                        static_channels = result.static_channels.len(),
                        join_skipped = result.channel_join_skipped,
                        "MCS connect complete; continuing to licensing"
                    );
                    mcs = Some(result);
                }
                Action::SessionActive { result } => {
                    tracing::debug!(
                        share_id = result.share_id,
                        width = result.desktop_size.0,
                        height = result.desktop_size.1,
                        server_capsets = result.server_capabilities.len(),
                        leftover = result.leftover.len(),
                        "session active"
                    );
                    let Some(mcs) = mcs else {
                        return Err(ConnectFailure::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "session-active reached without an MCS result",
                        )));
                    };
                    let Transport::Tls(stream) =
                        std::mem::replace(&mut transport, Transport::Absent)
                    else {
                        return Err(ConnectFailure::Io(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "session-active reached without a TLS stream",
                        )));
                    };
                    return Ok(ConnectOutcome {
                        mcs,
                        activation: result,
                        stream: *stream,
                    });
                }
                Action::FailWith(e) => return Err(ConnectFailure::Protocol(e)),
            }
        }

        // The queue drained without a terminal action: the machine needs more bytes — from the
        // plaintext socket during X.224, from the TLS stream during the MCS exchange. The
        // machine reassembles TPKT frames itself, so raw chunks are fine.
        let n =
            with_stage_timeout(sm.stage(), timeouts.stage, transport.read(&mut readbuf)).await?;
        if n == 0 {
            return Err(ConnectFailure::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("server closed the connection during {}", sm.stage()),
            )));
        }
        tracing::debug!(bytes = n, stage = sm.stage(), "read from socket");
        queue.extend(sm.process(Event::Received(&readbuf[..n])));
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

/// Why a running session ended.
#[derive(Debug)]
pub enum SessionFailure {
    /// Socket-level I/O failed.
    Io(io::Error),
    /// The server sent data the session machine rejects (malformed PDU / codec data).
    Protocol(SessionError),
}

impl core::fmt::Display for SessionFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionFailure::Io(e) => write!(f, "session I/O failed: {e}"),
            SessionFailure::Protocol(e) => write!(f, "session protocol failure: {e}"),
        }
    }
}

impl core::error::Error for SessionFailure {}

/// Drive the sans-IO [`SessionStateMachine`] over the connected stream: read raw bytes, feed
/// them to the machine, deliver every decoded [`FrameUpdate`] to `on_frame` **synchronously**,
/// and write the machine's outbound frames (Deactivation–Reactivation traffic) back to the
/// socket.
///
/// Build the machine from the connect results:
/// [`SessionStateMachine::new`] with a `SessionConfig` assembled from
/// [`ConnectOutcome::mcs`] / [`ConnectOutcome::activation`] (including
/// `activation.leftover`), then pass [`ConnectOutcome::stream`].
///
/// Runs until the transport ends, returning the typed [`DisconnectReason`] (issue #42): the
/// server's Set Error Info / MCS ultimatum attribution when one arrived before the close,
/// [`DisconnectReason::UnexpectedDisconnect`] otherwise. Protocol violations still surface as
/// `Err`. The future may also simply be dropped (the caller owns cancellation); the machine is
/// borrowed, so the caller keeps access to its framebuffer afterwards.
pub async fn run_session(
    stream: &mut TlsStream<TcpStream>,
    machine: &mut SessionStateMachine,
    on_frame: impl FnMut(&FrameUpdate),
    on_cursor: impl FnMut(&CursorEvent),
) -> Result<DisconnectReason, SessionFailure> {
    // A pre-closed input channel: the input branch disables itself on the first (None) recv.
    let (_, mut input) = tokio::sync::mpsc::channel(1);
    run_session_with_input(stream, machine, on_frame, on_cursor, &mut input).await
}

/// [`run_session`] plus host input: batches of [`InputEvent`]s received on `input` are encoded
/// by the machine ([`SessionStateMachine::encode_input`] — fast-path when the server advertised
/// it, the slow-path Input Event PDU otherwise) and written to the socket, interleaved with the
/// inbound graphics processing.
///
/// The host side holds the `mpsc::Sender`: a UI thread queues scancodes
/// ([`justrdp::Scancode`]'s press/release events), mouse events, and toggle syncs (send one
/// [`InputEvent::Sync`] with the OS lock state — [`keyboard_toggle_flags`] on Windows — right
/// after the session starts, and again whenever a lock LED changes). Closing the channel
/// disables the input branch; the session keeps running output-only.
pub async fn run_session_with_input(
    stream: &mut TlsStream<TcpStream>,
    machine: &mut SessionStateMachine,
    mut on_frame: impl FnMut(&FrameUpdate),
    mut on_cursor: impl FnMut(&CursorEvent),
    input: &mut tokio::sync::mpsc::Receiver<Vec<InputEvent>>,
) -> Result<DisconnectReason, SessionFailure> {
    let mut readbuf = [0u8; 16 * 1024];
    let mut input_open = true;
    // Drain bytes the connect sequence already buffered (ActivationResult::leftover, handed
    // to SessionStateMachine::new) before the first socket read.
    let mut pending = machine
        .process_bytes(&[])
        .map_err(SessionFailure::Protocol)?;
    loop {
        for output in pending.drain(..) {
            match output {
                SessionOutput::Frame(frame) => {
                    tracing::trace!(
                        x = frame.x,
                        y = frame.y,
                        width = frame.width,
                        height = frame.height,
                        "frame update"
                    );
                    on_frame(&frame);
                }
                SessionOutput::Cursor(event) => {
                    tracing::trace!(?event, "cursor event");
                    on_cursor(&event);
                }
                SessionOutput::WriteBytes(bytes) => {
                    stream.write_all(&bytes).await.map_err(SessionFailure::Io)?;
                }
                SessionOutput::DisplayControlReady => {
                    // This entry point predates resize commands; hosts that want resize use
                    // run_session_with_commands, which surfaces the event.
                    tracing::debug!(target: "rdp_displaycontrol_caps", "display control ready");
                }
            }
        }
        tokio::select! {
            received = stream.read(&mut readbuf) => {
                match received {
                    // Orderly server close: surface whatever the server attributed.
                    Ok(0) => return Ok(machine.disconnect_reason()),
                    Ok(n) => {
                        pending = machine
                            .process_bytes(&readbuf[..n])
                            .map_err(SessionFailure::Protocol)?;
                    }
                    // A broken read (reset, missing close_notify, dead network) ends the
                    // session the same way — with the recorded attribution if the server
                    // got its farewell out first, UnexpectedDisconnect otherwise.
                    Err(e) => {
                        tracing::debug!(error = %e, "session read failed; classifying the disconnect");
                        return Ok(machine.disconnect_reason());
                    }
                }
            }
            events = input.recv(), if input_open => {
                match events {
                    Some(events) => {
                        for frame in machine.encode_input(&events) {
                            tracing::trace!(
                                events = events.len(),
                                bytes = frame.len(),
                                "input pdu"
                            );
                            stream.write_all(&frame).await.map_err(SessionFailure::Io)?;
                        }
                    }
                    // Sender dropped: stop polling the channel, keep the session alive.
                    None => input_open = false,
                }
            }
        }
    }
}

/// A host→session instruction for [`run_session_with_commands`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCommand {
    /// Encode and send a batch of input events (the [`run_session_with_input`] semantics).
    Input(Vec<InputEvent>),
    /// Request a client-initiated desktop resize via the Display Control channel
    /// (MS-RDPEDISP). Valid once [`SessionEvent::DisplayControlReady`] has fired; a request
    /// the machine refuses ([`justrdp::ResizeError`]) is logged and dropped — the session
    /// keeps running and the host may retry. The server answers with
    /// Deactivation–Reactivation; the new size shows up as a full-screen frame update.
    Resize {
        /// Requested desktop width (odd values are rounded down — the spec forbids them).
        width: u16,
        /// Requested desktop height.
        height: u16,
    },
}

/// A session milestone surfaced to the host by [`run_session_with_commands`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// The Display Control dynamic channel is open and the server's caps arrived:
    /// [`SessionCommand::Resize`] is valid from now on.
    DisplayControlReady,
}

/// [`run_session_with_input`] generalized to host *commands* (input + resize) and
/// **cancel-aware teardown**: when `cancel` fires, the loop returns `Ok(())` promptly without
/// waiting for server traffic, so a host abandoning a resize mid-cycle (or shutting down) can
/// never deadlock on the session (issue #8's cancel-safety criterion). Dropping the returned
/// future remains equally safe — the machine is pure and the socket is caller-owned.
///
/// `on_event` receives session milestones (currently [`SessionEvent::DisplayControlReady`]);
/// `on_frame` and `on_cursor` keep the synchronous sink contracts of [`run_session`].
pub async fn run_session_with_commands(
    stream: &mut TlsStream<TcpStream>,
    machine: &mut SessionStateMachine,
    mut on_frame: impl FnMut(&FrameUpdate),
    mut on_cursor: impl FnMut(&CursorEvent),
    mut on_event: impl FnMut(SessionEvent),
    commands: &mut tokio::sync::mpsc::Receiver<SessionCommand>,
    cancel: &CancellationToken,
) -> Result<DisconnectReason, SessionFailure> {
    let mut readbuf = [0u8; 16 * 1024];
    let mut commands_open = true;
    let mut pending = machine
        .process_bytes(&[])
        .map_err(SessionFailure::Protocol)?;
    loop {
        for output in pending.drain(..) {
            match output {
                SessionOutput::Frame(frame) => on_frame(&frame),
                SessionOutput::Cursor(event) => on_cursor(&event),
                SessionOutput::WriteBytes(bytes) => {
                    stream.write_all(&bytes).await.map_err(SessionFailure::Io)?;
                }
                SessionOutput::DisplayControlReady => {
                    tracing::debug!(target: "rdp_displaycontrol_caps", "display control ready");
                    on_event(SessionEvent::DisplayControlReady);
                }
            }
        }
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("session cancelled by the host");
                return Ok(DisconnectReason::LocalClosed);
            }
            received = stream.read(&mut readbuf) => {
                match received {
                    Ok(0) => return Ok(machine.disconnect_reason()), // orderly server close
                    Ok(n) => {
                        pending = machine
                            .process_bytes(&readbuf[..n])
                            .map_err(SessionFailure::Protocol)?;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "session read failed; classifying the disconnect");
                        return Ok(machine.disconnect_reason());
                    }
                }
            }
            command = commands.recv(), if commands_open => {
                match command {
                    Some(SessionCommand::Input(events)) => {
                        for frame in machine.encode_input(&events) {
                            stream.write_all(&frame).await.map_err(SessionFailure::Io)?;
                        }
                    }
                    Some(SessionCommand::Resize { width, height }) => {
                        match machine.request_resize(width, height) {
                            Ok(frames) => {
                                tracing::info!(width, height, "resize requested");
                                for frame in frames {
                                    stream.write_all(&frame).await.map_err(SessionFailure::Io)?;
                                }
                            }
                            // Not fatal: the session is unaffected, the host may retry
                            // (e.g. after DisplayControlReady fires).
                            Err(e) => tracing::warn!(width, height, error = %e, "resize refused"),
                        }
                    }
                    // Sender dropped: stop polling, keep the session alive.
                    None => commands_open = false,
                }
            }
        }
    }
}

/// The current keyboard lock state as [`InputEvent::Sync`] toggle flags, read from the OS
/// (Windows: `GetKeyState`'s low-order toggle bit — no extra dependency, `user32` is always
/// present). Send a sync event carrying these right after the session starts, and again on
/// LED changes, so the server's modifier state matches the host's
/// (MS-RDPBCGR 2.2.8.1.2.2.5).
#[cfg(windows)]
pub fn keyboard_toggle_flags() -> u8 {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetKeyState(nVirtKey: i32) -> i16;
    }
    const VK_CAPITAL: i32 = 0x14;
    const VK_NUMLOCK: i32 = 0x90;
    const VK_SCROLL: i32 = 0x91;
    let toggled = |vk| unsafe { GetKeyState(vk) } & 0x0001 != 0;
    let mut flags = 0;
    if toggled(VK_SCROLL) {
        flags |= justrdp_pdu::input::SYNC_SCROLL_LOCK;
    }
    if toggled(VK_NUMLOCK) {
        flags |= justrdp_pdu::input::SYNC_NUM_LOCK;
    }
    if toggled(VK_CAPITAL) {
        flags |= justrdp_pdu::input::SYNC_CAPS_LOCK;
    }
    flags
}

/// On platforms without a host LED query implemented, the lock state is unknown, so report no
/// toggles set. The session still tracks Caps/Num/Scroll as the user presses them; only the
/// initial host-matching sync is skipped. (A Linux X11/evdev reader can replace this stub.)
#[cfg(not(windows))]
pub fn keyboard_toggle_flags() -> u8 {
    0
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
                    reason:
                        "server requires a KDC round-trip (Kerberos); only NTLM is supported in \
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

/// Read one BER-framed `TsRequest` from the TLS stream. A TSRequest is a DER `SEQUENCE` (`0x30`)
/// whose length prefix tells us exactly how many bytes to read, so we frame it precisely rather
/// than guessing a buffer size (TLS records may split a single TSRequest across reads). The
/// framing — the length cap, the over-wide rejection, mid-frame reassembly — is pinned by the
/// `connect`-level tests against a loopback TLS server replying with crafted TSRequest bytes.
async fn read_ts_request(reader: &mut TlsStream<TcpStream>) -> Result<TsRequest, ConnectFailure> {
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
        len_bytes
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tracing_test::traced_test;

    use justrdp::ClientInfoConfig;
    use justrdp_pdu::nego::SecurityProtocol;
    use justrdp_pdu::{client_info, gcc};

    /// A full connect config for the tests: SSL|HYBRID|HYBRID_EX advertised, a modest GCC core,
    /// two static channels, and explicitly chosen early-capability flags (caller policy — set
    /// here, in the host layer, exactly as the anti-hardcode rule demands).
    fn test_config() -> ConnectConfig {
        let core = gcc::ClientCoreData {
            version: gcc::RDP_VERSION_10_12,
            desktop_width: 1280,
            desktop_height: 800,
            keyboard_layout: 0x0409,
            client_build: 1,
            client_name: "justrdp".to_string(),
            keyboard_type: gcc::KEYBOARD_TYPE_IBM_ENHANCED,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            ime_file_name: String::new(),
            post_beta2_color_depth: gcc::COLOR_DEPTH_8BPP,
            client_product_id: 1,
            serial_number: 0,
            high_color_depth: gcc::HIGH_COLOR_DEPTH_24BPP,
            supported_color_depths: gcc::SUPPORTED_COLOR_DEPTH_24BPP
                | gcc::SUPPORTED_COLOR_DEPTH_16BPP
                | gcc::SUPPORTED_COLOR_DEPTH_32BPP,
            early_capability_flags: gcc::ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU
                | gcc::ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL
                | gcc::ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN,
            dig_product_id: String::new(),
            connection_type: gcc::CONNECTION_TYPE_LAN,
            // Overwritten by the machine with the negotiated protocol.
            server_selected_protocol: SecurityProtocol::from_bits(0),
        };
        ConnectConfig {
            requested: SecurityProtocol::SSL
                | SecurityProtocol::HYBRID
                | SecurityProtocol::HYBRID_EX,
            capabilities: justrdp_pdu::capability::default_client_capabilities(&core),
            core,
            security: gcc::ClientSecurityData::default(),
            channels: vec![
                gcc::ChannelDef::new("cliprdr", gcc::CHANNEL_OPTION_INITIALIZED).unwrap(),
                gcc::ChannelDef::new("drdynvc", gcc::CHANNEL_OPTION_INITIALIZED).unwrap(),
            ],
            client_info: ClientInfoConfig {
                flags: client_info::ClientInfoFlags::MOUSE
                    | client_info::ClientInfoFlags::AUTOLOGON
                    | client_info::ClientInfoFlags::LOGON_NOTIFY
                    | client_info::ClientInfoFlags::LOGON_ERRORS
                    | client_info::ClientInfoFlags::MOUSE_HAS_WHEEL,
                domain: String::new(),
                username: "rdptest".to_string(),
                alternate_shell: String::new(),
                work_dir: String::new(),
                address_family: client_info::ADDRESS_FAMILY_INET,
                client_address: "192.168.136.1".to_string(),
                client_dir: String::new(),
                timezone: client_info::TimezoneInfo::utc(),
                session_id: 0,
                performance_flags: 0x7,
            },
            license: justrdp::LicenseConfig {
                entropy: generate_license_entropy().expect("OS RNG"),
                platform_id: justrdp_pdu::license::PLATFORM_ID_NT_POST_52_MICROSOFT,
                hardware_id: [0x4A55_5354, 0x5244_5001, 0, 0], // "JUST","RDP\1" — arbitrary
            },
        }
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

    /// [`connect`] with the explicit accept-any opt-in the mock-server tests need: the mocks
    /// present a throwaway self-signed cert no trust store contains, so getting *past* the TLS
    /// stage means deliberately choosing [`TrustPolicy::DangerAcceptAny`] (issue #36 — the
    /// default policy would, correctly, refuse these servers; that refusal has its own test).
    async fn connect_danger(
        server: impl Into<ServerAddr>,
        config: ConnectConfig,
        credentials: Credentials,
        on_stage: impl FnMut(&str),
    ) -> Result<ConnectOutcome, ConnectFailure> {
        let options = ConnectOptions {
            trust: TrustPolicy::DangerAcceptAny,
            ..ConnectOptions::default()
        };
        connect_with_options(server, config, credentials, on_stage, options).await
    }

    /// Spawn a one-shot mock RDP server on loopback: it reads the client's plaintext Connection
    /// Request, replies with a Connection Confirm carrying `nego`, runs the TLS handshake with a
    /// throwaway self-signed cert, then reads one byte and drops the connection. It deliberately does
    /// **not** speak CredSSP, so the client reaches the `nla-credssp` stage and then fails there —
    /// which is exactly what lets these tests assert the TLS→NLA handoff without a real NTLM peer.
    async fn mock_tls_server(nego: [u8; 8]) -> SocketAddr {
        mock_tls_server_returning_cert(nego).await.0
    }

    /// [`mock_tls_server`], but also returns the DER of the self-signed cert the mock presents —
    /// the TOFU tests compute the expected `subjectPublicKey` pin from it.
    async fn mock_tls_server_returning_cert(nego: [u8; 8]) -> (SocketAddr, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let cert_der = cert.as_ref().to_vec();
        let key = ck.signing_key.serialize_der();
        let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 64];
            let _ = sock.read(&mut scratch).await.unwrap(); // drain the plaintext Connection Request
            sock.write_all(&confirm_frame(nego)).await.unwrap(); // plaintext Connection Confirm
            let Ok(mut tls) = acceptor.accept(sock).await else {
                return; // the client (correctly) refused the cert — nothing more to serve
            };
            let mut buf = [0u8; 1];
            let _ = tls.read(&mut buf).await; // read one byte of the first TSRequest, then drop → close
        });
        (addr, cert_der)
    }

    #[tokio::test]
    async fn connect_progresses_through_tls_into_nla() {
        // The mock completes X.224 + TLS but does not speak CredSSP. What we assert is the handoff:
        // the adapter extracts the server key, advances into `nla-credssp`, and only *then* fails —
        // proving TLS completed and the machine entered NLA before the (unauthenticatable) mock
        // closed the connection.
        let addr = mock_tls_server([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]).await;

        let mut stages = Vec::new();
        let err = connect_danger(addr, test_config(), test_credentials(), |s| {
            stages.push(s.to_string())
        })
        .await
        .unwrap_err();

        // TLS completed and the machine entered NLA before failing...
        assert_eq!(
            stages,
            vec![
                "tcp-connect",
                "x224-negotiate",
                "tls-handshake",
                "nla-credssp"
            ]
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
        let _ = connect_danger(addr, test_config(), test_credentials(), |_| {}).await;

        // Every connect stage through NLA is named in the debug logs (criterion 14: observable
        // transitions)...
        assert!(logs_contain("tcp-connect"), "tcp-connect stage not logged");
        assert!(
            logs_contain("x224-negotiate"),
            "x224-negotiate stage not logged"
        );
        assert!(
            logs_contain("tls-handshake"),
            "tls-handshake stage not logged"
        );
        assert!(logs_contain("nla-credssp"), "nla-credssp stage not logged");
        // ...and byte counts are logged for the plaintext bytes written and read.
        assert!(logs_contain("bytes="), "byte counts not logged");
    }

    #[test]
    fn the_default_trust_policy_is_chain_validation() {
        // The "cannot silently ship" guard from #36: the default-constructed options must perform
        // real chain validation. If the default ever regresses to accept-any, this is the tripwire.
        assert!(matches!(TrustPolicy::default(), TrustPolicy::Chain));
        assert!(matches!(
            ConnectOptions::default().trust,
            TrustPolicy::Chain
        ));
    }

    #[tokio::test]
    async fn connect_rejects_an_untrusted_certificate_by_default() {
        // The mock presents a throwaway self-signed cert no trust store contains. The default
        // policy must fail the handshake itself — the connect never reaches NLA, so the
        // credentials are never exposed to an unauthenticated peer.
        let addr = mock_tls_server([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]).await;

        let mut stages = Vec::new();
        let err = connect(addr, test_config(), test_credentials(), |s| {
            stages.push(s.to_string())
        })
        .await
        .unwrap_err();

        assert!(
            matches!(err, ConnectFailure::TlsHandshake { .. }),
            "expected a TLS trust failure, got {err:?}"
        );
        assert!(
            !stages.contains(&"nla-credssp".to_string()),
            "an untrusted certificate must never reach the NLA stage"
        );
    }

    #[tokio::test]
    async fn tofu_stores_the_pin_on_first_connect_and_proceeds() {
        // First contact: the store has no pin for this host, so TOFU trusts the presented key,
        // persists it, and lets the connect proceed (the mock then fails at NLA as always).
        let (addr, cert_der) =
            mock_tls_server_returning_cert([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]).await;
        let store = Arc::new(MemoryPinStore::default());
        let options = ConnectOptions {
            trust: TrustPolicy::Tofu(store.clone()),
            ..ConnectOptions::default()
        };

        let mut stages = Vec::new();
        let _ = connect_with_options(
            addr,
            test_config(),
            test_credentials(),
            |s| stages.push(s.to_string()),
            options,
        )
        .await;

        assert!(
            stages.contains(&"nla-credssp".to_string()),
            "first-use TOFU must let the connect proceed past TLS, got {stages:?}"
        );
        // The stored pin is exactly the cert's inner subjectPublicKey — the same material
        // CredSSP binds to, extracted by the same function.
        let expected = justrdp::tls::extract_subject_public_key(&cert_der).unwrap();
        assert_eq!(store.lookup("127.0.0.1").unwrap(), Some(expected));
    }

    #[tokio::test]
    async fn tofu_accepts_an_unchanged_key_on_reconnect() {
        let (addr, cert_der) =
            mock_tls_server_returning_cert([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]).await;
        let store = Arc::new(MemoryPinStore::default());
        let pin = justrdp::tls::extract_subject_public_key(&cert_der).unwrap();
        store.store("127.0.0.1", &pin).unwrap();
        let options = ConnectOptions {
            trust: TrustPolicy::Tofu(store),
            ..ConnectOptions::default()
        };

        let mut stages = Vec::new();
        let _ = connect_with_options(
            addr,
            test_config(),
            test_credentials(),
            |s| stages.push(s.to_string()),
            options,
        )
        .await;

        assert!(
            stages.contains(&"nla-credssp".to_string()),
            "an unchanged pinned key must connect, got {stages:?}"
        );
    }

    #[tokio::test]
    async fn tofu_rejects_a_changed_server_key() {
        // The store already pins a *different* key for this host — the situation TOFU exists to
        // catch (a MITM, or a silently reinstalled server). The handshake must fail with a typed
        // error that names the host and both key fingerprints, and never reach NLA.
        let (addr, cert_der) =
            mock_tls_server_returning_cert([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]).await;
        let store = Arc::new(MemoryPinStore::default());
        let pinned: &[u8] = b"not-the-key-the-server-presents";
        store.store("127.0.0.1", pinned).unwrap();
        let options = ConnectOptions {
            trust: TrustPolicy::Tofu(store.clone()),
            ..ConnectOptions::default()
        };

        let mut stages = Vec::new();
        let err = connect_with_options(
            addr,
            test_config(),
            test_credentials(),
            |s| stages.push(s.to_string()),
            options,
        )
        .await
        .unwrap_err();

        let ConnectFailure::TlsHandshake { reason } = &err else {
            panic!("expected a TLS trust failure, got {err:?}");
        };
        // The error names the host and both SHA-256 fingerprints, so a host application can
        // show the user exactly what changed.
        let presented = justrdp::tls::extract_subject_public_key(&cert_der).unwrap();
        assert!(reason.contains("127.0.0.1"), "no host in: {reason}");
        assert!(
            reason.contains(&pin_fingerprint(pinned)),
            "no pinned fingerprint in: {reason}"
        );
        assert!(
            reason.contains(&pin_fingerprint(&presented)),
            "no presented fingerprint in: {reason}"
        );
        assert!(
            !stages.contains(&"nla-credssp".to_string()),
            "a changed key must never reach the NLA stage"
        );
        // And the pin is NOT silently overwritten — the stored key stays the old one.
        assert_eq!(store.lookup("127.0.0.1").unwrap(), Some(pinned.to_vec()));
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
        let key = ck.signing_key.serialize_der();
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
        let _ = connect_danger(server, test_config(), test_credentials(), |s| {
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

        let _ = connect_danger(addr, test_config(), test_credentials(), |_| {}).await;

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
        let err = connect(addr, test_config(), test_credentials(), |_| {})
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

        let err = connect(addr, test_config(), test_credentials(), |_| {})
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

    #[tokio::test]
    async fn connect_maps_a_refused_dial_to_io() {
        // Reserve a loopback port, then release it: nobody listens, so the dial is refused and
        // must surface as ConnectFailure::Io (not a timeout, not a panic).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let err = connect(addr, test_config(), test_credentials(), |_| {})
            .await
            .unwrap_err();
        assert!(
            matches!(err, ConnectFailure::Io(_)),
            "expected Io, got {err:?}"
        );
    }

    /// Like `mock_tls_server`, but a CredSSP peer under our control: after the TLS handshake it
    /// swallows the client's first TSRequest (the SPNEGO/NTLM NEGOTIATE) and answers with the
    /// given raw bytes — each chunk flushed as its own TLS record, so a multi-chunk reply
    /// reaches the client split mid-frame, exactly as real servers split large TSRequests.
    /// This lets the tests drive the adapter's `nla-credssp` read path over the wire, through
    /// public `connect`, with hostile, truncated, or fragmented framing. `hold_open` keeps the
    /// connection alive after the reply (a failure must then come from the bytes, not an EOF);
    /// `false` drops it immediately (an EOF mid-frame).
    async fn mock_tls_server_replying_to_nla(reply: Vec<Vec<u8>>, hold_open: bool) -> SocketAddr {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = ck.signing_key.serialize_der();
        let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 64];
            let _ = sock.read(&mut scratch).await.unwrap(); // plaintext Connection Request
            sock.write_all(&confirm_frame([
                0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
            ]))
            .await
            .unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            let mut nego = [0u8; 4096];
            let _ = tls.read(&mut nego).await.unwrap(); // the client's first TSRequest
            for chunk in reply {
                tls.write_all(&chunk).await.unwrap();
                tls.flush().await.unwrap(); // one TLS record per chunk
            }
            if hold_open {
                let mut buf = [0u8; 1];
                let _ = tls.read(&mut buf).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn connect_rejects_an_oversized_ts_request_from_the_server() {
        // A hostile header claiming a 4-byte BER length of 0x00FF_FFFF (~16 MiB), far over the
        // cap. The connection stays open, so the only way connect can fail is the cap tripping
        // before the content is read or allocated.
        let addr =
            mock_tls_server_replying_to_nla(vec![vec![0x30, 0x84, 0x00, 0xFF, 0xFF, 0xFF]], true)
                .await;
        let err = connect_danger(addr, test_config(), test_credentials(), |_| {})
            .await
            .unwrap_err();
        match &err {
            ConnectFailure::Nla { reason } => {
                assert!(reason.contains("exceeds"), "unexpected reason: {reason}")
            }
            other => panic!("expected an over-cap Nla rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_rejects_an_overwide_ts_request_length() {
        // 0x80 | 0x10 = 16 BER length bytes — wider than usize; the adapter must refuse to
        // parse rather than overflow.
        let addr = mock_tls_server_replying_to_nla(vec![vec![0x30, 0x90]], true).await;
        let err = connect_danger(addr, test_config(), test_credentials(), |_| {})
            .await
            .unwrap_err();
        match &err {
            ConnectFailure::Nla { reason } => {
                assert!(
                    reason.contains("refusing to parse"),
                    "unexpected reason: {reason}"
                )
            }
            other => panic!("expected an over-wide length rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_surfaces_a_truncated_ts_request_as_io() {
        // A valid header promising 10 content bytes, but the server sends 3 and drops the
        // connection: the mid-frame EOF must surface as Io, not hang or panic.
        let addr =
            mock_tls_server_replying_to_nla(vec![vec![0x30, 0x0A, 0x01, 0x02, 0x03]], false).await;
        let err = connect_danger(addr, test_config(), test_credentials(), |_| {})
            .await
            .unwrap_err();
        assert!(
            matches!(err, ConnectFailure::Io(_)),
            "expected an Io EOF error, got {err:?}"
        );
    }

    /// The on-wire bytes of a TSRequest carrying an NSTATUS `errorCode` — what a real server
    /// sends when it rejects the authentication (e.g. STATUS_LOGON_FAILURE). The errorCode is
    /// the **last** field of the DER sequence, so the client can only surface it after framing
    /// and parsing the complete TSRequest.
    fn ts_request_with_error_code(nego_token_len: usize, code: u32) -> Vec<u8> {
        let ts = TsRequest {
            nego_tokens: (nego_token_len > 0).then(|| vec![0xAB; nego_token_len]),
            error_code: Some(sspi::credssp::NStatusCode(code)),
            ..TsRequest::default()
        };
        let mut buf = Vec::new();
        ts.encode_ts_request(&mut buf).unwrap();
        buf
    }

    const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;

    #[tokio::test]
    async fn connect_surfaces_a_server_reported_credssp_error() {
        // A short-form (single length byte) TSRequest carrying STATUS_LOGON_FAILURE: the only
        // way the client can report the server's error status is by having framed and parsed
        // the TSRequest correctly — the positive proof of the short-form read path.
        let reply = ts_request_with_error_code(0, STATUS_LOGON_FAILURE);
        assert!(
            reply[1] < 0x80,
            "expected short-form BER, got {:#x}",
            reply[1]
        );
        let addr = mock_tls_server_replying_to_nla(vec![reply], true).await;

        let err = connect_danger(addr, test_config(), test_credentials(), |_| {})
            .await
            .unwrap_err();
        match &err {
            ConnectFailure::Nla { reason } => assert!(
                reason.contains("error status"),
                "expected the server-reported CredSSP error, got: {reason}"
            ),
            other => panic!("expected an Nla failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_reassembles_a_split_long_form_ts_request() {
        // A 400-byte nego token forces long-form BER, and the reply arrives split across three
        // TLS records (servers really do split TSRequests — the reason the framing code reads
        // by declared length instead of guessing). The errorCode sits at the END of the frame:
        // surfacing it proves the client reassembled the whole long-form TSRequest.
        let reply = ts_request_with_error_code(400, STATUS_LOGON_FAILURE);
        assert!(
            reply[1] >= 0x80,
            "expected long-form BER, got {:#x}",
            reply[1]
        );
        let third = reply.len() / 3;
        let chunks = vec![
            reply[..third].to_vec(),
            reply[third..2 * third].to_vec(),
            reply[2 * third..].to_vec(),
        ];
        let addr = mock_tls_server_replying_to_nla(chunks, true).await;

        let err = connect_danger(addr, test_config(), test_credentials(), |_| {})
            .await
            .unwrap_err();
        match &err {
            ConnectFailure::Nla { reason } => assert!(
                reason.contains("error status"),
                "expected the server-reported CredSSP error, got: {reason}"
            ),
            other => panic!("expected an Nla failure, got {other:?}"),
        }
    }

    /// The password store backing the mock CredSSP server: one account whose password sspi's
    /// NTLM acceptor checks the client's AUTHENTICATE message against.
    struct SingleUser {
        username: String,
        password: String,
    }

    impl sspi::credssp::CredentialsProxy for SingleUser {
        type AuthenticationData = AuthIdentity;

        fn auth_data_by_user(&mut self, username: &Username) -> io::Result<AuthIdentity> {
            // Serve the account's password for whatever name the client claimed; a wrong
            // password still fails the NTLM MIC check, so this does not weaken the test.
            Ok(AuthIdentity {
                username: username.clone(),
                password: Secret::new(self.password.clone()),
            })
        }

        fn auth_data(&mut self) -> io::Result<Vec<AuthIdentity>> {
            let username = Username::parse(&self.username)
                .or_else(|_| Username::new(&self.username, None))
                .map_err(io::Error::other)?;
            Ok(vec![AuthIdentity {
                username,
                password: Secret::new(self.password.clone()),
            }])
        }
    }

    /// A loopback RDP server that speaks the whole pre-MCS sequence for real: X.224 confirm
    /// (HYBRID selected), TLS with a throwaway cert, then a complete CredSSP exchange driven by
    /// sspi's `CredSspServer` — the genuine peer of the `CredSspClient` the adapter runs.
    /// Requires the ADR-0004 fork-bridge (Devolutions/sspi-rs#688): the released 0.21.0 server
    /// drops its final SPNEGO token and can never finish against a Negotiate-NTLM client.
    /// The returned receiver yields the delegated account name once the server reaches
    /// `Finished`, after which it drops the connection (the client is in `capability-exchange`
    /// by then).
    async fn mock_credssp_server(
        username: &str,
        password: &str,
    ) -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        use sspi::credssp::{CredSspServer, ServerMode, ServerState};

        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        // The exact bytes the client binds pubKeyAuth to: the cert's inner subjectPublicKey,
        // extracted by the same public helper the connect machine uses.
        let public_key = justrdp::tls::extract_subject_public_key(cert.as_ref()).unwrap();
        let key = ck.signing_key.serialize_der();
        let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();

        let proxy = SingleUser {
            username: username.to_string(),
            password: password.to_string(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 64];
            let _ = sock.read(&mut scratch).await.unwrap(); // plaintext Connection Request
            sock.write_all(&confirm_frame([
                0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
            ]))
            .await
            .unwrap(); // select HYBRID: the client proceeds to TLS + NLA
            let mut tls = acceptor.accept(sock).await.unwrap();

            // Mirror the client's SPNEGO-wrapped-NTLM configuration on the acceptor side.
            let negotiate = NegotiateConfig::new(
                Box::new(NtlmConfig::default()),
                Some("ntlm,!kerberos,!pku2u".to_string()),
                "mockserver".to_string(),
            );
            let mut server =
                CredSspServer::new(public_key, proxy, ServerMode::Negotiate(negotiate)).unwrap();

            let mut inbox: Vec<u8> = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                // One TSRequest per client write, and the client awaits our reply before the
                // next — so accumulate until the buffer parses as a complete TSRequest.
                let ts_request = loop {
                    if !inbox.is_empty()
                        && let Ok(ts) = TsRequest::from_buffer(&inbox)
                    {
                        inbox.clear();
                        break ts;
                    }
                    let n = tls.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return; // client gave up mid-exchange — the test will fail on stages
                    }
                    inbox.extend_from_slice(&buf[..n]);
                };
                let state = match server.process(ts_request).start() {
                    GeneratorState::Completed(result) => {
                        result.expect("mock CredSSP server step failed")
                    }
                    GeneratorState::Suspended(_) => panic!("NTLM never needs a KDC round trip"),
                };
                match state {
                    ServerState::ReplyNeeded(reply) => {
                        let mut out = Vec::with_capacity(reply.buffer_len() as usize);
                        reply.encode_ts_request(&mut out).unwrap();
                        tls.write_all(&out).await.unwrap();
                    }
                    ServerState::Finished(identity) => {
                        // The delegated TSCredentials arrived: CredSSP is complete. Report the
                        // authenticated account and drop the connection — the client is already
                        // past NLA, so it fails (cleanly) in capability-exchange.
                        let _ = finished_tx.send(identity.username.account_name().to_string());
                        return;
                    }
                }
            }
        });
        (addr, finished_rx)
    }

    #[tokio::test]
    async fn connect_completes_credssp_against_a_loopback_server() {
        // The full NLA loop through public `connect`, in CI (previously real-VM-only):
        // NEGOTIATE → CHALLENGE → AUTHENTICATE+mechListMIC → accept-completed+mechListMIC →
        // pubKeyAuth → server pubKeyAuth → TSCredentials.
        let (addr, finished_rx) = mock_credssp_server("test", "test").await;

        let mut stages = Vec::new();
        let err = connect_danger(addr, test_config(), test_credentials(), |s| {
            stages.push(s.to_string())
        })
        .await
        .unwrap_err();

        // NLA completed: the machine moved past nla-credssp into capability-exchange...
        assert!(
            stages.contains(&"capability-exchange".to_string()),
            "expected the connect to clear NLA into capability-exchange, got {stages:?}"
        );
        // ...the failure is only the mock dropping the socket there...
        assert!(
            matches!(err, ConnectFailure::Io(_)),
            "expected the post-NLA drop as Io, got {err:?}"
        );
        // ...and the server side really finished CredSSP with the delegated credentials.
        let delegated = finished_rx.await.expect("the mock server reached Finished");
        assert_eq!(delegated, "test");
    }

    #[tokio::test]
    async fn connect_times_out_with_the_stage_name_when_the_server_stalls() {
        // A server that accepts the dial, swallows the Connection Request, and never replies:
        // the x224-negotiate stage must elapse and surface *its* name — observed through the
        // public connect API, with the stage timeout injected via ConnectTimeouts.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hold = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 64];
            let _ = sock.read(&mut scratch).await; // swallow the Connection Request…
            tokio::time::sleep(Duration::from_secs(60)).await; // …and stall, socket held open
        });

        let timeouts = ConnectTimeouts {
            stage: Duration::from_millis(200),
            ..ConnectTimeouts::default()
        };
        let err = connect_with_timeouts(addr, test_config(), test_credentials(), |_| {}, timeouts)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ConnectFailure::Timeout {
                    stage: "x224-negotiate"
                }
            ),
            "expected an x224-negotiate timeout, got {err:?}"
        );
        hold.abort();
    }

    /// Real-VM acceptance test (ADR-0001 real-VM harness). Ignored by default — run with
    /// `cargo test -p justrdp-tokio -- --ignored` against the live RDP test VM, with the test
    /// account supplied via `JUSTRDP_TEST_USERNAME` / `JUSTRDP_TEST_PASSWORD` /
    /// `JUSTRDP_TEST_DOMAIN` (the latter optional) — so no credential is committed to the repo.
    /// Verifies the full connect sequence to **session-active**: X.224 → TLS → CredSSP (and the
    /// HYBRID_EX early-auth check) → MCS/GCC + channel join → Client Info → licensing (this VM
    /// short-circuits with `STATUS_VALID_CLIENT`) → Demand/Confirm Active → finalization →
    /// Font Map, then proves the session is live by receiving the server's first post-active
    /// PDU (slice-5 acceptance).
    #[tokio::test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389 and JUSTRDP_TEST_* env vars"]
    async fn connect_reaches_session_active_against_real_vm() {
        let _vm = VM_SESSION.lock().await;
        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let config = test_config();
        let requested = config.requested;
        let requested_size = (config.core.desktop_width, config.core.desktop_height);
        let credentials = Credentials {
            username: std::env::var("JUSTRDP_TEST_USERNAME").expect("set JUSTRDP_TEST_USERNAME"),
            password: std::env::var("JUSTRDP_TEST_PASSWORD").expect("set JUSTRDP_TEST_PASSWORD"),
            domain: std::env::var("JUSTRDP_TEST_DOMAIN").ok(),
        };

        let mut stages = Vec::new();
        // The VM presents a self-signed cert: trusting it is an explicit, test-site decision
        // (issue #36) — the default chain policy is not weakened to make the suite pass.
        let result =
            connect_danger(addr, config, credentials, |s| stages.push(s.to_string())).await;
        eprintln!("stages: {stages:?}");
        let outcome = result.expect("connect should reach session-active against the real VM");
        eprintln!("mcs result: {:?}", outcome.mcs);
        eprintln!(
            "activation: share_id={:#010x} desktop={:?} server_capsets={} leftover={}",
            outcome.activation.share_id,
            outcome.activation.desktop_size,
            outcome.activation.server_capabilities.len(),
            outcome.activation.leftover.len(),
        );

        // The server must select exactly one protocol from the set we advertised...
        assert!(outcome.mcs.selected.bits() != 0);
        assert!(requested.contains(outcome.mcs.selected));
        // ...the MCS exchange must yield a valid user channel (T.125 UserIds start at 1001)
        // and the I/O channel...
        assert!(outcome.mcs.user_channel_id >= 1001);
        assert!(outcome.mcs.io_channel_id >= 1001);
        // ...the requested static channels are answered (granted or refused, never dropped)...
        assert!(outcome.mcs.static_channels.len() <= 2);
        for ch in &outcome.mcs.static_channels {
            assert!(
                ch.id >= 1001,
                "granted channel {} has id {}",
                ch.name,
                ch.id
            );
        }
        // ...and the connect sequence walked every canonical stage, ending in session-active.
        assert_eq!(stages.first().map(String::as_str), Some("tcp-connect"));
        for expected in [
            "x224-negotiate",
            "tls-handshake",
            "nla-credssp",
            "capability-exchange",
            "activation",
        ] {
            assert!(
                stages.contains(&expected.to_string()),
                "expected to reach the {expected} stage, got {stages:?}"
            );
        }
        assert_eq!(stages.last().map(String::as_str), Some("session-active"));

        // Capability exchange settled the desktop size: the VM honors the requested size
        // (compare against the server's own Bitmap capability set as the source of truth).
        let server_bitmap = outcome
            .activation
            .server_capabilities
            .iter()
            .find_map(|set| match set {
                justrdp_pdu::capability::CapabilitySet::Bitmap(bitmap) => Some(bitmap),
                _ => None,
            })
            .expect("the server's Demand Active carries a Bitmap capability set");
        assert_eq!(
            outcome.activation.desktop_size,
            (server_bitmap.desktop_width, server_bitmap.desktop_height),
            "ConnectionResult must record the server-negotiated size"
        );
        assert_eq!(
            outcome.activation.desktop_size, requested_size,
            "this VM honors the requested desktop size"
        );
        assert!(outcome.activation.share_id != 0);

        // Session-active proof: the server starts streaming on its own (graphics / pointer /
        // logon notifications). At least one complete inbound PDU must arrive — either already
        // buffered in `leftover` or readable from the live stream.
        let mut stream = outcome.stream;
        let mut inbox = outcome.activation.leftover;
        let mut buf = [0u8; 8192];
        let frame_len = loop {
            match justrdp_pdu::tpkt::frame_len(&inbox) {
                Ok(n) if inbox.len() >= n => break n,
                Ok(_) | Err(justrdp_pdu::DecodeError::NotEnoughBytes { .. }) => {
                    let n = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut buf))
                        .await
                        .expect("server should send a first PDU after session-active")
                        .expect("read from the live stream");
                    assert!(n > 0, "server closed right after session-active");
                    inbox.extend_from_slice(&buf[..n]);
                }
                // Post-active traffic may be fast-path (no TPKT); any bytes at all prove the
                // session is live.
                Err(_) => break inbox.len(),
            }
        };
        eprintln!(
            "first post-active pdu: {} bytes (of {} buffered)",
            frame_len,
            inbox.len()
        );
        assert!(frame_len > 0);
    }

    /// Caller policy for a *legacy-graphics* (bitmap update) session: do NOT advertise
    /// SUPPORT_DYN_VC_GFX_PROTOCOL (and skip drdynvc). A server seeing the EGFX gate flag
    /// negotiates graphics over the dynamic channel and never falls back to bitmap updates
    /// (verified against this VM: with the flag set it sends only drdynvc DVC requests and
    /// zero bitmap data). Until the EGFX slice exists, the caller advertises what the client
    /// can actually render — exactly the policy seam plan.md §0 demands stays caller-owned.
    fn legacy_graphics_config() -> ConnectConfig {
        let mut config = test_config();
        config.core.early_capability_flags = gcc::ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU
            | gcc::ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN;
        config.channels =
            vec![gcc::ChannelDef::new("cliprdr", gcc::CHANNEL_OPTION_INITIALIZED).unwrap()];
        config
    }

    /// Real-VM differential test (gate #6 fix note 3): capture live bitmap rectangles from
    /// the server and decode the identical bytes with both our codecs and ironrdp-graphics,
    /// asserting byte-identical pixels. The VM delivers them as fast-path updates — the
    /// `TS_BITMAP_DATA` payload inside is the same structure slow-path updates carry
    /// (MS-RDPBCGR 2.2.9.1.1.3.1.2.2), as recorded in the gate verdict.
    #[tokio::test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389 and JUSTRDP_TEST_* env vars"]
    async fn captured_bitmap_rectangles_decode_identically_in_ironrdp() {
        let _vm = VM_SESSION.lock().await;
        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let credentials = Credentials {
            username: std::env::var("JUSTRDP_TEST_USERNAME").expect("set JUSTRDP_TEST_USERNAME"),
            password: std::env::var("JUSTRDP_TEST_PASSWORD").expect("set JUSTRDP_TEST_PASSWORD"),
            domain: std::env::var("JUSTRDP_TEST_DOMAIN").ok(),
        };
        let outcome = connect_danger(addr, legacy_graphics_config(), credentials, |_| {})
            .await
            .expect("connect should reach session-active");
        let mut stream = outcome.stream;
        let mut inbox = outcome.activation.leftover;
        let mut buf = [0u8; 16384];

        // Capture compressed rectangles straight off the wire, reassembling fragmented
        // fast-path bitmap updates (large compressed bitmaps are exactly the ones servers
        // fragment).
        let mut captured: Vec<justrdp_pdu::update::BitmapData> = Vec::new();
        let mut fragment: Vec<u8> = Vec::new();
        let mut total_rects = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        'capture: while captured.len() < 32 {
            while let Some(&first) = inbox.first() {
                let len = if justrdp_pdu::fastpath::is_fastpath(first) {
                    justrdp_pdu::fastpath::frame_len(&inbox)
                } else {
                    justrdp_pdu::tpkt::frame_len(&inbox)
                };
                let len = match len {
                    Ok(n) if inbox.len() >= n => n,
                    _ => break,
                };
                let frame: Vec<u8> = inbox.drain(..len).collect();
                if !justrdp_pdu::fastpath::is_fastpath(first) {
                    continue;
                }
                for section in justrdp_pdu::fastpath::decode_updates(&frame).unwrap() {
                    if section.code != justrdp_pdu::fastpath::FP_UPDATE_BITMAP {
                        continue;
                    }
                    // Reassemble fragmented updates too — large (compressed) bitmaps are
                    // exactly the ones servers fragment.
                    let complete: Option<Vec<u8>> = match section.fragmentation {
                        justrdp_pdu::fastpath::FP_FRAGMENT_SINGLE => Some(section.data.to_vec()),
                        justrdp_pdu::fastpath::FP_FRAGMENT_FIRST => {
                            fragment = section.data.to_vec();
                            None
                        }
                        _ => {
                            fragment.extend_from_slice(section.data);
                            if section.fragmentation == justrdp_pdu::fastpath::FP_FRAGMENT_LAST {
                                Some(std::mem::take(&mut fragment))
                            } else {
                                None
                            }
                        }
                    };
                    let Some(data) = complete else { continue };
                    let mut cur = justrdp_pdu::cursor::ReadCursor::new(&data, "capture");
                    cur.read_u16_le().unwrap(); // updateType
                    let update = justrdp_pdu::update::BitmapUpdate::decode(&mut cur)
                        .expect("captured bitmap update decodes");
                    for rect in update.rectangles {
                        total_rects += 1;
                        if rect.compressed {
                            captured.push(rect);
                        }
                    }
                }
            }
            match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => inbox.extend_from_slice(&buf[..n]),
                _ => break 'capture,
            }
        }
        eprintln!(
            "captured {} compressed rectangles from the live server ({total_rects} total)",
            captured.len()
        );
        assert!(
            captured.len() >= 4,
            "expected the server to produce compressed bitmap rectangles to capture"
        );

        for (i, rect) in captured.iter().enumerate() {
            let (w, h) = (usize::from(rect.width), usize::from(rect.height));
            if rect.bits_per_pixel == 32 {
                let ours = justrdp_codecs::planar::decompress(&rect.data, w, h)
                    .unwrap_or_else(|e| panic!("rect {i}: ours failed: {e}"));
                let mut theirs = Vec::new();
                ironrdp_graphics::rdp6::BitmapStreamDecoder::default()
                    .decode_bitmap_stream_to_rgb24(&rect.data, &mut theirs, w, h)
                    .unwrap_or_else(|e| panic!("rect {i}: oracle failed: {e:?}"));
                let ours_rgb: Vec<u8> = ours
                    .chunks_exact(3)
                    .flat_map(|bgr| [bgr[2], bgr[1], bgr[0]])
                    .collect();
                assert_eq!(ours_rgb, theirs, "rect {i} ({w}x{h} planar) diverged");
            } else {
                let ours = justrdp_codecs::rle::decompress(&rect.data, w, h, rect.bits_per_pixel)
                    .unwrap_or_else(|e| panic!("rect {i}: ours failed: {e}"));
                let mut theirs = Vec::new();
                ironrdp_graphics::rle::decompress(
                    &rect.data,
                    &mut theirs,
                    w,
                    h,
                    usize::from(rect.bits_per_pixel),
                )
                .unwrap_or_else(|e| panic!("rect {i}: oracle failed: {e:?}"));
                assert_eq!(
                    ours, theirs,
                    "rect {i} ({w}x{h} @ {} bpp RLE) diverged",
                    rect.bits_per_pixel
                );
            }
        }
        eprintln!(
            "all {} captured rectangles byte-identical in both stacks",
            captured.len()
        );
    }

    /// Assemble the [`justrdp::SessionConfig`] from a connect outcome — including the server's
    /// Input capability flags, which pick the input transport (fast-path vs slow-path).
    fn session_config_from(
        outcome: &ConnectOutcome,
        capabilities: Vec<justrdp_pdu::capability::CapabilitySet>,
    ) -> justrdp::SessionConfig {
        let server_input_flags = outcome
            .activation
            .server_capabilities
            .iter()
            .find_map(|set| match set {
                justrdp_pdu::capability::CapabilitySet::Input(input) => Some(input.input_flags),
                _ => None,
            })
            .unwrap_or(0);
        justrdp::SessionConfig {
            user_channel_id: outcome.mcs.user_channel_id,
            io_channel_id: outcome.mcs.io_channel_id,
            share_id: outcome.activation.share_id,
            desktop_size: outcome.activation.desktop_size,
            capabilities,
            server_input_flags,
            drdynvc_channel_id: outcome
                .mcs
                .static_channels
                .iter()
                .find(|c| c.name == "drdynvc")
                .map(|c| c.id),
        }
    }

    /// Real-VM acceptance test for slice-6: connect to session-active, run the session loop,
    /// and verify the first decoded frames actually render the desktop — at least one
    /// FrameUpdate arrives, most of the screen gets painted, and the framebuffer is visibly
    /// not monochrome (taskbar/wallpaper/icons produce many distinct colors). A PPM dump of
    /// the framebuffer is written to the temp directory for human visual confirmation.
    #[tokio::test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389 and JUSTRDP_TEST_* env vars"]
    async fn first_frames_render_the_desktop_against_real_vm() {
        let _vm = VM_SESSION.lock().await;
        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let config = legacy_graphics_config();
        let session_capabilities = config.capabilities.clone();
        let credentials = Credentials {
            username: std::env::var("JUSTRDP_TEST_USERNAME").expect("set JUSTRDP_TEST_USERNAME"),
            password: std::env::var("JUSTRDP_TEST_PASSWORD").expect("set JUSTRDP_TEST_PASSWORD"),
            domain: std::env::var("JUSTRDP_TEST_DOMAIN").ok(),
        };
        let outcome = connect_danger(addr, config, credentials, |_| {})
            .await
            .expect("connect should reach session-active");

        let mut machine = SessionStateMachine::new(
            session_config_from(&outcome, session_capabilities),
            outcome.activation.leftover,
        );
        let mut stream = outcome.stream;

        // Let the session run for a few seconds: the server paints the full desktop right
        // after activation. The timeout is the expected exit (a session never ends itself).
        let mut frames = 0usize;
        let mut covered: u64 = 0;
        let ended = tokio::time::timeout(
            Duration::from_secs(8),
            run_session(
                &mut stream,
                &mut machine,
                |frame| {
                    frames += 1;
                    covered += u64::from(frame.width) * u64::from(frame.height);
                },
                |_| {},
            ),
        )
        .await;
        if let Ok(result) = ended {
            result.expect("session failed before the observation window closed");
            panic!("server closed the session unexpectedly early");
        }

        let fb = machine.framebuffer();
        let total = u64::from(fb.width()) * u64::from(fb.height());
        eprintln!(
            "frames={frames} covered={covered}px of {total}px ({}x{})",
            fb.width(),
            fb.height()
        );
        assert!(frames >= 1, "no FrameUpdate was emitted");
        assert!(
            covered >= total / 2,
            "expected at least half the desktop painted, got {covered} of {total}"
        );

        // Monochrome output would mean the decode silently produced garbage.
        let mut distinct = std::collections::HashSet::new();
        for px in fb.pixels().chunks_exact(4) {
            distinct.insert([px[0], px[1], px[2]]);
            if distinct.len() > 16 {
                break;
            }
        }
        assert!(
            distinct.len() > 16,
            "framebuffer is near-monochrome ({} colors) — decode likely broken",
            distinct.len()
        );

        // Visual confirmation artifact (open with any image viewer).
        let path = std::env::temp_dir().join("justrdp-slice6-first-frame.ppm");
        let mut ppm = format!("P6\n{} {}\n255\n", fb.width(), fb.height()).into_bytes();
        for px in fb.pixels().chunks_exact(4) {
            ppm.extend_from_slice(&px[..3]);
        }
        std::fs::write(&path, ppm).expect("write the visual dump");
        eprintln!("visual dump for confirmation: {}", path.display());
    }

    /// All real-VM tests log on to the same Windows session on the test VM; a concurrent
    /// logon with the same account takes the session over and kicks the other test mid-run
    /// (observed as a flake when the whole `--ignored` suite runs in parallel). Serialize
    /// them on one process-wide lock.
    static VM_SESSION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Credentials from the environment for the real-VM tests.
    fn vm_credentials() -> Credentials {
        Credentials {
            username: std::env::var("JUSTRDP_TEST_USERNAME").expect("set JUSTRDP_TEST_USERNAME"),
            password: std::env::var("JUSTRDP_TEST_PASSWORD").expect("set JUSTRDP_TEST_PASSWORD"),
            domain: std::env::var("JUSTRDP_TEST_DOMAIN").ok(),
        }
    }

    /// Cancel-safety (issue #8): cancelling the token ends `run_session_with_commands`
    /// promptly and cleanly even while the server is silent and a refused resize command is
    /// queued — no deadlock, no error. The mock completes a real TLS handshake and then holds
    /// the connection open without sending a byte.
    #[tokio::test]
    async fn cancellation_ends_the_session_loop_promptly() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = ck.signing_key.serialize_der();
        let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            let mut buf = [0u8; 256];
            // Hold the session open, consuming whatever the client writes (the refused
            // resize writes nothing, but input commands would land here).
            loop {
                match tls.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        // This raw session-loop test trusts the throwaway cert explicitly; trust policy is
        // exercised by the connect-level tests.
        let connector = TlsConnector::from(Arc::new(
            client_config(&TrustPolicy::DangerAcceptAny, "localhost").unwrap(),
        ));
        let mut stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), sock)
            .await
            .unwrap();
        let mut machine = SessionStateMachine::new(
            justrdp::SessionConfig {
                user_channel_id: 1007,
                io_channel_id: 1003,
                share_id: 0x0001_03EA,
                desktop_size: (16, 8),
                capabilities: Vec::new(),
                server_input_flags: 0,
                drdynvc_channel_id: None,
            },
            Vec::new(),
        );

        let (tx, mut commands) = tokio::sync::mpsc::channel(4);
        // A resize before DisplayControlReady: refused (warn + drop), session keeps running.
        tx.send(SessionCommand::Resize {
            width: 1024,
            height: 768,
        })
        .await
        .unwrap();
        let cancel = CancellationToken::new();
        let canceller = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            canceller.cancel();
        });

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_session_with_commands(
                &mut stream,
                &mut machine,
                |_| {},
                |_| {},
                |_| {},
                &mut commands,
                &cancel,
            ),
        )
        .await;
        assert!(
            matches!(result, Ok(Ok(DisconnectReason::LocalClosed))),
            "cancellation should end the loop cleanly as LocalClosed, got {result:?}"
        );
    }

    /// Cursor events reach the host's synchronous cursor sink (issue #41), mirroring the
    /// frame sink: a mock session server sends one fast-path New Pointer update (a 1×1
    /// 32-bpp shape) and closes; the `on_cursor` callback must observe the decoded shape.
    #[tokio::test]
    async fn run_session_surfaces_cursor_events_to_the_host() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = ck.signing_key.serialize_der();
        let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            // TS_FP_POINTERATTRIBUTE: xorBpp 32, cacheIndex 0, hotspot (3,1), 1×1,
            // lengthAndMask 2, lengthXorMask 4, BGRA pixel, opaque AND mask.
            let mut body = Vec::new();
            for v in [32u16, 0, 3, 1, 1, 1, 2, 4] {
                body.extend_from_slice(&v.to_le_bytes());
            }
            body.extend_from_slice(&[10, 20, 30, 255]); // B G R A
            body.extend_from_slice(&[0x00, 0x00]);
            let pdu = justrdp_pdu::fastpath::encode_pdu(&[(
                justrdp_pdu::fastpath::FP_UPDATE_NEW_POINTER,
                justrdp_pdu::fastpath::FP_FRAGMENT_SINGLE,
                &body,
            )]);
            tls.write_all(&pdu).await.unwrap();
            // Orderly TLS close (close_notify) → run_session returns Ok after draining.
            let _ = tls.shutdown().await;
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        let connector = TlsConnector::from(Arc::new(
            client_config(&TrustPolicy::DangerAcceptAny, "localhost").unwrap(),
        ));
        let mut stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), sock)
            .await
            .unwrap();
        let mut machine = SessionStateMachine::new(
            justrdp::SessionConfig {
                user_channel_id: 1007,
                io_channel_id: 1003,
                share_id: 0x0001_03EA,
                desktop_size: (16, 8),
                // The pointer cache is sized from this advertisement.
                capabilities: vec![justrdp_pdu::capability::CapabilitySet::Pointer(
                    justrdp_pdu::capability::PointerCapabilitySet {
                        color_pointer_flag: 1,
                        color_pointer_cache_size: 20,
                        pointer_cache_size: 20,
                    },
                )],
                server_input_flags: 0,
                drdynvc_channel_id: None,
            },
            Vec::new(),
        );

        let mut cursors: Vec<justrdp::CursorEvent> = Vec::new();
        run_session(
            &mut stream,
            &mut machine,
            |_| {},
            |c| cursors.push(c.clone()),
        )
        .await
        .unwrap();

        let [justrdp::CursorEvent::Set(image)] = cursors.as_slice() else {
            panic!("expected one SetCursor event, got {cursors:?}");
        };
        assert_eq!((image.width, image.height), (1, 1));
        assert_eq!((image.hotspot_x, image.hotspot_y), (3, 1));
        assert_eq!(image.rgba, [30, 20, 10, 255]); // BGRA wire → RGBA out
    }

    /// A bare mock session server: TLS handshake, then it writes `frames` to the client and
    /// closes cleanly (close_notify). No X.224/CredSSP — the machine under test is the
    /// *session* loop.
    async fn mock_session_server(frames: Vec<Vec<u8>>) -> SocketAddr {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = ck.signing_key.serialize_der();
        let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            for frame in frames {
                tls.write_all(&frame).await.unwrap();
            }
            let _ = tls.shutdown().await;
        });
        addr
    }

    /// Connect a raw TLS client to `addr` and run `run_session` over it with a fresh
    /// machine, returning the session's terminal value.
    async fn session_terminal_value(
        addr: SocketAddr,
    ) -> Result<justrdp::DisconnectReason, SessionFailure> {
        let sock = TcpStream::connect(addr).await.unwrap();
        let connector = TlsConnector::from(Arc::new(
            client_config(&TrustPolicy::DangerAcceptAny, "localhost").unwrap(),
        ));
        let mut stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), sock)
            .await
            .unwrap();
        let mut machine = SessionStateMachine::new(
            justrdp::SessionConfig {
                user_channel_id: 1007,
                io_channel_id: 1003,
                share_id: 0x0001_03EA,
                desktop_size: (16, 8),
                capabilities: Vec::new(),
                server_input_flags: 0,
                drdynvc_channel_id: None,
            },
            Vec::new(),
        );
        run_session(&mut stream, &mut machine, |_| {}, |_| {}).await
    }

    /// A server→client MCS Send Data Indication frame on `channel` (initiator 1002), TPKT
    /// framed — the transport every slow-path Share PDU rides.
    fn server_io_frame(channel: u16, payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() < 0x80, "test helper: short PER length only");
        let mut body = vec![0x68]; // CHOICE sendDataIndication (26 << 2)
        body.extend_from_slice(&(1002u16 - 1001).to_be_bytes());
        body.extend_from_slice(&channel.to_be_bytes());
        body.push(0x70); // dataPriority + segmentation
        body.push(payload.len() as u8);
        body.extend_from_slice(payload);
        justrdp_pdu::tpkt::encode(&justrdp_pdu::x224::encode_data(&body))
    }

    #[tokio::test]
    async fn an_error_info_before_close_attributes_the_disconnect() {
        // ERRINFO_LOGOFF_BY_USER then an orderly close: the terminal value must carry the
        // server's attribution — not UnexpectedDisconnect (the issue-42 ordering criterion).
        let error_info = justrdp_pdu::share::encode_share_data(
            1002,
            0x0001_03EA,
            justrdp_pdu::share::STREAM_MED,
            justrdp_pdu::share::PDU_TYPE2_SET_ERROR_INFO,
            &0x0000_000Cu32.to_le_bytes(),
        );
        let addr = mock_session_server(vec![server_io_frame(1003, &error_info)]).await;

        let reason = session_terminal_value(addr).await.unwrap();

        assert!(
            matches!(
                reason,
                justrdp::DisconnectReason::ServerDisconnected(
                    justrdp::ServerDisconnectCause::ErrorInfo(_)
                )
            ),
            "expected the Error Info attribution, got {reason:?}"
        );
        assert_eq!(reason.class(), justrdp::DisconnectClass::UserLogoff);
    }

    #[tokio::test]
    async fn a_provider_ultimatum_before_close_attributes_the_disconnect() {
        let dpum = justrdp_pdu::tpkt::encode(&justrdp_pdu::x224::encode_data(
            &justrdp_pdu::mcs::encode_disconnect_provider_ultimatum(
                justrdp_pdu::mcs::RN_PROVIDER_INITIATED,
            ),
        ));
        let addr = mock_session_server(vec![dpum]).await;

        let reason = session_terminal_value(addr).await.unwrap();

        assert_eq!(
            reason,
            justrdp::DisconnectReason::ServerDisconnected(
                justrdp::ServerDisconnectCause::ProviderUltimatum {
                    reason: justrdp_pdu::mcs::RN_PROVIDER_INITIATED
                }
            )
        );
    }

    #[tokio::test]
    async fn a_silent_close_is_an_unexpected_disconnect() {
        let addr = mock_session_server(Vec::new()).await;
        let reason = session_terminal_value(addr).await.unwrap();
        assert_eq!(reason, justrdp::DisconnectReason::UnexpectedDisconnect);
    }

    /// Real-VM acceptance test for slice-9: the EGFX Graphics Pipeline. Connect with the
    /// EGFX gate flag advertised (`test_config` sets `SUPPORT_DYN_VC_GFX_PROTOCOL` — the flag
    /// ironrdp hardcoded away, the reason justrdp exists) plus the drdynvc channel. On this
    /// VM that flag makes the server send **zero** slow-path bitmap data (verified in
    /// slice-6), so every rendered pixel below necessarily travelled the EGFX path: caps
    /// advertise/confirm → surface create/map → Progressive/Clear/Planar tile decode →
    /// dirty-region frames. Asserts the desktop actually painted (coverage + color variety),
    /// that the EGFX caps handshake was observed on the wire, and dumps a PPM for human
    /// confirmation.
    #[tokio::test]
    #[traced_test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389 and JUSTRDP_TEST_* env vars"]
    async fn egfx_graphics_pipeline_renders_the_desktop_against_real_vm() {
        let _vm = VM_SESSION.lock().await;
        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let config = test_config(); // EGFX flag ON + drdynvc channel
        let session_capabilities = config.capabilities.clone();
        let outcome = connect_danger(addr, config, vm_credentials(), |_| {})
            .await
            .expect("connect should reach session-active");
        let session_config = session_config_from(&outcome, session_capabilities);
        assert!(
            session_config.drdynvc_channel_id.is_some(),
            "the VM should grant the drdynvc static channel"
        );
        let mut machine = SessionStateMachine::new(session_config, outcome.activation.leftover);
        let mut stream = outcome.stream;

        let mut frames = 0usize;
        let mut covered: u64 = 0;
        let ended = tokio::time::timeout(
            Duration::from_secs(10),
            run_session(
                &mut stream,
                &mut machine,
                |frame| {
                    frames += 1;
                    covered += u64::from(frame.width) * u64::from(frame.height);
                },
                |_| {},
            ),
        )
        .await;
        if let Ok(result) = ended {
            result.expect("session failed during the observation window");
            panic!("server closed the session unexpectedly early");
        }

        let fb = machine.framebuffer();
        let total = u64::from(fb.width()) * u64::from(fb.height());
        eprintln!(
            "EGFX frames={frames} covered={covered}px of {total}px ({}x{})",
            fb.width(),
            fb.height()
        );
        assert!(frames >= 1, "no EGFX FrameUpdate was emitted");
        assert!(
            covered >= total / 2,
            "expected at least half the desktop painted via EGFX, got {covered} of {total}"
        );

        // The caps handshake must have been observed on the wire (not inferred).
        assert!(
            logs_contain("rdp_egfx_caps"),
            "EGFX caps milestones never logged"
        );
        assert!(
            logs_contain("EGFX caps confirmed"),
            "server never confirmed EGFX caps"
        );

        // Monochrome output would mean the tile decode silently produced garbage.
        let mut distinct = std::collections::HashSet::new();
        for px in fb.pixels().chunks_exact(4) {
            distinct.insert([px[0], px[1], px[2]]);
            if distinct.len() > 16 {
                break;
            }
        }
        assert!(
            distinct.len() > 16,
            "framebuffer is near-monochrome ({} colors) — EGFX decode likely broken",
            distinct.len()
        );

        let path = std::env::temp_dir().join("justrdp-slice9-egfx-frame.ppm");
        let mut ppm = format!("P6\n{} {}\n255\n", fb.width(), fb.height()).into_bytes();
        for px in fb.pixels().chunks_exact(4) {
            ppm.extend_from_slice(&px[..3]);
        }
        std::fs::write(&path, ppm).expect("write the visual dump");
        eprintln!("visual dump for confirmation: {}", path.display());
    }

    /// Corpus-capture harness for #56 (the self-owned ClearCodec rewrite). Drives a real-VM
    /// EGFX session with `JUSTRDP_CLEAR_CAPTURE_DIR` pointed at a dump directory; the ClearCodec
    /// chokepoint in `justrdp-codecs` writes every `CODECID_CLEARCODEC` payload there (one
    /// `clear-NNNN.bin` each) plus a `manifest.tsv` recording each stream's dimensions and
    /// decode status (`ok` / `err:<msg>`).
    ///
    /// The payloads whose status carries the `rlex: suite exceeds region pixel count` or
    /// `shortVBarCacheMiss` signatures are exactly the oracle-rejected corpus #56 needs: the
    /// bootstrap oracle cannot arbitrate them, so they must be harvested from a real server, not
    /// synthesised. This test only *proves capture works* and summarises what the VM emitted —
    /// it does not assert a particular signature appears, because which regions a server
    /// Clear-codes is non-deterministic. Curate the committed fixtures from the dump afterwards
    /// (the manifest's `err:` rows point at the streams worth keeping).
    #[tokio::test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389 and JUSTRDP_TEST_* env vars"]
    async fn capture_clearcodec_corpus_against_real_vm() {
        let _vm = VM_SESSION.lock().await;

        let dump = std::env::temp_dir().join("justrdp-clearcodec-corpus");
        let _ = std::fs::remove_dir_all(&dump);
        std::fs::create_dir_all(&dump).expect("create the capture dir");
        // SAFETY: set before the session task spins up and removed after it ends; the VM_SESSION
        // lock serialises real-VM tests and nothing else touches this var, so no concurrent
        // reader/writer races the process environment.
        unsafe {
            std::env::set_var("JUSTRDP_CLEAR_CAPTURE_DIR", &dump);
        }

        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let config = test_config(); // EGFX flag ON + drdynvc channel
        let session_capabilities = config.capabilities.clone();
        let outcome = connect_danger(addr, config, vm_credentials(), |_| {})
            .await
            .expect("connect should reach session-active");
        let session_config = session_config_from(&outcome, session_capabilities);
        let mut machine = SessionStateMachine::new(session_config, outcome.activation.leftover);
        let mut stream = outcome.stream;

        // Run long enough to surface Clear-coded regions. The desktop's taskbar/tray was
        // Clear-coded in slice-9; interacting with the desktop (opening windows) widens the
        // Clear area, so a longer window captures a richer corpus.
        let _ = tokio::time::timeout(
            Duration::from_secs(20),
            run_session(&mut stream, &mut machine, |_| {}, |_| {}),
        )
        .await;

        // SAFETY: see the matching `set_var` above — same serialised, single-writer context.
        unsafe {
            std::env::remove_var("JUSTRDP_CLEAR_CAPTURE_DIR");
        }

        let manifest = std::fs::read_to_string(dump.join("manifest.tsv")).unwrap_or_default();
        let rows: Vec<&str> = manifest.lines().collect();
        let mut ok = 0usize;
        let mut signatures: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for row in &rows {
            let status = row.splitn(5, '\t').nth(4).unwrap_or("");
            if status == "ok" {
                ok += 1;
            } else if let Some(msg) = status.strip_prefix("err:") {
                // The oracle messages read `ClearCodec decode: [path @ file:line] invalid
                // `field`: detail`; bucket by the part after the location bracket so the
                // signature — not the crate path — is the key.
                let sig = msg
                    .rsplit_once("] ")
                    .map(|(_, s)| s)
                    .unwrap_or(msg)
                    .trim()
                    .to_string();
                *signatures.entry(sig).or_default() += 1;
            }
        }
        eprintln!(
            "ClearCodec corpus: {} payloads captured ({ok} decoded ok, {} rejected) -> {}",
            rows.len(),
            rows.len() - ok,
            dump.display()
        );
        for (sig, n) in &signatures {
            eprintln!("  rejected x{n}: {sig}");
        }
        assert!(
            !rows.is_empty(),
            "no ClearCodec payloads captured — the VM may not have Clear-coded any region this \
             run; interact with the desktop (open windows) to widen the Clear area and retry"
        );
    }

    /// Real-VM acceptance test for slice-8: drdynvc + Display Control resize. Connect with
    /// the `drdynvc` static channel (EGFX gate flag deliberately **off**, so graphics stay on
    /// the proven bitmap path), wait for the server to negotiate drdynvc caps, create the
    /// Display Control channel and send its caps (surfaced as `DisplayControlReady`), then
    /// request a resize to a different resolution. The server answers with the
    /// Deactivation–Reactivation cycle; the test passes when the full-screen re-emit arrives
    /// at the new size and the framebuffer matches.
    ///
    /// The PDU sequence (issue #8's logging criterion) is captured through the core's
    /// tracing milestones — `rdp_drdynvc` (caps/create), `rdp_displaycontrol_caps`,
    /// `rdp_displaycontrol_resize`, `rdp_deactivate_all`, `rdp_demand_active`,
    /// `rdp_font_map` — asserted below and visible with `--nocapture`.
    #[tokio::test]
    #[traced_test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389 and JUSTRDP_TEST_* env vars"]
    async fn display_control_resize_against_real_vm() {
        let _vm = VM_SESSION.lock().await;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let mut config = legacy_graphics_config();
        config
            .channels
            .push(gcc::ChannelDef::new("drdynvc", gcc::CHANNEL_OPTION_INITIALIZED).unwrap());
        let session_capabilities = config.capabilities.clone();
        let initial_size = (config.core.desktop_width, config.core.desktop_height);
        let target = if initial_size == (1024, 768) {
            (1280, 1024)
        } else {
            (1024, 768)
        };

        let outcome = connect_danger(addr, config, vm_credentials(), |_| {})
            .await
            .expect("connect should reach session-active");
        let session_config = session_config_from(&outcome, session_capabilities);
        assert!(
            session_config.drdynvc_channel_id.is_some(),
            "the VM should grant the drdynvc static channel; granted: {:?}",
            outcome.mcs.static_channels
        );
        let mut machine = SessionStateMachine::new(session_config, outcome.activation.leftover);
        let mut stream = outcome.stream;

        let (tx, mut commands) = tokio::sync::mpsc::channel(4);
        let cancel = CancellationToken::new();
        let ready_seen = Arc::new(AtomicBool::new(false));
        let resized_seen = Arc::new(AtomicBool::new(false));

        let ready_in_event = ready_seen.clone();
        let on_event = move |event: SessionEvent| {
            assert_eq!(event, SessionEvent::DisplayControlReady);
            eprintln!("milestone: DisplayControlReady (drdynvc caps + create + EDISP caps done)");
            ready_in_event.store(true, Ordering::SeqCst);
            tx.try_send(SessionCommand::Resize {
                width: target.0,
                height: target.1,
            })
            .expect("queue the resize command");
            eprintln!(
                "milestone: Monitor Layout resize to {}x{} queued",
                target.0, target.1
            );
        };
        let resized_in_sink = resized_seen.clone();
        let canceller = cancel.clone();
        let on_frame = move |frame: &FrameUpdate| {
            if (frame.width, frame.height) == target && (frame.x, frame.y) == (0, 0) {
                // The post-reactivation full-screen re-emit at the new size.
                eprintln!(
                    "milestone: reactivation complete, full frame at {}x{}",
                    frame.width, frame.height
                );
                resized_in_sink.store(true, Ordering::SeqCst);
                canceller.cancel();
            }
        };

        let result = tokio::time::timeout(
            Duration::from_secs(30),
            run_session_with_commands(
                &mut stream,
                &mut machine,
                on_frame,
                |_| {},
                on_event,
                &mut commands,
                &cancel,
            ),
        )
        .await
        .expect("resize cycle should complete well within the window");
        result.expect("session failed during the resize cycle");

        assert!(
            ready_seen.load(Ordering::SeqCst),
            "DisplayControlReady never fired"
        );
        assert!(
            resized_seen.load(Ordering::SeqCst),
            "no full-screen frame at the new size"
        );
        let fb = machine.framebuffer();
        assert_eq!(
            (fb.width(), fb.height()),
            target,
            "framebuffer was not rebuilt at the negotiated size"
        );

        // The wire sequence, as observed PDUs (issue #8: "log the sequence of PDU types
        // exchanged") — each milestone must have actually been seen on the wire, not
        // inferred from pixels.
        for (target_name, what) in [
            ("rdp_drdynvc", "DYNVC capabilities/create traffic"),
            ("rdp_displaycontrol_caps", "DISPLAYCONTROL_CAPS"),
            ("rdp_displaycontrol_resize", "Monitor Layout resize request"),
            ("rdp_deactivate_all", "DeactivateAll"),
            ("rdp_demand_active", "Demand Active"),
            ("rdp_font_map", "Font Map (reactivation complete)"),
        ] {
            assert!(
                logs_contain(target_name),
                "{what} was never logged ({target_name})"
            );
        }
        eprintln!(
            "PDU sequence observed: DYNVC caps → create → EDISP caps → Monitor Layout → \
             DeactivateAll → Demand Active → Font Map"
        );
        eprintln!(
            "resize verified: {}x{} → {}x{}",
            initial_size.0,
            initial_size.1,
            fb.width(),
            fb.height()
        );
    }

    /// Queue one press+release pair for the key a Windows VK maps to.
    fn tap(vk: u16) -> Vec<InputEvent> {
        let sc = justrdp::input::scancode_from_windows_vk(vk)
            .unwrap_or_else(|| panic!("VK {vk:#04x} should map to a set-1 scancode"));
        vec![sc.press(), sc.release()]
    }

    /// Real-VM acceptance (issue #42): logging off inside the session ends it with the
    /// server's **typed** attribution (ERRINFO_LOGOFF_BY_USER → the UserLogoff bucket), not
    /// an unexplained EOF. The logoff is driven the same way slice-7 launches Notepad —
    /// click Start, type the command into the search, Enter — because this VM ignores the
    /// Windows logo key (server-side policy, probed in slice-7), so Win+R is unavailable.
    #[tokio::test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389 and JUSTRDP_TEST_* env vars"]
    async fn logoff_inside_the_session_yields_the_typed_reason() {
        let _vm = VM_SESSION.lock().await;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let config = test_config();
        let session_capabilities = config.capabilities.clone();
        let requested_size = (config.core.desktop_width, config.core.desktop_height);
        let outcome = connect_danger(addr, config, vm_credentials(), |_| {})
            .await
            .expect("connect should reach session-active");
        let mut machine = SessionStateMachine::new(
            session_config_from(&outcome, session_capabilities),
            outcome.activation.leftover,
        );
        let mut stream = outcome.stream;

        let frames_in_sink = Arc::new(AtomicUsize::new(0));
        let frames_in_driver = frames_in_sink.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<InputEvent>>(8);
        tokio::spawn(async move {
            let _ = tx
                .send(vec![InputEvent::Sync {
                    toggle_flags: keyboard_toggle_flags(),
                }])
                .await;
            // Wait until the desktop has painted AND settled.
            let mut last = frames_in_driver.load(Ordering::SeqCst);
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let now = frames_in_driver.load(Ordering::SeqCst);
                if now == last && now > 0 {
                    break;
                }
                last = now;
            }
            // Click the Start button (the slice-7-proven launch path), then type the
            // command into the Start search and run it.
            let (x, y) = (24u16, requested_size.1.saturating_sub(20));
            let _ = tx
                .send(vec![
                    InputEvent::Mouse {
                        flags: justrdp_pdu::input::PTRFLAGS_MOVE,
                        wheel_units: 0,
                        x,
                        y,
                    },
                    InputEvent::Mouse {
                        flags: justrdp_pdu::input::PTRFLAGS_DOWN
                            | justrdp_pdu::input::PTRFLAGS_BUTTON1,
                        wheel_units: 0,
                        x,
                        y,
                    },
                    InputEvent::Mouse {
                        flags: justrdp_pdu::input::PTRFLAGS_BUTTON1,
                        wheel_units: 0,
                        x,
                        y,
                    },
                ])
                .await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            for vk in [0x4Cu16, 0x4F, 0x47, 0x4F, 0x46, 0x46] {
                let _ = tx.send(tap(vk)).await; // L O G O F F
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = tx.send(tap(0x0D)).await; // Enter
            // Keep tx alive until the session ends so the input branch stays open.
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let ended = tokio::time::timeout(
            Duration::from_secs(60),
            run_session_with_input(
                &mut stream,
                &mut machine,
                |_| {
                    frames_in_sink.fetch_add(1, Ordering::SeqCst);
                },
                |_| {},
                &mut rx,
            ),
        )
        .await;
        let reason = match ended {
            Ok(result) => result.expect("the logoff close must classify, not fail"),
            Err(_elapsed) => {
                // Dump what the desktop looked like so the failure is diagnosable.
                let fb = machine.framebuffer();
                let path = std::env::temp_dir().join("justrdp-issue42-timeout.ppm");
                let mut ppm = format!("P6\n{} {}\n255\n", fb.width(), fb.height()).into_bytes();
                for px in fb.pixels().chunks_exact(4) {
                    ppm.extend_from_slice(&px[..3]);
                }
                std::fs::write(&path, ppm).expect("write the visual dump");
                panic!(
                    "the server did not close the session after the logoff; desktop dumped to {}",
                    path.display()
                );
            }
        };

        eprintln!("logoff terminal value: {reason:?} → {:?}", reason.class());
        assert!(
            matches!(reason, justrdp::DisconnectReason::ServerDisconnected(_)),
            "expected a server-attributed disconnect, got {reason:?}"
        );
        assert_eq!(reason.class(), justrdp::DisconnectClass::UserLogoff);
    }

    /// Real-VM acceptance (issue #42 C7): a server-side **disconnect** (not logoff) — driven by
    /// running `tsdiscon` inside the session — ends it with the server's *typed* attribution
    /// (an MCS Disconnect Provider Ultimatum, or a Set Error Info PDU), i.e.
    /// [`DisconnectReason::ServerDisconnected`], never an unexplained EOF. The exact class is
    /// VM-policy-dependent (commonly `ProviderUltimatum`), so it is logged rather than pinned;
    /// the invariant under test is *attributed vs unexpected*. `tsdiscon` is launched the same
    /// way slice-7 launches Notepad — Start button, type the command, Enter — because this VM
    /// ignores the Windows logo key (server-side policy probed in slice-7).
    #[tokio::test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389 and JUSTRDP_TEST_* env vars"]
    async fn tsdiscon_inside_the_session_yields_a_typed_server_disconnect() {
        let _vm = VM_SESSION.lock().await;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let config = test_config();
        let session_capabilities = config.capabilities.clone();
        let requested_size = (config.core.desktop_width, config.core.desktop_height);
        let outcome = connect_danger(addr, config, vm_credentials(), |_| {})
            .await
            .expect("connect should reach session-active");
        let mut machine = SessionStateMachine::new(
            session_config_from(&outcome, session_capabilities),
            outcome.activation.leftover,
        );
        let mut stream = outcome.stream;

        let frames_in_sink = Arc::new(AtomicUsize::new(0));
        let frames_in_driver = frames_in_sink.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<InputEvent>>(8);
        tokio::spawn(async move {
            let _ = tx
                .send(vec![InputEvent::Sync {
                    toggle_flags: keyboard_toggle_flags(),
                }])
                .await;
            // Wait until the desktop has painted AND settled.
            let mut last = frames_in_driver.load(Ordering::SeqCst);
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let now = frames_in_driver.load(Ordering::SeqCst);
                if now == last && now > 0 {
                    break;
                }
                last = now;
            }
            // Click the Start button, then type `tsdiscon` into the Start search and run it.
            let (x, y) = (24u16, requested_size.1.saturating_sub(20));
            let _ = tx
                .send(vec![
                    InputEvent::Mouse {
                        flags: justrdp_pdu::input::PTRFLAGS_MOVE,
                        wheel_units: 0,
                        x,
                        y,
                    },
                    InputEvent::Mouse {
                        flags: justrdp_pdu::input::PTRFLAGS_DOWN
                            | justrdp_pdu::input::PTRFLAGS_BUTTON1,
                        wheel_units: 0,
                        x,
                        y,
                    },
                    InputEvent::Mouse {
                        flags: justrdp_pdu::input::PTRFLAGS_BUTTON1,
                        wheel_units: 0,
                        x,
                        y,
                    },
                ])
                .await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            // T S D I S C O N
            for vk in [0x54u16, 0x53, 0x44, 0x49, 0x53, 0x43, 0x4F, 0x4E] {
                let _ = tx.send(tap(vk)).await;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = tx.send(tap(0x0D)).await; // Enter
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let ended = tokio::time::timeout(
            Duration::from_secs(60),
            run_session_with_input(
                &mut stream,
                &mut machine,
                |_| {
                    frames_in_sink.fetch_add(1, Ordering::SeqCst);
                },
                |_| {},
                &mut rx,
            ),
        )
        .await;
        let reason = ended
            .expect("the server should disconnect within 60s of tsdiscon")
            .expect("the disconnect must classify, not fail");

        eprintln!("tsdiscon terminal value: {reason:?} → {:?}", reason.class());
        assert!(
            matches!(reason, justrdp::DisconnectReason::ServerDisconnected(_)),
            "tsdiscon should be a server-attributed disconnect, got {reason:?}"
        );
    }

    /// A controllable TCP forwarding proxy in front of the VM: it accepts one client connection,
    /// pipes bytes both ways to `target`, and tears the whole thing down the instant the returned
    /// kill-switch fires — simulating a pulled cable. TLS is end-to-end (client ↔ VM), so the
    /// byte-level proxy is transparent to the handshake. Returns the local address to dial and
    /// the kill-switch sender.
    async fn kill_switch_proxy(
        target: SocketAddr,
    ) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut server = TcpStream::connect(target).await.unwrap();
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                // Kill-switch: returning drops both sockets, abruptly cutting the transport.
                _ = kill_rx => {}
            }
        });
        (local, kill_tx)
    }

    /// Real-VM acceptance (issue #42 C7): when the transport dies mid-session with no graceful
    /// disconnect PDU, the session ends as the *untyped* [`DisconnectReason::UnexpectedDisconnect`]
    /// — the complement of the attributed tsdiscon/logoff closes. The network loss is staged with
    /// [`kill_switch_proxy`]: once the desktop has settled, the proxy is dropped, severing the
    /// connection the way a pulled cable would.
    #[tokio::test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389 and JUSTRDP_TEST_* env vars"]
    async fn a_severed_transport_yields_unexpected_disconnect() {
        let _vm = VM_SESSION.lock().await;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let vm: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let (proxy_addr, kill) = kill_switch_proxy(vm).await;

        let config = test_config();
        let session_capabilities = config.capabilities.clone();
        let outcome = connect_danger(proxy_addr, config, vm_credentials(), |_| {})
            .await
            .expect("connect should reach session-active through the proxy");
        let mut machine = SessionStateMachine::new(
            session_config_from(&outcome, session_capabilities),
            outcome.activation.leftover,
        );
        let mut stream = outcome.stream;

        let frames = Arc::new(AtomicUsize::new(0));
        let frames_watch = frames.clone();
        tokio::spawn(async move {
            // Wait until the desktop has painted AND settled, then cut the transport.
            let mut last = frames_watch.load(Ordering::SeqCst);
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let now = frames_watch.load(Ordering::SeqCst);
                if now == last && now > 0 {
                    break;
                }
                last = now;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = kill.send(()); // sever the network
        });

        let ended = tokio::time::timeout(
            Duration::from_secs(60),
            run_session(
                &mut stream,
                &mut machine,
                |_| {
                    frames.fetch_add(1, Ordering::SeqCst);
                },
                |_| {},
            ),
        )
        .await;
        let reason = ended
            .expect("the session must end within 60s of the transport being cut")
            .expect("a severed transport is a clean terminal value, not a SessionFailure");

        eprintln!("severed-transport terminal value: {reason:?}");
        assert_eq!(reason, justrdp::DisconnectReason::UnexpectedDisconnect);
    }

    /// Real-VM acceptance test for slice-7: keyboard + mouse input over fast-path. Clicks
    /// the Start button (mouse), types "notepad" into the Start search and Enter to launch
    /// it, then types "aaa" (every keystroke through the VK→set-1 table) and scrolls the
    /// wheel — verifying the server *visibly responds* at each step: graphics traffic spikes
    /// after the input (a settled desktop paints nothing on its own) and the session survives
    /// 30+ mixed events. A PPM dump (Notepad showing "aaa") is written for human confirmation.
    ///
    /// The launch goes through the Start menu rather than Win+R: this VM ignores the Windows
    /// logo key (probed in isolation — every other key class works: plain scancodes, the
    /// extended-flagged Apps/arrow keys, all mouse paths — so the policy sits server-side,
    /// not in the encoding, which the ironrdp byte-differential pins down).
    #[tokio::test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389 and JUSTRDP_TEST_* env vars"]
    async fn keyboard_and_mouse_input_drive_the_real_vm() {
        let _vm = VM_SESSION.lock().await;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let config = legacy_graphics_config();
        let session_capabilities = config.capabilities.clone();
        let outcome = connect_danger(addr, config, vm_credentials(), |_| {})
            .await
            .expect("connect should reach session-active");
        let session_config = session_config_from(&outcome, session_capabilities);
        assert!(
            session_config.server_input_flags
                & (justrdp_pdu::capability::INPUT_FLAG_FASTPATH_INPUT
                    | justrdp_pdu::capability::INPUT_FLAG_FASTPATH_INPUT2)
                != 0,
            "this VM advertises fast-path input; flags={:#06x}",
            session_config.server_input_flags
        );
        let desktop = session_config.desktop_size;
        let mut machine = SessionStateMachine::new(session_config, outcome.activation.leftover);
        let mut stream = outcome.stream;

        let frames = Arc::new(AtomicUsize::new(0));
        let frames_in_sink = frames.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<InputEvent>>(64);

        let frames_in_driver = frames.clone();
        let driver = tokio::spawn(async move {
            let mut sent = 0usize;
            let send = |events: Vec<InputEvent>, sent: &mut usize| {
                *sent += events.len();
                let tx = tx.clone();
                async move { tx.send(events).await.expect("session loop alive") }
            };
            // Wait for the initial desktop paint to settle (no frames for 2 seconds), so
            // every later frame delta is attributable to our input alone.
            let mut last = frames_in_driver.load(Ordering::SeqCst);
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let now = frames_in_driver.load(Ordering::SeqCst);
                if now == last {
                    break;
                }
                last = now;
            }
            // Toggle sync first, as a real client would (criterion: lock-state sync on
            // session start, from the OS's live state).
            send(
                vec![InputEvent::Sync {
                    toggle_flags: keyboard_toggle_flags(),
                }],
                &mut sent,
            )
            .await;
            let idle_frames = frames_in_driver.load(Ordering::SeqCst);

            // Mouse: click the Start button (bottom-left corner).
            let click = |x: u16, y: u16| {
                vec![
                    InputEvent::Mouse {
                        flags: justrdp_pdu::input::PTRFLAGS_MOVE,
                        wheel_units: 0,
                        x,
                        y,
                    },
                    InputEvent::Mouse {
                        flags: justrdp_pdu::input::PTRFLAGS_DOWN
                            | justrdp_pdu::input::PTRFLAGS_BUTTON1,
                        wheel_units: 0,
                        x,
                        y,
                    },
                    InputEvent::Mouse {
                        flags: justrdp_pdu::input::PTRFLAGS_BUTTON1,
                        wheel_units: 0,
                        x,
                        y,
                    },
                ]
            };
            send(click(24, desktop.1.saturating_sub(20)), &mut sent).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            let after_click = frames_in_driver.load(Ordering::SeqCst);

            // Keyboard: type "notepad" into the Start search, Enter to launch it.
            for vk in [0x4Eu16, 0x4F, 0x54, 0x45, 0x50, 0x41, 0x44] {
                send(tap(vk), &mut sent).await; // N O T E P A D
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            send(tap(0x0D), &mut sent).await; // Enter
            tokio::time::sleep(Duration::from_secs(4)).await;
            for _ in 0..3 {
                send(tap(0x41), &mut sent).await; // A → "aaa" in Notepad
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            // Wheel scroll for good measure (vertical wheel, both directions).
            let (cx, cy) = (desktop.0 / 2, desktop.1 / 2);
            send(
                vec![
                    InputEvent::Mouse {
                        flags: justrdp_pdu::input::PTRFLAGS_WHEEL,
                        wheel_units: -120,
                        x: cx,
                        y: cy,
                    },
                    InputEvent::Mouse {
                        flags: justrdp_pdu::input::PTRFLAGS_WHEEL,
                        wheel_units: 120,
                        x: cx,
                        y: cy,
                    },
                ],
                &mut sent,
            )
            .await;
            // Hover moves for the pointer slice (#41): over Notepad's edit area (an I-beam
            // shape) and then over the desktop edge (an arrow) — each move makes the server
            // push the pointer shape for what's under the cursor.
            for (x, y) in [(cx, cy), (4, 4), (cx, cy)] {
                send(
                    vec![InputEvent::Mouse {
                        flags: justrdp_pdu::input::PTRFLAGS_MOVE,
                        wheel_units: 0,
                        x,
                        y,
                    }],
                    &mut sent,
                )
                .await;
                tokio::time::sleep(Duration::from_millis(700)).await;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            let after_typing = frames_in_driver.load(Ordering::SeqCst);
            (sent, idle_frames, after_click, after_typing)
            // tx drops here: the input branch disables, the session stays up.
        });

        // The timeout is the expected exit — a healthy session never ends on its own.
        let mut cursor_events: Vec<justrdp::CursorEvent> = Vec::new();
        let ended = tokio::time::timeout(
            Duration::from_secs(45),
            run_session_with_input(
                &mut stream,
                &mut machine,
                |_| {
                    frames_in_sink.fetch_add(1, Ordering::SeqCst);
                },
                |c| cursor_events.push(c.clone()),
                &mut rx,
            ),
        )
        .await;
        if let Ok(result) = ended {
            result.expect("session failed while input was in flight");
            panic!("server closed the session during the input exchange");
        }
        let (sent, idle_frames, after_click, after_typing) = driver.await.expect("input driver");

        // Pointer verification (#41): the hover moves above make the server push cursor
        // shapes (arrow over the desktop, an I-beam over Notepad's edit area). Every decoded
        // shape must be plausible: spec-capped dimensions, hotspot inside the shape, RGBA
        // sized exactly width × height × 4.
        let mut shapes = 0usize;
        for event in &cursor_events {
            if let justrdp::CursorEvent::Set(image) = event {
                shapes += 1;
                eprintln!(
                    "cursor shape: {}x{} hotspot ({}, {})",
                    image.width, image.height, image.hotspot_x, image.hotspot_y
                );
                assert!(image.width > 0 && image.width <= 96);
                assert!(image.height > 0 && image.height <= 96);
                assert!(image.hotspot_x < image.width && image.hotspot_y < image.height);
                assert_eq!(
                    image.rgba.len(),
                    usize::from(image.width) * usize::from(image.height) * 4
                );
            }
        }
        eprintln!(
            "cursor events: {} total, {shapes} SetCursor",
            cursor_events.len()
        );
        assert!(
            shapes >= 1,
            "expected at least one decoded pointer shape from the VM, got {cursor_events:?}"
        );

        eprintln!(
            "sent {sent} input events; frames: settled={idle_frames} → after click={after_click} \
             → after typing={after_typing}"
        );
        // 10+ mixed events were sent and the session survived them (the timeout fired with
        // no protocol error)…
        assert!(sent >= 10, "expected to send 10+ events, sent {sent}");
        // …the *mouse* visibly responded (the Start menu painted after the click)…
        assert!(
            after_click > idle_frames,
            "no graphics followed the Start-button click ({idle_frames} → {after_click})"
        );
        // …and the *keyboard* visibly responded (search results / Notepad painted), where a
        // settled desktop paints nothing on its own.
        assert!(
            after_typing > after_click,
            "no graphics followed the typing ({after_click} → {after_typing})"
        );

        // Visual confirmation artifact: Notepad with "aaa" typed into it.
        let fb = machine.framebuffer();
        let path = std::env::temp_dir().join("justrdp-slice7-input.ppm");
        let mut ppm = format!("P6\n{} {}\n255\n", fb.width(), fb.height()).into_bytes();
        for px in fb.pixels().chunks_exact(4) {
            ppm.extend_from_slice(&px[..3]);
        }
        std::fs::write(&path, ppm).expect("write the visual dump");
        eprintln!("visual dump for confirmation: {}", path.display());
    }

    /// Real-VM test for the slow-path input fallback: force `server_input_flags` to
    /// scancodes-only so the machine wraps the same events in slow-path Input Event PDUs
    /// (TS_INPUT_PDU_DATA over the share/MCS stack), and verify the live server accepts them —
    /// graphics follow the input and the session survives.
    #[tokio::test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389 and JUSTRDP_TEST_* env vars"]
    async fn slowpath_input_fallback_works_on_the_real_vm() {
        let _vm = VM_SESSION.lock().await;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let config = legacy_graphics_config();
        let session_capabilities = config.capabilities.clone();
        let outcome = connect_danger(addr, config, vm_credentials(), |_| {})
            .await
            .expect("connect should reach session-active");
        let mut session_config = session_config_from(&outcome, session_capabilities);
        // The fallback seam under test: pretend the server never advertised fast-path input.
        session_config.server_input_flags = justrdp_pdu::capability::INPUT_FLAG_SCANCODES;
        let mut machine = SessionStateMachine::new(session_config, outcome.activation.leftover);
        let mut stream = outcome.stream;

        let frames = Arc::new(AtomicUsize::new(0));
        let frames_in_sink = frames.clone();
        let frames_in_driver = frames.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<InputEvent>>(16);
        let driver = tokio::spawn(async move {
            // Same settle-then-measure protocol as the fast-path test.
            let mut last = frames_in_driver.load(Ordering::SeqCst);
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let now = frames_in_driver.load(Ordering::SeqCst);
                if now == last {
                    break;
                }
                last = now;
            }
            tx.send(vec![InputEvent::Sync { toggle_flags: 0 }])
                .await
                .expect("session loop alive");
            let idle_frames = frames_in_driver.load(Ordering::SeqCst);
            // Apps key (context menu) then Escape: a visible open/close round trip carried
            // entirely over slow-path Input Event PDUs.
            let apps = justrdp::input::scancode_from_windows_vk(0x5D).unwrap();
            tx.send(vec![apps.press(), apps.release()])
                .await
                .expect("session loop alive");
            tokio::time::sleep(Duration::from_secs(3)).await;
            tx.send(tap(0x1B)).await.expect("session loop alive"); // Escape closes it
            tokio::time::sleep(Duration::from_secs(2)).await;
            (idle_frames, frames_in_driver.load(Ordering::SeqCst))
        });

        let ended = tokio::time::timeout(
            Duration::from_secs(25),
            run_session_with_input(
                &mut stream,
                &mut machine,
                |_| {
                    frames_in_sink.fetch_add(1, Ordering::SeqCst);
                },
                |_| {},
                &mut rx,
            ),
        )
        .await;
        if let Ok(result) = ended {
            result.expect("session failed while slow-path input was in flight");
            panic!("server closed the session during slow-path input");
        }
        let (idle_frames, after_frames) = driver.await.expect("input driver");
        eprintln!("slow-path: frames before input {idle_frames}, after {after_frames}");
        assert!(
            after_frames > idle_frames,
            "the server did not respond to slow-path input ({idle_frames} → {after_frames})"
        );
    }
}
