//! The RD Gateway transport: TLS to the gateway, the WebSocket upgrade, and the stream that
//! carries the target's bytes inside MS-TSGU data packets (`docs/map/territory/rd-gateway.md`).
//!
//! [`open_gateway`] drives [`justrdp::gateway::GatewayStateMachine`] to an open Gateway Channel
//! and returns a [`GatewayStream`], which [`crate::connect_over_gateway`] runs the connection
//! over.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker, ready};
use std::time::Duration;

use justrdp::gateway::{
    GatewayAction, GatewayChannel, GatewayConfig, GatewayConfigError, GatewayErrorKind,
    GatewayStateMachine, MAX_DATA_LEN, STAGE_CHANNEL_CREATE, STAGE_CHANNEL_OPEN, STAGE_HANDSHAKE,
    STAGE_TUNNEL_AUTH, STAGE_TUNNEL_CREATE,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::trust::client_config;
use crate::websocket::{
    self, Control, FrameDecoder, FrameError, OPCODE_BINARY, OPCODE_CLOSE, OPCODE_PONG, UpgradeError,
};
use crate::{ConnectTimeouts, ServerAddr, TrustPolicy};

/// The stage label of the TCP dial to the gateway.
pub const STAGE_TCP_CONNECT: &str = "gateway-tcp-connect";
/// The stage label of the TLS handshake with the gateway.
pub const STAGE_TLS_HANDSHAKE: &str = "gateway-tls-handshake";
/// The stage label of the WebSocket upgrade.
pub const STAGE_WEBSOCKET_UPGRADE: &str = "gateway-websocket-upgrade";

/// The most reply bytes held unsent before reading from the gateway pauses.
const MAX_PENDING_OUT: usize = 256 * 1024;

/// How many bytes one read from the gateway takes.
const READ_CHUNK: usize = 16 * 1024;

/// The env var naming a file that every MS-TSGU byte the gateway sends is appended to, as
/// `JUSTRDP_CONNECT_CAPTURE_FILE` does for the connect sequence. An empty value counts as unset.
const GATEWAY_CAPTURE_FILE: &str = "JUSTRDP_GATEWAY_CAPTURE_FILE";

/// The WebSocket status code of a normal closure (RFC 6455 section 7.4.1).
const CLOSE_NORMAL: [u8; 2] = 1000u16.to_be_bytes();

/// The adapter-level knobs of [`open_gateway`]. The trust policy is the gateway's own: it is
/// separate from the one the target's certificate is checked with (ADR-0005).
///
/// `Default` validates the gateway's certificate against the OS trust store.
#[derive(Debug, Clone, Default)]
pub struct GatewayOptions {
    /// The TCP dial timeout, and the timeout of each stage after it. The host's answer to a
    /// consent message is under neither.
    pub timeouts: ConnectTimeouts,
    /// How to decide whether the gateway's TLS certificate is trusted.
    pub trust: TrustPolicy,
}

/// Why the tunnel to the target did not open, and the stage it failed in.
#[derive(Debug)]
pub struct GatewayFailure {
    /// The stage label: [`STAGE_TCP_CONNECT`], [`STAGE_TLS_HANDSHAKE`],
    /// [`STAGE_WEBSOCKET_UPGRADE`], or one of [`justrdp::gateway`]'s `STAGE_*` labels.
    pub stage: &'static str,
    /// What went wrong.
    pub kind: GatewayFailureKind,
}

/// What went wrong in a gateway stage.
#[derive(Debug)]
pub enum GatewayFailureKind {
    /// The config cannot be sent; nothing was dialed.
    Config(GatewayConfigError),
    /// A socket-level error, including the gateway ending the connection.
    Io(io::Error),
    /// The stage exceeded its timeout.
    Timeout,
    /// The TLS handshake with the gateway failed, the trust policy's refusal included.
    Tls {
        /// A description of the failure.
        reason: String,
    },
    /// The gateway did not answer the upgrade request with a WebSocket upgrade.
    Upgrade(UpgradeError),
    /// The gateway sent a WebSocket frame RFC 6455 does not admit.
    WebSocket(FrameError),
    /// The MS-TSGU sequence failed.
    Protocol(GatewayErrorKind),
    /// The gateway closed the WebSocket or the Gateway Channel.
    Closed {
        /// The `statusCode` of the gateway's close packet, when it sent one.
        status_code: Option<u32>,
    },
}

impl std::fmt::Display for GatewayFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RD Gateway failed during {}: {}", self.stage, self.kind)
    }
}

impl std::fmt::Display for GatewayFailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayFailureKind::Config(e) => write!(f, "{e}"),
            GatewayFailureKind::Io(e) => write!(f, "i/o error: {e}"),
            GatewayFailureKind::Timeout => f.write_str("timed out"),
            GatewayFailureKind::Tls { reason } => write!(f, "TLS handshake failed: {reason}"),
            GatewayFailureKind::Upgrade(e) => write!(f, "{e}"),
            GatewayFailureKind::WebSocket(e) => write!(f, "{e}"),
            GatewayFailureKind::Protocol(kind) => write!(f, "{kind}"),
            GatewayFailureKind::Closed {
                status_code: Some(code),
            } => write!(f, "the gateway closed the channel with status {code:#010x}"),
            GatewayFailureKind::Closed { status_code: None } => {
                f.write_str("the gateway closed the WebSocket")
            }
        }
    }
}

impl std::error::Error for GatewayFailure {}

/// What a [`GatewayStream`] rides: the TLS stream to the gateway.
trait GatewayIo: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> GatewayIo for T {}

/// How the stream's read side ended.
#[derive(Debug)]
enum Ended {
    /// The gateway closed the channel cleanly, or the connection ended.
    Eof,
    /// The tunnel failed; every later read reports it.
    Error(io::ErrorKind, String),
}

/// The byte stream to the target server through an RD Gateway: what is written goes out in
/// MS-TSGU data packets, and reads yield what the target sent. Flushing sends everything written;
/// shutting down closes the Gateway Channel and the WebSocket.
///
/// The gateway's keep-alive packets and WebSocket pings are answered while the stream is read,
/// so an idle session must keep reading.
pub struct GatewayStream {
    io: Box<dyn GatewayIo>,
    frames: FrameDecoder,
    machine: GatewayStateMachine,
    rng: SystemRandom,
    channel: GatewayChannel,
    /// Bytes the target sent, not yet read; `readable[read_pos..]` is what remains.
    readable: Vec<u8>,
    read_pos: usize,
    /// WebSocket frames not yet written; `out[out_pos..]` is what remains.
    out: Vec<u8>,
    out_pos: usize,
    /// The read buffer, kept between reads.
    chunk: Vec<u8>,
    /// A consent message the gateway sent and the host has not answered.
    consent: Option<String>,
    /// The `statusCode` of the gateway's close packet.
    closed: Option<u32>,
    /// The gateway sent a WebSocket close frame, or the connection ended.
    io_ended: bool,
    ended: Option<Ended>,
    close_sent: bool,
    /// Frames were written to `io` and not yet flushed.
    unflushed: bool,
    /// A writer waiting for `out` to drain.
    write_waker: Option<Waker>,
    /// A reader waiting for `out` to drain below the limit.
    read_waker: Option<Waker>,
}

impl std::fmt::Debug for GatewayStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayStream")
            .field("channel", &self.channel)
            .field("machine", &self.machine)
            .finish_non_exhaustive()
    }
}

impl GatewayStream {
    /// What the gateway granted with the Gateway Channel: the tunnel and channel ids, the
    /// negotiated capabilities, the redirection flags of its policy, and the idle timeout.
    pub fn channel(&self) -> &GatewayChannel {
        &self.channel
    }

    /// The `statusCode` of the packet the gateway closed the Gateway Channel with, an HRESULT,
    /// once it has. A read reports a non-zero one as an error; this is the code itself.
    pub fn close_status(&self) -> Option<u32> {
        self.closed
    }

    fn pending_out(&self) -> usize {
        self.out.len() - self.out_pos
    }

    /// Whether frames wait to be written or flushed.
    fn has_unsent(&self) -> bool {
        self.pending_out() > 0 || self.unflushed
    }

    /// Whether the gateway closed the Gateway Channel, the WebSocket or the connection.
    fn gateway_ended(&self) -> bool {
        self.closed.is_some() || self.io_ended
    }

    /// Queue one masked frame.
    fn queue_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), GatewayFailureKind> {
        let mut mask = [0u8; 4];
        self.rng.fill(&mut mask).map_err(|_| {
            GatewayFailureKind::Io(io::Error::other("OS RNG failed generating a frame mask"))
        })?;
        websocket::encode_frame(opcode, payload, mask, &mut self.out);
        Ok(())
    }

    /// Act on bytes read from the gateway: frames to packets, packets to the machine.
    fn ingest(&mut self, bytes: &[u8]) -> Result<(), GatewayFailureKind> {
        let mut data = Vec::new();
        let mut control = Vec::new();
        let fed = self.frames.feed(bytes, &mut data, &mut control);
        crate::append_capture(GATEWAY_CAPTURE_FILE, &data);
        for control in control {
            match control {
                Control::Ping(payload) => self.queue_frame(OPCODE_PONG, &payload)?,
                Control::Close => {
                    self.io_ended = true;
                    if !self.close_sent {
                        self.close_sent = true;
                        self.queue_frame(OPCODE_CLOSE, &CLOSE_NORMAL)?;
                    }
                }
            }
        }
        let actions = self.machine.receive(&data);
        self.act(actions)?;
        fed.map_err(GatewayFailureKind::WebSocket)
    }

    /// Carry out what the machine asked for.
    fn act(&mut self, actions: Vec<GatewayAction>) -> Result<(), GatewayFailureKind> {
        for action in actions {
            match action {
                GatewayAction::WriteBytes(packets) => self.queue_frame(OPCODE_BINARY, &packets)?,
                GatewayAction::ConsentRequested { message } => self.consent = Some(message),
                GatewayAction::Data(bytes) => self.readable.extend_from_slice(&bytes),
                GatewayAction::ChannelOpen(channel) => self.channel = channel,
                GatewayAction::Closed { status_code } => self.closed = Some(status_code),
                GatewayAction::FailWith(error) => {
                    return Err(GatewayFailureKind::Protocol(error.kind));
                }
            }
        }
        Ok(())
    }

    /// Write queued frames until none remain, and flush them.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
            self.unflushed = true;
        }
        self.out.clear();
        self.out_pos = 0;
        if self.unflushed {
            ready!(Pin::new(&mut self.io).poll_flush(cx))?;
            self.unflushed = false;
        }
        for waker in [self.write_waker.take(), self.read_waker.take()]
            .into_iter()
            .flatten()
        {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }

    /// Read once from the gateway and act on what arrived.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), GatewayFailureKind>> {
        let mut chunk = std::mem::take(&mut self.chunk);
        chunk.resize(READ_CHUNK, 0);
        let mut buf = ReadBuf::new(&mut chunk);
        let read = Pin::new(&mut self.io).poll_read(cx, &mut buf);
        let filled = buf.filled().len();
        let result = match read {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(GatewayFailureKind::Io(e))),
            Poll::Ready(Ok(())) if filled == 0 => {
                self.io_ended = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(())) => Poll::Ready(self.ingest(&chunk[..filled])),
        };
        self.chunk = chunk;
        result
    }

    /// Drive the sequence until it leaves `stage`, or until a consent message awaits the host
    /// with every request written and the gateway still there.
    fn poll_leave_stage(
        &mut self,
        cx: &mut Context<'_>,
        stage: &'static str,
    ) -> Poll<Result<(), GatewayFailureKind>> {
        loop {
            ready!(self.poll_drain(cx)).map_err(GatewayFailureKind::Io)?;
            if self.machine.stage() != stage {
                return Poll::Ready(Ok(()));
            }
            if self.gateway_ended() {
                return Poll::Ready(Err(match self.closed {
                    None if !self.close_sent => GatewayFailureKind::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the gateway ended the connection",
                    )),
                    status_code => GatewayFailureKind::Closed { status_code },
                }));
            }
            if self.consent.is_some() {
                return Poll::Ready(Ok(()));
            }
            ready!(self.poll_fill(cx))?;
        }
    }

    /// Record how the read side ended, once it has.
    fn note_end(&mut self) {
        if self.ended.is_some() {
            return;
        }
        self.ended = match self.closed {
            Some(0) => Some(Ended::Eof),
            Some(code) => Some(Ended::Error(
                io::ErrorKind::ConnectionAborted,
                format!("the RD Gateway closed the channel with status {code:#010x}"),
            )),
            None if self.io_ended => Some(Ended::Eof),
            None => None,
        };
    }

    fn fail(&mut self, kind: GatewayFailureKind) {
        self.ended = Some(match kind {
            GatewayFailureKind::Io(e) => Ended::Error(e.kind(), e.to_string()),
            other => Ended::Error(
                io::ErrorKind::InvalidData,
                format!("RD Gateway tunnel failed: {other}"),
            ),
        });
    }
}

impl AsyncRead for GatewayStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Replies go out as the stream is read, ahead of the bytes read.
            let mut replies_over_limit = false;
            if this.has_unsent() {
                match this.poll_drain(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => {
                        this.out.clear();
                        this.out_pos = 0;
                        this.unflushed = false;
                        if this.ended.is_none() {
                            this.fail(GatewayFailureKind::Io(e));
                        }
                    }
                    Poll::Pending => replies_over_limit = this.pending_out() > MAX_PENDING_OUT,
                }
            }
            if this.read_pos < this.readable.len() {
                let n = buf.remaining().min(this.readable.len() - this.read_pos);
                buf.put_slice(&this.readable[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
                if this.read_pos == this.readable.len() {
                    this.readable.clear();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match &this.ended {
                Some(Ended::Eof) => return Poll::Ready(Ok(())),
                Some(Ended::Error(kind, message)) => {
                    return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
                }
                None => {}
            }
            // Past the limit, reading waits for the replies to drain.
            if replies_over_limit {
                this.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if let Err(kind) = ready!(this.poll_fill(cx)) {
                this.fail(kind);
            }
            this.note_end();
        }
    }
}

impl AsyncWrite for GatewayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.ended.is_some() || this.close_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the RD Gateway channel is closed",
            )));
        }
        if this.poll_drain(cx)?.is_pending() {
            this.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_DATA_LEN);
        let packet = this
            .machine
            .send(&buf[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))?;
        this.queue_frame(OPCODE_BINARY, &packet)
            .map_err(|kind| io::Error::other(kind.to_string()))?;
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.poll_drain(cx)?.is_pending() {
            this.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.close_sent {
            this.close_sent = true;
            let queued = (|| {
                for action in this.machine.close() {
                    if let GatewayAction::WriteBytes(packet) = action {
                        this.queue_frame(OPCODE_BINARY, &packet)?;
                    }
                }
                this.queue_frame(OPCODE_CLOSE, &CLOSE_NORMAL)
            })();
            queued.map_err(|kind| io::Error::other(kind.to_string()))?;
        }
        if this.poll_drain(cx)?.is_pending() {
            this.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

/// Open a tunnel to `config`'s target through the RD Gateway at `gateway`, authenticating with
/// the config's PAA cookie: TCP, TLS under `options.trust`, the WebSocket upgrade, then the
/// MS-TSGU handshake, tunnel create, tunnel authorize and channel create.
///
/// `on_stage` is called with each stage label as it is entered, ending with
/// [`justrdp::gateway::STAGE_CHANNEL_OPEN`]. A failure carries the stage it happened in. The
/// cookie is written to the gateway and to nothing else.
///
/// `on_consent` is called with the consent message of the gateway's tunnel response, when it
/// carries one: the text its administrator set, which may be empty. It is what the gateway sent,
/// unchecked, so it may hold control characters. Returning `true` accepts it
/// and the sequence carries on. Returning `false` declines it: the connection to the gateway is
/// closed and the failure is [`justrdp::gateway::GatewayErrorKind::ConsentDeclined`] in
/// [`justrdp::gateway::STAGE_TUNNEL_CREATE`]. No timeout bounds the answer, and nothing is read
/// from or written to the gateway while it is awaited.
///
/// Run the connection over the returned stream with [`crate::connect_over_gateway`].
pub async fn open_gateway(
    gateway: impl Into<ServerAddr>,
    config: GatewayConfig,
    mut on_stage: impl FnMut(&str),
    on_consent: impl AsyncFnMut(&str) -> bool,
    options: GatewayOptions,
) -> Result<GatewayStream, GatewayFailure> {
    let gateway = gateway.into();
    let timeouts = options.timeouts;
    let machine = GatewayStateMachine::new(config).map_err(|e| GatewayFailure {
        stage: STAGE_TCP_CONNECT,
        kind: GatewayFailureKind::Config(e),
    })?;

    on_stage(STAGE_TCP_CONNECT);
    tracing::debug!(host = %gateway.host, port = gateway.port, "dialing the RD Gateway");
    let tcp = in_stage(STAGE_TCP_CONNECT, timeouts.tcp_connect, async {
        let tcp = TcpStream::connect((gateway.host.as_str(), gateway.port)).await?;
        tcp.set_nodelay(true)?;
        Ok(tcp)
    })
    .await?;

    on_stage(STAGE_TLS_HANDSHAKE);
    let tls_failure = |reason: String| GatewayFailure {
        stage: STAGE_TLS_HANDSHAKE,
        kind: GatewayFailureKind::Tls { reason },
    };
    let tls_config = client_config(&options.trust, &gateway.host)
        .map_err(|e| tls_failure(format!("building the TLS trust configuration: {e}")))?;
    let server_name = ServerName::try_from(gateway.host.clone())
        .map_err(|e| tls_failure(format!("invalid gateway name {:?}: {e}", gateway.host)))?;
    let connector = TlsConnector::from(Arc::new(tls_config));
    let tls = match tokio::time::timeout(timeouts.stage, connector.connect(server_name, tcp)).await
    {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => return Err(tls_failure(e.to_string())),
        Err(_) => {
            return Err(GatewayFailure {
                stage: STAGE_TLS_HANDSHAKE,
                kind: GatewayFailureKind::Timeout,
            });
        }
    };

    open_over(
        tls,
        &host_header(&gateway),
        machine,
        on_stage,
        on_consent,
        timeouts.stage,
    )
    .await
}

/// The `Host` header's value for `gateway`: an IPv6 literal in brackets, and the port unless it
/// is 443 (RFC 9110 section 7.2).
fn host_header(gateway: &ServerAddr) -> String {
    let host = if gateway.host.contains(':') {
        format!("[{}]", gateway.host)
    } else {
        gateway.host.clone()
    };
    if gateway.port == 443 {
        host
    } else {
        format!("{host}:{}", gateway.port)
    }
}

/// The stages of the MS-TSGU sequence, in the order they are entered.
const SEQUENCE: [&str; 5] = [
    STAGE_HANDSHAKE,
    STAGE_TUNNEL_CREATE,
    STAGE_TUNNEL_AUTH,
    STAGE_CHANNEL_CREATE,
    STAGE_CHANNEL_OPEN,
];

/// Announce every stage after `SEQUENCE[*announced]` up to `stage`.
fn announce_up_to(stage: &str, announced: &mut usize, on_stage: &mut impl FnMut(&str)) {
    let reached = SEQUENCE
        .iter()
        .position(|s| *s == stage)
        .unwrap_or(*announced);
    while *announced < reached {
        *announced += 1;
        on_stage(SEQUENCE[*announced]);
    }
}

/// Await `fut` under `stage`'s timeout, naming the stage in the failure.
async fn in_stage<T>(
    stage: &'static str,
    timeout: Duration,
    fut: impl Future<Output = io::Result<T>>,
) -> Result<T, GatewayFailure> {
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(GatewayFailure {
            stage,
            kind: GatewayFailureKind::Io(e),
        }),
        Err(_) => Err(GatewayFailure {
            stage,
            kind: GatewayFailureKind::Timeout,
        }),
    }
}

/// `bytes` as a GUID in its text form, without braces.
fn guid_text(bytes: [u8; 16]) -> String {
    let hex = |range: std::ops::Range<usize>| {
        bytes[range].iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(0..4),
        hex(4..6),
        hex(6..8),
        hex(8..10),
        hex(10..16)
    )
}

/// The WebSocket upgrade and the MS-TSGU sequence over `io`, which already reaches the gateway.
/// `host_header` is the `Host` header's value; `stage_timeout` bounds each stage on its own, and
/// not the host's answer to a consent message.
async fn open_over<S>(
    mut io: S,
    host_header: &str,
    mut machine: GatewayStateMachine,
    mut on_stage: impl FnMut(&str),
    mut on_consent: impl AsyncFnMut(&str) -> bool,
    stage_timeout: Duration,
) -> Result<GatewayStream, GatewayFailure>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    on_stage(STAGE_WEBSOCKET_UPGRADE);
    let upgrade_failure = |kind| GatewayFailure {
        stage: STAGE_WEBSOCKET_UPGRADE,
        kind,
    };
    let rng = SystemRandom::new();
    let mut nonce = [0u8; 16];
    let mut connection_id = [0u8; 16];
    rng.fill(&mut nonce)
        .and_then(|()| rng.fill(&mut connection_id))
        .map_err(|_| {
            upgrade_failure(GatewayFailureKind::Io(io::Error::other(
                "OS RNG failed generating the WebSocket key",
            )))
        })?;
    let key = websocket::base64(&nonce);
    let request = websocket::upgrade_request(host_header, &key, &guid_text(connection_id));
    let expected_accept = websocket::accept_for(&key);

    let mut response = Vec::new();
    let header_len = in_stage(STAGE_WEBSOCKET_UPGRADE, stage_timeout, async {
        io.write_all(&request).await?;
        io.flush().await?;
        loop {
            match websocket::parse_upgrade_response(&response, &expected_accept) {
                Ok(Some(header_len)) => return Ok(Ok(header_len)),
                Ok(None) => {}
                Err(e) => return Ok(Err(e)),
            }
            let mut chunk = [0u8; 1024];
            let n = io.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the gateway ended the connection",
                ));
            }
            response.extend_from_slice(&chunk[..n]);
        }
    })
    .await?
    .map_err(|e| upgrade_failure(GatewayFailureKind::Upgrade(e)))?;
    tracing::debug!("the RD Gateway upgraded the connection to WebSocket");

    let start = machine.start();
    let mut stream = GatewayStream {
        io: Box::new(io),
        frames: FrameDecoder::new(),
        machine,
        rng,
        channel: GatewayChannel::default(),
        readable: Vec::new(),
        read_pos: 0,
        out: Vec::new(),
        out_pos: 0,
        chunk: Vec::new(),
        consent: None,
        closed: None,
        io_ended: false,
        ended: None,
        close_sent: false,
        unflushed: false,
        write_waker: None,
        read_waker: None,
    };
    on_stage(SEQUENCE[0]);
    let mut announced = 0;
    for action in start {
        if let GatewayAction::WriteBytes(packet) = action {
            stream
                .queue_frame(OPCODE_BINARY, &packet)
                .map_err(|kind| GatewayFailure {
                    stage: SEQUENCE[0],
                    kind,
                })?;
        }
    }
    // One read can carry several responses, so the stage a step ends in is asked of the
    // machine afterwards, and the stages it passed through are announced before the outcome.
    let mut step = stream.ingest(&response[header_len..]);
    loop {
        let stage = stream.machine.stage();
        announce_up_to(stage, &mut announced, &mut on_stage);
        if let Err(kind) = step {
            return Err(GatewayFailure { stage, kind });
        }
        if stream.machine.is_open() {
            break;
        }
        let left = poll_fn(|cx| stream.poll_leave_stage(cx, stage));
        step = match tokio::time::timeout(stage_timeout, left).await {
            Ok(step) => step,
            Err(_) => Err(GatewayFailureKind::Timeout),
        };
        if step.is_err() || stream.gateway_ended() {
            continue;
        }
        if let Some(message) = stream.consent.take() {
            tracing::debug!(len = message.len(), "the RD Gateway sent a consent message");
            let answer = if on_consent(&message).await {
                stream.machine.accept_consent()
            } else {
                stream.machine.decline_consent()
            };
            step = stream.act(answer);
            if step.is_err() {
                // The WebSocket close frame, then the connection's shutdown.
                let _ = tokio::time::timeout(stage_timeout, stream.shutdown()).await;
            }
        }
    }
    tracing::debug!(channel = ?stream.channel, "the RD Gateway channel is open");
    Ok(stream)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use justrdp::gateway::{
        PaaCookie, STAGE_CHANNEL_CREATE, STAGE_CHANNEL_OPEN, STAGE_HANDSHAKE, STAGE_TUNNEL_AUTH,
        STAGE_TUNNEL_CREATE,
    };
    use justrdp_pdu::tsgu::{
        self, ChannelResponse, HandshakeResponse, Packet, TunnelAuthResponse, TunnelResponse,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Wake;
    use tokio::io::{BufWriter, DuplexStream};
    use tracing_test::traced_test;

    /// The gateway's side of a connection, for a test to script.
    pub(crate) struct StandIn<S> {
        pub(crate) io: S,
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> StandIn<S> {
        pub(crate) fn new(io: S) -> Self {
            Self { io }
        }

        /// Read the HTTP request up to the end of its header.
        pub(crate) async fn read_request(&mut self) -> String {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(self.io.read_u8().await.unwrap());
            }
            String::from_utf8(request).unwrap()
        }

        /// Read the upgrade request and accept it. Returns the request.
        pub(crate) async fn upgrade(&mut self) -> String {
            let request = self.read_request().await;
            let key = request
                .lines()
                .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
                .expect("the request carries a key");
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\r\n",
                websocket::accept_for(key)
            );
            self.io.write_all(response.as_bytes()).await.unwrap();
            request
        }

        /// Read one client frame: its opcode and unmasked payload. `None` at the end of the
        /// stream. A client frame is final and masked.
        pub(crate) async fn try_read_frame(&mut self) -> Option<(u8, Vec<u8>)> {
            let first = within(self.io.read_u8()).await.ok()?;
            let second = self.io.read_u8().await.unwrap();
            assert_eq!(
                first & 0xF0,
                0x80,
                "a client frame is final, reserved bits clear"
            );
            assert_eq!(second & 0x80, 0x80, "a client frame is masked");
            let len = match second & 0x7F {
                126 => u64::from(self.io.read_u16().await.unwrap()),
                127 => self.io.read_u64().await.unwrap(),
                len => u64::from(len),
            };
            let mut mask = [0u8; 4];
            self.io.read_exact(&mut mask).await.unwrap();
            let mut payload = vec![0u8; len as usize];
            self.io.read_exact(&mut payload).await.unwrap();
            for (byte, key) in payload.iter_mut().zip(mask.iter().cycle()) {
                *byte ^= key;
            }
            Some((first & 0x0F, payload))
        }

        pub(crate) async fn read_frame(&mut self) -> (u8, Vec<u8>) {
            self.try_read_frame().await.expect("a client frame")
        }

        /// Read one binary frame: the MS-TSGU packets in it.
        pub(crate) async fn read_packets(&mut self) -> Vec<u8> {
            let (opcode, payload) = self.read_frame().await;
            assert_eq!(opcode, OPCODE_BINARY);
            payload
        }

        /// Write one unmasked frame with this first byte (FIN and opcode).
        pub(crate) async fn write_frame(&mut self, first: u8, payload: &[u8]) {
            let mut frame = vec![first];
            match payload.len() {
                len @ 0..=125 => frame.push(len as u8),
                len @ 126..=0xFFFF => {
                    frame.push(126);
                    frame.extend((len as u16).to_be_bytes());
                }
                len => {
                    frame.push(127);
                    frame.extend((len as u64).to_be_bytes());
                }
            }
            frame.extend_from_slice(payload);
            self.io.write_all(&frame).await.unwrap();
        }

        /// Send MS-TSGU packets in one binary frame.
        pub(crate) async fn send(&mut self, packets: &[u8]) {
            self.write_frame(0x82, packets).await;
        }

        /// Answer the four requests of the sequence. Returns them in order. The upgrade has
        /// already happened.
        pub(crate) async fn open_channel(&mut self) -> [Vec<u8>; 4] {
            let handshake = self.read_packets().await;
            self.send(&handshake_response(0)).await;
            let tunnel_create = self.read_packets().await;
            self.send(&tunnel_response()).await;
            let tunnel_auth = self.read_packets().await;
            self.send(&tunnel_auth_response()).await;
            let channel_create = self.read_packets().await;
            self.send(&channel_response()).await;
            [handshake, tunnel_create, tunnel_auth, channel_create]
        }
    }

    pub(crate) fn handshake_response(error_code: u32) -> Vec<u8> {
        Packet::HandshakeResponse(HandshakeResponse {
            error_code,
            ver_major: 1,
            ver_minor: 0,
            server_version: 0,
            extended_auth: tsgu::HTTP_EXTENDED_AUTH_PAA,
        })
        .encode()
        .unwrap()
    }

    fn tunnel_response() -> Vec<u8> {
        Packet::TunnelResponse(TunnelResponse {
            server_version: 0,
            status_code: 0,
            tunnel_id: Some(7),
            caps_flags: Some(tsgu::HTTP_CAPABILITY_IDLE_TIMEOUT),
            soh_request: None,
            consent_msg: None,
        })
        .encode()
        .unwrap()
    }

    /// A tunnel response that carries `text` as its consent message.
    fn tunnel_response_with_consent(text: &str) -> Vec<u8> {
        Packet::TunnelResponse(TunnelResponse {
            server_version: 0,
            status_code: 0,
            tunnel_id: Some(7),
            caps_flags: Some(tsgu::HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN),
            soh_request: None,
            consent_msg: Some(tsgu::UnicodeString::from_str_nul(text)),
        })
        .encode()
        .unwrap()
    }

    /// The host's answer for a test whose gateway sends no consent message.
    async fn never_asked(_: &str) -> bool {
        panic!("the gateway sent no consent message");
    }

    fn tunnel_auth_response() -> Vec<u8> {
        Packet::TunnelAuthResponse(TunnelAuthResponse {
            error_code: 0,
            redir_flags: Some(tsgu::HTTP_TUNNEL_REDIR_DISABLE_DRIVE),
            idle_timeout: Some(30),
            soh_response: None,
        })
        .encode()
        .unwrap()
    }

    fn channel_response() -> Vec<u8> {
        Packet::ChannelResponse(ChannelResponse {
            error_code: 0,
            channel_id: Some(9),
            udp_port: None,
            authn_cookie: None,
        })
        .encode()
        .unwrap()
    }

    fn data_packet(data: &[u8]) -> Vec<u8> {
        Packet::Data(data).encode().unwrap()
    }

    fn machine(cookie: &str) -> GatewayStateMachine {
        GatewayStateMachine::new(GatewayConfig {
            paa_cookie: PaaCookie::from_token(cookie),
            target_host: "srv".to_string(),
            target_port: 3389,
            client_name: "pc".to_string(),
        })
        .unwrap()
    }

    const TIMEOUT: Duration = Duration::from_secs(5);

    /// Await `fut`, failing the test when it takes longer than any step here does.
    pub(crate) async fn within<T>(fut: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(20), fut)
            .await
            .expect("the step finishes")
    }

    /// A client and the stand-in gateway it talks to, on an in-memory pipe. The client's end
    /// holds what is written until it is flushed, as a TLS stream can.
    fn pipe() -> (BufWriter<DuplexStream>, StandIn<DuplexStream>) {
        let (client, gateway) = tokio::io::duplex(64 * 1024);
        (BufWriter::new(client), StandIn::new(gateway))
    }

    /// Open a tunnel against a stand-in gateway that grants everything. Returns both ends.
    async fn opened() -> (GatewayStream, StandIn<DuplexStream>) {
        let (client, mut gateway) = pipe();
        let serve = tokio::spawn(async move {
            gateway.upgrade().await;
            gateway.open_channel().await;
            gateway
        });
        let stream = open_over(
            client,
            "gw.example",
            machine("tok"),
            |_| {},
            never_asked,
            TIMEOUT,
        )
        .await
        .unwrap();
        (stream, serve.await.unwrap())
    }

    /// The handshake request with the `extendedAuth` mstsc sends for PAA (#613).
    const HANDSHAKE_REQUEST: [u8; 14] = [
        0x01, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, // header, packetLength 14
        0x01, 0x00, 0x00, 0x00, // version 1.0, clientVersion 0
        0x02, 0x00, // ExtendedAuth HTTP_EXTENDED_AUTH_PAA
    ];

    /// The tunnel create for the cookie "tok": what mstsc sends (#613) except `capsFlags`, which
    /// is `HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN` where mstsc sends 0x3f. `fieldsPresent` 0x1,
    /// the cookie as UTF-16LE with a NUL.
    const TUNNEL_CREATE: [u8; 26] = [
        0x04, 0x00, 0x00, 0x00, 0x1A, 0x00, 0x00, 0x00, // header, packetLength 26
        0x04, 0x00, 0x00, 0x00, // capsFlags HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN
        0x01, 0x00, 0x00, 0x00, // fieldsPresent PAA_COOKIE, reserved
        0x08, 0x00, b't', 0x00, b'o', 0x00, b'k', 0x00, 0x00, 0x00, // "tok\0"
    ];

    /// MS-TSGU 2.2.10.14 for the client name "pc".
    const TUNNEL_AUTH: [u8; 18] = [
        0x06, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, // header, packetLength 18
        0x00, 0x00, // fieldsPresent
        0x06, 0x00, b'p', 0x00, b'c', 0x00, 0x00, 0x00, // "pc\0"
    ];

    /// MS-TSGU 2.2.10.2 for the target "srv" on port 3389.
    const CHANNEL_CREATE: [u8; 24] = [
        0x08, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, // header, packetLength 24
        0x01, 0x00, // one resource, no alternates
        0x3D, 0x0D, 0x03, 0x00, // port 3389, protocol 3
        0x08, 0x00, b's', 0x00, b'r', 0x00, b'v', 0x00, 0x00, 0x00, // "srv\0"
    ];

    #[tokio::test]
    async fn the_tunnel_opens_with_the_observed_requests_and_carries_data_both_ways() {
        let (client, mut gateway) = pipe();
        let serve = tokio::spawn(async move {
            let request = gateway.upgrade().await;
            let requests = gateway.open_channel().await;
            (request, requests, gateway)
        });

        let mut stages = Vec::new();
        let mut stream = open_over(
            client,
            "gw.example",
            machine("tok"),
            |stage| stages.push(stage.to_string()),
            never_asked,
            TIMEOUT,
        )
        .await
        .unwrap();
        let (request, requests, mut gateway) = serve.await.unwrap();

        assert!(
            request.starts_with("RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n"),
            "{request}"
        );
        for header in [
            "Host: gw.example\r\n",
            "Accept: */*\r\n",
            "Cache-Control: no-cache\r\n",
            "Pragma: no-cache\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "RDG-Auth-Scheme: PAA\r\n",
        ] {
            assert!(
                request.contains(header),
                "{header:?} missing from {request}"
            );
        }
        assert!(!request.to_ascii_lowercase().contains("authorization"));

        assert_eq!(requests[0], HANDSHAKE_REQUEST);
        assert_eq!(requests[1], TUNNEL_CREATE);
        assert_eq!(requests[2], TUNNEL_AUTH);
        assert_eq!(requests[3], CHANNEL_CREATE);

        assert_eq!(
            stages,
            [
                STAGE_WEBSOCKET_UPGRADE,
                STAGE_HANDSHAKE,
                STAGE_TUNNEL_CREATE,
                STAGE_TUNNEL_AUTH,
                STAGE_CHANNEL_CREATE,
                STAGE_CHANNEL_OPEN,
            ]
        );
        assert_eq!(
            stream.channel(),
            &GatewayChannel {
                tunnel_id: Some(7),
                channel_id: Some(9),
                negotiated_caps: Some(tsgu::HTTP_CAPABILITY_IDLE_TIMEOUT),
                redir_flags: Some(tsgu::HTTP_TUNNEL_REDIR_DISABLE_DRIVE),
                idle_timeout_minutes: Some(30),
            }
        );

        // To the target: one data packet in one binary frame.
        stream.write_all(b"to-target").await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(gateway.read_packets().await, data_packet(b"to-target"));

        // From the target: a packet split across two frames, a fragmented message, and two
        // packets in one frame. The frames are a byte stream, split by packetLength.
        let first = data_packet(b"from-");
        gateway.send(&first[..5]).await;
        gateway.send(&first[5..]).await;
        let second = data_packet(b"the-");
        gateway.write_frame(0x02, &second[..3]).await;
        gateway.write_frame(0x80, &second[3..]).await;
        let mut both = data_packet(b"tar");
        both.extend(data_packet(b"get"));
        gateway.send(&both).await;
        let mut received = [0u8; 15];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"from-the-target");
    }

    /// Frames that arrive in the same read as the 101 response belong to the WebSocket stream.
    #[tokio::test]
    async fn a_packet_in_the_same_read_as_the_101_response_is_acted_on() {
        let (client, mut gateway) = pipe();
        let serve = tokio::spawn(async move {
            let request = gateway.read_request().await;
            let key = request
                .lines()
                .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
                .unwrap();
            let mut bytes = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\r\n",
                websocket::accept_for(key)
            )
            .into_bytes();
            let response = handshake_response(0);
            bytes.extend([0x82, response.len() as u8]);
            bytes.extend(response);
            gateway.io.write_all(&bytes).await.unwrap();

            assert_eq!(gateway.read_packets().await, HANDSHAKE_REQUEST);
            gateway.read_packets().await;
            gateway.send(&tunnel_response()).await;
            gateway.read_packets().await;
            gateway.send(&tunnel_auth_response()).await;
            gateway.read_packets().await;
            gateway.send(&channel_response()).await;
            gateway
        });
        open_over(
            client,
            "gw.example",
            machine("tok"),
            |_| {},
            never_asked,
            TIMEOUT,
        )
        .await
        .unwrap();
        serve.await.unwrap();
    }

    #[tokio::test]
    async fn a_write_longer_than_one_data_packet_goes_out_in_several() {
        let (mut stream, mut gateway) = opened().await;
        let big: Vec<u8> = (0..MAX_DATA_LEN + 10).map(|i| i as u8).collect();
        let writer = tokio::spawn(async move {
            stream.write_all(&big).await.unwrap();
            stream.flush().await.unwrap();
            (stream, big)
        });
        let first = gateway.read_packets().await;
        let second = gateway.read_packets().await;
        let (_stream, big) = writer.await.unwrap();
        assert_eq!(first, data_packet(&big[..MAX_DATA_LEN]));
        assert_eq!(second, data_packet(&big[MAX_DATA_LEN..]));
    }

    /// The gateway's ping and keep-alive are answered while the stream is read.
    #[tokio::test]
    async fn a_ping_and_a_keep_alive_are_answered_while_reading() {
        let (mut stream, mut gateway) = opened().await;
        let keep_alive = Packet::KeepAlive.encode().unwrap();
        gateway.write_frame(0x89, b"p1").await;
        gateway.send(&keep_alive).await;
        gateway.send(&data_packet(b"x")).await;

        assert_eq!(within(stream.read_u8()).await.unwrap(), b'x');
        assert_eq!(gateway.read_frame().await, (OPCODE_PONG, b"p1".to_vec()));
        assert_eq!(gateway.read_packets().await, keep_alive);
    }

    /// MS-TSGU 3.7.5.4, server-initiated: the close is answered, a failure status is an error
    /// on the read side, and nothing more can be written.
    #[tokio::test]
    async fn a_close_with_a_failure_status_is_answered_and_fails_the_stream() {
        let (mut stream, mut gateway) = opened().await;
        let mut bytes = data_packet(b"last");
        bytes.extend(
            Packet::CloseChannel {
                status_code: 0x8007_59F8,
            }
            .encode()
            .unwrap(),
        );
        gateway.send(&bytes).await;

        let mut last = [0u8; 4];
        stream.read_exact(&mut last).await.unwrap();
        assert_eq!(
            &last, b"last",
            "what arrived before the close is still read"
        );
        let error = stream.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            error.to_string(),
            "the RD Gateway closed the channel with status 0x800759f8"
        );
        assert_eq!(
            stream.write(b"x").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        // The failure is sticky.
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(stream.close_status(), Some(0x8007_59F8));
        // The response went out with the read that saw the close, with no flush from the host.
        assert_eq!(
            gateway.read_packets().await,
            Packet::CloseChannelResponse { status_code: 0 }
                .encode()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_close_with_status_zero_ends_the_stream() {
        let (mut stream, mut gateway) = opened().await;
        gateway
            .send(&Packet::CloseChannel { status_code: 0 }.encode().unwrap())
            .await;
        let mut rest = Vec::new();
        assert_eq!(stream.read_to_end(&mut rest).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_websocket_close_frame_is_echoed_and_ends_the_stream() {
        let (mut stream, mut gateway) = opened().await;
        gateway.write_frame(0x88, &[0x03, 0xE9]).await;
        let mut rest = Vec::new();
        assert_eq!(stream.read_to_end(&mut rest).await.unwrap(), 0);
        assert_eq!(stream.close_status(), None);
        assert_eq!(gateway.read_frame().await, (OPCODE_CLOSE, vec![0x03, 0xE8]));
        // The Gateway Channel itself was never closed; the WebSocket under it was.
        assert_eq!(
            stream.write(b"x").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[tokio::test]
    async fn the_connection_ending_ends_the_stream() {
        let (mut stream, gateway) = opened().await;
        drop(gateway);
        let mut rest = Vec::new();
        assert_eq!(stream.read_to_end(&mut rest).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_frame_the_gateway_may_not_send_fails_the_stream() {
        let (mut stream, mut gateway) = opened().await;
        gateway
            .io
            .write_all(&[0x82, 0x81, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let error = within(stream.read_u8()).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "RD Gateway tunnel failed: the server sent a masked WebSocket frame"
        );
    }

    /// MS-TSGU 3.7.5.4, client-initiated: the close packet, then the WebSocket close frame.
    #[tokio::test]
    async fn shutting_down_closes_the_channel_and_then_the_websocket() {
        let (mut stream, mut gateway) = opened().await;
        stream.shutdown().await.unwrap();
        assert_eq!(
            gateway.read_packets().await,
            Packet::CloseChannel { status_code: 0 }.encode().unwrap()
        );
        assert_eq!(gateway.read_frame().await, (OPCODE_CLOSE, vec![0x03, 0xE8]));
        assert_eq!(gateway.try_read_frame().await, None, "the pipe is shut");
        assert_eq!(
            stream.write(b"x").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    /// 1 MiB of pings, which the client answers with as many bytes of pongs and more.
    const PINGS: usize = 1024 * 1024 / 127;

    type GatewayReads =
        StandIn<tokio::io::Join<tokio::io::ReadHalf<DuplexStream>, tokio::io::Sink>>;

    /// An open tunnel whose gateway sends [`PINGS`] pings and then the data "done", reading
    /// nothing, and a client that has read until its unsent replies held it back.
    async fn flooded() -> (
        GatewayStream,
        GatewayReads,
        tokio::task::JoinHandle<tokio::io::WriteHalf<DuplexStream>>,
    ) {
        let (client, gateway) = tokio::io::duplex(1024);
        let mut gateway = StandIn::new(gateway);
        let serve = tokio::spawn(async move {
            gateway.upgrade().await;
            gateway.open_channel().await;
            gateway
        });
        let mut stream = open_over(
            client,
            "gw.example",
            machine("tok"),
            |_| {},
            never_asked,
            TIMEOUT,
        )
        .await
        .unwrap();
        let (gateway_reads, mut gateway_writes) = tokio::io::split(serve.await.unwrap().io);

        let flood = tokio::spawn(async move {
            let mut ping = vec![0x89, 125];
            ping.extend([0xAA; 125]);
            for _ in 0..PINGS {
                gateway_writes.write_all(&ping).await.unwrap();
            }
            let done = data_packet(b"done");
            let mut frame = vec![0x82, done.len() as u8];
            frame.extend(done);
            gateway_writes.write_all(&frame).await.unwrap();
            gateway_writes
        });

        let mut byte = [0u8; 1];
        let stalled =
            tokio::time::timeout(Duration::from_millis(300), stream.read(&mut byte)).await;
        assert!(stalled.is_err(), "nothing but pings has arrived");
        let gateway = StandIn::new(tokio::io::join(gateway_reads, tokio::io::sink()));
        (stream, gateway, flood)
    }

    /// A gateway that pings without reading does not make the client hold its replies without
    /// bound: past the limit the client stops reading until the replies drain.
    #[tokio::test]
    async fn replies_the_gateway_does_not_read_stop_the_reading() {
        let (mut stream, mut gateway, flood) = flooded().await;
        assert!(stream.pending_out() > 0);
        assert!(
            stream.pending_out() <= MAX_PENDING_OUT + 2 * READ_CHUNK,
            "{} reply bytes held",
            stream.pending_out()
        );
        assert!(!flood.is_finished(), "the gateway's writes are held back");

        // Once the gateway reads, everything flows again.
        let reader = tokio::spawn(async move {
            let mut done = [0u8; 4];
            stream.read_exact(&mut done).await.unwrap();
            stream.flush().await.unwrap();
            (done, stream)
        });
        for _ in 0..PINGS {
            assert_eq!(gateway.read_frame().await.0, OPCODE_PONG);
        }
        let (done, _stream) = reader.await.unwrap();
        assert_eq!(&done, b"done");
        flood.await.unwrap();
    }

    /// A waker that records being woken.
    #[derive(Default)]
    struct Woken(AtomicBool);

    impl Wake for Woken {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// The two directions may run on different tasks. A reader held back by unsent replies and
    /// a writer waiting for the same replies both wait on the pipe's one write registration,
    /// which the later of them takes; the drain wakes both.
    #[tokio::test]
    async fn a_held_back_reader_is_woken_when_another_task_drains_the_replies() {
        let (mut stream, mut gateway, _flood) = flooded().await;

        let reader = Arc::new(Woken::default());
        let reader_waker = Waker::from(reader.clone());
        let mut byte = [0u8; 1];
        let mut buf = ReadBuf::new(&mut byte);
        let read =
            Pin::new(&mut stream).poll_read(&mut Context::from_waker(&reader_waker), &mut buf);
        assert!(read.is_pending(), "the reader is held back");

        let writer = Arc::new(Woken::default());
        let writer_waker = Waker::from(writer.clone());
        let mut writer_cx = Context::from_waker(&writer_waker);
        assert!(
            Pin::new(&mut stream)
                .poll_write(&mut writer_cx, b"x")
                .is_pending()
        );
        reader.0.store(false, Ordering::SeqCst);

        // The gateway reads; the writer, which holds the registration, drains what it frees.
        loop {
            gateway.read_frame().await;
            if Pin::new(&mut stream)
                .poll_write(&mut writer_cx, b"x")
                .is_ready()
            {
                break;
            }
        }
        assert!(
            reader.0.load(Ordering::SeqCst),
            "the reader is woken once the replies have drained"
        );
    }

    /// `[MS-TSGU]` responses that arrive in one read are each acted on: every stage they pass
    /// through is announced, in order.
    #[tokio::test]
    async fn responses_that_arrive_together_announce_every_stage() {
        let (client, mut gateway) = pipe();
        let serve = tokio::spawn(async move {
            gateway.upgrade().await;
            let mut all = handshake_response(0);
            all.extend(tunnel_response());
            all.extend(tunnel_auth_response());
            all.extend(channel_response());
            gateway.send(&all).await;
            gateway
        });
        let mut stages = Vec::new();
        open_over(
            client,
            "gw.example",
            machine("tok"),
            |stage| stages.push(stage.to_string()),
            never_asked,
            TIMEOUT,
        )
        .await
        .unwrap();
        serve.await.unwrap();
        assert_eq!(
            stages,
            [
                STAGE_WEBSOCKET_UPGRADE,
                STAGE_HANDSHAKE,
                STAGE_TUNNEL_CREATE,
                STAGE_TUNNEL_AUTH,
                STAGE_CHANNEL_CREATE,
                STAGE_CHANNEL_OPEN,
            ]
        );
    }

    /// MS-TSGU 3.7.5.2 step 5: the consent message goes to the host, once, and nothing is sent
    /// until the host answers, however long that takes.
    #[tokio::test(start_paused = true)]
    async fn a_consent_message_waits_for_the_host_and_an_accepted_one_opens_the_tunnel() {
        let (client, mut gateway) = pipe();
        let (answer_tx, answer_rx) = tokio::sync::oneshot::channel::<bool>();
        let serve = tokio::spawn(async move {
            gateway.upgrade().await;
            gateway.read_packets().await;
            gateway.send(&handshake_response(0)).await;
            gateway.read_packets().await;
            gateway.send(&tunnel_response_with_consent("Agree?")).await;
            // Three times what a stage may take.
            let early = tokio::time::timeout(Duration::from_secs(3), gateway.io.read_u8()).await;
            assert!(
                early.is_err(),
                "a request went out before the host answered"
            );
            answer_tx.send(true).unwrap();
            let tunnel_auth = gateway.read_packets().await;
            gateway.send(&tunnel_auth_response()).await;
            let channel_create = gateway.read_packets().await;
            gateway.send(&channel_response()).await;
            (tunnel_auth, channel_create)
        });

        let mut stages = Vec::new();
        let mut asked = Vec::new();
        let mut answer_rx = Some(answer_rx);
        let stream = open_over(
            client,
            "gw.example",
            machine("tok"),
            |stage| stages.push(stage.to_string()),
            async |message: &str| {
                asked.push(message.to_string());
                answer_rx.take().expect("asked once").await.unwrap()
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let (tunnel_auth, channel_create) = serve.await.unwrap();

        assert_eq!(asked, ["Agree?"]);
        assert_eq!(tunnel_auth, TUNNEL_AUTH);
        assert_eq!(channel_create, CHANNEL_CREATE);
        assert_eq!(
            stages,
            [
                STAGE_WEBSOCKET_UPGRADE,
                STAGE_HANDSHAKE,
                STAGE_TUNNEL_CREATE,
                STAGE_TUNNEL_AUTH,
                STAGE_CHANNEL_CREATE,
                STAGE_CHANNEL_OPEN,
            ]
        );
        assert_eq!(
            stream.channel().negotiated_caps,
            Some(tsgu::HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN)
        );
    }

    /// MS-TSGU 3.7.5.4: no channel exists yet, so a declined tunnel ends with the connection's
    /// close and no tunnel authorization.
    #[tokio::test]
    async fn a_declined_consent_message_closes_the_connection_and_fails_the_tunnel_create() {
        let (client, mut gateway) = pipe();
        let serve = tokio::spawn(async move {
            gateway.upgrade().await;
            gateway.read_packets().await;
            gateway.send(&handshake_response(0)).await;
            gateway.read_packets().await;
            gateway.send(&tunnel_response_with_consent("Agree?")).await;
            let first = gateway.try_read_frame().await;
            let second = gateway.try_read_frame().await;
            (first, second)
        });

        let mut stages = Vec::new();
        let mut asked = 0;
        let failure = open_over(
            client,
            "gw.example",
            machine("tok"),
            |stage| stages.push(stage.to_string()),
            async |_: &str| {
                asked += 1;
                false
            },
            TIMEOUT,
        )
        .await
        .unwrap_err();
        let (first, second) = serve.await.unwrap();

        assert_eq!(asked, 1);
        assert_eq!(first, Some((OPCODE_CLOSE, CLOSE_NORMAL.to_vec())));
        assert_eq!(second, None, "nothing follows the close frame");
        assert_eq!(failure.stage, STAGE_TUNNEL_CREATE);
        assert!(
            matches!(
                failure.kind,
                GatewayFailureKind::Protocol(GatewayErrorKind::ConsentDeclined)
            ),
            "{failure:?}"
        );
        assert_eq!(
            failure.to_string(),
            "RD Gateway failed during gateway-tunnel-create: the gateway's consent message was \
             declined"
        );
        assert_eq!(
            stages,
            [
                STAGE_WEBSOCKET_UPGRADE,
                STAGE_HANDSHAKE,
                STAGE_TUNNEL_CREATE
            ]
        );
    }

    /// A consent message that arrives in the same read as the response before it is still the
    /// host's to answer, and the responses after its answer open the tunnel.
    #[tokio::test]
    async fn a_consent_message_in_the_same_read_as_the_handshake_response_is_asked() {
        let (client, mut gateway) = pipe();
        let serve = tokio::spawn(async move {
            gateway.upgrade().await;
            let mut both = handshake_response(0);
            both.extend(tunnel_response_with_consent("Agree?"));
            gateway.send(&both).await;
            gateway.read_packets().await;
            gateway.read_packets().await;
            let tunnel_auth = gateway.read_packets().await;
            gateway.send(&tunnel_auth_response()).await;
            gateway.read_packets().await;
            gateway.send(&channel_response()).await;
            (tunnel_auth, gateway)
        });
        let mut asked = Vec::new();
        open_over(
            client,
            "gw.example",
            machine("tok"),
            |_| {},
            async |message: &str| {
                asked.push(message.to_string());
                true
            },
            TIMEOUT,
        )
        .await
        .unwrap();
        assert_eq!(serve.await.unwrap().0, TUNNEL_AUTH);
        assert_eq!(asked, ["Agree?"]);
    }

    /// The requests the consent message answers are with the gateway before the host is asked,
    /// so nothing of them goes out after a decline.
    #[tokio::test(start_paused = true)]
    async fn the_requests_are_sent_before_the_host_is_asked() {
        let (client, mut gateway) = pipe();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<()>();
        let serve = tokio::spawn(async move {
            let request = gateway.read_request().await;
            let key = request
                .lines()
                .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
                .unwrap();
            // The 101 response and both responses in one write, before any request is read.
            let mut bytes = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                websocket::accept_for(key)
            )
            .into_bytes();
            let mut both = handshake_response(0);
            both.extend(tunnel_response_with_consent("Agree?"));
            bytes.extend([0x82, both.len() as u8]);
            bytes.extend(both);
            gateway.io.write_all(&bytes).await.unwrap();
            let handshake = gateway.read_packets().await;
            let tunnel_create = gateway.read_packets().await;
            seen_tx.send(()).unwrap();
            let after = gateway.try_read_frame().await;
            (handshake, tunnel_create, after)
        });
        let mut seen_rx = Some(seen_rx);
        let failure = open_over(
            client,
            "gw.example",
            machine("tok"),
            |_| {},
            async |_: &str| {
                let seen = seen_rx.take().expect("asked once");
                tokio::time::timeout(Duration::from_secs(5), seen)
                    .await
                    .expect("both requests reach the gateway before the host is asked")
                    .unwrap();
                false
            },
            TIMEOUT,
        )
        .await
        .unwrap_err();
        let (handshake, tunnel_create, after) = serve.await.unwrap();
        assert_eq!(handshake, HANDSHAKE_REQUEST);
        assert_eq!(tunnel_create, TUNNEL_CREATE);
        assert_eq!(after, Some((OPCODE_CLOSE, CLOSE_NORMAL.to_vec())));
        assert!(matches!(
            failure.kind,
            GatewayFailureKind::Protocol(GatewayErrorKind::ConsentDeclined)
        ));
    }

    /// One binary frame holding `packets`, then a WebSocket close frame, in one write.
    async fn send_then_close(gateway: &mut StandIn<DuplexStream>, packets: &[u8]) {
        let mut bytes = vec![0x82, packets.len() as u8];
        bytes.extend_from_slice(packets);
        bytes.extend([0x88, 0x00]);
        gateway.io.write_all(&bytes).await.unwrap();
    }

    /// A gateway that closes in the read that carried its consent message has no tunnel to
    /// consent to: the host is not asked.
    #[tokio::test]
    async fn a_gateway_that_closes_with_its_consent_message_does_not_ask_the_host() {
        let failure = failure_against(
            |mut gateway| async move {
                gateway.upgrade().await;
                gateway.read_packets().await;
                gateway.send(&handshake_response(0)).await;
                gateway.read_packets().await;
                send_then_close(&mut gateway, &tunnel_response_with_consent("Agree?")).await;
                std::future::pending::<()>().await;
            },
            TIMEOUT,
        )
        .await;
        assert_eq!(failure.stage, STAGE_TUNNEL_CREATE);
        assert!(
            matches!(
                failure.kind,
                GatewayFailureKind::Closed { status_code: None }
            ),
            "{failure:?}"
        );
    }

    /// The same when the handshake response shares that read, so the stage changed in it.
    #[tokio::test]
    async fn a_gateway_that_closes_in_the_read_that_changed_the_stage_does_not_ask_the_host() {
        let failure = failure_against(
            |mut gateway| async move {
                gateway.upgrade().await;
                gateway.read_packets().await;
                let mut both = handshake_response(0);
                both.extend(tunnel_response_with_consent("Agree?"));
                send_then_close(&mut gateway, &both).await;
                std::future::pending::<()>().await;
            },
            TIMEOUT,
        )
        .await;
        assert_eq!(failure.stage, STAGE_TUNNEL_CREATE);
        assert!(
            matches!(
                failure.kind,
                GatewayFailureKind::Closed { status_code: None }
            ),
            "{failure:?}"
        );
    }

    /// A packet the stage does not admit, in the read that carried the consent message, fails
    /// the tunnel create before the host is asked.
    #[tokio::test]
    async fn a_packet_out_of_order_after_the_consent_message_does_not_ask_the_host() {
        let failure = failure_against(
            |mut gateway| async move {
                gateway.upgrade().await;
                gateway.read_packets().await;
                gateway.send(&handshake_response(0)).await;
                gateway.read_packets().await;
                let mut both = tunnel_response_with_consent("Agree?");
                both.extend(channel_response());
                gateway.send(&both).await;
                std::future::pending::<()>().await;
            },
            TIMEOUT,
        )
        .await;
        assert_eq!(failure.stage, STAGE_TUNNEL_CREATE);
        assert!(
            matches!(
                failure.kind,
                GatewayFailureKind::Protocol(GatewayErrorKind::UnexpectedPacket { .. })
            ),
            "{failure:?}"
        );
    }

    /// A refusal names the stage it belongs to, not the stage the read began in.
    #[tokio::test]
    async fn a_refusal_in_the_same_read_as_the_response_before_it_names_its_own_stage() {
        let (client, mut gateway) = pipe();
        let server = tokio::spawn(async move {
            gateway.upgrade().await;
            let mut both = handshake_response(0);
            both.extend(
                Packet::TunnelResponse(TunnelResponse {
                    server_version: 0,
                    status_code: 0x8007_59E9,
                    tunnel_id: None,
                    caps_flags: None,
                    soh_request: None,
                    consent_msg: None,
                })
                .encode()
                .unwrap(),
            );
            gateway.send(&both).await;
            std::future::pending::<()>().await;
        });
        let mut stages = Vec::new();
        let failure = open_over(
            client,
            "gw.example",
            machine("tok"),
            |stage| stages.push(stage.to_string()),
            never_asked,
            TIMEOUT,
        )
        .await
        .unwrap_err();
        server.abort();
        assert_eq!(failure.stage, STAGE_TUNNEL_CREATE);
        assert!(matches!(
            failure.kind,
            GatewayFailureKind::Protocol(GatewayErrorKind::Refused { code: 0x8007_59E9 })
        ));
        assert_eq!(
            stages,
            [
                STAGE_WEBSOCKET_UPGRADE,
                STAGE_HANDSHAKE,
                STAGE_TUNNEL_CREATE
            ]
        );
    }

    /// A failure's text is the core's, for every kind of protocol failure.
    #[tokio::test]
    async fn a_response_out_of_order_is_reported_in_words() {
        let failure = failure_against(
            |mut gateway| async move {
                gateway.upgrade().await;
                gateway.send(&tunnel_response()).await;
                std::future::pending::<()>().await;
            },
            TIMEOUT,
        )
        .await;
        assert_eq!(
            failure.to_string(),
            "RD Gateway failed during gateway-handshake: unexpected packet type 0x5"
        );
    }

    #[test]
    fn the_host_header_brackets_an_ipv6_literal_and_omits_port_443() {
        let header = |host: &str, port| host_header(&ServerAddr::new(host, port));
        assert_eq!(header("gw.example", 443), "gw.example");
        assert_eq!(header("gw.example", 8443), "gw.example:8443");
        assert_eq!(header("192.0.2.7", 8443), "192.0.2.7:8443");
        assert_eq!(header("::1", 443), "[::1]");
        assert_eq!(header("2001:db8::7", 8443), "[2001:db8::7]:8443");
    }

    /// Run `open_over` against `serve` and return the failure it must end in.
    async fn failure_against<F, Fut>(serve: F, stage_timeout: Duration) -> GatewayFailure
    where
        F: FnOnce(StandIn<DuplexStream>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (client, gateway) = pipe();
        let server = tokio::spawn(serve(gateway));
        let failure = open_over(
            client,
            "gw.example",
            machine("tok"),
            |_| {},
            never_asked,
            stage_timeout,
        )
        .await
        .expect_err("the tunnel must not open");
        server.abort();
        assert!(
            failure
                .to_string()
                .starts_with(&format!("RD Gateway failed during {}: ", failure.stage)),
            "{failure}"
        );
        failure
    }

    #[tokio::test]
    async fn a_refused_upgrade_fails_the_upgrade_stage_with_the_status() {
        let failure = failure_against(
            |mut gateway| async move {
                gateway.read_request().await;
                gateway
                    .io
                    .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
                std::future::pending::<()>().await;
            },
            TIMEOUT,
        )
        .await;
        assert_eq!(failure.stage, STAGE_WEBSOCKET_UPGRADE);
        assert!(matches!(
            failure.kind,
            GatewayFailureKind::Upgrade(UpgradeError::Status(401))
        ));
        assert_eq!(
            failure.to_string(),
            "RD Gateway failed during gateway-websocket-upgrade: the server answered HTTP 401"
        );
    }

    #[tokio::test]
    async fn an_accept_that_does_not_match_the_key_fails_the_upgrade_stage() {
        let failure = failure_against(
            |mut gateway| async move {
                gateway.read_request().await;
                gateway
                    .io
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                          Connection: Upgrade\r\n\
                          Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                    )
                    .await
                    .unwrap();
                std::future::pending::<()>().await;
            },
            TIMEOUT,
        )
        .await;
        assert_eq!(failure.stage, STAGE_WEBSOCKET_UPGRADE);
        assert!(matches!(
            failure.kind,
            GatewayFailureKind::Upgrade(UpgradeError::NotWebSocket(_))
        ));
    }

    #[tokio::test]
    async fn a_gateway_that_hangs_up_on_the_request_fails_the_upgrade_stage() {
        let failure = failure_against(
            |mut gateway| async move {
                gateway.read_request().await;
            },
            TIMEOUT,
        )
        .await;
        assert_eq!(failure.stage, STAGE_WEBSOCKET_UPGRADE);
        assert!(
            matches!(&failure.kind, GatewayFailureKind::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof),
            "{failure:?}"
        );
    }

    #[tokio::test]
    async fn a_refused_handshake_fails_the_handshake_stage_with_the_code() {
        let failure = failure_against(
            |mut gateway| async move {
                gateway.upgrade().await;
                gateway.read_packets().await;
                gateway.send(&handshake_response(0x8007_59D8)).await;
                std::future::pending::<()>().await;
            },
            TIMEOUT,
        )
        .await;
        assert_eq!(failure.stage, STAGE_HANDSHAKE);
        assert!(matches!(
            failure.kind,
            GatewayFailureKind::Protocol(GatewayErrorKind::Refused { code: 0x8007_59D8 })
        ));
        assert_eq!(
            failure.to_string(),
            "RD Gateway failed during gateway-handshake: the gateway refused with code 0x800759d8"
        );
    }

    #[tokio::test]
    async fn a_gateway_that_hangs_up_on_the_tunnel_create_fails_that_stage() {
        let failure = failure_against(
            |mut gateway| async move {
                gateway.upgrade().await;
                gateway.read_packets().await;
                gateway.send(&handshake_response(0)).await;
                gateway.read_packets().await;
            },
            TIMEOUT,
        )
        .await;
        assert_eq!(failure.stage, STAGE_TUNNEL_CREATE);
        assert!(
            matches!(&failure.kind, GatewayFailureKind::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof),
            "{failure:?}"
        );
    }

    #[tokio::test]
    async fn a_websocket_close_during_the_tunnel_authorization_fails_that_stage() {
        let failure = failure_against(
            |mut gateway| async move {
                gateway.upgrade().await;
                gateway.read_packets().await;
                gateway.send(&handshake_response(0)).await;
                gateway.read_packets().await;
                gateway.send(&tunnel_response()).await;
                gateway.read_packets().await;
                gateway.write_frame(0x88, &[]).await;
                std::future::pending::<()>().await;
            },
            TIMEOUT,
        )
        .await;
        assert_eq!(failure.stage, STAGE_TUNNEL_AUTH);
        assert!(matches!(
            failure.kind,
            GatewayFailureKind::Closed { status_code: None }
        ));
    }

    #[tokio::test]
    async fn a_bad_frame_during_the_channel_create_fails_that_stage() {
        let failure = failure_against(
            |mut gateway| async move {
                gateway.upgrade().await;
                gateway.read_packets().await;
                gateway.send(&handshake_response(0)).await;
                gateway.read_packets().await;
                gateway.send(&tunnel_response()).await;
                gateway.read_packets().await;
                gateway.send(&tunnel_auth_response()).await;
                gateway.read_packets().await;
                gateway.io.write_all(&[0x92, 0x00]).await.unwrap();
                std::future::pending::<()>().await;
            },
            TIMEOUT,
        )
        .await;
        assert_eq!(failure.stage, STAGE_CHANNEL_CREATE);
        assert!(matches!(
            failure.kind,
            GatewayFailureKind::WebSocket(FrameError::ReservedBits)
        ));
    }

    /// Each stage is bounded on its own: a gateway that answers every stage but one, and that
    /// one later than the timeout, fails in that stage.
    #[tokio::test(start_paused = true)]
    async fn a_stage_that_stalls_times_out_with_its_name() {
        let started = tokio::time::Instant::now();
        let failure = failure_against(
            |mut gateway| async move {
                // Each answer takes most of a stage's time; three of them exceed it together.
                tokio::time::sleep(Duration::from_millis(800)).await;
                gateway.upgrade().await;
                gateway.read_packets().await;
                tokio::time::sleep(Duration::from_millis(800)).await;
                gateway.send(&handshake_response(0)).await;
                gateway.read_packets().await;
                tokio::time::sleep(Duration::from_millis(800)).await;
                gateway.send(&tunnel_response()).await;
                gateway.read_packets().await;
                std::future::pending::<()>().await;
            },
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(failure.stage, STAGE_TUNNEL_AUTH);
        assert!(matches!(failure.kind, GatewayFailureKind::Timeout));
        assert_eq!(
            failure.to_string(),
            "RD Gateway failed during gateway-tunnel-auth: timed out"
        );
        // Three answers of 800 ms, then the one-second timeout of the stage that stalled.
        let elapsed = started.elapsed();
        assert!(
            (Duration::from_millis(3400)..Duration::from_millis(3500)).contains(&elapsed),
            "{elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_upgrade_that_stalls_times_out_in_the_upgrade_stage() {
        let failure = failure_against(
            |mut gateway| async move {
                gateway.read_request().await;
                std::future::pending::<()>().await;
            },
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(failure.stage, STAGE_WEBSOCKET_UPGRADE);
        assert!(matches!(failure.kind, GatewayFailureKind::Timeout));
    }

    /// Every form the cookie could take in a log line or an error: its text, and its UTF-16LE
    /// bytes as `Debug` prints a byte slice and as hex.
    pub(crate) fn cookie_forms(cookie: &str) -> Vec<String> {
        let utf16: Vec<u8> = cookie.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let decimal = format!("{:?}", &utf16[..8]);
        let hex = |separator: &str| {
            utf16[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(separator)
        };
        vec![
            cookie.to_string(),
            decimal.trim_matches(['[', ']']).to_string(),
            hex(""),
            hex(" "),
            hex(", "),
        ]
    }

    #[tokio::test]
    #[traced_test]
    async fn the_cookie_is_in_no_log_and_no_error() {
        const COOKIE: &str = "paa-cookie-613-secret";

        // A tunnel that opens, carries data and closes.
        let (client, mut gateway) = pipe();
        let serve = tokio::spawn(async move {
            gateway.upgrade().await;
            let requests = gateway.open_channel().await;
            (requests, gateway)
        });
        let mut stream = open_over(
            client,
            "gw.example",
            machine(COOKIE),
            |_| {},
            never_asked,
            TIMEOUT,
        )
        .await
        .unwrap();
        let (requests, mut gateway) = serve.await.unwrap();
        let cookie_utf16: Vec<u8> = COOKIE.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(
            requests[1]
                .windows(cookie_utf16.len())
                .any(|w| w == cookie_utf16),
            "the cookie did go to the gateway"
        );
        stream.write_all(b"data").await.unwrap();
        gateway.send(&data_packet(b"data")).await;
        stream.read_u8().await.unwrap();
        let debugged = format!("{stream:?}");
        stream.shutdown().await.unwrap();

        // A tunnel the gateway refuses after it received the cookie.
        let failure = failure_against(
            |mut gateway| async move {
                gateway.upgrade().await;
                gateway.read_packets().await;
                gateway.send(&handshake_response(0)).await;
                gateway.read_packets().await;
                let refused = Packet::TunnelResponse(TunnelResponse {
                    server_version: 0,
                    status_code: 0x8007_59E9,
                    tunnel_id: None,
                    caps_flags: None,
                    soh_request: None,
                    consent_msg: None,
                });
                gateway.send(&refused.encode().unwrap()).await;
                std::future::pending::<()>().await;
            },
            TIMEOUT,
        )
        .await;
        assert_eq!(failure.stage, STAGE_TUNNEL_CREATE);

        assert!(
            logs_contain("gateway-tunnel-create") && logs_contain("channel is open"),
            "the tunnel's logs must be captured"
        );
        let errors = format!("{failure} {failure:?} {debugged}");
        for form in cookie_forms(COOKIE) {
            assert!(
                !logs_contain(&form),
                "the logs carry the cookie as {form:?}"
            );
            assert!(!errors.contains(&form), "{errors}");
        }
    }
}
