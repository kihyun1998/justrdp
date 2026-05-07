#![forbid(unsafe_code)]

//! `AsyncRdpClient` — pure-async façade over [`WebClient`] +
//! [`ActiveSession`] (v2).
//!
//! ## What changed from v1
//!
//! v1 wrapped the synchronous `justrdp_blocking::RdpClient` with a
//! `tokio::task::spawn_blocking` worker. That worked but had two
//! problems:
//!
//! 1. **Disconnect latency**: while the worker was parked inside
//!    `RdpClient::next_event` waiting for a server frame, the
//!    command channel was not polled. A `Disconnect` request
//!    waited until the server's next frame (or TCP keepalive)
//!    woke the worker. v1's docstring documented this as a known
//!    limitation.
//! 2. **Not fan-out friendly**: `spawn_blocking` workers each
//!    occupy one thread on the blocking pool; running 100 sessions
//!    needed careful pool tuning.
//!
//! v2 replaces `spawn_blocking` with `tokio::spawn` over an async
//! [`ActiveSession`]. The pump uses `tokio::select!` to multiplex
//! command receives with event polls, so a `Disconnect` arriving
//! while the pump is awaiting `next_events` cancels that future
//! and runs `session.shutdown()` immediately.
//!
//! The public surface is **byte-for-byte identical to v1** so
//! embedders see no breaking change. The internals (no
//! `spawn_blocking`, no blocking thread per session, real async
//! cancellation) move to the async core that Phase 2 / Phase 3
//! built up.
//!
//! ## Threading model
//!
//! `AsyncRdpClient` is `Send`. The pump task owns the
//! [`ActiveSession`] exclusively; commands flow in via a
//! `mpsc::Sender<Command>` (Send + Sync + Clone) and events flow
//! out via a `mpsc::Receiver<...>` (Send, single-consumer). All
//! `send_*` methods take `&self` so multiple tokio tasks can
//! dispatch input concurrently without external locking — the
//! commands are queued through the same channel and serialised by
//! the pump.
//!
//! [`WebClient`]: justrdp_async::WebClient
//! [`ActiveSession`]: justrdp_async::ActiveSession

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::io;

use justrdp_async::{ActiveSession, DriverError, WebClient};
use justrdp_svc::SvcProcessor;
use justrdp_blocking::{ConnectError, RdpEvent, RuntimeError};
use justrdp_connector::Config;
use justrdp_input::{LockKeys, MouseButton, Scancode};
use justrdp_tls::ServerCertVerifier;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::native_nla::NativeCredsspDriver;
use crate::native_tcp::NativeTcpTransport;
use crate::native_tls::{NativeTlsTransport, NativeTlsUpgrade};
use crate::pump::{self, Command};
use crate::verifier_bridge::build_native_tls_upgrade_with_verifier;

/// Bound on the in-flight command queue. Input rates (~100 Hz tops)
/// are nowhere near this; the bound exists purely to prevent
/// runaway memory if a misbehaving caller spams `send_*` while the
/// pump is wedged on a network read.
const CMD_QUEUE: usize = 64;

/// Bound on the event queue. Sized so a screen-full of fast-path
/// graphics tile updates does not force the pump to block on
/// `send` while the consumer is mid-frame.
const EVT_QUEUE: usize = 256;

/// Async wrapper around an RDP session. See the module-level docs
/// for the threading model and cancel-safety contract. v1 surface
/// preserved byte-for-byte.
pub struct AsyncRdpClient {
    cmd_tx: mpsc::Sender<Command>,
    evt_rx: mpsc::Receiver<Result<RdpEvent, RuntimeError>>,
    /// `Some` until `disconnect()` is called; we then `await` it so
    /// the caller's future does not return until the pump has
    /// emitted any final wire bytes.
    pump: Option<JoinHandle<()>>,
}

impl AsyncRdpClient {
    /// Connect to `server` over TCP+TLS using a no-verify rustls
    /// config — the same default behaviour as
    /// [`RdpClient::connect`](justrdp_blocking::RdpClient::connect)
    /// (server identity is not verified; CredSSP / NLA cross-checks
    /// the leaf SPKI separately, which is the real defence).
    pub async fn connect<A>(
        server: A,
        server_name: impl Into<String>,
        config: Config,
    ) -> Result<Self, ConnectError>
    where
        A: tokio::net::ToSocketAddrs + Send + 'static,
    {
        let server_name = server_name.into();
        let upgrader = NativeTlsUpgrade::dangerous_no_verify(&server_name)
            .map_err(transport_to_connect_error)?;
        connect_inner(server, config, upgrader, Vec::new()).await
    }

    /// Connect using a custom [`ServerCertVerifier`]. Mirrors
    /// [`RdpClient::connect_with_verifier`](justrdp_blocking::RdpClient::connect_with_verifier).
    pub async fn connect_with_verifier<A>(
        server: A,
        server_name: impl Into<String>,
        config: Config,
        verifier: Arc<dyn ServerCertVerifier>,
    ) -> Result<Self, ConnectError>
    where
        A: tokio::net::ToSocketAddrs + Send + 'static,
    {
        let server_name = server_name.into();
        let upgrader = build_native_tls_upgrade_with_verifier(&server_name, verifier)
            .map_err(transport_to_connect_error)?;
        connect_inner(server, config, upgrader, Vec::new()).await
    }

    /// Connect with a no-verify TLS upgrader **and** register
    /// [`SvcProcessor`]s on the resulting active session — RDPSND,
    /// CLIPRDR, RDPDR, EGFX, etc. Same security posture as
    /// [`connect`](Self::connect) (server identity not verified at
    /// the TLS layer; CredSSP / NLA still cross-checks the leaf
    /// SPKI). Mirrors [`RdpClient::connect_with_processors`](justrdp_blocking::RdpClient::connect_with_processors).
    ///
    /// Embedders constructing the per-session processor list inline:
    ///
    /// ```ignore
    /// let processors: Vec<Box<dyn SvcProcessor>> = vec![
    ///     Box::new(RdpsndClient::new(Box::new(audio_backend))),
    ///     Box::new(cliprdr_client),
    /// ];
    /// AsyncRdpClient::connect_with_processors(addr, host, config, processors).await?
    /// ```
    pub async fn connect_with_processors<A>(
        server: A,
        server_name: impl Into<String>,
        config: Config,
        processors: Vec<Box<dyn SvcProcessor>>,
    ) -> Result<Self, ConnectError>
    where
        A: tokio::net::ToSocketAddrs + Send + 'static,
    {
        let server_name = server_name.into();
        let upgrader = NativeTlsUpgrade::dangerous_no_verify(&server_name)
            .map_err(transport_to_connect_error)?;
        connect_inner(server, config, upgrader, processors).await
    }

    /// Combine a custom [`ServerCertVerifier`] *and* SVC processor
    /// registration. The intersection of [`connect_with_verifier`]
    /// and [`connect_with_processors`] — needed by embedders that
    /// pin certificates *and* need clipboard / audio / file
    /// redirect channels.
    ///
    /// [`connect_with_verifier`]: Self::connect_with_verifier
    /// [`connect_with_processors`]: Self::connect_with_processors
    pub async fn connect_with_verifier_and_processors<A>(
        server: A,
        server_name: impl Into<String>,
        config: Config,
        verifier: Arc<dyn ServerCertVerifier>,
        processors: Vec<Box<dyn SvcProcessor>>,
    ) -> Result<Self, ConnectError>
    where
        A: tokio::net::ToSocketAddrs + Send + 'static,
    {
        let server_name = server_name.into();
        let upgrader = build_native_tls_upgrade_with_verifier(&server_name, verifier)
            .map_err(transport_to_connect_error)?;
        connect_inner(server, config, upgrader, processors).await
    }

    /// Receive the next session event, awaiting until one arrives.
    ///
    /// Returns `None` once the pump exits (graceful disconnect,
    /// transport drop, or terminal error already surfaced via a
    /// prior `Some(Err(_))`). Treat `None` as the canonical
    /// end-of-session signal.
    pub async fn next_event(&mut self) -> Option<Result<RdpEvent, RuntimeError>> {
        self.evt_rx.recv().await
    }

    /// Send a raw scancode keyboard event.
    pub async fn send_keyboard(
        &self,
        scancode: Scancode,
        pressed: bool,
    ) -> Result<(), RuntimeError> {
        self.dispatch(|reply| Command::SendKeyboard {
            scancode,
            pressed,
            reply,
        })
        .await
    }

    /// Send a Unicode keyboard event. BMP code points only —
    /// non-BMP returns
    /// `RuntimeError::Unimplemented("non-BMP Unicode (use UTF-16 surrogate pairs)")`.
    pub async fn send_unicode(&self, ch: char, pressed: bool) -> Result<(), RuntimeError> {
        self.dispatch(|reply| Command::SendUnicode { ch, pressed, reply })
            .await
    }

    /// Send an absolute mouse position update.
    pub async fn send_mouse_move(&self, x: u16, y: u16) -> Result<(), RuntimeError> {
        self.dispatch(|reply| Command::SendMouseMove { x, y, reply })
            .await
    }

    /// Send a mouse button press / release at `(x, y)`.
    pub async fn send_mouse_button(
        &self,
        button: MouseButton,
        pressed: bool,
        x: u16,
        y: u16,
    ) -> Result<(), RuntimeError> {
        self.dispatch(|reply| Command::SendMouseButton {
            button,
            pressed,
            x,
            y,
            reply,
        })
        .await
    }

    /// Send a mouse wheel scroll event at `(x, y)`. The position
    /// is updated first, then the wheel scroll is emitted —
    /// matching v1's
    /// [`RdpClient::send_mouse_wheel`](justrdp_blocking::RdpClient::send_mouse_wheel)
    /// semantics where the event carries coordinates.
    pub async fn send_mouse_wheel(
        &self,
        delta: i16,
        horizontal: bool,
        x: u16,
        y: u16,
    ) -> Result<(), RuntimeError> {
        self.dispatch(|reply| Command::SendMouseWheel {
            delta,
            horizontal,
            x,
            y,
            reply,
        })
        .await
    }

    /// Send a Caps/Num/Scroll/Kana lock-state synchronisation.
    pub async fn send_synchronize(&self, lock_keys: LockKeys) -> Result<(), RuntimeError> {
        self.dispatch(|reply| Command::SendSynchronize { lock_keys, reply })
            .await
    }

    /// Gracefully disconnect: send a Disconnect PDU, drain the
    /// pump task, consume `self`.
    ///
    /// **v2 behaviour change**: disconnect now returns within a
    /// scheduling tick of the call regardless of whether the pump
    /// was awaiting `next_events()`. v1 had to wait for the next
    /// server frame or TCP keepalive — the cancel-safe `select!`
    /// pump in v2 cancels the pending `next_events()` future and
    /// runs `shutdown()` immediately.
    pub async fn disconnect(mut self) -> Result<(), RuntimeError> {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(Command::Disconnect { reply: tx })
            .await
            .is_err()
        {
            // Pump already gone (e.g. session ended via server
            // disconnect that the embedder consumed). Nothing to
            // tear down.
            return Ok(());
        }
        let result = match rx.await {
            Ok(r) => r,
            Err(_) => Err(RuntimeError::Disconnected),
        };

        // Wait for the pump task to fully exit so any in-flight
        // syscalls complete before we drop the JoinHandle.
        if let Some(pump) = self.pump.take() {
            let _ = pump.await;
        }

        result
    }

    /// Internal helper: build a command via `make_cmd`, push it to
    /// the pump, await the reply.
    async fn dispatch<F>(&self, make_cmd: F) -> Result<(), RuntimeError>
    where
        F: FnOnce(oneshot::Sender<Result<(), RuntimeError>>) -> Command,
    {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(make_cmd(tx))
            .await
            .map_err(|_| RuntimeError::Disconnected)?;
        rx.await.map_err(|_| RuntimeError::Disconnected)?
    }
}

impl Drop for AsyncRdpClient {
    fn drop(&mut self) {
        // Closing `cmd_tx` is the pump's signal to wind down on
        // its next `cmd_rx.recv()` poll. Embedders who need
        // bounded shutdown should call `disconnect()` explicitly.
    }
}

/// Run the async connect (TCP + outer TLS + CredSSP/NLA + Phase 2
/// handshake), then spawn the long-lived pump task on a tokio
/// (NOT `spawn_blocking`) executor.
async fn connect_inner<A>(
    server: A,
    config: Config,
    upgrader: NativeTlsUpgrade,
    processors: Vec<Box<dyn SvcProcessor>>,
) -> Result<AsyncRdpClient, ConnectError>
where
    A: tokio::net::ToSocketAddrs + Send + 'static,
{
    // 1. Resolve + open TCP.
    let transport = NativeTcpTransport::connect(server)
        .await
        .map_err(transport_to_connect_error)?;

    // 2. Drive the full handshake: outer TLS upgrade + (if the
    //    server requires it) CredSSP / NLA + X.224 / MCS / etc.
    //    `connect_with_nla` will skip the CredSSP step if the
    //    connector doesn't reach it (i.e. server selected plain
    //    RDP security), so always supplying the driver is safe.
    let credssp = NativeCredsspDriver::new();
    let webclient = WebClient::new(transport);
    let (result, post_tls) = webclient
        .connect_with_nla(config, upgrader, credssp)
        .await
        .map_err(driver_to_connect_error)?;

    // 3. Build the active session — `with_processors` accepts an
    //    empty Vec, so the no-processor entry points reuse this
    //    path without a separate ::new branch.
    let session: ActiveSession<NativeTlsTransport> =
        ActiveSession::with_processors(post_tls, &result, processors)
            .await
            .map_err(driver_to_connect_error)?;
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(CMD_QUEUE);
    let (evt_tx, evt_rx) = mpsc::channel::<Result<RdpEvent, RuntimeError>>(EVT_QUEUE);

    let pump = tokio::spawn(pump::pump(session, cmd_rx, evt_tx));

    Ok(AsyncRdpClient {
        cmd_tx,
        evt_rx,
        pump: Some(pump),
    })
}

/// Map a [`DriverError`] surfaced during the connect phase into
/// v1's [`ConnectError`] enum.
fn driver_to_connect_error(err: DriverError) -> ConnectError {
    use justrdp_async::TransportErrorKind;
    use justrdp_tls::TlsError;
    match err {
        DriverError::Transport(e) if e.kind() == TransportErrorKind::ConnectionClosed => {
            ConnectError::UnexpectedEof
        }
        DriverError::Transport(e) => ConnectError::Tcp(io::Error::other(format!("{e}"))),
        DriverError::Connector(e) => ConnectError::Connector(e),
        DriverError::FrameTooLarge { size } => ConnectError::FrameTooLarge(size),
        DriverError::TlsRequired => ConnectError::Unimplemented("TLS upgrade required"),
        DriverError::NlaRequired { state: _ } => ConnectError::Unimplemented("NLA / CredSSP required"),
        DriverError::TlsUpgrade(s) => ConnectError::Tls(TlsError::Handshake(s)),
        DriverError::Credssp(_) => ConnectError::Unimplemented("CredSSP exchange failed"),
        DriverError::Session(e) => ConnectError::Tcp(io::Error::other(format!("session: {e:?}"))),
        DriverError::Internal(s) => ConnectError::Tcp(io::Error::other(format!("internal: {s}"))),
        DriverError::Channel(s) => ConnectError::ChannelSetup(s),
    }
}

/// Map a [`TransportError`](justrdp_async::TransportError) from the
/// TCP-connect step into v1's [`ConnectError::Tcp`]. Mirrors the
/// kind that `RdpClient::connect`'s `?` operator on the underlying
/// `TcpStream::connect` produces.
fn transport_to_connect_error(err: justrdp_async::TransportError) -> ConnectError {
    use justrdp_async::TransportErrorKind;
    let io_kind = match err.kind() {
        TransportErrorKind::ConnectionClosed => io::ErrorKind::ConnectionRefused,
        TransportErrorKind::Io => io::ErrorKind::Other,
        TransportErrorKind::Protocol => io::ErrorKind::InvalidData,
        TransportErrorKind::Other | TransportErrorKind::Cancelled => io::ErrorKind::Other,
    };
    ConnectError::Tcp(io::Error::new(io_kind, format!("{err}")))
}

