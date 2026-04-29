#![forbid(unsafe_code)]

//! `AsyncRdpClient` — async façade over `RdpClient`.

use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use justrdp_blocking::{ConnectError, RdpClient, RdpEvent, RuntimeError};
use justrdp_connector::Config;
use justrdp_input::{LockKeys, MouseButton, Scancode};
use justrdp_tls::ServerCertVerifier;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::pump::{self, Command};

/// Bound on the in-flight command queue. Input rates (~100 Hz tops) are
/// nowhere near this, so the bound exists purely to prevent runaway
/// memory use if a misbehaving caller spams `send_*` while the worker
/// is wedged on a network read.
const CMD_QUEUE: usize = 64;

/// Bound on the event queue. Sized so a single screen-full of fast-path
/// graphics tile updates does not force the worker to block on
/// `blocking_send` while the consumer is mid-frame.
const EVT_QUEUE: usize = 256;

/// Async wrapper around [`RdpClient`].
///
/// See the crate-level docs for the threading model and cancel-safety
/// contract. All `send_*` methods take `&self`; the underlying mpsc
/// sender is `Send + Sync + Clone`, so multiple tokio tasks can dispatch
/// input concurrently without external locking.
pub struct AsyncRdpClient {
    cmd_tx: mpsc::Sender<Command>,
    evt_rx: mpsc::Receiver<Result<RdpEvent, RuntimeError>>,
    /// Held so callers can `await` the worker on graceful disconnect.
    /// `None` after `disconnect()` consumes `self`.
    pump: Option<JoinHandle<()>>,
}

impl AsyncRdpClient {
    /// Connect to `server` over TCP+TLS using the rustls `AcceptAll`
    /// verifier — the same default behaviour as
    /// [`RdpClient::connect`](justrdp_blocking::RdpClient::connect).
    ///
    /// `server_name` is the SNI hostname used during the TLS upgrade;
    /// it is taken by value because it must outlive the spawn_blocking
    /// closure.
    pub async fn connect<A>(
        server: A,
        server_name: impl Into<String>,
        config: Config,
    ) -> Result<Self, ConnectError>
    where
        A: ToSocketAddrs + Send + 'static,
    {
        let server_name = server_name.into();
        spawn_session(move || RdpClient::connect(server, &server_name, config)).await
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
        A: ToSocketAddrs + Send + 'static,
    {
        let server_name = server_name.into();
        spawn_session(move || {
            RdpClient::connect_with_verifier(server, &server_name, config, verifier)
        })
        .await
    }

    /// Receive the next session event, awaiting until one arrives.
    ///
    /// Returns `None` when the worker has exited (graceful disconnect,
    /// transport drop, or terminal error already surfaced via a prior
    /// `Some(Err(_))`). Treat `None` as the canonical end-of-session
    /// signal.
    pub async fn next_event(&mut self) -> Option<Result<RdpEvent, RuntimeError>> {
        self.evt_rx.recv().await
    }

    /// Send a raw scancode keyboard event.
    pub async fn send_keyboard(
        &self,
        scancode: Scancode,
        pressed: bool,
    ) -> Result<(), RuntimeError> {
        self.dispatch(|reply| Command::SendKeyboard { scancode, pressed, reply })
            .await
    }

    /// Send a Unicode keyboard event (BMP code points only; surrogate
    /// pairs are rejected by the underlying `RdpClient::send_unicode`).
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
        self.dispatch(|reply| Command::SendMouseButton { button, pressed, x, y, reply })
            .await
    }

    /// Send a mouse wheel scroll event.
    pub async fn send_mouse_wheel(
        &self,
        delta: i16,
        horizontal: bool,
        x: u16,
        y: u16,
    ) -> Result<(), RuntimeError> {
        self.dispatch(|reply| Command::SendMouseWheel { delta, horizontal, x, y, reply })
            .await
    }

    /// Send a Caps/Num/Scroll/Kana lock-state synchronisation.
    pub async fn send_synchronize(&self, lock_keys: LockKeys) -> Result<(), RuntimeError> {
        self.dispatch(|reply| Command::SendSynchronize { lock_keys, reply })
            .await
    }

    /// Gracefully disconnect: send a Disconnect PDU, drain the worker,
    /// and consume `self`.
    ///
    /// Returns the underlying `RdpClient::disconnect` result. If the
    /// worker has already exited (e.g. server-initiated disconnect that
    /// was surfaced through `next_event`), returns `Ok(())` because
    /// there is nothing left to tear down.
    pub async fn disconnect(mut self) -> Result<(), RuntimeError> {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(Command::Disconnect { reply: tx })
            .await
            .is_err()
        {
            // Worker already gone — nothing to do.
            return Ok(());
        }
        let result = match rx.await {
            Ok(r) => r,
            // Reply oneshot dropped → worker died mid-disconnect. The
            // session is effectively gone; report it as such rather
            // than masking a partial teardown.
            Err(_) => Err(RuntimeError::Disconnected),
        };

        // Wait for the worker to fully exit so any in-flight syscalls
        // complete before we drop the JoinHandle.
        if let Some(pump) = self.pump.take() {
            let _ = pump.await;
        }

        result
    }

    /// Internal helper: build a command via `make_cmd`, push it to the
    /// worker, await the reply.
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
        // Closing `cmd_tx` is the worker's signal to wind down on its
        // next try_recv between events. We cannot abort the worker's
        // in-flight blocking read from here — see the crate-level
        // cancel-safety note. Callers who need bounded shutdown should
        // call `disconnect()` explicitly.
    }
}

/// Run the synchronous connect on a blocking thread, then spawn the
/// long-lived event pump on a second blocking task.
async fn spawn_session<F>(connect: F) -> Result<AsyncRdpClient, ConnectError>
where
    F: FnOnce() -> Result<RdpClient, ConnectError> + Send + 'static,
{
    let client: RdpClient = tokio::task::spawn_blocking(connect)
        .await
        .map_err(join_error_to_connect)??;

    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(CMD_QUEUE);
    let (evt_tx, evt_rx) = mpsc::channel::<Result<RdpEvent, RuntimeError>>(EVT_QUEUE);

    let pump = tokio::task::spawn_blocking(move || {
        pump::run(client, cmd_rx, evt_tx);
    });

    Ok(AsyncRdpClient {
        cmd_tx,
        evt_rx,
        pump: Some(pump),
    })
}

fn join_error_to_connect(err: tokio::task::JoinError) -> ConnectError {
    let kind = if err.is_cancelled() {
        io::ErrorKind::Interrupted
    } else {
        io::ErrorKind::Other
    };
    ConnectError::Tcp(io::Error::new(
        kind,
        format!("connect blocking task failed: {err}"),
    ))
}
