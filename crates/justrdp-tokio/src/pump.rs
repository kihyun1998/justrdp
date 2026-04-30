#![forbid(unsafe_code)]

//! Async event pump for [`AsyncRdpClient`] v2.
//!
//! Replaces v1's `spawn_blocking` worker with a `tokio::spawn` task
//! that owns an [`ActiveSession`] and runs a `tokio::select!` loop:
//!
//! ```text
//! loop {
//!     select! {
//!         cmd = cmd_rx.recv() => handle command (input / Disconnect)
//!         events = session.next_events() => translate and forward
//!     }
//! }
//! ```
//!
//! ### Why this beats v1's `spawn_blocking`
//!
//! v1's worker calls `RdpClient::next_event` synchronously inside a
//! blocking thread. While that call is parked waiting for a frame
//! from the server, the command channel is *not* polled — so a
//! `Disconnect` command sits in `cmd_rx` until the next frame
//! arrives (or TCP keepalive fires for an idle session). This
//! manifests as v1's documented "disconnect 지연" bug.
//!
//! In v2 the same waiting reduces to `session.next_events().await`
//! which, by the [`ActiveSession`] contract, is **cancel-safe** —
//! Phase 2 made sure dropping the future loses no in-flight bytes.
//! When a `Disconnect` arrives, the `select!` cancels the
//! `next_events` future and we run `session.shutdown()` immediately,
//! which closes the TCP half-stream and wakes the (now cancelled)
//! poll. Disconnect latency drops from "next frame or keepalive" to
//! "scheduling tick".
//!
//! ### Cancel safety contract
//!
//! Both branches of the `select!` borrow `session` mutably. Tokio's
//! `select!` macro handles this correctly because it polls each
//! branch's future with disjoint borrow regions per iteration.
//! When one branch wins, the loser's future is dropped — its
//! borrow released — and the next iteration re-borrows freshly.

use alloc::format;
use alloc::sync::Arc;

use justrdp_async::{ActiveSession, DriverError};
use justrdp_blocking::{RdpEvent, RuntimeError};
use justrdp_input::{LockKeys, MouseButton, Scancode};
use tokio::sync::{mpsc, oneshot};

use crate::native_tls::NativeTlsTransport;
use crate::translate::{driver_error_to_runtime_error, session_event_to_rdp_events};

// Lightweight tracing — feature-gated so off-by-default builds pay
// nothing. When `tracing` is enabled the macros expand to real
// events on the `tracing` crate; otherwise they no-op.
#[cfg(feature = "tracing")]
use tracing::{debug, trace, warn};
#[cfg(not(feature = "tracing"))]
macro_rules! debug {
    ($($t:tt)*) => {};
}
#[cfg(not(feature = "tracing"))]
macro_rules! trace {
    ($($t:tt)*) => {};
}
#[cfg(not(feature = "tracing"))]
macro_rules! warn {
    ($($t:tt)*) => {};
}

/// Commands the async wrapper can dispatch to the pump task.
///
/// Every variant carries a `oneshot::Sender` so the caller's
/// `await` resolves only after the pump has executed the command
/// (and the underlying `ActiveSession` method has returned).
pub(crate) enum Command {
    SendKeyboard {
        scancode: Scancode,
        pressed: bool,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    SendUnicode {
        ch: char,
        pressed: bool,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    SendMouseMove {
        x: u16,
        y: u16,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    SendMouseButton {
        button: MouseButton,
        pressed: bool,
        x: u16,
        y: u16,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    SendMouseWheel {
        delta: i16,
        horizontal: bool,
        x: u16,
        y: u16,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    SendSynchronize {
        lock_keys: LockKeys,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    Disconnect {
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
}

/// Run the async pump until the session ends.
///
/// Exits when:
/// - a `Command::Disconnect` is processed (graceful), or
/// - the command channel closes (caller dropped without
///   `disconnect`), or
/// - `session.next_events()` returns an unrecoverable error, or
/// - the event channel's receiver was dropped (caller is gone).
pub(crate) async fn pump(
    mut session: ActiveSession<NativeTlsTransport>,
    mut cmd_rx: mpsc::Receiver<Command>,
    evt_tx: mpsc::Sender<Result<RdpEvent, RuntimeError>>,
) {
    // We use an `Arc<()>` as a cheap "keep the task alive" signal.
    // It does not actually carry data — its sole purpose is to
    // keep `evt_tx` from being dropped if the pump exits early.
    let _alive = Arc::new(());

    loop {
        tokio::select! {
            // Bias commands so a flood of incoming events doesn't
            // starve `Disconnect` arriving on `cmd_rx`. tokio's
            // select! defaults to round-robin (random in newer
            // versions); biased gives commands priority.
            biased;

            cmd = cmd_rx.recv() => {
                match cmd {
                    None => {
                        // Caller dropped without calling
                        // disconnect. Best-effort graceful close.
                        debug!("rdp.pump cmd channel closed; shutting down");
                        let _ = session.shutdown().await;
                        return;
                    }
                    Some(Command::Disconnect { reply }) => {
                        debug!("rdp.pump disconnect command received");
                        let r = session.shutdown().await
                            .map_err(driver_error_to_runtime_error);
                        let _ = reply.send(r);
                        return;
                    }
                    Some(other) => {
                        if let Err(e) = handle_input(other, &mut session).await {
                            warn!(?e, "rdp.pump input dispatch failed; exiting");
                            let _ = evt_tx.send(Err(e)).await;
                            return;
                        }
                    }
                }
            }

            events = session.next_events() => {
                match events {
                    Ok(list) => {
                        let mut terminated = false;
                        for ev in list {
                            // Detect Terminated *before* translation
                            // so we can stop the pump after surfacing
                            // it. Translation maps Terminated →
                            // Disconnected which we still want the
                            // embedder to see.
                            let is_terminator = matches!(
                                &ev,
                                justrdp_async::SessionEvent::Terminated(_)
                            );
                            for rdp_ev in session_event_to_rdp_events(ev) {
                                if evt_tx.send(Ok(rdp_ev)).await.is_err() {
                                    // Receiver dropped — caller went
                                    // away mid-session. Same cleanup
                                    // as the cmd-channel-disconnected
                                    // branch.
                                    debug!("rdp.pump evt receiver gone; shutting down");
                                    let _ = session.shutdown().await;
                                    return;
                                }
                            }
                            if is_terminator {
                                terminated = true;
                            }
                        }
                        if terminated {
                            // Server-initiated graceful disconnect
                            // already surfaced. Close the event
                            // channel by returning so
                            // `next_event() -> None` on the caller side.
                            return;
                        }
                    }
                    Err(DriverError::Transport(e)) if e.kind()
                        == justrdp_async::TransportErrorKind::ConnectionClosed =>
                    {
                        // Clean transport close — surface as the
                        // "session ended" signal and return.
                        trace!("rdp.pump transport closed cleanly");
                        return;
                    }
                    Err(err) => {
                        let runtime = driver_error_to_runtime_error(err);
                        let _ = evt_tx.send(Err(runtime)).await;
                        return;
                    }
                }
            }
        }
    }
}

/// Dispatch one input command to the active session. Errors are
/// translated to v1's `RuntimeError` shape and replied via the
/// oneshot. The function only returns `Err` when the failure is
/// session-fatal (e.g. transport lost) — input that's locally
/// invalid (BMP-only Unicode, X1/X2 mouse) returns `Ok(())` to the
/// caller and a tracing entry on the diagnostic side.
async fn handle_input(
    cmd: Command,
    session: &mut ActiveSession<NativeTlsTransport>,
) -> Result<(), RuntimeError> {
    let session_result = match cmd {
        Command::SendKeyboard {
            scancode,
            pressed,
            reply,
        } => {
            let r = if pressed {
                session.key_press(scancode).await
            } else {
                session.key_release(scancode).await
            };
            send_reply(reply, r.map(|_| ()))
        }
        Command::SendUnicode {
            ch,
            pressed,
            reply,
        } => {
            let code = u32::from(ch);
            if code > u16::MAX as u32 {
                // Non-BMP — same fallback as Phase 2's
                // send_unicode_char: return Ok without emitting,
                // leave it to the embedder to break into surrogate
                // pairs if they really need to.
                let _ = reply.send(Err(RuntimeError::Unimplemented(
                    "non-BMP Unicode (use UTF-16 surrogate pairs)",
                )));
                Ok(())
            } else {
                let r = session.send_unicode(code as u16, pressed).await;
                send_reply(reply, r)
            }
        }
        Command::SendMouseMove { x, y, reply } => {
            let r = session.move_mouse(x, y).await;
            send_reply(reply, r.map(|_| ()))
        }
        Command::SendMouseButton {
            button,
            pressed,
            x,
            y,
            reply,
        } => {
            let r = if pressed {
                session.button_press(button, x, y).await
            } else {
                session.button_release(button, x, y).await
            };
            send_reply(reply, r.map(|_| ()))
        }
        Command::SendMouseWheel {
            delta,
            horizontal,
            x,
            y,
            reply,
        } => {
            // Composed: position the pointer first (matches v1
            // semantics where the wheel event includes coordinates)
            // then issue the wheel scroll. If the position update
            // fails the wheel call still happens — same fail-open
            // behaviour as v1's RdpClient::send_mouse_wheel.
            let _ = session.move_mouse(x, y).await;
            let r = if horizontal {
                session.horizontal_wheel_scroll(delta).await
            } else {
                session.wheel_scroll(delta).await
            };
            send_reply(reply, r)
        }
        Command::SendSynchronize { lock_keys, reply } => {
            let r = session.send_synchronize(lock_keys).await;
            send_reply(reply, r)
        }
        Command::Disconnect { .. } => {
            // Disconnect is intercepted in `pump()` so it can
            // consume the session. Reaching here is a routing bug.
            unreachable!("Disconnect must be intercepted in pump()");
        }
    };
    session_result
}

/// Reply on the oneshot and surface a fatal session error if the
/// underlying call returned one. Local validation errors (returned
/// to the caller via `reply.send(Err(...))`) do not propagate up.
fn send_reply<T>(
    reply: oneshot::Sender<Result<(), RuntimeError>>,
    result: Result<T, DriverError>,
) -> Result<(), RuntimeError> {
    match result {
        Ok(_) => {
            let _ = reply.send(Ok(()));
            Ok(())
        }
        Err(err) => {
            // Distinguish "session is gone" (fatal) from "bad input"
            // (non-fatal). For now, anything from the session pump
            // that returns DriverError is treated as session-fatal
            // — matches v1 semantics where a bad input would surface
            // as RuntimeError but the session would also be tearing
            // down already.
            let runtime = driver_error_to_runtime_error(err);
            let _ = reply.send(Err(format_runtime(&runtime)));
            Err(runtime)
        }
    }
}

/// Clone-with-context a `RuntimeError` for the reply side. v1's
/// RuntimeError doesn't impl `Clone`, so we re-render via Display
/// when surfacing the same error to both the reply oneshot and the
/// pump's `Err` return.
fn format_runtime(e: &RuntimeError) -> RuntimeError {
    use std::io;
    // Best-effort copy: matching variants we can reconstruct, others
    // collapse to Disconnected (which is what the embedder ends up
    // observing anyway since the pump exits).
    match e {
        RuntimeError::Disconnected => RuntimeError::Disconnected,
        RuntimeError::FrameTooLarge(n) => RuntimeError::FrameTooLarge(*n),
        RuntimeError::Unimplemented(s) => RuntimeError::Unimplemented(*s),
        RuntimeError::Io(_) => RuntimeError::Io(io::Error::other(format!("{e}"))),
        RuntimeError::Session(_) => RuntimeError::Disconnected,
    }
}
