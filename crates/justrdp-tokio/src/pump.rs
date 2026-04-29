#![forbid(unsafe_code)]

//! Worker loop that runs on a `tokio::task::spawn_blocking` thread.
//!
//! The worker owns the [`RdpClient`] and is the *only* place that
//! touches it directly. Commands arrive via [`Command`] over an mpsc
//! channel; events leave via another mpsc channel. Each loop iteration
//! drains the command queue (non-blocking) before pumping one event
//! from the wire so input is not held back behind the next-frame read.

use justrdp_blocking::{RdpClient, RdpEvent, RuntimeError};
use justrdp_input::{LockKeys, MouseButton, Scancode};
use tokio::sync::{mpsc, oneshot};

/// Commands the async wrapper can dispatch to the worker.
///
/// Every variant carries a `oneshot` reply so the caller's `await`
/// resolves only after the underlying `RdpClient` method returns.
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

/// Run the worker loop until the session ends.
///
/// Returns when:
/// - a [`Command::Disconnect`] is processed (graceful), or
/// - the command channel is dropped, or
/// - [`RdpClient::next_event`] returns an error or `Ok(None)` (server
///   closed the session, transport dropped, etc.).
pub(crate) fn run(
    mut client: RdpClient,
    mut cmd_rx: mpsc::Receiver<Command>,
    evt_tx: mpsc::Sender<Result<RdpEvent, RuntimeError>>,
) {
    loop {
        // Drain pending commands non-blocking. Disconnect short-circuits
        // the whole loop because `RdpClient::disconnect` consumes self.
        loop {
            match cmd_rx.try_recv() {
                Ok(Command::Disconnect { reply }) => {
                    let result = client.disconnect();
                    let _ = reply.send(result);
                    return;
                }
                Ok(other) => {
                    handle_input(other, &mut client);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // Caller dropped without calling disconnect — best
                    // effort cleanup so the server sees a graceful close.
                    let _ = client.disconnect();
                    return;
                }
            }
        }

        // Pump a single server event. This blocks until the server
        // sends a frame, the transport drops, or auto-reconnect runs.
        match client.next_event() {
            Ok(Some(event)) => {
                if evt_tx.blocking_send(Ok(event)).is_err() {
                    // Receiver dropped — caller went away. Same cleanup
                    // as the cmd-channel-disconnected branch.
                    let _ = client.disconnect();
                    return;
                }
            }
            Ok(None) => {
                // Graceful end of session. Closing the channel signals
                // EOF to `AsyncRdpClient::next_event`.
                return;
            }
            Err(err) => {
                let _ = evt_tx.blocking_send(Err(err));
                return;
            }
        }
    }
}

fn handle_input(cmd: Command, client: &mut RdpClient) {
    match cmd {
        Command::SendKeyboard { scancode, pressed, reply } => {
            let _ = reply.send(client.send_keyboard(scancode, pressed));
        }
        Command::SendUnicode { ch, pressed, reply } => {
            let _ = reply.send(client.send_unicode(ch, pressed));
        }
        Command::SendMouseMove { x, y, reply } => {
            let _ = reply.send(client.send_mouse_move(x, y));
        }
        Command::SendMouseButton { button, pressed, x, y, reply } => {
            let _ = reply.send(client.send_mouse_button(button, pressed, x, y));
        }
        Command::SendMouseWheel { delta, horizontal, x, y, reply } => {
            let _ = reply.send(client.send_mouse_wheel(delta, horizontal, x, y));
        }
        Command::SendSynchronize { lock_keys, reply } => {
            let _ = reply.send(client.send_synchronize(lock_keys));
        }
        Command::Disconnect { .. } => {
            // Disconnect is handled in `run` so it can consume `client`.
            // Reaching here would mean the dispatcher routed it wrong.
            unreachable!("Disconnect must be intercepted in run()");
        }
    }
}
