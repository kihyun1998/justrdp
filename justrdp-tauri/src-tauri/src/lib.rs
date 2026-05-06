//! Tauri-side bridge for the JustRDP async client (v2).
//!
//! Slice A (this commit): connect / input / disconnect cycle.
//!   `RdpEvent::GraphicsUpdate` is observed but only a frame counter
//!   is forwarded to the frontend — actual decoding (BitmapRenderer
//!   + FrameSink wiring) lives in Slice B.
//!
//! ## Why a task-owned `AsyncRdpClient`
//!
//! v2's [`AsyncRdpClient::next_event`] is `&mut self` (it owns the
//! `mpsc::Receiver` for events). Wrapping the client in `Arc` would
//! prevent calling it. Wrapping in `Mutex<AsyncRdpClient>` would
//! serialise `send_*` against `next_event` — but `next_event` awaits
//! arbitrarily long, so `send_*` would block indefinitely.
//!
//! Resolution: each session spawns one **owner task** that holds the
//! `AsyncRdpClient` exclusively. Frontend commands are forwarded to
//! the task via an mpsc channel; the task uses `tokio::select!` to
//! multiplex frontend commands with `next_event`. Backlog cannot
//! accumulate because the task is the only consumer of both
//! channels.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, Window};
use tokio::sync::{Mutex, mpsc, oneshot};

use justrdp_input::{MouseButton, Scancode};
use justrdp_tokio::{AsyncRdpClient, Config, RdpEvent};

/// In-flight messages from frontend commands to the per-session
/// owner task. The task owns `AsyncRdpClient` and replies via the
/// `oneshot` channels embedded in each variant.
enum SessionMsg {
    Input {
        event: InputEvent,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Disconnect {
        reply: oneshot::Sender<Result<(), String>>,
    },
}

/// Frontend-shaped input event. One enum so we keep a single
/// `send_input` Tauri command instead of four overlapping ones.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum InputEvent {
    /// `code` is the 8-bit AT/PS-2 scancode; `extended` carries the
    /// E0 prefix bit (arrow keys, right-side modifiers, etc.).
    Key { code: u8, extended: bool, pressed: bool },
    MouseMove { x: u16, y: u16 },
    /// `button`: 0=Left 1=Right 2=Middle 3=X1 4=X2.
    MouseButton { button: u8, pressed: bool, x: u16, y: u16 },
    Wheel { delta: i16, horizontal: bool, x: u16, y: u16 },
}

/// Outbound `Window::emit("rdp:event", ...)` payload. Slice A keeps
/// this minimal — Slice B will replace `Frame { count }` with
/// `Frame { x, y, w, h, rgba_b64 }`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FrontendEvent {
    Frame { count: u64 },
    PointerPosition { x: u16, y: u16 },
    Disconnected { reason: String },
    Error { message: String },
}

struct AppState {
    sessions: Mutex<HashMap<u64, mpsc::Sender<SessionMsg>>>,
    next_id: AtomicU64,
}

impl AppState {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }
}

#[tauri::command]
async fn rdp_connect(
    window: Window,
    state: tauri::State<'_, Arc<AppState>>,
    host: String,
    port: u16,
    user: String,
    pass: String,
    domain: Option<String>,
) -> Result<u64, String> {
    let mut builder = Config::builder(&user, &pass);
    if let Some(d) = domain {
        builder = builder.domain(&d);
    }
    let config = builder.build();

    let client = AsyncRdpClient::connect(format!("{host}:{port}"), host.clone(), config)
        .await
        .map_err(|e| format!("connect failed: {e}"))?;

    let id = state.next_id.fetch_add(1, Ordering::Relaxed) + 1;
    let (msg_tx, msg_rx) = mpsc::channel::<SessionMsg>(64);

    let task_window = window.clone();
    let task_state = state.inner().clone();
    tokio::spawn(async move {
        run_session(id, client, msg_rx, task_window, task_state).await;
    });

    state.sessions.lock().await.insert(id, msg_tx);
    Ok(id)
}

/// Per-session owner task. Holds `AsyncRdpClient` exclusively and
/// multiplexes frontend commands with `next_event` polling via
/// `tokio::select!`. Exits on Disconnect, server-side termination,
/// or transport error.
async fn run_session(
    id: u64,
    mut client: AsyncRdpClient,
    mut msg_rx: mpsc::Receiver<SessionMsg>,
    window: Window,
    state: Arc<AppState>,
) {
    let mut frame_count: u64 = 0;
    // Emit a Frame event every Nth update so we don't spam the IPC
    // bridge while we don't have actual pixels to ship yet.
    const FRAME_REPORT_EVERY: u64 = 30;

    loop {
        tokio::select! {
            biased;

            msg = msg_rx.recv() => {
                let Some(msg) = msg else { break };
                match msg {
                    SessionMsg::Input { event, reply } => {
                        let result = dispatch_input(&client, event).await;
                        let _ = reply.send(result);
                    }
                    SessionMsg::Disconnect { reply } => {
                        // Drain remaining events without blocking,
                        // then consume `client` to call disconnect().
                        // We have to break out of the loop because
                        // disconnect takes self by value.
                        let result = client.disconnect().await
                            .map_err(|e| e.to_string());
                        let _ = reply.send(result);
                        break;
                    }
                }
            }

            evt = client.next_event() => {
                match evt {
                    Some(Ok(RdpEvent::GraphicsUpdate { .. })) => {
                        frame_count += 1;
                        if frame_count % FRAME_REPORT_EVERY == 0 {
                            let _ = window.emit(
                                "rdp:event",
                                FrontendEvent::Frame { count: frame_count },
                            );
                        }
                    }
                    Some(Ok(RdpEvent::PointerPosition { x, y })) => {
                        let _ = window.emit(
                            "rdp:event",
                            FrontendEvent::PointerPosition { x, y },
                        );
                    }
                    Some(Ok(RdpEvent::Disconnected(reason))) => {
                        let _ = window.emit(
                            "rdp:event",
                            FrontendEvent::Disconnected {
                                reason: format!("{reason:?}"),
                            },
                        );
                        break;
                    }
                    Some(Ok(_)) => {
                        // Other variants (cursor bitmap, channel data,
                        // session info, etc.) are observed but not
                        // forwarded in Slice A.
                    }
                    Some(Err(e)) => {
                        let _ = window.emit(
                            "rdp:event",
                            FrontendEvent::Error {
                                message: e.to_string(),
                            },
                        );
                        break;
                    }
                    None => break,
                }
            }
        }
    }

    state.sessions.lock().await.remove(&id);
}

async fn dispatch_input(client: &AsyncRdpClient, event: InputEvent) -> Result<(), String> {
    let r = match event {
        InputEvent::Key { code, extended, pressed } => {
            client.send_keyboard(Scancode::new(code, extended), pressed).await
        }
        InputEvent::MouseMove { x, y } => client.send_mouse_move(x, y).await,
        InputEvent::MouseButton { button, pressed, x, y } => {
            let btn = match button {
                0 => MouseButton::Left,
                1 => MouseButton::Right,
                2 => MouseButton::Middle,
                3 => MouseButton::X1,
                4 => MouseButton::X2,
                _ => return Err(format!("unknown mouse button {button}")),
            };
            client.send_mouse_button(btn, pressed, x, y).await
        }
        InputEvent::Wheel { delta, horizontal, x, y } => {
            client.send_mouse_wheel(delta, horizontal, x, y).await
        }
    };
    r.map_err(|e| e.to_string())
}

#[tauri::command]
async fn rdp_send_input(
    state: tauri::State<'_, Arc<AppState>>,
    id: u64,
    event: InputEvent,
) -> Result<(), String> {
    let tx = {
        let map = state.sessions.lock().await;
        map.get(&id).cloned().ok_or_else(|| "unknown session".to_string())?
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(SessionMsg::Input { event, reply: reply_tx })
        .await
        .map_err(|_| "session task gone".to_string())?;
    reply_rx.await.map_err(|_| "session task dropped reply".to_string())?
}

#[tauri::command]
async fn rdp_set_local_clipboard(
    _state: tauri::State<'_, Arc<AppState>>,
    _id: u64,
    _text: String,
) -> Result<(), String> {
    // Placeholder — clipboard channel wiring is out of scope for
    // Slice A. Returns Ok so frontend can call without erroring.
    Ok(())
}

#[tauri::command]
async fn rdp_poll_remote_clipboard(
    _state: tauri::State<'_, Arc<AppState>>,
    _id: u64,
) -> Result<Option<String>, String> {
    // Placeholder — see rdp_set_local_clipboard.
    Ok(None)
}

#[tauri::command]
async fn rdp_disconnect(
    state: tauri::State<'_, Arc<AppState>>,
    id: u64,
) -> Result<(), String> {
    let tx = {
        let map = state.sessions.lock().await;
        map.get(&id).cloned()
    };
    let Some(tx) = tx else { return Ok(()) };

    let (reply_tx, reply_rx) = oneshot::channel();
    if tx.send(SessionMsg::Disconnect { reply: reply_tx }).await.is_err() {
        // Task already exited (e.g. server-initiated disconnect
        // arrived just before the user clicked). Clean up the map
        // entry just in case it lingers, then succeed silently.
        state.sessions.lock().await.remove(&id);
        return Ok(());
    }
    reply_rx.await.map_err(|_| "disconnect reply dropped".to_string())?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = Arc::new(AppState::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(move |app| {
            app.manage(state.clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            rdp_connect,
            rdp_send_input,
            rdp_set_local_clipboard,
            rdp_poll_remote_clipboard,
            rdp_disconnect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
