//! Tauri-side bridge for the JustRDP async client (v2).
//!
//! Slice B (this commit): GraphicsUpdate is decoded through
//!   `justrdp_web::render_event` into a [`TauriFrameSink`], which
//!   accumulates damaged rectangles and ships them to the frontend
//!   as a single `Frame { blits }` IPC event. The frontend renders
//!   each blit with `ctx.putImageData`.
//!
//! Slice A (prior commit): connect / input / disconnect cycle.
//!   `RdpEvent::GraphicsUpdate` was observed but only a frame counter
//!   was forwarded.
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

mod audio;
mod clipboard;
mod input;
mod sink;
mod trust;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Serialize;
use tauri::{Emitter, Manager, Window};
use tokio::sync::{Mutex, mpsc, oneshot};

use justrdp_async::SessionEvent;
use justrdp_tokio::{AsyncRdpClient, Config, RdpEvent};
use justrdp_web::{render_event_stateful, BitmapRenderer};

use crate::input::{InputAction, InputEvent};
use crate::sink::{BlitRecord, TauriFrameSink};
use crate::trust::{
    hex_decode_fingerprint, hex_encode_fingerprint, CaptureSpki, TrustStore, TrustStoreVerifier,
};

/// Default desktop size negotiated with the server. Pinned so the
/// shadow framebuffer matches the canvas (`<canvas width=1024
/// height=768>` in `App.tsx`). Resize support arrives in a later
/// slice (display-control channel + dynamic canvas).
const DESKTOP_WIDTH: u16 = 1024;
const DESKTOP_HEIGHT: u16 = 768;

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

/// Outbound `Window::emit("rdp:event", ...)` payload. `Frame`
/// carries one batch of damaged rectangles (one per BitmapData in
/// the originating GraphicsUpdate); the frontend draws each with
/// `putImageData` at `(x, y)`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FrontendEvent {
    Frame { blits: Vec<BlitRecord> },
    PointerPosition { x: u16, y: u16 },
    /// Server asked the client to hide the cursor entirely
    /// (full-screen video, certain password fields). Frontend
    /// applies CSS `cursor: none`. (Slice α)
    PointerHidden,
    /// Server asked the client to restore the system default
    /// cursor (after a previous hide / sprite). Frontend applies
    /// CSS `cursor: default`. (Slice α)
    PointerDefault,
    /// Server pushed a fully-decoded cursor sprite. Frontend
    /// off-screen-canvas + `toDataURL` + assigns
    /// `canvas.style.cursor = url(...) hsX hsY, default`.
    /// (Slice β / #10)
    PointerSprite {
        width: u16,
        height: u16,
        hotspot_x: u16,
        hotspot_y: u16,
        /// Top-down RGBA8 base64-encoded for IPC transport.
        rgba_b64: String,
    },
    Disconnected { reason: String },
    Error { message: String },
}

struct AppState {
    sessions: Mutex<HashMap<u64, mpsc::Sender<SessionMsg>>>,
    next_id: AtomicU64,
    /// TOFU certificate trust store. Wrapped in `std::sync::RwLock`
    /// (not `tokio::sync::RwLock`) because the verifier callback is
    /// sync and runs on the rustls handshake thread.
    trust_store: Arc<StdRwLock<TrustStore>>,
}

impl AppState {
    fn new(trust_store: Arc<StdRwLock<TrustStore>>) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            trust_store,
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
    let mut builder =
        Config::builder(&user, &pass).desktop_size(DESKTOP_WIDTH, DESKTOP_HEIGHT);
    if let Some(d) = domain {
        builder = builder.domain(&d);
    }
    let config = builder.build();

    // Slice D2 + D1: register RDPSND audio processor and CLIPRDR
    // clipboard processor on platforms that have wired backends.
    // Both `new_platform_*_processor` calls return None on
    // unsupported targets; in that case the session has no audio /
    // clipboard path (frames are silently dropped upstream by the
    // SVC dispatcher).
    let mut processors = Vec::new();
    if let Some(audio) = audio::new_platform_audio_processor() {
        processors.push(audio);
    }
    if let Some(clip) = clipboard::new_platform_clipboard_processor() {
        processors.push(clip);
    }

    // Slice E: TLS verifier choice is feature-gated. Production
    // builds use the TOFU TrustStoreVerifier so an unknown / mismatched
    // SPKI fails the handshake; dev builds with `dev-no-verify` keep
    // the legacy dangerous_no_verify path for quick iteration.
    #[cfg(feature = "dev-no-verify")]
    let client = AsyncRdpClient::connect_with_processors(
        format!("{host}:{port}"),
        host.clone(),
        config,
        processors,
    )
    .await
    .map_err(|e| format!("connect failed: {e}"))?;

    #[cfg(not(feature = "dev-no-verify"))]
    let client = {
        let verifier: std::sync::Arc<dyn justrdp_tls::ServerCertVerifier> =
            std::sync::Arc::new(TrustStoreVerifier::new(state.trust_store.clone()));
        AsyncRdpClient::connect_with_verifier_and_processors(
            format!("{host}:{port}"),
            host.clone(),
            config,
            verifier,
            processors,
        )
        .await
        .map_err(|e| format!("connect failed: {e}"))?
    };

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
    let mut sink = TauriFrameSink::new(DESKTOP_WIDTH, DESKTOP_HEIGHT);
    // Session-scoped renderer state — Drawing Order delta-coding
    // history, bitmap / brush / glyph caches. MUST live as long as
    // the session; resetting it mid-session desynchronises the
    // server's elided fields and corrupts every subsequent order.
    let mut renderer = BitmapRenderer::new();
    // Slice β (#10): per-session cursor sprite cache. Color pointer
    // emits get decoded here and cached against the server-supplied
    // index for future Cached-pointer lookups (Slice δ).
    let mut cursor_cache = justrdp_cursor::CursorCache::new();

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
                    Some(Ok(RdpEvent::GraphicsUpdate { update_code, data })) => {
                        // Reconstruct a SessionEvent::Graphics so
                        // render_event can decode the bitmap update.
                        // Fields are 1:1 with the v1-compat
                        // translation in justrdp_tokio::translate
                        // (translate.rs:35).
                        let sev = SessionEvent::Graphics { update_code, data };
                        match render_event_stateful(&sev, &mut sink, &mut renderer) {
                            Ok(true) => {
                                let blits = sink.drain_blits();
                                if !blits.is_empty() {
                                    let _ = window.emit(
                                        "rdp:event",
                                        FrontendEvent::Frame { blits },
                                    );
                                }
                            }
                            Ok(false) => {}
                            Err(e) => {
                                // Surface decoder errors instead of
                                // silently dropping. Don't tear
                                // down the session — codec gaps
                                // (RFX without registered codec_id,
                                // NSCodec, …) are recoverable; the
                                // next refresh paints cleanly.
                                let _ = window.emit(
                                    "rdp:event",
                                    FrontendEvent::Error {
                                        message: format!("render: {e:?}"),
                                    },
                                );
                            }
                        }
                    }
                    Some(Ok(RdpEvent::PointerPosition { x, y })) => {
                        let _ = window.emit(
                            "rdp:event",
                            FrontendEvent::PointerPosition { x, y },
                        );
                    }
                    // Slice α: hide / restore tracer. Sprite-bearing
                    // PointerBitmap stays in the catch-all arm below
                    // until Slice β wires the decoder + cache + CSS
                    // cursor URL flow.
                    Some(Ok(RdpEvent::PointerHidden)) => {
                        let _ = window.emit("rdp:event", FrontendEvent::PointerHidden);
                    }
                    Some(Ok(RdpEvent::PointerDefault)) => {
                        let _ = window.emit("rdp:event", FrontendEvent::PointerDefault);
                    }
                    // Slice β (#10): decode Color pointer payloads.
                    // pointer_type 0x06 LARGE / 0x07 CACHED / 0x08
                    // POINTER (New) cannot be decoded yet (Slices
                    // γ / δ); fall back to PointerDefault so the
                    // host always shows an OS arrow rather than
                    // stale state.
                    Some(Ok(RdpEvent::PointerBitmap { pointer_type, data })) => {
                        const TS_PTRMSGTYPE_COLOR: u16 = 0x0009;
                        if pointer_type == TS_PTRMSGTYPE_COLOR {
                            match justrdp_cursor::decode_color(&data) {
                                Ok(cursor) => {
                                    if let Some(idx) = justrdp_cursor::extract_cache_index(&data) {
                                        cursor_cache.add(idx, cursor.clone());
                                    }
                                    let rgba_b64 = B64.encode(&cursor.rgba);
                                    let _ = window.emit(
                                        "rdp:event",
                                        FrontendEvent::PointerSprite {
                                            width: cursor.width,
                                            height: cursor.height,
                                            hotspot_x: cursor.hotspot_x,
                                            hotspot_y: cursor.hotspot_y,
                                            rgba_b64,
                                        },
                                    );
                                }
                                Err(_) => {
                                    let _ = window.emit(
                                        "rdp:event",
                                        FrontendEvent::PointerDefault,
                                    );
                                }
                            }
                        } else {
                            // New / Large / Cached — Slice γ / δ
                            // wires these. For now, fall back to
                            // OS default so the user always sees
                            // a cursor inside the canvas.
                            let _ = window.emit(
                                "rdp:event",
                                FrontendEvent::PointerDefault,
                            );
                        }
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
    let action = input::translate(event).map_err(|e| format!("translate: {e:?}"))?;
    let r = match action {
        InputAction::Key { scancode, pressed } => client.send_keyboard(scancode, pressed).await,
        InputAction::MouseMove { x, y } => client.send_mouse_move(x, y).await,
        InputAction::MouseButton { button, pressed, x, y } => {
            client.send_mouse_button(button, pressed, x, y).await
        }
        InputAction::Wheel { delta, horizontal, x, y } => {
            client.send_mouse_wheel(delta, horizontal, x, y).await
        }
        InputAction::Unicode { ch, pressed } => client.send_unicode(ch, pressed).await,
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

// Slice D1 deleted the `rdp_set_local_clipboard` and
// `rdp_poll_remote_clipboard` placeholder commands — clipboard
// sync now flows through the CLIPRDR SVC processor registered in
// `rdp_connect`, which talks directly to the OS clipboard via
// `NativeClipboard`. No frontend-driven polling is needed.

/// Probe `host:port` over TCP+TLS just enough to capture the
/// server's leaf SPKI fingerprint, then abort the handshake. Used
/// by the frontend's first-use trust prompt — it shows the user
/// the hex fingerprint before the user calls `rdp_trust_spki`.
///
/// Implementation note: the capturing verifier returns `Reject`,
/// which makes the rustls handshake fail with an "unknown issuer"-
/// style error. That's fine — we collected the fingerprint *before*
/// the verifier returned, so the Reject just acts as a fast-fail.
#[tauri::command]
async fn rdp_fetch_cert_spki(host: String, port: u16) -> Result<String, String> {
    let capture = Arc::new(CaptureSpki::new());
    let verifier: Arc<dyn justrdp_tls::ServerCertVerifier> = capture.clone();

    // Dummy credentials — we never reach the RDP handshake. The TLS
    // handshake itself is enough to receive the server cert.
    let config = Config::builder("probe", "probe").build();

    let _ = AsyncRdpClient::connect_with_verifier_and_processors(
        format!("{host}:{port}"),
        host.clone(),
        config,
        verifier,
        Vec::new(),
    )
    .await;

    // Whether the connect Result was Ok or Err, the verifier was
    // invoked and the SPKI was captured. If the cert was somehow
    // unparseable, surface that as a distinct error so the frontend
    // doesn't show an empty hex string.
    capture
        .captured()
        .map(|fp| hex_encode_fingerprint(&fp))
        .ok_or_else(|| {
            format!("could not extract SPKI from server cert at {host}:{port}")
        })
}

/// Persist a SPKI fingerprint to the trust store. Called by the
/// frontend after the user accepts the first-use trust prompt.
#[tauri::command]
async fn rdp_trust_spki(
    state: tauri::State<'_, Arc<AppState>>,
    host: String,
    spki_hex: String,
) -> Result<(), String> {
    let fp = hex_decode_fingerprint(&spki_hex)
        .ok_or_else(|| format!("invalid SPKI hex (expected 64 lowercase chars): {spki_hex}"))?;
    let mut store = state
        .trust_store
        .write()
        .map_err(|_| "trust store lock poisoned".to_string())?;
    store.add(&host, fp).map_err(|e| format!("trust persist failed: {e}"))
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
    tauri::Builder::default()
        .setup(|app| {
            // Resolve the platform-appropriate per-app config dir
            // (`%APPDATA%\com.user.justrdp-tauri\` on Windows etc.)
            // and open the trust store there. Failure to resolve
            // falls back to the OS temp dir — better than refusing
            // to launch.
            let store_path = app
                .path()
                .app_config_dir()
                .map(|d| d.join("trusted-spki.json"))
                .unwrap_or_else(|_| std::env::temp_dir().join("justrdp-trusted-spki.json"));
            let trust_store = Arc::new(StdRwLock::new(TrustStore::open(store_path)));
            let state = Arc::new(AppState::new(trust_store));
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            rdp_connect,
            rdp_send_input,
            rdp_disconnect,
            rdp_fetch_cert_spki,
            rdp_trust_spki,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
