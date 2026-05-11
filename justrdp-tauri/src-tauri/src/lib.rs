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
mod avc;
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
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{Emitter, Manager, Window};
use tokio::sync::{Mutex, mpsc, oneshot};

use justrdp_async::SessionEvent;
use justrdp_dvc::DrdynvcClient;
use justrdp_egfx::GfxClient;
use justrdp_tokio::{AsyncRdpClient, Config, RdpEvent};
use justrdp_web::{render_event_stateful, BitmapRenderer, GfxRenderer, MutexFrameSink};

use crate::avc::NoopAvcDecoder;
use crate::input::{InputAction, InputEvent};
use crate::sink::{SharedSink, TauriFrameSink};
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

/// Outbound `Window::emit("rdp:event", ...)` payload for low-frequency
/// events (cursor, disconnect, error). Graphics frames moved to a
/// dedicated `tauri::ipc::Channel<Vec<u8>>` (PRD #31) — JSON encoding
/// + base64 wrapping was the dominant per-frame cost.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FrontendEvent {
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
    // Frontend supplies a binary channel for graphics frames. Channel
    // payloads are `pack_frame`-formatted RGBA blits — no JSON, no
    // base64, ~50% smaller than the legacy `emit("rdp:event", Frame)`
    // path and no per-frame encode/decode cost. PRD #31.
    frame_channel: Channel<InvokeResponseBody>,
) -> Result<u64, String> {
    // CHANNEL_OPTION_INITIALIZED (0x80000000) + CHANNEL_OPTION_COMPRESS_RDP
    // (0x00800000). Standard mstsc/FreeRDP flags for plain SVCs that
    // support per-frame RDP compression.
    const SVC_FLAGS: u32 = 0x8080_0000;

    let mut builder = Config::builder(&user, &pass)
        .desktop_size(DESKTOP_WIDTH, DESKTOP_HEIGHT)
        // PRD #1 #2/#3/#5 silent-failure fix (discovered 2026-05-11 via
        // [DIAG-egfx] log returning zero callbacks): SVC processors only
        // get an MCS channel id when the channel name is also advertised
        // in the connector's Config::static_channels. Otherwise the
        // server allocates nothing and the processor sits idle (no
        // error). Audio + clipboard advertised even when the platform
        // backend is None — the processor list filters them out, but
        // advertising costs nothing.
        .channel("rdpsnd", SVC_FLAGS)
        .channel("cliprdr", SVC_FLAGS)
        // PRD #20 #29: drdynvc hosts EGFX (Microsoft::Windows::RDS::Graphics)
        // dynamic channel — required for ClearCodec / AVC / surface bits.
        .channel("drdynvc", SVC_FLAGS);
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
    let audio_processor = audio::new_platform_audio_processor();
    log::info!(
        "[DIAG-clip] audio backend registered = {}",
        audio_processor.is_some()
    );
    if let Some(audio) = audio_processor {
        processors.push(audio);
    }
    let clipboard_processor = clipboard::new_platform_clipboard_processor();
    log::info!(
        "[DIAG-clip] clipboard backend registered = {}",
        clipboard_processor.is_some()
    );
    if let Some(clip) = clipboard_processor {
        processors.push(clip);
    }

    // PRD #20 / #29: shared canvas state. The EGFX SVC pump (DrdynvcClient
    // → GfxClient → GfxRenderer below) and `run_session`'s fast-path
    // renderer both blit into the same `TauriFrameSink`. `SharedSink`
    // wraps it in `Arc<Mutex<...>>` for thread-safe access; `Notify`
    // wakes `run_session` to drain pending blits whenever EGFX writes
    // arrive (fast-path-only sessions still drain inline because each
    // `next_event` already triggers a drain).
    let frame_sink = Arc::new(std::sync::Mutex::new(TauriFrameSink::new(
        DESKTOP_WIDTH,
        DESKTOP_HEIGHT,
    )));
    let drain_notify = Arc::new(tokio::sync::Notify::new());

    // EGFX adapter: GfxRenderer translates RDPGFX_WIRE_TO_SURFACE_PDU_1
    // payloads into `FrameSink::blit_rgba` calls on `frame_sink`. The
    // NoopAvcDecoder placeholder lets AVC420 / AVC444 payloads land
    // somewhere without erroring; the real WebCodecs backend is #26.
    let mut gfx_renderer = GfxRenderer::new(SharedSink::new(
        frame_sink.clone(),
        drain_notify.clone(),
    ));
    gfx_renderer.set_avc_decoder(Box::new(NoopAvcDecoder));

    // DRDYNVC SVC processor: hosts the EGFX dynamic channel
    // (`Microsoft::Windows::RDS::Graphics`). On `Create Request` from
    // the server, GfxClient reaches `WaitingForCapsConfirm`; cap-confirm
    // unlocks the surface-bits dispatch loop.
    let mut drdynvc = DrdynvcClient::new();
    drdynvc.register(Box::new(GfxClient::with_handler(Box::new(gfx_renderer))));
    processors.push(Box::new(drdynvc));

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

    // [DIAG-egfx] which static channels actually got an MCS id from
    // the server. If `drdynvc` is absent, the EGFX channel cannot
    // possibly open — server rejected our advertise (likely a GPO /
    // capset mismatch on Win Server 2019). If `drdynvc` is present
    // but no `[DIAG-egfx] on_create_surface` lines follow, server
    // accepted DRDYNVC but did not initiate `Microsoft::Windows::RDS::Graphics`.
    log::info!(
        "[DIAG-egfx] post-handshake channel_ids = {:?}",
        client.channel_ids()
    );

    let id = state.next_id.fetch_add(1, Ordering::Relaxed) + 1;
    let (msg_tx, msg_rx) = mpsc::channel::<SessionMsg>(64);

    let task_window = window.clone();
    let task_state = state.inner().clone();
    let task_sink = frame_sink.clone();
    let task_notify = drain_notify.clone();
    let task_channel = frame_channel.clone();
    tokio::spawn(async move {
        run_session(
            id,
            client,
            msg_rx,
            task_window,
            task_state,
            task_sink,
            task_notify,
            task_channel,
        )
        .await;
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
    frame_sink: Arc<std::sync::Mutex<TauriFrameSink>>,
    drain_notify: Arc<tokio::sync::Notify>,
    frame_channel: Channel<InvokeResponseBody>,
) {
    // Fast-path render uses a `MutexFrameSink` view into the shared
    // `frame_sink`. The EGFX SVC pump (registered in `rdp_connect`)
    // writes into the same `Arc<Mutex<TauriFrameSink>>` via its own
    // `SharedSink`, so both rendering paths land in one canvas.
    let mut sink = MutexFrameSink::new(frame_sink.clone());
    // Session-scoped renderer state — Drawing Order delta-coding
    // history, bitmap / brush / glyph caches. MUST live as long as
    // the session; resetting it mid-session desynchronises the
    // server's elided fields and corrupts every subsequent order.
    let mut renderer = BitmapRenderer::new();
    // PRD #14 Slice α: register the negotiated RFX codec_id from the
    // post-handshake `ConnectionResult` so SurfaceCommands carrying
    // RFX-tagged payloads decode through `BitmapRenderer.process_surface_commands`
    // instead of being dropped. `None` means the server didn't echo
    // RFX in its `BitmapCodecs` reply — embedder skips registration
    // and falls back to raw Bitmap fast-path automatically.
    if let Some(id) = client.rfx_codec_id() {
        renderer.set_rfx_codec_id(id);
    }
    // PRD #14 Slice β (#16): NSCodec — RGB image codec, strong on
    // continuous tones / gradients. ClearCodec is intentionally
    // omitted: per MS-RDPEGFX §2.2.4 it is EGFX-only, not advertised
    // through `BitmapCodecs`. Tracked as a follow-up EGFX SVC PRD.
    if let Some(id) = client.nscodec_codec_id() {
        renderer.set_nscodec_codec_id(id);
    }
    // Slice β (#10): per-session cursor sprite cache. Color pointer
    // emits get decoded here and cached against the server-supplied
    // index for future Cached-pointer lookups (Slice δ).
    let mut cursor_cache = justrdp_cursor::CursorCache::new();

    loop {
        tokio::select! {
            biased;

            // PRD #20 / #29: drain blits emitted by the EGFX SVC pump
            // (which writes into `frame_sink` from a separate task). On
            // pure-EGFX sessions there are no fast-path events to
            // trigger the inline drain in the `next_event` arm, so this
            // notify-driven branch is the only thing keeping the canvas
            // refreshing. `Notify` is idempotent — multiple back-to-back
            // EGFX writes coalesce into one drain wake.
            _ = drain_notify.notified() => {
                // [DIAG-perf] EGFX-side drain path — binary IPC channel
                let t0 = std::time::Instant::now();
                let (has_pending, packed) = match frame_sink.lock() {
                    Ok(mut s) => (s.has_pending(), s.drain_packed()),
                    Err(_) => continue,
                };
                let t1 = std::time::Instant::now();
                let bytes_len = packed.len();
                if has_pending {
                    let _ = frame_channel.send(InvokeResponseBody::Raw(packed));
                }
                let t2 = std::time::Instant::now();
                if has_pending {
                    log::info!(
                        "[DIAG-perf] rust.egfx_drain bytes={bytes_len} drain_us={d} send_us={e}",
                        d = (t1 - t0).as_micros(),
                        e = (t2 - t1).as_micros(),
                    );
                }
            }

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
                        // [DIAG-perf] fast-path render path
                        let t0 = std::time::Instant::now();
                        let data_len = data.len();
                        let upd_dbg = format!("{update_code:?}");
                        let sev = SessionEvent::Graphics { update_code, data };
                        let render_result = render_event_stateful(&sev, &mut sink, &mut renderer);
                        let t1 = std::time::Instant::now();
                        match render_result {
                            Ok(true) => {
                                let (has_pending, packed) = match frame_sink.lock() {
                                    Ok(mut s) => (s.has_pending(), s.drain_packed()),
                                    Err(_) => (false, Vec::new()),
                                };
                                let t2 = std::time::Instant::now();
                                let bytes_len = packed.len();
                                if has_pending {
                                    let _ = frame_channel.send(InvokeResponseBody::Raw(packed));
                                }
                                let t3 = std::time::Instant::now();
                                log::info!(
                                    "[DIAG-perf] rust.fastpath kind={upd_dbg} wire_bytes={data_len} packed_bytes={bytes_len} render_us={r} drain_us={d} send_us={e}",
                                    r = (t1 - t0).as_micros(),
                                    d = (t2 - t1).as_micros(),
                                    e = (t3 - t2).as_micros(),
                                );
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
                    // Slices β + γ + δ: decode Color (0x09) / New
                    // POINTER (0x08, Windows 11 default) / Cached
                    // (0x07) → emit sprite. New pointer covers
                    // ~90% of Windows server traffic; Color is the
                    // legacy XP-era fallback. Cached re-uses a
                    // previously-decoded sprite (no IPC re-encode).
                    // LARGE (0x06, HiDPI 96×96) is rare and stays
                    // silent for now.
                    Some(Ok(RdpEvent::PointerBitmap { pointer_type, data })) => {
                        // Match BOTH slow-path messageType codes
                        // (0x06/0x07/0x08/0x09) AND fast-path
                        // FastPathUpdateType u8 codes (0xC/0xA/0xB/0x9).
                        // Modern Windows servers send fast-path
                        // almost exclusively, so missing the
                        // fast-path arm leaves cursor stuck.
                        const COLOR: &[u16] = &[0x0009]; // slow & fast share 0x9
                        const POINTER_NEW: &[u16] = &[0x0008, 0x000B]; // slow=0x8, fast=0xB
                        const CACHED: &[u16] = &[0x0007, 0x000A]; // slow=0x7, fast=0xA
                        // LARGE: slow=0x6, fast=0xC — silent for now.

                        let decoded = if COLOR.contains(&pointer_type) {
                            let r = justrdp_cursor::decode_color(&data);
                            if let Ok(ref c) = r {
                                if let Some(idx) = justrdp_cursor::extract_cache_index(&data) {
                                    cursor_cache.add(idx, c.clone());
                                }
                            }
                            r.ok()
                        } else if POINTER_NEW.contains(&pointer_type) {
                            // New Pointer puts cacheIndex at offset 2 (after xorBpp).
                            let r = justrdp_cursor::decode_new(&data);
                            if let Ok(ref c) = r {
                                if data.len() >= 4 {
                                    let idx = u16::from_le_bytes([data[2], data[3]]);
                                    cursor_cache.add(idx, c.clone());
                                }
                            }
                            r.ok()
                        } else if CACHED.contains(&pointer_type) {
                            justrdp_cursor::decode_cached(&data, &cursor_cache).ok()
                        } else {
                            None // LARGE / unknown — silent drop
                        };

                        if let Some(cursor) = decoded {
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
                        // Decoder rejection / unknown type → keep
                        // last-painted cursor. Better than forcing
                        // a default arrow that overwrites a valid
                        // sprite from an earlier message.
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
    let action = match input::translate(event) {
        Ok(a) => a,
        Err(e) => {
            log::info!("[DIAG-key] rust.translate_err {:?}", e);
            return Err(format!("translate: {e:?}"));
        }
    };
    // Mirror only key events into the diag log — other input types are
    // already in the [DIAG-perf] perf log indirectly.
    if let InputAction::Key { scancode, pressed } = &action {
        log::info!(
            "[DIAG-key] rust.dispatch Key sc=0x{:02x} pressed={}",
            scancode.code,
            pressed
        );
    }
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
    if let Err(e) = &r {
        log::info!("[DIAG-key] rust.send_err {}", e);
    }
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
    // Identifier (e.g. `com.user.justrdp-tauri`) drives both the OS log
    // dir namespacing and the log file name. Reading from the compiled
    // tauri.conf.json keeps the two in sync without manual config.
    let context: tauri::Context = tauri::generate_context!();
    let log_file_name = context.config().identifier.clone();

    tauri::Builder::default()
        // File-only logging (LogDir target). OS-standard locations:
        //   Windows: %APPDATA%/<identifier>/logs/<file_name>.log
        //   macOS:   ~/Library/Logs/<identifier>/<file_name>.log
        //   Linux:   ~/.local/share/<identifier>/logs/<file_name>.log
        // Rotation: 5MB, KeepAll. Local timezone (KST-aware).
        .plugin(
            tauri_plugin_log::Builder::new()
                .targets([tauri_plugin_log::Target::new(
                    tauri_plugin_log::TargetKind::LogDir {
                        file_name: Some(log_file_name),
                    },
                )])
                .timezone_strategy(tauri_plugin_log::TimezoneStrategy::UseLocal)
                .max_file_size(5_000_000)
                .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepAll)
                .level(log::LevelFilter::Info)
                .build(),
        )
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
        .run(context)
        .expect("error while running tauri application");
}
