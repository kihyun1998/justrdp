#![forbid(unsafe_code)]

//! `wasm-bindgen` JavaScript facade (wasm32 only).
//!
//! Two entry points:
//!
//! 1. [`justrdp_connect`] — one-shot Promise that runs the handshake and
//!    drops the connection. Useful as a smoke test from JS.
//! 2. [`JsClient`] — stateful handle. Holds the post-handshake
//!    [`ActiveSession`] *and* a [`CanvasFrameSink`] across JS calls so
//!    the embedder can `connect()` once, then run a `pollEvents()` loop
//!    that streams pixels into a `<canvas>`.
//!
//! Cancellation: every async method takes ownership of the relevant
//! components via `Option::take`, runs the future without holding a
//! `RefCell` borrow across the await, then puts the components back.
//! If a JS caller drops the returned Promise, the components are lost
//! (subsequent calls error with `"not connected"`); that's the same
//! footgun every wasm-bindgen async API has and matches the way browser
//! Promise consumers interact with state in practice.
//!
//! [`ActiveSession`]: crate::ActiveSession
//! [`CanvasFrameSink`]: crate::CanvasFrameSink

use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;

use js_sys::{Object, Reflect};
use justrdp_connector::Config;
use justrdp_pdu::x224::SecurityProtocol;
use wasm_bindgen::prelude::*;
use web_sys::HtmlCanvasElement;

use crate::canvas::CanvasFrameSink;
use crate::clipboard::ClipboardChannel;
use crate::driver::WebClient;
use crate::transport::WebTransport;
use crate::input::{
    mouse_button_event, mouse_move_event, mouse_wheel_event, scancode_event, MouseButton,
};
use crate::render::BitmapRenderer;
use crate::session::ActiveSession;
use crate::websocket::{WebSocketConfig, WebSocketTransport};

/// One-shot Standard-Security connect.
///
/// Resolves with a small JS object describing the negotiated session:
/// ```text
/// { shareId, ioChannelId, userChannelId, channels: ["rdpdr", ...] }
/// ```
/// Rejects with an `Error` whose message is a human-readable diagnostic.
#[wasm_bindgen(js_name = justrdpConnect)]
pub async fn justrdp_connect(
    url: String,
    username: String,
    password: String,
    domain: Option<String>,
) -> Result<JsValue, JsValue> {
    // 1. Open the WebSocket bridge.
    let transport = WebSocketTransport::connect(WebSocketConfig::new(url))
        .await
        .map_err(|e| js_error(format!("websocket: {e}")))?;

    // 2. Build a Standard-Security Config. Builder defaults are sane; we
    //    only override auth/security flags and the browser-sourced
    //    client_random.
    let mut client_random = [0u8; 32];
    getrandom::getrandom(&mut client_random)
        .map_err(|e| js_error(format!("crypto.getRandomValues: {e}")))?;

    let mut builder =
        Config::builder(&username, &password).security_protocol(SecurityProtocol::RDP);
    if let Some(d) = domain.as_deref().filter(|s| !s.is_empty()) {
        builder = builder.domain(d);
    }
    let mut config = builder.build();
    config.client_random = Some(client_random);

    // 3. Drive the handshake.
    let client = WebClient::new(transport);
    let (result, _transport) = client
        .connect(config)
        .await
        .map_err(|e| js_error(format!("handshake: {e}")))?;

    // S2 lets the transport drop here; S3 will retain it on a JsClient
    // handle for the active-session pump. WebSocketTransport sends a
    // close frame on Drop via its retained event-handler closures.
    Ok(serialize_summary(&result))
}

fn js_error(msg: impl Into<String>) -> JsValue {
    js_sys::Error::new(&msg.into()).into()
}

// ── Stateful JsClient handle ────────────────────────────────────────

#[derive(Default)]
struct JsClientInner {
    /// Active session after a successful `connect()`. Taken out for the
    /// duration of every async method that touches it, then put back.
    session: Option<ActiveSession<WebSocketTransport>>,
    /// Optional render target. None means events are decoded but not
    /// blitted (handy for headless tests / "tail the channel" UIs).
    sink: Option<CanvasFrameSink>,
    /// Stateful renderer — caches the 8 bpp palette across batches and
    /// (in S3d-2+) will hold codec contexts. Surviving across
    /// `disconnect()` / `connect()` is fine: a fresh handshake will
    /// emit a Palette PDU before any 8 bpp Bitmap, and codec state in
    /// later steps will be reset on session boundaries.
    renderer: BitmapRenderer,
    /// Last successful `connect()` summary, mirrored so JS can read it
    /// at any time without re-issuing the connect Promise.
    last_summary: Option<JsValue>,
    /// JS-side flag: the bridge handles TLS termination, so the
    /// connector's `EnhancedSecurityUpgrade` is treated as already
    /// done. Mirrors `WebClient::with_external_tls(true)`.
    external_tls: bool,
    /// Clipboard channel router. Auto-attached on `connect()` if the
    /// negotiated channels include `cliprdr`.
    clipboard: Option<ClipboardChannel>,
}

/// Stateful RDP-over-WebSocket client. Hold one per `<canvas>`.
///
/// Lifecycle: `new()` → `attachCanvas()` (optional) → `connect()` →
/// `pollEvents()` loop → `disconnect()`.
#[wasm_bindgen]
pub struct JsClient {
    inner: Rc<RefCell<JsClientInner>>,
}

#[wasm_bindgen]
impl JsClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(JsClientInner::default())),
        }
    }

    /// Bind a `<canvas>` element. Calling this *before* `connect()` is
    /// the common path; calling after a successful connect also works
    /// and replaces any previously attached canvas.
    #[wasm_bindgen(js_name = attachCanvas)]
    pub fn attach_canvas(&self, canvas: HtmlCanvasElement) -> Result<(), JsValue> {
        let sink = CanvasFrameSink::from_canvas(&canvas)?;
        self.inner.borrow_mut().sink = Some(sink);
        Ok(())
    }

    /// Tell the client that the WebSocket bridge already terminates TLS
    /// to the RDP server (typical wsproxy / chisel / TS Gateway setup
    /// with a `wss://` URL). When set, the connector's SSL/HYBRID
    /// `EnhancedSecurityUpgrade` is treated as done-by-bridge and the
    /// handshake continues without an in-band TLS handshake. Default
    /// is `false`.
    ///
    /// NLA / CredSSP still surfaces as `not connected → NLA required`
    /// because justrdp-web does not implement CredSSP yet.
    #[wasm_bindgen(js_name = setExternalTls)]
    pub fn set_external_tls(&self, enabled: bool) {
        self.inner.borrow_mut().external_tls = enabled;
    }

    /// Whether `connect()` has succeeded and `disconnect()` hasn't run.
    #[wasm_bindgen(getter)]
    pub fn connected(&self) -> bool {
        self.inner.borrow().session.is_some()
    }

    /// Last successful connect summary (the same shape returned by
    /// `connect()`), or `null` if no handshake has succeeded yet.
    #[wasm_bindgen(getter, js_name = lastSummary)]
    pub fn last_summary(&self) -> JsValue {
        self.inner
            .borrow()
            .last_summary
            .clone()
            .unwrap_or(JsValue::NULL)
    }

    /// Open a WebSocket bridge to `url`, run the Standard-Security
    /// handshake, and store the resulting session for `pollEvents()`.
    /// Resolves with the same JS object as [`justrdp_connect`].
    pub async fn connect(
        &self,
        url: String,
        username: String,
        password: String,
        domain: Option<String>,
    ) -> Result<JsValue, JsValue> {
        // Bail if a session is already up — caller must explicitly
        // disconnect before reconnecting (avoids accidentally leaking
        // an old transport).
        if self.inner.borrow().session.is_some() {
            return Err(js_error("already connected"));
        }

        let transport = WebSocketTransport::connect(WebSocketConfig::new(url))
            .await
            .map_err(|e| js_error(format!("websocket: {e}")))?;

        let mut client_random = [0u8; 32];
        getrandom::getrandom(&mut client_random)
            .map_err(|e| js_error(format!("crypto.getRandomValues: {e}")))?;

        let mut builder =
            Config::builder(&username, &password).security_protocol(SecurityProtocol::RDP);
        if let Some(d) = domain.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.domain(d);
        }
        let mut config = builder.build();
        config.client_random = Some(client_random);

        let external_tls = self.inner.borrow().external_tls;
        let client = WebClient::new(transport).with_external_tls(external_tls);
        let (result, transport) = client
            .connect(config)
            .await
            .map_err(|e| js_error(format!("handshake: {e}")))?;

        let summary = serialize_summary(&result);
        let session = ActiveSession::new(transport, &result);
        // Auto-attach the clipboard channel when the server negotiated
        // it. `from_connection` errors with ChannelNotNegotiated if
        // not — we silently leave clipboard disabled in that case.
        let clipboard = ClipboardChannel::from_connection(&result).ok();
        let mut g = self.inner.borrow_mut();
        g.session = Some(session);
        g.last_summary = Some(summary.clone());
        g.clipboard = clipboard;
        Ok(summary)
    }

    /// Read one frame from the wire, route it through `ActiveStage`,
    /// and (if a canvas is attached) render any `Graphics::Bitmap`
    /// rectangles. Returns the number of rectangles drawn.
    ///
    /// On `Terminated` the session is automatically dropped — the
    /// `connected` getter will flip to `false` and a subsequent call
    /// returns `Err("not connected")`.
    #[wasm_bindgen(js_name = pollEvents)]
    pub async fn poll_events(&self) -> Result<u32, JsValue> {
        // Take the session, run the future without a borrow held across
        // the await, then put it back unless the session has terminated.
        let mut session = self
            .inner
            .borrow_mut()
            .session
            .take()
            .ok_or_else(|| js_error("not connected"))?;
        let result = session.next_events().await;

        // Take the sink for rendering. Done after the await so the
        // borrow doesn't span the suspension.
        let mut sink_opt = self.inner.borrow_mut().sink.take();

        let events = match result {
            Ok(events) => events,
            Err(e) => {
                // Restore both components so the caller can decide how
                // to recover (e.g. retry on a transient transport hiccup).
                let mut g = self.inner.borrow_mut();
                g.session = Some(session);
                g.sink = sink_opt;
                return Err(js_error(format!("poll: {e}")));
            }
        };

        let mut blits: u32 = 0;
        let mut terminated = false;
        // Collect clipboard channel response frames in order; we send
        // them after the per-event loop so the borrow tracking stays
        // simple (no awaits while holding any RefCell guard).
        let mut clipboard_responses: Vec<Vec<u8>> = Vec::new();
        for event in &events {
            if let Some(sink) = sink_opt.as_mut() {
                let mut g = self.inner.borrow_mut();
                if let Ok(true) = g.renderer.render(event, sink) {
                    blits += 1;
                }
            }
            if let crate::SessionEvent::Channel { channel_id, data } = event {
                let mut g = self.inner.borrow_mut();
                if let Some(cl) = g.clipboard.as_mut() {
                    if let Ok(frames) = cl.process_channel_data(*channel_id, data) {
                        clipboard_responses.extend(frames);
                    }
                }
            }
            if matches!(event, crate::SessionEvent::Terminated(_)) {
                terminated = true;
            }
        }

        // Drain any clipboard response frames back to the server. Each
        // frame is a complete TPKT-framed slow-path PDU.
        for frame in &clipboard_responses {
            session
                .transport()
                .send(frame)
                .await
                .map_err(|e| js_error(format!("clipboard send: {e}")))?;
        }

        let mut g = self.inner.borrow_mut();
        if !terminated {
            g.session = Some(session);
        } else {
            // Tear down clipboard with the session — it's tied to a
            // specific cliprdr channel id from this connection.
            g.clipboard = None;
        }
        // Sink survives the session — embedders may attach a new session
        // on the same canvas without re-binding it.
        g.sink = sink_opt;
        Ok(blits)
    }

    // ── Clipboard (S5b) ────────────────────────────────────────────

    /// Whether the current session negotiated the `cliprdr` channel.
    /// `false` for sessions where the server didn't include it (no
    /// clipboard sync available).
    #[wasm_bindgen(getter, js_name = hasClipboard)]
    pub fn has_clipboard(&self) -> bool {
        self.inner.borrow().clipboard.is_some()
    }

    /// Push a string to the RDP clipboard as `CF_UNICODETEXT`. The
    /// renderer encodes it as UTF-16LE with a NUL terminator and
    /// announces a one-format format list to the server. The server
    /// will follow up with a format-data-request, which `pollEvents`
    /// auto-handles via the bundled backend.
    #[wasm_bindgen(js_name = setLocalClipboardText)]
    pub async fn set_local_clipboard_text(&self, text: String) -> Result<(), JsValue> {
        // Build CF_UNICODETEXT bytes: UTF-16LE codepoints + 0x0000 terminator.
        let mut bytes = Vec::with_capacity(text.len() * 2 + 2);
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0u8, 0u8]);

        // set_local_format_data needs &mut clipboard; take/put-back to
        // avoid holding a RefCell borrow across the awaited send.
        let mut clipboard = self
            .inner
            .borrow_mut()
            .clipboard
            .take()
            .ok_or_else(|| js_error("clipboard channel not available"))?;
        let frames = match clipboard.set_local_format_data(13 /* CF_UNICODETEXT */, bytes, "") {
            Ok(f) => f,
            Err(e) => {
                self.inner.borrow_mut().clipboard = Some(clipboard);
                return Err(js_error(format!("set local clipboard: {e}")));
            }
        };
        // Take session for the send loop.
        let mut session = match self.inner.borrow_mut().session.take() {
            Some(s) => s,
            None => {
                self.inner.borrow_mut().clipboard = Some(clipboard);
                return Err(js_error("not connected"));
            }
        };
        let mut send_err = None;
        for frame in &frames {
            if let Err(e) = session.transport().send(frame).await {
                send_err = Some(format!("clipboard send: {e}"));
                break;
            }
        }
        let mut g = self.inner.borrow_mut();
        g.session = Some(session);
        g.clipboard = Some(clipboard);
        if let Some(msg) = send_err {
            return Err(js_error(msg));
        }
        Ok(())
    }

    /// Drain the most-recently-received `CF_UNICODETEXT` clipboard
    /// data from the server, decoded as a UTF-16LE string. Returns
    /// `null` if the server hasn't pushed text since the last poll.
    #[wasm_bindgen(js_name = pollRemoteClipboardText)]
    pub fn poll_remote_clipboard_text(&self) -> JsValue {
        let bytes = match self.inner.borrow_mut().clipboard.as_mut() {
            Some(cl) => cl.take_remote_format_data(13),
            None => None,
        };
        let Some(bytes) = bytes else {
            return JsValue::NULL;
        };
        // Decode UTF-16LE, drop trailing NUL.
        let mut units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|w| u16::from_le_bytes([w[0], w[1]]))
            .collect();
        if units.last() == Some(&0) {
            units.pop();
        }
        match String::from_utf16(&units) {
            Ok(s) => JsValue::from_str(&s),
            Err(_) => JsValue::NULL,
        }
    }

    // ── Input forwarding (S4) ──────────────────────────────────────

    /// Send a key-down. `keyCode` is a PS/2 set-1 scancode; the JS
    /// embedder is responsible for KeyboardEvent → scancode mapping
    /// (the demo page ships a US-English subset).
    #[wasm_bindgen(js_name = sendKeyDown)]
    pub async fn send_key_down(&self, key_code: u8, extended: bool) -> Result<(), JsValue> {
        self.send_one(scancode_event(key_code, true, extended)).await
    }

    /// Companion key-up.
    #[wasm_bindgen(js_name = sendKeyUp)]
    pub async fn send_key_up(&self, key_code: u8, extended: bool) -> Result<(), JsValue> {
        self.send_one(scancode_event(key_code, false, extended)).await
    }

    /// Mouse move to absolute desktop pixel `(x, y)`.
    #[wasm_bindgen(js_name = sendMouseMove)]
    pub async fn send_mouse_move(&self, x: u16, y: u16) -> Result<(), JsValue> {
        self.send_one(mouse_move_event(x, y)).await
    }

    /// Mouse button press / release at `(x, y)`. `button` is `0` for
    /// left, `1` for right, `2` for middle (matching `MouseEvent.button`
    /// in the DOM).
    #[wasm_bindgen(js_name = sendMouseButton)]
    pub async fn send_mouse_button(
        &self,
        x: u16,
        y: u16,
        button: u8,
        pressed: bool,
    ) -> Result<(), JsValue> {
        let button = match button {
            0 => MouseButton::Left,
            1 => MouseButton::Right,
            2 => MouseButton::Middle,
            other => {
                return Err(js_error(format!("unknown mouse button index {other}")));
            }
        };
        self.send_one(mouse_button_event(x, y, button, pressed)).await
    }

    /// Mouse wheel rotation. `deltaY` is the vertical step, positive
    /// for "wheel up". Pass `horizontal=true` to translate to a
    /// horizontal-wheel event instead.
    #[wasm_bindgen(js_name = sendMouseWheel)]
    pub async fn send_mouse_wheel(
        &self,
        x: u16,
        y: u16,
        delta: i32,
        horizontal: bool,
    ) -> Result<(), JsValue> {
        self.send_one(mouse_wheel_event(x, y, delta, horizontal)).await
    }

    /// Internal helper: take session, send one input event, put back.
    async fn send_one(
        &self,
        event: justrdp_pdu::rdp::fast_path::FastPathInputEvent,
    ) -> Result<(), JsValue> {
        let mut session = self
            .inner
            .borrow_mut()
            .session
            .take()
            .ok_or_else(|| js_error("not connected"))?;
        let result = session.send_input(&[event]).await;
        // Always put back so a transient error keeps the session usable.
        self.inner.borrow_mut().session = Some(session);
        result.map_err(|e| js_error(format!("send_input: {e}")))?;
        Ok(())
    }

    /// Drop the active session (if any). Idempotent; calling on a
    /// disconnected client is a no-op.
    pub async fn disconnect(&self) -> Result<(), JsValue> {
        let session_opt = self.inner.borrow_mut().session.take();
        let Some(mut session) = session_opt else {
            return Ok(());
        };
        // Best-effort: ignore errors — the embedder already saw the
        // disconnect intent and can move on.
        let _ = session.disconnect().await;
        Ok(())
    }
}

fn serialize_summary(result: &justrdp_connector::ConnectionResult) -> JsValue {
    let obj = Object::new();
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("shareId"),
        &JsValue::from_f64(result.share_id as f64),
    );
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("ioChannelId"),
        &JsValue::from_f64(result.io_channel_id as f64),
    );
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("userChannelId"),
        &JsValue::from_f64(result.user_channel_id as f64),
    );
    let channels = js_sys::Array::new();
    for (name, _id) in &result.channel_ids {
        channels.push(&JsValue::from_str(name));
    }
    let _ = Reflect::set(&obj, &JsValue::from_str("channels"), &channels);
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("selectedProtocol"),
        &JsValue::from_str(&format!("{:?}", result.selected_protocol)),
    );
    obj.into()
}

