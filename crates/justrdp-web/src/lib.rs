#![forbid(unsafe_code)]
#![doc = "Transport-agnostic web / WASM bindings for JustRDP."]
#![doc = ""]
#![doc = "## Architecture"]
#![doc = ""]
#![doc = "Two layers, deliberately separated so embedders are not forced into"]
#![doc = "any single transport:"]
#![doc = ""]
#![doc = "1. **Core (transport-agnostic)** — [`WebTransport`] trait + error"]
#![doc = "   types. No browser, no WebSocket. Anyone shipping a custom RDP"]
#![doc = "   gateway, WebTransport, WebRTC DataChannel, or Tauri-style native"]
#![doc = "   bridge implements the trait and reuses the rest of this crate."]
#![doc = "2. **Reference WebSocket transport** — [`WebSocketTransport`] (only"]
#![doc = "   compiled for `wasm32` + `feature = \"websocket\"`). A thin wrapper"]
#![doc = "   over `web_sys::WebSocket` covering the 90% case (raw RDP bytes"]
#![doc = "   over a WS bridge such as wsproxy)."]
#![doc = ""]
#![doc = "Later steps add `WasmConnector<T: WebTransport>`, Canvas/WebGL"]
#![doc = "rendering, input forwarding, and channel adapters — all parameterized"]
#![doc = "over the trait so the choice of transport never leaks upward."]

extern crate alloc;

mod audio;
mod clipboard;
mod input;
mod render;

#[cfg(target_arch = "wasm32")]
mod canvas;

#[cfg(all(feature = "websocket", target_arch = "wasm32"))]
mod websocket;

#[cfg(all(feature = "native-tcp", not(target_arch = "wasm32")))]
mod native_tcp;

#[cfg(all(feature = "native-tls", not(target_arch = "wasm32")))]
mod native_tls;

#[cfg(all(feature = "native-nla", not(target_arch = "wasm32")))]
mod native_nla;

#[cfg(target_arch = "wasm32")]
mod js;

pub use audio::{AudioChannel, AudioChannelError, AudioFrame, AudioState};
pub use clipboard::{ClipboardChannel, ClipboardChannelError, ClipboardState};
// `WebTransport` family + driver / session pump live in `justrdp-async`
// since §5.6.1 Phase 1. Re-exported here so existing embedders keep
// compiling against `justrdp_web::WebClient` etc.
pub use justrdp_async::{
    ActiveSession, CredsspDriver, DriverError, PointerEvent, SessionEvent, TlsUpgrade,
    TransportError, TransportErrorKind, WebClient, WebTransport, MAX_HANDSHAKE_PDU_SIZE,
};
pub use input::{
    mouse_button_event, mouse_move_event, mouse_wheel_event, scancode_event, MouseButton,
    KBDFLAGS_EXTENDED, KBDFLAGS_RELEASE,
};
pub use render::{
    decode_bitmap_update_fast_path, render_event, BitmapRenderer, DecodedRect, FrameSink,
    GlyphCacheRevision, RenderError,
};

#[cfg(target_arch = "wasm32")]
pub use canvas::CanvasFrameSink;

#[cfg(all(feature = "websocket", target_arch = "wasm32"))]
pub use websocket::{WebSocketConfig, WebSocketTransport};

#[cfg(all(feature = "native-tcp", not(target_arch = "wasm32")))]
pub use native_tcp::NativeTcpTransport;

#[cfg(all(feature = "native-tls", not(target_arch = "wasm32")))]
pub use native_tls::{NativeTlsTransport, NativeTlsUpgrade};

#[cfg(all(feature = "native-nla", not(target_arch = "wasm32")))]
pub use native_nla::NativeCredsspDriver;
