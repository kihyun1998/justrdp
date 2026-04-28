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

mod clipboard;
mod driver;
mod error;
mod input;
mod render;
mod session;
mod transport;

#[cfg(target_arch = "wasm32")]
mod canvas;

#[cfg(all(feature = "websocket", target_arch = "wasm32"))]
mod websocket;

#[cfg(target_arch = "wasm32")]
mod js;

pub use clipboard::{ClipboardChannel, ClipboardChannelError, ClipboardState};
pub use driver::{
    CredsspDriver, DriverError, TlsUpgrade, WebClient, MAX_HANDSHAKE_PDU_SIZE,
};
pub use error::{TransportError, TransportErrorKind};
pub use input::{
    mouse_button_event, mouse_move_event, mouse_wheel_event, scancode_event, MouseButton,
    KBDFLAGS_EXTENDED, KBDFLAGS_RELEASE,
};
pub use render::{
    decode_bitmap_update_fast_path, render_event, BitmapRenderer, DecodedRect, FrameSink,
    GlyphCacheRevision, RenderError,
};
pub use session::{ActiveSession, PointerEvent, SessionEvent};
pub use transport::WebTransport;

#[cfg(target_arch = "wasm32")]
pub use canvas::CanvasFrameSink;

#[cfg(all(feature = "websocket", target_arch = "wasm32"))]
pub use websocket::{WebSocketConfig, WebSocketTransport};
