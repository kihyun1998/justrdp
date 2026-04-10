#![forbid(unsafe_code)]

//! Events emitted by [`crate::RdpClient::next_event`].
//!
//! This enum is a superset of `justrdp_session::ActiveStageOutput` translated
//! into a runtime-friendly shape, plus events that only the blocking layer
//! can produce (reconnect, redirect).

use justrdp_pdu::rdp::fast_path::FastPathUpdateType;
use justrdp_session::GracefulDisconnectReason;

/// Events emitted from the active session loop.
#[derive(Debug, Clone)]
pub enum RdpEvent {
    /// Server sent a graphics update. Raw data; decode with `justrdp-graphics`
    /// or `justrdp-egfx` depending on the update code.
    GraphicsUpdate {
        update_code: FastPathUpdateType,
        data: Vec<u8>,
    },

    /// Mouse cursor moved to an absolute position.
    PointerPosition { x: u16, y: u16 },
    /// Server requested default (arrow) pointer.
    PointerDefault,
    /// Server requested hiding the pointer.
    PointerHidden,
    /// Server sent a pointer bitmap update.
    PointerBitmap { pointer_type: u16, data: Vec<u8> },

    /// Server sent a keyboard indicator update (Caps/Num/Scroll/Kana).
    /// OS LED syncing is intentionally the caller's responsibility.
    /// *Scaffold: not yet populated.*
    KeyboardIndicators {
        scroll: bool,
        num: bool,
        caps: bool,
        kana: bool,
    },

    /// Server requested an IME status update.
    /// *Scaffold: not yet populated.*
    ImeStatus { state: u32, convert: u32 },

    /// Server sent a Play Sound (beep) PDU.
    /// *Scaffold: not yet populated.*
    PlaySound { frequency: u32, duration_ms: u32 },

    /// Server requested rendering pause/resume.
    /// *Scaffold: not yet populated.*
    SuppressOutput { allow: bool },

    /// Server sent Save Session Info (logon notifications, ARC cookie, etc.).
    /// The raw enum variant is forwarded so callers can inspect type.
    SaveSessionInfo(justrdp_pdu::rdp::finalization::SaveSessionInfoData),

    /// Server sent a monitor layout update during the active session.
    ServerMonitorLayout {
        monitors: Vec<justrdp_pdu::rdp::finalization::MonitorLayoutEntry>,
    },

    /// A virtual channel delivered an opaque PDU. Dispatch via SVC/DVC processors.
    ChannelData { channel_id: u16, data: Vec<u8> },

    /// The blocking layer is attempting to reconnect after a drop.
    /// *Scaffold: not yet populated — will be emitted by Auto-Reconnect runtime (9.2).*
    Reconnecting { attempt: u32 },
    /// Reconnection succeeded. *Scaffold: not yet populated.*
    Reconnected,

    /// The server sent a Session Redirection PDU and the blocking layer
    /// is switching to the new target.
    /// *Scaffold: not yet populated — will be emitted by Session Redirection runtime (9.3).*
    Redirected { target: String },

    /// The session has terminated.
    Disconnected(GracefulDisconnectReason),
}
