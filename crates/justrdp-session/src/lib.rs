#![no_std]
#![forbid(unsafe_code)]

//! Active RDP session processing -- MS-RDPBCGR Phase 4.
//!
//! After the connection sequence completes (`justrdp-connector` reaches `Connected`),
//! the session enters the active phase. This crate processes incoming frames
//! (fast-path and slow-path) and produces [`ActiveStageOutput`] values for the caller.
//!
//! # Usage
//!
//! ```ignore
//! let mut session = ActiveStage::new(connection_result);
//! loop {
//!     let frame = read_frame(&stream).await?;
//!     let outputs = session.process(&frame)?;
//!     for output in outputs {
//!         match output {
//!             ActiveStageOutput::GraphicsUpdate { .. } => { /* render */ }
//!             ActiveStageOutput::ResponseFrame(data) => { stream.write_all(&data).await?; }
//!             ActiveStageOutput::Terminate { .. } => break,
//!             _ => {}
//!         }
//!     }
//! }
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod complete_data;
#[cfg(feature = "alloc")]
mod fast_path_proc;
#[cfg(feature = "alloc")]
mod x224_proc;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use justrdp_bulk::bulk::BulkDecompressor;
#[cfg(feature = "alloc")]
use justrdp_core::{Encode, WriteCursor};
#[cfg(feature = "alloc")]
use justrdp_pdu::rdp::finalization::{MonitorLayoutEntry, SaveSessionInfoData};
#[cfg(feature = "alloc")]
use justrdp_pdu::mcs::{DisconnectProviderUltimatum, DisconnectReason};
#[cfg(feature = "alloc")]
use justrdp_pdu::rdp::fast_path::{FastPathInputEvent, FastPathUpdateType};
#[cfg(feature = "alloc")]
use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE, TPKT_VERSION};
#[cfg(feature = "alloc")]
use justrdp_pdu::x224::{DataTransfer, DATA_TRANSFER_HEADER_SIZE};

#[cfg(feature = "alloc")]
use complete_data::CompleteData;

// ── Shared constants and helpers ──

/// Maximum decompressed output size (16 MiB).
/// Shared between fast-path and slow-path processors to prevent decompression bombs.
#[cfg(feature = "alloc")]
pub(crate) const MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

/// Decompress data with a size cap. Returns an error if the decompressed output
/// exceeds [`MAX_DECOMPRESSED_BYTES`].
///
/// **Defense-in-depth:** Current algorithms (MPPC, NCRUSH, XCRUSH, ZGFX) already
/// enforce internal output caps ≤ 16 MiB, so the post-decompression check here is
/// a safety net. If a new algorithm is added to `BulkDecompressor` without an
/// internal cap, this check prevents unbounded heap growth.
///
/// `context` is a label for error messages (e.g. "fast-path" or "slow-path").
#[cfg(feature = "alloc")]
pub(crate) fn decompress_checked(
    compression_flags: u8,
    data: &[u8],
    decompressor: &mut BulkDecompressor,
    context: &str,
) -> SessionResult<Vec<u8>> {
    let mut decompressed = Vec::new();
    decompressor
        .decompress(compression_flags, data, &mut decompressed)
        .map_err(|e| SessionError::Decompress(alloc::format!("{e:?}")))?;
    if decompressed.len() > MAX_DECOMPRESSED_BYTES {
        return Err(SessionError::Protocol(alloc::format!(
            "{context} decompressed payload exceeds size limit",
        )));
    }
    Ok(decompressed)
}

// ── Public types ──

/// Disconnect reason for [`ActiveStageOutput::Terminate`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GracefulDisconnectReason {
    /// Server sent SetErrorInfoPdu with a specific error code.
    ServerError(u32),
    /// Server sent MCS DisconnectProviderUltimatum.
    /// Value is MCS T.125 disconnect reason (0=DomainDisconnected..4=ChannelPurged).
    ServerDisconnect(DisconnectReason),
    /// Server sent a redirection PDU during active session.
    ServerRedirect,
    /// Server denied our shutdown request.
    ShutdownDenied,
    /// User-initiated disconnect.
    UserRequested,
}

/// Information needed to perform deactivation-reactivation.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeactivationReactivation {
    pub share_id: u32,
}

/// Output produced by [`ActiveStage::process`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveStageOutput {
    /// A response frame that must be sent back to the server.
    ResponseFrame(Vec<u8>),
    /// A graphics update (bitmap data) for a screen region.
    GraphicsUpdate {
        /// Update type (Orders, Bitmap, Palette, SurfaceCommands, Synchronize).
        update_code: FastPathUpdateType,
        /// Raw update data (caller interprets based on update_code).
        data: Vec<u8>,
    },
    /// Server requests the default (arrow) pointer.
    PointerDefault,
    /// Server requests hiding the pointer.
    PointerHidden,
    /// Server sends a pointer position update.
    PointerPosition { x: u16, y: u16 },
    /// Server sends a pointer bitmap (color/new/large/cached).
    /// Embedders that want a fully-decoded sprite call
    /// `justrdp-cursor::decode_color` (and friends in Slices γ / δ)
    /// on `data` plus `pointer_type`. Embedder-side decoding keeps
    /// the cursor sprite cache out of the session crate (the cache
    /// is UI state, not protocol state).
    PointerBitmap {
        /// Pointer update sub-type (slow-path messageType u16 or fast-path update code).
        pointer_type: u16,
        /// Raw pointer data for embedder-side decoding via `justrdp-cursor`.
        data: Vec<u8>,
    },
    /// Server sent Deactivate All PDU -- caller must drive reactivation.
    DeactivateAll(DeactivationReactivation),
    /// Server re-sent Demand Active PDU during active session (deactivation-reactivation).
    /// Caller must re-run the capability exchange using the raw PDU bytes.
    ServerReactivation {
        /// Raw remaining bytes after the ShareControlHeader (the DemandActivePdu body).
        raw_pdu: Vec<u8>,
    },
    /// Session terminated.
    Terminate(GracefulDisconnectReason),
    /// Server sent Save Session Info (logon notification, auto-reconnect cookie, etc.).
    SaveSessionInfo {
        data: SaveSessionInfoData,
    },
    /// Server sent a PDU on a virtual channel.
    ChannelData {
        channel_id: u16,
        data: Vec<u8>,
    },
    /// Server sent a Monitor Layout PDU (MS-RDPBCGR 2.2.12.1).
    ///
    /// Contains the server's current monitor arrangement. Emitted during the active
    /// session when the server reconfigures monitors (e.g., after a display control
    /// layout change triggers deactivation-reactivation).
    ServerMonitorLayout {
        /// Monitor definitions: left/top/right/bottom (inclusive bounding box, signed)
        /// and flags (`TS_MONITOR_PRIMARY` = 0x0000_0001).
        monitors: Vec<MonitorLayoutEntry>,
    },
    /// Server sent a Set Keyboard Indicators PDU (MS-RDPBCGR 2.2.8.2.1.1).
    ///
    /// Updates the client's CapsLock / NumLock / ScrollLock / Kana state to
    /// match the server's keyboard model. The runtime forwards the raw flag
    /// bits; whether and how to apply them to OS-level LEDs is the caller's
    /// responsibility (Linux X11/Wayland, Windows SetKeyboardState, etc.).
    KeyboardIndicators {
        /// Raw led flags. Bit 0 = Scroll Lock, bit 1 = Num Lock,
        /// bit 2 = Caps Lock, bit 3 = Kana Lock.
        led_flags: u16,
    },
    /// Server sent a Set Keyboard IME Status PDU (MS-RDPBCGR 2.2.8.2.2.1).
    ///
    /// Used by East Asian language stacks to mirror IME activation state
    /// (open/closed) and conversion mode between server and client.
    KeyboardImeStatus {
        /// IME open state (non-zero = open). MS-RDPBCGR 2.2.8.2.2.1: DWORD.
        ime_state: u32,
        /// IME conversion mode bitfield (language-specific).
        ime_conv_mode: u32,
    },
    /// Server sent a Play Sound PDU (MS-RDPBCGR 2.2.9.1.1.5.1).
    ///
    /// Instructs the client to emit a system beep. Most clients ignore this
    /// in favor of audio redirection over RDPSND, but it remains the only
    /// way to play a beep before the audio channel is up.
    PlaySound {
        /// Duration of the beep in milliseconds.
        duration_ms: u32,
        /// Frequency of the beep in hertz.
        frequency_hz: u32,
    },
    /// Server sent a Suppress Output PDU (MS-RDPBCGR 2.2.11.3).
    ///
    /// Tells the client to pause (`allow_display_updates == false`) or resume
    /// (`true`) painting display updates. When resuming, the server includes
    /// an inclusive rectangle that should be considered dirty and repainted.
    SuppressOutput {
        /// `true` if the client should allow display updates, `false` to pause.
        allow_display_updates: bool,
        /// Optional dirty rectangle `(left, top, right, bottom)` accompanying
        /// a resume signal. `None` when display updates are being paused.
        rect: Option<(u16, u16, u16, u16)>,
    },
}

/// Session processing error.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub enum SessionError {
    /// PDU decode error.
    Decode(justrdp_core::DecodeError),
    /// PDU encode error.
    Encode(justrdp_core::EncodeError),
    /// Decompression error.
    Decompress(String),
    /// Protocol violation.
    Protocol(String),
}

#[cfg(feature = "alloc")]
impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "decode error: {e}"),
            Self::Encode(e) => write!(f, "encode error: {e}"),
            Self::Decompress(msg) => write!(f, "decompression error: {msg}"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
        }
    }
}

#[cfg(feature = "alloc")]
impl From<justrdp_core::DecodeError> for SessionError {
    fn from(e: justrdp_core::DecodeError) -> Self {
        Self::Decode(e)
    }
}

#[cfg(feature = "alloc")]
impl From<justrdp_core::EncodeError> for SessionError {
    fn from(e: justrdp_core::EncodeError) -> Self {
        Self::Encode(e)
    }
}

#[cfg(feature = "alloc")]
pub type SessionResult<T> = Result<T, SessionError>;

// ── ActiveStage ──

/// Connection result from the connector (re-exported subset needed for session).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub io_channel_id: u16,
    pub user_channel_id: u16,
    pub share_id: u32,
    /// Channel name → MCS channel ID mapping.
    pub channel_ids: Vec<(String, u16)>,
}

/// Active session processor.
///
/// Accepts incoming RDP frames and produces [`ActiveStageOutput`] values.
#[cfg(feature = "alloc")]
pub struct ActiveStage {
    config: SessionConfig,
    /// Decompressor for slow-path data (separate context per MS-RDPBCGR 3.2.5.3).
    slow_path_decompressor: BulkDecompressor,
    /// Decompressor for fast-path data (separate context per MS-RDPBCGR 3.2.5.3).
    fast_path_decompressor: BulkDecompressor,
    complete_data: CompleteData,
    /// Last error info received from server (for correlating with disconnect).
    last_error_info: u32,
}

#[cfg(feature = "alloc")]
impl ActiveStage {
    /// Create a new active session processor.
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            slow_path_decompressor: BulkDecompressor::new(),
            fast_path_decompressor: BulkDecompressor::new(),
            complete_data: CompleteData::new(),
            last_error_info: 0,
        }
    }

    /// Process an incoming frame (complete PDU, as delimited by `TpktHint`).
    ///
    /// Returns a list of outputs that the caller should handle.
    pub fn process(&mut self, frame: &[u8]) -> SessionResult<Vec<ActiveStageOutput>> {
        if frame.is_empty() {
            return Ok(vec![]);
        }

        // Discriminate fast-path vs slow-path by first byte.
        // MS-RDPBCGR 2.2.1.1: TPKT version byte is 0x03.
        // MS-RDPBCGR 2.2.9.1.2: fast-path action field occupies bits 0-1.
        if frame[0] == TPKT_VERSION {
            self.process_slow_path(frame)
        } else {
            self.process_fast_path(frame)
        }
    }

    /// Build a fast-path input frame from input events.
    ///
    /// Returns the encoded frame bytes ready to send to the server.
    pub fn encode_input_events(&self, events: &[FastPathInputEvent]) -> SessionResult<Vec<u8>> {
        fast_path_proc::encode_fast_path_input(events)
    }

    /// Build a graceful shutdown request frame.
    pub fn encode_shutdown_request(&self) -> SessionResult<Vec<u8>> {
        x224_proc::encode_shutdown_request(
            self.config.user_channel_id,
            self.config.io_channel_id,
            self.config.share_id,
        )
    }

    /// Build a Refresh Rect PDU frame (MS-RDPBCGR 2.2.11.2). Tells the
    /// server to re-emit the listed inclusive rectangles. Useful after
    /// a window restore / first-paint to force the server to send a
    /// fresh bitmap update.
    pub fn encode_refresh_rect(
        &self,
        areas: &[justrdp_pdu::rdp::finalization::InclusiveRect],
    ) -> SessionResult<Vec<u8>> {
        x224_proc::encode_refresh_rect(
            self.config.user_channel_id,
            self.config.io_channel_id,
            self.config.share_id,
            areas,
        )
    }

    /// Build a Suppress Output PDU frame (MS-RDPBCGR 2.2.11.3). Pass
    /// `allow=false` to pause display updates (e.g. window minimize),
    /// `allow=true` with the visible viewport rect to resume.
    pub fn encode_suppress_output(
        &self,
        allow: bool,
        rect: Option<justrdp_pdu::rdp::finalization::InclusiveRect>,
    ) -> SessionResult<Vec<u8>> {
        x224_proc::encode_suppress_output(
            self.config.user_channel_id,
            self.config.io_channel_id,
            self.config.share_id,
            allow,
            rect,
        )
    }

    /// Build an MCS DisconnectProviderUltimatum frame (for immediate disconnect).
    pub fn encode_disconnect(&self) -> SessionResult<Vec<u8>> {
        let dpu = DisconnectProviderUltimatum {
            reason: DisconnectReason::UserRequested,
        };
        let inner_size = DATA_TRANSFER_HEADER_SIZE + dpu.size();
        let mut buf = vec![0u8; TPKT_HEADER_SIZE + inner_size];
        let mut cursor = WriteCursor::new(&mut buf);
        TpktHeader::try_for_payload(inner_size)?.encode(&mut cursor)?;
        DataTransfer.encode(&mut cursor)?;
        dpu.encode(&mut cursor)?;
        Ok(buf)
    }

    /// Get the session configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    // ── Fast-path processing ──

    fn process_fast_path(&mut self, frame: &[u8]) -> SessionResult<Vec<ActiveStageOutput>> {
        fast_path_proc::process_fast_path_output(
            frame,
            &mut self.fast_path_decompressor,
            &mut self.complete_data,
        )
    }

    // ── Slow-path processing ──

    fn process_slow_path(&mut self, frame: &[u8]) -> SessionResult<Vec<ActiveStageOutput>> {
        x224_proc::process_slow_path(
            frame,
            &self.config,
            &mut self.slow_path_decompressor,
            &mut self.last_error_info,
        )
    }
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for ActiveStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ActiveStage")
            .field("config", &self.config)
            .finish()
    }
}
