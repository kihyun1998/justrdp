//! The sans-IO session state machine (ADR-0001): after the connect machine reaches
//! `session-active`, this machine consumes raw socket bytes and produces [`SessionOutput`]s —
//! decoded [`FrameUpdate`]s for the host's frame sink, and the occasional outbound frame
//! (Deactivation–Reactivation re-runs capability exchange in-session, plan.md §0's resize
//! trap). Implemented so far: slow-path *and* fast-path output graphics (bitmap + palette
//! updates, with fast-path fragment reassembly — slice-6) and outbound keyboard/mouse input
//! (slice-7), and slow-path pointer updates. Orders are a later slice: an order update falls
//! to the dispatch's catch-all with its cursor unread — **skipped, not decoded** (the phrase
//! here said "decoded-and-skipped" until #252, and neither half was true of it). The
//! robustness policy is unchanged (plan.md §11c: unknown-but-well-formed never kills the
//! session, malformed input does); what changed is the claim about *how* it is unknown.

use crate::cursor::{CursorEvent, CursorImage};
use crate::disconnect::{DisconnectReason, ServerDisconnectCause};
use crate::dvc::{Drdynvc, DvcError, DvcEvent, DynamicChannelError};
use crate::framebuffer::{FrameUpdate, Framebuffer};
use justrdp_codecs::color::{self, Palette};
use justrdp_codecs::{nscodec, planar, pointer as pointer_codec, rle};
use justrdp_pdu::capability::{self, CapabilitySet};
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::input::InputEvent;
use justrdp_pdu::pointer::PointerUpdate;
use justrdp_pdu::surface_commands::{self, SurfaceBits, SurfaceCommand};
use justrdp_pdu::{
    displaycontrol, dvc, fastpath, finalization, input, mcs, pointer, session_info, share, sound,
    svc, tpkt, update, x224,
};

/// Everything the session machine needs from the completed connect sequence: channel
/// addressing from [`crate::McsConnectResult`], the share state from
/// [`crate::ActivationResult`], and the same capability list the connect config carried (the
/// reactivation Confirm Active re-sends it, with the freshly negotiated size patched into the
/// Bitmap set exactly as at connect time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    /// The user channel ID (`initiator` for outbound MCS data).
    pub user_channel_id: u16,
    /// The I/O channel ID all share PDUs ride on.
    pub io_channel_id: u16,
    /// The share ID from activation.
    pub share_id: u32,
    /// The negotiated desktop size — the framebuffer's initial dimensions.
    pub desktop_size: (u16, u16),
    /// The Confirm Active capability sets (caller-owned, verbatim — plan.md §0).
    pub capabilities: Vec<CapabilitySet>,
    /// The server's `inputFlags` from its Demand Active Input capability set
    /// ([`crate::ActivationResult::server_capabilities`]). Selects the input transport:
    /// fast-path when the server advertised `INPUT_FLAG_FASTPATH_INPUT`/`INPUT2`, the
    /// slow-path Input Event PDU otherwise.
    pub server_input_flags: u16,
    /// The MCS channel ID the server granted for the `drdynvc` static channel
    /// ([`crate::McsConnectResult::static_channels`], entry named `"drdynvc"`), or `None` if
    /// the channel was not requested/granted — dynamic channels (Display Control resize,
    /// EGFX, …) are then unavailable.
    pub drdynvc_channel_id: Option<u16>,
    /// The granted static channels ([`crate::McsConnectResult::static_channels`]). Every one
    /// but [`Self::drdynvc_channel_id`] is the host's: its messages surface as
    /// [`SessionOutput::ChannelData`] and [`SessionStateMachine::send_channel`] sends on it.
    pub static_channels: Vec<crate::StaticChannel>,
    /// The dynamic channel names the host terminates (ADR-0018): a Create Request for one is
    /// accepted, and its messages surface as [`SessionOutput::DynamicChannelData`]. A name the
    /// core terminates (Display Control, the Graphics Pipeline) is refused by
    /// [`SessionStateMachine::new`].
    pub dynamic_channels: Vec<String>,
    /// What the graphics channel advertises when the server opens it.
    pub egfx: crate::EgfxConfig,
}

/// How many desktops' worth of decoded pixels one graphics update may buy (#367).
pub(crate) const PAINT_BUDGET_FRAMEBUFFERS: usize = 2;

/// What one bitmap rectangle or surface-bits command did.
enum Painted {
    /// Decoded, with the dirty rectangle it left, if any.
    Frame(Option<FrameUpdate>),
    /// Not decoded: it would have spent more than the update's paint budget had left.
    OverBudget,
}

/// Spend `cost` from `budget`, or leave it untouched and return `false` when it does not fit.
fn charge(budget: &mut usize, cost: usize) -> bool {
    match budget.checked_sub(cost) {
        Some(left) => {
            *budget = left;
            true
        }
        None => false,
    }
}

/// Record that an update was cut short by its paint budget (#367; ADR-0009 §3(b)).
fn note_paint_budget(update: &'static str, declared: usize, painted: usize) {
    tracing::warn!(
        target: "rdp_paint_budget",
        update,
        declared,
        painted,
        skipped = declared - painted,
        "paint budget reached; the remaining commands of this update were skipped",
    );
}

/// One effect of feeding bytes to the machine, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOutput {
    /// Fresh pixels for the host's frame sink.
    Frame(FrameUpdate),
    /// A cursor change for the host's cursor sink (issue #41).
    Cursor(CursorEvent),
    /// Bytes the adapter must write to the socket (reactivation / drdynvc traffic).
    WriteBytes(Vec<u8>),
    /// The Display Control channel is open and the server's caps arrived:
    /// [`SessionStateMachine::request_resize`] is valid from now on.
    DisplayControlReady,
    /// The server refused a [`SessionStateMachine::request_shutdown`] — `[MS-RDPBCGR]` 2.2.2.2.
    /// The session is **unaffected**: it keeps running and the host may carry on or give up.
    ShutdownDenied,
    /// Who logged on, into which session, whether the logon carried an error, and the cookie
    /// that would resume it — `[MS-RDPBCGR]` 2.2.10.1 (issue #304).
    ///
    /// What the host does with any of it is the host's (CLAUDE.md): 3.2.5.10.1 says only that
    /// the client SHOULD save the cookie and MAY act on the rest. A logon error here is a
    /// **notification, not a disconnect** — unlike [`Self::ShutdownDenied`] it may precede one,
    /// and the attribution for a close that follows is still Set Error Info.
    SaveSessionInfo(session_info::SaveSessionInfo),
    /// The server's view of the keyboard locks — `[MS-RDPBCGR]` 2.2.8.2.1.1 (issue #305), in
    /// the bits of [`InputEvent::Sync`]. What the host does with it (LEDs, a status display,
    /// nothing) is the host's.
    KeyboardIndicators(input::KeyboardIndicators),
    /// The server asked for a beep — `[MS-RDPBCGR]` 2.2.9.1.1.5 (issue #354), the PDU the
    /// default Sound capability set invites. Whether and how it sounds is the host's.
    PlaySound(sound::PlaySound),
    /// One whole message on a static channel the host requested (issue #307), reassembled
    /// from its chunks (`[MS-RDPBCGR]` 3.1.5.2.2). What the bytes mean is the host's.
    ChannelData {
        /// The MCS channel ID it arrived on, as in [`SessionConfig::static_channels`].
        channel: u16,
        /// The message.
        data: Vec<u8>,
    },
    /// A message on a host static channel was larger than that channel's message cap
    /// ([`SessionStateMachine::set_channel_message_cap`]), so it was skipped unbuffered. The
    /// session goes on.
    ChannelMessageDropped {
        /// The MCS channel ID it arrived on.
        channel: u16,
        /// Its declared length.
        total_length: usize,
    },
    /// The server opened a dynamic channel the host registered in
    /// [`SessionConfig::dynamic_channels`] (ADR-0018). Messages and sends on it use
    /// `channel_id` until [`Self::DynamicChannelClosed`] names it, or until the host closes it
    /// with [`SessionStateMachine::close_dynamic_channel`].
    DynamicChannelOpened {
        /// The name the host registered.
        name: String,
        /// The id the server gave the channel.
        channel_id: u32,
    },
    /// One whole message on a host dynamic channel, reassembled from its data PDUs
    /// (`[MS-RDPEDYC]` 3.1.5.2). What the bytes mean is the host's.
    DynamicChannelData {
        /// The channel's id, as in [`Self::DynamicChannelOpened`].
        channel_id: u32,
        /// The message.
        data: Vec<u8>,
    },
    /// The server closed a host dynamic channel, or reused its id for a new channel.
    DynamicChannelClosed {
        /// The channel's id.
        channel_id: u32,
    },
}

/// Record one Save Session Info at its arrival, for whichever leg received it.
///
/// Shared because the connect leg and the session leg both dispatch this PDU, and the existing
/// asymmetry is already a known hole: `on_data_pdu`'s reactivation arms note that `connect.rs`
/// emits an `rdp_finalization` record per reply while they emit nothing. One function is the
/// same move `Control::check_server_action` made for a value check in #252 — one family, one
/// answer, whichever leg asks.
///
/// `arcRandomBits` is never a field here. It is the HMAC key that resumes the session
/// (`[MS-RDPBCGR]` 5.5), and a log is exactly the place it must not reach — which is also why
/// [`session_info::ServerAutoReconnect`] hand-writes its `Debug`.
pub(crate) fn log_save_session_info(leg: &'static str, info: &session_info::SaveSessionInfo) {
    match info {
        session_info::SaveSessionInfo::Logon(i) | session_info::SaveSessionInfo::LogonLong(i) => {
            tracing::debug!(
                target: "rdp_save_session_info",
                leg,
                session_id = i.session_id,
                domain = %i.domain,
                user = %i.user,
                "server logon info"
            );
        }
        session_info::SaveSessionInfo::PlainNotify => {
            tracing::debug!(target: "rdp_save_session_info", leg, "server plain logon notify");
        }
        session_info::SaveSessionInfo::Extended(ext) => {
            tracing::debug!(
                target: "rdp_save_session_info",
                leg,
                fields_present = format_args!("{:#010x}", ext.fields_present),
                cookie_logon_id = ext.auto_reconnect.as_ref().map(|c| c.logon_id),
                "server extended logon info"
            );
            if let Some(err) = ext.logon_error {
                tracing::info!(
                    target: "rdp_logon_error",
                    leg,
                    notification_type = format_args!("{:#010x}", err.notification_type.as_u32()),
                    notification_data = format_args!("{:#010x}", err.notification_data),
                    data_is_session_id = err.notification_type.data_is_session_id(),
                    description = %err.description(),
                    "server logon notification"
                );
            }
        }
        session_info::SaveSessionInfo::Unknown { info_type } => {
            tracing::debug!(
                target: "rdp_save_session_info",
                leg,
                info_type = format_args!("{info_type:#010x}"),
                "server Save Session Info of an undefined infoType"
            );
        }
    }
}

/// Why a [`SessionStateMachine::request_resize`] call was refused (the session itself is
/// unaffected — the host may retry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeError {
    /// The drdynvc channel was not granted, the server has not created the Display Control
    /// channel, or its caps have not arrived yet (wait for
    /// [`SessionOutput::DisplayControlReady`]).
    NotReady,
    /// The dimensions are outside MS-RDPEDISP 2.2.2.2.1's 200–8192 range, or the area
    /// exceeds what the server's caps allow.
    InvalidDimensions {
        /// Why the dimensions were rejected.
        reason: &'static str,
    },
    /// The desktop scale factor is outside 2.2.2.2.1's 100–500 percent, where the server
    /// would ignore it.
    InvalidScaleFactor {
        /// The rejected desktop scale factor, in percent.
        desktop_scale_factor: u32,
    },
}

/// A client-initiated resize for [`SessionStateMachine::request_resize`]: one primary monitor
/// with the host's size, scale factors and orientation (MS-RDPEDISP 2.2.2.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResizeRequest {
    /// Desktop width; an odd value is rounded down, as the spec forbids it.
    pub width: u16,
    /// Desktop height.
    pub height: u16,
    /// `DesktopScaleFactor`, in percent (100–500).
    pub desktop_scale_factor: u32,
    /// `DeviceScaleFactor`.
    pub device_scale_factor: displaycontrol::DeviceScaleFactor,
    /// `Orientation`.
    pub orientation: displaycontrol::Orientation,
}

impl ResizeRequest {
    /// A resize to `width` × `height` at 100 percent, not rotated.
    pub fn new(width: u16, height: u16) -> Self {
        Self {
            width,
            height,
            desktop_scale_factor: displaycontrol::MIN_DESKTOP_SCALE_FACTOR,
            device_scale_factor: displaycontrol::DeviceScaleFactor::Percent100,
            orientation: displaycontrol::Orientation::Landscape,
        }
    }

    /// The same request with these scale factors.
    pub fn with_scale(
        self,
        desktop_scale_factor: u32,
        device_scale_factor: displaycontrol::DeviceScaleFactor,
    ) -> Self {
        Self {
            desktop_scale_factor,
            device_scale_factor,
            ..self
        }
    }

    /// The same request with this orientation.
    pub fn with_orientation(self, orientation: displaycontrol::Orientation) -> Self {
        Self {
            orientation,
            ..self
        }
    }
}

impl core::fmt::Display for ResizeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResizeError::NotReady => {
                write!(f, "Display Control is not ready (no channel or caps yet)")
            }
            ResizeError::InvalidDimensions { reason } => {
                write!(f, "invalid resize dimensions: {reason}")
            }
            ResizeError::InvalidScaleFactor {
                desktop_scale_factor,
            } => write!(
                f,
                "desktop scale factor {desktop_scale_factor}% is outside 100–500 \
                 (MS-RDPEDISP 2.2.2.2.1)"
            ),
        }
    }
}

impl core::error::Error for ResizeError {}

/// Why [`SessionStateMachine::send_channel`] or
/// [`SessionStateMachine::set_channel_message_cap`] was refused (the session itself is
/// unaffected). Only `send_channel` can return [`ChannelSendError::SuspendedQueueFull`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSendError {
    /// The channel is not one of [`SessionConfig::static_channels`].
    NotGranted {
        /// The MCS channel ID asked for.
        channel: u16,
    },
    /// The channel is `drdynvc`, whose traffic the machine itself produces.
    CoreOwned {
        /// The MCS channel ID asked for.
        channel: u16,
    },
    /// The server suspended virtual channel traffic and the messages held for its resume
    /// would exceed 64 MiB with this one, whatever the channel's receive cap.
    SuspendedQueueFull {
        /// The MCS channel ID asked for.
        channel: u16,
    },
}

impl core::fmt::Display for ChannelSendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChannelSendError::NotGranted { channel } => {
                write!(f, "static channel {channel} was not granted")
            }
            ChannelSendError::CoreOwned { channel } => {
                write!(
                    f,
                    "static channel {channel} is drdynvc, which the session owns"
                )
            }
            ChannelSendError::SuspendedQueueFull { channel } => write!(
                f,
                "virtual channel traffic is suspended and the held messages would exceed 64 MiB \
                 (channel {channel})"
            ),
        }
    }
}

impl core::error::Error for ChannelSendError {}

/// Why the session failed. Malformed server data is fatal (likely protocol desync,
/// plan.md §11c); everything else never reaches this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// A malformed PDU.
    Decode(justrdp_pdu::DecodeError),
    /// A dynamic channel's processor rejected a complete channel message (ADR-0014 Decision 2).
    ///
    /// Only a processor's own verdict lands here. A failure of the drdynvc transport under it —
    /// SVC chunking, a malformed drdynvc PDU, a reassembly cap — is [`Self::Decode`], even on a
    /// channel that is open.
    DynamicChannel {
        /// The channel name the server created it under, e.g.
        /// `"Microsoft::Windows::RDS::Graphics"`.
        channel: &'static str,
        /// What the processor returned.
        error: justrdp_pdu::DecodeError,
    },
    /// The desktop size the server declared cannot be allocated
    /// ([`crate::framebuffer::FramebufferError`]).
    ///
    /// Reachable three ways, all server-driven and none clamped before arrival: the
    /// `SessionConfig` the connect sequence hands over, a reactivation `DemandActive`, and a
    /// EGFX `OutputResized`. Refused rather than clamped because a silent tolerance
    /// is indistinguishable from a bug (ADR-0009 §3(b)).
    ///
    /// Only the third has a channel to name, and it is named — the refusal happens here rather
    /// than inside `DvcProcessor::process`, so [`Self::DynamicChannel`] cannot carry it
    /// (ADR-0014's 2026-09-16 amendment, #286).
    Framebuffer {
        /// The dynamic channel whose PDU declared the size, for the one of the three paths
        /// that has one; `None` for the connect sequence and for a reactivation Demand Active.
        channel: Option<&'static str>,
        /// Why the framebuffer refused it.
        error: crate::framebuffer::FramebufferError,
    },
    /// [`SessionConfig::egfx`] cannot be advertised.
    EgfxConfig(crate::EgfxConfigError),
    /// [`SessionConfig::dynamic_channels`] names a channel the core terminates.
    DynamicChannelConfig(crate::dvc::CoreOwnedDynamicChannel),
    /// Interleaved-RLE bitmap data failed to decompress.
    Rle(rle::RleError),
    /// RDP6 planar bitmap data failed to decompress.
    Planar(planar::PlanarError),
    /// Decoded pixels could not be converted (bad depth / short buffer).
    Color(color::ColorError),
    /// A pointer shape failed to decode (bad mask sizes / unsupported depth).
    Pointer(pointer_codec::PointerError),
    /// NSCodec bitmap data in a Set Surface Bits command failed to decode.
    Nscodec(nscodec::NscError),
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionError::Decode(e) => write!(f, "malformed session PDU: {e}"),
            SessionError::DynamicChannel { channel, error } => {
                write!(f, "dynamic channel {channel}: {error}")
            }
            SessionError::EgfxConfig(e) => write!(f, "EGFX config: {e}"),
            SessionError::DynamicChannelConfig(e) => write!(f, "dynamic channel config: {e}"),
            SessionError::Rle(e) => write!(f, "interleaved RLE: {e}"),
            SessionError::Planar(e) => write!(f, "RDP6 planar: {e}"),
            SessionError::Color(e) => write!(f, "pixel conversion: {e}"),
            SessionError::Pointer(e) => write!(f, "pointer shape: {e}"),
            SessionError::Nscodec(e) => write!(f, "NSCodec surface bits: {e}"),
            SessionError::Framebuffer {
                channel: Some(channel),
                error,
            } => write!(f, "framebuffer, from dynamic channel {channel}: {error}"),
            SessionError::Framebuffer {
                channel: None,
                error,
            } => write!(f, "framebuffer: {error}"),
        }
    }
}

impl core::error::Error for SessionError {}

impl From<DvcError> for SessionError {
    fn from(error: DvcError) -> Self {
        match error {
            DvcError::Transport(e) => SessionError::Decode(e),
            DvcError::Processor { channel, error } => {
                SessionError::DynamicChannel { channel, error }
            }
        }
    }
}

/// The event a decoded shape surfaces as: zero-sized shapes are the wire form of "no shape"
/// (servers send them to blank the cursor), so they arrive as [`CursorEvent::Hidden`].
fn cursor_event_for(image: CursorImage) -> CursorEvent {
    if image.rgba.is_empty() {
        CursorEvent::Hidden
    } else {
        CursorEvent::Set(image)
    }
}

/// Where the machine stands in the (re)activation cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Live: graphics PDUs update the framebuffer.
    Active,
    /// The server sent DeactivateAll; waiting for its next Demand Active.
    Deactivated,
    /// Confirm Active + finalization batch sent; waiting for the Font Map.
    Reactivating,
}

/// The sans-IO session machine. Feed it socket bytes with
/// [`SessionStateMachine::process_bytes`]; it never touches the socket itself.
#[derive(Debug)]
pub struct SessionStateMachine {
    config: SessionConfig,
    framebuffer: Framebuffer,
    palette: Palette,
    phase: Phase,
    /// Unprocessed socket bytes (TPKT reassembly, same contract as the connect machine).
    inbox: Vec<u8>,
    /// Reassembly buffer for a fragmented fast-path update (FIRST … NEXT … LAST), keyed by
    /// the update code in flight (fragments of one update are never interleaved with
    /// another's — MS-RDPBCGR 2.2.9.1.2.1).
    fragment: Option<(u8, Vec<u8>)>,
    /// The pointer cache (issue #41), sized from the Pointer capability set the caller
    /// advertised — Color/New shapes store into it, Cached re-selects from it. It survives
    /// deactivation–reactivation (the cache belongs to the connection, not the share).
    cursor_cache: Vec<Option<CursorImage>>,
    /// The server's latest Set Error Info attribution (issue #42); `ERRINFO_NONE` clears it.
    error_info: Option<justrdp_pdu::errinfo::ErrorInfo>,
    /// The reason from a received MCS Disconnect Provider Ultimatum (issue #42).
    ultimatum_reason: Option<u8>,
    /// The drdynvc transport + Display Control state (slice-8).
    drdynvc: Drdynvc,
    /// Chunk reassembly for each host static channel, keyed by MCS channel ID.
    channels: Vec<(u16, crate::svc::Reassembler)>,
    /// Outbound virtual channel frames held while the server has suspended virtual channel
    /// traffic (`CHANNEL_FLAG_SUSPEND`); `None` while it flows.
    suspended: Option<Vec<Vec<u8>>>,
    /// Bytes of host messages among the held frames.
    held_bytes: usize,
    /// The Surface Commands `cmdFlags` the Confirm Active advertised.
    surface_commands: u32,
    /// Whether the Confirm Active advertised NSCodec, so Set Surface Bits may carry
    /// [`capability::CODEC_ID_NSCODEC`].
    nscodec_advertised: bool,
}

impl SessionStateMachine {
    /// Build the machine straight off the connect results. `leftover` is
    /// [`crate::ActivationResult::leftover`] — bytes already consumed from the socket that
    /// belong to this machine; they are processed by the first [`Self::process_bytes`] call.
    /// Fails when the connect sequence hands over a desktop size past
    /// [`crate::framebuffer::MAX_DESKTOP_DIM`] — a server-declared value that reaches an
    /// allocation, so refusing it here is what keeps the allocation total
    /// (ADR-0012 §1; the 32-bit overflow it prevents is reproduced in `framebuffer`'s tests).
    pub fn new(config: SessionConfig, leftover: Vec<u8>) -> Result<Self, SessionError> {
        let framebuffer =
            Framebuffer::new(config.desktop_size.0, config.desktop_size.1).map_err(|error| {
                SessionError::Framebuffer {
                    channel: None,
                    error,
                }
            })?;
        let graphics =
            crate::egfx::GraphicsProcessor::new(&config.egfx).map_err(SessionError::EgfxConfig)?;
        let drdynvc = Drdynvc::new(graphics, &config.dynamic_channels)
            .map_err(SessionError::DynamicChannelConfig)?;
        // The cache honors what the caller advertised in its Pointer capability set:
        // `pointerCacheSize` when present (the cache New Pointer messages address), else
        // `colorPointerCacheSize`; no Pointer set advertised means no cache (a conforming
        // server then sends no shape messages at all).
        let cache_size = config
            .capabilities
            .iter()
            .find_map(|set| match set {
                CapabilitySet::Pointer(p) => Some(if p.pointer_cache_size > 0 {
                    p.pointer_cache_size
                } else {
                    p.color_pointer_cache_size
                }),
                _ => None,
            })
            .unwrap_or(0);
        let surface_commands = config
            .capabilities
            .iter()
            .find_map(|set| match set {
                CapabilitySet::SurfaceCommands(s) => Some(s.cmd_flags),
                _ => None,
            })
            .unwrap_or(0);
        let nscodec_advertised = config.capabilities.iter().any(|set| {
            matches!(set, CapabilitySet::BitmapCodecs(c)
                if c.codecs.iter().any(|codec| codec.guid == capability::CODEC_GUID_NSCODEC
                    && codec.id == capability::CODEC_ID_NSCODEC))
        });
        let channels = config
            .static_channels
            .iter()
            .filter(|c| Some(c.id) != config.drdynvc_channel_id)
            .map(|c| {
                (
                    c.id,
                    crate::svc::Reassembler::dropping(crate::svc::CHANNEL_MESSAGE_CAP),
                )
            })
            .collect();
        Ok(Self {
            config,
            framebuffer,
            palette: Palette::default(),
            phase: Phase::Active,
            inbox: leftover,
            fragment: None,
            cursor_cache: vec![None; usize::from(cache_size)],
            error_info: None,
            ultimatum_reason: None,
            drdynvc,
            channels,
            suspended: None,
            held_bytes: 0,
            surface_commands,
            nscodec_advertised,
        })
    }

    /// Why the session ended, as far as the server said (issue #42). The adapter calls this
    /// when the transport closes: a recorded Set Error Info code is the attribution (it
    /// outranks the generic MCS ultimatum); with neither, the close is
    /// [`DisconnectReason::UnexpectedDisconnect`].
    pub fn disconnect_reason(&self) -> DisconnectReason {
        if let Some(info) = self.error_info {
            DisconnectReason::ServerDisconnected(ServerDisconnectCause::ErrorInfo(info))
        } else if let Some(reason) = self.ultimatum_reason {
            DisconnectReason::ServerDisconnected(ServerDisconnectCause::ProviderUltimatum {
                reason,
            })
        } else {
            DisconnectReason::UnexpectedDisconnect
        }
    }

    /// The framebuffer (host-side rendering can snapshot it at any time).
    pub fn framebuffer(&self) -> &Framebuffer {
        &self.framebuffer
    }

    /// Feed raw socket bytes (any chunking); returns the outputs they produced, in order.
    /// The stream interleaves TPKT frames (slow-path) and fast-path PDUs; the first byte
    /// disambiguates (TPKT's version byte is `0x03`, a fast-path header has `action == 0`).
    pub fn process_bytes(&mut self, bytes: &[u8]) -> Result<Vec<SessionOutput>, SessionError> {
        self.inbox.extend_from_slice(bytes);
        // Take the inbox so complete frames are processed as borrowed slices — one drain at
        // the end instead of a per-frame allocate-and-shift (#86). The buffer must live
        // outside `self` while the frame handlers (`&mut self`) run.
        let mut inbox = core::mem::take(&mut self.inbox);
        let mut outputs = Vec::new();
        let mut consumed = 0;
        let mut error = None;
        while let Some(&first) = inbox.get(consumed) {
            let rest = &inbox[consumed..];
            let result = if fastpath::is_fastpath(first) {
                fastpath::frame_len(rest)
            } else {
                tpkt::frame_len(rest)
            };
            let frame_len = match result {
                Ok(n) => n,
                Err(justrdp_pdu::DecodeError::NotEnoughBytes { .. }) => break,
                Err(e) => {
                    error = Some(SessionError::Decode(e));
                    break;
                }
            };
            if rest.len() < frame_len {
                break;
            }
            let frame = &rest[..frame_len];
            let handled = if fastpath::is_fastpath(first) {
                self.on_fastpath_pdu(frame, &mut outputs)
            } else {
                self.on_frame(frame, &mut outputs)
            };
            if let Err(e) = handled {
                error = Some(e);
                break;
            }
            consumed += frame_len;
        }
        inbox.drain(..consumed);
        self.inbox = inbox;
        match error {
            Some(e) => Err(e),
            None => Ok(outputs),
        }
    }

    /// Handle one complete fast-path output PDU: reassemble fragmented updates, then route
    /// bitmap/palette bodies through the same handlers as their slow-path twins, and surface
    /// commands to [`Self::apply_surface_bits`].
    fn on_fastpath_pdu(
        &mut self,
        frame: &[u8],
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        for section in fastpath::decode_updates(frame).map_err(SessionError::Decode)? {
            let starts = matches!(
                section.fragmentation,
                fastpath::FP_FRAGMENT_SINGLE | fastpath::FP_FRAGMENT_FIRST
            );
            if starts && self.fragment.is_some() {
                return Err(SessionError::Decode(
                    justrdp_pdu::DecodeError::InvalidField {
                        field: "TS_FP_UPDATE.fragmentation",
                        reason: "a fragment sequence was interrupted before its last fragment",
                    },
                ));
            }
            let complete: Option<(u8, Vec<u8>)> = match section.fragmentation {
                fastpath::FP_FRAGMENT_SINGLE => Some((section.code, section.data.to_vec())),
                fastpath::FP_FRAGMENT_FIRST => {
                    self.fragment = Some((section.code, section.data.to_vec()));
                    None
                }
                fastpath::FP_FRAGMENT_NEXT | fastpath::FP_FRAGMENT_LAST => {
                    match self.fragment.as_mut() {
                        Some((code, buffer)) if *code == section.code => {
                            // Cap reassembly so an endless NEXT stream cannot grow the
                            // buffer unboundedly (the TSRequest-cap precedent): one full
                            // desktop of RGBA pixels plus headers, at least
                            // `HONOURED_MAX_REQUEST_SIZE`.
                            let cap = (usize::from(self.framebuffer.width())
                                * usize::from(self.framebuffer.height())
                                * 4
                                + (64 << 10))
                                .max(crate::advertise::HONOURED_MAX_REQUEST_SIZE as usize);
                            if buffer.len() + section.data.len() > cap {
                                return Err(SessionError::Decode(
                                    justrdp_pdu::DecodeError::InvalidField {
                                        field: "TS_FP_UPDATE.fragmentation",
                                        reason: "fragmented update exceeds the reassembly cap",
                                    },
                                ));
                            }
                            buffer.extend_from_slice(section.data);
                        }
                        // A continuation without a matching FIRST: protocol desync.
                        _ => {
                            return Err(SessionError::Decode(
                                justrdp_pdu::DecodeError::InvalidField {
                                    field: "TS_FP_UPDATE.fragmentation",
                                    reason: "fragment continuation without a first fragment",
                                },
                            ));
                        }
                    }
                    if section.fragmentation == fastpath::FP_FRAGMENT_LAST {
                        self.fragment.take()
                    } else {
                        None
                    }
                }
                _ => unreachable!("fragmentation is a 2-bit field"),
            };
            let Some((code, data)) = complete else {
                continue;
            };
            if self.phase != Phase::Active {
                continue; // graphics pause during deactivation–reactivation
            }
            let mut cur = ReadCursor::new(&data, "fast-path update body");
            match code {
                fastpath::FP_UPDATE_BITMAP => {
                    // The body is a TS_UPDATE_BITMAP_DATA, updateType field included.
                    cur.read_u16_le().map_err(SessionError::Decode)?;
                    let bitmap =
                        update::BitmapUpdate::decode(&mut cur).map_err(SessionError::Decode)?;
                    self.apply_bitmap_update(&bitmap, outputs)?;
                }
                fastpath::FP_UPDATE_PALETTE => {
                    cur.read_u16_le().map_err(SessionError::Decode)?;
                    let palette =
                        update::PaletteUpdate::decode(&mut cur).map_err(SessionError::Decode)?;
                    self.palette = Palette {
                        entries: palette.entries,
                    };
                }
                fastpath::FP_UPDATE_PTR_NULL
                | fastpath::FP_UPDATE_PTR_DEFAULT
                | fastpath::FP_UPDATE_PTR_POSITION
                | fastpath::FP_UPDATE_COLOR_POINTER
                | fastpath::FP_UPDATE_CACHED_POINTER
                | fastpath::FP_UPDATE_NEW_POINTER => {
                    let update = PointerUpdate::decode_fastpath(code, &mut cur)
                        .map_err(SessionError::Decode)?;
                    self.on_pointer(update, outputs)?;
                }
                fastpath::FP_UPDATE_SURFCMDS => {
                    let commands =
                        surface_commands::decode_all(&data).map_err(SessionError::Decode)?;
                    let mut budget = self.paint_budget();
                    for (index, command) in commands.iter().enumerate() {
                        self.note_unadvertised(command);
                        // A Frame Marker is decoded and dropped.
                        let SurfaceCommand::SurfaceBits(bits) = command else {
                            continue;
                        };
                        match self.apply_surface_bits(bits, &mut budget)? {
                            Painted::Frame(Some(frame_update)) => {
                                outputs.push(SessionOutput::Frame(frame_update));
                            }
                            Painted::Frame(None) => {}
                            Painted::OverBudget => {
                                note_paint_budget("TS_FP_SURFCMDS", commands.len(), index);
                                break;
                            }
                        }
                    }
                }
                // Synchronize, large pointers (capability never advertised), orders: skipped.
                _ => {}
            }
        }
        Ok(())
    }

    /// Handle one decoded pointer update — both transports route here (issue #41).
    fn on_pointer(
        &mut self,
        update: PointerUpdate,
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        match update {
            PointerUpdate::System { pointer_type } => {
                // SYSPTR_NULL hides; anything else (SYSPTR_DEFAULT being the only other
                // conforming value) restores the host default.
                let event = if pointer_type == pointer::SYSPTR_NULL {
                    CursorEvent::Hidden
                } else {
                    CursorEvent::Default
                };
                outputs.push(SessionOutput::Cursor(event));
            }
            PointerUpdate::Position { x, y } => {
                outputs.push(SessionOutput::Cursor(CursorEvent::Move { x, y }));
            }
            // The Color message is implicitly 24-bpp; New carries its own depth.
            PointerUpdate::Color(attr) => self.set_cursor_shape(24, attr, outputs)?,
            PointerUpdate::New { xor_bpp, color } => {
                self.set_cursor_shape(xor_bpp, color, outputs)?;
            }
            PointerUpdate::Cached { cache_index } => {
                let image = self
                    .cursor_cache
                    .get(usize::from(cache_index))
                    .and_then(Option::as_ref)
                    .ok_or(SessionError::Decode(
                        justrdp_pdu::DecodeError::InvalidField {
                            field: "TS_CACHEDPOINTERATTRIBUTE.cacheIndex",
                            reason: "cache index beyond the advertised cache or an unfilled slot",
                        },
                    ))?;
                outputs.push(SessionOutput::Cursor(cursor_event_for(image.clone())));
            }
        }
        Ok(())
    }

    /// Decode a Color/New shape, store it in its cache slot, and surface it.
    fn set_cursor_shape(
        &mut self,
        xor_bpp: u16,
        attr: pointer::ColorPointerAttribute,
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        // 8-bpp shapes resolve through the *session* palette — pointer messages carry none
        // of their own.
        let rgba = pointer_codec::decode_pointer(
            attr.width,
            attr.height,
            xor_bpp,
            &attr.xor_mask,
            &attr.and_mask,
            &self.palette,
        )
        .map_err(SessionError::Pointer)?;
        let image = CursorImage {
            width: attr.width,
            height: attr.height,
            hotspot_x: attr.hot_spot.0,
            hotspot_y: attr.hot_spot.1,
            rgba,
        };
        let slot = self
            .cursor_cache
            .get_mut(usize::from(attr.cache_index))
            .ok_or(SessionError::Decode(
                justrdp_pdu::DecodeError::InvalidField {
                    field: "TS_COLORPOINTERATTRIBUTE.cacheIndex",
                    reason: "cache index beyond the advertised pointer cache",
                },
            ))?;
        *slot = Some(image.clone());
        outputs.push(SessionOutput::Cursor(cursor_event_for(image)));
        Ok(())
    }

    /// Handle one complete TPKT frame.
    fn on_frame(
        &mut self,
        frame: &[u8],
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        let tpdu = tpkt::decode(frame).map_err(SessionError::Decode)?;
        let body = x224::decode_data(tpdu).map_err(SessionError::Decode)?;
        if mcs::DisconnectProviderUltimatum::matches(body) {
            // The server's last MCS word before closing the socket (issue #42): record the
            // reason for the adapter to surface at EOF.
            let dpum =
                mcs::DisconnectProviderUltimatum::decode(body).map_err(SessionError::Decode)?;
            tracing::info!(target: "rdp_dpum", reason = dpum.reason, "MCS Disconnect Provider Ultimatum");
            self.ultimatum_reason = Some(dpum.reason);
            return Ok(());
        }
        let indication = mcs::SendDataIndication::decode(body).map_err(SessionError::Decode)?;
        if indication.channel_id != self.config.io_channel_id {
            if Some(indication.channel_id) == self.config.drdynvc_channel_id {
                return self.on_drdynvc(indication.channel_id, indication.user_data, outputs);
            }
            return self.on_static_channel(indication.channel_id, indication.user_data, outputs);
        }
        let mut cur = ReadCursor::new(indication.user_data, "session share pdu");
        let header = share::ShareControlHeader::decode(&mut cur).map_err(SessionError::Decode)?;
        match header.pdu_type {
            share::PDU_TYPE_DATA => self.on_data_pdu(&mut cur, outputs),
            share::PDU_TYPE_DEACTIVATE_ALL => {
                // The server is resetting the session (most commonly a resize). Wait for the
                // next Demand Active; graphics stop in the meantime.
                tracing::debug!(target: "rdp_deactivate_all", "DeactivateAll received");
                self.phase = Phase::Deactivated;
                Ok(())
            }
            share::PDU_TYPE_DEMAND_ACTIVE => self.on_demand_active(header, &mut cur, outputs),
            // 2.2.8.1.1.1.1: a T.128 Flow PDU MUST be ignored (#309). Named rather than left to
            // the catch-all so both legs say the same thing about it — the connect leg's
            // catch-all is strict, and needed the arm to survive one.
            share::PDU_TYPE_FLOW_CONTROL => {
                tracing::debug!(target: "rdp_flow_control", "T.128 Flow PDU ignored");
                Ok(())
            }
            // Anything else mid-session (e.g. a Server Redirect, the broker epic) is
            // unsupported but well-formed at this layer: skipped.
            _ => Ok(()),
        }
    }

    /// Handle a Share Data PDU.
    fn on_data_pdu(
        &mut self,
        cur: &mut ReadCursor<'_>,
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        let data = share::ShareDataHeader::decode(cur).map_err(SessionError::Decode)?;
        match data.pdu_type2 {
            share::PDU_TYPE2_UPDATE if self.phase == Phase::Active => {
                let update_type = cur.read_u16_le().map_err(SessionError::Decode)?;
                match update_type {
                    update::UPDATETYPE_BITMAP => {
                        let bitmap =
                            update::BitmapUpdate::decode(cur).map_err(SessionError::Decode)?;
                        self.apply_bitmap_update(&bitmap, outputs)?;
                    }
                    update::UPDATETYPE_PALETTE => {
                        let palette =
                            update::PaletteUpdate::decode(cur).map_err(SessionError::Decode)?;
                        self.palette = Palette {
                            entries: palette.entries,
                        };
                    }
                    // Synchronize updates are no-ops; orders cannot arrive (none advertised
                    // in the Order capset) — an order update from a non-conforming server is
                    // skipped, not fatal.
                    _ => {}
                }
                Ok(())
            }
            // The server's other finalization replies on the reactivation leg. Measured against
            // the real VM (#252): a resize produces `DeactivateAll → Demand Active →
            // Synchronize → Control(Cooperate) → Control(GrantedControl) → Font Map`, the same
            // four the connect leg gets. They used to fall to the catch-all with the cursor
            // dropped unread, so `connect.rs` checked a server `action` this path never looked
            // at — one family, two answers. #252 decided *against* gating session-active on
            // their arrival; this is only the value check, held identically on both legs.
            // ADR-0012 §3's "one undefined input, one answer across a family". Its own sentence
            // says *codec* family, so this was precedent rather than authority until the
            // Amendment 2026-08-25 extended the reach to PDU families on the strength of this
            // very site — one of the two non-codec cases that showed the rule derives past the
            // layer it was written about.
            //
            // **Observability is not yet symmetric.** `connect.rs` emits an `rdp_finalization`
            // record per reply; these two arms emit nothing, so a reactivation is still three
            // asserted milestones out of six PDUs. The value checks match on both legs; the
            // milestones do not, and this comment is here so the gap is a known one.
            share::PDU_TYPE2_SYNCHRONIZE if self.phase == Phase::Reactivating => {
                finalization::Synchronize::decode(cur).map_err(SessionError::Decode)?;
                Ok(())
            }
            share::PDU_TYPE2_CONTROL if self.phase == Phase::Reactivating => {
                finalization::Control::decode(cur)
                    .map_err(SessionError::Decode)?
                    .check_server_action()
                    .map_err(SessionError::Decode)?;
                Ok(())
            }
            share::PDU_TYPE2_FONT_MAP if self.phase == Phase::Reactivating => {
                finalization::FontMap::decode(cur).map_err(SessionError::Decode)?;
                tracing::debug!(target: "rdp_font_map", "Font Map received — reactivation complete");
                self.phase = Phase::Active;
                // Reactivation complete: re-emit the full screen so the host repaints
                // (content restarts black; the server repaints everything next).
                outputs.push(SessionOutput::Frame(self.framebuffer.full_frame()));
                Ok(())
            }
            share::PDU_TYPE2_POINTER if self.phase == Phase::Active => {
                let update = PointerUpdate::decode_slowpath(cur).map_err(SessionError::Decode)?;
                self.on_pointer(update, outputs)
            }
            share::PDU_TYPE2_SHUTDOWN_DENIED => {
                // The refusal to a request we sent (issue #228). Surfaced rather than skipped:
                // a host that can ask has to be able to hear "no", and the alternative — the
                // request simply having no visible effect — is indistinguishable from the PDU
                // never having been sent.
                tracing::info!(
                    target: "rdp_shutdown_denied",
                    "server denied the shutdown request"
                );
                outputs.push(SessionOutput::ShutdownDenied);
                Ok(())
            }
            share::PDU_TYPE2_SET_ERROR_INFO => {
                // The server's attribution for the close that usually follows (issue #42).
                // ERRINFO_NONE (0) clears rather than attributes.
                let info = justrdp_pdu::errinfo::decode_set_error_info(cur)
                    .map_err(SessionError::Decode)?;
                if info.as_u32() == 0 {
                    self.error_info = None;
                } else {
                    tracing::info!(
                        target: "rdp_error_info",
                        code = format_args!("{:#010x}", info.as_u32()),
                        description = %info.description(),
                        "server Set Error Info"
                    );
                    self.error_info = Some(info);
                }
                Ok(())
            }
            share::PDU_TYPE2_SAVE_SESSION_INFO => {
                // Who logged on, into which session, and the cookie that would resume it
                // (issue #304). No phase guard: 2.2.10.1 ties this PDU to the logon, not to
                // the share, so it may arrive at any point a share is up.
                let info =
                    session_info::SaveSessionInfo::decode(cur).map_err(SessionError::Decode)?;
                log_save_session_info("session", &info);
                outputs.push(SessionOutput::SaveSessionInfo(info));
                Ok(())
            }
            share::PDU_TYPE2_SET_KEYBOARD_INDICATORS => {
                // The server's lock state (issue #305). No phase guard, as for Save Session
                // Info: it concerns the keyboard, not the share.
                let indicators =
                    input::KeyboardIndicators::decode(cur).map_err(SessionError::Decode)?;
                tracing::debug!(
                    target: "rdp_keyboard_indicators",
                    led_flags = format_args!("{:#06x}", indicators.led_flags),
                    "server Set Keyboard Indicators"
                );
                outputs.push(SessionOutput::KeyboardIndicators(indicators));
                Ok(())
            }
            share::PDU_TYPE2_PLAY_SOUND => {
                // The beep the default Sound set invites (issue #354). No phase guard, as for
                // Set Keyboard Indicators.
                let beep = sound::PlaySound::decode(cur).map_err(SessionError::Decode)?;
                tracing::debug!(
                    target: "rdp_play_sound",
                    duration = beep.duration,
                    frequency = beep.frequency,
                    "server Play Sound"
                );
                outputs.push(SessionOutput::PlaySound(beep));
                Ok(())
            }
            // The rest: skipped, cursor unread, until their epics. (Set Error Info, the
            // reactivation Synchronize/Control, Save Session Info, Set Keyboard Indicators and
            // Play Sound have their own arms above — this comment used to claim the first two,
            // and to call the skip a decode; #252.)
            _ => Ok(()),
        }
    }

    /// Record a surface command whose `cmdFlags` bit the Confirm Active did not set (ADR-0009
    /// §3(b)).
    fn note_unadvertised(&self, command: &SurfaceCommand<'_>) {
        let (cmd_type, flag) = match command {
            SurfaceCommand::SurfaceBits(bits)
                if bits.cmd_type == surface_commands::CMDTYPE_STREAM_SURFACE_BITS =>
            {
                (bits.cmd_type, capability::SURFCMDS_STREAM_SURFACE_BITS)
            }
            SurfaceCommand::SurfaceBits(bits) => {
                (bits.cmd_type, capability::SURFCMDS_SET_SURFACE_BITS)
            }
            SurfaceCommand::FrameMarker(_) => (
                surface_commands::CMDTYPE_FRAME_MARKER,
                capability::SURFCMDS_FRAME_MARKER,
            ),
        };
        if self.surface_commands & flag == 0 {
            tracing::debug!(
                target: "rdp_surface_bits",
                cmd_type,
                advertised = self.surface_commands,
                "surface command the Confirm Active did not advertise"
            );
        }
    }

    /// Decode one Set Surface Bits / Stream Surface Bits command into the framebuffer, at
    /// `(destLeft, destTop)` with the bitmap's own size (2.2.9.2.1: `destRight`/`destBottom`
    /// SHOULD be ignored).
    fn apply_surface_bits(
        &mut self,
        bits: &SurfaceBits<'_>,
        budget: &mut usize,
    ) -> Result<Painted, SessionError> {
        let bitmap = &bits.bitmap;
        if bitmap.width > self.framebuffer.width() || bitmap.height > self.framebuffer.height() {
            return Err(SessionError::Decode(
                justrdp_pdu::DecodeError::InvalidField {
                    field: "TS_BITMAP_DATA_EX",
                    reason: "surface bits exceed the negotiated desktop size",
                },
            ));
        }
        let width = usize::from(bitmap.width);
        let height = usize::from(bitmap.height);
        let decodes = bitmap.codec_id == 0
            || (bitmap.codec_id == capability::CODEC_ID_NSCODEC && self.nscodec_advertised);
        if decodes && !charge(budget, width * height * 4) {
            return Ok(Painted::OverBudget);
        }
        // Both layouts are bottom-up.
        let rgba = match bitmap.codec_id {
            0 => color::to_rgba(
                bitmap.data,
                width,
                height,
                u16::from(bitmap.bpp),
                &self.palette,
                true,
            )
            .map_err(SessionError::Color)?,
            capability::CODEC_ID_NSCODEC if self.nscodec_advertised => {
                let bgra = nscodec::decode(bitmap.data, bitmap.width, bitmap.height)
                    .map_err(SessionError::Nscodec)?;
                color::to_rgba(&bgra, width, height, 32, &Palette::default(), true)
                    .map_err(SessionError::Color)?
            }
            codec_id => {
                tracing::debug!(
                    target: "rdp_surface_bits",
                    codec_id,
                    "Set Surface Bits with a codec ID the client did not advertise — skipped"
                );
                return Ok(Painted::Frame(None));
            }
        };
        Ok(Painted::Frame(self.framebuffer.blit(
            bits.dest_left,
            bits.dest_top,
            bitmap.width,
            bitmap.height,
            &rgba,
            width,
        )))
    }

    /// Decode every rectangle of one bitmap update, within one paint budget.
    fn apply_bitmap_update(
        &mut self,
        bitmap: &update::BitmapUpdate,
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        let mut budget = self.paint_budget();
        for (index, rect) in bitmap.rectangles.iter().enumerate() {
            match self.apply_bitmap(rect, &mut budget)? {
                Painted::Frame(Some(frame_update)) => {
                    outputs.push(SessionOutput::Frame(frame_update));
                }
                Painted::Frame(None) => {}
                Painted::OverBudget => {
                    note_paint_budget("TS_UPDATE_BITMAP_DATA", bitmap.rectangles.len(), index);
                    break;
                }
            }
        }
        Ok(())
    }

    /// The decoded bytes one graphics update may buy.
    fn paint_budget(&self) -> usize {
        usize::from(self.framebuffer.width())
            * usize::from(self.framebuffer.height())
            * 4
            * PAINT_BUDGET_FRAMEBUFFERS
    }

    /// Decode one bitmap rectangle into the framebuffer.
    fn apply_bitmap(
        &mut self,
        rect: &update::BitmapData,
        budget: &mut usize,
    ) -> Result<Painted, SessionError> {
        // Bound the wire-declared dimensions BEFORE the decoders allocate width × height
        // buffers: a tiny malicious PDU declaring 65535×65535 would otherwise force a
        // multi-gigabyte allocation (OOM abort, not a typed error — plan.md §11c; same
        // class as the capped TSRequest read, gate #3). Legitimate rectangles never exceed
        // the negotiated desktop plus the legacy 4-pixel alignment padding.
        let max_w = self.framebuffer.width().saturating_add(3);
        let max_h = self.framebuffer.height().saturating_add(3);
        if rect.width > max_w || rect.height > max_h {
            return Err(SessionError::Decode(
                justrdp_pdu::DecodeError::InvalidField {
                    field: "TS_BITMAP_DATA",
                    reason: "bitmap rectangle exceeds the negotiated desktop size",
                },
            ));
        }
        let width = usize::from(rect.width);
        let height = usize::from(rect.height);
        if !charge(budget, width * height * 4) {
            return Ok(Painted::OverBudget);
        }
        // All slow-path bitmap layouts are bottom-up; the conversion flips to top-down RGBA.
        let rgba = match (rect.compressed, rect.bits_per_pixel) {
            (false, bpp) => color::to_rgba(&rect.data, width, height, bpp, &self.palette, true)
                .map_err(SessionError::Color)?,
            // Compressed 32-bpp slow-path data is RDP6 planar (MS-RDPBCGR
            // 2.2.9.1.1.3.1.2.2); the decoder yields BGR24 in the same bottom-up layout.
            (true, 32) => {
                let bgr =
                    planar::decompress(&rect.data, width, height).map_err(SessionError::Planar)?;
                color::to_rgba(&bgr, width, height, 24, &self.palette, true)
                    .map_err(SessionError::Color)?
            }
            (true, bpp) => {
                let raw =
                    rle::decompress(&rect.data, width, height, bpp).map_err(SessionError::Rle)?;
                color::to_rgba(&raw, width, height, bpp, &self.palette, true)
                    .map_err(SessionError::Color)?
            }
        };
        // The carried bitmap may overhang the destination rectangle (legacy 4-pixel
        // alignment); the destination is inclusive, the overhang is right/bottom padding.
        let dest_w = rect.right.saturating_sub(rect.left).saturating_add(1);
        let dest_h = rect.bottom.saturating_sub(rect.top).saturating_add(1);
        Ok(Painted::Frame(self.framebuffer.blit(
            rect.left,
            rect.top,
            dest_w.min(rect.width),
            dest_h.min(rect.height),
            &rgba,
            width,
        )))
    }

    /// A Demand Active mid-session: the Deactivation–Reactivation sequence (plan.md §0 —
    /// most commonly a resize). Confirm with the caller's capabilities (new size patched into
    /// the Bitmap set), pipeline the finalization batch, rebuild the framebuffer.
    fn on_demand_active(
        &mut self,
        header: share::ShareControlHeader,
        cur: &mut ReadCursor<'_>,
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        let demand = capability::DemandActive::decode(cur).map_err(SessionError::Decode)?;
        self.config.share_id = header.share_id;
        let (width, height) = demand
            .bitmap()
            .map(|b| (b.desktop_width, b.desktop_height))
            .unwrap_or(self.config.desktop_size);
        tracing::debug!(
            target: "rdp_demand_active",
            width,
            height,
            "Demand Active received (reactivation)"
        );
        if (width, height) != self.config.desktop_size {
            self.framebuffer
                .resize(width, height)
                .map_err(|error| SessionError::Framebuffer {
                    channel: None,
                    error,
                })?;
            self.config.desktop_size = (width, height);
        }

        let mut caps = self.config.capabilities.clone();
        for set in &mut caps {
            if let CapabilitySet::Bitmap(bitmap) = set {
                bitmap.desktop_width = width;
                bitmap.desktop_height = height;
            }
        }
        let confirm = share::encode_share_control(
            share::PDU_TYPE_CONFIRM_ACTIVE,
            self.config.user_channel_id,
            header.share_id,
            &capability::encode_confirm_active(header.pdu_source, b"justrdp\0", &caps),
        );
        outputs.push(self.send_io(&confirm));
        let batch = [
            (
                share::PDU_TYPE2_SYNCHRONIZE,
                finalization::Synchronize {
                    target_user: header.pdu_source,
                }
                .encode(),
            ),
            (
                share::PDU_TYPE2_CONTROL,
                finalization::Control::new(finalization::CTRLACTION_COOPERATE).encode(),
            ),
            (
                share::PDU_TYPE2_CONTROL,
                finalization::Control::new(finalization::CTRLACTION_REQUEST_CONTROL).encode(),
            ),
            (share::PDU_TYPE2_FONT_LIST, finalization::encode_font_list()),
        ];
        for (pdu_type2, body) in batch {
            outputs.push(self.send_io(&share::encode_share_data(
                self.config.user_channel_id,
                header.share_id,
                share::STREAM_MED,
                pdu_type2,
                &body,
            )));
        }
        self.phase = Phase::Reactivating;
        Ok(())
    }

    /// Encode host input events into complete outbound wire frames (plan.md §6a). The
    /// transport is chosen from what the server's Input capability set advertised: fast-path
    /// input PDUs when `INPUT_FLAG_FASTPATH_INPUT`/`INPUT2` was set, the slow-path Input
    /// Event PDU otherwise. Batches over a single PDU's event bound are split automatically
    /// (the fast-path spill rule), and mouse coordinates are clamped to the current desktop —
    /// a stale coordinate from a pre-resize host event must not land outside the new desktop.
    ///
    /// The adapter writes the returned frames to the socket in order. Pure function of the
    /// machine's negotiated state: no I/O, no phase change (servers accept input during
    /// reactivation; they simply ignore what no longer applies).
    pub fn encode_input(&self, events: &[InputEvent]) -> Vec<Vec<u8>> {
        if events.is_empty() {
            return Vec::new();
        }
        let (max_x, max_y) = (
            self.config.desktop_size.0.saturating_sub(1),
            self.config.desktop_size.1.saturating_sub(1),
        );
        let events: Vec<InputEvent> = events
            .iter()
            .map(|event| match *event {
                InputEvent::Mouse {
                    flags,
                    wheel_units,
                    x,
                    y,
                } => InputEvent::Mouse {
                    flags,
                    wheel_units,
                    x: x.min(max_x),
                    y: y.min(max_y),
                },
                InputEvent::MouseX { flags, x, y } => InputEvent::MouseX {
                    flags,
                    x: x.min(max_x),
                    y: y.min(max_y),
                },
                other => other,
            })
            .collect();

        let fastpath_input = self.config.server_input_flags
            & (capability::INPUT_FLAG_FASTPATH_INPUT | capability::INPUT_FLAG_FASTPATH_INPUT2)
            != 0;
        if fastpath_input {
            // 255 events is the numEvents field bound; at ≤7 wire bytes per event a full
            // chunk stays far below the 0x7FFF length-field ceiling.
            events
                .chunks(255)
                .map(input::encode_fastpath_input)
                .collect()
        } else {
            events
                .chunks(255)
                .map(|chunk| {
                    self.wrap_io(&share::encode_share_data(
                        self.config.user_channel_id,
                        self.config.share_id,
                        share::STREAM_HI,
                        share::PDU_TYPE2_INPUT,
                        &input::encode_slowpath_input_body(chunk),
                    ))
                })
                .collect()
        }
    }

    /// Consume one MCS-delivered payload on a static channel other than I/O and drdynvc: a
    /// host channel's chunk goes to its reassembler, and anything else was never granted.
    fn on_static_channel(
        &mut self,
        channel: u16,
        payload: &[u8],
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        let Some((_, reassembler)) = self.channels.iter_mut().find(|(id, _)| *id == channel) else {
            tracing::debug!(
                target: "rdp_svc",
                channel,
                bytes = payload.len(),
                "data on a static channel that was never granted; skipped"
            );
            return Ok(());
        };
        let data = reassembler.push(payload).map_err(SessionError::Decode)?;
        self.note_channel_flow(payload, outputs);
        match data {
            Some(crate::svc::Reassembled::Message(data)) => {
                outputs.push(SessionOutput::ChannelData { channel, data });
            }
            Some(crate::svc::Reassembled::Dropped { total_length }) => {
                outputs.push(SessionOutput::ChannelMessageDropped {
                    channel,
                    total_length,
                });
            }
            None => {}
        }
        Ok(())
    }

    /// Set the largest message the host static channel `channel` delivers; a larger one is
    /// skipped and reported as [`SessionOutput::ChannelMessageDropped`]. The default is 64 MiB.
    /// A message already arriving keeps the cap its first chunk met.
    pub fn set_channel_message_cap(
        &mut self,
        channel: u16,
        cap: usize,
    ) -> Result<(), ChannelSendError> {
        if Some(channel) == self.config.drdynvc_channel_id {
            return Err(ChannelSendError::CoreOwned { channel });
        }
        let (_, reassembler) = self
            .channels
            .iter_mut()
            .find(|(id, _)| *id == channel)
            .ok_or(ChannelSendError::NotGranted { channel })?;
        reassembler.set_cap(cap);
        Ok(())
    }

    /// Track `CHANNEL_FLAG_SUSPEND` / `RESUME` on a received chunk (`[MS-RDPBCGR]` 2.2.6.1.1):
    /// a suspend starts holding outbound virtual channel frames, a resume releases them in order.
    fn note_channel_flow(&mut self, payload: &[u8], outputs: &mut Vec<SessionOutput>) {
        let Some(flags) = payload
            .get(4..8)
            .map(|f| u32::from_le_bytes([f[0], f[1], f[2], f[3]]))
        else {
            return;
        };
        if flags & crate::svc::CHANNEL_FLAG_SUSPEND != 0 && self.suspended.is_none() {
            tracing::debug!(target: "rdp_svc", "virtual channel traffic suspended");
            self.suspended = Some(Vec::new());
        } else if flags & crate::svc::CHANNEL_FLAG_RESUME != 0
            && let Some(held) = self.suspended.take()
        {
            tracing::debug!(target: "rdp_svc", frames = held.len(), "virtual channel traffic resumed");
            outputs.extend(held.into_iter().map(SessionOutput::WriteBytes));
            self.held_bytes = 0;
        }
    }

    /// `frames` to write now, or none while suspended (they are held for the resume).
    fn unless_suspended(&mut self, frames: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        match &mut self.suspended {
            Some(held) => {
                held.extend(frames);
                Vec::new()
            }
            None => frames,
        }
    }

    /// Consume one MCS-delivered payload on the drdynvc static channel: SVC reassembly →
    /// drdynvc dispatch (caps response, Display Control create, channel data) → outbound
    /// responses and the [`SessionOutput::DisplayControlReady`] milestone.
    fn on_drdynvc(
        &mut self,
        mcs_channel_id: u16,
        payload: &[u8],
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        let events = self.drdynvc.on_svc_payload(payload)?;
        self.note_channel_flow(payload, outputs);
        for event in events {
            match event {
                DvcEvent::Send(pdu) => {
                    let frames: Vec<Vec<u8>> = svc::encode_chunks(&pdu)
                        .iter()
                        .map(|chunk| self.wrap_channel(mcs_channel_id, chunk))
                        .collect();
                    outputs.extend(
                        self.unless_suspended(frames)
                            .into_iter()
                            .map(SessionOutput::WriteBytes),
                    );
                }
                DvcEvent::DisplayControlReady => {
                    outputs.push(SessionOutput::DisplayControlReady);
                }
                DvcEvent::OutputResized {
                    channel,
                    width,
                    height,
                } => {
                    if (width, height) != self.config.desktop_size {
                        // Resize first, commit the new size only if it succeeded — otherwise a
                        // refused size would still be recorded and every later blit would index
                        // against dimensions the buffer does not have.
                        self.framebuffer.resize(width, height).map_err(|error| {
                            SessionError::Framebuffer {
                                channel: Some(channel),
                                error,
                            }
                        })?;
                        self.config.desktop_size = (width, height);
                    }
                }
                DvcEvent::HostOpened { name, channel_id } => {
                    outputs.push(SessionOutput::DynamicChannelOpened { name, channel_id });
                }
                DvcEvent::HostData { channel_id, data } => {
                    outputs.push(SessionOutput::DynamicChannelData { channel_id, data });
                }
                DvcEvent::HostClosed { channel_id } => {
                    outputs.push(SessionOutput::DynamicChannelClosed { channel_id });
                }
            }
        }
        // EGFX draw ops marked surface regions dirty during processing; blit them straight into
        // the framebuffer now (ADR-0010 #163 — no owned copy on the bridge). The framebuffer is
        // the single authoritative screen state legacy graphics writes too.
        for update in self.drdynvc.flush_frames(&mut self.framebuffer) {
            outputs.push(SessionOutput::Frame(update));
        }
        Ok(())
    }

    /// Ask the server to end this session — the Shutdown Request PDU (`[MS-RDPBCGR]` 2.2.2.1).
    ///
    /// The returned frames go to the socket verbatim. The PDU is **bodyless**: its Share Data
    /// header is the whole thing, which is why this takes no arguments and cannot fail.
    ///
    /// What it is *not* is session control. The server decides, and may refuse — Windows Server
    /// 2022 refuses **unconditionally**, measured against the test VM with nothing open and
    /// nothing unsaved (issue #228, `docs/plan.md` §0). A refusal arrives as
    /// [`SessionOutput::ShutdownDenied`]; a grant arrives as the session ending, which the
    /// adapter already classifies through [`Self::disconnect_reason`]. So a host that needs the
    /// session *gone* cannot rely on this, and one that wants to ask politely — and to know it
    /// was refused rather than ignored — now can.
    ///
    /// Valid whenever the session is live; there is no capability to negotiate first.
    pub fn request_shutdown(&self) -> Vec<Vec<u8>> {
        vec![self.wrap_io(&share::encode_share_data(
            self.config.user_channel_id,
            self.config.share_id,
            share::STREAM_MED,
            share::PDU_TYPE2_SHUTDOWN_REQUEST,
            &[],
        ))]
    }

    /// Encode a client-initiated resize as a Display Control Monitor Layout PDU
    /// (MS-RDPEDISP 2.2.2.2): one primary monitor at the origin with the requested size, scale
    /// factors and orientation. The
    /// returned frames go to the socket verbatim; the server answers with
    /// Deactivation–Reactivation (DeactivateAll → Demand Active carrying the new size), which
    /// this machine already consumes — the framebuffer rebuilds and a full-screen
    /// [`SessionOutput::Frame`] re-emit follows the reactivation Font Map.
    ///
    /// Valid only after [`SessionOutput::DisplayControlReady`]. An odd `width` is rounded
    /// down to even (the spec forbids odd widths; mstsc does the same).
    pub fn request_resize(&mut self, request: ResizeRequest) -> Result<Vec<Vec<u8>>, ResizeError> {
        let drdynvc_id = self
            .config
            .drdynvc_channel_id
            .ok_or(ResizeError::NotReady)?;
        let (channel_id, caps) = self
            .drdynvc
            .display_control()
            .ok_or(ResizeError::NotReady)?;
        let width = u32::from(request.width) & !1; // MS-RDPEDISP 2.2.2.2.1: width must be even
        let height = u32::from(request.height);
        let range = displaycontrol::MIN_MONITOR_DIMENSION..=displaycontrol::MAX_MONITOR_DIMENSION;
        if !range.contains(&width) || !range.contains(&height) {
            return Err(ResizeError::InvalidDimensions {
                reason: "width/height must be within 200–8192 (MS-RDPEDISP 2.2.2.2.1)",
            });
        }
        if u64::from(width) * u64::from(height) > caps.max_area() {
            return Err(ResizeError::InvalidDimensions {
                reason: "requested area exceeds the server's Display Control caps",
            });
        }
        let scale =
            displaycontrol::MIN_DESKTOP_SCALE_FACTOR..=displaycontrol::MAX_DESKTOP_SCALE_FACTOR;
        if !scale.contains(&request.desktop_scale_factor) {
            return Err(ResizeError::InvalidScaleFactor {
                desktop_scale_factor: request.desktop_scale_factor,
            });
        }
        tracing::debug!(
            target: "rdp_displaycontrol_resize",
            width,
            height,
            desktop_scale_factor = request.desktop_scale_factor,
            device_scale_factor = request.device_scale_factor.percent(),
            orientation = request.orientation.degrees(),
            "Monitor Layout resize request encoded"
        );
        let layout = displaycontrol::encode_monitor_layout(&[displaycontrol::Monitor {
            desktop_scale_factor: request.desktop_scale_factor,
            device_scale_factor: request.device_scale_factor.percent(),
            orientation: request.orientation.degrees(),
            ..displaycontrol::Monitor::primary(width, height)
        }]);
        let mut frames = Vec::new();
        for pdu in dvc::encode_data(channel_id, &layout) {
            for chunk in svc::encode_chunks(&pdu) {
                frames.push(self.wrap_channel(drdynvc_id, &chunk));
            }
        }
        Ok(self.unless_suspended(frames))
    }

    /// Encode `message` for the host static channel `channel`: split into chunks
    /// (`[MS-RDPBCGR]` 3.1.5.2.1), each a complete outbound frame for the socket. While the
    /// server has suspended virtual channel traffic the frames are held instead, returned
    /// empty here, and surface as [`SessionOutput::WriteBytes`] when it resumes.
    pub fn send_channel(
        &mut self,
        channel: u16,
        message: &[u8],
    ) -> Result<Vec<Vec<u8>>, ChannelSendError> {
        if Some(channel) == self.config.drdynvc_channel_id {
            return Err(ChannelSendError::CoreOwned { channel });
        }
        if !self.channels.iter().any(|(id, _)| *id == channel) {
            return Err(ChannelSendError::NotGranted { channel });
        }
        if self.suspended.is_some() {
            let held_bytes = self.held_bytes.saturating_add(message.len());
            if held_bytes > crate::svc::CHANNEL_MESSAGE_CAP {
                return Err(ChannelSendError::SuspendedQueueFull { channel });
            }
            self.held_bytes = held_bytes;
        }
        let show_protocol = self.config.static_channels.iter().any(|c| {
            c.id == channel && c.options & justrdp_pdu::gcc::CHANNEL_OPTION_SHOW_PROTOCOL != 0
        });
        let chunks = if show_protocol {
            svc::encode_chunks_show_protocol(message)
        } else {
            svc::encode_chunks(message)
        };
        let frames = chunks
            .iter()
            .map(|chunk| self.wrap_channel(channel, chunk))
            .collect();
        Ok(self.unless_suspended(frames))
    }

    /// Encode `message` for the host dynamic channel `channel_id` (ADR-0018): drdynvc data
    /// PDUs, fragmented when longer than one (`[MS-RDPEDYC]` 3.1.5.1.2), each split into chunks
    /// on the drdynvc channel. While the server has suspended virtual channel traffic the frames
    /// are held instead, returned empty here, and surface as [`SessionOutput::WriteBytes`] when
    /// it resumes.
    pub fn send_dynamic_channel(
        &mut self,
        channel_id: u32,
        message: &[u8],
    ) -> Result<Vec<Vec<u8>>, DynamicChannelError> {
        let pdus = self.drdynvc.host_send(channel_id, message)?;
        if self.suspended.is_some() {
            let held_bytes = self.held_bytes.saturating_add(message.len());
            if held_bytes > crate::svc::CHANNEL_MESSAGE_CAP {
                return Err(DynamicChannelError::SuspendedQueueFull { channel_id });
            }
            self.held_bytes = held_bytes;
        }
        Ok(self.drdynvc_frames(&pdus))
    }

    /// Close the host dynamic channel `channel_id` (`[MS-RDPEDYC]` 2.2.4): the channel is gone
    /// on this side at once, and the returned frames carry the Close PDU. No
    /// [`SessionOutput::DynamicChannelClosed`] follows for it.
    pub fn close_dynamic_channel(
        &mut self,
        channel_id: u32,
    ) -> Result<Vec<Vec<u8>>, DynamicChannelError> {
        let pdu = self.drdynvc.host_close(channel_id)?;
        Ok(self.drdynvc_frames(&[pdu]))
    }

    /// The frames carrying drdynvc `pdus` on the drdynvc channel, or none while suspended.
    /// A host channel is open only when drdynvc was granted, so the channel ID is known.
    fn drdynvc_frames(&mut self, pdus: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let Some(drdynvc_id) = self.config.drdynvc_channel_id else {
            return Vec::new();
        };
        let frames = pdus
            .iter()
            .flat_map(|pdu| svc::encode_chunks(pdu))
            .map(|chunk| self.wrap_channel(drdynvc_id, &chunk))
            .collect();
        self.unless_suspended(frames)
    }

    /// Wrap a channel payload into a complete outbound frame on `channel_id`.
    fn wrap_channel(&self, channel_id: u16, payload: &[u8]) -> Vec<u8> {
        tpkt::encode(&x224::encode_data(&mcs::encode_send_data_request(
            self.config.user_channel_id,
            channel_id,
            payload,
        )))
    }

    /// Wrap an I/O-channel payload into a complete outbound frame.
    fn wrap_io(&self, payload: &[u8]) -> Vec<u8> {
        self.wrap_channel(self.config.io_channel_id, payload)
    }

    /// Wrap an I/O-channel payload into an outbound [`SessionOutput`].
    fn send_io(&self, payload: &[u8]) -> SessionOutput {
        SessionOutput::WriteBytes(self.wrap_io(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::displaycontrol::{DeviceScaleFactor, Orientation};

    const IO: u16 = 1003;
    const USER: u16 = 1007;
    const DRDYNVC: u16 = 1005;
    const CLIPRDR: u16 = 1004;
    const RDPDR: u16 = 1006;
    const RAIL: u16 = 1008;
    const SHARE: u32 = 0x0001_03EA;

    /// Read a delivered frame's pixels back out of the retained framebuffer — the host's job
    /// now that [`FrameUpdate`] carries only the dirty rect (ADR-0010).
    fn frame_pixels(sm: &SessionStateMachine, frame: &FrameUpdate) -> Vec<u8> {
        let mut px = vec![0u8; usize::from(frame.width) * usize::from(frame.height) * 4];
        sm.framebuffer()
            .copy_rect_into(frame.x, frame.y, frame.width, frame.height, &mut px)
            .expect("a FrameUpdate this framebuffer produced is in bounds");
        px
    }

    /// One fast-path Surface Commands Update carrying `body`.
    fn surface_commands_pdu(body: &[u8]) -> Vec<u8> {
        fastpath::encode_pdu(&[(
            fastpath::FP_UPDATE_SURFCMDS,
            fastpath::FP_FRAGMENT_SINGLE,
            body,
        )])
    }

    /// A Set Surface Bits command at `(x, y)` whose bitmap is `w`×`h` in `codec_id`.
    fn set_surface_bits(x: u16, y: u16, w: u16, h: u16, codec_id: u8, data: &[u8]) -> Vec<u8> {
        let mut out = surface_commands::CMDTYPE_SET_SURFACE_BITS
            .to_le_bytes()
            .to_vec();
        for v in [x, y, x + w, y + h] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&[32, 0, 0, codec_id]);
        out.extend_from_slice(&w.to_le_bytes());
        out.extend_from_slice(&h.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    fn frame_marker(action: u16) -> Vec<u8> {
        let mut out = surface_commands::CMDTYPE_FRAME_MARKER
            .to_le_bytes()
            .to_vec();
        out.extend_from_slice(&action.to_le_bytes());
        out.extend_from_slice(&9u32.to_le_bytes());
        out
    }

    /// A 1×2 NSCodec stream with raw planes and colour-loss level 1. Plane row 0 is
    /// Y100 Co10 Cg5 (RGB 105,105,85); plane row 1 is Y50 Co0 Cg0 (RGB 50,50,50).
    fn nscodec_1x2() -> Vec<u8> {
        let mut nsc = Vec::new();
        for count in [2u32, 2, 2, 2] {
            nsc.extend_from_slice(&count.to_le_bytes());
        }
        nsc.extend_from_slice(&[1, 0, 0, 0]); // ColorLossLevel, ChromaSubsamplingLevel, reserved
        nsc.extend_from_slice(&[100, 50, 10, 0, 5, 0, 255, 255]); // Y, Co, Cg, A planes
        nsc
    }

    /// Issue #150: NSCodec Set Surface Bits paint at `(destLeft, destTop)` with the bitmap's
    /// own size, bottom-up: plane row 0 is the bottom row on screen.
    #[test]
    fn nscodec_surface_bits_paint_bottom_up_at_the_destination() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let outputs = sm
            .process_bytes(&surface_commands_pdu(&set_surface_bits(
                3,
                2,
                1,
                2,
                capability::CODEC_ID_NSCODEC,
                &nscodec_1x2(),
            )))
            .unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y, frame.width, frame.height), (3, 2, 1, 2));
        assert_eq!(
            frame_pixels(&sm, frame),
            [50, 50, 50, 255, 105, 105, 85, 255]
        );
    }

    /// 2.2.9.2.1: `destRight`/`destBottom` SHOULD be ignored, so a bitmap paints at its own size
    /// whatever they say.
    #[test]
    fn surface_bits_ignore_dest_right_and_bottom() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let mut bits = set_surface_bits(3, 2, 1, 2, capability::CODEC_ID_NSCODEC, &nscodec_1x2());
        bits[6..10].copy_from_slice(&[0, 0, 0, 0]); // destRight = destBottom = 0
        let outputs = sm.process_bytes(&surface_commands_pdu(&bits)).unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y, frame.width, frame.height), (3, 2, 1, 2));
    }

    /// Issue #150: `codecID` 0 is unencoded, and bottom-up like legacy graphics' bitmaps.
    #[test]
    fn unencoded_surface_bits_paint_bottom_up() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let bgra = [1, 2, 3, 0, 4, 5, 6, 0];
        let outputs = sm
            .process_bytes(&surface_commands_pdu(&set_surface_bits(
                0, 0, 1, 2, 0, &bgra,
            )))
            .unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        let px = frame_pixels(&sm, frame);
        assert_eq!((&px[..3], &px[4..7]), (&[6, 5, 4][..], &[3, 2, 1][..]));
    }

    /// Frame Markers paint nothing, and do not stop the commands around them.
    #[test]
    fn frame_markers_bracket_surface_bits_without_painting() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let mut body = frame_marker(surface_commands::FRAMEACTION_BEGIN);
        body.extend(set_surface_bits(
            0,
            0,
            1,
            2,
            capability::CODEC_ID_NSCODEC,
            &nscodec_1x2(),
        ));
        body.extend(frame_marker(surface_commands::FRAMEACTION_END));
        let outputs = sm.process_bytes(&surface_commands_pdu(&body)).unwrap();
        assert!(
            matches!(outputs.as_slice(), [SessionOutput::Frame(_)]),
            "{outputs:?}"
        );
        let markers_only = frame_marker(surface_commands::FRAMEACTION_BEGIN);
        assert!(
            sm.process_bytes(&surface_commands_pdu(&markers_only))
                .unwrap()
                .is_empty()
        );
    }

    /// A codec ID the Confirm Active never assigned is skipped, not fatal (ADR-0009 §2) — and so
    /// is NSCodec's ID when NSCodec was not advertised.
    #[test]
    fn surface_bits_in_a_codec_never_advertised_paint_nothing() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let bits = set_surface_bits(0, 0, 1, 2, 3, &[0; 8]);
        assert_eq!(
            sm.process_bytes(&surface_commands_pdu(&bits)),
            Ok(Vec::new())
        );

        let mut cfg = config();
        cfg.capabilities
            .retain(|set| !matches!(set, CapabilitySet::BitmapCodecs(_)));
        let mut sm = SessionStateMachine::new(cfg, Vec::new()).unwrap();
        let bits = set_surface_bits(0, 0, 1, 2, capability::CODEC_ID_NSCODEC, &nscodec_1x2());
        assert_eq!(
            sm.process_bytes(&surface_commands_pdu(&bits)),
            Ok(Vec::new())
        );

        // NSCodec under another codec ID, which the connect layer refuses, does not count.
        let mut cfg = config();
        for set in &mut cfg.capabilities {
            if let CapabilitySet::BitmapCodecs(c) = set {
                c.codecs[0].id = 2;
            }
        }
        let mut sm = SessionStateMachine::new(cfg, Vec::new()).unwrap();
        assert_eq!(
            sm.process_bytes(&surface_commands_pdu(&bits)),
            Ok(Vec::new())
        );
    }

    /// Surface bits larger than the desktop are refused before any decoder allocates.
    #[test]
    fn surface_bits_larger_than_the_desktop_are_refused() {
        for (w, h) in [(17, 1), (1, 9)] {
            let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
            let bits = set_surface_bits(0, 0, w, h, capability::CODEC_ID_NSCODEC, &[]);
            assert_eq!(
                sm.process_bytes(&surface_commands_pdu(&bits)),
                Err(SessionError::Decode(
                    justrdp_pdu::DecodeError::InvalidField {
                        field: "TS_BITMAP_DATA_EX",
                        reason: "surface bits exceed the negotiated desktop size",
                    }
                )),
                "{w}x{h}"
            );
        }
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let bits = set_surface_bits(0, 0, 16, 8, 0, &[0; 16 * 8 * 4]);
        assert!(
            sm.process_bytes(&surface_commands_pdu(&bits)).is_ok(),
            "the desktop size fits"
        );
    }

    /// NSCodec bitmap data that does not decode is a typed error.
    #[test]
    fn malformed_nscodec_surface_bits_are_a_typed_error() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let bits = set_surface_bits(0, 0, 1, 2, capability::CODEC_ID_NSCODEC, &[0; 4]);
        assert!(matches!(
            sm.process_bytes(&surface_commands_pdu(&bits)),
            Err(SessionError::Nscodec(_))
        ));
    }

    /// A desktop-sized NSCodec stream whose four planes are all empty: the decoder fills every
    /// plane, so 20 bytes of header buy a full-desktop decode (#367).
    fn nscodec_empty_planes() -> Vec<u8> {
        let mut nsc = vec![0u8; 16];
        nsc.extend_from_slice(&[1, 0, 0, 0]);
        nsc
    }

    /// Issue #367: one Surface Commands update buys at most `PAINT_BUDGET_FRAMEBUFFERS`
    /// desktops of decoding; the commands past it are skipped, not fatal, and the next update
    /// is charged afresh.
    #[test]
    fn surface_bits_past_the_paint_budget_are_skipped() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let body: Vec<u8> = (0..5)
            .flat_map(|_| {
                set_surface_bits(
                    0,
                    0,
                    16,
                    8,
                    capability::CODEC_ID_NSCODEC,
                    &nscodec_empty_planes(),
                )
            })
            .collect();
        for _ in 0..2 {
            let outputs = sm.process_bytes(&surface_commands_pdu(&body)).unwrap();
            assert_eq!(
                outputs.len(),
                PAINT_BUDGET_FRAMEBUFFERS,
                "exactly the budget's worth of desktops is painted: {outputs:?}"
            );
        }
    }

    /// The charge is the decoded size, not the clipped one: a desktop-sized bitmap at the last
    /// pixel paints one pixel and still costs a desktop's decode.
    #[test]
    fn the_paint_budget_charges_what_is_decoded_not_what_is_clipped() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let body: Vec<u8> = (0..5)
            .flat_map(|_| {
                set_surface_bits(
                    15,
                    7,
                    16,
                    8,
                    capability::CODEC_ID_NSCODEC,
                    &nscodec_empty_planes(),
                )
            })
            .collect();
        let outputs = sm.process_bytes(&surface_commands_pdu(&body)).unwrap();
        assert_eq!(outputs.len(), PAINT_BUDGET_FRAMEBUFFERS, "{outputs:?}");
    }

    /// Issue #367: legacy graphics' bitmap rectangles are charged the same way.
    #[test]
    fn bitmap_rectangles_past_the_paint_budget_are_skipped() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let mut body = update::UPDATETYPE_BITMAP.to_le_bytes().to_vec();
        body.extend_from_slice(&5u16.to_le_bytes());
        for _ in 0..5 {
            for v in [0u16, 0, 15, 7, 16, 8, 24, 0] {
                body.extend_from_slice(&v.to_le_bytes());
            }
            body.extend_from_slice(&((16 * 8 * 3) as u16).to_le_bytes());
            body.extend_from_slice(&[7; 16 * 8 * 3]);
        }
        let pdu = fastpath::encode_pdu(&[(
            fastpath::FP_UPDATE_BITMAP,
            fastpath::FP_FRAGMENT_SINGLE,
            &body,
        )]);
        let outputs = sm.process_bytes(&pdu).unwrap();
        assert_eq!(outputs.len(), PAINT_BUDGET_FRAMEBUFFERS, "{outputs:?}");
    }

    /// One Set Surface Bits command shaped to reach the decoders (#369): a bitmap mostly inside
    /// a 64x48 desktop, codec 1 most often, and NSCodec planes whose counts often equal their
    /// decoded sizes, so the planes are copied raw rather than failing the RLE.
    fn reaching_surface_bits() -> impl proptest::strategy::Strategy<Value = Vec<u8>> {
        use proptest::prelude::*;
        let geometry = (0u16..=72, 0u16..=56, 1u16..=64, 1u16..=48);
        let codec =
            prop_oneof![6 => Just(capability::CODEC_ID_NSCODEC), 2 => Just(0u8), 1 => any::<u8>()];
        let counts = prop_oneof![4 => Just(None), 1 => proptest::collection::vec(0u32..=8192, 4).prop_map(Some)];
        (geometry, codec, 1u8..=7, any::<bool>(), counts, any::<u8>()).prop_map(
            |((x, y, w, h), codec_id, cll, subsampled, counts, fill)| {
                let data = match codec_id {
                    capability::CODEC_ID_NSCODEC => {
                        let sizes = nscodec::plane_sizes(w.into(), h.into(), subsampled)
                            .expect("a 64x48 bitmap's planes are sized");
                        let counts =
                            counts.map_or(sizes.map(|n| n as u32), |c| [c[0], c[1], c[2], c[3]]);
                        let mut nsc = Vec::new();
                        for count in counts {
                            nsc.extend_from_slice(&count.to_le_bytes());
                        }
                        nsc.extend_from_slice(&[cll, u8::from(subsampled), 0, 0]);
                        let body: u32 = counts.iter().sum();
                        nsc.extend(std::iter::repeat_n(fill, body.min(65_536) as usize));
                        nsc
                    }
                    _ => vec![fill; usize::from(w) * usize::from(h) * 4],
                };
                set_surface_bits(x, y, w, h, codec_id, &data)
            },
        )
    }

    proptest::proptest! {
        // ADR-0008 and #369: the session's Surface Bits path never panics, over inputs weighted
        // to get past the NSCodec header and the size refusal into the decode and the blit.
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]
        #[test]
        fn surface_bits_through_the_session_never_panic(
            commands in proptest::collection::vec(reaching_surface_bits(), 1..=4),
        ) {
            let mut cfg = config();
            cfg.desktop_size = (64, 48);
            let mut sm = SessionStateMachine::new(cfg, Vec::new()).unwrap();
            let _ = sm.process_bytes(&surface_commands_pdu(&commands.concat()));
        }
    }

    /// Issue #368: `[MS-RDPBCGR]` 3.2.5.9.3.1 allows only FIRST (NEXT...) LAST, and "any
    /// deviation ... SHOULD trigger a disconnect". A FIRST or a SINGLE arriving while a
    /// fragmented update is open is one, and is refused like a NEXT without a FIRST.
    #[test]
    fn a_first_or_single_fragment_inside_an_open_sequence_is_refused() {
        let body = bitmap_update_body(0, 0, 4, 2, [1, 2, 3]);
        let (head, _) = body.split_at(10);
        for interrupting in [fastpath::FP_FRAGMENT_FIRST, fastpath::FP_FRAGMENT_SINGLE] {
            let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
            let first = fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_FIRST,
                head,
            )]);
            assert_eq!(sm.process_bytes(&first), Ok(Vec::new()));
            let next = fastpath::encode_pdu(&[(fastpath::FP_UPDATE_BITMAP, interrupting, &body)]);
            assert_eq!(
                sm.process_bytes(&next),
                Err(SessionError::Decode(
                    justrdp_pdu::DecodeError::InvalidField {
                        field: "TS_FP_UPDATE.fragmentation",
                        reason: "a fragment sequence was interrupted before its last fragment",
                    }
                )),
                "fragmentation {interrupting}"
            );
        }
    }

    fn config() -> SessionConfig {
        SessionConfig {
            user_channel_id: USER,
            io_channel_id: IO,
            share_id: SHARE,
            desktop_size: (16, 8),
            capabilities: capability::default_client_capabilities(&test_core()),
            server_input_flags: capability::INPUT_FLAG_SCANCODES
                | capability::INPUT_FLAG_FASTPATH_INPUT2,
            drdynvc_channel_id: Some(DRDYNVC),
            static_channels: [
                ("cliprdr", CLIPRDR, 0),
                ("drdynvc", DRDYNVC, 0),
                ("rdpdr", RDPDR, 0),
                ("rail", RAIL, justrdp_pdu::gcc::CHANNEL_OPTION_SHOW_PROTOCOL),
            ]
            .into_iter()
            .map(|(name, id, options)| crate::StaticChannel {
                name: name.to_string(),
                id,
                options,
            })
            .collect(),
            dynamic_channels: vec![HOST_DVC.to_string()],
            egfx: Default::default(),
        }
    }

    /// The dynamic channel name [`config`] registers for the host.
    const HOST_DVC: &str = "Test::Host::Channel";

    /// The exact 32 bytes this client put on the wire during #198's probe, which the real VM
    /// **parsed and answered** (with `PDUTYPE2_SHUTDOWN_DENIED`). Pinned here rather than
    /// re-derived from the spec, because "a server accepted this" is a stronger statement about
    /// a send path than "we read the layout the same way twice".
    ///
    /// Decoded, so a future reader does not have to:
    ///
    /// ```text
    /// 03 00 00 20                 TPKT   version 3, length 32
    /// 02 f0 80                    X.224  Data TPDU
    /// 64 00 05 03 eb 70 12        MCS    SendDataRequest, initiator 1006, channel 1003, 18 bytes
    /// 12 00 17 00 ee 03           Share  totalLength 18, PDUTYPE_DATA | version 0x0010, source 1006
    /// ea 03 01 00                 shareId 0x000103EA
    /// 00 02 00 00 24 00 00 00     Data   pad, STREAM_MED, uncompressed 0, pduType2 0x24, no compression
    /// ```
    ///
    /// The body is empty: `[MS-RDPBCGR]` 2.2.2.1 makes the Share Data header the whole PDU.
    #[test]
    fn request_shutdown_encodes_the_frame_the_vm_answered() {
        let sm = SessionStateMachine::new(
            SessionConfig {
                user_channel_id: 1006,
                io_channel_id: 1003,
                share_id: 0x0001_03EA,
                ..config()
            },
            Vec::new(),
        )
        .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let frames = sm.request_shutdown();
        assert_eq!(frames.len(), 1, "one frame, not a batch");
        assert_eq!(
            frames[0],
            vec![
                0x03, 0x00, 0x00, 0x20, 0x02, 0xf0, 0x80, 0x64, 0x00, 0x05, 0x03, 0xeb, 0x70, 0x12,
                0x12, 0x00, 0x17, 0x00, 0xee, 0x03, 0xea, 0x03, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00,
                0x24, 0x00, 0x00, 0x00,
            ]
        );
    }

    /// The refusal is the *point*: a host that asks for a shutdown has to be able to hear "no",
    /// and before this it was a `pduType2` the dispatcher skipped in silence.
    #[test]
    fn a_shutdown_denied_surfaces_to_the_host() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let outputs = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_SHUTDOWN_DENIED, &[]))
            .expect("a bodyless refusal decodes");
        assert_eq!(outputs, vec![SessionOutput::ShutdownDenied]);
    }

    /// Issue #309, at the level the defect showed up. A Flow Control PDU used to **end the
    /// session**: the header decoder demanded ten bytes of an eight-byte PDU. 2.2.8.1.1.1.1 says
    /// it MUST be ignored — so the proof is that the session survives *and the next PDU still
    /// reaches the host*, not merely that the decode stopped failing.
    ///
    /// **All three T.128 flow types, and the reason is the first one.** This test was written
    /// with only `0x42` and a mutation removing the `0x8000` branch left it green: `0x42 & 0xF`
    /// is 2, which is no Share PDU type, so the ordinary path skipped it by luck. `0x41` masks
    /// to 1 — `PDUTYPE_DEMANDACTIVEPDU` — and without the branch the machine runs a
    /// reactivation over two bytes of flow header. Values are FreeRDP's `PDU_TYPE_FLOW_*`.
    #[test]
    fn a_flow_control_pdu_is_ignored_and_the_session_keeps_going() {
        const FLOW_TEST: u8 = 0x41;
        const FLOW_RESPONSE: u8 = 0x42;
        const FLOW_STOP: u8 = 0x43;
        for flow_type in [FLOW_TEST, FLOW_RESPONSE, FLOW_STOP] {
            let mut sm = SessionStateMachine::new(config(), Vec::new())
                .expect("the test desktop size is within MAX_DESKTOP_DIM");
            // totalLength = 0x8000, pduTypeFlow, pad, flowIdentifier, flowNumber, pduSource
            let flow = [0x00, 0x80, flow_type, 0x00, 0x01, 0x02, 0xEA, 0x03];
            let outputs = sm
                .process_bytes(&server_io_frame(&flow))
                .unwrap_or_else(|e| panic!("Flow PDU {flow_type:#04x} must be ignored: {e:?}"));
            assert!(outputs.is_empty(), "{flow_type:#04x}: nothing surfaces");
            assert_eq!(
                sm.phase,
                Phase::Active,
                "{flow_type:#04x}: and the machine does not move"
            );

            let outputs = sm
                .process_bytes(&server_data_pdu(share::PDU_TYPE2_SHUTDOWN_DENIED, &[]))
                .unwrap_or_else(|e| panic!("{flow_type:#04x}: the session must survive: {e:?}"));
            assert_eq!(outputs, vec![SessionOutput::ShutdownDenied]);
        }
    }

    /// Issue #309. A header-only Deactivate All — six bytes, the spec's whole header, no
    /// `shareId` — used to end the session. IronRDP records xrdp sending exactly this.
    #[test]
    fn a_header_only_deactivate_all_deactivates_instead_of_ending_the_session() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let mut deactivate = 6u16.to_le_bytes().to_vec();
        deactivate.extend_from_slice(&(share::PDU_TYPE_DEACTIVATE_ALL | 0x0010).to_le_bytes());
        deactivate.extend_from_slice(&1002u16.to_le_bytes());
        sm.process_bytes(&server_io_frame(&deactivate))
            .expect("a six-byte header is not malformed");
        assert_eq!(sm.phase, Phase::Deactivated);
    }

    /// A Save Session Info body carrying a Plain Notify — the shortest well-formed one there
    /// is, and the only variant with nothing to assert about its contents.
    fn plain_notify_body() -> Vec<u8> {
        let mut body = session_info::INFOTYPE_LOGON_PLAINNOTIFY
            .to_le_bytes()
            .to_vec();
        body.extend_from_slice(&[0u8; 576]);
        body
    }

    /// …and it is *only* the refusal that surfaces. A neighbouring `pduType2` must not, or the
    /// host learns "the server refused" from a PDU that said nothing of the kind — the same
    /// side-condition that makes the positive assertion above mean anything.
    #[test]
    fn a_neighbouring_data_pdu_is_not_mistaken_for_a_refusal() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        for pdu_type2 in [
            share::PDU_TYPE2_SHUTDOWN_REQUEST, // 0x24 — ours to send, never to receive
            0x2D,                              // Set Keyboard IME Status — catch-all, unread
        ] {
            let outputs = sm
                .process_bytes(&server_data_pdu(pdu_type2, &[]))
                .expect("an unhandled data PDU is skipped, not fatal");
            assert!(
                outputs.is_empty(),
                "pduType2 {pdu_type2:#04x} must not surface as a refusal"
            );
        }
        // 0x26 and 0x29 used to sit in that list, as `pduType2`s the dispatcher skipped in
        // silence. Since #304 and #305 each has a handler, so the side condition they carry is
        // the stronger one: handled neighbours must not be mistaken for each other.
        let outputs = sm
            .process_bytes(&server_data_pdu(
                share::PDU_TYPE2_SAVE_SESSION_INFO,
                &plain_notify_body(),
            ))
            .expect("a well-formed Save Session Info decodes");
        assert_eq!(
            outputs,
            vec![SessionOutput::SaveSessionInfo(
                session_info::SaveSessionInfo::PlainNotify
            )]
        );
        let outputs = sm
            .process_bytes(&server_data_pdu(
                share::PDU_TYPE2_SET_KEYBOARD_INDICATORS,
                &[0, 0, input::SYNC_CAPS_LOCK, 0],
            ))
            .expect("a well-formed Set Keyboard Indicators decodes");
        assert_eq!(
            outputs,
            vec![SessionOutput::KeyboardIndicators(
                input::KeyboardIndicators { led_flags: 0x0004 }
            )]
        );
        let outputs = sm
            .process_bytes(&server_data_pdu(
                share::PDU_TYPE2_PLAY_SOUND,
                &[0x2C, 0x01, 0, 0, 0x20, 0x03, 0, 0],
            ))
            .expect("a well-formed Play Sound decodes");
        assert_eq!(
            outputs,
            vec![SessionOutput::PlaySound(sound::PlaySound {
                duration: 300,
                frequency: 800
            })]
        );
    }

    /// Issue #305: the server's lock state reaches the host, one output per PDU, as sent.
    #[test]
    fn set_keyboard_indicators_surfaces_the_server_lock_state() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        for led_flags in [0x0000u16, 0x0002, 0x0006, 0x000F] {
            let mut body = 0u16.to_le_bytes().to_vec(); // unitId
            body.extend_from_slice(&led_flags.to_le_bytes());
            let outputs = sm
                .process_bytes(&server_data_pdu(
                    share::PDU_TYPE2_SET_KEYBOARD_INDICATORS,
                    &body,
                ))
                .expect("a well-formed Set Keyboard Indicators decodes");
            assert_eq!(
                outputs,
                vec![SessionOutput::KeyboardIndicators(
                    input::KeyboardIndicators { led_flags }
                )],
                "ledFlags {led_flags:#06x}"
            );
        }
        assert_eq!(sm.phase, Phase::Active);
    }

    /// Issue #354: the beep the default Sound set invites reaches the host, as sent.
    #[test]
    fn play_sound_surfaces_the_beep() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        for (duration, frequency) in [(300u32, 800u32), (0, 0), (u32::MAX, 37)] {
            let mut body = duration.to_le_bytes().to_vec();
            body.extend_from_slice(&frequency.to_le_bytes());
            let outputs = sm
                .process_bytes(&server_data_pdu(share::PDU_TYPE2_PLAY_SOUND, &body))
                .expect("a well-formed Play Sound decodes");
            assert_eq!(
                outputs,
                vec![SessionOutput::PlaySound(sound::PlaySound {
                    duration,
                    frequency
                })],
                "duration {duration}, frequency {frequency}"
            );
        }
        assert_eq!(sm.phase, Phase::Active);
    }

    #[test]
    fn a_truncated_play_sound_is_a_typed_error() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let result = sm.process_bytes(&server_data_pdu(
            share::PDU_TYPE2_PLAY_SOUND,
            &[0x2C, 0x01, 0, 0, 0x20, 0x03, 0],
        ));
        assert!(
            matches!(result, Err(SessionError::Decode(_))),
            "got {result:?}"
        );
    }

    #[test]
    fn a_truncated_set_keyboard_indicators_is_a_typed_error() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let result = sm.process_bytes(&server_data_pdu(
            share::PDU_TYPE2_SET_KEYBOARD_INDICATORS,
            &[0, 0, 4],
        ));
        assert!(
            matches!(result, Err(SessionError::Decode(_))),
            "got {result:?}"
        );
    }

    fn test_core() -> justrdp_pdu::gcc::ClientCoreData {
        justrdp_pdu::gcc::ClientCoreData {
            version: justrdp_pdu::gcc::RDP_VERSION_10_12,
            desktop_width: 16,
            desktop_height: 8,
            keyboard_layout: 0x409,
            client_build: 1,
            client_name: "session-test".to_string(),
            keyboard_type: justrdp_pdu::gcc::KEYBOARD_TYPE_IBM_ENHANCED,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            ime_file_name: String::new(),
            post_beta2_color_depth: justrdp_pdu::gcc::COLOR_DEPTH_8BPP,
            client_product_id: 1,
            serial_number: 0,
            high_color_depth: justrdp_pdu::gcc::HIGH_COLOR_DEPTH_24BPP,
            supported_color_depths: justrdp_pdu::gcc::SUPPORTED_COLOR_DEPTH_24BPP,
            early_capability_flags: justrdp_pdu::gcc::ClientEarlyCapabilityFlags::empty(),
            dig_product_id: String::new(),
            connection_type: justrdp_pdu::gcc::CONNECTION_TYPE_LAN,
            server_selected_protocol: justrdp_pdu::nego::SecurityProtocol::from_bits(0),
        }
    }

    /// Frame a server→client payload on `channel` (SendDataIndication is encoded by hand:
    /// choice 0x68, initiator 1002, the channel, then a PER length).
    fn server_channel_frame(channel: u16, user_data: &[u8]) -> Vec<u8> {
        let mut body = vec![0x68];
        body.extend_from_slice(&(1002u16 - 1001).to_be_bytes());
        body.extend_from_slice(&channel.to_be_bytes());
        body.push(0x70);
        if user_data.len() < 128 {
            body.push(user_data.len() as u8);
        } else {
            body.extend_from_slice(&(0x8000u16 | user_data.len() as u16).to_be_bytes());
        }
        body.extend_from_slice(user_data);
        tpkt::encode(&x224::encode_data(&body))
    }

    /// Frame a server→client I/O payload.
    fn server_io_frame(user_data: &[u8]) -> Vec<u8> {
        server_channel_frame(IO, user_data)
    }

    /// Frame one complete drdynvc PDU as server→client SVC chunks on the drdynvc channel.
    fn server_dvc_frames(pdu: &[u8]) -> Vec<Vec<u8>> {
        svc::encode_chunks(pdu)
            .iter()
            .map(|chunk| server_channel_frame(DRDYNVC, chunk))
            .collect()
    }

    /// Walk a fresh machine to the resize-ready state: drdynvc caps exchanged, Display
    /// Control channel 7 created, server caps (1 monitor, `area_a × area_b`) consumed.
    fn display_control_ready(sm: &mut SessionStateMachine, area_a: u32, area_b: u32) {
        display_control_ready_caps(sm, 1, area_a, area_b);
    }

    fn display_control_ready_caps(
        sm: &mut SessionStateMachine,
        max_num_monitors: u32,
        area_a: u32,
        area_b: u32,
    ) {
        let caps_request = vec![0x50, 0x00, 0x01, 0x00];
        for frame in server_dvc_frames(&caps_request) {
            sm.process_bytes(&frame).unwrap();
        }
        let mut create = vec![0x10, 0x07];
        create.extend_from_slice(displaycontrol::CHANNEL_NAME.as_bytes());
        create.push(0);
        for frame in server_dvc_frames(&create) {
            sm.process_bytes(&frame).unwrap();
        }
        let mut caps = Vec::new();
        caps.extend_from_slice(&displaycontrol::TYPE_CAPS.to_le_bytes());
        caps.extend_from_slice(&20u32.to_le_bytes());
        for v in [max_num_monitors, area_a, area_b] {
            caps.extend_from_slice(&v.to_le_bytes());
        }
        let mut ready = false;
        for pdu in dvc::encode_data(7, &caps) {
            for frame in server_dvc_frames(&pdu) {
                for output in sm.process_bytes(&frame).unwrap() {
                    ready |= output == SessionOutput::DisplayControlReady;
                }
            }
        }
        assert!(ready, "DisplayControlReady never surfaced");
    }

    /// A machine parked in [`Phase::Reactivating`]: DeactivateAll, then a Demand Active for an
    /// 8x4 desktop. This is the state the server's Synchronize / Control replies arrive in on a
    /// real resize (#252, measured against the VM).
    fn reactivating() -> SessionStateMachine {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let deactivate = server_io_frame(&share::encode_share_control(
            share::PDU_TYPE_DEACTIVATE_ALL,
            1002,
            SHARE,
            &[],
        ));
        assert!(sm.process_bytes(&deactivate).unwrap().is_empty());

        let sets = vec![CapabilitySet::Bitmap(capability::BitmapCapabilitySet {
            preferred_bits_per_pixel: 24,
            desktop_width: 8,
            desktop_height: 4,
            desktop_resize_flag: 1,
            drawing_flags: 0,
        })];
        let mut caps = Vec::new();
        for set in &sets {
            set.encode(&mut caps);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes());
        body.extend_from_slice(&((caps.len() + 4) as u16).to_le_bytes());
        body.extend_from_slice(b"RDP\0");
        body.extend_from_slice(&(sets.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&caps);
        body.extend_from_slice(&0u32.to_le_bytes());
        let demand = server_io_frame(&share::encode_share_control(
            share::PDU_TYPE_DEMAND_ACTIVE,
            1002,
            SHARE + 1,
            &body,
        ));
        let outputs = sm.process_bytes(&demand).unwrap();
        assert_eq!(outputs.len(), 5, "Confirm Active + the finalization batch");
        sm
    }

    fn server_data_pdu(pdu_type2: u8, body: &[u8]) -> Vec<u8> {
        server_io_frame(&share::encode_share_data(
            1002,
            SHARE,
            share::STREAM_MED,
            pdu_type2,
            body,
        ))
    }

    /// [`server_data_pdu`] with the Share Data header's `compressedType` byte replaced.
    fn server_data_pdu_compressed_type(pdu_type2: u8, compressed_type: u8, body: &[u8]) -> Vec<u8> {
        let mut user_data =
            share::encode_share_data(1002, SHARE, share::STREAM_MED, pdu_type2, body);
        // shareControlHeader (6) + shareId (4) + pad (1) + streamId (1) + uncompressedLength (2)
        // + pduType2 (1) puts compressedType at 15.
        assert_eq!((user_data[14], user_data[15]), (pdu_type2, 0));
        user_data[15] = compressed_type;
        server_io_frame(&user_data)
    }

    /// An uncompressed 24-bpp bitmap update: one rect at (x,y), w×h, all pixels `bgr`.
    fn bitmap_update_frame(x: u16, y: u16, w: u16, h: u16, bgr: [u8; 3]) -> Vec<u8> {
        server_data_pdu(
            share::PDU_TYPE2_UPDATE,
            &bitmap_update_body(x, y, w, h, bgr),
        )
    }

    /// A TS_FP_POINTERATTRIBUTE body: a 1×1 shape at `xor_bpp` 32 with one BGRA pixel,
    /// AND mask all zeros (opaque).
    fn new_pointer_body(cache_index: u16, bgra: [u8; 4], hot_spot: (u16, u16)) -> Vec<u8> {
        let mut body = Vec::new();
        for v in [
            32u16, // xorBpp
            cache_index,
            hot_spot.0,
            hot_spot.1,
            1, // width
            1, // height
            2, // lengthAndMask (1 bit padded to 2 bytes)
            4, // lengthXorMask
        ] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(&bgra);
        body.extend_from_slice(&[0x00, 0x00]); // andMaskData
        body
    }

    fn fastpath_pointer_pdu(code: u8, body: &[u8]) -> Vec<u8> {
        fastpath::encode_pdu(&[(code, fastpath::FP_FRAGMENT_SINGLE, body)])
    }

    #[test]
    fn fastpath_new_pointer_emits_set_cursor_and_caches_the_shape() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");

        let body = new_pointer_body(3, [10, 20, 30, 200], (5, 4));
        let outputs = sm
            .process_bytes(&fastpath_pointer_pdu(
                fastpath::FP_UPDATE_NEW_POINTER,
                &body,
            ))
            .unwrap();
        let [SessionOutput::Cursor(CursorEvent::Set(image))] = outputs.as_slice() else {
            panic!("expected one SetCursor, got {outputs:?}");
        };
        assert_eq!((image.width, image.height), (1, 1));
        assert_eq!((image.hotspot_x, image.hotspot_y), (5, 4));
        // BGRA source → straight-alpha RGBA.
        assert_eq!(image.rgba, [30, 20, 10, 200]);

        // A Cached re-select of the same slot re-emits the stored shape.
        let outputs = sm
            .process_bytes(&fastpath_pointer_pdu(
                fastpath::FP_UPDATE_CACHED_POINTER,
                &3u16.to_le_bytes(),
            ))
            .unwrap();
        let [SessionOutput::Cursor(CursorEvent::Set(cached))] = outputs.as_slice() else {
            panic!("expected the cached SetCursor, got {outputs:?}");
        };
        assert_eq!(cached.rgba, [30, 20, 10, 200]);
        assert_eq!((cached.hotspot_x, cached.hotspot_y), (5, 4));
    }

    #[test]
    fn frames_split_across_process_bytes_calls_reassemble() {
        // The inbox contract (#86): a frame arriving in two chunks produces nothing on the
        // first call and the full output on the second.
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let frame = bitmap_update_frame(0, 0, 4, 4, [9, 8, 7]);
        let (a, b) = frame.split_at(5);
        assert!(sm.process_bytes(a).unwrap().is_empty());
        let outputs = sm.process_bytes(b).unwrap();
        assert!(
            matches!(outputs.as_slice(), [SessionOutput::Frame(_)]),
            "expected the reassembled frame, got {outputs:?}"
        );
    }

    /// Issue #253. justrdp has no bulk decompressor, so a Share Data PDU flagged
    /// `PACKET_COMPRESSED` is a typed error rather than its compressed bytes read as fields —
    /// the answer fast-path and the SVC layer already give (ADR-0009 §1). The body is a valid
    /// uncompressed bitmap update, so without the check this paints a frame.
    #[test]
    fn a_compressed_share_data_pdu_is_a_typed_error() {
        let body = bitmap_update_body(0, 0, 4, 4, [9, 8, 7]);
        for compressed_type in [0x20, 0x21, 0xA1] {
            let mut sm = SessionStateMachine::new(config(), Vec::new())
                .expect("the test desktop size is within MAX_DESKTOP_DIM");
            let frame =
                server_data_pdu_compressed_type(share::PDU_TYPE2_UPDATE, compressed_type, &body);
            assert!(
                matches!(
                    sm.process_bytes(&frame),
                    Err(SessionError::Decode(
                        justrdp_pdu::DecodeError::InvalidField {
                            field: "TS_SHAREDATAHEADER.compressedType",
                            ..
                        }
                    ))
                ),
                "compressedType {compressed_type:#04x} should be refused"
            );
        }
    }

    /// The other half of #253's predicate: without `PACKET_COMPRESSED` the payload is plain
    /// bytes whatever the type nibble, `PACKET_AT_FRONT` or `PACKET_FLUSHED` say
    /// (2.2.8.1.1.1.2), so none of them is refused.
    #[test]
    fn share_data_flags_without_packet_compressed_still_decode() {
        let body = bitmap_update_body(0, 0, 4, 4, [9, 8, 7]);
        for compressed_type in [0x01, 0x40, 0x80, 0xCF] {
            let mut sm = SessionStateMachine::new(config(), Vec::new())
                .expect("the test desktop size is within MAX_DESKTOP_DIM");
            let frame =
                server_data_pdu_compressed_type(share::PDU_TYPE2_UPDATE, compressed_type, &body);
            let outputs = sm
                .process_bytes(&frame)
                .unwrap_or_else(|e| panic!("compressedType {compressed_type:#04x}: {e:?}"));
            assert!(
                matches!(outputs.as_slice(), [SessionOutput::Frame(_)]),
                "compressedType {compressed_type:#04x} should paint, got {outputs:?}"
            );
        }
    }

    #[test]
    fn multiple_frames_in_one_call_process_in_order() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let mut bytes = bitmap_update_frame(0, 0, 4, 4, [1, 2, 3]);
        bytes.extend_from_slice(&bitmap_update_frame(4, 0, 4, 4, [4, 5, 6]));
        let outputs = sm.process_bytes(&bytes).unwrap();
        let [SessionOutput::Frame(first), SessionOutput::Frame(second)] = outputs.as_slice() else {
            panic!("expected two frames, got {outputs:?}");
        };
        assert_eq!((first.x, second.x), (0, 4));
    }

    #[test]
    fn fastpath_hidden_and_default_pointers_emit_their_events() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");

        let outputs = sm
            .process_bytes(&fastpath_pointer_pdu(fastpath::FP_UPDATE_PTR_NULL, &[]))
            .unwrap();
        assert_eq!(outputs, vec![SessionOutput::Cursor(CursorEvent::Hidden)]);

        let outputs = sm
            .process_bytes(&fastpath_pointer_pdu(fastpath::FP_UPDATE_PTR_DEFAULT, &[]))
            .unwrap();
        assert_eq!(outputs, vec![SessionOutput::Cursor(CursorEvent::Default)]);
    }

    #[test]
    fn slowpath_pointer_messages_ride_the_pointer_data_pdu() {
        // The slow-path transport for the same updates: a TS_POINTER_PDU as a Share Data PDU
        // body. Position is the message servers send most.
        let mut body = justrdp_pdu::pointer::PTRMSGTYPE_POSITION
            .to_le_bytes()
            .to_vec();
        body.extend_from_slice(&0u16.to_le_bytes()); // pad2Octets
        body.extend_from_slice(&7u16.to_le_bytes());
        body.extend_from_slice(&6u16.to_le_bytes());

        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let outputs = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_POINTER, &body))
            .unwrap();
        assert_eq!(
            outputs,
            vec![SessionOutput::Cursor(CursorEvent::Move { x: 7, y: 6 })]
        );
    }

    #[test]
    fn slowpath_color_pointer_decodes_as_24bpp() {
        // TS_PTRMSGTYPE_COLOR carries an implicit 24-bpp shape. 1×1: xor stride is 4 bytes
        // (24 bits → 2-byte aligned), BGR + 1 pad byte.
        let mut attr = Vec::new();
        for v in [2u16, 0, 0, 1, 1, 2, 4] {
            attr.extend_from_slice(&v.to_le_bytes());
        }
        attr.extend_from_slice(&[1, 2, 3, 0]); // xor: B=1 G=2 R=3 + stride pad
        attr.extend_from_slice(&[0x00, 0x00]); // and
        let mut body = justrdp_pdu::pointer::PTRMSGTYPE_COLOR
            .to_le_bytes()
            .to_vec();
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&attr);

        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let outputs = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_POINTER, &body))
            .unwrap();
        let [SessionOutput::Cursor(CursorEvent::Set(image))] = outputs.as_slice() else {
            panic!("expected SetCursor, got {outputs:?}");
        };
        assert_eq!(image.rgba, [3, 2, 1, 255]);
    }

    #[test]
    fn cached_pointer_misuse_is_a_typed_error() {
        // Index beyond the advertised cache size (default capset: 20 entries): protocol
        // violation, fatal per plan.md §11c.
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        assert!(matches!(
            sm.process_bytes(&fastpath_pointer_pdu(
                fastpath::FP_UPDATE_CACHED_POINTER,
                &20u16.to_le_bytes(),
            )),
            Err(SessionError::Decode(_))
        ));

        // A never-filled slot inside the bounds is the same desync.
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        assert!(matches!(
            sm.process_bytes(&fastpath_pointer_pdu(
                fastpath::FP_UPDATE_CACHED_POINTER,
                &0u16.to_le_bytes(),
            )),
            Err(SessionError::Decode(_))
        ));
    }

    #[test]
    fn a_set_error_info_pdu_becomes_the_disconnect_attribution() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        // Before anything arrives, a close is unattributable.
        assert_eq!(
            sm.disconnect_reason(),
            DisconnectReason::UnexpectedDisconnect
        );

        // ERRINFO_LOGOFF_BY_USER (0x0000000C), then the socket closes (the close itself is
        // the adapter's observation — the machine only records the attribution).
        let outputs = sm
            .process_bytes(&server_data_pdu(
                share::PDU_TYPE2_SET_ERROR_INFO,
                &0x0000_000Cu32.to_le_bytes(),
            ))
            .unwrap();
        assert!(outputs.is_empty(), "attribution is silent, got {outputs:?}");
        assert_eq!(
            sm.disconnect_reason(),
            DisconnectReason::ServerDisconnected(ServerDisconnectCause::ErrorInfo(
                justrdp_pdu::errinfo::ErrorInfo::ProtocolIndependent(
                    justrdp_pdu::errinfo::ProtocolIndependentCode::LogoffByUser
                )
            ))
        );
    }

    #[test]
    fn errinfo_none_does_not_attribute_the_disconnect() {
        // ERRINFO_NONE (0): servers send it to clear state — not an attribution.
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        sm.process_bytes(&server_data_pdu(
            share::PDU_TYPE2_SET_ERROR_INFO,
            &0u32.to_le_bytes(),
        ))
        .unwrap();
        assert_eq!(
            sm.disconnect_reason(),
            DisconnectReason::UnexpectedDisconnect
        );
    }

    #[test]
    fn a_disconnect_provider_ultimatum_attributes_the_disconnect() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let frame = tpkt::encode(&x224::encode_data(
            &mcs::encode_disconnect_provider_ultimatum(mcs::RN_PROVIDER_INITIATED),
        ));
        let outputs = sm.process_bytes(&frame).unwrap();
        assert!(outputs.is_empty());
        assert_eq!(
            sm.disconnect_reason(),
            DisconnectReason::ServerDisconnected(ServerDisconnectCause::ProviderUltimatum {
                reason: mcs::RN_PROVIDER_INITIATED
            })
        );
    }

    #[test]
    fn an_error_info_outranks_the_generic_ultimatum() {
        // The usual server farewell is Error Info (specific) followed by a DPum (generic)
        // followed by close: the specific attribution must win regardless of order.
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        sm.process_bytes(&server_data_pdu(
            share::PDU_TYPE2_SET_ERROR_INFO,
            &0x0000_000Cu32.to_le_bytes(),
        ))
        .unwrap();
        sm.process_bytes(&tpkt::encode(&x224::encode_data(
            &mcs::encode_disconnect_provider_ultimatum(mcs::RN_PROVIDER_INITIATED),
        )))
        .unwrap();
        assert!(matches!(
            sm.disconnect_reason(),
            DisconnectReason::ServerDisconnected(ServerDisconnectCause::ErrorInfo(_))
        ));
    }

    #[test]
    fn a_truncated_error_info_body_is_a_typed_error() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        assert!(matches!(
            sm.process_bytes(&server_data_pdu(
                share::PDU_TYPE2_SET_ERROR_INFO,
                &[0x0C, 0x00]
            )),
            Err(SessionError::Decode(_))
        ));
    }

    #[test]
    fn uncompressed_bitmap_yields_a_frame_update() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let outputs = sm
            .process_bytes(&bitmap_update_frame(2, 1, 4, 2, [10, 20, 30]))
            .unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y, frame.width, frame.height), (2, 1, 4, 2));
        // BGR [10,20,30] → RGBA [30,20,10,255].
        assert_eq!(&frame_pixels(&sm, frame)[..4], &[30, 20, 10, 255]);
        // And the framebuffer holds it at (2,1): row 1 × stride 16 px + col 2, ×4 bytes.
        let off = (16 + 2) * 4;
        assert_eq!(&sm.framebuffer().pixels()[off..off + 4], &[30, 20, 10, 255]);
    }

    #[test]
    fn rle_compressed_bitmap_decodes_through_the_codec() {
        // 4×2 @ 16bpp COLOR_RUN(8) of red (0xF800), flagged compressed without CD header.
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_BITMAP.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [0u16, 0, 3, 1, 4, 2, 16] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(
            &(update::BITMAP_COMPRESSION | update::NO_BITMAP_COMPRESSION_HDR).to_le_bytes(),
        );
        let stream = [0x68, 0x00, 0xF8]; // COLOR_RUN run 8, pixel 0xF800
        body.extend_from_slice(&(stream.len() as u16).to_le_bytes());
        body.extend_from_slice(&stream);

        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let outputs = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_UPDATE, &body))
            .unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        let px = frame_pixels(&sm, frame);
        assert_eq!(&px[..4], &[255, 0, 0, 255]);
        assert!(px.as_chunks::<4>().0.iter().all(|p| *p == [255, 0, 0, 255]));
    }

    #[test]
    fn palette_update_applies_to_subsequent_8bpp_bitmaps() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        // Palette: entry 5 = (1,2,3).
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_PALETTE.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&256u32.to_le_bytes());
        for i in 0..256u16 {
            if i == 5 {
                body.extend_from_slice(&[1, 2, 3]);
            } else {
                body.extend_from_slice(&[0, 0, 0]);
            }
        }
        assert!(
            sm.process_bytes(&server_data_pdu(share::PDU_TYPE2_UPDATE, &body))
                .unwrap()
                .is_empty()
        );

        // 8-bpp uncompressed bitmap of index 5.
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_BITMAP.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [0u16, 0, 3, 0, 4, 1, 8, 0, 4] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(&[5, 5, 5, 5]);
        let outputs = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_UPDATE, &body))
            .unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame");
        };
        assert_eq!(&frame_pixels(&sm, frame)[..4], &[1, 2, 3, 255]);
    }

    /// Issue #252, and this half was found by **measurement**, not by reading. A capture of
    /// `display_control_resize_against_real_vm` (real VM, 2026-08-25) shows the server's
    /// reactivation is `DeactivateAll → Demand Active → Synchronize → Control(Cooperate) →
    /// Control(GrantedControl) → Font Map` — the same four replies as the connect leg. Before
    /// this, three of them fell to the catch-all and the `ReadCursor` was dropped unread, so
    /// the connect path validated a server `action` the reactivation path never even looked at.
    /// That is one family with two answers, which is the shape ADR-0012 §3 exists to end — and
    /// this site is half the evidence for its Amendment 2026-08-25, which extended the rule from
    /// codec families to PDU families rather than leaving two records citing it as precedent.
    ///
    /// (`justrdp-tokio`'s resize test printed a "PDU sequence observed" line naming only
    /// DeactivateAll → Demand Active → Font Map. The capture refutes it; it was a hardcoded
    /// string, not an observation.)
    #[test]
    fn reactivation_holds_the_connect_paths_control_action_rule() {
        let mut sm = reactivating();

        // The two the server actually sends are accepted and change nothing observable.
        for action in [
            finalization::CTRLACTION_COOPERATE,
            finalization::CTRLACTION_GRANTED_CONTROL,
        ] {
            let body = finalization::Control {
                action,
                grant_id: 1007,
                control_id: 1002,
            }
            .encode();
            let outputs = sm
                .process_bytes(&server_data_pdu(share::PDU_TYPE2_CONTROL, &body))
                .expect("a server Control the spec allows is not an error");
            assert!(outputs.is_empty(), "got {outputs:?}");
        }
        // A Synchronize with the mandated messageType likewise.
        let sync = finalization::Synchronize { target_user: 0 }.encode();
        assert!(
            sm.process_bytes(&server_data_pdu(share::PDU_TYPE2_SYNCHRONIZE, &sync))
                .expect("a well-formed Synchronize is not an error")
                .is_empty()
        );

        // …and the ones neither reference accepts are typed errors here too.
        let mut sm = reactivating();
        let detach = finalization::Control {
            action: finalization::CTRLACTION_DETACH,
            grant_id: 0,
            control_id: 0,
        }
        .encode();
        assert!(
            matches!(
                sm.process_bytes(&server_data_pdu(share::PDU_TYPE2_CONTROL, &detach)),
                Err(SessionError::Decode(_))
            ),
            "a server Control(Detach) during reactivation should be a typed error"
        );

        let mut sm = reactivating();
        let bad_sync = [0x02, 0x00, 0x00, 0x00]; // messageType 2
        assert!(
            matches!(
                sm.process_bytes(&server_data_pdu(share::PDU_TYPE2_SYNCHRONIZE, &bad_sync)),
                Err(SessionError::Decode(_))
            ),
            "a Synchronize whose messageType is not SYNCMSGTYPE_SYNC should be a typed error"
        );
    }

    #[test]
    fn deactivate_reactivate_resizes_and_reemits_full_screen() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");

        // DeactivateAll: graphics stop, no output.
        let deactivate = server_io_frame(&share::encode_share_control(
            share::PDU_TYPE_DEACTIVATE_ALL,
            1002,
            SHARE,
            &[],
        ));
        assert!(sm.process_bytes(&deactivate).unwrap().is_empty());

        // Demand Active with a new 8×4 desktop.
        let sets = vec![CapabilitySet::Bitmap(capability::BitmapCapabilitySet {
            preferred_bits_per_pixel: 24,
            desktop_width: 8,
            desktop_height: 4,
            desktop_resize_flag: 1,
            drawing_flags: 0,
        })];
        let mut caps = Vec::new();
        for s in &sets {
            s.encode(&mut caps);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes());
        body.extend_from_slice(&((caps.len() + 4) as u16).to_le_bytes());
        body.extend_from_slice(b"RDP\0");
        body.extend_from_slice(&(sets.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&caps);
        body.extend_from_slice(&0u32.to_le_bytes());
        let demand = server_io_frame(&share::encode_share_control(
            share::PDU_TYPE_DEMAND_ACTIVE,
            1002,
            SHARE + 1,
            &body,
        ));
        let outputs = sm.process_bytes(&demand).unwrap();
        // Confirm Active + 4 finalization frames, all outbound writes.
        assert_eq!(outputs.len(), 5);
        assert!(
            outputs
                .iter()
                .all(|o| matches!(o, SessionOutput::WriteBytes(_)))
        );
        assert_eq!(
            (sm.framebuffer().width(), sm.framebuffer().height()),
            (8, 4)
        );

        // Bitmaps are ignored until the Font Map closes reactivation…
        assert!(
            sm.process_bytes(&bitmap_update_frame(0, 0, 4, 2, [9, 9, 9]))
                .unwrap()
                .is_empty()
        );

        // …which re-emits the full (new-size) screen.
        let font_map = server_data_pdu(share::PDU_TYPE2_FONT_MAP, &[0, 0, 0, 0, 3, 0, 4, 0]);
        let outputs = sm.process_bytes(&font_map).unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected the full-screen re-emit, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y, frame.width, frame.height), (0, 0, 8, 4));

        // And graphics flow again.
        let outputs = sm
            .process_bytes(&bitmap_update_frame(0, 0, 4, 2, [10, 20, 30]))
            .unwrap();
        assert_eq!(outputs.len(), 1);
    }

    /// The TS_UPDATE_BITMAP_DATA body (updateType included) of one uncompressed 24-bpp rect.
    fn bitmap_update_body(x: u16, y: u16, w: u16, h: u16, bgr: [u8; 3]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_BITMAP.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [x, y, x + w - 1, y + h - 1, w, h, 24, 0] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        let data: Vec<u8> = (0..w as usize * h as usize).flat_map(|_| bgr).collect();
        body.extend_from_slice(&(data.len() as u16).to_le_bytes());
        body.extend_from_slice(&data);
        body
    }

    #[test]
    fn fastpath_bitmap_update_yields_a_frame() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let body = bitmap_update_body(1, 1, 4, 2, [40, 50, 60]);
        let pdu = fastpath::encode_pdu(&[(
            fastpath::FP_UPDATE_BITMAP,
            fastpath::FP_FRAGMENT_SINGLE,
            &body,
        )]);
        let outputs = sm.process_bytes(&pdu).unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y), (1, 1));
        assert_eq!(&frame_pixels(&sm, frame)[..4], &[60, 50, 40, 255]);
    }

    #[test]
    fn fragmented_fastpath_update_reassembles() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let body = bitmap_update_body(0, 0, 8, 4, [1, 2, 3]);
        let (a, rest) = body.split_at(10);
        let (b, c) = rest.split_at(15);
        // Three PDUs carrying FIRST / NEXT / LAST fragments, mixed with TPKT traffic between.
        let outputs = sm
            .process_bytes(&fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_FIRST,
                a,
            )]))
            .unwrap();
        assert!(outputs.is_empty());
        // A slow-path PDU between two fast-path fragments, and since #304 a *handled* one:
        // it must consume its whole body and leave the reassembly buffer alone.
        let tpkt_between =
            server_data_pdu(share::PDU_TYPE2_SAVE_SESSION_INFO, &plain_notify_body());
        assert_eq!(
            sm.process_bytes(&tpkt_between).unwrap(),
            vec![SessionOutput::SaveSessionInfo(
                session_info::SaveSessionInfo::PlainNotify
            )]
        );
        assert!(
            sm.process_bytes(&fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_NEXT,
                b,
            )]))
            .unwrap()
            .is_empty()
        );
        let outputs = sm
            .process_bytes(&fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_LAST,
                c,
            )]))
            .unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected the reassembled frame, got {outputs:?}");
        };
        assert_eq!((frame.width, frame.height), (8, 4));
        assert_eq!(&frame_pixels(&sm, frame)[..4], &[3, 2, 1, 255]);
    }

    #[test]
    fn oversized_bitmap_dimensions_are_rejected_before_allocation() {
        // A ~30-byte PDU declaring a 65535×65535 compressed bitmap must yield a typed
        // error, not a multi-gigabyte allocation (gate #6 fix note 1).
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_BITMAP.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [0u16, 0, 65534, 65534, 65535, 65535, 24] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(
            &(update::BITMAP_COMPRESSION | update::NO_BITMAP_COMPRESSION_HDR).to_le_bytes(),
        );
        body.extend_from_slice(&1u16.to_le_bytes());
        body.push(0x1F);
        let err = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_UPDATE, &body))
            .unwrap_err();
        assert!(
            matches!(
                err,
                SessionError::Decode(justrdp_pdu::DecodeError::InvalidField { .. })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn fragment_reassembly_is_capped() {
        // An endless FIRST + NEXT stream must hit the reassembly cap (typed error), not
        // grow without bound (gate #6 fix note 1). Test desktop is 16×8 → cap ≈ 1 MiB.
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let chunk = vec![0u8; 16 << 10];
        assert!(
            sm.process_bytes(&fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_FIRST,
                &chunk,
            )]))
            .unwrap()
            .is_empty()
        );
        let mut result = Ok(Vec::new());
        for _ in 0..80 {
            result = sm.process_bytes(&fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_NEXT,
                &chunk,
            )]));
            if result.is_err() {
                break;
            }
        }
        assert!(
            matches!(result, Err(SessionError::Decode(_))),
            "cap never tripped: {result:?}"
        );
    }

    #[test]
    fn fragment_continuation_without_first_is_a_typed_error() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let err = sm
            .process_bytes(&fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_LAST,
                &[0; 4],
            )]))
            .unwrap_err();
        assert!(matches!(err, SessionError::Decode(_)), "got {err:?}");
    }

    #[test]
    fn non_io_channels_and_unknown_pdus_are_skipped() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        // Set Error Info is the last data PDU that decodes and produces no output: it is
        // recorded on the machine and read at disconnect rather than surfaced. This was a
        // loop over two until #41 took the pointer PDUs and #304 took save-session-info.
        assert!(
            sm.process_bytes(&server_data_pdu(share::PDU_TYPE2_SET_ERROR_INFO, &[0u8; 4]))
                .unwrap()
                .is_empty()
        );
        // Traffic on a static channel that was never granted (1009) is skipped.
        let mut body = vec![0x68];
        body.extend_from_slice(&(1002u16 - 1001).to_be_bytes());
        body.extend_from_slice(&1009u16.to_be_bytes());
        body.push(0x70);
        body.push(2);
        body.extend_from_slice(&[0xAB, 0xCD]);
        let frame = tpkt::encode(&x224::encode_data(&body));
        assert!(sm.process_bytes(&frame).unwrap().is_empty());
    }

    /// The Server Announce Request the test VM sends on `rdpdr` right after logon, captured
    /// on 2026-09-22 (#307): one chunk, FIRST|LAST, `rDnI` + version 1.13 + clientId 12.
    const VM_RDPDR_SERVER_ANNOUNCE: [u8; 12] = [
        0x72, 0x44, 0x6E, 0x49, 0x01, 0x00, 0x0D, 0x00, 0x0C, 0x00, 0x00, 0x00,
    ];

    fn channel_data(channel: u16, data: &[u8]) -> SessionOutput {
        SessionOutput::ChannelData {
            channel,
            data: data.to_vec(),
        }
    }

    /// A host channel message over its cap is skipped and reported, and the session goes on
    /// to deliver the next one.
    #[test]
    fn a_host_message_over_its_cap_is_dropped_and_the_session_goes_on() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        sm.set_channel_message_cap(CLIPRDR, 3000).unwrap();
        let big = vec![7u8; 5000];
        let mut outputs = Vec::new();
        for chunk in svc::encode_chunks(&big) {
            outputs.extend(
                sm.process_bytes(&server_channel_frame(CLIPRDR, &chunk))
                    .unwrap(),
            );
        }
        assert_eq!(
            outputs,
            vec![SessionOutput::ChannelMessageDropped {
                channel: CLIPRDR,
                total_length: 5000
            }]
        );
        let small = &svc::encode_chunks(b"next")[0];
        assert_eq!(
            sm.process_bytes(&server_channel_frame(CLIPRDR, small))
                .unwrap(),
            vec![channel_data(CLIPRDR, b"next")]
        );
    }

    #[test]
    fn a_host_can_raise_a_channels_cap() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let big: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let deliver = |sm: &mut SessionStateMachine| {
            let mut outputs = Vec::new();
            for chunk in svc::encode_chunks(&big) {
                outputs.extend(
                    sm.process_bytes(&server_channel_frame(CLIPRDR, &chunk))
                        .unwrap(),
                );
            }
            outputs
        };
        sm.set_channel_message_cap(CLIPRDR, 100).unwrap();
        assert_eq!(
            deliver(&mut sm),
            vec![SessionOutput::ChannelMessageDropped {
                channel: CLIPRDR,
                total_length: 5000
            }]
        );
        sm.set_channel_message_cap(CLIPRDR, 5000).unwrap();
        assert_eq!(deliver(&mut sm), vec![channel_data(CLIPRDR, &big)]);
    }

    /// Only a host channel has a cap to set: drdynvc keeps its own, and an ungranted channel has
    /// none.
    #[test]
    fn only_a_host_channels_cap_can_be_set() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        assert_eq!(
            sm.set_channel_message_cap(DRDYNVC, 1),
            Err(ChannelSendError::CoreOwned { channel: DRDYNVC })
        );
        assert_eq!(
            sm.set_channel_message_cap(IO, 1),
            Err(ChannelSendError::NotGranted { channel: IO })
        );
    }

    #[test]
    fn a_granted_channels_message_reaches_the_host_intact() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let chunk = &svc::encode_chunks(&VM_RDPDR_SERVER_ANNOUNCE)[0];
        let outputs = sm
            .process_bytes(&server_channel_frame(RDPDR, chunk))
            .unwrap();
        assert_eq!(
            outputs,
            vec![channel_data(RDPDR, &VM_RDPDR_SERVER_ANNOUNCE)]
        );
    }

    /// A message spanning several MCS payloads surfaces once, whole, on its last chunk — and
    /// a message on another channel in between is its own stream (`[MS-RDPBCGR]` 1.3.3).
    #[test]
    fn chunked_messages_reassemble_per_channel() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let big: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let chunks = svc::encode_chunks(&big);
        assert!(chunks.len() > 2);
        assert!(
            sm.process_bytes(&server_channel_frame(CLIPRDR, &chunks[0]))
                .unwrap()
                .is_empty()
        );
        let rdpdr = &svc::encode_chunks(&VM_RDPDR_SERVER_ANNOUNCE)[0];
        assert_eq!(
            sm.process_bytes(&server_channel_frame(RDPDR, rdpdr))
                .unwrap(),
            vec![channel_data(RDPDR, &VM_RDPDR_SERVER_ANNOUNCE)]
        );
        let mut outputs = Vec::new();
        for chunk in &chunks[1..] {
            outputs.extend(
                sm.process_bytes(&server_channel_frame(CLIPRDR, chunk))
                    .unwrap(),
            );
        }
        assert_eq!(outputs, vec![channel_data(CLIPRDR, &big)]);
    }

    /// `VCCAPS_NO_COMPR` was advertised, so a compressed chunk on a host channel is a
    /// transport error, as it is on drdynvc.
    #[test]
    fn a_compressed_chunk_on_a_host_channel_ends_the_session() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let mut chunk = 1u32.to_le_bytes().to_vec();
        chunk.extend_from_slice(
            &(svc::CHANNEL_FLAG_FIRST
                | svc::CHANNEL_FLAG_LAST
                | svc::CHANNEL_FLAG_PACKET_COMPRESSED)
                .to_le_bytes(),
        );
        chunk.push(0xAA);
        let err = sm
            .process_bytes(&server_channel_frame(CLIPRDR, &chunk))
            .unwrap_err();
        assert!(
            matches!(
                err,
                SessionError::Decode(justrdp_pdu::DecodeError::InvalidField {
                    field: "CHANNEL_PDU_HEADER.flags",
                    ..
                })
            ),
            "{err:?}"
        );
    }

    /// A FIRST chunk while a message is in flight on a host channel ends the session: both
    /// reference clients refuse it, and so does this machine.
    #[test]
    fn a_first_chunk_mid_sequence_on_a_host_channel_ends_the_session() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let first = |total: u32, data: &[u8]| {
            let mut chunk = total.to_le_bytes().to_vec();
            chunk.extend_from_slice(&svc::CHANNEL_FLAG_FIRST.to_le_bytes());
            chunk.extend_from_slice(data);
            server_channel_frame(CLIPRDR, &chunk)
        };
        assert!(sm.process_bytes(&first(9, b"old")).unwrap().is_empty());
        let err = sm.process_bytes(&first(3, b"new")).unwrap_err();
        assert!(
            matches!(
                err,
                SessionError::Decode(justrdp_pdu::DecodeError::InvalidField {
                    field: "CHANNEL_PDU_HEADER.flags",
                    ..
                })
            ),
            "{err:?}"
        );
    }

    /// A header-only chunk carrying `flags` (SUSPEND / RESUME carry no message data).
    fn flag_chunk(flags: u32) -> Vec<u8> {
        let mut chunk = 0u32.to_le_bytes().to_vec();
        chunk.extend_from_slice(&flags.to_le_bytes());
        chunk
    }

    /// `[MS-RDPBCGR]` 2.2.6.1.1: after SUSPEND, all virtual channel traffic is suspended until
    /// RESUME. A host message is held, not sent and not refused, and goes out on the RESUME.
    #[test]
    fn a_host_send_while_suspended_goes_out_on_resume() {
        let expected = SessionStateMachine::new(config(), Vec::new())
            .unwrap()
            .send_channel(RDPDR, b"hello")
            .unwrap();
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let suspend = server_channel_frame(CLIPRDR, &flag_chunk(crate::svc::CHANNEL_FLAG_SUSPEND));
        assert!(sm.process_bytes(&suspend).unwrap().is_empty());
        assert_eq!(
            sm.send_channel(RDPDR, b"hello").unwrap(),
            Vec::<Vec<u8>>::new()
        );
        let resume = server_channel_frame(CLIPRDR, &flag_chunk(crate::svc::CHANNEL_FLAG_RESUME));
        let outputs = sm.process_bytes(&resume).unwrap();
        let written: Vec<SessionOutput> = expected
            .into_iter()
            .map(SessionOutput::WriteBytes)
            .collect();
        assert_eq!(outputs, written);
        // Resumed: the next send goes straight out.
        assert_eq!(sm.send_channel(RDPDR, b"hello").unwrap().len(), 1);
    }

    /// The machine's own virtual channel traffic is held too: a drdynvc response while
    /// suspended, and a Display Control resize.
    #[test]
    fn the_machines_own_channel_traffic_is_held_while_suspended() {
        let caps_request = [0x50u8, 0x00, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut fresh = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let mut expected = Vec::new();
        for frame in server_dvc_frames(&caps_request) {
            expected.extend(fresh.process_bytes(&frame).unwrap());
        }
        assert!(matches!(
            expected.as_slice(),
            [SessionOutput::WriteBytes(_)]
        ));

        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let suspend = server_channel_frame(DRDYNVC, &flag_chunk(crate::svc::CHANNEL_FLAG_SUSPEND));
        assert!(sm.process_bytes(&suspend).unwrap().is_empty());
        for frame in server_dvc_frames(&caps_request) {
            assert!(sm.process_bytes(&frame).unwrap().is_empty());
        }
        let resume = server_channel_frame(DRDYNVC, &flag_chunk(crate::svc::CHANNEL_FLAG_RESUME));
        assert_eq!(sm.process_bytes(&resume).unwrap(), expected);

        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        display_control_ready(&mut sm, 8192, 8192);
        let resize = sm.request_resize(ResizeRequest::new(1280, 1024)).unwrap();
        assert!(sm.process_bytes(&suspend).unwrap().is_empty());
        assert_eq!(
            sm.request_resize(ResizeRequest::new(1280, 1024)).unwrap(),
            Vec::<Vec<u8>>::new()
        );
        let written: Vec<SessionOutput> =
            resize.into_iter().map(SessionOutput::WriteBytes).collect();
        assert_eq!(sm.process_bytes(&resume).unwrap(), written);
    }

    /// What the host can have held is bounded; past it the send is refused, and nothing of
    /// the refused message is held.
    #[test]
    fn a_host_send_past_the_suspended_bound_is_refused() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let suspend = server_channel_frame(CLIPRDR, &flag_chunk(crate::svc::CHANNEL_FLAG_SUSPEND));
        sm.process_bytes(&suspend).unwrap();
        let too_big = vec![0u8; crate::svc::CHANNEL_MESSAGE_CAP + 1];
        assert_eq!(
            sm.send_channel(RDPDR, &too_big),
            Err(ChannelSendError::SuspendedQueueFull { channel: RDPDR })
        );
        let resume = server_channel_frame(CLIPRDR, &flag_chunk(crate::svc::CHANNEL_FLAG_RESUME));
        assert!(sm.process_bytes(&resume).unwrap().is_empty());
    }

    /// A RESUME with nothing suspended changes nothing.
    #[test]
    fn a_resume_without_a_suspend_is_harmless() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let resume = server_channel_frame(CLIPRDR, &flag_chunk(crate::svc::CHANNEL_FLAG_RESUME));
        assert!(sm.process_bytes(&resume).unwrap().is_empty());
        assert_eq!(sm.send_channel(RDPDR, b"x").unwrap().len(), 1);
    }

    /// drdynvc is granted and listed with the host's channels, and still never reaches the
    /// host: its traffic is the dynamic-channel manager's.
    #[test]
    fn drdynvc_traffic_is_not_host_channel_data() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let caps_request = vec![0x50, 0x00, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut outputs = Vec::new();
        for frame in server_dvc_frames(&caps_request) {
            outputs.extend(sm.process_bytes(&frame).unwrap());
        }
        assert!(
            matches!(outputs.as_slice(), [SessionOutput::WriteBytes(_)]),
            "{outputs:?}"
        );
    }

    /// `[MS-RDPBCGR]` 3.1.5.2.2: a chunk with neither FIRST nor LAST outside a sequence is a
    /// whole message. drdynvc refused it until #307 gave it the shared reassembler.
    #[test]
    fn a_flagless_single_chunk_is_answered_on_drdynvc() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let caps_request = [0x50u8, 0x00, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut chunk = (caps_request.len() as u32).to_le_bytes().to_vec();
        chunk.extend_from_slice(&0u32.to_le_bytes());
        chunk.extend_from_slice(&caps_request);
        let outputs = sm
            .process_bytes(&server_channel_frame(DRDYNVC, &chunk))
            .unwrap();
        assert!(
            matches!(outputs.as_slice(), [SessionOutput::WriteBytes(_)]),
            "{outputs:?}"
        );
    }

    #[test]
    fn send_channel_chunks_the_message_onto_the_channel() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let message: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let frames = sm.send_channel(CLIPRDR, &message).unwrap();
        let chunks = svc::encode_chunks(&message);
        assert_eq!(frames.len(), chunks.len());
        for (frame, chunk) in frames.iter().zip(&chunks) {
            assert_eq!(tpkt::frame_len(frame).unwrap(), frame.len());
            let body = x224::decode_data(tpkt::decode(frame).unwrap()).unwrap();
            // SendDataRequest: choice 0x64, initiator (USER - 1001), channel, priority, length.
            assert_eq!(body[0], 0x64);
            assert_eq!(&body[1..3], &(USER - 1001).to_be_bytes());
            assert_eq!(&body[3..5], &CLIPRDR.to_be_bytes());
            assert!(
                body.ends_with(chunk),
                "the frame must carry the chunk verbatim"
            );
        }
    }

    /// A channel the host opened with `CHANNEL_OPTION_SHOW_PROTOCOL` shows the header on every
    /// chunk, a single-chunk message included; any other channel never does.
    #[test]
    fn send_channel_honours_the_show_protocol_option() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        let flags_of = |frames: &[Vec<u8>]| -> Vec<u32> {
            frames
                .iter()
                .map(|frame| {
                    let body = x224::decode_data(tpkt::decode(frame).unwrap()).unwrap();
                    // The frame ends with the chunk: an 8-byte header, then the 4-byte message.
                    let chunk = &body[body.len() - 12..];
                    u32::from_le_bytes(chunk[4..8].try_into().unwrap())
                })
                .collect()
        };
        let whole = svc::CHANNEL_FLAG_FIRST | svc::CHANNEL_FLAG_LAST;
        let rail = sm.send_channel(RAIL, b"exec").unwrap();
        assert_eq!(
            flags_of(&rail),
            vec![whole | svc::CHANNEL_FLAG_SHOW_PROTOCOL]
        );
        let rdpdr = sm.send_channel(RDPDR, b"exec").unwrap();
        assert_eq!(flags_of(&rdpdr), vec![whole]);
        let chunked = sm.send_channel(RDPDR, &[7; 4000]).unwrap();
        assert_eq!(chunked.len(), 3);
        for frame in &chunked {
            let body = x224::decode_data(tpkt::decode(frame).unwrap()).unwrap();
            let needle = 4000u32.to_le_bytes();
            let at = body
                .windows(4)
                .position(|w| w == needle)
                .expect("the chunk header's total length");
            let flags = u32::from_le_bytes(body[at + 4..at + 8].try_into().unwrap());
            assert_eq!(flags & svc::CHANNEL_FLAG_SHOW_PROTOCOL, 0);
        }
    }

    #[test]
    fn send_channel_refuses_a_channel_the_host_does_not_own() {
        let mut sm = SessionStateMachine::new(config(), Vec::new()).unwrap();
        assert_eq!(
            sm.send_channel(1009, b"x"),
            Err(ChannelSendError::NotGranted { channel: 1009 })
        );
        assert_eq!(
            sm.send_channel(IO, b"x"),
            Err(ChannelSendError::NotGranted { channel: IO })
        );
        assert_eq!(
            sm.send_channel(DRDYNVC, b"x"),
            Err(ChannelSendError::CoreOwned { channel: DRDYNVC })
        );
    }

    #[test]
    fn input_uses_fastpath_when_the_server_advertised_it() {
        let sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let frames = sm.encode_input(&[InputEvent::ScanCode {
            code: 0x1E,
            release: false,
            extended: false,
            extended1: false,
        }]);
        assert_eq!(frames.len(), 1);
        // A fast-path frame, not a TPKT frame.
        assert!(fastpath::is_fastpath(frames[0][0]));
        assert_eq!(
            frames[0],
            input::encode_fastpath_input(&[InputEvent::ScanCode {
                code: 0x1E,
                release: false,
                extended: false,
                extended1: false,
            }])
        );
    }

    #[test]
    fn input_falls_back_to_slowpath_without_the_server_flag() {
        let mut cfg = config();
        cfg.server_input_flags = capability::INPUT_FLAG_SCANCODES;
        let sm = SessionStateMachine::new(cfg, Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let event = InputEvent::Mouse {
            flags: input::PTRFLAGS_MOVE,
            wheel_units: 0,
            x: 3,
            y: 4,
        };
        let frames = sm.encode_input(&[event]);
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        // A TPKT frame wrapping MCS → Share Data PDU_TYPE2_INPUT with our event inside.
        assert_eq!(frame[0], 0x03);
        assert_eq!(justrdp_pdu::tpkt::frame_len(frame).unwrap(), frame.len());
        let body = input::encode_slowpath_input_body(&[event]);
        assert!(
            frame.windows(body.len()).any(|w| w == body),
            "slow-path frame does not embed the input body"
        );
    }

    #[test]
    fn input_mouse_coordinates_clamp_to_the_desktop() {
        let sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM"); // 16×8 desktop
        let frames = sm.encode_input(&[InputEvent::Mouse {
            flags: input::PTRFLAGS_MOVE,
            wheel_units: 0,
            x: 500,
            y: 500,
        }]);
        // Fast-path: header(1) + len(1) + eventHeader(1) + flags(2) + x(2) + y(2).
        let frame = &frames[0];
        assert_eq!(u16::from_le_bytes([frame[5], frame[6]]), 15);
        assert_eq!(u16::from_le_bytes([frame[7], frame[8]]), 7);
    }

    #[test]
    fn input_batches_over_255_events_spill_into_multiple_pdus() {
        let sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let events = vec![
            InputEvent::ScanCode {
                code: 0x1E,
                release: false,
                extended: false,
                extended1: false,
            };
            300
        ];
        let frames = sm.encode_input(&events);
        assert_eq!(frames.len(), 2);
        // 255 + 45 events; both frames self-describe their length correctly.
        assert_eq!(fastpath::frame_len(&frames[0]).unwrap(), frames[0].len());
        assert_eq!(fastpath::frame_len(&frames[1]).unwrap(), frames[1].len());
        assert!(sm.encode_input(&[]).is_empty());
    }

    #[test]
    fn drdynvc_caps_request_is_answered_on_the_drdynvc_channel() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let caps_request = vec![0x50, 0x00, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut outputs = Vec::new();
        for frame in server_dvc_frames(&caps_request) {
            outputs.extend(sm.process_bytes(&frame).unwrap());
        }
        let [SessionOutput::WriteBytes(frame)] = outputs.as_slice() else {
            panic!("expected one response frame, got {outputs:?}");
        };
        // A server offering version 3 gets version 2 back (#287), SVC-chunked on the drdynvc
        // channel (big-endian MCS channelId).
        let expected_chunk = &svc::encode_chunks(&dvc::encode_capabilities_response(2))[0];
        assert!(
            frame
                .windows(expected_chunk.len())
                .any(|w| w == expected_chunk.as_slice())
        );
        assert!(frame.windows(2).any(|w| w == DRDYNVC.to_be_bytes()));
    }

    #[test]
    fn display_control_ready_enables_request_resize() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        assert_eq!(
            sm.request_resize(ResizeRequest::new(1280, 1024)),
            Err(ResizeError::NotReady)
        );
        display_control_ready(&mut sm, 8192, 8192);

        let frames = sm.request_resize(ResizeRequest::new(1280, 1024)).unwrap();
        assert_eq!(frames.len(), 1, "a 56-byte layout fits one SVC chunk");
        let layout =
            displaycontrol::encode_monitor_layout(&[displaycontrol::Monitor::primary(1280, 1024)]);
        let expected_chunk = &svc::encode_chunks(&dvc::encode_data(7, &layout)[0])[0];
        assert!(
            frames[0]
                .windows(expected_chunk.len())
                .any(|w| w == expected_chunk.as_slice()),
            "resize frame does not embed the Monitor Layout DVC data"
        );
        assert_eq!(tpkt::frame_len(&frames[0]).unwrap(), frames[0].len());
    }

    /// A server Create Request for dynamic channel `channel_id` named `name`, as SVC frames.
    fn server_dvc_create(channel_id: u8, name: &str) -> Vec<Vec<u8>> {
        let mut create = vec![0x10, channel_id];
        create.extend_from_slice(name.as_bytes());
        create.push(0);
        server_dvc_frames(&create)
    }

    /// One EGFX PDU on dynamic channel `channel_id`, uncompressed-segment wrapped.
    fn server_egfx(channel_id: u32, cmd_id: u16, body: &[u8]) -> Vec<Vec<u8>> {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&cmd_id.to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
        pdu.extend_from_slice(body);
        dvc::encode_data(channel_id, &justrdp_pdu::egfx::wrap_uncompressed(&pdu))
            .iter()
            .flat_map(|data| server_dvc_frames(data))
            .collect()
    }

    /// A fresh machine with the drdynvc capabilities exchanged and dynamic channel `channel_id`
    /// created as `name`.
    fn with_open_dvc(channel_id: u8, name: &str) -> SessionStateMachine {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        for frame in server_dvc_frames(&[0x50, 0x00, 0x01, 0x00])
            .into_iter()
            .chain(server_dvc_create(channel_id, name))
        {
            sm.process_bytes(&frame).unwrap();
        }
        sm
    }

    /// An `RDPGFX_SOLIDFILL_PDU` body filling one 4×4 rect of surface 1.
    fn solid_fill_surface_1() -> Vec<u8> {
        [
            &1u16.to_le_bytes()[..],
            &[0, 0, 0xFF, 0],
            &1u16.to_le_bytes(),
            &[0, 0, 0, 0, 4, 0, 4, 0],
        ]
        .concat()
    }

    /// `[MS-RDPEDYC]` 3.1.1 lets a server reuse a channel id only after a Close, and the probe on
    /// #270 saw this server recycle one within 40 ms — first for two channels we refuse, then
    /// for one we accept. A Create Request for an id that is still bound replaces the binding
    /// either way, so it must tear the old one down the way a Close does: here the old binding
    /// was Display Control, and resize requests must stop going to an id the server has reused.
    #[test]
    fn a_rebound_channel_id_no_longer_receives_resize_requests() {
        for (name, what) in [
            (justrdp_pdu::egfx::CHANNEL_NAME, "an accepted channel"),
            (
                "Microsoft::Windows::RDS::Geometry::v08.01",
                "a refused channel",
            ),
        ] {
            let mut sm = SessionStateMachine::new(config(), Vec::new())
                .expect("the test desktop size is within MAX_DESKTOP_DIM");
            display_control_ready(&mut sm, 1920, 1080);
            assert!(sm.request_resize(ResizeRequest::new(1280, 1024)).is_ok());

            for frame in server_dvc_create(7, name) {
                sm.process_bytes(&frame).unwrap();
            }
            assert!(
                matches!(
                    sm.request_resize(ResizeRequest::new(1280, 1024)),
                    Err(ResizeError::NotReady)
                ),
                "channel 7 was reused for {what}, not Display Control"
            );
        }
    }

    /// The same teardown for a rebound graphics channel: the new binding starts with no
    /// surfaces, so a fill naming the old binding's surface is the unknown-surface error rather
    /// than a paint into stale state.
    #[test]
    fn a_rebound_graphics_channel_starts_without_the_old_bindings_surfaces() {
        let create_surface = [1u16.to_le_bytes(), 16u16.to_le_bytes(), 16u16.to_le_bytes()]
            .concat()
            .into_iter()
            .chain([justrdp_pdu::egfx::PIXEL_FORMAT_XRGB_8888])
            .collect::<Vec<u8>>();
        let solid_fill = solid_fill_surface_1();
        let open_with_surface = || {
            let mut sm = with_open_dvc(8, justrdp_pdu::egfx::CHANNEL_NAME);
            for frame in server_egfx(8, justrdp_pdu::egfx::CMDID_CREATE_SURFACE, &create_surface) {
                sm.process_bytes(&frame).unwrap();
            }
            sm
        };

        // Control: on the original binding the fill paints surface 1.
        let mut sm = open_with_surface();
        for frame in server_egfx(8, justrdp_pdu::egfx::CMDID_SOLID_FILL, &solid_fill) {
            sm.process_bytes(&frame)
                .expect("surface 1 exists on the original binding");
        }

        let mut sm = open_with_surface();
        for frame in server_dvc_create(8, justrdp_pdu::egfx::CHANNEL_NAME) {
            sm.process_bytes(&frame).unwrap();
        }
        let results: Vec<_> = server_egfx(8, justrdp_pdu::egfx::CMDID_SOLID_FILL, &solid_fill)
            .iter()
            .map(|frame| sm.process_bytes(frame))
            .collect();
        assert!(
            results.iter().any(|r| matches!(
                r,
                Err(SessionError::DynamicChannel {
                    error: justrdp_pdu::DecodeError::InvalidField {
                        field: "RDPGFX_SOLIDFILL_PDU",
                        ..
                    },
                    ..
                })
            )),
            "the rebound binding should not know surface 1, got {results:?}"
        );
    }

    /// ADR-0014 Decision 2: a session ended by a dynamic-channel processor names the channel.
    /// Here the graphics processor rejects a fill naming a surface it never created.
    #[test]
    fn a_failing_graphics_processor_names_its_channel() {
        let mut sm = with_open_dvc(8, justrdp_pdu::egfx::CHANNEL_NAME);
        let results: Vec<_> = server_egfx(
            8,
            justrdp_pdu::egfx::CMDID_SOLID_FILL,
            &solid_fill_surface_1(),
        )
        .iter()
        .map(|frame| sm.process_bytes(frame))
        .collect();
        assert!(
            results.iter().any(|r| matches!(
                r,
                Err(SessionError::DynamicChannel {
                    channel: "Microsoft::Windows::RDS::Graphics",
                    error: justrdp_pdu::DecodeError::InvalidField {
                        field: "RDPGFX_SOLIDFILL_PDU",
                        ..
                    },
                })
            )),
            "the failure should name the graphics channel, got {results:?}"
        );
    }

    /// The host's `SessionConfig::egfx` is what the graphics channel advertises when the server
    /// opens it.
    #[test]
    fn the_graphics_channel_advertises_the_session_config() {
        let egfx = crate::EgfxConfig {
            versions: Some(vec![justrdp_pdu::egfx::CAPVERSION_10]),
            cache: crate::EgfxCacheMode::Small,
        };
        let mut sm =
            SessionStateMachine::new(SessionConfig { egfx, ..config() }, Vec::new()).unwrap();
        let mut writes = Vec::new();
        for frame in server_dvc_frames(&[0x50, 0x00, 0x01, 0x00])
            .into_iter()
            .chain(server_dvc_create(8, justrdp_pdu::egfx::CHANNEL_NAME))
        {
            for output in sm.process_bytes(&frame).unwrap() {
                if let SessionOutput::WriteBytes(bytes) = output {
                    writes.push(bytes);
                }
            }
        }
        let advertise =
            justrdp_pdu::egfx::encode_caps_advertise(&[justrdp_pdu::egfx::CapSet::Flags {
                version: justrdp_pdu::egfx::CAPVERSION_10,
                flags: justrdp_pdu::egfx::CAPS_FLAG_AVC_DISABLED
                    | justrdp_pdu::egfx::CAPS_FLAG_SMALL_CACHE,
            }]);
        assert!(
            writes.iter().any(|w| w.ends_with(&advertise)),
            "the channel's advertise is the configured one, got {writes:02X?}"
        );
    }

    #[test]
    fn a_graphics_config_that_cannot_be_advertised_refuses_the_session() {
        let egfx = crate::EgfxConfig {
            versions: Some(vec![justrdp_pdu::egfx::CAPVERSION_106]),
            ..crate::EgfxConfig::default()
        };
        assert_eq!(
            SessionStateMachine::new(SessionConfig { egfx, ..config() }, Vec::new()).err(),
            Some(SessionError::EgfxConfig(
                crate::EgfxConfigError::NotAdvertisable(justrdp_pdu::egfx::CAPVERSION_106)
            ))
        );
    }

    /// The same failure once the server has confirmed 10.4 takes the 3.3.5.19 reset instead
    /// (ADR-0014, 2026-09-17 amendment): the session survives and the client's next write on
    /// the graphics channel is the Caps Advertise its opening sent.
    #[test]
    fn a_graphics_miss_at_10_4_resends_the_advertise_and_keeps_the_session() {
        use crate::dvc::DvcProcessor;
        let advertise = crate::egfx::GraphicsProcessor::default().start(8);
        let [crate::dvc::ProcessorOutput::Send(advertise)] = advertise.as_slice() else {
            panic!("start sends one advertise");
        };
        let confirm = [
            justrdp_pdu::egfx::CAPVERSION_104.to_le_bytes(),
            4u32.to_le_bytes(),
            0u32.to_le_bytes(),
        ]
        .concat();
        let writes = |sm: &mut SessionStateMachine, cmd_id, body: &[u8]| {
            let mut writes = Vec::new();
            for frame in server_egfx(8, cmd_id, body) {
                for output in sm.process_bytes(&frame).expect("the session survives") {
                    if let SessionOutput::WriteBytes(bytes) = output {
                        writes.push(bytes);
                    }
                }
            }
            writes
        };

        let mut sm = with_open_dvc(8, justrdp_pdu::egfx::CHANNEL_NAME);
        writes(&mut sm, justrdp_pdu::egfx::CMDID_CAPS_CONFIRM, &confirm);
        let sent = writes(
            &mut sm,
            justrdp_pdu::egfx::CMDID_SOLID_FILL,
            &solid_fill_surface_1(),
        );
        assert!(
            sent.iter().any(|bytes| bytes
                .windows(advertise.len())
                .any(|w| w == advertise.as_slice())),
            "the reset should resend the advertise, wrote {sent:02x?}"
        );
    }

    /// The same attribution for the other registered processor: a Display Control PDU whose
    /// header length does not cover the header.
    #[test]
    fn a_failing_display_control_processor_names_its_channel() {
        let mut sm = with_open_dvc(7, displaycontrol::CHANNEL_NAME);
        let mut malformed = Vec::new();
        malformed.extend_from_slice(&displaycontrol::TYPE_CAPS.to_le_bytes());
        malformed.extend_from_slice(&4u32.to_le_bytes());
        let results: Vec<_> = dvc::encode_data(7, &malformed)
            .iter()
            .flat_map(|pdu| server_dvc_frames(pdu))
            .map(|frame| sm.process_bytes(&frame))
            .collect();
        assert!(
            results.iter().any(|r| matches!(
                r,
                Err(SessionError::DynamicChannel {
                    channel: "Microsoft::Windows::RDS::DisplayControl",
                    error: justrdp_pdu::DecodeError::InvalidField {
                        field: "DISPLAYCONTROL_HEADER.Length",
                        ..
                    },
                })
            )),
            "the failure should name the Display Control channel, got {results:?}"
        );
    }

    /// An `RDPGFX_RESET_GRAPHICS_PDU` body. `[MS-RDPEGFX]` 2.2.2.14 fixes `pduLength` at 340
    /// including the 8-byte header; only `width` and `height` are consumed, so `monitorCount`
    /// and the monitor array are a single monitor and zeroes.
    fn reset_graphics_body(width: u32, height: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&width.to_le_bytes());
        body.extend_from_slice(&height.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.resize(340 - 8, 0);
        body
    }

    /// ADR-0014's amendment left one channel-originated failure unattributed: a `ResetGraphics`
    /// size the framebuffer refuses (#286). It leaves `process` as a `ProcessorOutput`, so the
    /// refusal happens in the session machine, and only the size band `MAX_DESKTOP_DIM + 1 ..=
    /// u16::MAX` reaches it — below that the framebuffer accepts, above it `u16::try_from`
    /// refuses inside `process` and the existing attribution already applies.
    #[test]
    fn an_output_resize_the_framebuffer_refuses_names_its_channel() {
        let mut sm = with_open_dvc(8, justrdp_pdu::egfx::CHANNEL_NAME);
        let width = u32::from(crate::framebuffer::MAX_DESKTOP_DIM) + 1;
        let results: Vec<_> = server_egfx(
            8,
            justrdp_pdu::egfx::CMDID_RESET_GRAPHICS,
            &reset_graphics_body(width, 768),
        )
        .iter()
        .map(|frame| sm.process_bytes(frame))
        .collect();
        assert!(
            results.iter().any(|r| matches!(
                r,
                Err(SessionError::Framebuffer {
                    channel: Some("Microsoft::Windows::RDS::Graphics"),
                    error: crate::framebuffer::FramebufferError::DesktopTooLarge {
                        width: 16385,
                        height: 768,
                    },
                })
            )),
            "the refusal should name the graphics channel, got {results:?}"
        );
    }

    /// The happy path of the arm the two tests above bracket, which had no session-level
    /// coverage at all: `egfx`'s own `reset_graphics_resizes_the_output` stops at the
    /// `ProcessorOutput`. It is also what proves `reset_graphics_body` builds a PDU this path
    /// consumes, rather than one that fails for a framing reason and reads as a refusal.
    #[test]
    fn an_output_resize_within_the_cap_rebuilds_the_framebuffer() {
        let mut sm = with_open_dvc(8, justrdp_pdu::egfx::CHANNEL_NAME);
        for frame in server_egfx(
            8,
            justrdp_pdu::egfx::CMDID_RESET_GRAPHICS,
            &reset_graphics_body(64, 32),
        ) {
            sm.process_bytes(&frame).expect("64x32 is within the cap");
        }
        assert_eq!(
            sm.framebuffer.pixels().len(),
            64 * 32 * 4,
            "the framebuffer should have been rebuilt at the size the server declared"
        );
    }

    /// The other side of the line the variant draws: the same error from a path no dynamic
    /// channel produced stays unattributed. Asserting it is what stops a later blanket
    /// `Some(..)` from passing the test above.
    #[test]
    fn a_framebuffer_refusal_the_connect_sequence_produced_names_no_channel() {
        let mut config = config();
        config.desktop_size = (crate::framebuffer::MAX_DESKTOP_DIM + 1, 768);
        assert!(
            matches!(
                SessionStateMachine::new(config, Vec::new()),
                Err(SessionError::Framebuffer { channel: None, .. })
            ),
            "a desktop size from the connect sequence belongs to no channel"
        );
    }

    /// A malformed Share Data PDU is no dynamic channel's failure.
    #[test]
    fn a_share_data_failure_is_not_attributed_to_a_channel() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        assert!(matches!(
            sm.process_bytes(&server_data_pdu(
                share::PDU_TYPE2_SET_ERROR_INFO,
                &[0x0C, 0x00]
            )),
            Err(SessionError::Decode(_))
        ));
    }

    /// Nor is a drdynvc transport failure on a channel that is open: the reassembly cap is the
    /// manager's bound, not the processor's verdict.
    #[test]
    fn an_open_channels_transport_failure_is_not_attributed_to_it() {
        let mut sm = with_open_dvc(8, justrdp_pdu::egfx::CHANNEL_NAME);
        // DYNVC_DATA_FIRST (Cmd 2, Sp 2 = 4-byte Length, cbChId 0) on channel 8 declaring a
        // message past the reassembly cap.
        let mut data_first = vec![0x28, 8];
        data_first.extend_from_slice(&u32::MAX.to_le_bytes());
        data_first.extend_from_slice(&[0; 4]);
        let results: Vec<_> = server_dvc_frames(&data_first)
            .iter()
            .map(|frame| sm.process_bytes(frame))
            .collect();
        assert!(
            results.iter().any(|r| matches!(
                r,
                Err(SessionError::Decode(
                    justrdp_pdu::DecodeError::InvalidField {
                        field: "DYNVC_DATA_FIRST.Length",
                        ..
                    }
                ))
            )),
            "an open channel's transport failure is not its processor's, got {results:?}"
        );
    }

    /// #287. justrdp answers drdynvc version 2, and `[MS-RDPEDYC]` 2.2.3.3/2.2.3.4 forbid the
    /// compressed data PDUs below version 3, so either one is a typed transport error whichever
    /// channel it names, open or never opened.
    #[test]
    fn a_compressed_dvc_data_pdu_is_a_typed_error() {
        // Cmd 6 (Len 0 = 1-byte Length, cbId 0) and Cmd 7 (cbId 0), each carrying a one-byte
        // uncompressed RDP_SEGMENTED_DATA segment of type PACKET_COMPR_TYPE_RDP8_LITE (2.2.3.3).
        let first_compressed = [0x60, 8, 0x01, 0xE0, 0x06, 0xAA];
        let compressed = [0x70, 8, 0xE0, 0x06, 0xAA];
        for (pdu, field) in [
            (&first_compressed[..], "DYNVC_DATA_FIRST_COMPRESSED.Cmd"),
            (&compressed[..], "DYNVC_DATA_COMPRESSED.Cmd"),
        ] {
            for (open, what) in [(true, "an open channel"), (false, "an unopened channel")] {
                let mut sm = if open {
                    with_open_dvc(8, justrdp_pdu::egfx::CHANNEL_NAME)
                } else {
                    with_open_dvc(9, displaycontrol::CHANNEL_NAME)
                };
                let results: Vec<_> = server_dvc_frames(pdu)
                    .iter()
                    .map(|frame| sm.process_bytes(frame))
                    .collect();
                assert!(
                    results.iter().any(|r| matches!(
                        r,
                        Err(SessionError::Decode(
                            justrdp_pdu::DecodeError::InvalidField { field: f, .. }
                        )) if *f == field
                    )),
                    "{field} on {what} should be refused, got {results:?}"
                );
            }
        }
    }

    /// Beside that refusal, soft-sync (Cmd 8/9) and an unassigned `Cmd` are still skipped.
    #[test]
    fn soft_sync_and_unassigned_dvc_commands_are_still_skipped() {
        for cmd in [0x08u8, 0x09, 0x0F] {
            let mut sm = with_open_dvc(8, justrdp_pdu::egfx::CHANNEL_NAME);
            for frame in server_dvc_frames(&[cmd << 4, 8, 0x00]) {
                assert_eq!(
                    sm.process_bytes(&frame),
                    Ok(Vec::new()),
                    "Cmd {cmd:#x} should still be skipped"
                );
            }
        }
    }

    #[test]
    fn request_resize_rounds_odd_widths_down_and_validates_ranges() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        display_control_ready(&mut sm, 1920, 1080);

        // Odd width 1281 → 1280 on the wire (MS-RDPEDISP forbids odd widths).
        let frames = sm.request_resize(ResizeRequest::new(1281, 1024)).unwrap();
        let layout_even =
            displaycontrol::encode_monitor_layout(&[displaycontrol::Monitor::primary(1280, 1024)]);
        assert!(
            frames[0]
                .windows(layout_even.len())
                .any(|w| w == layout_even)
        );

        // Out-of-range dimensions and caps-exceeding areas are typed errors.
        assert!(matches!(
            sm.request_resize(ResizeRequest::new(100, 768)),
            Err(ResizeError::InvalidDimensions { .. })
        ));
        assert!(matches!(
            sm.request_resize(ResizeRequest::new(8192, 8192)), // 64 MPx > 1920×1080 caps area
            Err(ResizeError::InvalidDimensions { .. })
        ));
    }

    /// Issue #356: the host's scale factors and orientation reach the wire in the Monitor
    /// Layout, as the values 2.2.2.2.1 defines for them.
    #[test]
    fn a_resize_carries_the_hosts_scale_and_orientation() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        display_control_ready(&mut sm, 1920, 1080);
        for (desktop, device, orientation, wire) in [
            (
                150,
                DeviceScaleFactor::Percent100,
                Orientation::Portrait,
                (150, 100, 90),
            ),
            (
                100,
                DeviceScaleFactor::Percent140,
                Orientation::LandscapeFlipped,
                (100, 140, 180),
            ),
            (
                500,
                DeviceScaleFactor::Percent180,
                Orientation::PortraitFlipped,
                (500, 180, 270),
            ),
            (
                100,
                DeviceScaleFactor::Percent100,
                Orientation::Landscape,
                (100, 100, 0),
            ),
        ] {
            let request = ResizeRequest::new(1280, 1024)
                .with_scale(desktop, device)
                .with_orientation(orientation);
            let frames = sm.request_resize(request).unwrap();
            let layout = displaycontrol::encode_monitor_layout(&[displaycontrol::Monitor {
                desktop_scale_factor: wire.0,
                device_scale_factor: wire.1,
                orientation: wire.2,
                ..displaycontrol::Monitor::primary(1280, 1024)
            }]);
            assert!(
                frames[0].windows(layout.len()).any(|w| w == layout),
                "{request:?} should encode {wire:?}"
            );
        }
    }

    /// A desktop scale factor the server would ignore (2.2.2.2.1: below 100 or above 500) is
    /// refused rather than sent.
    #[test]
    fn a_desktop_scale_factor_outside_100_to_500_is_refused() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        display_control_ready(&mut sm, 1920, 1080);
        for desktop in [0, 99, 501, u32::MAX] {
            assert_eq!(
                sm.request_resize(
                    ResizeRequest::new(1280, 1024)
                        .with_scale(desktop, DeviceScaleFactor::Percent100)
                ),
                Err(ResizeError::InvalidScaleFactor {
                    desktop_scale_factor: desktop
                }),
                "{desktop}%"
            );
        }
        for desktop in [100, 500] {
            assert!(
                sm.request_resize(
                    ResizeRequest::new(1280, 1024)
                        .with_scale(desktop, DeviceScaleFactor::Percent100)
                )
                .is_ok(),
                "{desktop}% is in range"
            );
        }
    }

    #[test]
    fn hostile_caps_area_does_not_overflow_request_resize() {
        // A malicious server can advertise u32::MAX Display Control area factors;
        // their product (u32³ > u64) must not overflow caps.max_area() into a
        // debug-build panic when the client validates a resize. The product
        // saturates, so an in-range resize still proceeds. Parallel of slice-9's
        // hostile_map_origin_does_not_overflow_or_emit.
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        // All three caps factors maxed → the product is u32³ ≈ 2^96, which
        // overflows u64 (monitors must also be large; the 2-arg helper pins it to
        // 1, where MAX² still fits u64 and would not exercise the guard).
        display_control_ready_caps(&mut sm, u32::MAX, u32::MAX, u32::MAX);
        assert!(
            sm.request_resize(ResizeRequest::new(1280, 1024)).is_ok(),
            "a saturated caps limit must not block a legitimately-bounded resize"
        );
    }

    #[test]
    fn refused_dynamic_channels_get_a_negative_creation_status() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let mut create = vec![0x10, 0x09];
        create.extend_from_slice(b"Microsoft::Windows::RDS::Geometry\0");
        let mut outputs = Vec::new();
        for frame in server_dvc_frames(&create) {
            outputs.extend(sm.process_bytes(&frame).unwrap());
        }
        let [SessionOutput::WriteBytes(frame)] = outputs.as_slice() else {
            panic!("expected one refusal frame, got {outputs:?}");
        };
        let refusal = dvc::encode_create_response(9, 0x8000_4005);
        let expected_chunk = &svc::encode_chunks(&refusal)[0];
        assert!(
            frame
                .windows(expected_chunk.len())
                .any(|w| w == expected_chunk.as_slice())
        );
        // And resize stays unavailable.
        assert_eq!(
            sm.request_resize(ResizeRequest::new(1280, 1024)),
            Err(ResizeError::NotReady)
        );
    }

    #[test]
    fn resize_then_deactivate_reactivate_applies_the_new_size() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        display_control_ready(&mut sm, 8192, 8192);
        sm.request_resize(ResizeRequest::new(8, 4)).unwrap_err(); // below 200: validated
        let _ = sm.request_resize(ResizeRequest::new(1280, 1024)).unwrap();

        // The server answers with the Deactivation–Reactivation cycle (already covered by
        // deactivate_reactivate_resizes_and_reemits_full_screen); here we assert the
        // drdynvc state survives it: Display Control stays ready afterwards.
        let deactivate = server_io_frame(&share::encode_share_control(
            share::PDU_TYPE_DEACTIVATE_ALL,
            1002,
            SHARE,
            &[],
        ));
        assert!(sm.process_bytes(&deactivate).unwrap().is_empty());
        assert!(
            sm.request_resize(ResizeRequest::new(1024, 768)).is_ok(),
            "resize survives deactivation"
        );
    }

    #[test]
    fn without_a_drdynvc_channel_resize_is_not_ready_and_traffic_is_skipped() {
        let mut cfg = config();
        cfg.drdynvc_channel_id = None;
        cfg.static_channels.retain(|c| c.id != DRDYNVC);
        let mut sm = SessionStateMachine::new(cfg, Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        assert_eq!(
            sm.request_resize(ResizeRequest::new(1280, 1024)),
            Err(ResizeError::NotReady)
        );
        // What would have been drdynvc traffic is now unknown-static-channel noise: skipped.
        let caps_request = vec![0x50, 0x00, 0x01, 0x00];
        for frame in server_dvc_frames(&caps_request) {
            assert!(sm.process_bytes(&frame).unwrap().is_empty());
        }
    }

    #[test]
    fn malformed_bitmap_data_is_a_typed_error_not_a_panic() {
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        // Compressed flag with garbage RLE that overruns the image.
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_BITMAP.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [0u16, 0, 3, 0, 4, 1, 8] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(
            &(update::BITMAP_COMPRESSION | update::NO_BITMAP_COMPRESSION_HDR).to_le_bytes(),
        );
        body.extend_from_slice(&1u16.to_le_bytes());
        body.push(0x1F); // BG run of 31 pixels into a 4-pixel image
        let err = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_UPDATE, &body))
            .unwrap_err();
        assert!(matches!(err, SessionError::Rle(_)), "got {err:?}");

        // Bytes split across reads still reassemble (chunked TPKT).
        let mut sm = SessionStateMachine::new(config(), Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        let frame = bitmap_update_frame(0, 0, 4, 2, [1, 2, 3]);
        let (a, b) = frame.split_at(7);
        assert!(sm.process_bytes(a).unwrap().is_empty());
        assert_eq!(sm.process_bytes(b).unwrap().len(), 1);
    }

    /// The complete outbound frames that carry drdynvc PDU `pdu` on the drdynvc channel.
    fn client_dvc_frames(sm: &SessionStateMachine, pdu: &[u8]) -> Vec<SessionOutput> {
        svc::encode_chunks(pdu)
            .iter()
            .map(|chunk| SessionOutput::WriteBytes(sm.wrap_channel(DRDYNVC, chunk)))
            .collect()
    }

    /// Feed every frame and collect what the machine produced.
    fn feed_all(sm: &mut SessionStateMachine, frames: Vec<Vec<u8>>) -> Vec<SessionOutput> {
        frames
            .iter()
            .flat_map(|frame| sm.process_bytes(frame).unwrap())
            .collect()
    }

    /// One drdynvc data message for dynamic channel `channel_id`, as server SVC frames.
    fn server_dvc_data(channel_id: u32, message: &[u8]) -> Vec<Vec<u8>> {
        dvc::encode_data(channel_id, message)
            .iter()
            .flat_map(|pdu| server_dvc_frames(pdu))
            .collect()
    }

    /// ADR-0018: a Create Request for a name the host registered is accepted, and the host
    /// learns the id the server gave it.
    #[test]
    fn a_host_registered_dynamic_channel_is_accepted_and_announced() {
        let mut sm = with_open_dvc(9, "Some::Other::Channel");
        let outputs = feed_all(&mut sm, server_dvc_create(9, HOST_DVC));
        let mut expected = client_dvc_frames(&sm, &dvc::encode_create_response(9, 0));
        expected.push(SessionOutput::DynamicChannelOpened {
            name: HOST_DVC.to_string(),
            channel_id: 9,
        });
        assert_eq!(outputs, expected);
    }

    /// A host channel's message reaches the host whole, whether it fits one data PDU or arrives
    /// as Data First plus Data.
    #[test]
    fn a_host_dynamic_channel_message_reaches_the_host_whole() {
        let mut sm = with_open_dvc(9, HOST_DVC);
        let short = b"one data pdu".to_vec();
        assert_eq!(
            feed_all(&mut sm, server_dvc_data(9, &short)),
            vec![SessionOutput::DynamicChannelData {
                channel_id: 9,
                data: short,
            }]
        );
        let long: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();
        assert!(
            dvc::encode_data(9, &long).len() > 1,
            "the message is fragmented"
        );
        assert_eq!(
            feed_all(&mut sm, server_dvc_data(9, &long)),
            vec![SessionOutput::DynamicChannelData {
                channel_id: 9,
                data: long,
            }]
        );
    }

    /// The host learns that its channel ended, from a server Close and from a Create Request
    /// that reuses the id, and nothing more reaches it on that id.
    #[test]
    fn the_host_learns_when_the_server_ends_its_dynamic_channel() {
        let mut sm = with_open_dvc(9, HOST_DVC);
        assert_eq!(
            feed_all(&mut sm, server_dvc_frames(&dvc::encode_close(9))),
            vec![SessionOutput::DynamicChannelClosed { channel_id: 9 }]
        );
        assert!(feed_all(&mut sm, server_dvc_data(9, b"late")).is_empty());

        let mut sm = with_open_dvc(9, HOST_DVC);
        let outputs = feed_all(&mut sm, server_dvc_create(9, "Some::Other::Channel"));
        let mut expected = vec![SessionOutput::DynamicChannelClosed { channel_id: 9 }];
        expected.extend(client_dvc_frames(
            &sm,
            &dvc::encode_create_response(9, 0x8000_4005),
        ));
        assert_eq!(outputs, expected);
        assert!(feed_all(&mut sm, server_dvc_data(9, b"late")).is_empty());
    }

    /// A host message goes out as drdynvc data PDUs on the channel's id, fragmented when it
    /// is longer than one.
    #[test]
    fn a_host_message_goes_out_on_its_dynamic_channel() {
        let mut sm = with_open_dvc(9, HOST_DVC);
        for message in [b"short".to_vec(), vec![0x5A; 4000]] {
            let pdus = dvc::encode_data(9, &message);
            let expected: Vec<Vec<u8>> = pdus
                .iter()
                .flat_map(|pdu| client_dvc_frames(&sm, pdu))
                .map(|output| match output {
                    SessionOutput::WriteBytes(frame) => frame,
                    other => panic!("{other:?}"),
                })
                .collect();
            assert_eq!(sm.send_dynamic_channel(9, &message), Ok(expected));
        }
    }

    /// Only an open host channel takes a send or a close: not an id never opened, and not a
    /// channel a core processor terminates.
    #[test]
    fn a_send_or_close_needs_an_open_host_dynamic_channel() {
        let mut sm = with_open_dvc(7, displaycontrol::CHANNEL_NAME);
        for channel_id in [7, 9] {
            assert_eq!(
                sm.send_dynamic_channel(channel_id, b"x"),
                Err(DynamicChannelError::NotOpen { channel_id })
            );
            assert_eq!(
                sm.close_dynamic_channel(channel_id),
                Err(DynamicChannelError::NotOpen { channel_id })
            );
        }
    }

    /// The host closes its channel with a Close PDU; the channel is then gone on this side.
    /// Data already in flight on it, and a stray Close for it, are ignored (`[MS-RDPEDYC]`
    /// 3.2.5.2: the server does not answer a client-initiated Close).
    #[test]
    fn the_host_closes_its_dynamic_channel() {
        let mut sm = with_open_dvc(9, HOST_DVC);
        let expected: Vec<Vec<u8>> = client_dvc_frames(&sm, &dvc::encode_close(9))
            .into_iter()
            .map(|output| match output {
                SessionOutput::WriteBytes(frame) => frame,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(sm.close_dynamic_channel(9), Ok(expected));
        assert!(feed_all(&mut sm, server_dvc_data(9, b"in flight")).is_empty());
        assert!(feed_all(&mut sm, server_dvc_frames(&dvc::encode_close(9))).is_empty());
        assert_eq!(
            sm.send_dynamic_channel(9, b"x"),
            Err(DynamicChannelError::NotOpen { channel_id: 9 })
        );
    }

    /// A host may not register a name the core terminates.
    #[test]
    fn a_host_cannot_register_a_core_dynamic_channel() {
        for name in [
            displaycontrol::CHANNEL_NAME,
            justrdp_pdu::egfx::CHANNEL_NAME,
        ] {
            let config = SessionConfig {
                dynamic_channels: vec![HOST_DVC.to_string(), name.to_string()],
                ..config()
            };
            assert_eq!(
                SessionStateMachine::new(config, Vec::new()).err(),
                Some(SessionError::DynamicChannelConfig(
                    crate::dvc::CoreOwnedDynamicChannel {
                        name: name.to_string()
                    }
                ))
            );
        }
    }

    /// While the server has suspended virtual channel traffic a host dynamic channel message is
    /// held, and goes out on the resume.
    #[test]
    fn a_host_dynamic_channel_send_is_held_while_suspended() {
        let mut sm = with_open_dvc(9, HOST_DVC);
        let suspend = server_channel_frame(DRDYNVC, &flag_chunk(crate::svc::CHANNEL_FLAG_SUSPEND));
        assert!(sm.process_bytes(&suspend).unwrap().is_empty());
        assert_eq!(sm.send_dynamic_channel(9, b"held"), Ok(Vec::new()));
        let resume = server_channel_frame(DRDYNVC, &flag_chunk(crate::svc::CHANNEL_FLAG_RESUME));
        assert_eq!(
            sm.process_bytes(&resume).unwrap(),
            client_dvc_frames(&sm, &dvc::encode_data(9, b"held")[0])
        );
    }

    /// Held host messages share the 64 MiB bound with static channels; past it a dynamic
    /// channel send is refused and the session goes on.
    #[test]
    fn a_host_dynamic_channel_send_past_the_suspended_bound_is_refused() {
        let mut sm = with_open_dvc(9, HOST_DVC);
        let suspend = server_channel_frame(DRDYNVC, &flag_chunk(crate::svc::CHANNEL_FLAG_SUSPEND));
        sm.process_bytes(&suspend).unwrap();
        let big = vec![0u8; crate::svc::CHANNEL_MESSAGE_CAP];
        assert_eq!(sm.send_dynamic_channel(9, &big), Ok(Vec::new()));
        assert_eq!(
            sm.send_dynamic_channel(9, b"x"),
            Err(DynamicChannelError::SuspendedQueueFull { channel_id: 9 })
        );
    }

    /// A server minting fresh ids for one host name is capped per name, and cannot spend the
    /// slots the core's channels need: the Graphics Pipeline still opens.
    #[test]
    fn a_host_dynamic_channel_name_cannot_exhaust_the_core_channels() {
        let mut sm = with_open_dvc(10, HOST_DVC);
        for id in 11..=13 {
            feed_all(&mut sm, server_dvc_create(id, HOST_DVC));
        }
        let refused = feed_all(&mut sm, server_dvc_create(14, HOST_DVC));
        assert_eq!(
            refused,
            client_dvc_frames(&sm, &dvc::encode_create_response(14, 0x8000_4005)),
            "a fifth channel for one host name is refused"
        );
        let accepted = feed_all(
            &mut sm,
            server_dvc_create(15, justrdp_pdu::egfx::CHANNEL_NAME),
        );
        assert_eq!(
            accepted.first(),
            client_dvc_frames(&sm, &dvc::encode_create_response(15, 0)).first(),
            "the Graphics Pipeline is still accepted"
        );
    }

    /// A final Data PDU that carries more than DataFirst declared still delivers the declared
    /// length, as it did before host channels existed; the excess is dropped.
    #[test]
    fn a_host_dynamic_channel_message_is_cut_at_its_declared_length() {
        let mut sm = with_open_dvc(9, HOST_DVC);
        let long: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();
        let mut pdus = dvc::encode_data(9, &long);
        pdus.last_mut()
            .expect("fragmented")
            .extend_from_slice(b"excess");
        let frames: Vec<Vec<u8>> = pdus.iter().flat_map(|pdu| server_dvc_frames(pdu)).collect();
        assert_eq!(
            feed_all(&mut sm, frames),
            vec![SessionOutput::DynamicChannelData {
                channel_id: 9,
                data: long,
            }]
        );
    }

    /// Audio output's messages are the same bytes on both transports (#387). A server format
    /// list (`[MS-RDPEA]` 4.1.1) and a Wave2 PDU longer than one static channel chunk and one
    /// dynamic channel data PDU reach the host whole on `rdpsnd` and on `AUDIO_PLAYBACK_DVC`, and
    /// one audio output helper answers each sequence the same way.
    #[test]
    fn audio_output_hears_the_same_messages_on_either_transport() {
        use crate::rdpsnd::{AudioOutput, AudioOutputConfig, AudioOutputEvent};
        const RDPSND: u16 = 1009;
        let formats = hex_bytes(concat!(
            "072b900008fb8b00e0f1090070271f7700000500ff050000010002002256000088580100040010000000",
            "060002002256000044ac0000020008000000070002002256000044ac000002000800000002000200225600",
            "0027570000000404002000f403070000010000000200ff00000000c0004000f0000000cc0130ff880118ff",
            "1100020022560000b9560000000404000200f903",
        ));
        // A Wave2 in client format 0 (the server's PCM 22.05 kHz stereo 16-bit), 4000 bytes.
        let sample: Vec<u8> = (0..4000u32).map(|i| (i * 7 % 256) as u8).collect();
        let mut wave2 = vec![0x0d, 0x00];
        wave2.extend_from_slice(&((12 + sample.len()) as u16).to_le_bytes());
        wave2.extend_from_slice(&[0x16, 0xa1, 0x00, 0x00, 0x02, 0, 0, 0]);
        wave2.extend_from_slice(&0x0DAC_B8C2u32.to_le_bytes());
        wave2.extend_from_slice(&sample);
        let messages = [formats, wave2];
        assert!(svc::encode_chunks(&messages[1]).len() > 1);
        assert!(dvc::encode_data(9, &messages[1]).len() > 1);

        let mut config = config();
        config.static_channels.push(crate::StaticChannel {
            name: "rdpsnd".to_string(),
            id: RDPSND,
            options: 0,
        });
        config.dynamic_channels = vec![justrdp_pdu::rdpsnd::DVC_CHANNEL_NAME.to_string()];
        let mut sm = SessionStateMachine::new(config, Vec::new())
            .expect("the test desktop size is within MAX_DESKTOP_DIM");
        for frame in server_dvc_frames(&[0x50, 0x00, 0x01, 0x00])
            .into_iter()
            .chain(server_dvc_create(9, justrdp_pdu::rdpsnd::DVC_CHANNEL_NAME))
        {
            sm.process_bytes(&frame).unwrap();
        }

        let mut on_static = Vec::new();
        let mut on_dynamic = Vec::new();
        for message in &messages {
            for chunk in svc::encode_chunks(message) {
                for output in sm
                    .process_bytes(&server_channel_frame(RDPSND, &chunk))
                    .unwrap()
                {
                    if let SessionOutput::ChannelData {
                        channel: RDPSND,
                        data,
                    } = output
                    {
                        on_static.push(data);
                    }
                }
            }
            for output in feed_all(&mut sm, server_dvc_data(9, message)) {
                if let SessionOutput::DynamicChannelData {
                    channel_id: 9,
                    data,
                } = output
                {
                    on_dynamic.push(data);
                }
            }
        }
        assert_eq!(on_static, messages);
        assert_eq!(on_dynamic, messages);

        let answers = |received: &[Vec<u8>]| {
            let mut output = AudioOutput::new(AudioOutputConfig::default()).unwrap();
            received
                .iter()
                .flat_map(|message| output.process(message).unwrap())
                .collect::<Vec<_>>()
        };
        let from_static = answers(&on_static);
        assert!(
            matches!(from_static.last(), Some(AudioOutputEvent::Block(block)) if block.samples.len() == 2000),
            "the Wave2 decodes to 2000 samples"
        );
        assert_eq!(from_static, answers(&on_dynamic));
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
