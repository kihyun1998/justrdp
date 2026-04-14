//! MS-RDPEV constants: interface values, function ids, capability types,
//! platform cookies, sample extension flags, and result codes.
//!
//! Wire-format layout lives in [`crate::pdu::header`] -- this module only
//! exposes the raw numeric discriminators so the header module and the
//! per-PDU modules can reference them without a circular import.
//!
//! All values reference MS-RDPEV v18.0 section numbers. Forward-compat
//! `Other(raw)` variants preserve unknown discriminators.

// ── InterfaceId / Mask packing (MS-RDPEV §2.2.1) ────────────────────

/// Bits [31:30] of the 32-bit `InterfaceId` field carry a two-bit
/// `Mask` that discriminates between request, response, and interface-
/// manipulation messages. The remaining 30 bits carry the
/// `InterfaceValue`.
///
/// The packing is `raw = interface_value | (mask as u32)`, so `Mask` is
/// stored as a pre-shifted u32 constant that can be OR-ed directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mask {
    /// `STREAM_ID_NONE = 0x00000000` -- interface manipulation (QI/release).
    None,
    /// `STREAM_ID_PROXY = 0x40000000` -- request PDU (FunctionId present).
    Proxy,
    /// `STREAM_ID_STUB = 0x80000000` -- response PDU (no FunctionId, 8-byte header).
    Stub,
    /// Preserved raw two-bit value for forward-compat (bits [31:30] == 0b11).
    Other(u8),
}

impl Mask {
    pub const NONE: u32 = 0x0000_0000;
    pub const PROXY: u32 = 0x4000_0000;
    pub const STUB: u32 = 0x8000_0000;

    /// The two Mask bits, stored in their natural u32 position (already
    /// shifted into bits [31:30]).
    pub const BITS: u32 = 0xC000_0000;

    /// Extracts a `Mask` from a raw 32-bit InterfaceId field.
    pub fn from_interface_id(raw: u32) -> Self {
        match raw & Self::BITS {
            Self::NONE => Self::None,
            Self::PROXY => Self::Proxy,
            Self::STUB => Self::Stub,
            other => Self::Other(((other >> 30) & 0x3) as u8),
        }
    }

    /// Shifted u32 value ready to be OR-ed into an InterfaceId word.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::None => Self::NONE,
            Self::Proxy => Self::PROXY,
            Self::Stub => Self::STUB,
            Self::Other(bits) => ((bits & 0x3) as u32) << 30,
        }
    }
}

/// 30-bit mask used to extract `InterfaceValue` from the `InterfaceId`
/// field (bits [29:0]).
pub const INTERFACE_VALUE_MASK: u32 = 0x3FFF_FFFF;

/// Packs an `InterfaceValue` and `Mask` into the 32-bit `InterfaceId`
/// word written to the wire.
pub fn pack_interface_id(interface_value: u32, mask: Mask) -> u32 {
    (interface_value & INTERFACE_VALUE_MASK) | mask.as_u32()
}

/// Splits a raw on-wire `InterfaceId` into `(interface_value, mask)`.
pub fn unpack_interface_id(raw: u32) -> (u32, Mask) {
    (raw & INTERFACE_VALUE_MASK, Mask::from_interface_id(raw))
}

// ── InterfaceValue (MS-RDPEV §2.2.1) ────────────────────────────────

/// The MS-RDPEV `InterfaceValue` discriminator (lower 30 bits of
/// `InterfaceId`). `0x0` is the main Server Data interface; `0x1` is
/// the Client Notifications interface used for `PLAYBACK_ACK` and
/// `CLIENT_EVENT_NOTIFICATION`. Unknown values are preserved via
/// `Other(raw)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceValue {
    /// 0x00000000 -- Server Data / Capabilities Negotiator.
    ServerData,
    /// 0x00000001 -- Client Notifications (`PLAYBACK_ACK`, `CLIENT_EVENT_NOTIFICATION`).
    ClientNotifications,
    /// Reserved / QI-assigned future interfaces.
    Other(u32),
}

impl InterfaceValue {
    pub const SERVER_DATA: u32 = 0x0000_0000;
    pub const CLIENT_NOTIFICATIONS: u32 = 0x0000_0001;

    pub fn from_u32(raw: u32) -> Self {
        match raw {
            Self::SERVER_DATA => Self::ServerData,
            Self::CLIENT_NOTIFICATIONS => Self::ClientNotifications,
            other => Self::Other(other),
        }
    }

    pub fn to_u32(self) -> u32 {
        match self {
            Self::ServerData => Self::SERVER_DATA,
            Self::ClientNotifications => Self::CLIENT_NOTIFICATIONS,
            Self::Other(raw) => raw & INTERFACE_VALUE_MASK,
        }
    }
}

pub mod interface_value {
    //! Numeric `InterfaceValue`s from MS-RDPEV §2.2.1.
    pub const SERVER_DATA: u32 = 0x0000_0000;
    pub const CLIENT_NOTIFICATIONS: u32 = 0x0000_0001;
}

// ── FunctionId (MS-RDPEV §2.2.1) ────────────────────────────────────

pub mod function_id {
    //! Raw u32 `FunctionId`s. Grouped by interface -- MS-RDPEV §2.2.1.
    //!
    //! Note: on `InterfaceValue=0` the opcodes 0x100..=0x116 belong to
    //! the Server Data interface; on `InterfaceValue=1` the opcodes
    //! 0x100 and 0x101 belong to the Client Notifications interface
    //! (different interface → same opcodes, disambiguated by InterfaceValue).

    // ── Interface manipulation (any interface, Mask=STREAM_ID_NONE) §2.2.3 ──
    pub const RIMCALL_RELEASE: u32 = 0x0000_0001;
    pub const RIMCALL_QUERY_INTERFACE: u32 = 0x0000_0002;

    // ── Server Data interface (InterfaceValue=0, Mask=STREAM_ID_PROXY) §2.2.5 ──
    pub const EXCHANGE_CAPABILITIES_REQ: u32 = 0x0000_0100;
    pub const SET_CHANNEL_PARAMS: u32 = 0x0000_0101;
    pub const ADD_STREAM: u32 = 0x0000_0102;
    pub const ON_SAMPLE: u32 = 0x0000_0103;
    pub const SET_VIDEO_WINDOW: u32 = 0x0000_0104;
    pub const ON_NEW_PRESENTATION: u32 = 0x0000_0105;
    pub const SHUTDOWN_PRESENTATION_REQ: u32 = 0x0000_0106;
    pub const SET_TOPOLOGY_REQ: u32 = 0x0000_0107;
    pub const CHECK_FORMAT_SUPPORT_REQ: u32 = 0x0000_0108;
    pub const ON_PLAYBACK_STARTED: u32 = 0x0000_0109;
    pub const ON_PLAYBACK_PAUSED: u32 = 0x0000_010A;
    pub const ON_PLAYBACK_STOPPED: u32 = 0x0000_010B;
    pub const ON_PLAYBACK_RESTARTED: u32 = 0x0000_010C;
    pub const ON_PLAYBACK_RATE_CHANGED: u32 = 0x0000_010D;
    pub const ON_FLUSH: u32 = 0x0000_010E;
    pub const ON_STREAM_VOLUME: u32 = 0x0000_010F;
    pub const ON_CHANNEL_VOLUME: u32 = 0x0000_0110;
    pub const ON_END_OF_STREAM: u32 = 0x0000_0111;
    pub const SET_ALLOCATOR: u32 = 0x0000_0112;
    pub const NOTIFY_PREROLL: u32 = 0x0000_0113;
    pub const UPDATE_GEOMETRY_INFO: u32 = 0x0000_0114;
    pub const REMOVE_STREAM: u32 = 0x0000_0115;
    pub const SET_SOURCE_VIDEO_RECT: u32 = 0x0000_0116;

    // ── Client Notifications interface (InterfaceValue=1, Mask=STREAM_ID_PROXY) §2.2.6 ──
    pub const PLAYBACK_ACK: u32 = 0x0000_0100;
    pub const CLIENT_EVENT_NOTIFICATION: u32 = 0x0000_0101;
}

/// Strongly-typed `FunctionId` that remembers which interface it was
/// parsed under. Used by the dispatch layer; the raw u32 value on its
/// own is ambiguous between the Server Data (0x100 family) and Client
/// Notifications (0x100 family) interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionId {
    // ── Interface manipulation ──
    RimCallRelease,
    RimCallQueryInterface,
    // ── Server Data interface ──
    ExchangeCapabilitiesReq,
    SetChannelParams,
    AddStream,
    OnSample,
    SetVideoWindow,
    OnNewPresentation,
    ShutdownPresentationReq,
    SetTopologyReq,
    CheckFormatSupportReq,
    OnPlaybackStarted,
    OnPlaybackPaused,
    OnPlaybackStopped,
    OnPlaybackRestarted,
    OnPlaybackRateChanged,
    OnFlush,
    OnStreamVolume,
    OnChannelVolume,
    OnEndOfStream,
    SetAllocator,
    NotifyPreroll,
    UpdateGeometryInfo,
    RemoveStream,
    SetSourceVideoRect,
    // ── Client Notifications interface ──
    PlaybackAck,
    ClientEventNotification,
    /// Preserved raw (interface_value, function_id) for forward-compat.
    Other {
        interface_value: u32,
        function_id: u32,
    },
}

impl FunctionId {
    /// Maps `(interface_value, raw)` to a strongly-typed `FunctionId`.
    /// Never fails -- unknown pairs collapse to `Other { .. }`.
    pub fn from_raw(interface_value: u32, raw: u32) -> Self {
        use function_id as f;
        match (interface_value, raw) {
            (_, f::RIMCALL_RELEASE) => Self::RimCallRelease,
            (_, f::RIMCALL_QUERY_INTERFACE) => Self::RimCallQueryInterface,
            (interface_value::SERVER_DATA, f::EXCHANGE_CAPABILITIES_REQ) => {
                Self::ExchangeCapabilitiesReq
            }
            (interface_value::SERVER_DATA, f::SET_CHANNEL_PARAMS) => Self::SetChannelParams,
            (interface_value::SERVER_DATA, f::ADD_STREAM) => Self::AddStream,
            (interface_value::SERVER_DATA, f::ON_SAMPLE) => Self::OnSample,
            (interface_value::SERVER_DATA, f::SET_VIDEO_WINDOW) => Self::SetVideoWindow,
            (interface_value::SERVER_DATA, f::ON_NEW_PRESENTATION) => Self::OnNewPresentation,
            (interface_value::SERVER_DATA, f::SHUTDOWN_PRESENTATION_REQ) => {
                Self::ShutdownPresentationReq
            }
            (interface_value::SERVER_DATA, f::SET_TOPOLOGY_REQ) => Self::SetTopologyReq,
            (interface_value::SERVER_DATA, f::CHECK_FORMAT_SUPPORT_REQ) => {
                Self::CheckFormatSupportReq
            }
            (interface_value::SERVER_DATA, f::ON_PLAYBACK_STARTED) => Self::OnPlaybackStarted,
            (interface_value::SERVER_DATA, f::ON_PLAYBACK_PAUSED) => Self::OnPlaybackPaused,
            (interface_value::SERVER_DATA, f::ON_PLAYBACK_STOPPED) => Self::OnPlaybackStopped,
            (interface_value::SERVER_DATA, f::ON_PLAYBACK_RESTARTED) => Self::OnPlaybackRestarted,
            (interface_value::SERVER_DATA, f::ON_PLAYBACK_RATE_CHANGED) => {
                Self::OnPlaybackRateChanged
            }
            (interface_value::SERVER_DATA, f::ON_FLUSH) => Self::OnFlush,
            (interface_value::SERVER_DATA, f::ON_STREAM_VOLUME) => Self::OnStreamVolume,
            (interface_value::SERVER_DATA, f::ON_CHANNEL_VOLUME) => Self::OnChannelVolume,
            (interface_value::SERVER_DATA, f::ON_END_OF_STREAM) => Self::OnEndOfStream,
            (interface_value::SERVER_DATA, f::SET_ALLOCATOR) => Self::SetAllocator,
            (interface_value::SERVER_DATA, f::NOTIFY_PREROLL) => Self::NotifyPreroll,
            (interface_value::SERVER_DATA, f::UPDATE_GEOMETRY_INFO) => Self::UpdateGeometryInfo,
            (interface_value::SERVER_DATA, f::REMOVE_STREAM) => Self::RemoveStream,
            (interface_value::SERVER_DATA, f::SET_SOURCE_VIDEO_RECT) => Self::SetSourceVideoRect,
            (interface_value::CLIENT_NOTIFICATIONS, f::PLAYBACK_ACK) => Self::PlaybackAck,
            (interface_value::CLIENT_NOTIFICATIONS, f::CLIENT_EVENT_NOTIFICATION) => {
                Self::ClientEventNotification
            }
            (iv, fid) => Self::Other {
                interface_value: iv,
                function_id: fid,
            },
        }
    }

    /// Returns the raw `FunctionId` u32 that would be written on the wire.
    pub fn to_u32(self) -> u32 {
        use function_id as f;
        match self {
            Self::RimCallRelease => f::RIMCALL_RELEASE,
            Self::RimCallQueryInterface => f::RIMCALL_QUERY_INTERFACE,
            Self::ExchangeCapabilitiesReq => f::EXCHANGE_CAPABILITIES_REQ,
            Self::SetChannelParams => f::SET_CHANNEL_PARAMS,
            Self::AddStream => f::ADD_STREAM,
            Self::OnSample => f::ON_SAMPLE,
            Self::SetVideoWindow => f::SET_VIDEO_WINDOW,
            Self::OnNewPresentation => f::ON_NEW_PRESENTATION,
            Self::ShutdownPresentationReq => f::SHUTDOWN_PRESENTATION_REQ,
            Self::SetTopologyReq => f::SET_TOPOLOGY_REQ,
            Self::CheckFormatSupportReq => f::CHECK_FORMAT_SUPPORT_REQ,
            Self::OnPlaybackStarted => f::ON_PLAYBACK_STARTED,
            Self::OnPlaybackPaused => f::ON_PLAYBACK_PAUSED,
            Self::OnPlaybackStopped => f::ON_PLAYBACK_STOPPED,
            Self::OnPlaybackRestarted => f::ON_PLAYBACK_RESTARTED,
            Self::OnPlaybackRateChanged => f::ON_PLAYBACK_RATE_CHANGED,
            Self::OnFlush => f::ON_FLUSH,
            Self::OnStreamVolume => f::ON_STREAM_VOLUME,
            Self::OnChannelVolume => f::ON_CHANNEL_VOLUME,
            Self::OnEndOfStream => f::ON_END_OF_STREAM,
            Self::SetAllocator => f::SET_ALLOCATOR,
            Self::NotifyPreroll => f::NOTIFY_PREROLL,
            Self::UpdateGeometryInfo => f::UPDATE_GEOMETRY_INFO,
            Self::RemoveStream => f::REMOVE_STREAM,
            Self::SetSourceVideoRect => f::SET_SOURCE_VIDEO_RECT,
            Self::PlaybackAck => f::PLAYBACK_ACK,
            Self::ClientEventNotification => f::CLIENT_EVENT_NOTIFICATION,
            Self::Other { function_id, .. } => function_id,
        }
    }
}

// ── Capability types (MS-RDPEV §2.2.4.3) ────────────────────────────

pub mod capability_type {
    //! `TSMM_CAPABILITIES.CapabilityType` values -- MS-RDPEV §2.2.4.3.
    pub const VERSION: u32 = 0x0000_0001;
    pub const PLATFORM: u32 = 0x0000_0002;
    pub const AUDIO_SUPPORT: u32 = 0x0000_0003;
    pub const LATENCY: u32 = 0x0000_0004;
}

/// `MMREDIR_CAPABILITY_PLATFORM` bit flags carried in the u32 payload
/// of a `CapabilityType = PLATFORM` capability entry. MS-RDPEV §2.2.10.
pub mod platform_capability_flags {
    pub const MF: u32 = 0x0000_0001;
    pub const DSHOW: u32 = 0x0000_0002;
    pub const OTHER: u32 = 0x0000_0004;
}

/// `MMREDIR_CAPABILITY_AUDIOSUPPORT` values. MS-RDPEV §2.2.15.
pub mod audio_support_capability {
    pub const SUPPORTED: u32 = 0x0000_0001;
    pub const NO_DEVICE: u32 = 0x0000_0002;
}

/// `TSMM_PLATFORM_COOKIE_*` values -- MS-RDPEV §2.2.9.
pub mod platform_cookie {
    pub const UNDEFINED: u32 = 0x0000_0000;
    pub const MF: u32 = 0x0000_0001;
    pub const DSHOW: u32 = 0x0000_0002;
}

// ── Sample / window flags ───────────────────────────────────────────

/// `SampleExtensions` bit flags in `TS_MM_DATA_SAMPLE`. MS-RDPEV §2.2.8.
pub mod sample_extensions {
    pub const CLEANPOINT: u32 = 0x0000_0001;
    pub const DISCONTINUITY: u32 = 0x0000_0002;
    pub const INTERLACED: u32 = 0x0000_0004;
    pub const BOTTOM_FIELD_FIRST: u32 = 0x0000_0008;
    pub const REPEAT_FIELD_FIRST: u32 = 0x0000_0010;
    pub const SINGLE_FIELD: u32 = 0x0000_0020;
    pub const DERIVED_FROM_TOP_FIELD: u32 = 0x0000_0040;
    pub const HAS_NO_TIMESTAMPS: u32 = 0x0000_0080;
    pub const RELATIVE_TIMESTAMPS: u32 = 0x0000_0100;
    pub const ABSOLUTE_TIMESTAMPS: u32 = 0x0000_0200;
}

/// `TS_WNDFLAG` bits used by `TS_GEOMETRY_INFO`. MS-RDPEV §2.2.13.
pub mod window_flags {
    pub const NEW: u32 = 0x0000_0001;
    pub const DELETED: u32 = 0x0000_0002;
    pub const VISRGN: u32 = 0x0000_1000;
}

// ── Standard HRESULTs ───────────────────────────────────────────────

/// `S_OK` -- successful response Result code.
pub const S_OK: u32 = 0x0000_0000;
/// `E_FAIL` -- generic failure; used when the client cannot honour a request.
pub const E_FAIL: u32 = 0x8000_4005;
/// `E_NOTIMPL` -- unsupported function or interface.
pub const E_NOTIMPL: u32 = 0x8000_4001;
/// `E_OUTOFMEMORY` -- allocation failure mapped from `CamError::OutOfMemory`.
pub const E_OUT_OF_MEMORY: u32 = 0x8007_000E;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_roundtrip_known_values() {
        for raw in [Mask::NONE, Mask::PROXY, Mask::STUB] {
            let m = Mask::from_interface_id(raw);
            assert_eq!(m.as_u32(), raw);
        }
    }

    #[test]
    fn mask_preserves_unknown_bits() {
        let weird = 0xC000_0000;
        let m = Mask::from_interface_id(weird);
        assert!(matches!(m, Mask::Other(_)));
        assert_eq!(m.as_u32(), weird);
    }

    #[test]
    fn pack_unpack_interface_id_roundtrip() {
        let raw = pack_interface_id(0x0000_0001, Mask::Proxy);
        assert_eq!(raw, 0x4000_0001);
        let (iv, m) = unpack_interface_id(raw);
        assert_eq!(iv, 1);
        assert_eq!(m, Mask::Proxy);
    }

    #[test]
    fn pack_truncates_interface_value_to_30_bits() {
        let raw = pack_interface_id(0xFFFF_FFFF, Mask::Stub);
        assert_eq!(raw & Mask::BITS, Mask::STUB);
        assert_eq!(raw & INTERFACE_VALUE_MASK, INTERFACE_VALUE_MASK);
    }

    #[test]
    fn function_id_dispatch_respects_interface() {
        // Opcode 0x100 means two different things on each interface.
        let on_server = FunctionId::from_raw(0, 0x100);
        let on_client = FunctionId::from_raw(1, 0x100);
        assert_eq!(on_server, FunctionId::ExchangeCapabilitiesReq);
        assert_eq!(on_client, FunctionId::PlaybackAck);
    }

    #[test]
    fn function_id_unknown_preserves_pair() {
        let fid = FunctionId::from_raw(7, 0xDEAD_BEEF);
        assert!(matches!(
            fid,
            FunctionId::Other {
                interface_value: 7,
                function_id: 0xDEAD_BEEF
            }
        ));
    }

    #[test]
    fn function_id_to_u32_roundtrip_server_data() {
        for fid in [
            FunctionId::ExchangeCapabilitiesReq,
            FunctionId::SetChannelParams,
            FunctionId::AddStream,
            FunctionId::OnSample,
            FunctionId::SetSourceVideoRect,
        ] {
            let raw = fid.to_u32();
            let back = FunctionId::from_raw(interface_value::SERVER_DATA, raw);
            assert_eq!(back, fid);
        }
    }

    #[test]
    fn function_id_to_u32_roundtrip_client_notifications() {
        for fid in [FunctionId::PlaybackAck, FunctionId::ClientEventNotification] {
            let raw = fid.to_u32();
            let back = FunctionId::from_raw(interface_value::CLIENT_NOTIFICATIONS, raw);
            assert_eq!(back, fid);
        }
    }
}
