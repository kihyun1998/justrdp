#![forbid(unsafe_code)]

//! Connection Finalization and Session PDUs -- MS-RDPBCGR 2.2.1.13+
//!
//! These PDUs are exchanged after Demand Active / Confirm Active to finalize
//! the RDP connection, plus active session data PDUs.

use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeError, EncodeResult};

// ── Synchronize PDU ──

/// Synchronize PDU data (2.2.1.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynchronizePdu {
    pub message_type: u16, // always 1 (SYNCMSGTYPE_SYNC)
    pub target_user: u16,
}

pub const SYNCHRONIZE_PDU_SIZE: usize = 4;

impl Encode for SynchronizePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.message_type, "SynchronizePdu::messageType")?;
        dst.write_u16_le(self.target_user, "SynchronizePdu::targetUser")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "SynchronizePdu" }
    fn size(&self) -> usize { SYNCHRONIZE_PDU_SIZE }
}

impl<'de> Decode<'de> for SynchronizePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            message_type: src.read_u16_le("SynchronizePdu::messageType")?,
            target_user: src.read_u16_le("SynchronizePdu::targetUser")?,
        })
    }
}

// ── Control PDU ──

/// Control action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ControlAction {
    RequestControl = 0x0001,
    GrantedControl = 0x0002,
    Detach = 0x0003,
    Cooperate = 0x0004,
}

impl ControlAction {
    pub fn from_u16(val: u16) -> DecodeResult<Self> {
        match val {
            0x0001 => Ok(Self::RequestControl),
            0x0002 => Ok(Self::GrantedControl),
            0x0003 => Ok(Self::Detach),
            0x0004 => Ok(Self::Cooperate),
            _ => Err(DecodeError::unexpected_value("ControlAction", "action", "unknown")),
        }
    }
}

/// Control PDU data (2.2.1.15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlPdu {
    pub action: ControlAction,
    pub grant_id: u16,
    pub control_id: u32,
}

pub const CONTROL_PDU_SIZE: usize = 8;

impl Encode for ControlPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.action as u16, "ControlPdu::action")?;
        dst.write_u16_le(self.grant_id, "ControlPdu::grantId")?;
        dst.write_u32_le(self.control_id, "ControlPdu::controlId")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "ControlPdu" }
    fn size(&self) -> usize { CONTROL_PDU_SIZE }
}

impl<'de> Decode<'de> for ControlPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            action: ControlAction::from_u16(src.read_u16_le("ControlPdu::action")?)?,
            grant_id: src.read_u16_le("ControlPdu::grantId")?,
            control_id: src.read_u32_le("ControlPdu::controlId")?,
        })
    }
}

// ── Font List / Font Map PDU ──

/// Font List PDU data (2.2.1.18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FontListPdu {
    pub number_fonts: u16,
    pub total_num_fonts: u16,
    pub list_flags: u16,
    pub entry_size: u16,
}

impl FontListPdu {
    /// Standard font list (no actual fonts, just signaling).
    pub fn default_request() -> Self {
        Self {
            number_fonts: 0,
            total_num_fonts: 0,
            list_flags: 0x0003, // FONTLIST_FIRST | FONTLIST_LAST
            entry_size: 0x0032,
        }
    }
}

pub const FONT_LIST_PDU_SIZE: usize = 8;

impl Encode for FontListPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.number_fonts, "FontListPdu::numberFonts")?;
        dst.write_u16_le(self.total_num_fonts, "FontListPdu::totalNumFonts")?;
        dst.write_u16_le(self.list_flags, "FontListPdu::listFlags")?;
        dst.write_u16_le(self.entry_size, "FontListPdu::entrySize")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "FontListPdu" }
    fn size(&self) -> usize { FONT_LIST_PDU_SIZE }
}

impl<'de> Decode<'de> for FontListPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            number_fonts: src.read_u16_le("FontListPdu::numberFonts")?,
            total_num_fonts: src.read_u16_le("FontListPdu::totalNumFonts")?,
            list_flags: src.read_u16_le("FontListPdu::listFlags")?,
            entry_size: src.read_u16_le("FontListPdu::entrySize")?,
        })
    }
}

/// Font Map PDU data (2.2.1.22).
pub type FontMapPdu = FontListPdu; // Same structure

// ── Persistent Key List PDU ──

/// Persistent Key List PDU (2.2.1.17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentKeyListPdu {
    pub num_entries: [u16; 5],  // numEntriesCache0..4
    pub total_entries: [u16; 5], // totalEntriesCache0..4
    pub flags: u8, // PERSIST_FIRST_PDU(0x01) | PERSIST_LAST_PDU(0x02)
    pub keys: Vec<PersistentKeyEntry>,
}

/// A single persistent key entry (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistentKeyEntry {
    pub key1: u32,
    pub key2: u32,
}

pub const PERSISTENT_KEY_LIST_HEADER_SIZE: usize = 20 + 1 + 3; // 5*2 + 5*2 + flags + pad3

impl Encode for PersistentKeyListPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        for i in 0..5 {
            dst.write_u16_le(self.num_entries[i], "PersistentKeyList::numEntries")?;
        }
        for i in 0..5 {
            dst.write_u16_le(self.total_entries[i], "PersistentKeyList::totalEntries")?;
        }
        dst.write_u8(self.flags, "PersistentKeyList::flags")?;
        dst.write_zeros(3, "PersistentKeyList::pad")?;
        for key in &self.keys {
            dst.write_u32_le(key.key1, "PersistentKeyEntry::key1")?;
            dst.write_u32_le(key.key2, "PersistentKeyEntry::key2")?;
        }
        Ok(())
    }
    fn name(&self) -> &'static str { "PersistentKeyListPdu" }
    fn size(&self) -> usize { PERSISTENT_KEY_LIST_HEADER_SIZE + self.keys.len() * 8 }
}

impl<'de> Decode<'de> for PersistentKeyListPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let mut num_entries = [0u16; 5];
        let mut total_entries = [0u16; 5];
        for i in 0..5 { num_entries[i] = src.read_u16_le("PersistentKeyList::numEntries")?; }
        for i in 0..5 { total_entries[i] = src.read_u16_le("PersistentKeyList::totalEntries")?; }
        let flags = src.read_u8("PersistentKeyList::flags")?;
        src.skip(3, "PersistentKeyList::pad")?;

        let total_keys: usize = num_entries.iter().map(|&n| n as usize).sum();
        // MS-RDPBCGR 2.2.1.17: cap total keys to prevent excessive allocation
        if total_keys > 16384 {
            return Err(DecodeError::unexpected_value("PersistentKeyListPdu", "totalKeys", "exceeds maximum 16384"));
        }
        let mut keys = Vec::with_capacity(total_keys);
        for _ in 0..total_keys {
            keys.push(PersistentKeyEntry {
                key1: src.read_u32_le("PersistentKeyEntry::key1")?,
                key2: src.read_u32_le("PersistentKeyEntry::key2")?,
            });
        }
        Ok(Self { num_entries, total_entries, flags, keys })
    }
}

// ── Deactivate All PDU ──

/// Deactivate All PDU (2.2.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeactivateAllPdu {
    pub share_id: u32,
    pub length_source_descriptor: u16,
}

pub const DEACTIVATE_ALL_PDU_SIZE: usize = 6;

impl Encode for DeactivateAllPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.share_id, "DeactivateAllPdu::shareId")?;
        dst.write_u16_le(self.length_source_descriptor, "DeactivateAllPdu::lengthSrcDescriptor")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "DeactivateAllPdu" }
    fn size(&self) -> usize { DEACTIVATE_ALL_PDU_SIZE }
}

impl<'de> Decode<'de> for DeactivateAllPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            share_id: src.read_u32_le("DeactivateAllPdu::shareId")?,
            length_source_descriptor: src.read_u16_le("DeactivateAllPdu::lengthSrcDescriptor")?,
        })
    }
}

// ── Input Event PDU ──

/// Slow-path input event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum InputEventType {
    Synchronize = 0x0000,
    ScanCode = 0x0004,
    Unicode = 0x0005,
    Mouse = 0x8001,
    ExtendedMouse = 0x8002,
}

/// Input event (variable, stored as raw bytes for flexibility).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputEventPdu {
    pub num_events: u16,
    pub event_data: Vec<u8>,
}

impl Encode for InputEventPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.num_events, "InputEventPdu::numEvents")?;
        dst.write_u16_le(0, "InputEventPdu::pad")?;
        dst.write_slice(&self.event_data, "InputEventPdu::eventData")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "InputEventPdu" }
    fn size(&self) -> usize { 4 + self.event_data.len() }
}

impl<'de> Decode<'de> for InputEventPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let num_events = src.read_u16_le("InputEventPdu::numEvents")?;
        let _pad = src.read_u16_le("InputEventPdu::pad")?;
        let event_data = src.peek_remaining().to_vec();
        src.skip(event_data.len(), "InputEventPdu::eventData")?;
        Ok(Self { num_events, event_data })
    }
}

// ── Play Sound PDU ──

/// Play Sound PDU Data (MS-RDPBCGR 2.2.9.1.1.5.1).
///
/// Sent by the server to instruct the client to play a system beep with
/// a specific duration and frequency. Both fields are little-endian UINT32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaySoundPdu {
    /// Duration of the beep, in milliseconds.
    pub duration_ms: u32,
    /// Frequency of the beep, in hertz.
    pub frequency_hz: u32,
}

impl Encode for PlaySoundPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.duration_ms, "PlaySound::duration")?;
        dst.write_u32_le(self.frequency_hz, "PlaySound::frequency")?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "PlaySoundPdu"
    }
    fn size(&self) -> usize {
        8
    }
}

impl<'de> Decode<'de> for PlaySoundPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let duration_ms = src.read_u32_le("PlaySound::duration")?;
        let frequency_hz = src.read_u32_le("PlaySound::frequency")?;
        Ok(Self {
            duration_ms,
            frequency_hz,
        })
    }
}

// ── Suppress Output PDU ──

/// Suppress Output PDU (2.2.11.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuppressOutputPdu {
    pub allow_display_updates: u8, // 0 = suppress, 1 = allow
    pub left: Option<u16>,
    pub top: Option<u16>,
    pub right: Option<u16>,
    pub bottom: Option<u16>,
}

impl Encode for SuppressOutputPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(self.allow_display_updates, "SuppressOutput::allowDisplayUpdates")?;
        dst.write_zeros(3, "SuppressOutput::pad")?;
        if self.allow_display_updates != 0 {
            dst.write_u16_le(self.left.unwrap_or(0), "SuppressOutput::left")?;
            dst.write_u16_le(self.top.unwrap_or(0), "SuppressOutput::top")?;
            dst.write_u16_le(self.right.unwrap_or(0), "SuppressOutput::right")?;
            dst.write_u16_le(self.bottom.unwrap_or(0), "SuppressOutput::bottom")?;
        }
        Ok(())
    }
    fn name(&self) -> &'static str { "SuppressOutputPdu" }
    fn size(&self) -> usize { 4 + if self.allow_display_updates != 0 { 8 } else { 0 } }
}

impl<'de> Decode<'de> for SuppressOutputPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let allow = src.read_u8("SuppressOutput::allowDisplayUpdates")?;
        src.skip(3, "SuppressOutput::pad")?;
        let (left, top, right, bottom) = if allow != 0 {
            (
                Some(src.read_u16_le("SuppressOutput::left")?),
                Some(src.read_u16_le("SuppressOutput::top")?),
                Some(src.read_u16_le("SuppressOutput::right")?),
                Some(src.read_u16_le("SuppressOutput::bottom")?),
            )
        } else {
            (None, None, None, None)
        };
        Ok(Self { allow_display_updates: allow, left, top, right, bottom })
    }
}

// ── Set Error Info PDU ──

/// Set Error Info PDU (2.2.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetErrorInfoPdu {
    pub error_info: u32,
}

/// Common error codes (MS-RDPBCGR 2.2.5.1.1, Set Error Info PDU).
pub const ERRINFO_NONE: u32 = 0x0000_0000;
pub const ERRINFO_RPC_INITIATED_DISCONNECT: u32 = 0x0000_0001;
pub const ERRINFO_RPC_INITIATED_LOGOFF: u32 = 0x0000_0002;
pub const ERRINFO_IDLE_TIMEOUT: u32 = 0x0000_0003;
pub const ERRINFO_LOGON_TIMEOUT: u32 = 0x0000_0004;
pub const ERRINFO_DISCONNECTED_BY_OTHER: u32 = 0x0000_0005;
pub const ERRINFO_OUT_OF_MEMORY: u32 = 0x0000_0006;
pub const ERRINFO_SERVER_DENIED_CONNECTION: u32 = 0x0000_0007;
pub const ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES: u32 = 0x0000_0009;
pub const ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED: u32 = 0x0000_000A;
pub const ERRINFO_RPC_INITIATED_DISCONNECT_BY_USER: u32 = 0x0000_000B;
pub const ERRINFO_LOGOFF_BY_USER: u32 = 0x0000_000C;

/// Classify a `SetErrorInfoPdu::error_info` code as retryable or not.
///
/// Retryable codes are transient failures where re-opening the
/// connection (typically with the Auto-Reconnect Cookie) has a
/// reasonable chance of succeeding. Non-retryable codes indicate
/// either a deliberate user/administrator action (logoff, kick) or a
/// policy-driven denial (insufficient privileges, license failure,
/// credential refresh required) where a plain reconnect would just
/// hit the same wall.
///
/// See roadmap §21.6 for the full code table.
///
/// Used by `justrdp-blocking::RdpClient::next_event` to gate the
/// auto-reconnect path when the server initiates a clean termination
/// via SetErrorInfo + DisconnectProviderUltimatum.
pub const fn is_error_info_retryable(code: u32) -> bool {
    match code {
        // No error — this isn't a real disconnect reason.
        ERRINFO_NONE => true,

        // Administrator / user initiated — user intent is to leave.
        ERRINFO_RPC_INITIATED_DISCONNECT
        | ERRINFO_RPC_INITIATED_LOGOFF
        | ERRINFO_DISCONNECTED_BY_OTHER
        | ERRINFO_SERVER_DENIED_CONNECTION
        | ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES
        | ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED
        | ERRINFO_RPC_INITIATED_DISCONNECT_BY_USER
        | ERRINFO_LOGOFF_BY_USER => false,

        // Transient server-side failures — reconnect often succeeds.
        ERRINFO_IDLE_TIMEOUT | ERRINFO_LOGON_TIMEOUT | ERRINFO_OUT_OF_MEMORY => true,

        // Licensing errors (0x100C..=0x1015) — persistent and usually
        // won't clear on retry without operator intervention.
        0x0000_100C..=0x0000_1015 => false,

        // Protocol / encryption failures (0x1000..=0x100B) — usually
        // transient bugs or MITM artifacts; let reconnect try once.
        0x0000_1000..=0x0000_100B => true,

        // Connection Broker / redirection codes (0x0400..=0x040F) are
        // informational: the client should be doing a redirect, not a
        // retry. Mark as non-retryable so we don't loop.
        0x0000_0400..=0x0000_040F => false,

        // Unknown / future codes — assume transient and retry once.
        _ => true,
    }
}

impl Encode for SetErrorInfoPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.error_info, "SetErrorInfo::errorInfo")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "SetErrorInfoPdu" }
    fn size(&self) -> usize { 4 }
}

impl<'de> Decode<'de> for SetErrorInfoPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self { error_info: src.read_u32_le("SetErrorInfo::errorInfo")? })
    }
}

// ── Shutdown Request/Denied PDU ──

/// Shutdown Request PDU (empty body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownRequestPdu;

impl Encode for ShutdownRequestPdu {
    fn encode(&self, _dst: &mut WriteCursor<'_>) -> EncodeResult<()> { Ok(()) }
    fn name(&self) -> &'static str { "ShutdownRequestPdu" }
    fn size(&self) -> usize { 0 }
}

impl<'de> Decode<'de> for ShutdownRequestPdu {
    fn decode(_src: &mut ReadCursor<'de>) -> DecodeResult<Self> { Ok(Self) }
}

/// Shutdown Denied PDU (empty body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownDeniedPdu;

impl Encode for ShutdownDeniedPdu {
    fn encode(&self, _dst: &mut WriteCursor<'_>) -> EncodeResult<()> { Ok(()) }
    fn name(&self) -> &'static str { "ShutdownDeniedPdu" }
    fn size(&self) -> usize { 0 }
}

impl<'de> Decode<'de> for ShutdownDeniedPdu {
    fn decode(_src: &mut ReadCursor<'de>) -> DecodeResult<Self> { Ok(Self) }
}

// ── Refresh Rect PDU ──

/// Refresh Rect PDU (2.2.11.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRectPdu {
    pub areas: Vec<InclusiveRect>,
}

/// Inclusive rectangle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InclusiveRect {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

impl Encode for RefreshRectPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(self.areas.len() as u8, "RefreshRect::numberOfAreas")?;
        dst.write_zeros(3, "RefreshRect::pad")?;
        for r in &self.areas {
            dst.write_u16_le(r.left, "RefreshRect::left")?;
            dst.write_u16_le(r.top, "RefreshRect::top")?;
            dst.write_u16_le(r.right, "RefreshRect::right")?;
            dst.write_u16_le(r.bottom, "RefreshRect::bottom")?;
        }
        Ok(())
    }
    fn name(&self) -> &'static str { "RefreshRectPdu" }
    fn size(&self) -> usize { 4 + self.areas.len() * 8 }
}

impl<'de> Decode<'de> for RefreshRectPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let count = src.read_u8("RefreshRect::numberOfAreas")? as usize;
        src.skip(3, "RefreshRect::pad")?;
        let mut areas = Vec::with_capacity(count);
        for _ in 0..count {
            areas.push(InclusiveRect {
                left: src.read_u16_le("RefreshRect::left")?,
                top: src.read_u16_le("RefreshRect::top")?,
                right: src.read_u16_le("RefreshRect::right")?,
                bottom: src.read_u16_le("RefreshRect::bottom")?,
            });
        }
        Ok(Self { areas })
    }
}

// ── Save Session Info PDU (MS-RDPBCGR 2.2.10.1) ──

/// Info type constants (MS-RDPBCGR 2.2.10.1.1).
pub const INFOTYPE_LOGON: u32 = 0x0000_0000;
pub const INFOTYPE_LOGON_LONG: u32 = 0x0000_0001;
pub const INFOTYPE_LOGON_PLAINNOTIFY: u32 = 0x0000_0002;
pub const INFOTYPE_LOGON_EXTENDED_INFO: u32 = 0x0000_0003;

/// Extended logon field flags (MS-RDPBCGR 2.2.10.1.1.4).
pub const LOGON_EX_AUTORECONNECTCOOKIE: u32 = 0x0000_0001;
pub const LOGON_EX_LOGONERRORS: u32 = 0x0000_0002;

/// Auto-Reconnect version (MS-RDPBCGR 2.2.4.2 / 2.2.4.3).
pub const AUTO_RECONNECT_VERSION_1: u32 = 0x0000_0001;

/// Fixed length of ARC_SC/CS_PRIVATE_PACKET (MS-RDPBCGR 2.2.4.2 / 2.2.4.3).
pub const ARC_PACKET_LEN: u32 = 0x0000_001C; // 28

/// TS_LOGON_INFO_VERSION_2 fixed portion size (MS-RDPBCGR 2.2.10.1.1.2).
const LOGON_INFO_V2_FIXED_SIZE: u32 = 576;

/// TS_LOGON_INFO_PLAINNOTIFY payload size (MS-RDPBCGR 2.2.10.1.1.3).
const LOGON_INFO_PLAINNOTIFY_SIZE: usize = 576;

/// TS_LOGON_INFO_EXTENDED pad size (MS-RDPBCGR 2.2.10.1.1.4).
const LOGON_INFO_EXTENDED_PAD: usize = 570;

/// TS_LOGON_INFO_VERSION_2 pad size (MS-RDPBCGR 2.2.10.1.1.2).
const LOGON_INFO_V2_PAD: usize = 558;

/// Save Session Info PDU (2.2.10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveSessionInfoPdu {
    pub info_data: SaveSessionInfoData,
}

/// Typed session info data keyed on infoType (MS-RDPBCGR 2.2.10.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveSessionInfoData {
    /// INFOTYPE_LOGON (0x00000000) — TS_LOGON_INFO (V1).
    LogonV1(LogonInfoV1),
    /// INFOTYPE_LOGON_LONG (0x00000001) — TS_LOGON_INFO_VERSION_2.
    LogonV2(LogonInfoV2),
    /// INFOTYPE_LOGON_PLAINNOTIFY (0x00000002) — 576 bytes of padding.
    PlainNotify,
    /// INFOTYPE_LOGON_EXTENDED_INFO (0x00000003) — TS_LOGON_INFO_EXTENDED.
    Extended(LogonInfoExtended),
}

/// TS_LOGON_INFO (MS-RDPBCGR 2.2.10.1.1.1) — 576 bytes total on wire.
///
/// cbDomain(4) + Domain(52) + cbUserName(4) + UserName(512) + SessionId(4) = 576.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogonInfoV1 {
    pub domain: Vec<u8>,
    pub user_name: Vec<u8>,
    pub session_id: u32,
}

/// TS_LOGON_INFO_VERSION_2 (MS-RDPBCGR 2.2.10.1.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogonInfoV2 {
    pub session_id: u32,
    pub domain: Vec<u8>,
    pub user_name: Vec<u8>,
}

/// TS_LOGON_INFO_EXTENDED (MS-RDPBCGR 2.2.10.1.1.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogonInfoExtended {
    pub auto_reconnect_cookie: Option<ArcScPrivatePacket>,
    pub logon_errors: Option<LogonErrorsInfo>,
}

/// TS_LOGON_ERRORS_INFO (MS-RDPBCGR 2.2.10.1.1.4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogonErrorsInfo {
    pub error_notification_type: u32,
    pub error_notification_data: u32,
}

impl SaveSessionInfoData {
    /// Extract the server-issued Auto-Reconnect Cookie if this PDU contains one.
    ///
    /// Returns `Some` only for `Extended` variants whose `LogonInfoExtended` carries
    /// an `ArcScPrivatePacket`. The returned bytes can be passed to
    /// `ArcScPrivatePacket::to_storage_bytes()` for persistence, or copied directly
    /// into a connector `ArcCookie` for the next reconnect attempt.
    ///
    /// Returns `(logon_id, arc_random_bits)` so callers do not need to depend on
    /// the connector's `ArcCookie` type from this `pdu` crate.
    pub fn arc_random(&self) -> Option<(u32, [u8; 16])> {
        match self {
            Self::Extended(ext) => ext
                .auto_reconnect_cookie
                .as_ref()
                .map(|p| (p.logon_id, p.arc_random_bits)),
            _ => None,
        }
    }
}

/// ARC_SC_PRIVATE_PACKET — server Auto-Reconnect Cookie (MS-RDPBCGR 2.2.4.2).
///
/// Wire: cbLen(u32) + Version(u32) + LogonId(u32) + ArcRandomBits([u8;16]) = 28 bytes.
///
/// `Debug` redacts `arc_random_bits` to prevent accidental secret leakage in logs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ArcScPrivatePacket {
    pub logon_id: u32,
    pub arc_random_bits: [u8; 16],
}

impl core::fmt::Debug for ArcScPrivatePacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArcScPrivatePacket")
            .field("logon_id", &self.logon_id)
            .field("arc_random_bits", &"[REDACTED]")
            .finish()
    }
}

/// ARC_CS_PRIVATE_PACKET — client Auto-Reconnect response (MS-RDPBCGR 2.2.4.3).
///
/// Wire: cbLen(u32) + Version(u32) + LogonId(u32) + SecurityVerifier([u8;16]) = 28 bytes.
///
/// `Debug` redacts `security_verifier` to prevent accidental token leakage in logs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ArcCsPrivatePacket {
    pub logon_id: u32,
    pub security_verifier: [u8; 16],
}

impl core::fmt::Debug for ArcCsPrivatePacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArcCsPrivatePacket")
            .field("logon_id", &self.logon_id)
            .field("security_verifier", &"[REDACTED]")
            .finish()
    }
}

// ── SaveSessionInfoPdu Encode/Decode ──

impl Encode for SaveSessionInfoPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        match &self.info_data {
            SaveSessionInfoData::LogonV1(v1) => {
                dst.write_u32_le(INFOTYPE_LOGON, "SaveSessionInfo::infoType")?;
                encode_logon_v1(v1, dst)?;
            }
            SaveSessionInfoData::LogonV2(v2) => {
                dst.write_u32_le(INFOTYPE_LOGON_LONG, "SaveSessionInfo::infoType")?;
                encode_logon_v2(v2, dst)?;
            }
            SaveSessionInfoData::PlainNotify => {
                dst.write_u32_le(INFOTYPE_LOGON_PLAINNOTIFY, "SaveSessionInfo::infoType")?;
                dst.write_zeros(LOGON_INFO_PLAINNOTIFY_SIZE, "SaveSessionInfo::plainNotifyPad")?;
            }
            SaveSessionInfoData::Extended(ext) => {
                dst.write_u32_le(INFOTYPE_LOGON_EXTENDED_INFO, "SaveSessionInfo::infoType")?;
                encode_logon_extended(ext, dst)?;
            }
        }
        Ok(())
    }
    fn name(&self) -> &'static str { "SaveSessionInfoPdu" }
    fn size(&self) -> usize {
        4 + match &self.info_data {
            SaveSessionInfoData::LogonV1(_) => 576, // 4+52+4+512+4 (cbDomain+Domain+cbUserName+UserName+SessionId)
            SaveSessionInfoData::LogonV2(v2) => {
                LOGON_INFO_V2_FIXED_SIZE as usize + v2.domain.len() + v2.user_name.len()
            }
            SaveSessionInfoData::PlainNotify => LOGON_INFO_PLAINNOTIFY_SIZE,
            SaveSessionInfoData::Extended(ext) => logon_extended_size(ext),
        }
    }
}

impl<'de> Decode<'de> for SaveSessionInfoPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let info_type = src.read_u32_le("SaveSessionInfo::infoType")?;
        let info_data = match info_type {
            INFOTYPE_LOGON => SaveSessionInfoData::LogonV1(decode_logon_v1(src)?),
            INFOTYPE_LOGON_LONG => SaveSessionInfoData::LogonV2(decode_logon_v2(src)?),
            INFOTYPE_LOGON_PLAINNOTIFY => {
                src.skip(LOGON_INFO_PLAINNOTIFY_SIZE, "SaveSessionInfo::plainNotifyPad")?;
                SaveSessionInfoData::PlainNotify
            }
            INFOTYPE_LOGON_EXTENDED_INFO => {
                SaveSessionInfoData::Extended(decode_logon_extended(src)?)
            }
            _ => {
                return Err(DecodeError::unexpected_value(
                    "SaveSessionInfoPdu", "infoType", "unknown info type",
                ));
            }
        };
        Ok(Self { info_data })
    }
}

// ── LogonInfoV1 helpers (MS-RDPBCGR 2.2.10.1.1.1) — fixed 576 bytes ──

fn encode_logon_v1(v1: &LogonInfoV1, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
    if v1.domain.len() > 52 {
        return Err(EncodeError::invalid_value("LogonInfoV1", "domain too long"));
    }
    if v1.user_name.len() > 512 {
        return Err(EncodeError::invalid_value("LogonInfoV1", "userName too long"));
    }
    // cbDomain (byte count of domain content)
    dst.write_u32_le(v1.domain.len() as u32, "LogonV1::cbDomain")?;
    // Domain — 52-byte fixed buffer
    dst.write_slice(&v1.domain, "LogonV1::domain")?;
    dst.write_zeros(52 - v1.domain.len(), "LogonV1::domainPad")?;
    // cbUserName
    dst.write_u32_le(v1.user_name.len() as u32, "LogonV1::cbUserName")?;
    // UserName — 512-byte fixed buffer
    dst.write_slice(&v1.user_name, "LogonV1::userName")?;
    dst.write_zeros(512 - v1.user_name.len(), "LogonV1::userNamePad")?;
    // SessionId
    dst.write_u32_le(v1.session_id, "LogonV1::sessionId")?;
    Ok(())
}

fn decode_logon_v1(src: &mut ReadCursor<'_>) -> DecodeResult<LogonInfoV1> {
    let cb_domain = src.read_u32_le("LogonV1::cbDomain")? as usize;
    if cb_domain > 52 {
        return Err(DecodeError::unexpected_value("LogonInfoV1", "cbDomain", "exceeds 52"));
    }
    let domain_buf = src.read_slice(52, "LogonV1::domain")?;
    let domain = domain_buf[..cb_domain].to_vec();

    let cb_user = src.read_u32_le("LogonV1::cbUserName")? as usize;
    if cb_user > 512 {
        return Err(DecodeError::unexpected_value("LogonInfoV1", "cbUserName", "exceeds 512"));
    }
    let user_buf = src.read_slice(512, "LogonV1::userName")?;
    let user_name = user_buf[..cb_user].to_vec();

    let session_id = src.read_u32_le("LogonV1::sessionId")?;
    Ok(LogonInfoV1 { domain, user_name, session_id })
}

// ── LogonInfoV2 helpers (MS-RDPBCGR 2.2.10.1.1.2) ──

fn encode_logon_v2(v2: &LogonInfoV2, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
    // Version MUST be 0x0001
    dst.write_u16_le(0x0001, "LogonV2::version")?;
    // Size MUST be 576 (fixed portion)
    dst.write_u32_le(LOGON_INFO_V2_FIXED_SIZE, "LogonV2::size")?;
    dst.write_u32_le(v2.session_id, "LogonV2::sessionId")?;
    dst.write_u32_le(v2.domain.len() as u32, "LogonV2::cbDomain")?;
    dst.write_u32_le(v2.user_name.len() as u32, "LogonV2::cbUserName")?;
    // Pad (558 bytes)
    dst.write_zeros(LOGON_INFO_V2_PAD, "LogonV2::pad")?;
    // Variable-length domain and userName
    dst.write_slice(&v2.domain, "LogonV2::domain")?;
    dst.write_slice(&v2.user_name, "LogonV2::userName")?;
    Ok(())
}

fn decode_logon_v2(src: &mut ReadCursor<'_>) -> DecodeResult<LogonInfoV2> {
    let version = src.read_u16_le("LogonV2::version")?;
    if version != 0x0001 {
        return Err(DecodeError::unexpected_value("LogonInfoV2", "version", "must be 0x0001"));
    }
    let size = src.read_u32_le("LogonV2::size")?;
    if size != LOGON_INFO_V2_FIXED_SIZE {
        return Err(DecodeError::unexpected_value("LogonInfoV2", "size", "must be 576"));
    }
    let session_id = src.read_u32_le("LogonV2::sessionId")?;
    let cb_domain = src.read_u32_le("LogonV2::cbDomain")? as usize;
    let cb_user = src.read_u32_le("LogonV2::cbUserName")? as usize;
    // Cap to prevent excessive allocation (practical limit: domain/user < 64 KiB)
    if cb_domain > 65536 {
        return Err(DecodeError::unexpected_value("LogonInfoV2", "cbDomain", "exceeds 64 KiB"));
    }
    if cb_user > 65536 {
        return Err(DecodeError::unexpected_value("LogonInfoV2", "cbUserName", "exceeds 64 KiB"));
    }
    // Pad (558 bytes)
    src.skip(LOGON_INFO_V2_PAD, "LogonV2::pad")?;
    // Variable data
    let domain = src.read_slice(cb_domain, "LogonV2::domain")?.to_vec();
    let user_name = src.read_slice(cb_user, "LogonV2::userName")?.to_vec();
    Ok(LogonInfoV2 { session_id, domain, user_name })
}

// ── LogonInfoExtended helpers (MS-RDPBCGR 2.2.10.1.1.4) ──

fn logon_extended_size(ext: &LogonInfoExtended) -> usize {
    // Length(u16) + FieldsPresent(u32) + LogonFields + Pad(570)
    let mut fields_size = 0usize;
    if ext.auto_reconnect_cookie.is_some() {
        fields_size += 4 + ARC_CS_PRIVATE_PACKET_SIZE; // cbFieldData + ARC_SC_PRIVATE_PACKET
    }
    if ext.logon_errors.is_some() {
        fields_size += 4 + 8; // cbFieldData + LogonErrorsInfo
    }
    2 + 4 + fields_size + LOGON_INFO_EXTENDED_PAD
}

fn encode_logon_extended(ext: &LogonInfoExtended, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
    let mut fields_present: u32 = 0;
    if ext.auto_reconnect_cookie.is_some() {
        fields_present |= LOGON_EX_AUTORECONNECTCOOKIE;
    }
    if ext.logon_errors.is_some() {
        fields_present |= LOGON_EX_LOGONERRORS;
    }

    // Length covers everything except the 570-byte Pad (MS-RDPBCGR 2.2.10.1.1.4).
    let total = logon_extended_size(ext);
    let length = u16::try_from(total - LOGON_INFO_EXTENDED_PAD)
        .map_err(|_| EncodeError::other("LogonExtended::length", "size overflows u16"))?;

    dst.write_u16_le(length, "LogonExtended::length")?;
    dst.write_u32_le(fields_present, "LogonExtended::fieldsPresent")?;

    // ARC field MUST precede logon errors per MS-RDPBCGR 2.2.10.1.1.4 field ordering.
    if let Some(ref arc) = ext.auto_reconnect_cookie {
        dst.write_u32_le(ARC_CS_PRIVATE_PACKET_SIZE as u32, "LogonField::cbFieldData")?;
        dst.write_u32_le(ARC_PACKET_LEN, "ArcSc::cbLen")?;
        dst.write_u32_le(AUTO_RECONNECT_VERSION_1, "ArcSc::version")?;
        dst.write_u32_le(arc.logon_id, "ArcSc::logonId")?;
        dst.write_slice(&arc.arc_random_bits, "ArcSc::arcRandomBits")?;
    }

    // Logon errors second
    if let Some(ref errors) = ext.logon_errors {
        dst.write_u32_le(8, "LogonField::cbFieldData")?;
        dst.write_u32_le(errors.error_notification_type, "LogonErrors::type")?;
        dst.write_u32_le(errors.error_notification_data, "LogonErrors::data")?;
    }

    // 570-byte pad
    dst.write_zeros(LOGON_INFO_EXTENDED_PAD, "LogonExtended::pad")?;
    Ok(())
}

fn decode_logon_extended(src: &mut ReadCursor<'_>) -> DecodeResult<LogonInfoExtended> {
    // MS-RDPBCGR 2.2.10.1.1.4: Length covers Length+FieldsPresent+LogonFields (excluding Pad).
    // Minimum: Length(2) + FieldsPresent(4) = 6.
    let length = src.read_u16_le("LogonExtended::length")? as usize;
    if length < 6 {
        return Err(DecodeError::unexpected_value(
            "LogonInfoExtended", "length", "must be >= 6",
        ));
    }
    let fields_present = src.read_u32_le("LogonExtended::fieldsPresent")?;

    // ARC cookie first per MS-RDPBCGR 2.2.10.1.1.4 field ordering.
    let auto_reconnect_cookie = if fields_present & LOGON_EX_AUTORECONNECTCOOKIE != 0 {
        let cb_field = src.read_u32_le("LogonField::cbFieldData")? as usize;
        if cb_field < ARC_CS_PRIVATE_PACKET_SIZE {
            return Err(DecodeError::unexpected_value("LogonInfoExtended", "cbFieldData", "ARC field too small"));
        }
        let cb_len = src.read_u32_le("ArcSc::cbLen")?;
        if cb_len != ARC_PACKET_LEN {
            return Err(DecodeError::unexpected_value("ArcScPrivatePacket", "cbLen", "must be 28"));
        }
        let version = src.read_u32_le("ArcSc::version")?;
        if version != AUTO_RECONNECT_VERSION_1 {
            return Err(DecodeError::unexpected_value("ArcScPrivatePacket", "version", "must be 1"));
        }
        let logon_id = src.read_u32_le("ArcSc::logonId")?;
        let bits = src.read_slice(16, "ArcSc::arcRandomBits")?;
        let mut arc_random_bits = [0u8; 16];
        arc_random_bits.copy_from_slice(bits);
        // Cap cbFieldData to prevent abusive skip values, then consume any extra bytes.
        if cb_field > 4096 {
            return Err(DecodeError::unexpected_value(
                "LogonInfoExtended", "cbFieldData", "ARC field exceeds 4096 bytes",
            ));
        }
        if cb_field > ARC_CS_PRIVATE_PACKET_SIZE {
            src.skip(cb_field - ARC_CS_PRIVATE_PACKET_SIZE, "ArcSc::extraPad")?;
        }
        Some(ArcScPrivatePacket { logon_id, arc_random_bits })
    } else {
        None
    };

    // Logon errors second per MS-RDPBCGR 2.2.10.1.1.4 field ordering.
    let logon_errors = if fields_present & LOGON_EX_LOGONERRORS != 0 {
        let cb_field = src.read_u32_le("LogonField::cbFieldData")? as usize;
        if cb_field < 8 {
            return Err(DecodeError::unexpected_value("LogonInfoExtended", "cbFieldData", "logon errors field too small"));
        }
        if cb_field > 4096 {
            return Err(DecodeError::unexpected_value(
                "LogonInfoExtended", "cbFieldData", "logon errors field exceeds 4096 bytes",
            ));
        }
        let error_notification_type = src.read_u32_le("LogonErrors::type")?;
        let error_notification_data = src.read_u32_le("LogonErrors::data")?;
        if cb_field > 8 {
            src.skip(cb_field - 8, "LogonErrors::extraPad")?;
        }
        Some(LogonErrorsInfo { error_notification_type, error_notification_data })
    } else {
        None
    };

    // 570-byte pad (always present)
    src.skip(LOGON_INFO_EXTENDED_PAD, "LogonExtended::pad")?;

    Ok(LogonInfoExtended { auto_reconnect_cookie, logon_errors })
}

// ── ArcCsPrivatePacket Encode/Decode (MS-RDPBCGR 2.2.4.3) ──

pub const ARC_CS_PRIVATE_PACKET_SIZE: usize = 28;

impl Encode for ArcCsPrivatePacket {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(ARC_PACKET_LEN, "ArcCs::cbLen")?;
        dst.write_u32_le(AUTO_RECONNECT_VERSION_1, "ArcCs::version")?;
        dst.write_u32_le(self.logon_id, "ArcCs::logonId")?;
        dst.write_slice(&self.security_verifier, "ArcCs::securityVerifier")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "ArcCsPrivatePacket" }
    fn size(&self) -> usize { ARC_CS_PRIVATE_PACKET_SIZE }
}

impl<'de> Decode<'de> for ArcCsPrivatePacket {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cb_len = src.read_u32_le("ArcCs::cbLen")?;
        if cb_len != ARC_PACKET_LEN {
            return Err(DecodeError::unexpected_value("ArcCsPrivatePacket", "cbLen", "must be 28"));
        }
        let version = src.read_u32_le("ArcCs::version")?;
        if version != AUTO_RECONNECT_VERSION_1 {
            return Err(DecodeError::unexpected_value("ArcCsPrivatePacket", "version", "must be 1"));
        }
        let logon_id = src.read_u32_le("ArcCs::logonId")?;
        let verifier_bytes = src.read_slice(16, "ArcCs::securityVerifier")?;
        let mut security_verifier = [0u8; 16];
        security_verifier.copy_from_slice(verifier_bytes);
        Ok(Self { logon_id, security_verifier })
    }
}

// ── Monitor Layout PDU ──

/// Monitor Layout PDU (2.2.12.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorLayoutPdu {
    pub monitors: Vec<MonitorLayoutEntry>,
}

/// TS_MONITOR_PRIMARY flag for [`MonitorLayoutEntry::flags`] (MS-RDPBCGR 2.2.1.3.6.1).
pub const TS_MONITOR_PRIMARY: u32 = 0x0000_0001;

/// Monitor layout entry — TS_MONITOR_DEF (MS-RDPBCGR 2.2.1.3.6.1).
///
/// Wire order: left(i32), top(i32), right(i32), bottom(i32), flags(u32).
/// Coordinates are inclusive bounding-box corners (right = left + width - 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorLayoutEntry {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub flags: u32,
}

impl Encode for MonitorLayoutPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // MS-RDPBCGR 2.2.12.1: defensive cap consistent with CS_MONITOR maximum
        if self.monitors.len() > 16 {
            return Err(EncodeError::invalid_value("MonitorLayoutPdu", "monitorCount"));
        }
        for m in &self.monitors {
            if m.right < m.left || m.bottom < m.top {
                return Err(EncodeError::invalid_value("MonitorLayoutEntry", "inverted bounding box"));
            }
        }
        dst.write_u32_le(self.monitors.len() as u32, "MonitorLayout::monitorCount")?;
        for m in &self.monitors {
            dst.write_i32_le(m.left, "MonitorLayout::left")?;
            dst.write_i32_le(m.top, "MonitorLayout::top")?;
            dst.write_i32_le(m.right, "MonitorLayout::right")?;
            dst.write_i32_le(m.bottom, "MonitorLayout::bottom")?;
            dst.write_u32_le(m.flags, "MonitorLayout::flags")?;
        }
        Ok(())
    }
    fn name(&self) -> &'static str { "MonitorLayoutPdu" }
    fn size(&self) -> usize { 4 + self.monitors.len() * 20 }
}

impl<'de> Decode<'de> for MonitorLayoutPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let count = src.read_u32_le("MonitorLayout::monitorCount")? as usize;
        // MS-RDPBCGR 2.2.12.1: practical limit consistent with ClientMonitorData
        if count > 16 {
            return Err(DecodeError::unexpected_value("MonitorLayoutPdu", "monitorCount", "exceeds maximum 16"));
        }
        let mut monitors = Vec::with_capacity(count);
        for _ in 0..count {
            let entry = MonitorLayoutEntry {
                left: src.read_i32_le("MonitorLayout::left")?,
                top: src.read_i32_le("MonitorLayout::top")?,
                right: src.read_i32_le("MonitorLayout::right")?,
                bottom: src.read_i32_le("MonitorLayout::bottom")?,
                flags: src.read_u32_le("MonitorLayout::flags")?,
            };
            // Reject inverted bounding boxes (right < left or bottom < top)
            if entry.right < entry.left || entry.bottom < entry.top {
                return Err(DecodeError::invalid_value("MonitorLayoutEntry", "inverted bounding box"));
            }
            monitors.push(entry);
        }
        Ok(Self { monitors })
    }
}

// ── Auto-Detect PDUs ──

/// Auto-Detect Request/Response header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoDetectPdu {
    pub header_length: u8,
    pub header_type_id: u8,
    pub sequence_number: u16,
    pub request_type: u16,
    pub payload: Vec<u8>,
}

impl Encode for AutoDetectPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(self.header_length, "AutoDetect::headerLength")?;
        dst.write_u8(self.header_type_id, "AutoDetect::headerTypeId")?;
        dst.write_u16_le(self.sequence_number, "AutoDetect::sequenceNumber")?;
        dst.write_u16_le(self.request_type, "AutoDetect::requestType")?;
        dst.write_slice(&self.payload, "AutoDetect::payload")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "AutoDetectPdu" }
    fn size(&self) -> usize { 6 + self.payload.len() }
}

impl<'de> Decode<'de> for AutoDetectPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header_length = src.read_u8("AutoDetect::headerLength")?;
        let header_type_id = src.read_u8("AutoDetect::headerTypeId")?;
        let sequence_number = src.read_u16_le("AutoDetect::sequenceNumber")?;
        let request_type = src.read_u16_le("AutoDetect::requestType")?;
        let payload_len = (header_length as usize).saturating_sub(6);
        let payload = if payload_len > 0 {
            src.read_slice(payload_len, "AutoDetect::payload")?.into()
        } else {
            Vec::new()
        };
        Ok(Self { header_length, header_type_id, sequence_number, request_type, payload })
    }
}

// ── Multitransport PDUs ──

/// Initiate Multitransport Request (2.2.15.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitiateMultitransportRequest {
    pub request_id: u32,
    pub request_protocol: u16,
    pub reserved: u16,
    pub security_cookie: [u8; 16],
}

pub const INITIATE_MULTITRANSPORT_SIZE: usize = 24;

impl Encode for InitiateMultitransportRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.request_id, "Multitransport::requestId")?;
        dst.write_u16_le(self.request_protocol, "Multitransport::requestProtocol")?;
        dst.write_u16_le(self.reserved, "Multitransport::reserved")?;
        dst.write_slice(&self.security_cookie, "Multitransport::securityCookie")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "InitiateMultitransportRequest" }
    fn size(&self) -> usize { INITIATE_MULTITRANSPORT_SIZE }
}

impl<'de> Decode<'de> for InitiateMultitransportRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let request_id = src.read_u32_le("Multitransport::requestId")?;
        let request_protocol = src.read_u16_le("Multitransport::requestProtocol")?;
        let reserved = src.read_u16_le("Multitransport::reserved")?;
        let cookie_bytes = src.read_slice(16, "Multitransport::securityCookie")?;
        let mut security_cookie = [0u8; 16];
        security_cookie.copy_from_slice(cookie_bytes);
        Ok(Self { request_id, request_protocol, reserved, security_cookie })
    }
}

/// Multitransport Response (2.2.15.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultitransportResponse {
    pub request_id: u32,
    pub hr_response: u32,
}

pub const MULTITRANSPORT_RESPONSE_SIZE: usize = 8;

impl Encode for MultitransportResponse {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.request_id, "MultitransportResp::requestId")?;
        dst.write_u32_le(self.hr_response, "MultitransportResp::hrResponse")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "MultitransportResponse" }
    fn size(&self) -> usize { MULTITRANSPORT_RESPONSE_SIZE }
}

impl<'de> Decode<'de> for MultitransportResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            request_id: src.read_u32_le("MultitransportResp::requestId")?,
            hr_response: src.read_u32_le("MultitransportResp::hrResponse")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn synchronize_pdu_roundtrip() {
        let pdu = SynchronizePdu { message_type: 1, target_user: 0x03EA };
        let mut buf = [0u8; SYNCHRONIZE_PDU_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(SynchronizePdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn control_pdu_roundtrip() {
        for action in [ControlAction::Cooperate, ControlAction::RequestControl, ControlAction::GrantedControl] {
            let pdu = ControlPdu { action, grant_id: 0, control_id: 0 };
            let mut buf = [0u8; CONTROL_PDU_SIZE];
            let mut cursor = WriteCursor::new(&mut buf);
            pdu.encode(&mut cursor).unwrap();
            let mut cursor = ReadCursor::new(&buf);
            assert_eq!(ControlPdu::decode(&mut cursor).unwrap(), pdu);
        }
    }

    #[test]
    fn font_list_roundtrip() {
        let pdu = FontListPdu::default_request();
        let mut buf = [0u8; FONT_LIST_PDU_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(FontListPdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn persistent_key_list_roundtrip() {
        let pdu = PersistentKeyListPdu {
            num_entries: [2, 0, 0, 0, 0],
            total_entries: [2, 0, 0, 0, 0],
            flags: 0x03, // first + last
            keys: vec![
                PersistentKeyEntry { key1: 0x1111, key2: 0x2222 },
                PersistentKeyEntry { key1: 0x3333, key2: 0x4444 },
            ],
        };
        let size = pdu.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(PersistentKeyListPdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn deactivate_all_roundtrip() {
        let pdu = DeactivateAllPdu { share_id: 0x00040006, length_source_descriptor: 0 };
        let mut buf = [0u8; DEACTIVATE_ALL_PDU_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(DeactivateAllPdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn set_error_info_roundtrip() {
        let pdu = SetErrorInfoPdu { error_info: ERRINFO_IDLE_TIMEOUT };
        let mut buf = [0u8; 4];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(SetErrorInfoPdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn is_error_info_retryable_classifies_user_actions_as_final() {
        // User / admin initiated disconnects: no retry.
        assert!(!is_error_info_retryable(ERRINFO_RPC_INITIATED_DISCONNECT));
        assert!(!is_error_info_retryable(ERRINFO_RPC_INITIATED_LOGOFF));
        assert!(!is_error_info_retryable(ERRINFO_DISCONNECTED_BY_OTHER));
        assert!(!is_error_info_retryable(ERRINFO_LOGOFF_BY_USER));
        assert!(!is_error_info_retryable(ERRINFO_RPC_INITIATED_DISCONNECT_BY_USER));
    }

    #[test]
    fn is_error_info_retryable_classifies_policy_denials_as_final() {
        assert!(!is_error_info_retryable(ERRINFO_SERVER_DENIED_CONNECTION));
        assert!(!is_error_info_retryable(ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES));
        assert!(!is_error_info_retryable(ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED));
    }

    #[test]
    fn is_error_info_retryable_classifies_transient_failures_as_retryable() {
        assert!(is_error_info_retryable(ERRINFO_NONE));
        assert!(is_error_info_retryable(ERRINFO_IDLE_TIMEOUT));
        assert!(is_error_info_retryable(ERRINFO_LOGON_TIMEOUT));
        assert!(is_error_info_retryable(ERRINFO_OUT_OF_MEMORY));
    }

    #[test]
    fn is_error_info_retryable_classifies_license_errors_as_final() {
        // 0x100C..=0x1015 range (licensing)
        assert!(!is_error_info_retryable(0x100C));
        assert!(!is_error_info_retryable(0x100D));
        assert!(!is_error_info_retryable(0x1010));
        assert!(!is_error_info_retryable(0x1015));
    }

    #[test]
    fn is_error_info_retryable_classifies_protocol_errors_as_retryable() {
        // 0x1000..=0x100B (encryption / decryption failures) are transient.
        assert!(is_error_info_retryable(0x1000));
        assert!(is_error_info_retryable(0x1005));
        assert!(is_error_info_retryable(0x100B));
    }

    #[test]
    fn is_error_info_retryable_classifies_connection_broker_as_final() {
        // 0x0400..=0x040F (Connection Broker / redirection codes)
        // should trigger a redirect path, not a plain retry loop.
        assert!(!is_error_info_retryable(0x0400));
        assert!(!is_error_info_retryable(0x0408));
        assert!(!is_error_info_retryable(0x040F));
    }

    #[test]
    fn is_error_info_retryable_unknown_codes_default_to_retryable() {
        // Future codes are treated as transient — fail open. If the
        // server keeps emitting the same unknown code, the reconnect
        // policy's max_attempts cap bounds the retry loop.
        assert!(is_error_info_retryable(0xDEAD_BEEF));
        assert!(is_error_info_retryable(0x9999));
    }

    #[test]
    fn suppress_output_allow_roundtrip() {
        let pdu = SuppressOutputPdu {
            allow_display_updates: 1,
            left: Some(0), top: Some(0), right: Some(1919), bottom: Some(1079),
        };
        let size = pdu.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(SuppressOutputPdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn suppress_output_suppress_roundtrip() {
        let pdu = SuppressOutputPdu {
            allow_display_updates: 0,
            left: None, top: None, right: None, bottom: None,
        };
        let size = pdu.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(SuppressOutputPdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn play_sound_roundtrip() {
        let pdu = PlaySoundPdu {
            duration_ms: 250,
            frequency_hz: 880,
        };
        let size = pdu.size();
        assert_eq!(size, 8);
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        // Wire format: <duration LE u32><frequency LE u32>
        assert_eq!(buf, [0xFA, 0x00, 0x00, 0x00, 0x70, 0x03, 0x00, 0x00]);
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(PlaySoundPdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn play_sound_zero_values_roundtrip() {
        let pdu = PlaySoundPdu {
            duration_ms: 0,
            frequency_hz: 0,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(PlaySoundPdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn refresh_rect_roundtrip() {
        let pdu = RefreshRectPdu {
            areas: vec![InclusiveRect { left: 0, top: 0, right: 100, bottom: 100 }],
        };
        let size = pdu.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(RefreshRectPdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn multitransport_request_roundtrip() {
        let pdu = InitiateMultitransportRequest {
            request_id: 1, request_protocol: 0x0001, reserved: 0,
            security_cookie: [0xAA; 16],
        };
        let mut buf = [0u8; INITIATE_MULTITRANSPORT_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(InitiateMultitransportRequest::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn multitransport_response_roundtrip() {
        let pdu = MultitransportResponse { request_id: 1, hr_response: 0 };
        let mut buf = [0u8; MULTITRANSPORT_RESPONSE_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(MultitransportResponse::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn auto_detect_roundtrip() {
        let pdu = AutoDetectPdu {
            header_length: 6, header_type_id: 0x00,
            sequence_number: 1, request_type: 0x0001, payload: Vec::new(),
        };
        let size = pdu.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(AutoDetectPdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn monitor_layout_roundtrip() {
        let pdu = MonitorLayoutPdu {
            monitors: vec![MonitorLayoutEntry { left: 0, top: 0, right: 1919, bottom: 1079, flags: 1 }],
        };
        let size = pdu.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(MonitorLayoutPdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn monitor_layout_negative_coordinates() {
        // Secondary monitor to the left of primary: left=-1920, right=-1
        let pdu = MonitorLayoutPdu {
            monitors: vec![
                MonitorLayoutEntry { left: 0, top: 0, right: 1919, bottom: 1079, flags: 1 },
                MonitorLayoutEntry { left: -1920, top: 0, right: -1, bottom: 1079, flags: 0 },
            ],
        };
        let size = pdu.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        let decoded = MonitorLayoutPdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(decoded.monitors[1].left, -1920);
        assert_eq!(decoded.monitors[1].right, -1);
    }

    #[test]
    fn monitor_layout_empty() {
        let pdu = MonitorLayoutPdu { monitors: vec![] };
        assert_eq!(pdu.size(), 4);
        let mut buf = vec![0u8; 4];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        let decoded = MonitorLayoutPdu::decode(&mut cursor).unwrap();
        assert!(decoded.monitors.is_empty());
    }

    #[test]
    fn monitor_layout_roundtrip_max_monitors() {
        // 16 monitors (accept boundary): total size = 4 + 16*20 = 324 bytes
        let monitors: Vec<MonitorLayoutEntry> = (0..16i32)
            .map(|i| MonitorLayoutEntry {
                left: i * 1920,
                top: 0,
                right: (i + 1) * 1920 - 1,
                bottom: 1079,
                flags: if i == 0 { 1 } else { 0 },
            })
            .collect();
        let pdu = MonitorLayoutPdu { monitors };
        assert_eq!(pdu.size(), 4 + 16 * 20);
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        let decoded = MonitorLayoutPdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded.monitors.len(), 16);
        assert_eq!(decoded.monitors[0].flags, 1);
        assert_eq!(decoded.monitors[15].left, 15 * 1920);
    }

    #[test]
    fn monitor_layout_rejects_too_many_monitors() {
        // Hand-craft wire bytes with monitorCount=17
        let mut buf = vec![0u8; 4];
        buf[0] = 17; // monitorCount = 17 (LE)
        let mut cursor = ReadCursor::new(&buf);
        assert!(MonitorLayoutPdu::decode(&mut cursor).is_err());
    }

    #[test]
    fn monitor_layout_encode_rejects_inverted_bounding_box() {
        let pdu = MonitorLayoutPdu {
            monitors: vec![MonitorLayoutEntry { left: 100, top: 0, right: 0, bottom: 1079, flags: 1 }],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        assert!(pdu.encode(&mut cursor).is_err());
    }

    #[test]
    fn monitor_layout_decode_rejects_inverted_bounding_box() {
        // Hand-craft wire bytes: monitorCount=1, left=100, top=0, right=0, bottom=1079, flags=1
        let mut buf = vec![0u8; 24];
        let mut cursor = WriteCursor::new(&mut buf);
        cursor.write_u32_le(1, "mc").unwrap(); // monitorCount
        cursor.write_i32_le(100, "left").unwrap();
        cursor.write_i32_le(0, "top").unwrap();
        cursor.write_i32_le(0, "right").unwrap(); // right < left → inverted
        cursor.write_i32_le(1079, "bottom").unwrap();
        cursor.write_u32_le(1, "flags").unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert!(MonitorLayoutPdu::decode(&mut cursor).is_err());
    }

    #[test]
    fn control_action_unknown() {
        assert!(ControlAction::from_u16(0xFFFF).is_err());
    }

    #[test]
    fn control_pdu_detach_roundtrip() {
        let pdu = ControlPdu { action: ControlAction::Detach, grant_id: 0, control_id: 0 };
        let mut buf = [0u8; CONTROL_PDU_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(ControlPdu::decode(&mut cursor).unwrap().action, ControlAction::Detach);
    }

    #[test]
    fn persistent_key_list_zero_keys() {
        let pdu = PersistentKeyListPdu {
            num_entries: [0; 5],
            total_entries: [0; 5],
            flags: 0x03, // FIRST | LAST
            keys: alloc::vec![],
        };
        let size = pdu.size();
        assert_eq!(size, PERSISTENT_KEY_LIST_HEADER_SIZE);
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        let decoded = PersistentKeyListPdu::decode(&mut cursor).unwrap();
        assert!(decoded.keys.is_empty());
    }

    // ── Derive macro test ──

    #[derive(Debug, Clone, PartialEq, Eq, crate::DeriveEncode, crate::DeriveDecode)]
    struct DeriveTestPdu {
        #[pdu(u16_le)]
        field_a: u16,
        #[pdu(u32_le)]
        field_b: u32,
        #[pdu(u8)]
        field_c: u8,
    }

    #[test]
    fn derive_encode_decode_roundtrip() {
        let pdu = DeriveTestPdu { field_a: 0x1234, field_b: 0xDEADBEEF, field_c: 0x42 };
        assert_eq!(pdu.size(), 7); // 2 + 4 + 1

        let mut buf = [0u8; 7];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        // Check wire format
        assert_eq!(buf[0..2], [0x34, 0x12]); // u16 LE
        assert_eq!(buf[2..6], [0xEF, 0xBE, 0xAD, 0xDE]); // u32 LE
        assert_eq!(buf[6], 0x42); // u8

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeriveTestPdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[derive(Debug, Clone, PartialEq, Eq, crate::DeriveEncode, crate::DeriveDecode)]
    struct DeriveTestBytes {
        #[pdu(u8)]
        tag: u8,
        #[pdu(bytes = 4)]
        data: [u8; 4],
    }

    #[test]
    fn derive_bytes_roundtrip() {
        let pdu = DeriveTestBytes { tag: 0xFF, data: [1, 2, 3, 4] };
        assert_eq!(pdu.size(), 5);

        let mut buf = [0u8; 5];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeriveTestBytes::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[derive(Debug, Clone, PartialEq, Eq, crate::DeriveEncode, crate::DeriveDecode)]
    struct DeriveTestRest {
        #[pdu(u16_le)]
        header: u16,
        #[pdu(rest)]
        payload: Vec<u8>,
    }

    #[test]
    fn derive_rest_roundtrip() {
        let pdu = DeriveTestRest { header: 0xABCD, payload: vec![1, 2, 3, 4, 5] };
        assert_eq!(pdu.size(), 7); // 2 + 5

        let mut buf = vec![0u8; 7];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeriveTestRest::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn derive_rest_empty_payload() {
        let pdu = DeriveTestRest { header: 0x0000, payload: vec![] };
        assert_eq!(pdu.size(), 2);

        let mut buf = [0u8; 2];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeriveTestRest::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
        assert!(decoded.payload.is_empty());
    }

    // ── Pad test ──

    #[derive(Debug, Clone, PartialEq, Eq, crate::DeriveEncode, crate::DeriveDecode)]
    struct DeriveTestPad {
        #[pdu(u8)]
        tag: u8,
        #[pdu(pad = 3)]
        _reserved: (),
        #[pdu(u8)]
        value: u8,
    }

    #[test]
    fn derive_pad_encode_decode() {
        let pdu = DeriveTestPad { tag: 0x01, _reserved: (), value: 0x02 };
        assert_eq!(pdu.size(), 5); // 1 + 3 + 1

        let mut buf = [0u8; 5];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        assert_eq!(&buf[1..4], &[0x00, 0x00, 0x00]); // pad bytes are zero

        // Non-zero bytes in pad position are silently skipped on decode
        buf[1] = 0xFF; buf[2] = 0xFF; buf[3] = 0xFF;
        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeriveTestPad::decode(&mut cursor).unwrap();
        assert_eq!(decoded.tag, 0x01);
        assert_eq!(decoded.value, 0x02);
    }

    // ── Big-endian test ──

    #[derive(Debug, Clone, PartialEq, Eq, crate::DeriveEncode, crate::DeriveDecode)]
    struct DeriveTestBe {
        #[pdu(u16_be)]
        a: u16,
        #[pdu(u32_be)]
        b: u32,
    }

    #[test]
    fn derive_be_wire_order() {
        let pdu = DeriveTestBe { a: 0x1234, b: 0xDEADBEEF };
        assert_eq!(pdu.size(), 6);

        let mut buf = [0u8; 6];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        assert_eq!(&buf[0..2], &[0x12, 0x34]); // big-endian MSB first
        assert_eq!(&buf[2..6], &[0xDE, 0xAD, 0xBE, 0xEF]);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeriveTestBe::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }

    // ── Signed integer test ──

    #[derive(Debug, Clone, PartialEq, Eq, crate::DeriveEncode, crate::DeriveDecode)]
    struct DeriveTestSigned {
        #[pdu(i16_le)]
        a: i16,
        #[pdu(i32_le)]
        b: i32,
    }

    #[test]
    fn derive_signed_negative_roundtrip() {
        let pdu = DeriveTestSigned { a: -1, b: -2147483648 }; // -1, i32::MIN
        assert_eq!(pdu.size(), 6);

        let mut buf = [0u8; 6];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        assert_eq!(&buf[0..2], &[0xFF, 0xFF]); // -1 as i16 LE
        assert_eq!(&buf[2..6], &[0x00, 0x00, 0x00, 0x80]); // i32::MIN LE

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeriveTestSigned::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }

    // ── u64 test ──

    #[derive(Debug, Clone, PartialEq, Eq, crate::DeriveEncode, crate::DeriveDecode)]
    struct DeriveTestU64 {
        #[pdu(u64_le)]
        val: u64,
    }

    #[test]
    fn derive_u64_roundtrip() {
        let pdu = DeriveTestU64 { val: 0xDEADBEEF_CAFEBABE };
        assert_eq!(pdu.size(), 8);

        let mut buf = [0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeriveTestU64::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }

    // ── Truncated input test ──

    #[test]
    fn derive_truncated_input_returns_error() {
        let buf = [0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE]; // 6 bytes, needs 7
        let mut cursor = ReadCursor::new(&buf);
        assert!(DeriveTestPdu::decode(&mut cursor).is_err());
    }

    // ── Save Session Info PDU tests ──

    #[test]
    fn save_session_info_plain_notify_roundtrip() {
        let pdu = SaveSessionInfoPdu {
            info_data: SaveSessionInfoData::PlainNotify,
        };
        assert_eq!(pdu.size(), 4 + 576); // infoType + 576 pad
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        let decoded = SaveSessionInfoPdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded.info_data, SaveSessionInfoData::PlainNotify);
    }

    #[test]
    fn save_session_info_logon_v1_roundtrip() {
        let pdu = SaveSessionInfoPdu {
            info_data: SaveSessionInfoData::LogonV1(LogonInfoV1 {
                domain: b"TEST\0\0".to_vec(), // 6 bytes (UTF-16LE "TE" + null + pad)
                user_name: b"admin\0".to_vec(),
                session_id: 42,
            }),
        };
        assert_eq!(pdu.size(), 4 + 576);
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        let decoded = SaveSessionInfoPdu::decode(&mut cursor).unwrap();
        match decoded.info_data {
            SaveSessionInfoData::LogonV1(v1) => {
                assert_eq!(v1.domain, b"TEST\0\0");
                assert_eq!(v1.user_name, b"admin\0");
                assert_eq!(v1.session_id, 42);
            }
            _ => panic!("expected LogonV1"),
        }
    }

    #[test]
    fn save_session_info_logon_v2_roundtrip() {
        let domain = b"DOMAIN\0\0".to_vec();
        let user = b"user\0\0".to_vec();
        let pdu = SaveSessionInfoPdu {
            info_data: SaveSessionInfoData::LogonV2(LogonInfoV2 {
                session_id: 99,
                domain: domain.clone(),
                user_name: user.clone(),
            }),
        };
        assert_eq!(pdu.size(), 4 + 576 + domain.len() + user.len());
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        let decoded = SaveSessionInfoPdu::decode(&mut cursor).unwrap();
        match decoded.info_data {
            SaveSessionInfoData::LogonV2(v2) => {
                assert_eq!(v2.session_id, 99);
                assert_eq!(v2.domain, domain);
                assert_eq!(v2.user_name, user);
            }
            _ => panic!("expected LogonV2"),
        }
    }

    #[test]
    fn save_session_info_extended_with_arc_roundtrip() {
        let arc = ArcScPrivatePacket {
            logon_id: 0x1234,
            arc_random_bits: [0xAA; 16],
        };
        let pdu = SaveSessionInfoPdu {
            info_data: SaveSessionInfoData::Extended(LogonInfoExtended {
                auto_reconnect_cookie: Some(arc),
                logon_errors: None,
            }),
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        let decoded = SaveSessionInfoPdu::decode(&mut cursor).unwrap();
        match decoded.info_data {
            SaveSessionInfoData::Extended(ext) => {
                let cookie = ext.auto_reconnect_cookie.unwrap();
                assert_eq!(cookie.logon_id, 0x1234);
                assert_eq!(cookie.arc_random_bits, [0xAA; 16]);
                assert!(ext.logon_errors.is_none());
            }
            _ => panic!("expected Extended"),
        }
    }

    #[test]
    fn save_session_info_extended_with_logon_errors_roundtrip() {
        let pdu = SaveSessionInfoPdu {
            info_data: SaveSessionInfoData::Extended(LogonInfoExtended {
                auto_reconnect_cookie: None,
                logon_errors: Some(LogonErrorsInfo {
                    error_notification_type: 0x01,
                    error_notification_data: 0x02,
                }),
            }),
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        let decoded = SaveSessionInfoPdu::decode(&mut cursor).unwrap();
        match decoded.info_data {
            SaveSessionInfoData::Extended(ext) => {
                assert!(ext.auto_reconnect_cookie.is_none());
                let errors = ext.logon_errors.unwrap();
                assert_eq!(errors.error_notification_type, 0x01);
                assert_eq!(errors.error_notification_data, 0x02);
            }
            _ => panic!("expected Extended"),
        }
    }

    #[test]
    fn save_session_info_extended_both_fields_roundtrip() {
        let pdu = SaveSessionInfoPdu {
            info_data: SaveSessionInfoData::Extended(LogonInfoExtended {
                auto_reconnect_cookie: Some(ArcScPrivatePacket {
                    logon_id: 7,
                    arc_random_bits: [0xBB; 16],
                }),
                logon_errors: Some(LogonErrorsInfo {
                    error_notification_type: 0x10,
                    error_notification_data: 0x20,
                }),
            }),
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        let decoded = SaveSessionInfoPdu::decode(&mut cursor).unwrap();
        match decoded.info_data {
            SaveSessionInfoData::Extended(ext) => {
                assert_eq!(ext.auto_reconnect_cookie.unwrap().logon_id, 7);
                assert_eq!(ext.logon_errors.unwrap().error_notification_type, 0x10);
            }
            _ => panic!("expected Extended"),
        }
    }

    #[test]
    fn save_session_info_unknown_info_type_rejected() {
        let mut buf = vec![0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        cursor.write_u32_le(0xFF, "it").unwrap(); // invalid infoType
        let mut cursor = ReadCursor::new(&buf);
        assert!(SaveSessionInfoPdu::decode(&mut cursor).is_err());
    }

    // ── ArcCsPrivatePacket tests ──

    #[test]
    fn arc_cs_private_packet_roundtrip() {
        let pkt = ArcCsPrivatePacket {
            logon_id: 0x1234_5678,
            security_verifier: [0xAB; 16],
        };
        assert_eq!(pkt.size(), 28);
        let mut buf = [0u8; 28];
        let mut cursor = WriteCursor::new(&mut buf);
        pkt.encode(&mut cursor).unwrap();

        // Verify wire format
        assert_eq!(&buf[0..4], &0x1Cu32.to_le_bytes()); // cbLen = 28
        assert_eq!(&buf[4..8], &1u32.to_le_bytes()); // version = 1
        assert_eq!(&buf[8..12], &0x1234_5678u32.to_le_bytes()); // logonId
        assert_eq!(&buf[12..28], &[0xAB; 16]); // securityVerifier

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ArcCsPrivatePacket::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn arc_cs_private_packet_rejects_bad_cblen() {
        let mut buf = [0u8; 28];
        let mut cursor = WriteCursor::new(&mut buf);
        cursor.write_u32_le(0x20, "cbLen").unwrap(); // wrong cbLen
        cursor.write_u32_le(1, "ver").unwrap();
        cursor.write_u32_le(0, "id").unwrap();
        cursor.write_slice(&[0u8; 16], "sv").unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert!(ArcCsPrivatePacket::decode(&mut cursor).is_err());
    }

    #[test]
    fn arc_cs_private_packet_rejects_bad_version() {
        let mut buf = [0u8; 28];
        let mut cursor = WriteCursor::new(&mut buf);
        cursor.write_u32_le(0x1C, "cbLen").unwrap();
        cursor.write_u32_le(2, "ver").unwrap(); // wrong version
        cursor.write_u32_le(0, "id").unwrap();
        cursor.write_slice(&[0u8; 16], "sv").unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert!(ArcCsPrivatePacket::decode(&mut cursor).is_err());
    }

    #[test]
    fn arc_sc_decode_rejects_bad_cblen() {
        // Build a LogonInfoExtended with ARC that has wrong cbLen
        let mut buf = vec![0u8; 4 + 2 + 4 + 4 + 28 + 570]; // infoType + Length + FieldsPresent + cbFieldData + ARC + pad
        let mut cursor = WriteCursor::new(&mut buf);
        cursor.write_u32_le(INFOTYPE_LOGON_EXTENDED_INFO, "it").unwrap();
        cursor.write_u16_le(38, "len").unwrap(); // Length = 2 + 4 + (4 + 28) = 38
        cursor.write_u32_le(LOGON_EX_AUTORECONNECTCOOKIE, "fp").unwrap();
        cursor.write_u32_le(28, "cbField").unwrap();
        cursor.write_u32_le(0xFF, "cbLen").unwrap(); // BAD cbLen
        // rest doesn't matter — should fail before reading further
        let mut cursor = ReadCursor::new(&buf);
        assert!(SaveSessionInfoPdu::decode(&mut cursor).is_err());
    }

    #[test]
    fn logon_v2_rejects_bad_version() {
        let mut buf = vec![0u8; 4 + 576]; // infoType + fixed V2 portion (no variable)
        let mut cursor = WriteCursor::new(&mut buf);
        cursor.write_u32_le(INFOTYPE_LOGON_LONG, "it").unwrap();
        cursor.write_u16_le(0x0002, "ver").unwrap(); // BAD version
        let mut cursor = ReadCursor::new(&buf);
        assert!(SaveSessionInfoPdu::decode(&mut cursor).is_err());
    }

    #[test]
    fn logon_v1_wire_format_session_id_at_correct_offset() {
        // Verify SessionId is at byte offset 4(cbDomain) + 52(Domain) + 4(cbUserName) + 512(UserName) = 572
        // relative to info_data start (after infoType).
        let pdu = SaveSessionInfoPdu {
            info_data: SaveSessionInfoData::LogonV1(LogonInfoV1 {
                domain: vec![],
                user_name: vec![],
                session_id: 0xDEADBEEF,
            }),
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        // infoType(4) + cbDomain(4) + Domain(52) + cbUserName(4) + UserName(512) = offset 576
        // SessionId starts at offset 576
        let session_id_offset = 4 + 4 + 52 + 4 + 512;
        let session_id = u32::from_le_bytes([
            buf[session_id_offset], buf[session_id_offset + 1],
            buf[session_id_offset + 2], buf[session_id_offset + 3],
        ]);
        assert_eq!(session_id, 0xDEADBEEF);
    }

    #[test]
    fn arc_cs_wire_format_byte_level() {
        let pkt = ArcCsPrivatePacket {
            logon_id: 0x1234_5678,
            security_verifier: [0xAB; 16],
        };
        let mut buf = [0u8; 28];
        let mut cursor = WriteCursor::new(&mut buf);
        pkt.encode(&mut cursor).unwrap();

        // cbLen at offset 0
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 28);
        // Version at offset 4
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 1);
        // LogonId at offset 8
        assert_eq!(u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]), 0x1234_5678);
        // SecurityVerifier at offset 12
        assert_eq!(&buf[12..28], &[0xAB; 16]);
    }

    #[test]
    fn save_session_info_data_arc_random_extracts_cookie() {
        let pdu = SaveSessionInfoData::Extended(LogonInfoExtended {
            auto_reconnect_cookie: Some(ArcScPrivatePacket {
                logon_id: 0x55,
                arc_random_bits: [0x77; 16],
            }),
            logon_errors: None,
        });
        let extracted = pdu.arc_random();
        assert_eq!(extracted, Some((0x55, [0x77; 16])));

        // PlainNotify and LogonV1 must return None.
        assert_eq!(SaveSessionInfoData::PlainNotify.arc_random(), None);
        assert_eq!(
            SaveSessionInfoData::LogonV1(LogonInfoV1 {
                domain: vec![], user_name: vec![], session_id: 0,
            }).arc_random(),
            None,
        );

        // Extended without ARC must return None.
        let no_arc = SaveSessionInfoData::Extended(LogonInfoExtended {
            auto_reconnect_cookie: None,
            logon_errors: None,
        });
        assert_eq!(no_arc.arc_random(), None);
    }

    #[test]
    fn logon_extended_empty_fields_roundtrip() {
        // FieldsPresent = 0: no logon fields, just 570-byte pad
        let pdu = SaveSessionInfoPdu {
            info_data: SaveSessionInfoData::Extended(LogonInfoExtended {
                auto_reconnect_cookie: None,
                logon_errors: None,
            }),
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        let decoded = SaveSessionInfoPdu::decode(&mut cursor).unwrap();
        match decoded.info_data {
            SaveSessionInfoData::Extended(ext) => {
                assert!(ext.auto_reconnect_cookie.is_none());
                assert!(ext.logon_errors.is_none());
            }
            _ => panic!("expected Extended"),
        }
    }
}
