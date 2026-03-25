#![forbid(unsafe_code)]

//! Connection Finalization and Session PDUs -- MS-RDPBCGR 2.2.1.13+
//!
//! These PDUs are exchanged after Demand Active / Confirm Active to finalize
//! the RDP connection, plus active session data PDUs.

use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

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

/// Common error codes.
pub const ERRINFO_NONE: u32 = 0x0000_0000;
pub const ERRINFO_RPC_INITIATED_DISCONNECT: u32 = 0x0000_0001;
pub const ERRINFO_RPC_INITIATED_LOGOFF: u32 = 0x0000_0002;
pub const ERRINFO_IDLE_TIMEOUT: u32 = 0x0000_0003;
pub const ERRINFO_LOGON_TIMEOUT: u32 = 0x0000_0004;
pub const ERRINFO_DISCONNECTED_BY_OTHER: u32 = 0x0000_0005;

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

// ── Save Session Info PDU ──

/// Save Session Info PDU (2.2.10.1) -- stored as raw data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveSessionInfoPdu {
    pub info_type: u32,
    pub info_data: Vec<u8>,
}

impl Encode for SaveSessionInfoPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.info_type, "SaveSessionInfo::infoType")?;
        dst.write_slice(&self.info_data, "SaveSessionInfo::infoData")?;
        Ok(())
    }
    fn name(&self) -> &'static str { "SaveSessionInfoPdu" }
    fn size(&self) -> usize { 4 + self.info_data.len() }
}

impl<'de> Decode<'de> for SaveSessionInfoPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let info_type = src.read_u32_le("SaveSessionInfo::infoType")?;
        let info_data = src.peek_remaining().to_vec();
        src.skip(info_data.len(), "SaveSessionInfo::infoData")?;
        Ok(Self { info_type, info_data })
    }
}

// ── Monitor Layout PDU ──

/// Monitor Layout PDU (2.2.12.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorLayoutPdu {
    pub monitors: Vec<MonitorLayoutEntry>,
}

/// Monitor layout entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorLayoutEntry {
    pub flags: u32,
    pub left: u32,
    pub top: u32,
    pub width: u32,
    pub height: u32,
}

impl Encode for MonitorLayoutPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.monitors.len() as u32, "MonitorLayout::monitorCount")?;
        for m in &self.monitors {
            dst.write_u32_le(m.flags, "MonitorLayout::flags")?;
            dst.write_u32_le(m.left, "MonitorLayout::left")?;
            dst.write_u32_le(m.top, "MonitorLayout::top")?;
            dst.write_u32_le(m.width, "MonitorLayout::width")?;
            dst.write_u32_le(m.height, "MonitorLayout::height")?;
        }
        Ok(())
    }
    fn name(&self) -> &'static str { "MonitorLayoutPdu" }
    fn size(&self) -> usize { 4 + self.monitors.len() * 20 }
}

impl<'de> Decode<'de> for MonitorLayoutPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let count = src.read_u32_le("MonitorLayout::monitorCount")? as usize;
        let mut monitors = Vec::with_capacity(count);
        for _ in 0..count {
            monitors.push(MonitorLayoutEntry {
                flags: src.read_u32_le("MonitorLayout::flags")?,
                left: src.read_u32_le("MonitorLayout::left")?,
                top: src.read_u32_le("MonitorLayout::top")?,
                width: src.read_u32_le("MonitorLayout::width")?,
                height: src.read_u32_le("MonitorLayout::height")?,
            });
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
            monitors: vec![MonitorLayoutEntry { flags: 1, left: 0, top: 0, width: 1920, height: 1080 }],
        };
        let size = pdu.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(MonitorLayoutPdu::decode(&mut cursor).unwrap(), pdu);
    }

    #[test]
    fn control_action_unknown() {
        assert!(ControlAction::from_u16(0xFFFF).is_err());
    }
}
