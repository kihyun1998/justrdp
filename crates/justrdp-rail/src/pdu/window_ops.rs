#![forbid(unsafe_code)]

//! Window operation PDUs -- MS-RDPERP 2.2.2.6, 2.2.2.7

use justrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use super::header::{RailHeader, RailOrderType, RAIL_HEADER_SIZE};

// ── System command constants -- MS-RDPERP 2.2.2.6.3 ──

pub const SC_SIZE: u16 = 0xF000;
pub const SC_MOVE: u16 = 0xF010;
pub const SC_MINIMIZE: u16 = 0xF020;
pub const SC_MAXIMIZE: u16 = 0xF030;
pub const SC_CLOSE: u16 = 0xF060;
pub const SC_KEYMENU: u16 = 0xF100;
pub const SC_RESTORE: u16 = 0xF120;
pub const SC_DEFAULT: u16 = 0xF160;

// ── Move/size type constants -- MS-RDPERP 2.2.2.7.1 ──

pub const RAIL_WMSZ_LEFT: u16 = 0x0001;
pub const RAIL_WMSZ_RIGHT: u16 = 0x0002;
pub const RAIL_WMSZ_TOP: u16 = 0x0003;
pub const RAIL_WMSZ_TOPLEFT: u16 = 0x0004;
pub const RAIL_WMSZ_TOPRIGHT: u16 = 0x0005;
pub const RAIL_WMSZ_BOTTOM: u16 = 0x0006;
pub const RAIL_WMSZ_BOTTOMLEFT: u16 = 0x0007;
pub const RAIL_WMSZ_BOTTOMRIGHT: u16 = 0x0008;
pub const RAIL_WMSZ_MOVE: u16 = 0x0009;
pub const RAIL_WMSZ_KEYMOVE: u16 = 0x000A;
pub const RAIL_WMSZ_KEYSIZE: u16 = 0x000B;

// ── Notify event message constants -- MS-RDPERP 2.2.2.6.4 ──

pub const WM_LBUTTONDOWN: u32 = 0x0000_0201;
pub const WM_LBUTTONUP: u32 = 0x0000_0202;
pub const WM_RBUTTONDOWN: u32 = 0x0000_0204;
pub const WM_RBUTTONUP: u32 = 0x0000_0205;
pub const WM_CONTEXTMENU: u32 = 0x0000_007B;
pub const NIN_SELECT: u32 = 0x0000_0400;
pub const NIN_KEYSELECT: u32 = 0x0000_0401;
pub const NIN_BALLOONSHOW: u32 = 0x0000_0402;
pub const NIN_BALLOONHIDE: u32 = 0x0000_0403;
pub const NIN_BALLOONTIMEOUT: u32 = 0x0000_0404;
pub const NIN_BALLOONUSERCLICK: u32 = 0x0000_0405;

/// Client Activate PDU -- MS-RDPERP 2.2.2.6.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivatePdu {
    pub window_id: u32,
    pub enabled: bool,
}

impl ActivatePdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4 + 1;

    pub fn new(window_id: u32, enabled: bool) -> Self {
        Self { window_id, enabled }
    }
}

impl Encode for ActivatePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::Activate, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.window_id, "Activate::WindowId")?;
        dst.write_u8(u8::from(self.enabled), "Activate::Enabled")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ActivatePdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for ActivatePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let window_id = src.read_u32_le("Activate::WindowId")?;
        let enabled = src.read_u8("Activate::Enabled")? != 0;
        Ok(Self { window_id, enabled })
    }
}

/// Client System Menu PDU -- MS-RDPERP 2.2.2.6.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysMenuPdu {
    pub window_id: u32,
    pub left: i16,
    pub top: i16,
}

impl SysMenuPdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4 + 2 + 2;

    pub fn new(window_id: u32, left: i16, top: i16) -> Self {
        Self {
            window_id,
            left,
            top,
        }
    }
}

impl Encode for SysMenuPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::SysMenu, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.window_id, "SysMenu::WindowId")?;
        dst.write_i16_le(self.left, "SysMenu::Left")?;
        dst.write_i16_le(self.top, "SysMenu::Top")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SysMenuPdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for SysMenuPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let window_id = src.read_u32_le("SysMenu::WindowId")?;
        let left = src.read_i16_le("SysMenu::Left")?;
        let top = src.read_i16_le("SysMenu::Top")?;
        Ok(Self {
            window_id,
            left,
            top,
        })
    }
}

/// Client System Command PDU -- MS-RDPERP 2.2.2.6.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysCommandPdu {
    pub window_id: u32,
    pub command: u16,
}

impl SysCommandPdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4 + 2;

    pub fn new(window_id: u32, command: u16) -> Self {
        Self { window_id, command }
    }
}

impl Encode for SysCommandPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::SysCommand, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.window_id, "SysCommand::WindowId")?;
        dst.write_u16_le(self.command, "SysCommand::Command")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SysCommandPdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for SysCommandPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let window_id = src.read_u32_le("SysCommand::WindowId")?;
        let command = src.read_u16_le("SysCommand::Command")?;
        Ok(Self { window_id, command })
    }
}

/// Client Notify Event PDU -- MS-RDPERP 2.2.2.6.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyEventPdu {
    pub window_id: u32,
    pub notify_icon_id: u32,
    pub message: u32,
}

impl NotifyEventPdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4 + 4 + 4;

    pub fn new(window_id: u32, notify_icon_id: u32, message: u32) -> Self {
        Self {
            window_id,
            notify_icon_id,
            message,
        }
    }
}

impl Encode for NotifyEventPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::NotifyEvent, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.window_id, "NotifyEvent::WindowId")?;
        dst.write_u32_le(self.notify_icon_id, "NotifyEvent::NotifyIconId")?;
        dst.write_u32_le(self.message, "NotifyEvent::Message")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "NotifyEventPdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for NotifyEventPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let window_id = src.read_u32_le("NotifyEvent::WindowId")?;
        let notify_icon_id = src.read_u32_le("NotifyEvent::NotifyIconId")?;
        let message = src.read_u32_le("NotifyEvent::Message")?;
        Ok(Self {
            window_id,
            notify_icon_id,
            message,
        })
    }
}

/// Client Get Application ID PDU -- MS-RDPERP 2.2.2.6.5
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAppIdReqPdu {
    pub window_id: u32,
}

impl GetAppIdReqPdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4;

    pub fn new(window_id: u32) -> Self {
        Self { window_id }
    }
}

impl Encode for GetAppIdReqPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::GetAppIdReq, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.window_id, "GetAppIdReq::WindowId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "GetAppIdReqPdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for GetAppIdReqPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let window_id = src.read_u32_le("GetAppIdReq::WindowId")?;
        Ok(Self { window_id })
    }
}

/// Server Get Application ID Response PDU -- MS-RDPERP 2.2.2.8.1
///
/// `ApplicationId` is a fixed 520-byte field (null-terminated UTF-16LE, zero-padded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAppIdRespPdu {
    pub window_id: u32,
    /// Null-terminated UTF-16LE, always 520 bytes on the wire.
    pub application_id: [u8; 520],
}

impl GetAppIdRespPdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4 + 520;

    pub fn new(window_id: u32, application_id: [u8; 520]) -> Self {
        Self {
            window_id,
            application_id,
        }
    }
}

impl Encode for GetAppIdRespPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::GetAppIdResp, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.window_id, "GetAppIdResp::WindowId")?;
        dst.write_slice(&self.application_id, "GetAppIdResp::ApplicationId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "GetAppIdRespPdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for GetAppIdRespPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let window_id = src.read_u32_le("GetAppIdResp::WindowId")?;
        let slice = src.read_slice(520, "GetAppIdResp::ApplicationId")?;
        let mut application_id = [0u8; 520];
        application_id.copy_from_slice(slice);
        Ok(Self {
            window_id,
            application_id,
        })
    }
}

/// Server Move/Size Start/End PDU -- MS-RDPERP 2.2.2.7.1 / 2.2.2.7.3
///
/// Both use `orderType = 0x0009`; distinguished by `is_move_size_start`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMoveSizePdu {
    pub window_id: u32,
    pub is_move_size_start: bool,
    pub move_size_type: u16,
    pub pos_x: i16,
    pub pos_y: i16,
}

impl LocalMoveSizePdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4 + 2 + 2 + 2 + 2;

    pub fn new(
        window_id: u32,
        is_move_size_start: bool,
        move_size_type: u16,
        pos_x: i16,
        pos_y: i16,
    ) -> Self {
        Self {
            window_id,
            is_move_size_start,
            move_size_type,
            pos_x,
            pos_y,
        }
    }
}

impl Encode for LocalMoveSizePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::LocalMoveSize, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.window_id, "LocalMoveSize::WindowId")?;
        dst.write_u16_le(
            u16::from(self.is_move_size_start),
            "LocalMoveSize::IsMoveSizeStart",
        )?;
        dst.write_u16_le(self.move_size_type, "LocalMoveSize::MoveSizeType")?;
        dst.write_i16_le(self.pos_x, "LocalMoveSize::PosX")?;
        dst.write_i16_le(self.pos_y, "LocalMoveSize::PosY")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "LocalMoveSizePdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for LocalMoveSizePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let window_id = src.read_u32_le("LocalMoveSize::WindowId")?;
        let is_start = src.read_u16_le("LocalMoveSize::IsMoveSizeStart")?;
        let move_size_type = src.read_u16_le("LocalMoveSize::MoveSizeType")?;
        let pos_x = src.read_i16_le("LocalMoveSize::PosX")?;
        let pos_y = src.read_i16_le("LocalMoveSize::PosY")?;
        Ok(Self {
            window_id,
            is_move_size_start: is_start != 0,
            move_size_type,
            pos_x,
            pos_y,
        })
    }
}

/// Server Min Max Info PDU -- MS-RDPERP 2.2.2.7.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinMaxInfoPdu {
    pub window_id: u32,
    pub max_width: i16,
    pub max_height: i16,
    pub max_pos_x: i16,
    pub max_pos_y: i16,
    pub min_track_width: i16,
    pub min_track_height: i16,
    pub max_track_width: i16,
    pub max_track_height: i16,
}

impl MinMaxInfoPdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4 + 8 * 2;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_id: u32,
        max_width: i16,
        max_height: i16,
        max_pos_x: i16,
        max_pos_y: i16,
        min_track_width: i16,
        min_track_height: i16,
        max_track_width: i16,
        max_track_height: i16,
    ) -> Self {
        Self {
            window_id,
            max_width,
            max_height,
            max_pos_x,
            max_pos_y,
            min_track_width,
            min_track_height,
            max_track_width,
            max_track_height,
        }
    }
}

impl Encode for MinMaxInfoPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::MinMaxInfo, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.window_id, "MinMaxInfo::WindowId")?;
        dst.write_i16_le(self.max_width, "MinMaxInfo::MaxWidth")?;
        dst.write_i16_le(self.max_height, "MinMaxInfo::MaxHeight")?;
        dst.write_i16_le(self.max_pos_x, "MinMaxInfo::MaxPosX")?;
        dst.write_i16_le(self.max_pos_y, "MinMaxInfo::MaxPosY")?;
        dst.write_i16_le(self.min_track_width, "MinMaxInfo::MinTrackWidth")?;
        dst.write_i16_le(self.min_track_height, "MinMaxInfo::MinTrackHeight")?;
        dst.write_i16_le(self.max_track_width, "MinMaxInfo::MaxTrackWidth")?;
        dst.write_i16_le(self.max_track_height, "MinMaxInfo::MaxTrackHeight")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "MinMaxInfoPdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for MinMaxInfoPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let window_id = src.read_u32_le("MinMaxInfo::WindowId")?;
        Ok(Self {
            window_id,
            max_width: src.read_i16_le("MinMaxInfo::MaxWidth")?,
            max_height: src.read_i16_le("MinMaxInfo::MaxHeight")?,
            max_pos_x: src.read_i16_le("MinMaxInfo::MaxPosX")?,
            max_pos_y: src.read_i16_le("MinMaxInfo::MaxPosY")?,
            min_track_width: src.read_i16_le("MinMaxInfo::MinTrackWidth")?,
            min_track_height: src.read_i16_le("MinMaxInfo::MinTrackHeight")?,
            max_track_width: src.read_i16_le("MinMaxInfo::MaxTrackWidth")?,
            max_track_height: src.read_i16_le("MinMaxInfo::MaxTrackHeight")?,
        })
    }
}

/// Client Window Move PDU -- MS-RDPERP 2.2.2.7.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowMovePdu {
    pub window_id: u32,
    pub left: i16,
    pub top: i16,
    pub right: i16,
    pub bottom: i16,
}

impl WindowMovePdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4 + 4 * 2;

    pub fn new(window_id: u32, left: i16, top: i16, right: i16, bottom: i16) -> Self {
        Self {
            window_id,
            left,
            top,
            right,
            bottom,
        }
    }
}

impl Encode for WindowMovePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::WindowMove, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.window_id, "WindowMove::WindowId")?;
        dst.write_i16_le(self.left, "WindowMove::Left")?;
        dst.write_i16_le(self.top, "WindowMove::Top")?;
        dst.write_i16_le(self.right, "WindowMove::Right")?;
        dst.write_i16_le(self.bottom, "WindowMove::Bottom")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "WindowMovePdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for WindowMovePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let window_id = src.read_u32_le("WindowMove::WindowId")?;
        Ok(Self {
            window_id,
            left: src.read_i16_le("WindowMove::Left")?,
            top: src.read_i16_le("WindowMove::Top")?,
            right: src.read_i16_le("WindowMove::Right")?,
            bottom: src.read_i16_le("WindowMove::Bottom")?,
        })
    }
}

/// Window Cloak State Change PDU -- MS-RDPERP 2.2.2.12.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloakPdu {
    pub window_id: u32,
    pub cloaked: bool,
}

impl CloakPdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4 + 1;

    pub fn new(window_id: u32, cloaked: bool) -> Self {
        Self { window_id, cloaked }
    }
}

impl Encode for CloakPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::Cloak, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.window_id, "Cloak::WindowId")?;
        dst.write_u8(u8::from(self.cloaked), "Cloak::Cloaked")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CloakPdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for CloakPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let window_id = src.read_u32_le("Cloak::WindowId")?;
        let cloaked = src.read_u8("Cloak::Cloaked")? != 0;
        Ok(Self { window_id, cloaked })
    }
}

/// Server Z-Order Sync PDU -- MS-RDPERP 2.2.2.11.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZOrderSyncPdu {
    pub window_id_marker: u32,
}

impl ZOrderSyncPdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4;

    pub fn new(window_id_marker: u32) -> Self {
        Self { window_id_marker }
    }
}

impl Encode for ZOrderSyncPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::ZOrderSync, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.window_id_marker, "ZOrderSync::WindowIdMarker")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ZOrderSyncPdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for ZOrderSyncPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let window_id_marker = src.read_u32_le("ZOrderSync::WindowIdMarker")?;
        Ok(Self { window_id_marker })
    }
}

/// Client Window Snap PDU -- MS-RDPERP 2.2.2.7.5
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapArrangePdu {
    pub window_id: u32,
    pub left: i16,
    pub top: i16,
    pub right: i16,
    pub bottom: i16,
}

impl SnapArrangePdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4 + 4 * 2;

    pub fn new(window_id: u32, left: i16, top: i16, right: i16, bottom: i16) -> Self {
        Self {
            window_id,
            left,
            top,
            right,
            bottom,
        }
    }
}

impl Encode for SnapArrangePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::SnapArrange, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.window_id, "SnapArrange::WindowId")?;
        dst.write_i16_le(self.left, "SnapArrange::Left")?;
        dst.write_i16_le(self.top, "SnapArrange::Top")?;
        dst.write_i16_le(self.right, "SnapArrange::Right")?;
        dst.write_i16_le(self.bottom, "SnapArrange::Bottom")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SnapArrangePdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for SnapArrangePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let window_id = src.read_u32_le("SnapArrange::WindowId")?;
        Ok(Self {
            window_id,
            left: src.read_i16_le("SnapArrange::Left")?,
            top: src.read_i16_le("SnapArrange::Top")?,
            right: src.read_i16_le("SnapArrange::Right")?,
            bottom: src.read_i16_le("SnapArrange::Bottom")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activate_roundtrip() {
        let pdu = ActivatePdu::new(0x0001_0042, true);
        let mut buf = [0u8; ActivatePdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = RailHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.order_type, RailOrderType::Activate);
        let decoded = ActivatePdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn sys_menu_roundtrip() {
        let pdu = SysMenuPdu::new(0x42, -10, 200);
        let mut buf = [0u8; SysMenuPdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = SysMenuPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn sys_command_roundtrip() {
        let pdu = SysCommandPdu::new(0x42, SC_MAXIMIZE);
        let mut buf = [0u8; SysCommandPdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = SysCommandPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn notify_event_roundtrip() {
        let pdu = NotifyEventPdu::new(0x42, 0x01, WM_LBUTTONDOWN);
        let mut buf = [0u8; NotifyEventPdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = NotifyEventPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn local_move_size_roundtrip() {
        let pdu = LocalMoveSizePdu {
            window_id: 0x42,
            is_move_size_start: true,
            move_size_type: RAIL_WMSZ_MOVE,
            pos_x: 100,
            pos_y: -50,
        };
        let mut buf = [0u8; LocalMoveSizePdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = LocalMoveSizePdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn min_max_info_roundtrip() {
        let pdu = MinMaxInfoPdu {
            window_id: 0x42,
            max_width: 1920,
            max_height: 1080,
            max_pos_x: 0,
            max_pos_y: 0,
            min_track_width: 200,
            min_track_height: 100,
            max_track_width: 3840,
            max_track_height: 2160,
        };
        let mut buf = [0u8; MinMaxInfoPdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = MinMaxInfoPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn window_move_roundtrip() {
        let pdu = WindowMovePdu::new(0x42, 0, 0, 800, 600);
        let mut buf = [0u8; WindowMovePdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = WindowMovePdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn cloak_roundtrip() {
        let pdu = CloakPdu::new(0x42, true);
        let mut buf = [0u8; CloakPdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = CloakPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn z_order_sync_roundtrip() {
        let pdu = ZOrderSyncPdu::new(0xDEAD);
        let mut buf = [0u8; ZOrderSyncPdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = ZOrderSyncPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn snap_arrange_roundtrip() {
        let pdu = SnapArrangePdu::new(0x42, 0, 0, 960, 1080);
        let mut buf = [0u8; SnapArrangePdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = SnapArrangePdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn get_app_id_req_roundtrip() {
        let pdu = GetAppIdReqPdu::new(0x42);
        let mut buf = [0u8; GetAppIdReqPdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = GetAppIdReqPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn get_app_id_resp_roundtrip() {
        let mut app_id = [0u8; 520];
        // "test" in UTF-16LE + null terminator
        app_id[0] = b't';
        app_id[2] = b'e';
        app_id[4] = b's';
        app_id[6] = b't';
        let pdu = GetAppIdRespPdu {
            window_id: 0x42,
            application_id: app_id,
        };
        let mut buf = [0u8; GetAppIdRespPdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = GetAppIdRespPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }
}
