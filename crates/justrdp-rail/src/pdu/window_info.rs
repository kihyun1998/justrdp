#![forbid(unsafe_code)]

//! Window Information Orders -- MS-RDPERP 2.2.1.3
//!
//! These are Alternate Secondary Drawing Orders (not SVC PDUs).
//! They travel inside the core RDP drawing order pipeline.

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use super::header::{read_unicode_string, RailRect16};

// ── FieldsPresentFlags constants -- MS-RDPERP 2.2.1.3.1.2.1 ──

pub const WINDOW_ORDER_TYPE_WINDOW: u32 = 0x0100_0000;
pub const WINDOW_ORDER_TYPE_NOTIFY: u32 = 0x0200_0000;
pub const WINDOW_ORDER_STATE_NEW: u32 = 0x1000_0000;
pub const WINDOW_ORDER_STATE_DELETED: u32 = 0x2000_0000;
pub const WINDOW_ORDER_ICON: u32 = 0x4000_0000;
pub const WINDOW_ORDER_CACHEDICON: u32 = 0x8000_0000;

pub const WINDOW_ORDER_FIELD_OWNER: u32 = 0x0000_0002;
pub const WINDOW_ORDER_FIELD_TITLE: u32 = 0x0000_0004;
pub const WINDOW_ORDER_FIELD_STYLE: u32 = 0x0000_0008;
pub const WINDOW_ORDER_FIELD_SHOW: u32 = 0x0000_0010;
pub const WINDOW_ORDER_FIELD_APPBAR_STATE: u32 = 0x0000_0040;
pub const WINDOW_ORDER_FIELD_RESIZE_MARGIN_X: u32 = 0x0000_0080;
pub const WINDOW_ORDER_FIELD_WNDRECTS: u32 = 0x0000_0100;
pub const WINDOW_ORDER_FIELD_VISIBILITY: u32 = 0x0000_0200;
pub const WINDOW_ORDER_FIELD_WNDSIZE: u32 = 0x0000_0400;
pub const WINDOW_ORDER_FIELD_WNDOFFSET: u32 = 0x0000_0800;
pub const WINDOW_ORDER_FIELD_VISOFFSET: u32 = 0x0000_1000;
pub const WINDOW_ORDER_FIELD_ICON_BIG: u32 = 0x0000_2000;
pub const WINDOW_ORDER_FIELD_CLIENTAREAOFFSET: u32 = 0x0000_4000;
pub const WINDOW_ORDER_FIELD_CLIENTDELTA: u32 = 0x0000_8000;
pub const WINDOW_ORDER_FIELD_CLIENTAREASIZE: u32 = 0x0001_0000;
pub const WINDOW_ORDER_FIELD_RPCONTENT: u32 = 0x0002_0000;
pub const WINDOW_ORDER_FIELD_ROOTPARENT: u32 = 0x0004_0000;
pub const WINDOW_ORDER_FIELD_ENFORCE_SERVER_ZORDER: u32 = 0x0008_0000;
pub const WINDOW_ORDER_FIELD_ICON_OVERLAY: u32 = 0x0010_0000;
pub const WINDOW_ORDER_FIELD_ICON_OVERLAY_NULL: u32 = 0x0020_0000;
pub const WINDOW_ORDER_FIELD_OVERLAY_DESCRIPTION: u32 = 0x0040_0000;
pub const WINDOW_ORDER_FIELD_TASKBAR_BUTTON: u32 = 0x0080_0000;
pub const WINDOW_ORDER_FIELD_APPBAR_EDGE: u32 = 0x0000_0001;
pub const WINDOW_ORDER_FIELD_RESIZE_MARGIN_Y: u32 = 0x0800_0000;

/// Maximum number of window/visibility rects to prevent unbounded alloc.
const MAX_RECTS: u16 = 256;

/// Maximum icon bitmap data size (96x96 @ 32bpp = 36864, round up).
const MAX_ICON_DATA_BYTES: usize = 36_864;

/// Maximum color table size (256 RGBQUAD entries for 8bpp).
const MAX_COLOR_TABLE_BYTES: usize = 1024;

/// Window order header payload size after the 1-byte alternate secondary order header:
/// order_size(2) + flags(4) + window_id(4) = 10 bytes.
/// -- MS-RDPERP 2.2.1.3.1.1
///
/// Note: the full on-wire header is 11 bytes (including the 1-byte alt-sec order header),
/// but `decode_window_order` expects data starting *after* that byte.
pub const WINDOW_ORDER_HEADER_SIZE: usize = 10;

/// TS_ICON_INFO -- MS-RDPERP 2.2.1.2.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconInfo {
    pub cache_entry: u16,
    pub cache_id: u8,
    pub bpp: u8,
    pub width: u16,
    pub height: u16,
    /// Only present when bpp is 1, 4, or 8.
    pub color_table: Vec<u8>,
    pub bits_mask: Vec<u8>,
    pub bits_color: Vec<u8>,
}

impl IconInfo {
    fn has_color_table(&self) -> bool {
        matches!(self.bpp, 1 | 4 | 8)
    }

    pub fn wire_size(&self) -> usize {
        let base = 2 + 1 + 1 + 2 + 2; // cache_entry + cache_id + bpp + width + height
        let ct = if self.has_color_table() {
            2 + self.color_table.len()
        } else {
            0
        };
        let mask = 2 + self.bits_mask.len();
        let color = 2 + self.bits_color.len();
        base + ct + mask + color
    }
}

impl Encode for IconInfo {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.cache_entry, "IconInfo::CacheEntry")?;
        dst.write_u8(self.cache_id, "IconInfo::CacheId")?;
        dst.write_u8(self.bpp, "IconInfo::Bpp")?;
        dst.write_u16_le(self.width, "IconInfo::Width")?;
        dst.write_u16_le(self.height, "IconInfo::Height")?;
        if self.has_color_table() {
            let cb = u16::try_from(self.color_table.len())
                .map_err(|_| EncodeError::other("IconInfo", "CbColorTable"))?;
            dst.write_u16_le(cb, "IconInfo::CbColorTable")?;
        }
        let cb_mask = u16::try_from(self.bits_mask.len())
            .map_err(|_| EncodeError::other("IconInfo", "CbBitsMask"))?;
        dst.write_u16_le(cb_mask, "IconInfo::CbBitsMask")?;
        let cb_color = u16::try_from(self.bits_color.len())
            .map_err(|_| EncodeError::other("IconInfo", "CbBitsColor"))?;
        dst.write_u16_le(cb_color, "IconInfo::CbBitsColor")?;
        dst.write_slice(&self.bits_mask, "IconInfo::BitsMask")?;
        if self.has_color_table() {
            dst.write_slice(&self.color_table, "IconInfo::ColorTable")?;
        }
        dst.write_slice(&self.bits_color, "IconInfo::BitsColor")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "IconInfo"
    }

    fn size(&self) -> usize {
        self.wire_size()
    }
}

impl<'de> Decode<'de> for IconInfo {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cache_entry = src.read_u16_le("IconInfo::CacheEntry")?;
        let cache_id = src.read_u8("IconInfo::CacheId")?;
        let bpp = src.read_u8("IconInfo::Bpp")?;
        if !matches!(bpp, 1 | 4 | 8 | 16 | 24 | 32) {
            return Err(DecodeError::invalid_value("IconInfo", "Bpp"));
        }
        let width = src.read_u16_le("IconInfo::Width")?;
        let height = src.read_u16_le("IconInfo::Height")?;

        let has_ct = matches!(bpp, 1 | 4 | 8);
        let cb_color_table = if has_ct {
            let cb = src.read_u16_le("IconInfo::CbColorTable")? as usize;
            if cb > MAX_COLOR_TABLE_BYTES {
                return Err(DecodeError::invalid_value("IconInfo", "CbColorTable"));
            }
            cb
        } else {
            0
        };
        let cb_bits_mask = src.read_u16_le("IconInfo::CbBitsMask")? as usize;
        if cb_bits_mask > MAX_ICON_DATA_BYTES {
            return Err(DecodeError::invalid_value("IconInfo", "CbBitsMask"));
        }
        let cb_bits_color = src.read_u16_le("IconInfo::CbBitsColor")? as usize;
        if cb_bits_color > MAX_ICON_DATA_BYTES {
            return Err(DecodeError::invalid_value("IconInfo", "CbBitsColor"));
        }

        let bits_mask = src.read_slice(cb_bits_mask, "IconInfo::BitsMask")?.to_vec();
        let color_table = if has_ct {
            src.read_slice(cb_color_table, "IconInfo::ColorTable")?.to_vec()
        } else {
            Vec::new()
        };
        let bits_color = src.read_slice(cb_bits_color, "IconInfo::BitsColor")?.to_vec();

        Ok(Self {
            cache_entry,
            cache_id,
            bpp,
            width,
            height,
            color_table,
            bits_mask,
            bits_color,
        })
    }
}

/// TS_CACHED_ICON_INFO -- MS-RDPERP 2.2.1.2.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedIconInfo {
    pub cache_entry: u16,
    pub cache_id: u8,
}

impl CachedIconInfo {
    pub const SIZE: usize = 3;
}

impl Encode for CachedIconInfo {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.cache_entry, "CachedIconInfo::CacheEntry")?;
        dst.write_u8(self.cache_id, "CachedIconInfo::CacheId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CachedIconInfo"
    }

    fn size(&self) -> usize {
        Self::SIZE
    }
}

impl<'de> Decode<'de> for CachedIconInfo {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cache_entry = src.read_u16_le("CachedIconInfo::CacheEntry")?;
        let cache_id = src.read_u8("CachedIconInfo::CacheId")?;
        Ok(Self {
            cache_entry,
            cache_id,
        })
    }
}

/// Parsed window order (from alternate secondary drawing order stream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowOrder {
    /// New or existing window update.
    WindowUpdate(WindowUpdateOrder),
    /// Window deleted.
    WindowDelete {
        window_id: u32,
    },
    /// Window icon.
    WindowIcon {
        window_id: u32,
        is_big: bool,
        is_overlay: bool,
        icon: IconInfo,
    },
    /// Cached window icon.
    WindowCachedIcon {
        window_id: u32,
        is_big: bool,
        is_overlay: bool,
        cached: CachedIconInfo,
    },
}

/// New or existing window order fields -- MS-RDPERP 2.2.1.3.1.2.1
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WindowUpdateOrder {
    pub window_id: u32,
    pub is_new: bool,
    pub fields_present: u32,
    pub owner_window_id: Option<u32>,
    pub style: Option<u32>,
    pub extended_style: Option<u32>,
    pub show_state: Option<u8>,
    pub title: Option<Vec<u8>>,
    pub client_offset_x: Option<i32>,
    pub client_offset_y: Option<i32>,
    pub client_area_width: Option<u32>,
    pub client_area_height: Option<u32>,
    pub window_left_resize_margin: Option<u32>,
    pub window_right_resize_margin: Option<u32>,
    pub window_top_resize_margin: Option<u32>,
    pub window_bottom_resize_margin: Option<u32>,
    pub rp_content: Option<u8>,
    pub root_parent_handle: Option<u32>,
    pub window_offset_x: Option<i32>,
    pub window_offset_y: Option<i32>,
    pub window_client_delta_x: Option<i32>,
    pub window_client_delta_y: Option<i32>,
    pub window_width: Option<u32>,
    pub window_height: Option<u32>,
    pub window_rects: Option<Vec<RailRect16>>,
    pub visible_offset_x: Option<i32>,
    pub visible_offset_y: Option<i32>,
    pub visibility_rects: Option<Vec<RailRect16>>,
    pub overlay_description: Option<Vec<u8>>,
    pub taskbar_button: Option<u8>,
    pub enforce_server_z_order: Option<u8>,
    pub appbar_state: Option<u8>,
    pub appbar_edge: Option<u8>,
}

/// Decode a window order from the alternate secondary order stream.
///
/// `data` must start after the 1-byte alternate secondary order header byte.
/// The caller is responsible for parsing the order header byte and verifying
/// the order type is `TS_ALTSEC_WINDOW` (0x0B).
///
/// The cursor is bounded to the declared `OrderSize` to prevent reading
/// past the PDU boundary.
pub fn decode_window_order(data: &[u8]) -> DecodeResult<WindowOrder> {
    // Read the header fields first to get order_size.
    if data.len() < 10 {
        return Err(DecodeError::invalid_value("WindowOrder", "header too short"));
    }
    let order_size = u16::from_le_bytes([data[0], data[1]]) as usize;

    // order_size includes the 1-byte alt-sec header byte that the caller already consumed.
    // Minimum valid: 1 (alt-sec byte) + WINDOW_ORDER_HEADER_SIZE (10) = 11.
    if order_size < 1 + WINDOW_ORDER_HEADER_SIZE {
        return Err(DecodeError::invalid_value("WindowOrder", "OrderSize"));
    }
    let bounded_len = (order_size - 1).min(data.len());
    let mut src = ReadCursor::new(&data[..bounded_len]);

    let _order_size_field = src.read_u16_le("WindowOrder::OrderSize")?;
    let flags = src.read_u32_le("WindowOrder::FieldsPresentFlags")?;
    let window_id = src.read_u32_le("WindowOrder::WindowId")?;

    if flags & WINDOW_ORDER_TYPE_WINDOW == 0 {
        return Err(DecodeError::invalid_value("WindowOrder", "FieldsPresentFlags"));
    }

    // Deleted window
    if flags & WINDOW_ORDER_STATE_DELETED != 0 {
        return Ok(WindowOrder::WindowDelete { window_id });
    }

    // ICON and CACHEDICON are mutually exclusive.
    if flags & WINDOW_ORDER_ICON != 0 && flags & WINDOW_ORDER_CACHEDICON != 0 {
        return Err(DecodeError::invalid_value("WindowOrder", "FieldsPresentFlags"));
    }

    // Window icon
    if flags & WINDOW_ORDER_ICON != 0 {
        let is_big = flags & WINDOW_ORDER_FIELD_ICON_BIG != 0;
        let is_overlay = flags & WINDOW_ORDER_FIELD_ICON_OVERLAY != 0;
        let icon = IconInfo::decode(&mut src)?;
        return Ok(WindowOrder::WindowIcon {
            window_id,
            is_big,
            is_overlay,
            icon,
        });
    }

    // Cached icon
    if flags & WINDOW_ORDER_CACHEDICON != 0 {
        let is_big = flags & WINDOW_ORDER_FIELD_ICON_BIG != 0;
        let is_overlay = flags & WINDOW_ORDER_FIELD_ICON_OVERLAY != 0;
        let cached = CachedIconInfo::decode(&mut src)?;
        return Ok(WindowOrder::WindowCachedIcon {
            window_id,
            is_big,
            is_overlay,
            cached,
        });
    }

    // New or existing window update
    let is_new = flags & WINDOW_ORDER_STATE_NEW != 0;
    let mut order = WindowUpdateOrder {
        window_id,
        is_new,
        fields_present: flags,
        ..Default::default()
    };

    if flags & WINDOW_ORDER_FIELD_OWNER != 0 {
        order.owner_window_id = Some(src.read_u32_le("WindowUpdate::OwnerWindowId")?);
    }
    if flags & WINDOW_ORDER_FIELD_STYLE != 0 {
        order.style = Some(src.read_u32_le("WindowUpdate::Style")?);
        order.extended_style = Some(src.read_u32_le("WindowUpdate::ExtendedStyle")?);
    }
    if flags & WINDOW_ORDER_FIELD_SHOW != 0 {
        order.show_state = Some(src.read_u8("WindowUpdate::ShowState")?);
    }
    if flags & WINDOW_ORDER_FIELD_TITLE != 0 {
        order.title = Some(read_unicode_string(&mut src, "WindowUpdate::TitleInfo", 520)?);
    }
    if flags & WINDOW_ORDER_FIELD_CLIENTAREAOFFSET != 0 {
        order.client_offset_x = Some(src.read_i32_le("WindowUpdate::ClientOffsetX")?);
        order.client_offset_y = Some(src.read_i32_le("WindowUpdate::ClientOffsetY")?);
    }
    if flags & WINDOW_ORDER_FIELD_CLIENTAREASIZE != 0 {
        order.client_area_width = Some(src.read_u32_le("WindowUpdate::ClientAreaWidth")?);
        order.client_area_height = Some(src.read_u32_le("WindowUpdate::ClientAreaHeight")?);
    }
    if flags & WINDOW_ORDER_FIELD_RESIZE_MARGIN_X != 0 {
        order.window_left_resize_margin =
            Some(src.read_u32_le("WindowUpdate::WindowLeftResizeMargin")?);
        order.window_right_resize_margin =
            Some(src.read_u32_le("WindowUpdate::WindowRightResizeMargin")?);
    }
    if flags & WINDOW_ORDER_FIELD_RESIZE_MARGIN_Y != 0 {
        order.window_top_resize_margin =
            Some(src.read_u32_le("WindowUpdate::WindowTopResizeMargin")?);
        order.window_bottom_resize_margin =
            Some(src.read_u32_le("WindowUpdate::WindowBottomResizeMargin")?);
    }
    if flags & WINDOW_ORDER_FIELD_RPCONTENT != 0 {
        order.rp_content = Some(src.read_u8("WindowUpdate::RPContent")?);
    }
    if flags & WINDOW_ORDER_FIELD_ROOTPARENT != 0 {
        order.root_parent_handle = Some(src.read_u32_le("WindowUpdate::RootParentHandle")?);
    }
    if flags & WINDOW_ORDER_FIELD_WNDOFFSET != 0 {
        order.window_offset_x = Some(src.read_i32_le("WindowUpdate::WindowOffsetX")?);
        order.window_offset_y = Some(src.read_i32_le("WindowUpdate::WindowOffsetY")?);
    }
    if flags & WINDOW_ORDER_FIELD_CLIENTDELTA != 0 {
        order.window_client_delta_x = Some(src.read_i32_le("WindowUpdate::WindowClientDeltaX")?);
        order.window_client_delta_y = Some(src.read_i32_le("WindowUpdate::WindowClientDeltaY")?);
    }
    if flags & WINDOW_ORDER_FIELD_WNDSIZE != 0 {
        order.window_width = Some(src.read_u32_le("WindowUpdate::WindowWidth")?);
        order.window_height = Some(src.read_u32_le("WindowUpdate::WindowHeight")?);
    }
    if flags & WINDOW_ORDER_FIELD_WNDRECTS != 0 {
        let num = src.read_u16_le("WindowUpdate::NumWindowRects")?;
        if num > MAX_RECTS {
            return Err(DecodeError::invalid_value("WindowUpdate", "NumWindowRects"));
        }
        let mut rects = Vec::with_capacity(num as usize);
        for _ in 0..num {
            rects.push(RailRect16::decode(&mut src)?);
        }
        order.window_rects = Some(rects);
    }
    if flags & WINDOW_ORDER_FIELD_VISOFFSET != 0 {
        order.visible_offset_x = Some(src.read_i32_le("WindowUpdate::VisibleOffsetX")?);
        order.visible_offset_y = Some(src.read_i32_le("WindowUpdate::VisibleOffsetY")?);
    }
    if flags & WINDOW_ORDER_FIELD_VISIBILITY != 0 {
        let num = src.read_u16_le("WindowUpdate::NumVisibilityRects")?;
        if num > MAX_RECTS {
            return Err(DecodeError::invalid_value(
                "WindowUpdate",
                "NumVisibilityRects",
            ));
        }
        let mut rects = Vec::with_capacity(num as usize);
        for _ in 0..num {
            rects.push(RailRect16::decode(&mut src)?);
        }
        order.visibility_rects = Some(rects);
    }
    if flags & WINDOW_ORDER_FIELD_OVERLAY_DESCRIPTION != 0 {
        order.overlay_description =
            Some(read_unicode_string(&mut src, "WindowUpdate::OverlayDescription", 520)?);
    }
    if flags & WINDOW_ORDER_FIELD_TASKBAR_BUTTON != 0 {
        order.taskbar_button = Some(src.read_u8("WindowUpdate::TaskbarButton")?);
    }
    if flags & WINDOW_ORDER_FIELD_ENFORCE_SERVER_ZORDER != 0 {
        order.enforce_server_z_order = Some(src.read_u8("WindowUpdate::EnforceServerZOrder")?);
    }
    if flags & WINDOW_ORDER_FIELD_APPBAR_STATE != 0 {
        order.appbar_state = Some(src.read_u8("WindowUpdate::AppBarState")?);
    }
    if flags & WINDOW_ORDER_FIELD_APPBAR_EDGE != 0 {
        order.appbar_edge = Some(src.read_u8("WindowUpdate::AppBarEdge")?);
    }

    Ok(WindowOrder::WindowUpdate(order))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_deleted_window() {
        // OrderSize=11, Flags=WINDOW_ORDER_TYPE_WINDOW|WINDOW_ORDER_STATE_DELETED, WindowId=0x42
        let mut data = Vec::new();
        data.extend_from_slice(&11u16.to_le_bytes()); // OrderSize
        let flags = WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_STATE_DELETED;
        data.extend_from_slice(&flags.to_le_bytes()); // Flags
        data.extend_from_slice(&0x42u32.to_le_bytes()); // WindowId

        let order = decode_window_order(&data).unwrap();
        assert!(matches!(order, WindowOrder::WindowDelete { window_id: 0x42 }));
    }

    #[test]
    fn decode_new_window_with_style() {
        let mut data = Vec::new();
        data.extend_from_slice(&19u16.to_le_bytes()); // OrderSize (11 + 4 + 4 = 19)
        let flags =
            WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_STATE_NEW | WINDOW_ORDER_FIELD_STYLE;
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&0x42u32.to_le_bytes()); // WindowId
        data.extend_from_slice(&0x00CF0000u32.to_le_bytes()); // Style (WS_OVERLAPPEDWINDOW)
        data.extend_from_slice(&0x00000100u32.to_le_bytes()); // ExtendedStyle

        let order = decode_window_order(&data).unwrap();
        match order {
            WindowOrder::WindowUpdate(u) => {
                assert!(u.is_new);
                assert_eq!(u.window_id, 0x42);
                assert_eq!(u.style, Some(0x00CF0000));
                assert_eq!(u.extended_style, Some(0x00000100));
            }
            _ => panic!("expected WindowUpdate"),
        }
    }

    #[test]
    fn icon_info_32bpp_roundtrip() {
        let icon = IconInfo {
            cache_entry: 5,
            cache_id: 2,
            bpp: 32,
            width: 16,
            height: 16,
            color_table: Vec::new(),
            bits_mask: alloc::vec![0xFF; 64],
            bits_color: alloc::vec![0xAB; 1024],
        };
        let mut buf = alloc::vec![0u8; icon.wire_size()];
        let mut cursor = WriteCursor::new(&mut buf);
        icon.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = IconInfo::decode(&mut cursor).unwrap();
        assert_eq!(icon, decoded);
    }

    #[test]
    fn icon_info_8bpp_with_color_table() {
        let icon = IconInfo {
            cache_entry: 0,
            cache_id: 0,
            bpp: 8,
            width: 4,
            height: 4,
            color_table: alloc::vec![0x00; 1024], // 256 * 4 bytes RGBQUAD
            bits_mask: alloc::vec![0xFF; 4],
            bits_color: alloc::vec![0x01; 16],
        };
        let mut buf = alloc::vec![0u8; icon.wire_size()];
        let mut cursor = WriteCursor::new(&mut buf);
        icon.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = IconInfo::decode(&mut cursor).unwrap();
        assert_eq!(icon, decoded);
    }

    #[test]
    fn cached_icon_info_roundtrip() {
        let cached = CachedIconInfo {
            cache_entry: 42,
            cache_id: 3,
        };
        let mut buf = [0u8; CachedIconInfo::SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        cached.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = CachedIconInfo::decode(&mut cursor).unwrap();
        assert_eq!(cached, decoded);
    }

    #[test]
    fn decode_window_with_rects() {
        let mut data = Vec::new();
        let flags = WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_FIELD_WNDRECTS;
        // OrderSize = 1 (alt-sec) + 10 (header) + 2 (NumRects) + 2*8 (rects) = 29
        data.extend_from_slice(&29u16.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&0x42u32.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes()); // NumWindowRects
        // Rect 1: (0, 0, 100, 100)
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&100u16.to_le_bytes());
        data.extend_from_slice(&100u16.to_le_bytes());
        // Rect 2: (200, 200, 400, 400)
        data.extend_from_slice(&200u16.to_le_bytes());
        data.extend_from_slice(&200u16.to_le_bytes());
        data.extend_from_slice(&400u16.to_le_bytes());
        data.extend_from_slice(&400u16.to_le_bytes());

        let order = decode_window_order(&data).unwrap();
        match order {
            WindowOrder::WindowUpdate(u) => {
                let rects = u.window_rects.unwrap();
                assert_eq!(rects.len(), 2);
                assert_eq!(rects[0].right, 100);
                assert_eq!(rects[1].left, 200);
            }
            _ => panic!("expected WindowUpdate"),
        }
    }

    #[test]
    fn reject_too_many_rects() {
        let mut data = Vec::new();
        let flags = WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_FIELD_WNDRECTS;
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&0x42u32.to_le_bytes());
        data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // NumWindowRects = 65535

        assert!(decode_window_order(&data).is_err());
    }

    #[test]
    fn decode_window_icon_order() {
        let icon = IconInfo {
            cache_entry: 3,
            cache_id: 1,
            bpp: 32,
            width: 16,
            height: 16,
            color_table: Vec::new(),
            bits_mask: alloc::vec![0xFF; 64],
            bits_color: alloc::vec![0xAB; 1024],
        };
        let mut data = Vec::new();
        let total = 1 + 10 + icon.wire_size(); // alt-sec byte + header payload + icon
        data.extend_from_slice(&(total as u16).to_le_bytes());
        let flags = WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_ICON | WINDOW_ORDER_FIELD_ICON_BIG;
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&0x42u32.to_le_bytes());
        // Append icon data
        let mut icon_buf = alloc::vec![0u8; icon.wire_size()];
        let mut cursor = WriteCursor::new(&mut icon_buf);
        icon.encode(&mut cursor).unwrap();
        data.extend_from_slice(&icon_buf);

        let order = decode_window_order(&data).unwrap();
        match order {
            WindowOrder::WindowIcon {
                window_id,
                is_big,
                is_overlay,
                icon: decoded_icon,
            } => {
                assert_eq!(window_id, 0x42);
                assert!(is_big);
                assert!(!is_overlay);
                assert_eq!(decoded_icon.width, 16);
            }
            _ => panic!("expected WindowIcon"),
        }
    }

    #[test]
    fn decode_window_cached_icon_order() {
        let mut data = Vec::new();
        let total = 1 + 10 + CachedIconInfo::SIZE;
        data.extend_from_slice(&(total as u16).to_le_bytes());
        let flags = WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_CACHEDICON;
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&0x42u32.to_le_bytes());
        data.extend_from_slice(&7u16.to_le_bytes()); // CacheEntry
        data.push(2); // CacheId

        let order = decode_window_order(&data).unwrap();
        match order {
            WindowOrder::WindowCachedIcon {
                window_id,
                cached,
                ..
            } => {
                assert_eq!(window_id, 0x42);
                assert_eq!(cached.cache_entry, 7);
                assert_eq!(cached.cache_id, 2);
            }
            _ => panic!("expected WindowCachedIcon"),
        }
    }

    #[test]
    fn reject_icon_and_cached_icon_both_set() {
        let mut data = Vec::new();
        data.extend_from_slice(&20u16.to_le_bytes());
        let flags = WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_ICON | WINDOW_ORDER_CACHEDICON;
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&0x42u32.to_le_bytes());

        assert!(decode_window_order(&data).is_err());
    }
}
