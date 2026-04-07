#![forbid(unsafe_code)]

//! Notification Icon Orders -- MS-RDPERP 2.2.1.3.2

use alloc::vec::Vec;

use justrdp_core::{Decode, DecodeError, DecodeResult, ReadCursor};

use super::header::read_unicode_string;
use super::window_info::{
    CachedIconInfo, IconInfo,
    WINDOW_ORDER_CACHEDICON, WINDOW_ORDER_ICON, WINDOW_ORDER_STATE_DELETED,
    WINDOW_ORDER_STATE_NEW, WINDOW_ORDER_TYPE_NOTIFY,
};

// ── Notification icon field flags -- MS-RDPERP 2.2.1.3.2.2.1 ──

pub const WINDOW_ORDER_FIELD_NOTIFY_VERSION: u32 = 0x0000_0008;
pub const WINDOW_ORDER_FIELD_NOTIFY_TIP: u32 = 0x0000_0001;
pub const WINDOW_ORDER_FIELD_NOTIFY_INFO_TIP: u32 = 0x0000_0002;
pub const WINDOW_ORDER_FIELD_NOTIFY_STATE: u32 = 0x0000_0004;

/// TS_NOTIFY_ICON_INFOTIP -- MS-RDPERP 2.2.1.2.6
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyIconInfoTip {
    /// Timeout in ms.
    pub timeout: u32,
    /// Info flags.
    pub info_flags: u32,
    /// Balloon text (UTF-16LE).
    pub text: Vec<u8>,
    /// Balloon title (UTF-16LE).
    pub title: Vec<u8>,
}

/// Parsed notification icon order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyIconOrder {
    /// New or existing notification icon update.
    Update(NotifyIconUpdateOrder),
    /// Notification icon deleted.
    Delete {
        window_id: u32,
        notify_icon_id: u32,
    },
}

/// New or existing notification icon fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyIconUpdateOrder {
    pub window_id: u32,
    pub notify_icon_id: u32,
    pub is_new: bool,
    pub version: Option<u32>,
    pub tool_tip: Option<Vec<u8>>,
    pub info_tip: Option<NotifyIconInfoTip>,
    pub state: Option<u32>,
    pub icon: Option<IconInfo>,
    pub cached_icon: Option<CachedIconInfo>,
}

/// Decode a notification icon order from the alternate secondary order stream.
///
/// `data` must start after the 1-byte alternate secondary order header byte.
/// The caller is responsible for verifying the order type is `TS_ALTSEC_WINDOW` (0x0B).
///
/// The cursor is bounded to the declared `OrderSize` to prevent reading
/// past the PDU boundary.
pub fn decode_notify_icon_order(data: &[u8]) -> DecodeResult<NotifyIconOrder> {
    if data.len() < 14 {
        return Err(DecodeError::invalid_value("NotifyIconOrder", "header too short"));
    }
    let order_size = u16::from_le_bytes([data[0], data[1]]) as usize;

    // order_size includes the 1-byte alt-sec header byte already consumed.
    // Notify icon header payload: order_size(2) + flags(4) + window_id(4) + notify_icon_id(4) = 14.
    // Minimum valid: 1 (alt-sec byte) + 14 = 15.
    if order_size < 15 {
        return Err(DecodeError::invalid_value("NotifyIconOrder", "OrderSize"));
    }
    let bounded_len = (order_size - 1).min(data.len());
    let mut src = ReadCursor::new(&data[..bounded_len]);

    let _order_size_field = src.read_u16_le("NotifyIcon::OrderSize")?;
    let flags = src.read_u32_le("NotifyIcon::FieldsPresentFlags")?;
    let window_id = src.read_u32_le("NotifyIcon::WindowId")?;
    let notify_icon_id = src.read_u32_le("NotifyIcon::NotifyIconId")?;

    if flags & WINDOW_ORDER_TYPE_NOTIFY == 0 {
        return Err(DecodeError::invalid_value(
            "NotifyIconOrder",
            "FieldsPresentFlags",
        ));
    }

    // Deleted notification icon
    if flags & WINDOW_ORDER_STATE_DELETED != 0 {
        return Ok(NotifyIconOrder::Delete {
            window_id,
            notify_icon_id,
        });
    }

    // ICON and CACHEDICON are mutually exclusive.
    if flags & WINDOW_ORDER_ICON != 0 && flags & WINDOW_ORDER_CACHEDICON != 0 {
        return Err(DecodeError::invalid_value(
            "NotifyIconOrder",
            "FieldsPresentFlags",
        ));
    }

    let is_new = flags & WINDOW_ORDER_STATE_NEW != 0;

    let version = if flags & WINDOW_ORDER_FIELD_NOTIFY_VERSION != 0 {
        Some(src.read_u32_le("NotifyIcon::Version")?)
    } else {
        None
    };

    let tool_tip = if flags & WINDOW_ORDER_FIELD_NOTIFY_TIP != 0 {
        // MS-RDPERP 2.2.1.3.2.2.1: ToolTip max 128 chars = 256 bytes
        Some(read_unicode_string(&mut src, "NotifyIcon::ToolTip", 256)?)
    } else {
        None
    };

    let info_tip = if flags & WINDOW_ORDER_FIELD_NOTIFY_INFO_TIP != 0 {
        let timeout = src.read_u32_le("NotifyIconInfoTip::Timeout")?;
        let info_flags = src.read_u32_le("NotifyIconInfoTip::InfoFlags")?;
        // MS-RDPERP 2.2.1.2.6: Text max 256 chars = 512 bytes, Title max 64 chars = 128 bytes
        let text = read_unicode_string(&mut src, "NotifyIconInfoTip::Text", 512)?;
        let title = read_unicode_string(&mut src, "NotifyIconInfoTip::Title", 128)?;
        Some(NotifyIconInfoTip {
            timeout,
            info_flags,
            text,
            title,
        })
    } else {
        None
    };

    let state = if flags & WINDOW_ORDER_FIELD_NOTIFY_STATE != 0 {
        Some(src.read_u32_le("NotifyIcon::State")?)
    } else {
        None
    };

    let icon = if flags & WINDOW_ORDER_ICON != 0 {
        Some(IconInfo::decode(&mut src)?)
    } else {
        None
    };

    let cached_icon = if flags & WINDOW_ORDER_CACHEDICON != 0 {
        Some(CachedIconInfo::decode(&mut src)?)
    } else {
        None
    };

    Ok(NotifyIconOrder::Update(NotifyIconUpdateOrder {
        window_id,
        notify_icon_id,
        is_new,
        version,
        tool_tip,
        info_tip,
        state,
        icon,
        cached_icon,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_deleted_notify_icon() {
        let mut data = Vec::new();
        data.extend_from_slice(&15u16.to_le_bytes()); // OrderSize
        let flags = WINDOW_ORDER_TYPE_NOTIFY | WINDOW_ORDER_STATE_DELETED;
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&0x8Eu32.to_le_bytes()); // WindowId
        data.extend_from_slice(&0x9CD2u32.to_le_bytes()); // NotifyIconId

        let order = decode_notify_icon_order(&data).unwrap();
        match order {
            NotifyIconOrder::Delete {
                window_id,
                notify_icon_id,
            } => {
                assert_eq!(window_id, 0x8E);
                assert_eq!(notify_icon_id, 0x9CD2);
            }
            _ => panic!("expected Delete"),
        }
    }

    #[test]
    fn decode_new_notify_icon_with_version() {
        let mut data = Vec::new();
        // OrderSize = 1 (alt-sec) + 14 (header) + 4 (version) = 19
        data.extend_from_slice(&19u16.to_le_bytes());
        let flags = WINDOW_ORDER_TYPE_NOTIFY
            | WINDOW_ORDER_STATE_NEW
            | WINDOW_ORDER_FIELD_NOTIFY_VERSION;
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&0x42u32.to_le_bytes());
        data.extend_from_slice(&0x01u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes()); // Version = 3

        let order = decode_notify_icon_order(&data).unwrap();
        match order {
            NotifyIconOrder::Update(u) => {
                assert!(u.is_new);
                assert_eq!(u.version, Some(3));
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn decode_notify_icon_with_tooltip() {
        let mut data = Vec::new();
        // OrderSize = 1 (alt-sec) + 14 (header) + 2 (cbString) + 4 (body) = 21
        data.extend_from_slice(&21u16.to_le_bytes());
        let flags = WINDOW_ORDER_TYPE_NOTIFY | WINDOW_ORDER_FIELD_NOTIFY_TIP;
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&0x42u32.to_le_bytes());
        data.extend_from_slice(&0x01u32.to_le_bytes());
        // UNICODE_STRING: cbString=4, body="AB" in UTF-16LE
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&[0x41, 0x00, 0x42, 0x00]);

        let order = decode_notify_icon_order(&data).unwrap();
        match order {
            NotifyIconOrder::Update(u) => {
                let tip = u.tool_tip.unwrap();
                assert_eq!(tip, &[0x41, 0x00, 0x42, 0x00]);
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn decode_notify_icon_with_info_tip() {
        let mut data = Vec::new();
        // OrderSize = 1 (alt-sec) + 14 (header) + 4 (timeout) + 4 (flags) + 6 (text) + 4 (title) = 33
        data.extend_from_slice(&33u16.to_le_bytes());
        let flags = WINDOW_ORDER_TYPE_NOTIFY | WINDOW_ORDER_FIELD_NOTIFY_INFO_TIP;
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&0x42u32.to_le_bytes()); // WindowId
        data.extend_from_slice(&0x01u32.to_le_bytes()); // NotifyIconId
        // InfoTip: Timeout(4) + InfoFlags(4) + Text(UNICODE_STRING) + Title(UNICODE_STRING)
        data.extend_from_slice(&5000u32.to_le_bytes()); // Timeout
        data.extend_from_slice(&0x01u32.to_le_bytes()); // InfoFlags
        // Text: "Hi" in UTF-16LE
        data.extend_from_slice(&4u16.to_le_bytes()); // cbString=4
        data.extend_from_slice(&[0x48, 0x00, 0x69, 0x00]);
        // Title: "T" in UTF-16LE
        data.extend_from_slice(&2u16.to_le_bytes()); // cbString=2
        data.extend_from_slice(&[0x54, 0x00]);

        let order = decode_notify_icon_order(&data).unwrap();
        match order {
            NotifyIconOrder::Update(u) => {
                let tip = u.info_tip.unwrap();
                assert_eq!(tip.timeout, 5000);
                assert_eq!(tip.text, &[0x48, 0x00, 0x69, 0x00]);
                assert_eq!(tip.title, &[0x54, 0x00]);
            }
            _ => panic!("expected Update"),
        }
    }
}
