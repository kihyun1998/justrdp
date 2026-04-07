#![forbid(unsafe_code)]

//! TS_RAIL_PDU_HEADER -- MS-RDPERP 2.2.2.1

use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

/// RAIL PDU header size in bytes.
pub const RAIL_HEADER_SIZE: usize = 4;

// ── Order type constants -- MS-RDPERP 2.2.2.1 ──

/// Client Execute PDU.
pub const TS_RAIL_ORDER_EXEC: u16 = 0x0001;
/// Client Activate PDU.
pub const TS_RAIL_ORDER_ACTIVATE: u16 = 0x0002;
/// System Parameters Update PDU (bidirectional).
pub const TS_RAIL_ORDER_SYSPARAM: u16 = 0x0003;
/// Client System Command PDU.
pub const TS_RAIL_ORDER_SYSCOMMAND: u16 = 0x0004;
/// Handshake PDU.
pub const TS_RAIL_ORDER_HANDSHAKE: u16 = 0x0005;
/// Client Notify Event PDU.
pub const TS_RAIL_ORDER_NOTIFY_EVENT: u16 = 0x0006;
/// Client Window Move PDU.
pub const TS_RAIL_ORDER_WINDOWMOVE: u16 = 0x0008;
/// Server Move/Size Start/End PDU.
pub const TS_RAIL_ORDER_LOCALMOVESIZE: u16 = 0x0009;
/// Server Min Max Info PDU.
pub const TS_RAIL_ORDER_MINMAXINFO: u16 = 0x000A;
/// Client Information PDU.
pub const TS_RAIL_ORDER_CLIENTSTATUS: u16 = 0x000B;
/// Client System Menu PDU.
pub const TS_RAIL_ORDER_SYSMENU: u16 = 0x000C;
/// Language Bar Info PDU (bidirectional).
pub const TS_RAIL_ORDER_LANGBARINFO: u16 = 0x000D;
/// Client Get AppId Request PDU.
pub const TS_RAIL_ORDER_GET_APPID_REQ: u16 = 0x000E;
/// Server Get AppId Response PDU.
pub const TS_RAIL_ORDER_GET_APPID_RESP: u16 = 0x000F;
/// Server Taskbar Info PDU.
pub const TS_RAIL_ORDER_TASKBARINFO: u16 = 0x0010;
/// Language IME Info PDU.
pub const TS_RAIL_ORDER_LANGUAGEIMEINFO: u16 = 0x0011;
/// Compartment Info PDU.
pub const TS_RAIL_ORDER_COMPARTMENTINFO: u16 = 0x0012;
/// HandshakeEx PDU.
pub const TS_RAIL_ORDER_HANDSHAKE_EX: u16 = 0x0013;
/// Server Z-Order Sync PDU.
pub const TS_RAIL_ORDER_ZORDER_SYNC: u16 = 0x0014;
/// Window Cloak State Change PDU (bidirectional).
pub const TS_RAIL_ORDER_CLOAK: u16 = 0x0015;
/// Power Display Request PDU.
pub const TS_RAIL_ORDER_POWER_DISPLAY_REQUEST: u16 = 0x0016;
/// Client Window Snap PDU.
pub const TS_RAIL_ORDER_SNAP_ARRANGE: u16 = 0x0017;
/// Server Get AppId Extended Response PDU.
pub const TS_RAIL_ORDER_GET_APPID_RESP_EX: u16 = 0x0018;
/// Text Scale Info PDU.
pub const TS_RAIL_ORDER_TEXTSCALEINFO: u16 = 0x0019;
/// Caret Blink Info PDU.
pub const TS_RAIL_ORDER_CARETBLINKINFO: u16 = 0x001A;
/// Server Execute Result PDU.
pub const TS_RAIL_ORDER_EXEC_RESULT: u16 = 0x0080;

/// RAIL PDU order type -- MS-RDPERP 2.2.2.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RailOrderType {
    Exec = TS_RAIL_ORDER_EXEC,
    Activate = TS_RAIL_ORDER_ACTIVATE,
    SysParam = TS_RAIL_ORDER_SYSPARAM,
    SysCommand = TS_RAIL_ORDER_SYSCOMMAND,
    Handshake = TS_RAIL_ORDER_HANDSHAKE,
    NotifyEvent = TS_RAIL_ORDER_NOTIFY_EVENT,
    WindowMove = TS_RAIL_ORDER_WINDOWMOVE,
    LocalMoveSize = TS_RAIL_ORDER_LOCALMOVESIZE,
    MinMaxInfo = TS_RAIL_ORDER_MINMAXINFO,
    ClientStatus = TS_RAIL_ORDER_CLIENTSTATUS,
    SysMenu = TS_RAIL_ORDER_SYSMENU,
    LangBarInfo = TS_RAIL_ORDER_LANGBARINFO,
    GetAppIdReq = TS_RAIL_ORDER_GET_APPID_REQ,
    GetAppIdResp = TS_RAIL_ORDER_GET_APPID_RESP,
    TaskbarInfo = TS_RAIL_ORDER_TASKBARINFO,
    LanguageImeInfo = TS_RAIL_ORDER_LANGUAGEIMEINFO,
    CompartmentInfo = TS_RAIL_ORDER_COMPARTMENTINFO,
    HandshakeEx = TS_RAIL_ORDER_HANDSHAKE_EX,
    ZOrderSync = TS_RAIL_ORDER_ZORDER_SYNC,
    Cloak = TS_RAIL_ORDER_CLOAK,
    PowerDisplayRequest = TS_RAIL_ORDER_POWER_DISPLAY_REQUEST,
    SnapArrange = TS_RAIL_ORDER_SNAP_ARRANGE,
    GetAppIdRespEx = TS_RAIL_ORDER_GET_APPID_RESP_EX,
    TextScaleInfo = TS_RAIL_ORDER_TEXTSCALEINFO,
    CaretBlinkInfo = TS_RAIL_ORDER_CARETBLINKINFO,
    ExecResult = TS_RAIL_ORDER_EXEC_RESULT,
}

impl RailOrderType {
    /// Try to convert a u16 value to a RailOrderType.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            TS_RAIL_ORDER_EXEC => Some(Self::Exec),
            TS_RAIL_ORDER_ACTIVATE => Some(Self::Activate),
            TS_RAIL_ORDER_SYSPARAM => Some(Self::SysParam),
            TS_RAIL_ORDER_SYSCOMMAND => Some(Self::SysCommand),
            TS_RAIL_ORDER_HANDSHAKE => Some(Self::Handshake),
            TS_RAIL_ORDER_NOTIFY_EVENT => Some(Self::NotifyEvent),
            TS_RAIL_ORDER_WINDOWMOVE => Some(Self::WindowMove),
            TS_RAIL_ORDER_LOCALMOVESIZE => Some(Self::LocalMoveSize),
            TS_RAIL_ORDER_MINMAXINFO => Some(Self::MinMaxInfo),
            TS_RAIL_ORDER_CLIENTSTATUS => Some(Self::ClientStatus),
            TS_RAIL_ORDER_SYSMENU => Some(Self::SysMenu),
            TS_RAIL_ORDER_LANGBARINFO => Some(Self::LangBarInfo),
            TS_RAIL_ORDER_GET_APPID_REQ => Some(Self::GetAppIdReq),
            TS_RAIL_ORDER_GET_APPID_RESP => Some(Self::GetAppIdResp),
            TS_RAIL_ORDER_TASKBARINFO => Some(Self::TaskbarInfo),
            TS_RAIL_ORDER_LANGUAGEIMEINFO => Some(Self::LanguageImeInfo),
            TS_RAIL_ORDER_COMPARTMENTINFO => Some(Self::CompartmentInfo),
            TS_RAIL_ORDER_HANDSHAKE_EX => Some(Self::HandshakeEx),
            TS_RAIL_ORDER_ZORDER_SYNC => Some(Self::ZOrderSync),
            TS_RAIL_ORDER_CLOAK => Some(Self::Cloak),
            TS_RAIL_ORDER_POWER_DISPLAY_REQUEST => Some(Self::PowerDisplayRequest),
            TS_RAIL_ORDER_SNAP_ARRANGE => Some(Self::SnapArrange),
            TS_RAIL_ORDER_GET_APPID_RESP_EX => Some(Self::GetAppIdRespEx),
            TS_RAIL_ORDER_TEXTSCALEINFO => Some(Self::TextScaleInfo),
            TS_RAIL_ORDER_CARETBLINKINFO => Some(Self::CaretBlinkInfo),
            TS_RAIL_ORDER_EXEC_RESULT => Some(Self::ExecResult),
            _ => None,
        }
    }
}

/// Common header for all RAIL PDUs -- MS-RDPERP 2.2.2.1
///
/// ```text
/// +──────────────+──────────────+
/// │ orderType    │ orderLength  │
/// │ (2 bytes)    │ (2 bytes)    │
/// +──────────────+──────────────+
/// ```
///
/// `orderLength` includes the 4-byte header itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RailHeader {
    /// PDU type identifier.
    pub order_type: RailOrderType,
    /// Total PDU length including this header.
    pub order_length: u16,
}

impl RailHeader {
    /// Create a new RAIL header.
    pub fn new(order_type: RailOrderType, order_length: u16) -> Self {
        Self {
            order_type,
            order_length,
        }
    }
}

impl Encode for RailHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.order_type as u16, "RailHeader::orderType")?;
        dst.write_u16_le(self.order_length, "RailHeader::orderLength")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RailHeader"
    }

    fn size(&self) -> usize {
        RAIL_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for RailHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let raw_type = src.read_u16_le("RailHeader::orderType")?;
        let order_type = RailOrderType::from_u16(raw_type).ok_or_else(|| {
            DecodeError::invalid_value("RailHeader", "orderType")
        })?;
        let order_length = src.read_u16_le("RailHeader::orderLength")?;

        if order_length < RAIL_HEADER_SIZE as u16 {
            return Err(DecodeError::invalid_value("RailHeader", "orderLength"));
        }

        Ok(Self {
            order_type,
            order_length,
        })
    }
}

// ── Client status flags -- MS-RDPERP 2.2.2.2.2 ──

/// Allow local move/size of RAIL windows.
pub const TS_RAIL_CLIENTSTATUS_ALLOWLOCALMOVESIZE: u32 = 0x0000_0001;
/// Client supports auto-reconnection.
pub const TS_RAIL_CLIENTSTATUS_AUTORECONNECT: u32 = 0x0000_0002;
/// Client supports Z-order sync.
pub const TS_RAIL_CLIENTSTATUS_ZORDER_SYNC: u32 = 0x0000_0004;
/// Client supports window resize margins.
pub const TS_RAIL_CLIENTSTATUS_WINDOW_RESIZE_MARGIN_SUPPORTED: u32 = 0x0000_0010;
/// Client supports high-DPI icons.
pub const TS_RAIL_CLIENTSTATUS_HIGH_DPI_ICONS_SUPPORTED: u32 = 0x0000_0020;
/// Client supports appbar remoting.
pub const TS_RAIL_CLIENTSTATUS_APPBAR_REMOTING_SUPPORTED: u32 = 0x0000_0040;
/// Client supports power display requests.
pub const TS_RAIL_CLIENTSTATUS_POWER_DISPLAY_REQUEST_SUPPORTED: u32 = 0x0000_0080;
/// Client supports bidirectional cloak.
pub const TS_RAIL_CLIENTSTATUS_BIDIRECTIONAL_CLOAK_SUPPORTED: u32 = 0x0000_0200;
/// Client wants to suppress icon orders.
pub const TS_RAIL_CLIENTSTATUS_SUPPRESS_ICON_ORDERS: u32 = 0x0000_0400;

/// Client Information PDU -- MS-RDPERP 2.2.2.2.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientStatusPdu {
    pub flags: u32,
}

impl ClientStatusPdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4;

    pub fn new(flags: u32) -> Self {
        Self { flags }
    }
}

impl Encode for ClientStatusPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::ClientStatus, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.flags, "ClientStatus::Flags")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ClientStatusPdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for ClientStatusPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let flags = src.read_u32_le("ClientStatus::Flags")?;
        Ok(Self { flags })
    }
}

// ── UNICODE_STRING helper -- MS-RDPERP 2.2.1.2.1 ──

/// Read a UNICODE_STRING (length-prefixed UTF-16LE, NOT null-terminated).
///
/// Returns raw UTF-16LE bytes.
pub fn read_unicode_string(
    src: &mut ReadCursor<'_>,
    context: &'static str,
    max_bytes: u16,
) -> DecodeResult<alloc::vec::Vec<u8>> {
    let cb = src.read_u16_le(context)?;
    if cb > max_bytes {
        return Err(DecodeError::invalid_value("UNICODE_STRING", context));
    }
    if cb % 2 != 0 {
        return Err(DecodeError::invalid_value("UNICODE_STRING", context));
    }
    let data = src.read_slice(cb as usize, context)?;
    Ok(data.to_vec())
}

/// Write a UNICODE_STRING (length-prefixed UTF-16LE).
pub fn write_unicode_string(
    dst: &mut WriteCursor<'_>,
    data: &[u8],
    context: &'static str,
) -> EncodeResult<()> {
    let len = u16::try_from(data.len())
        .map_err(|_| justrdp_core::EncodeError::other("UNICODE_STRING", context))?;
    dst.write_u16_le(len, context)?;
    dst.write_slice(data, context)?;
    Ok(())
}

/// TS_RECTANGLE_16 -- MS-RDPERP 2.2.1.2.2 (unsigned variant)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RailRect16 {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

impl Encode for RailRect16 {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.left, "RailRect16::left")?;
        dst.write_u16_le(self.top, "RailRect16::top")?;
        dst.write_u16_le(self.right, "RailRect16::right")?;
        dst.write_u16_le(self.bottom, "RailRect16::bottom")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RailRect16"
    }

    fn size(&self) -> usize {
        8
    }
}

impl<'de> Decode<'de> for RailRect16 {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            left: src.read_u16_le("RailRect16::left")?,
            top: src.read_u16_le("RailRect16::top")?,
            right: src.read_u16_le("RailRect16::right")?,
            bottom: src.read_u16_le("RailRect16::bottom")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = RailHeader::new(RailOrderType::Handshake, 8);
        let mut buf = [0u8; RAIL_HEADER_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = RailHeader::decode(&mut cursor).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn header_invalid_order_type() {
        let bytes = [0xFF, 0xFF, 0x04, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        assert!(RailHeader::decode(&mut cursor).is_err());
    }

    #[test]
    fn header_order_length_too_small() {
        // orderType=Handshake, orderLength=2 (< 4)
        let bytes = [0x05, 0x00, 0x02, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        assert!(RailHeader::decode(&mut cursor).is_err());
    }

    #[test]
    fn client_status_roundtrip() {
        let pdu = ClientStatusPdu::new(
            TS_RAIL_CLIENTSTATUS_ALLOWLOCALMOVESIZE | TS_RAIL_CLIENTSTATUS_ZORDER_SYNC,
        );
        let mut buf = [0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = RailHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.order_type, RailOrderType::ClientStatus);
        let decoded = ClientStatusPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn rect16_roundtrip() {
        let rect = RailRect16 {
            left: 10,
            top: 20,
            right: 100,
            bottom: 200,
        };
        let mut buf = [0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        rect.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(RailRect16::decode(&mut cursor).unwrap(), rect);
    }
}
