#![forbid(unsafe_code)]

//! RDPDR_HEADER -- MS-RDPEFS 2.2.1.1
//!
//! 4-byte shared header present in all device redirection PDUs.

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeResult};

/// RDPDR shared header size in bytes.
pub const SHARED_HEADER_SIZE: usize = 4;

/// Device redirection component types -- MS-RDPEFS 2.2.1.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Component {
    /// RDPDR_CTYP_CORE -- Core component.
    Core = 0x4472,
    /// RDPDR_CTYP_PRN -- Printing component.
    Printer = 0x5052,
}

impl Component {
    /// Try to convert a u16 to a Component.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x4472 => Some(Self::Core),
            0x5052 => Some(Self::Printer),
            _ => None,
        }
    }
}

/// Device redirection packet identifiers -- MS-RDPEFS 2.2.1.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PacketId {
    /// PAKID_CORE_SERVER_ANNOUNCE
    ServerAnnounce = 0x496E,
    /// PAKID_CORE_CLIENTID_CONFIRM
    ClientIdConfirm = 0x4343,
    /// PAKID_CORE_CLIENT_NAME
    ClientName = 0x434E,
    /// PAKID_CORE_DEVICELIST_ANNOUNCE
    DeviceListAnnounce = 0x4441,
    /// PAKID_CORE_DEVICE_REPLY
    DeviceReply = 0x6472,
    /// PAKID_CORE_DEVICE_IOREQUEST
    DeviceIoRequest = 0x4952,
    /// PAKID_CORE_DEVICE_IOCOMPLETION
    DeviceIoCompletion = 0x4943,
    /// PAKID_CORE_SERVER_CAPABILITY
    ServerCapability = 0x5350,
    /// PAKID_CORE_CLIENT_CAPABILITY
    ClientCapability = 0x4350,
    /// PAKID_CORE_DEVICELIST_REMOVE
    DeviceListRemove = 0x444D,
    /// PAKID_CORE_USER_LOGGEDON
    UserLoggedOn = 0x554C,
    /// PAKID_PRN_CACHE_DATA -- MS-RDPEPC
    PrnCacheData = 0x5043,
    /// PAKID_PRN_USING_XPS -- MS-RDPEPC
    PrnUsingXps = 0x5543,
}

impl PacketId {
    /// Try to convert a u16 to a PacketId.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x496E => Some(Self::ServerAnnounce),
            0x4343 => Some(Self::ClientIdConfirm),
            0x434E => Some(Self::ClientName),
            0x4441 => Some(Self::DeviceListAnnounce),
            0x6472 => Some(Self::DeviceReply),
            0x4952 => Some(Self::DeviceIoRequest),
            0x4943 => Some(Self::DeviceIoCompletion),
            0x5350 => Some(Self::ServerCapability),
            0x4350 => Some(Self::ClientCapability),
            0x444D => Some(Self::DeviceListRemove),
            0x554C => Some(Self::UserLoggedOn),
            0x5043 => Some(Self::PrnCacheData),
            0x5543 => Some(Self::PrnUsingXps),
            _ => None,
        }
    }
}

/// RDPDR_HEADER -- MS-RDPEFS 2.2.1.1
///
/// ```text
/// ┌────────────┬────────────┐
/// │ Component  │ PacketId   │
/// │ (2 bytes)  │ (2 bytes)  │
/// └────────────┴────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedHeader {
    /// Component type identifier.
    pub component: Component,
    /// Packet type identifier.
    pub packet_id: PacketId,
}

impl SharedHeader {
    /// Create a new RDPDR shared header.
    pub fn new(component: Component, packet_id: PacketId) -> Self {
        Self {
            component,
            packet_id,
        }
    }
}

impl Encode for SharedHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.component as u16, "SharedHeader::Component")?;
        dst.write_u16_le(self.packet_id as u16, "SharedHeader::PacketId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SharedHeader"
    }

    fn size(&self) -> usize {
        SHARED_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for SharedHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let raw_component = src.read_u16_le("SharedHeader::Component")?;
        let component = Component::from_u16(raw_component)
            .ok_or_else(|| DecodeError::invalid_value("SharedHeader", "Component"))?;

        let raw_packet_id = src.read_u16_le("SharedHeader::PacketId")?;
        let packet_id = PacketId::from_u16(raw_packet_id)
            .ok_or_else(|| DecodeError::invalid_value("SharedHeader", "PacketId"))?;

        Ok(Self {
            component,
            packet_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = SharedHeader::new(Component::Core, PacketId::ServerAnnounce);
        let mut buf = [0u8; SHARED_HEADER_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = SharedHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded.component, Component::Core);
        assert_eq!(decoded.packet_id, PacketId::ServerAnnounce);
    }

    #[test]
    fn header_known_bytes() {
        // 0x4472 = RDPDR_CTYP_CORE (Component::Core)
        // 0x4952 = PAKID_CORE_DEVICE_IOREQUEST (PacketId::DeviceIoRequest)
        // Wire bytes (little-endian): [0x72, 0x44, 0x52, 0x49]
        let bytes = [0x72, 0x44, 0x52, 0x49];
        let mut cursor = ReadCursor::new(&bytes);
        let header = SharedHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.component, Component::Core);
        assert_eq!(header.packet_id, PacketId::DeviceIoRequest);
    }
}
