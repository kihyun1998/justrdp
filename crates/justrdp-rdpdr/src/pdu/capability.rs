#![forbid(unsafe_code)]

//! Device Redirection Capability Sets -- MS-RDPEFS 2.2.1.2.1, 2.2.2.7, 2.2.2.7.1

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{Decode, Encode};
use justrdp_core::{DecodeError, DecodeResult, EncodeError, EncodeResult};
use justrdp_core::{ReadCursor, WriteCursor};

// === Capability Header constants -- MS-RDPEFS 2.2.1.2.1 ===

/// Capability header size (CapabilityType + CapabilityLength + Version)
const CAPABILITY_HEADER_SIZE: usize = 8;

/// General capability type -- MS-RDPEFS 2.2.1.2.1
const CAP_GENERAL_TYPE: u16 = 0x0001;
/// Printer capability type -- MS-RDPEFS 2.2.1.2.1
const CAP_PRINTER_TYPE: u16 = 0x0002;
/// Port capability type -- MS-RDPEFS 2.2.1.2.1
const CAP_PORT_TYPE: u16 = 0x0003;
/// Drive capability type -- MS-RDPEFS 2.2.1.2.1
const CAP_DRIVE_TYPE: u16 = 0x0004;
/// SmartCard capability type -- MS-RDPEFS 2.2.1.2.1
const CAP_SMARTCARD_TYPE: u16 = 0x0005;

/// General capability version 1 -- MS-RDPEFS 2.2.2.7.1
pub const GENERAL_CAPABILITY_VERSION_01: u32 = 0x0000_0001;
/// General capability version 2 -- MS-RDPEFS 2.2.2.7.1
pub const GENERAL_CAPABILITY_VERSION_02: u32 = 0x0000_0002;

/// Protocol major version -- MS-RDPEFS 2.2.2.7.1
pub const RDPDR_MAJOR_RDP_VERSION: u16 = 0x0001;

// === IoCode1 flags -- MS-RDPEFS 2.2.2.7.1 ===

/// I/O request code bitmask (IoCode1 field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoCode1(u32);

impl IoCode1 {
    pub const RDPDR_IRP_MJ_CREATE: Self = Self(0x0000_0001);
    pub const RDPDR_IRP_MJ_CLEANUP: Self = Self(0x0000_0002);
    pub const RDPDR_IRP_MJ_CLOSE: Self = Self(0x0000_0004);
    pub const RDPDR_IRP_MJ_READ: Self = Self(0x0000_0008);
    pub const RDPDR_IRP_MJ_WRITE: Self = Self(0x0000_0010);
    pub const RDPDR_IRP_MJ_FLUSH_BUFFERS: Self = Self(0x0000_0020);
    pub const RDPDR_IRP_MJ_SHUTDOWN: Self = Self(0x0000_0040);
    pub const RDPDR_IRP_MJ_DEVICE_CONTROL: Self = Self(0x0000_0080);
    pub const RDPDR_IRP_MJ_QUERY_VOLUME_INFORMATION: Self = Self(0x0000_0100);
    pub const RDPDR_IRP_MJ_SET_VOLUME_INFORMATION: Self = Self(0x0000_0200);
    pub const RDPDR_IRP_MJ_QUERY_INFORMATION: Self = Self(0x0000_0400);
    pub const RDPDR_IRP_MJ_SET_INFORMATION: Self = Self(0x0000_0800);
    pub const RDPDR_IRP_MJ_DIRECTORY_CONTROL: Self = Self(0x0000_1000);
    pub const RDPDR_IRP_MJ_LOCK_CONTROL: Self = Self(0x0000_2000);
    pub const RDPDR_IRP_MJ_QUERY_SECURITY: Self = Self(0x0000_4000);
    pub const RDPDR_IRP_MJ_SET_SECURITY: Self = Self(0x0000_8000);

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Get raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check if all bits in `other` are set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// === ExtendedPdu flags -- MS-RDPEFS 2.2.2.7.1 ===

/// Extended PDU capability flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedPdu(u32);

impl ExtendedPdu {
    pub const RDPDR_DEVICE_REMOVE_PDUS: Self = Self(0x0000_0001);
    pub const RDPDR_CLIENT_DISPLAY_NAME_PDU: Self = Self(0x0000_0002);
    pub const RDPDR_USER_LOGGEDON_PDU: Self = Self(0x0000_0004);

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Get raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check if all bits in `other` are set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// === ExtraFlags1 flags -- MS-RDPEFS 2.2.2.7.1 ===

/// Extra capability flags (ExtraFlags1 field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtraFlags1(u32);

impl ExtraFlags1 {
    pub const NONE: Self = Self(0x0000_0000);
    pub const ENABLE_ASYNCIO: Self = Self(0x0000_0001);

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Get raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check if all bits in `other` are set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// === General Capability Set -- MS-RDPEFS 2.2.2.7.1 ===

/// General Capability Set -- MS-RDPEFS 2.2.2.7.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralCapabilitySet {
    /// OS type (informational, ignored) -- MS-RDPEFS 2.2.2.7.1
    pub os_type: u32,
    /// OS version (informational, ignored) -- MS-RDPEFS 2.2.2.7.1
    pub os_version: u32,
    /// Protocol major version; MUST be 0x0001 -- MS-RDPEFS 2.2.2.7.1
    pub protocol_major_version: u16,
    /// Protocol minor version -- MS-RDPEFS 2.2.2.7.1
    pub protocol_minor_version: u16,
    /// Supported I/O request codes -- MS-RDPEFS 2.2.2.7.1
    pub io_code1: IoCode1,
    /// Extended PDU flags -- MS-RDPEFS 2.2.2.7.1
    pub extended_pdu: ExtendedPdu,
    /// Extra flags -- MS-RDPEFS 2.2.2.7.1
    pub extra_flags1: ExtraFlags1,
    /// Number of special device types; only present in Version 2 -- MS-RDPEFS 2.2.2.7.1
    pub special_type_device_cap: Option<u32>,
}

/// V1 total size including 8-byte header -- MS-RDPEFS 2.2.2.7.1
const GENERAL_CAP_V1_SIZE: usize = 40;
/// V2 total size including 8-byte header -- MS-RDPEFS 2.2.2.7.1
const GENERAL_CAP_V2_SIZE: usize = 44;

// === CapabilitySet enum ===

/// A single capability set (header + data) -- MS-RDPEFS 2.2.1.2.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilitySet {
    /// General capability set -- MS-RDPEFS 2.2.2.7.1
    General(GeneralCapabilitySet),
    /// Printer capability set -- MS-RDPEFS 2.2.2.2
    Printer,
    /// Port capability set -- MS-RDPEFS 2.2.2.3
    Port,
    /// Drive capability set -- MS-RDPEFS 2.2.2.4
    Drive {
        /// Version field from the capability header.
        version: u32,
    },
    /// SmartCard capability set -- MS-RDPEFS 2.2.2.5
    SmartCard,
}

impl CapabilitySet {
    /// Wire size of this capability set including its 8-byte header.
    fn wire_size(&self) -> usize {
        match self {
            CapabilitySet::General(g) => {
                if g.special_type_device_cap.is_some() {
                    GENERAL_CAP_V2_SIZE
                } else {
                    GENERAL_CAP_V1_SIZE
                }
            }
            CapabilitySet::Printer | CapabilitySet::Port | CapabilitySet::SmartCard => {
                CAPABILITY_HEADER_SIZE
            }
            CapabilitySet::Drive { .. } => CAPABILITY_HEADER_SIZE,
        }
    }
}

impl Encode for CapabilitySet {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        match self {
            CapabilitySet::General(g) => {
                let is_v2 = g.special_type_device_cap.is_some();
                let version = if is_v2 {
                    GENERAL_CAPABILITY_VERSION_02
                } else {
                    GENERAL_CAPABILITY_VERSION_01
                };
                let length = if is_v2 {
                    GENERAL_CAP_V2_SIZE
                } else {
                    GENERAL_CAP_V1_SIZE
                };

                // Capability header -- MS-RDPEFS 2.2.1.2.1
                dst.write_u16_le(CAP_GENERAL_TYPE, "CapabilitySet::capabilityType")?;
                dst.write_u16_le(length as u16, "CapabilitySet::capabilityLength")?;
                dst.write_u32_le(version, "CapabilitySet::version")?;

                // General capability data -- MS-RDPEFS 2.2.2.7.1
                dst.write_u32_le(g.os_type, "GeneralCapabilitySet::osType")?;
                dst.write_u32_le(g.os_version, "GeneralCapabilitySet::osVersion")?;
                dst.write_u16_le(
                    g.protocol_major_version,
                    "GeneralCapabilitySet::protocolMajorVersion",
                )?;
                dst.write_u16_le(
                    g.protocol_minor_version,
                    "GeneralCapabilitySet::protocolMinorVersion",
                )?;
                dst.write_u32_le(g.io_code1.bits(), "GeneralCapabilitySet::ioCode1")?;
                dst.write_u32_le(0, "GeneralCapabilitySet::ioCode2")?; // MUST be 0
                dst.write_u32_le(g.extended_pdu.bits(), "GeneralCapabilitySet::extendedPDU")?;
                dst.write_u32_le(g.extra_flags1.bits(), "GeneralCapabilitySet::extraFlags1")?;
                dst.write_u32_le(0, "GeneralCapabilitySet::extraFlags2")?; // MUST be 0

                if let Some(special) = g.special_type_device_cap {
                    dst.write_u32_le(special, "GeneralCapabilitySet::specialTypeDeviceCap")?;
                }
            }
            CapabilitySet::Printer => {
                dst.write_u16_le(CAP_PRINTER_TYPE, "CapabilitySet::capabilityType")?;
                dst.write_u16_le(
                    CAPABILITY_HEADER_SIZE as u16,
                    "CapabilitySet::capabilityLength",
                )?;
                dst.write_u32_le(
                    GENERAL_CAPABILITY_VERSION_01,
                    "CapabilitySet::version",
                )?;
            }
            CapabilitySet::Port => {
                dst.write_u16_le(CAP_PORT_TYPE, "CapabilitySet::capabilityType")?;
                dst.write_u16_le(
                    CAPABILITY_HEADER_SIZE as u16,
                    "CapabilitySet::capabilityLength",
                )?;
                dst.write_u32_le(
                    GENERAL_CAPABILITY_VERSION_01,
                    "CapabilitySet::version",
                )?;
            }
            CapabilitySet::Drive { version } => {
                dst.write_u16_le(CAP_DRIVE_TYPE, "CapabilitySet::capabilityType")?;
                dst.write_u16_le(
                    CAPABILITY_HEADER_SIZE as u16,
                    "CapabilitySet::capabilityLength",
                )?;
                dst.write_u32_le(*version, "CapabilitySet::version")?;
            }
            CapabilitySet::SmartCard => {
                dst.write_u16_le(CAP_SMARTCARD_TYPE, "CapabilitySet::capabilityType")?;
                dst.write_u16_le(
                    CAPABILITY_HEADER_SIZE as u16,
                    "CapabilitySet::capabilityLength",
                )?;
                dst.write_u32_le(
                    GENERAL_CAPABILITY_VERSION_01,
                    "CapabilitySet::version",
                )?;
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CapabilitySet"
    }

    fn size(&self) -> usize {
        self.wire_size()
    }
}

impl<'de> Decode<'de> for CapabilitySet {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cap_type = src.read_u16_le("CapabilitySet::capabilityType")?;
        let cap_length = src.read_u16_le("CapabilitySet::capabilityLength")?;
        let version = src.read_u32_le("CapabilitySet::version")?;

        if (cap_length as usize) < CAPABILITY_HEADER_SIZE {
            return Err(DecodeError::invalid_value(
                "CapabilitySet",
                "capabilityLength",
            ));
        }

        let data_len = cap_length as usize - CAPABILITY_HEADER_SIZE;

        match cap_type {
            CAP_GENERAL_TYPE => {
                // V1 needs 32 bytes of data after header, V2 needs 36
                let min_data = GENERAL_CAP_V1_SIZE - CAPABILITY_HEADER_SIZE; // 32
                if data_len < min_data {
                    return Err(DecodeError::invalid_value(
                        "GeneralCapabilitySet",
                        "capabilityLength too small",
                    ));
                }

                let os_type = src.read_u32_le("GeneralCapabilitySet::osType")?;
                let os_version = src.read_u32_le("GeneralCapabilitySet::osVersion")?;
                let protocol_major_version =
                    src.read_u16_le("GeneralCapabilitySet::protocolMajorVersion")?;
                let protocol_minor_version =
                    src.read_u16_le("GeneralCapabilitySet::protocolMinorVersion")?;
                let io_code1 =
                    IoCode1::from_bits(src.read_u32_le("GeneralCapabilitySet::ioCode1")?);
                let _io_code2 = src.read_u32_le("GeneralCapabilitySet::ioCode2")?;
                let extended_pdu =
                    ExtendedPdu::from_bits(src.read_u32_le("GeneralCapabilitySet::extendedPDU")?);
                let extra_flags1 =
                    ExtraFlags1::from_bits(src.read_u32_le("GeneralCapabilitySet::extraFlags1")?);
                let _extra_flags2 = src.read_u32_le("GeneralCapabilitySet::extraFlags2")?;

                let special_type_device_cap = if version == GENERAL_CAPABILITY_VERSION_02
                    && data_len >= (GENERAL_CAP_V2_SIZE - CAPABILITY_HEADER_SIZE)
                {
                    Some(src.read_u32_le("GeneralCapabilitySet::specialTypeDeviceCap")?)
                } else {
                    None
                };

                // Skip any extra bytes beyond known fields
                let consumed = if special_type_device_cap.is_some() {
                    GENERAL_CAP_V2_SIZE - CAPABILITY_HEADER_SIZE
                } else {
                    GENERAL_CAP_V1_SIZE - CAPABILITY_HEADER_SIZE
                };
                let extra = data_len.saturating_sub(consumed);
                if extra > 0 {
                    src.skip(extra, "GeneralCapabilitySet::extra")?;
                }

                Ok(CapabilitySet::General(GeneralCapabilitySet {
                    os_type,
                    os_version,
                    protocol_major_version,
                    protocol_minor_version,
                    io_code1,
                    extended_pdu,
                    extra_flags1,
                    special_type_device_cap,
                }))
            }
            CAP_PRINTER_TYPE => {
                if data_len > 0 {
                    src.skip(data_len, "PrinterCapabilitySet::extra")?;
                }
                Ok(CapabilitySet::Printer)
            }
            CAP_PORT_TYPE => {
                if data_len > 0 {
                    src.skip(data_len, "PortCapabilitySet::extra")?;
                }
                Ok(CapabilitySet::Port)
            }
            CAP_DRIVE_TYPE => {
                if data_len > 0 {
                    src.skip(data_len, "DriveCapabilitySet::extra")?;
                }
                Ok(CapabilitySet::Drive { version })
            }
            CAP_SMARTCARD_TYPE => {
                if data_len > 0 {
                    src.skip(data_len, "SmartCardCapabilitySet::extra")?;
                }
                Ok(CapabilitySet::SmartCard)
            }
            _ => Err(DecodeError::invalid_value(
                "CapabilitySet",
                "capabilityType",
            )),
        }
    }
}

// === Capability Request PDU -- MS-RDPEFS 2.2.2.7 ===

/// Server Device Redirection Capability Request -- MS-RDPEFS 2.2.2.7
///
/// Wire format (after RDPDR_HEADER, which is handled externally):
/// ```text
/// offset  size  field
/// 0       2     numCapabilities (u16 LE)
/// 2       2     Padding         (u16 LE)
/// 4       var   CapabilitySet[]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRequestPdu {
    /// Capability sets.
    pub capabilities: Vec<CapabilitySet>,
}

impl CapabilityRequestPdu {
    /// Create a new capability request PDU.
    pub fn new(capabilities: Vec<CapabilitySet>) -> Self {
        Self { capabilities }
    }
}

impl Encode for CapabilityRequestPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let num = u16::try_from(self.capabilities.len())
            .map_err(|_| EncodeError::invalid_value("CapabilityRequestPdu", "numCapabilities too large"))?;
        dst.write_u16_le(num, "CapabilityRequestPdu::numCapabilities")?;
        dst.write_u16_le(0, "CapabilityRequestPdu::padding")?;
        for cap in &self.capabilities {
            cap.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CapabilityRequestPdu"
    }

    fn size(&self) -> usize {
        // 2 (numCapabilities) + 2 (padding) + sum of capability sizes
        4 + self.capabilities.iter().map(|c| c.size()).sum::<usize>()
    }
}

/// Maximum number of capability sets to prevent excessive allocation.
const MAX_CAPABILITIES: u16 = 64;

impl<'de> Decode<'de> for CapabilityRequestPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let num = src.read_u16_le("CapabilityRequestPdu::numCapabilities")?;
        if num > MAX_CAPABILITIES {
            return Err(DecodeError::invalid_value(
                "CapabilityRequestPdu",
                "numCapabilities",
            ));
        }
        let _padding = src.read_u16_le("CapabilityRequestPdu::padding")?;

        let mut capabilities = Vec::with_capacity(num as usize);
        for _ in 0..num {
            capabilities.push(CapabilitySet::decode(src)?);
        }

        Ok(Self { capabilities })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn general_capability_v1_roundtrip() {
        let cap = CapabilitySet::General(GeneralCapabilitySet {
            os_type: 0,
            os_version: 0,
            protocol_major_version: RDPDR_MAJOR_RDP_VERSION,
            protocol_minor_version: 0x000C,
            io_code1: IoCode1::RDPDR_IRP_MJ_CREATE
                .union(IoCode1::RDPDR_IRP_MJ_CLOSE)
                .union(IoCode1::RDPDR_IRP_MJ_READ),
            extended_pdu: ExtendedPdu::RDPDR_USER_LOGGEDON_PDU,
            extra_flags1: ExtraFlags1::NONE,
            special_type_device_cap: None,
        });

        assert_eq!(cap.size(), GENERAL_CAP_V1_SIZE);

        let mut buf = vec![0u8; cap.size()];
        let mut wc = WriteCursor::new(&mut buf);
        cap.encode(&mut wc).unwrap();

        let mut rc = ReadCursor::new(&buf);
        let decoded = CapabilitySet::decode(&mut rc).unwrap();
        assert_eq!(cap, decoded);
    }

    #[test]
    fn general_capability_v2_roundtrip() {
        let cap = CapabilitySet::General(GeneralCapabilitySet {
            os_type: 0x0002,
            os_version: 0x0001_0000,
            protocol_major_version: RDPDR_MAJOR_RDP_VERSION,
            protocol_minor_version: 0x000C,
            io_code1: IoCode1::from_bits(0x0000_FFFF),
            extended_pdu: ExtendedPdu::RDPDR_DEVICE_REMOVE_PDUS
                .union(ExtendedPdu::RDPDR_CLIENT_DISPLAY_NAME_PDU)
                .union(ExtendedPdu::RDPDR_USER_LOGGEDON_PDU),
            extra_flags1: ExtraFlags1::ENABLE_ASYNCIO,
            special_type_device_cap: Some(1),
        });

        assert_eq!(cap.size(), GENERAL_CAP_V2_SIZE);

        let mut buf = vec![0u8; cap.size()];
        let mut wc = WriteCursor::new(&mut buf);
        cap.encode(&mut wc).unwrap();

        let mut rc = ReadCursor::new(&buf);
        let decoded = CapabilitySet::decode(&mut rc).unwrap();
        assert_eq!(cap, decoded);
    }

    #[test]
    fn simple_capability_sets_roundtrip() {
        for cap in [
            CapabilitySet::Printer,
            CapabilitySet::Port,
            CapabilitySet::Drive {
                version: GENERAL_CAPABILITY_VERSION_02,
            },
            CapabilitySet::SmartCard,
        ] {
            assert_eq!(cap.size(), CAPABILITY_HEADER_SIZE);

            let mut buf = vec![0u8; cap.size()];
            let mut wc = WriteCursor::new(&mut buf);
            cap.encode(&mut wc).unwrap();

            let mut rc = ReadCursor::new(&buf);
            let decoded = CapabilitySet::decode(&mut rc).unwrap();
            assert_eq!(cap, decoded);
        }
    }

    #[test]
    fn capability_request_pdu_roundtrip() {
        let pdu = CapabilityRequestPdu::new(vec![
            CapabilitySet::General(GeneralCapabilitySet {
                os_type: 0,
                os_version: 0,
                protocol_major_version: RDPDR_MAJOR_RDP_VERSION,
                protocol_minor_version: 0x000C,
                io_code1: IoCode1::from_bits(0x0000_FFFF),
                extended_pdu: ExtendedPdu::RDPDR_USER_LOGGEDON_PDU,
                extra_flags1: ExtraFlags1::NONE,
                special_type_device_cap: Some(2),
            }),
            CapabilitySet::Printer,
            CapabilitySet::Port,
            CapabilitySet::Drive {
                version: GENERAL_CAPABILITY_VERSION_02,
            },
            CapabilitySet::SmartCard,
        ]);

        let expected_size = 4 + GENERAL_CAP_V2_SIZE + 4 * CAPABILITY_HEADER_SIZE;
        assert_eq!(pdu.size(), expected_size);

        let mut buf = vec![0u8; pdu.size()];
        let mut wc = WriteCursor::new(&mut buf);
        pdu.encode(&mut wc).unwrap();

        let mut rc = ReadCursor::new(&buf);
        let decoded = CapabilityRequestPdu::decode(&mut rc).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn capability_request_empty() {
        let pdu = CapabilityRequestPdu::new(vec![]);

        let mut buf = vec![0u8; pdu.size()];
        let mut wc = WriteCursor::new(&mut buf);
        pdu.encode(&mut wc).unwrap();

        let mut rc = ReadCursor::new(&buf);
        let decoded = CapabilityRequestPdu::decode(&mut rc).unwrap();
        assert_eq!(decoded.capabilities.len(), 0);
    }

    #[test]
    fn io_code1_contains() {
        let flags = IoCode1::RDPDR_IRP_MJ_CREATE.union(IoCode1::RDPDR_IRP_MJ_READ);
        assert!(flags.contains(IoCode1::RDPDR_IRP_MJ_CREATE));
        assert!(flags.contains(IoCode1::RDPDR_IRP_MJ_READ));
        assert!(!flags.contains(IoCode1::RDPDR_IRP_MJ_WRITE));
    }

    #[test]
    fn extended_pdu_contains() {
        let flags = ExtendedPdu::RDPDR_DEVICE_REMOVE_PDUS
            .union(ExtendedPdu::RDPDR_USER_LOGGEDON_PDU);
        assert!(flags.contains(ExtendedPdu::RDPDR_DEVICE_REMOVE_PDUS));
        assert!(flags.contains(ExtendedPdu::RDPDR_USER_LOGGEDON_PDU));
        assert!(!flags.contains(ExtendedPdu::RDPDR_CLIENT_DISPLAY_NAME_PDU));
    }
}
