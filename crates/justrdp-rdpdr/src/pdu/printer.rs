#![forbid(unsafe_code)]

//! Printer redirection PDUs -- MS-RDPEPC
//!
//! Printer-specific PDU types for the RDPDR channel.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeResult};
use justrdp_core::{ReadCursor, WriteCursor};

use super::util::decode_utf16le;

// ── Printer Announce Flags -- MS-RDPEPC 2.2.2.1 ─────────────────────────────

/// Printer announce flags -- MS-RDPEPC 2.2.2.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrinterFlags(u32);

impl PrinterFlags {
    /// No special flags.
    pub const NONE: Self = Self(0x0000_0000);
    /// RDPDR_PRINTER_ANNOUNCE_FLAG_ASCII -- strings are ASCII, not UTF-16LE.
    pub const ASCII: Self = Self(0x0000_0001);
    /// RDPDR_PRINTER_ANNOUNCE_FLAG_DEFAULTPRINTER -- this is the default printer.
    pub const DEFAULT_PRINTER: Self = Self(0x0000_0002);
    /// RDPDR_PRINTER_ANNOUNCE_FLAG_NETWORKPRINTER -- network printer.
    pub const NETWORK_PRINTER: Self = Self(0x0000_0004);
    /// RDPDR_PRINTER_ANNOUNCE_FLAG_TSPRINTER -- TS (EasyPrint) printer.
    pub const TS_PRINTER: Self = Self(0x0000_0008);
    /// RDPDR_PRINTER_ANNOUNCE_FLAG_XPSFORMAT -- client supports XPS output.
    pub const XPS_FORMAT: Self = Self(0x0000_0010);

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// ── DR_PRN_DEVICE_ANNOUNCE DeviceData -- MS-RDPEPC 2.2.2.1 ──────────────────

/// Printer device data (content of DeviceAnnounce.device_data for RDPDR_DTYP_PRINT).
///
/// ```text
/// offset  size  field
/// 0       4     Flags            (u32 LE)
/// 4       4     CodePage         (u32 LE)
/// 8       4     PnpNameLen       (u32 LE) - bytes
/// 12      4     DriverNameLen    (u32 LE) - bytes
/// 16      4     PrinterNameLen   (u32 LE) - bytes
/// 20      4     CachedFieldsLen  (u32 LE) - bytes
/// 24      var   PnpName          - null-terminated UTF-16LE
/// 24+a    var   DriverName       - null-terminated UTF-16LE
/// 24+a+b  var   PrinterName      - null-terminated UTF-16LE
/// ...     var   CachedFields     - opaque blob
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrinterDeviceData {
    /// Printer announce flags.
    pub flags: PrinterFlags,
    /// Code page for the printer name (0 = Unicode).
    pub code_page: u32,
    /// PnP device name (UTF-16LE, may be empty).
    pub pnp_name: String,
    /// Printer driver name (UTF-16LE).
    pub driver_name: String,
    /// Printer display name (UTF-16LE).
    pub printer_name: String,
    /// Cached printer configuration data (opaque).
    pub cached_fields: Vec<u8>,
}

/// Fixed header size: Flags(4) + CodePage(4) + PnpNameLen(4) + DriverNameLen(4)
/// + PrinterNameLen(4) + CachedFieldsLen(4) = 24
const PRINTER_DATA_FIXED_SIZE: usize = 24;

/// Maximum printer data length on decode.
const MAX_PRINTER_DATA_LEN: u32 = 1024 * 1024; // 1 MB

impl PrinterDeviceData {
    /// Encode a string as null-terminated UTF-16LE and return the byte length.
    fn encode_name(s: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        for code_unit in s.encode_utf16() {
            buf.extend_from_slice(&code_unit.to_le_bytes());
        }
        buf.extend_from_slice(&[0x00, 0x00]);
        buf
    }

    /// Encode into a byte vector suitable for DeviceAnnounce.device_data.
    pub fn to_device_data(&self) -> Vec<u8> {
        let pnp_bytes = Self::encode_name(&self.pnp_name);
        let driver_bytes = Self::encode_name(&self.driver_name);
        let printer_bytes = Self::encode_name(&self.printer_name);

        let total = PRINTER_DATA_FIXED_SIZE
            + pnp_bytes.len()
            + driver_bytes.len()
            + printer_bytes.len()
            + self.cached_fields.len();

        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&self.flags.bits().to_le_bytes());
        buf.extend_from_slice(&self.code_page.to_le_bytes());
        buf.extend_from_slice(&(pnp_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(driver_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(printer_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(self.cached_fields.len() as u32).to_le_bytes());
        buf.extend_from_slice(&pnp_bytes);
        buf.extend_from_slice(&driver_bytes);
        buf.extend_from_slice(&printer_bytes);
        buf.extend_from_slice(&self.cached_fields);
        buf
    }

    /// Decode from DeviceAnnounce.device_data bytes.
    pub fn from_device_data(data: &[u8]) -> DecodeResult<Self> {
        let mut src = ReadCursor::new(data);

        let flags = PrinterFlags::from_bits(src.read_u32_le("PrinterDeviceData::Flags")?);
        let code_page = src.read_u32_le("PrinterDeviceData::CodePage")?;
        let pnp_name_len = src.read_u32_le("PrinterDeviceData::PnpNameLen")?;
        let driver_name_len = src.read_u32_le("PrinterDeviceData::DriverNameLen")?;
        let printer_name_len = src.read_u32_le("PrinterDeviceData::PrinterNameLen")?;
        let cached_fields_len = src.read_u32_le("PrinterDeviceData::CachedFieldsLen")?;

        for (name, len) in [
            ("PnpNameLen", pnp_name_len),
            ("DriverNameLen", driver_name_len),
            ("PrinterNameLen", printer_name_len),
            ("CachedFieldsLen", cached_fields_len),
        ] {
            if len > MAX_PRINTER_DATA_LEN {
                return Err(DecodeError::invalid_value("PrinterDeviceData", name));
            }
        }

        let pnp_name = decode_utf16le(
            src.read_slice(pnp_name_len as usize, "PrinterDeviceData::PnpName")?,
        );
        let driver_name = decode_utf16le(
            src.read_slice(driver_name_len as usize, "PrinterDeviceData::DriverName")?,
        );
        let printer_name = decode_utf16le(
            src.read_slice(printer_name_len as usize, "PrinterDeviceData::PrinterName")?,
        );
        let cached_fields = src
            .read_slice(cached_fields_len as usize, "PrinterDeviceData::CachedFields")?
            .to_vec();

        Ok(Self {
            flags,
            code_page,
            pnp_name,
            driver_name,
            printer_name,
            cached_fields,
        })
    }
}

// ── DR_PRN_USING_XPS -- MS-RDPEPC 2.2.2.2 ──────────────────────────────────

/// Server Printer Set XPS Mode -- MS-RDPEPC 2.2.2.2
///
/// Body after RDPDR_HEADER (Component=PRN, PacketId=PRN_USING_XPS):
/// ```text
/// offset  size  field
/// 0       4     PrinterId  (u32 LE)
/// 4       4     Flags      (u32 LE)
/// total   8 bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrinterUsingXpsPdu {
    /// The printer device ID that should use XPS.
    pub printer_id: u32,
    /// Flags (implementation-specific).
    pub flags: u32,
}

impl Encode for PrinterUsingXpsPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.printer_id, "PrinterUsingXpsPdu::PrinterId")?;
        dst.write_u32_le(self.flags, "PrinterUsingXpsPdu::Flags")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "PrinterUsingXpsPdu"
    }

    fn size(&self) -> usize {
        8
    }
}

impl<'de> Decode<'de> for PrinterUsingXpsPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let printer_id = src.read_u32_le("PrinterUsingXpsPdu::PrinterId")?;
        let flags = src.read_u32_le("PrinterUsingXpsPdu::Flags")?;
        Ok(Self { printer_id, flags })
    }
}

// ── DR_PRN_CACHE_DATA -- MS-RDPEPC 2.2.2.3 ──────────────────────────────────

/// Printer cache event type -- MS-RDPEPC 2.2.2.3-2.2.2.6
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PrinterCacheEventId {
    /// RDPDR_ADD_PRINTER_EVENT -- MS-RDPEPC 2.2.2.3
    Add = 0x0000_0001,
    /// RDPDR_UPDATE_PRINTER_EVENT -- MS-RDPEPC 2.2.2.4
    Update = 0x0000_0002,
    /// RDPDR_DELETE_PRINTER_EVENT -- MS-RDPEPC 2.2.2.5
    Delete = 0x0000_0003,
    /// RDPDR_RENAME_PRINTER_EVENT -- MS-RDPEPC 2.2.2.6
    Rename = 0x0000_0004,
}

impl PrinterCacheEventId {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x0000_0001 => Some(Self::Add),
            0x0000_0002 => Some(Self::Update),
            0x0000_0003 => Some(Self::Delete),
            0x0000_0004 => Some(Self::Rename),
            _ => None,
        }
    }
}

/// Server Printer Cache Data -- MS-RDPEPC 2.2.2.3
///
/// Body after RDPDR_HEADER (Component=PRN, PacketId=PRN_CACHE_DATA):
/// ```text
/// offset  size  field
/// 0       4     EventId     (u32 LE)
/// 4       var   EventData   (depends on EventId)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrinterCacheDataPdu {
    /// Cache event type.
    pub event_id: PrinterCacheEventId,
    /// Raw event data (interpretation depends on event_id).
    pub event_data: Vec<u8>,
}

const MAX_CACHE_DATA_LEN: usize = 1024 * 1024; // 1 MB

impl Encode for PrinterCacheDataPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.event_id as u32, "PrinterCacheDataPdu::EventId")?;
        if !self.event_data.is_empty() {
            dst.write_slice(&self.event_data, "PrinterCacheDataPdu::EventData")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "PrinterCacheDataPdu"
    }

    fn size(&self) -> usize {
        4 + self.event_data.len()
    }
}

impl<'de> Decode<'de> for PrinterCacheDataPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let event_id_raw = src.read_u32_le("PrinterCacheDataPdu::EventId")?;
        let event_id = PrinterCacheEventId::from_u32(event_id_raw)
            .ok_or_else(|| DecodeError::invalid_value("PrinterCacheDataPdu", "EventId"))?;
        let remaining = src.remaining();
        if remaining > MAX_CACHE_DATA_LEN {
            return Err(DecodeError::invalid_value(
                "PrinterCacheDataPdu",
                "EventData too large",
            ));
        }
        let event_data = if remaining > 0 {
            src.read_slice(remaining, "PrinterCacheDataPdu::EventData")?
                .to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            event_id,
            event_data,
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn printer_device_data_roundtrip() {
        let data = PrinterDeviceData {
            flags: PrinterFlags::DEFAULT_PRINTER.union(PrinterFlags::XPS_FORMAT),
            code_page: 0,
            pnp_name: String::new(),
            driver_name: String::from("Apollo P-1200"),
            printer_name: String::from("Apollo P-1200"),
            cached_fields: Vec::new(),
        };

        let encoded = data.to_device_data();
        let decoded = PrinterDeviceData::from_device_data(&encoded).unwrap();

        assert_eq!(decoded.flags, data.flags);
        assert_eq!(decoded.code_page, 0);
        assert_eq!(decoded.pnp_name, "");
        assert_eq!(decoded.driver_name, "Apollo P-1200");
        assert_eq!(decoded.printer_name, "Apollo P-1200");
        assert!(decoded.cached_fields.is_empty());
    }

    #[test]
    fn printer_device_data_with_cached_fields() {
        let data = PrinterDeviceData {
            flags: PrinterFlags::NONE,
            code_page: 0,
            pnp_name: String::from("PnP Name"),
            driver_name: String::from("Driver"),
            printer_name: String::from("Printer"),
            cached_fields: vec![0x01, 0x02, 0x03, 0x04],
        };

        let encoded = data.to_device_data();
        let decoded = PrinterDeviceData::from_device_data(&encoded).unwrap();
        assert_eq!(decoded.pnp_name, "PnP Name");
        assert_eq!(decoded.cached_fields, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn printer_flags_contains() {
        let flags = PrinterFlags::DEFAULT_PRINTER.union(PrinterFlags::XPS_FORMAT);
        assert!(flags.contains(PrinterFlags::DEFAULT_PRINTER));
        assert!(flags.contains(PrinterFlags::XPS_FORMAT));
        assert!(!flags.contains(PrinterFlags::NETWORK_PRINTER));
    }

    #[test]
    fn printer_using_xps_roundtrip() {
        let pdu = PrinterUsingXpsPdu {
            printer_id: 1,
            flags: 0x7FFA_5BF8,
        };

        let mut buf = [0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = PrinterUsingXpsPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn printer_using_xps_known_bytes() {
        // From MS-RDPEPC example
        #[rustfmt::skip]
        let bytes = [
            0x01, 0x00, 0x00, 0x00, // PrinterId = 1
            0xF8, 0x5B, 0xFA, 0x7F, // Flags = 0x7FFA5BF8
        ];
        let mut cursor = ReadCursor::new(&bytes);
        let pdu = PrinterUsingXpsPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu.printer_id, 1);
        assert_eq!(pdu.flags, 0x7FFA_5BF8);
    }

    #[test]
    fn printer_cache_data_roundtrip() {
        let pdu = PrinterCacheDataPdu {
            event_id: PrinterCacheEventId::Update,
            event_data: vec![0xAA, 0xBB, 0xCC],
        };

        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = PrinterCacheDataPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn printer_cache_data_empty() {
        let pdu = PrinterCacheDataPdu {
            event_id: PrinterCacheEventId::Delete,
            event_data: Vec::new(),
        };

        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = PrinterCacheDataPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }
}
