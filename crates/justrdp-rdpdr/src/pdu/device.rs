#![forbid(unsafe_code)]

//! Device announce and device list PDUs -- MS-RDPEFS 2.2.1.3, 2.2.2.9, 2.2.2.1, 2.2.3.2

extern crate alloc;

use alloc::vec::Vec;
use core::str;

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeError, EncodeResult};
use justrdp_core::{Decode, Encode};

/// Maximum DeviceDataLength on decode to prevent unbounded allocation.
const MAX_DEVICE_DATA_LENGTH: u32 = 65535;

/// Maximum DeviceCount on decode to prevent unbounded allocation.
const MAX_DEVICE_COUNT: u32 = 1024;

/// Fixed size of a DEVICE_ANNOUNCE without variable DeviceData.
/// DeviceType(4) + DeviceId(4) + PreferredDosName(8) + DeviceDataLength(4) = 20
const DEVICE_ANNOUNCE_FIXED_SIZE: usize = 20;

// ── DeviceType (MS-RDPEFS 2.2.1.3) ──────────────────────────────────────────

/// Device type constants -- MS-RDPEFS 2.2.1.3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceType {
    /// Serial port device.
    Serial = 0x0000_0001,
    /// Parallel port device.
    Parallel = 0x0000_0002,
    /// Printer device.
    Printer = 0x0000_0004,
    /// File system device.
    Filesystem = 0x0000_0008,
    /// Smart card device.
    Smartcard = 0x0000_0020,
}

impl DeviceType {
    /// Convert a raw `u32` to a `DeviceType`, returning `None` for unknown values.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x0000_0001 => Some(Self::Serial),
            0x0000_0002 => Some(Self::Parallel),
            0x0000_0004 => Some(Self::Printer),
            0x0000_0008 => Some(Self::Filesystem),
            0x0000_0020 => Some(Self::Smartcard),
            _ => None,
        }
    }
}

// ── DEVICE_ANNOUNCE (MS-RDPEFS 2.2.1.3) ─────────────────────────────────────

/// DEVICE_ANNOUNCE structure -- MS-RDPEFS 2.2.1.3
///
/// ```text
/// offset  size  field
/// 0       4     DeviceType        (u32 LE)
/// 4       4     DeviceId          (u32 LE)
/// 8       8     PreferredDosName  (u8[8]) - ASCII, null-padded
/// 16      4     DeviceDataLength  (u32 LE)
/// 20      var   DeviceData
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAnnounce {
    pub device_type: DeviceType,
    pub device_id: u32,
    pub preferred_dos_name: [u8; 8],
    pub device_data: Vec<u8>,
}

impl DeviceAnnounce {
    /// Create a new `DeviceAnnounce`.
    ///
    /// `dos_name` is copied into the 8-byte `PreferredDosName` field, null-padded.
    /// At most 7 characters are used (the 8th byte is always null).
    pub fn new(device_type: DeviceType, device_id: u32, dos_name: &str, device_data: Vec<u8>) -> Self {
        let mut preferred_dos_name = [0u8; 8];
        let name_bytes = dos_name.as_bytes();
        let copy_len = name_bytes.len().min(7);
        preferred_dos_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        Self {
            device_type,
            device_id,
            preferred_dos_name,
            device_data,
        }
    }

    /// Return the preferred DOS name as a `&str`, up to the first null byte.
    pub fn dos_name_str(&self) -> &str {
        let end = self
            .preferred_dos_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(8);
        // The name should be ASCII; if it's not valid UTF-8 we fall back to empty.
        str::from_utf8(&self.preferred_dos_name[..end]).unwrap_or("")
    }

    /// Create a filesystem drive device announce.
    ///
    /// `device_id` is a client-assigned unique ID.
    /// `dos_name` is the drive letter (e.g., `"C:"`).
    /// `display_name` is an optional Unicode display name sent as DeviceData
    /// when DRIVE_CAPABILITY_VERSION_02 is negotiated.
    ///
    /// MS-RDPEFS 2.2.3.1
    pub fn filesystem(device_id: u32, dos_name: &str, display_name: Option<&str>) -> Self {
        let device_data = match display_name {
            Some(name) => encode_utf16le_null(name),
            None => Vec::new(),
        };
        Self::new(DeviceType::Filesystem, device_id, dos_name, device_data)
    }

    /// Create a smart card device announce.
    ///
    /// PreferredDosName is always `"SCARD"` per MS-RDPESC.
    /// DeviceDataLength is always 0.
    pub fn smartcard(device_id: u32) -> Self {
        Self::new(DeviceType::Smartcard, device_id, "SCARD", Vec::new())
    }

    /// Create a printer device announce.
    ///
    /// `device_id` is a client-assigned unique ID.
    /// `dos_name` is the printer name (max 7 chars).
    /// `device_data` is the printer-specific data per MS-RDPEPC 2.2.2.1.
    pub fn printer(device_id: u32, dos_name: &str, device_data: Vec<u8>) -> Self {
        Self::new(DeviceType::Printer, device_id, dos_name, device_data)
    }
}

/// Encode a string as null-terminated UTF-16LE.
fn encode_utf16le_null(s: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for code_unit in s.encode_utf16() {
        buf.extend_from_slice(&code_unit.to_le_bytes());
    }
    buf.extend_from_slice(&[0x00, 0x00]);
    buf
}

impl Encode for DeviceAnnounce {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.device_type as u32, "DeviceAnnounce::DeviceType")?;
        dst.write_u32_le(self.device_id, "DeviceAnnounce::DeviceId")?;
        dst.write_slice(&self.preferred_dos_name, "DeviceAnnounce::PreferredDosName")?;
        let data_len = u32::try_from(self.device_data.len())
            .map_err(|_| EncodeError::invalid_value("DeviceAnnounce", "DeviceDataLength too large"))?;
        dst.write_u32_le(data_len, "DeviceAnnounce::DeviceDataLength")?;
        if !self.device_data.is_empty() {
            dst.write_slice(&self.device_data, "DeviceAnnounce::DeviceData")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DeviceAnnounce"
    }

    fn size(&self) -> usize {
        DEVICE_ANNOUNCE_FIXED_SIZE + self.device_data.len()
    }
}

impl<'de> Decode<'de> for DeviceAnnounce {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let device_type_raw = src.read_u32_le("DeviceAnnounce::DeviceType")?;
        let device_type = DeviceType::from_u32(device_type_raw).ok_or_else(|| {
            DecodeError::invalid_value("DeviceAnnounce", "DeviceType")
        })?;

        let device_id = src.read_u32_le("DeviceAnnounce::DeviceId")?;

        let dos_name_bytes = src.read_slice(8, "DeviceAnnounce::PreferredDosName")?;
        let mut preferred_dos_name = [0u8; 8];
        preferred_dos_name.copy_from_slice(dos_name_bytes);

        let device_data_length = src.read_u32_le("DeviceAnnounce::DeviceDataLength")?;
        if device_data_length > MAX_DEVICE_DATA_LENGTH {
            return Err(DecodeError::invalid_value(
                "DeviceAnnounce",
                "DeviceDataLength",
            ));
        }

        let device_data = if device_data_length > 0 {
            src.read_slice(device_data_length as usize, "DeviceAnnounce::DeviceData")?
                .to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            device_type,
            device_id,
            preferred_dos_name,
            device_data,
        })
    }
}

// ── DeviceListAnnouncePdu (MS-RDPEFS 2.2.2.9) ───────────────────────────────

/// DR_DEVICELIST_ANNOUNCE body (no RDPDR_HEADER) -- MS-RDPEFS 2.2.2.9
///
/// ```text
/// offset  size  field
/// 0       4     DeviceCount  (u32 LE)
/// 4       var   DeviceList[] - array of DeviceCount DEVICE_ANNOUNCE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceListAnnouncePdu {
    pub devices: Vec<DeviceAnnounce>,
}

impl Encode for DeviceListAnnouncePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.devices.len() as u32, "DeviceListAnnouncePdu::DeviceCount")?;
        for device in &self.devices {
            device.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DeviceListAnnouncePdu"
    }

    fn size(&self) -> usize {
        4 + self.devices.iter().map(|d| d.size()).sum::<usize>()
    }
}

impl<'de> Decode<'de> for DeviceListAnnouncePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let device_count = src.read_u32_le("DeviceListAnnouncePdu::DeviceCount")?;
        if device_count > MAX_DEVICE_COUNT {
            return Err(DecodeError::invalid_value(
                "DeviceListAnnouncePdu",
                "DeviceCount",
            ));
        }

        let mut devices = Vec::with_capacity(device_count as usize);
        for _ in 0..device_count {
            devices.push(DeviceAnnounce::decode(src)?);
        }

        Ok(Self { devices })
    }
}

// ── DeviceAnnounceResponsePdu (MS-RDPEFS 2.2.2.1) ───────────────────────────

/// DR_DEVICE_ANNOUNCE_RSP body (no RDPDR_HEADER) -- MS-RDPEFS 2.2.2.1
///
/// ```text
/// offset  size  field
/// 0       4     DeviceId    (u32 LE)
/// 4       4     ResultCode  (u32 LE) - NTSTATUS
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAnnounceResponsePdu {
    pub device_id: u32,
    pub result_code: u32,
}

impl Encode for DeviceAnnounceResponsePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.device_id, "DeviceAnnounceResponsePdu::DeviceId")?;
        dst.write_u32_le(self.result_code, "DeviceAnnounceResponsePdu::ResultCode")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DeviceAnnounceResponsePdu"
    }

    fn size(&self) -> usize {
        8
    }
}

impl<'de> Decode<'de> for DeviceAnnounceResponsePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let device_id = src.read_u32_le("DeviceAnnounceResponsePdu::DeviceId")?;
        let result_code = src.read_u32_le("DeviceAnnounceResponsePdu::ResultCode")?;
        Ok(Self {
            device_id,
            result_code,
        })
    }
}

// ── DeviceListRemovePdu (MS-RDPEFS 2.2.3.2) ─────────────────────────────────

/// DR_DEVICELIST_REMOVE body (no RDPDR_HEADER) -- MS-RDPEFS 2.2.3.2
///
/// ```text
/// offset  size  field
/// 0       4     DeviceCount  (u32 LE)
/// 4       var   DeviceIds[]  - array of DeviceCount u32 LE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceListRemovePdu {
    pub device_ids: Vec<u32>,
}

impl Encode for DeviceListRemovePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.device_ids.len() as u32, "DeviceListRemovePdu::DeviceCount")?;
        for &id in &self.device_ids {
            dst.write_u32_le(id, "DeviceListRemovePdu::DeviceId")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DeviceListRemovePdu"
    }

    fn size(&self) -> usize {
        4 + self.device_ids.len() * 4
    }
}

impl<'de> Decode<'de> for DeviceListRemovePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let device_count = src.read_u32_le("DeviceListRemovePdu::DeviceCount")?;
        if device_count > MAX_DEVICE_COUNT {
            return Err(DecodeError::invalid_value(
                "DeviceListRemovePdu",
                "DeviceCount",
            ));
        }

        let mut device_ids = Vec::with_capacity(device_count as usize);
        for _ in 0..device_count {
            device_ids.push(src.read_u32_le("DeviceListRemovePdu::DeviceId")?);
        }

        Ok(Self { device_ids })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn device_announce_roundtrip() {
        let announce = DeviceAnnounce::new(
            DeviceType::Filesystem,
            42,
            "MYFS",
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );

        assert_eq!(announce.dos_name_str(), "MYFS");
        assert_eq!(announce.size(), 24);

        let mut buf = vec![0u8; announce.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        announce.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeviceAnnounce::decode(&mut cursor).unwrap();
        assert_eq!(announce, decoded);
    }

    #[test]
    fn device_announce_empty_device_data() {
        let announce = DeviceAnnounce::new(DeviceType::Smartcard, 1, "SCARD", Vec::new());

        assert_eq!(announce.dos_name_str(), "SCARD");
        assert_eq!(announce.device_data.len(), 0);
        assert_eq!(announce.size(), DEVICE_ANNOUNCE_FIXED_SIZE);

        let mut buf = vec![0u8; announce.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        announce.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeviceAnnounce::decode(&mut cursor).unwrap();
        assert_eq!(announce, decoded);
    }

    #[test]
    fn device_announce_dos_name_truncated_to_7() {
        let announce = DeviceAnnounce::new(DeviceType::Serial, 0, "LONGNAME", Vec::new());
        // Only first 7 chars are kept, 8th is null.
        assert_eq!(announce.dos_name_str(), "LONGNAM");
        assert_eq!(announce.preferred_dos_name[7], 0);
    }

    #[test]
    fn device_list_announce_roundtrip() {
        let pdu = DeviceListAnnouncePdu {
            devices: vec![
                DeviceAnnounce::new(DeviceType::Filesystem, 1, "FS1", vec![0x01, 0x02]),
                DeviceAnnounce::new(DeviceType::Printer, 2, "PRN", Vec::new()),
            ],
        };

        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeviceListAnnouncePdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn device_announce_response_roundtrip() {
        let pdu = DeviceAnnounceResponsePdu {
            device_id: 42,
            result_code: 0x0000_0000, // STATUS_SUCCESS
        };

        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeviceAnnounceResponsePdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn device_announce_filesystem_no_display_name() {
        let announce = DeviceAnnounce::filesystem(1, "C:", None);
        assert_eq!(announce.device_type, DeviceType::Filesystem);
        assert_eq!(announce.device_id, 1);
        assert_eq!(announce.dos_name_str(), "C:");
        assert!(announce.device_data.is_empty());

        let mut buf = vec![0u8; announce.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        announce.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeviceAnnounce::decode(&mut cursor).unwrap();
        assert_eq!(announce, decoded);
    }

    #[test]
    fn device_announce_filesystem_with_display_name() {
        let announce = DeviceAnnounce::filesystem(2, "D:", Some("Data Drive"));
        assert_eq!(announce.device_type, DeviceType::Filesystem);
        assert_eq!(announce.dos_name_str(), "D:");
        // DeviceData is UTF-16LE null-terminated "Data Drive"
        assert!(!announce.device_data.is_empty());
        // 10 chars × 2 bytes + 2 null = 22 bytes
        assert_eq!(announce.device_data.len(), 22);

        let mut buf = vec![0u8; announce.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        announce.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeviceAnnounce::decode(&mut cursor).unwrap();
        assert_eq!(announce, decoded);
    }

    #[test]
    fn device_announce_smartcard() {
        let announce = DeviceAnnounce::smartcard(10);
        assert_eq!(announce.device_type, DeviceType::Smartcard);
        assert_eq!(announce.dos_name_str(), "SCARD");
        assert!(announce.device_data.is_empty());
        assert_eq!(announce.size(), DEVICE_ANNOUNCE_FIXED_SIZE);
    }

    #[test]
    fn device_announce_printer() {
        let announce = DeviceAnnounce::printer(5, "PRN1", vec![0x01, 0x02, 0x03]);
        assert_eq!(announce.device_type, DeviceType::Printer);
        assert_eq!(announce.dos_name_str(), "PRN1");
        assert_eq!(announce.device_data.len(), 3);
    }

    #[test]
    fn device_list_remove_roundtrip() {
        let pdu = DeviceListRemovePdu {
            device_ids: vec![1, 2, 3],
        };

        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DeviceListRemovePdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }
}
