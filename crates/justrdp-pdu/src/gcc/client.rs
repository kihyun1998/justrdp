#![forbid(unsafe_code)]

//! GCC Client Data Blocks -- MS-RDPBCGR 2.2.1.3
//!
//! Each block starts with a header (type: u16 LE, length: u16 LE).

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

use super::{write_block_header, read_block_header, ClientDataBlockType, DATA_BLOCK_HEADER_SIZE};

// ── ClientCoreData (CS_CORE 0xC001) ──

/// RDP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RdpVersion {
    V4 = 0x00080001,
    V5Plus = 0x00080004,
    V10 = 0x00080005,
    V10_1 = 0x00080006,
    V10_2 = 0x00080007,
    V10_3 = 0x00080008,
    V10_4 = 0x00080009,
    V10_5 = 0x0008000A,
    V10_6 = 0x0008000B,
    V10_7 = 0x0008000C,
    V10_8 = 0x0008000D,
    V10_9 = 0x0008000E,
    V10_10 = 0x0008000F,
    V10_11 = 0x00080010,
    V10_12 = 0x00080011,
}

impl RdpVersion {
    pub fn from_u32(val: u32) -> Self {
        match val {
            0x00080001 => Self::V4,
            0x00080004 => Self::V5Plus,
            0x00080005 => Self::V10,
            0x00080006 => Self::V10_1,
            0x00080007 => Self::V10_2,
            0x00080008 => Self::V10_3,
            0x00080009 => Self::V10_4,
            0x0008000A => Self::V10_5,
            0x0008000B => Self::V10_6,
            0x0008000C => Self::V10_7,
            0x0008000D => Self::V10_8,
            0x0008000E => Self::V10_9,
            0x0008000F => Self::V10_10,
            0x00080010 => Self::V10_11,
            0x00080011 => Self::V10_12,
            _ => Self::V5Plus, // fallback to common version
        }
    }
}

/// Color depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ColorDepth {
    Bpp4 = 0xCA00,
    Bpp8 = 0xCA01,
    Bpp15 = 0xCA02,
    Bpp16 = 0xCA03,
    Bpp24 = 0xCA04,
}

impl ColorDepth {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0xCA00 => Self::Bpp4,
            0xCA01 => Self::Bpp8,
            0xCA02 => Self::Bpp15,
            0xCA03 => Self::Bpp16,
            0xCA04 => Self::Bpp24,
            _ => Self::Bpp8,
        }
    }
}

/// High color depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HighColorDepth {
    Bpp4 = 0x0004,
    Bpp8 = 0x0008,
    Bpp15 = 0x000F,
    Bpp16 = 0x0010,
    Bpp24 = 0x0018,
}

impl HighColorDepth {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0x0004 => Self::Bpp4,
            0x0008 => Self::Bpp8,
            0x000F => Self::Bpp15,
            0x0010 => Self::Bpp16,
            0x0018 => Self::Bpp24,
            _ => Self::Bpp24,
        }
    }
}

/// Supported color depth flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportedColorDepths(u16);

impl SupportedColorDepths {
    pub const BPP24: Self = Self(0x0001);
    pub const BPP16: Self = Self(0x0002);
    pub const BPP15: Self = Self(0x0004);
    pub const BPP32: Self = Self(0x0008);

    pub fn from_bits(bits: u16) -> Self { Self(bits) }
    pub fn bits(&self) -> u16 { self.0 }
}

/// Connection type (for auto-detect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ConnectionType {
    Unknown = 0x00,
    Modem = 0x01,
    BroadbandLow = 0x02,
    Satellite = 0x03,
    BroadbandHigh = 0x04,
    Wan = 0x05,
    Lan = 0x06,
    Autodetect = 0x07,
}

/// Early capability flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EarlyCapabilityFlags(u16);

impl EarlyCapabilityFlags {
    pub const SUPPORT_ERRINFO_PDU: Self = Self(0x0001);
    pub const WANT_32BPP_SESSION: Self = Self(0x0002);
    pub const SUPPORT_STATUSINFO_PDU: Self = Self(0x0004);
    pub const STRONG_ASYMMETRIC_KEYS: Self = Self(0x0008);
    pub const SUPPORT_MONITOR_LAYOUT_PDU: Self = Self(0x0040);
    pub const SUPPORT_NETCHAR_AUTODETECT: Self = Self(0x0080);
    pub const SUPPORT_DYNVC_GFX_PROTOCOL: Self = Self(0x0100);
    pub const SUPPORT_DYNAMIC_TIME_ZONE: Self = Self(0x0200);
    pub const SUPPORT_HEARTBEAT_PDU: Self = Self(0x0400);

    pub fn from_bits(bits: u16) -> Self { Self(bits) }
    pub fn bits(&self) -> u16 { self.0 }
    pub fn contains(&self, other: Self) -> bool { (self.0 & other.0) == other.0 }
}

/// Client Core Data (CS_CORE).
///
/// The most important client data block, carrying resolution, color depth,
/// keyboard info, client name, and capability flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCoreData {
    pub version: RdpVersion,
    pub desktop_width: u16,
    pub desktop_height: u16,
    pub color_depth: ColorDepth,
    pub sas_sequence: u16,
    pub keyboard_layout: u32,
    pub client_build: u32,
    pub client_name: String, // UTF-16LE on wire, max 15 chars + null
    pub keyboard_type: u32,
    pub keyboard_sub_type: u32,
    pub keyboard_function_key: u32,
    pub ime_file_name: [u8; 64],
    // Optional fields (present based on block length)
    pub post_beta2_color_depth: Option<ColorDepth>,
    pub client_product_id: Option<u16>,
    pub serial_number: Option<u32>,
    pub high_color_depth: Option<HighColorDepth>,
    pub supported_color_depths: Option<SupportedColorDepths>,
    pub early_capability_flags: Option<EarlyCapabilityFlags>,
    pub client_dig_product_id: Option<[u8; 64]>,
    pub connection_type: Option<u8>,
    pub pad1: Option<u8>,
    pub server_selected_protocol: Option<u32>,
    // RDP 10.0+ fields
    pub desktop_physical_width: Option<u32>,
    pub desktop_physical_height: Option<u32>,
    pub desktop_orientation: Option<u16>,
    pub desktop_scale_factor: Option<u32>,
    pub device_scale_factor: Option<u32>,
}

/// Fixed size of ClientCoreData up to imeFileName.
const CLIENT_CORE_FIXED_SIZE: usize = 4 + 2 + 2 + 2 + 2 + 4 + 4 + 32 + 4 + 4 + 4 + 64;

impl ClientCoreData {
    /// Create with typical defaults for an RDP 5+ connection.
    pub fn new(width: u16, height: u16) -> Self {
        Self {
            version: RdpVersion::V10_12,
            desktop_width: width,
            desktop_height: height,
            color_depth: ColorDepth::Bpp8,
            sas_sequence: 0xAA03, // RNS_UD_SAS_DEL
            keyboard_layout: 0x0409, // US English
            client_build: 22621,
            client_name: String::new(),
            keyboard_type: 4, // IBM enhanced (101/102)
            keyboard_sub_type: 0,
            keyboard_function_key: 12,
            ime_file_name: [0u8; 64],
            post_beta2_color_depth: Some(ColorDepth::Bpp8),
            client_product_id: Some(1),
            serial_number: Some(0),
            high_color_depth: Some(HighColorDepth::Bpp16),
            supported_color_depths: Some(SupportedColorDepths::from_bits(0x000F)),
            early_capability_flags: Some(EarlyCapabilityFlags::SUPPORT_ERRINFO_PDU),
            client_dig_product_id: Some([0u8; 64]),
            connection_type: Some(0),
            pad1: Some(0),
            server_selected_protocol: Some(0),
            desktop_physical_width: Some(0),
            desktop_physical_height: Some(0),
            desktop_orientation: Some(0),
            desktop_scale_factor: Some(0),
            device_scale_factor: Some(0),
        }
    }

    fn optional_size(&self) -> usize {
        let mut size = 0;
        if self.post_beta2_color_depth.is_some() { size += 2; } else { return size; }
        if self.client_product_id.is_some() { size += 2; } else { return size; }
        if self.serial_number.is_some() { size += 4; } else { return size; }
        if self.high_color_depth.is_some() { size += 2; } else { return size; }
        if self.supported_color_depths.is_some() { size += 2; } else { return size; }
        if self.early_capability_flags.is_some() { size += 2; } else { return size; }
        if self.client_dig_product_id.is_some() { size += 64; } else { return size; }
        if self.connection_type.is_some() { size += 1; } else { return size; }
        if self.pad1.is_some() { size += 1; } else { return size; }
        if self.server_selected_protocol.is_some() { size += 4; } else { return size; }
        if self.desktop_physical_width.is_some() { size += 4; } else { return size; }
        if self.desktop_physical_height.is_some() { size += 4; } else { return size; }
        if self.desktop_orientation.is_some() { size += 2; } else { return size; }
        if self.desktop_scale_factor.is_some() { size += 4; } else { return size; }
        if self.device_scale_factor.is_some() { size += 4; } else { return size; }
        size
    }
}

impl Encode for ClientCoreData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let total = DATA_BLOCK_HEADER_SIZE + CLIENT_CORE_FIXED_SIZE + self.optional_size();
        write_block_header(dst, ClientDataBlockType::CoreData as u16, total as u16, "ClientCoreData::header")?;

        dst.write_u32_le(self.version as u32, "ClientCoreData::version")?;
        dst.write_u16_le(self.desktop_width, "ClientCoreData::desktopWidth")?;
        dst.write_u16_le(self.desktop_height, "ClientCoreData::desktopHeight")?;
        dst.write_u16_le(self.color_depth as u16, "ClientCoreData::colorDepth")?;
        dst.write_u16_le(self.sas_sequence, "ClientCoreData::sasSequence")?;
        dst.write_u32_le(self.keyboard_layout, "ClientCoreData::keyboardLayout")?;
        dst.write_u32_le(self.client_build, "ClientCoreData::clientBuild")?;

        // Client name: UTF-16LE, 32 bytes (15 chars + null)
        let mut name_buf = [0u8; 32];
        let mut offset = 0;
        for ch in self.client_name.encode_utf16().take(15) {
            let bytes = ch.to_le_bytes();
            name_buf[offset] = bytes[0];
            name_buf[offset + 1] = bytes[1];
            offset += 2;
        }
        dst.write_slice(&name_buf, "ClientCoreData::clientName")?;

        dst.write_u32_le(self.keyboard_type, "ClientCoreData::keyboardType")?;
        dst.write_u32_le(self.keyboard_sub_type, "ClientCoreData::keyboardSubType")?;
        dst.write_u32_le(self.keyboard_function_key, "ClientCoreData::keyboardFuncKey")?;
        dst.write_slice(&self.ime_file_name, "ClientCoreData::imeFileName")?;

        // Optional fields
        if let Some(v) = self.post_beta2_color_depth { dst.write_u16_le(v as u16, "ClientCoreData::postBeta2ColorDepth")?; } else { return Ok(()); }
        if let Some(v) = self.client_product_id { dst.write_u16_le(v, "ClientCoreData::clientProductId")?; } else { return Ok(()); }
        if let Some(v) = self.serial_number { dst.write_u32_le(v, "ClientCoreData::serialNumber")?; } else { return Ok(()); }
        if let Some(v) = self.high_color_depth { dst.write_u16_le(v as u16, "ClientCoreData::highColorDepth")?; } else { return Ok(()); }
        if let Some(v) = self.supported_color_depths { dst.write_u16_le(v.bits(), "ClientCoreData::supportedColorDepths")?; } else { return Ok(()); }
        if let Some(v) = self.early_capability_flags { dst.write_u16_le(v.bits(), "ClientCoreData::earlyCapabilityFlags")?; } else { return Ok(()); }
        if let Some(ref v) = self.client_dig_product_id { dst.write_slice(v, "ClientCoreData::clientDigProductId")?; } else { return Ok(()); }
        if let Some(v) = self.connection_type { dst.write_u8(v, "ClientCoreData::connectionType")?; } else { return Ok(()); }
        if let Some(v) = self.pad1 { dst.write_u8(v, "ClientCoreData::pad1")?; } else { return Ok(()); }
        if let Some(v) = self.server_selected_protocol { dst.write_u32_le(v, "ClientCoreData::serverSelectedProtocol")?; } else { return Ok(()); }
        if let Some(v) = self.desktop_physical_width { dst.write_u32_le(v, "ClientCoreData::desktopPhysicalWidth")?; } else { return Ok(()); }
        if let Some(v) = self.desktop_physical_height { dst.write_u32_le(v, "ClientCoreData::desktopPhysicalHeight")?; } else { return Ok(()); }
        if let Some(v) = self.desktop_orientation { dst.write_u16_le(v, "ClientCoreData::desktopOrientation")?; } else { return Ok(()); }
        if let Some(v) = self.desktop_scale_factor { dst.write_u32_le(v, "ClientCoreData::desktopScaleFactor")?; } else { return Ok(()); }
        if let Some(v) = self.device_scale_factor { dst.write_u32_le(v, "ClientCoreData::deviceScaleFactor")?; } else { return Ok(()); }

        Ok(())
    }

    fn name(&self) -> &'static str { "ClientCoreData" }

    fn size(&self) -> usize {
        DATA_BLOCK_HEADER_SIZE + CLIENT_CORE_FIXED_SIZE + self.optional_size()
    }
}

impl<'de> Decode<'de> for ClientCoreData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, blen) = read_block_header(src, "ClientCoreData::header")?;
        if btype != ClientDataBlockType::CoreData as u16 {
            return Err(DecodeError::unexpected_value("ClientCoreData", "type", "expected 0xC001"));
        }
        let data_len = (blen as usize).saturating_sub(DATA_BLOCK_HEADER_SIZE);
        let start = src.pos();

        let version = RdpVersion::from_u32(src.read_u32_le("ClientCoreData::version")?);
        let desktop_width = src.read_u16_le("ClientCoreData::desktopWidth")?;
        let desktop_height = src.read_u16_le("ClientCoreData::desktopHeight")?;
        let color_depth = ColorDepth::from_u16(src.read_u16_le("ClientCoreData::colorDepth")?);
        let sas_sequence = src.read_u16_le("ClientCoreData::sasSequence")?;
        let keyboard_layout = src.read_u32_le("ClientCoreData::keyboardLayout")?;
        let client_build = src.read_u32_le("ClientCoreData::clientBuild")?;

        // Client name: 32 bytes UTF-16LE
        let name_bytes = src.read_slice(32, "ClientCoreData::clientName")?;
        let u16_units: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let client_name = String::from_utf16_lossy(&u16_units);

        let keyboard_type = src.read_u32_le("ClientCoreData::keyboardType")?;
        let keyboard_sub_type = src.read_u32_le("ClientCoreData::keyboardSubType")?;
        let keyboard_function_key = src.read_u32_le("ClientCoreData::keyboardFuncKey")?;
        let ime_slice = src.read_slice(64, "ClientCoreData::imeFileName")?;
        let mut ime_file_name = [0u8; 64];
        ime_file_name.copy_from_slice(ime_slice);

        // End position for this data block
        let end_pos = start + data_len;

        macro_rules! rem {
            () => { end_pos.saturating_sub(src.pos()) };
        }

        let post_beta2_color_depth = if rem!() >= 2 { Some(ColorDepth::from_u16(src.read_u16_le("ClientCoreData::postBeta2ColorDepth")?)) } else { None };
        let client_product_id = if rem!() >= 2 { Some(src.read_u16_le("ClientCoreData::clientProductId")?) } else { None };
        let serial_number = if rem!() >= 4 { Some(src.read_u32_le("ClientCoreData::serialNumber")?) } else { None };
        let high_color_depth = if rem!() >= 2 { Some(HighColorDepth::from_u16(src.read_u16_le("ClientCoreData::highColorDepth")?)) } else { None };
        let supported_color_depths = if rem!() >= 2 { Some(SupportedColorDepths::from_bits(src.read_u16_le("ClientCoreData::supportedColorDepths")?)) } else { None };
        let early_capability_flags = if rem!() >= 2 { Some(EarlyCapabilityFlags::from_bits(src.read_u16_le("ClientCoreData::earlyCapabilityFlags")?)) } else { None };
        let client_dig_product_id = if rem!() >= 64 {
            let s = src.read_slice(64, "ClientCoreData::clientDigProductId")?;
            let mut buf = [0u8; 64]; buf.copy_from_slice(s); Some(buf)
        } else { None };
        let connection_type = if rem!() >= 1 { Some(src.read_u8("ClientCoreData::connectionType")?) } else { None };
        let pad1 = if rem!() >= 1 { Some(src.read_u8("ClientCoreData::pad1")?) } else { None };
        let server_selected_protocol = if rem!() >= 4 { Some(src.read_u32_le("ClientCoreData::serverSelectedProtocol")?) } else { None };
        let desktop_physical_width = if rem!() >= 4 { Some(src.read_u32_le("ClientCoreData::desktopPhysicalWidth")?) } else { None };
        let desktop_physical_height = if rem!() >= 4 { Some(src.read_u32_le("ClientCoreData::desktopPhysicalHeight")?) } else { None };
        let desktop_orientation = if rem!() >= 2 { Some(src.read_u16_le("ClientCoreData::desktopOrientation")?) } else { None };
        let desktop_scale_factor = if rem!() >= 4 { Some(src.read_u32_le("ClientCoreData::desktopScaleFactor")?) } else { None };
        let device_scale_factor = if rem!() >= 4 { Some(src.read_u32_le("ClientCoreData::deviceScaleFactor")?) } else { None };

        // Skip any remaining unknown fields
        let leftover = rem!();
        if leftover > 0 { src.skip(leftover, "ClientCoreData::unknown")?; }

        Ok(Self {
            version, desktop_width, desktop_height, color_depth, sas_sequence,
            keyboard_layout, client_build, client_name, keyboard_type,
            keyboard_sub_type, keyboard_function_key, ime_file_name,
            post_beta2_color_depth, client_product_id, serial_number,
            high_color_depth, supported_color_depths, early_capability_flags,
            client_dig_product_id, connection_type, pad1, server_selected_protocol,
            desktop_physical_width, desktop_physical_height, desktop_orientation,
            desktop_scale_factor, device_scale_factor,
        })
    }
}

// ── ClientSecurityData (CS_SECURITY 0xC002) ──

/// Client Security Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecurityData {
    pub encryption_methods: u32,
    pub ext_encryption_methods: u32,
}

impl ClientSecurityData {
    pub fn new() -> Self {
        Self {
            encryption_methods: 0,
            ext_encryption_methods: 0,
        }
    }
}

const CLIENT_SECURITY_DATA_SIZE: usize = DATA_BLOCK_HEADER_SIZE + 8;

impl Encode for ClientSecurityData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_block_header(dst, ClientDataBlockType::SecurityData as u16, CLIENT_SECURITY_DATA_SIZE as u16, "ClientSecurityData::header")?;
        dst.write_u32_le(self.encryption_methods, "ClientSecurityData::encryptionMethods")?;
        dst.write_u32_le(self.ext_encryption_methods, "ClientSecurityData::extEncryptionMethods")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "ClientSecurityData" }
    fn size(&self) -> usize { CLIENT_SECURITY_DATA_SIZE }
}

impl<'de> Decode<'de> for ClientSecurityData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, _blen) = read_block_header(src, "ClientSecurityData::header")?;
        if btype != ClientDataBlockType::SecurityData as u16 {
            return Err(DecodeError::unexpected_value("ClientSecurityData", "type", "expected 0xC002"));
        }
        Ok(Self {
            encryption_methods: src.read_u32_le("ClientSecurityData::encryptionMethods")?,
            ext_encryption_methods: src.read_u32_le("ClientSecurityData::extEncryptionMethods")?,
        })
    }
}

// ── ClientNetworkData (CS_NET 0xC003) ──

/// Channel definition in ClientNetworkData.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelDef {
    /// Channel name (max 7 ASCII chars + null, 8 bytes on wire).
    pub name: [u8; 8],
    /// Channel option flags.
    pub options: u32,
}

impl ChannelDef {
    pub fn new(name: &str, options: u32) -> Self {
        let mut buf = [0u8; 8];
        let bytes = name.as_bytes();
        let len = bytes.len().min(7);
        buf[..len].copy_from_slice(&bytes[..len]);
        Self { name: buf, options }
    }

    pub fn name_str(&self) -> &str {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.name[..end]).unwrap_or("")
    }
}

/// Client Network Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientNetworkData {
    pub channels: Vec<ChannelDef>,
}

impl Encode for ClientNetworkData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let total = self.size() as u16;
        write_block_header(dst, ClientDataBlockType::NetworkData as u16, total, "ClientNetworkData::header")?;
        dst.write_u32_le(self.channels.len() as u32, "ClientNetworkData::channelCount")?;
        for ch in &self.channels {
            dst.write_slice(&ch.name, "ClientNetworkData::channelName")?;
            dst.write_u32_le(ch.options, "ClientNetworkData::channelOptions")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str { "ClientNetworkData" }

    fn size(&self) -> usize {
        DATA_BLOCK_HEADER_SIZE + 4 + self.channels.len() * 12
    }
}

impl<'de> Decode<'de> for ClientNetworkData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, _blen) = read_block_header(src, "ClientNetworkData::header")?;
        if btype != ClientDataBlockType::NetworkData as u16 {
            return Err(DecodeError::unexpected_value("ClientNetworkData", "type", "expected 0xC003"));
        }
        let count = src.read_u32_le("ClientNetworkData::channelCount")? as usize;
        let mut channels = Vec::with_capacity(count);
        for _ in 0..count {
            let name_bytes = src.read_slice(8, "ClientNetworkData::channelName")?;
            let mut name = [0u8; 8];
            name.copy_from_slice(name_bytes);
            let options = src.read_u32_le("ClientNetworkData::channelOptions")?;
            channels.push(ChannelDef { name, options });
        }
        Ok(Self { channels })
    }
}

// ── ClientClusterData (CS_CLUSTER 0xC004) ──

/// Client Cluster Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientClusterData {
    pub flags: u32,
    pub redirected_session_id: u32,
}

const CLIENT_CLUSTER_DATA_SIZE: usize = DATA_BLOCK_HEADER_SIZE + 8;

impl Encode for ClientClusterData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_block_header(dst, ClientDataBlockType::ClusterData as u16, CLIENT_CLUSTER_DATA_SIZE as u16, "ClientClusterData::header")?;
        dst.write_u32_le(self.flags, "ClientClusterData::flags")?;
        dst.write_u32_le(self.redirected_session_id, "ClientClusterData::redirectedSessionId")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "ClientClusterData" }
    fn size(&self) -> usize { CLIENT_CLUSTER_DATA_SIZE }
}

impl<'de> Decode<'de> for ClientClusterData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, _blen) = read_block_header(src, "ClientClusterData::header")?;
        if btype != ClientDataBlockType::ClusterData as u16 {
            return Err(DecodeError::unexpected_value("ClientClusterData", "type", "expected 0xC004"));
        }
        Ok(Self {
            flags: src.read_u32_le("ClientClusterData::flags")?,
            redirected_session_id: src.read_u32_le("ClientClusterData::redirectedSessionId")?,
        })
    }
}

// ── ClientMonitorData (CS_MONITOR 0xC005) ──

/// Monitor definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorDef {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub flags: u32, // 0x01 = primary
}

/// Client Monitor Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMonitorData {
    pub monitors: Vec<MonitorDef>,
}

impl Encode for ClientMonitorData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let total = self.size() as u16;
        write_block_header(dst, ClientDataBlockType::MonitorData as u16, total, "ClientMonitorData::header")?;
        dst.write_u32_le(0, "ClientMonitorData::flags")?; // reserved
        dst.write_u32_le(self.monitors.len() as u32, "ClientMonitorData::monitorCount")?;
        for m in &self.monitors {
            dst.write_i32_le(m.left, "MonitorDef::left")?;
            dst.write_i32_le(m.top, "MonitorDef::top")?;
            dst.write_i32_le(m.right, "MonitorDef::right")?;
            dst.write_i32_le(m.bottom, "MonitorDef::bottom")?;
            dst.write_u32_le(m.flags, "MonitorDef::flags")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str { "ClientMonitorData" }

    fn size(&self) -> usize {
        DATA_BLOCK_HEADER_SIZE + 4 + 4 + self.monitors.len() * 20
    }
}

impl<'de> Decode<'de> for ClientMonitorData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, _blen) = read_block_header(src, "ClientMonitorData::header")?;
        if btype != ClientDataBlockType::MonitorData as u16 {
            return Err(DecodeError::unexpected_value("ClientMonitorData", "type", "expected 0xC005"));
        }
        let _flags = src.read_u32_le("ClientMonitorData::flags")?;
        let count = src.read_u32_le("ClientMonitorData::monitorCount")? as usize;
        let mut monitors = Vec::with_capacity(count);
        for _ in 0..count {
            monitors.push(MonitorDef {
                left: src.read_i32_le("MonitorDef::left")?,
                top: src.read_i32_le("MonitorDef::top")?,
                right: src.read_i32_le("MonitorDef::right")?,
                bottom: src.read_i32_le("MonitorDef::bottom")?,
                flags: src.read_u32_le("MonitorDef::flags")?,
            });
        }
        Ok(Self { monitors })
    }
}

// ── ClientMonitorExtendedData (CS_MONITOR_EX 0xC008) ──

/// Extended monitor attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorAttributeDef {
    pub physical_width: u32,
    pub physical_height: u32,
    pub orientation: u32,
    pub desktop_scale_factor: u32,
    pub device_scale_factor: u32,
}

/// Client Monitor Extended Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMonitorExtendedData {
    pub monitors: Vec<MonitorAttributeDef>,
}

impl Encode for ClientMonitorExtendedData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let total = self.size() as u16;
        write_block_header(dst, ClientDataBlockType::MonitorExtendedData as u16, total, "ClientMonitorExtendedData::header")?;
        dst.write_u32_le(0, "ClientMonitorExtendedData::flags")?;
        dst.write_u32_le(20, "ClientMonitorExtendedData::monitorAttributeSize")?; // each attribute = 20 bytes
        dst.write_u32_le(self.monitors.len() as u32, "ClientMonitorExtendedData::monitorCount")?;
        for m in &self.monitors {
            dst.write_u32_le(m.physical_width, "MonitorAttr::physicalWidth")?;
            dst.write_u32_le(m.physical_height, "MonitorAttr::physicalHeight")?;
            dst.write_u32_le(m.orientation, "MonitorAttr::orientation")?;
            dst.write_u32_le(m.desktop_scale_factor, "MonitorAttr::desktopScaleFactor")?;
            dst.write_u32_le(m.device_scale_factor, "MonitorAttr::deviceScaleFactor")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str { "ClientMonitorExtendedData" }

    fn size(&self) -> usize {
        DATA_BLOCK_HEADER_SIZE + 4 + 4 + 4 + self.monitors.len() * 20
    }
}

impl<'de> Decode<'de> for ClientMonitorExtendedData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, _blen) = read_block_header(src, "ClientMonitorExtendedData::header")?;
        if btype != ClientDataBlockType::MonitorExtendedData as u16 {
            return Err(DecodeError::unexpected_value("ClientMonitorExtendedData", "type", "expected 0xC008"));
        }
        let _flags = src.read_u32_le("ClientMonitorExtendedData::flags")?;
        let _attr_size = src.read_u32_le("ClientMonitorExtendedData::monitorAttributeSize")?;
        let count = src.read_u32_le("ClientMonitorExtendedData::monitorCount")? as usize;
        let mut monitors = Vec::with_capacity(count);
        for _ in 0..count {
            monitors.push(MonitorAttributeDef {
                physical_width: src.read_u32_le("MonitorAttr::physicalWidth")?,
                physical_height: src.read_u32_le("MonitorAttr::physicalHeight")?,
                orientation: src.read_u32_le("MonitorAttr::orientation")?,
                desktop_scale_factor: src.read_u32_le("MonitorAttr::desktopScaleFactor")?,
                device_scale_factor: src.read_u32_le("MonitorAttr::deviceScaleFactor")?,
            });
        }
        Ok(Self { monitors })
    }
}

// ── ClientMessageChannelData (CS_MCS_MSGCHANNEL 0xC006) ──

/// Client Message Channel Data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientMessageChannelData {
    pub flags: u32,
}

const CLIENT_MSG_CHANNEL_SIZE: usize = DATA_BLOCK_HEADER_SIZE + 4;

impl Encode for ClientMessageChannelData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_block_header(dst, ClientDataBlockType::MessageChannelData as u16, CLIENT_MSG_CHANNEL_SIZE as u16, "ClientMsgChannel::header")?;
        dst.write_u32_le(self.flags, "ClientMsgChannel::flags")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "ClientMessageChannelData" }
    fn size(&self) -> usize { CLIENT_MSG_CHANNEL_SIZE }
}

impl<'de> Decode<'de> for ClientMessageChannelData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, _blen) = read_block_header(src, "ClientMsgChannel::header")?;
        if btype != ClientDataBlockType::MessageChannelData as u16 {
            return Err(DecodeError::unexpected_value("ClientMessageChannelData", "type", "expected 0xC006"));
        }
        Ok(Self { flags: src.read_u32_le("ClientMsgChannel::flags")? })
    }
}

// ── ClientMultitransportChannelData (CS_MULTITRANSPORT 0xC00A) ──

/// Client Multitransport Channel Data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientMultitransportChannelData {
    pub flags: u32,
}

const CLIENT_MULTITRANSPORT_SIZE: usize = DATA_BLOCK_HEADER_SIZE + 4;

impl Encode for ClientMultitransportChannelData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_block_header(dst, ClientDataBlockType::MultitransportChannelData as u16, CLIENT_MULTITRANSPORT_SIZE as u16, "ClientMultitransport::header")?;
        dst.write_u32_le(self.flags, "ClientMultitransport::flags")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "ClientMultitransportChannelData" }
    fn size(&self) -> usize { CLIENT_MULTITRANSPORT_SIZE }
}

impl<'de> Decode<'de> for ClientMultitransportChannelData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, _blen) = read_block_header(src, "ClientMultitransport::header")?;
        if btype != ClientDataBlockType::MultitransportChannelData as u16 {
            return Err(DecodeError::unexpected_value("ClientMultitransportChannelData", "type", "expected 0xC00A"));
        }
        Ok(Self { flags: src.read_u32_le("ClientMultitransport::flags")? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_core_data_roundtrip() {
        let mut core = ClientCoreData::new(1920, 1080);
        core.client_name = "TESTPC".into();
        core.server_selected_protocol = Some(0x02); // HYBRID

        let size = core.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        core.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientCoreData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.desktop_width, 1920);
        assert_eq!(decoded.desktop_height, 1080);
        assert_eq!(decoded.client_name, "TESTPC");
        assert_eq!(decoded.version, RdpVersion::V10_12);
        assert_eq!(decoded.server_selected_protocol, Some(0x02));
    }

    #[test]
    fn client_core_data_minimal() {
        // Only fixed fields, no optional
        let mut core = ClientCoreData::new(800, 600);
        core.post_beta2_color_depth = None;
        core.client_product_id = None;
        core.serial_number = None;
        core.high_color_depth = None;
        core.supported_color_depths = None;
        core.early_capability_flags = None;
        core.client_dig_product_id = None;
        core.connection_type = None;
        core.pad1 = None;
        core.server_selected_protocol = None;

        let size = core.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        core.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientCoreData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.desktop_width, 800);
        assert_eq!(decoded.post_beta2_color_depth, None);
        assert_eq!(decoded.server_selected_protocol, None);
    }

    #[test]
    fn client_security_data_roundtrip() {
        let sec = ClientSecurityData { encryption_methods: 0x03, ext_encryption_methods: 0 };
        let mut buf = [0u8; CLIENT_SECURITY_DATA_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        sec.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientSecurityData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.encryption_methods, 0x03);
    }

    #[test]
    fn client_network_data_roundtrip() {
        let net = ClientNetworkData {
            channels: alloc::vec![
                ChannelDef::new("rdpdr", 0x80800000),
                ChannelDef::new("cliprdr", 0xC0A00000),
            ],
        };
        let size = net.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        net.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientNetworkData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.channels.len(), 2);
        assert_eq!(decoded.channels[0].name_str(), "rdpdr");
        assert_eq!(decoded.channels[1].name_str(), "cliprdr");
        assert_eq!(decoded.channels[0].options, 0x80800000);
    }

    #[test]
    fn client_cluster_data_roundtrip() {
        let cluster = ClientClusterData { flags: 0x0D, redirected_session_id: 0 };
        let mut buf = [0u8; CLIENT_CLUSTER_DATA_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        cluster.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientClusterData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.flags, 0x0D);
    }

    #[test]
    fn client_monitor_data_roundtrip() {
        let mon = ClientMonitorData {
            monitors: alloc::vec![
                MonitorDef { left: 0, top: 0, right: 1919, bottom: 1079, flags: 1 },
                MonitorDef { left: 1920, top: 0, right: 3839, bottom: 1079, flags: 0 },
            ],
        };
        let size = mon.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        mon.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientMonitorData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.monitors.len(), 2);
        assert_eq!(decoded.monitors[0].flags, 1); // primary
        assert_eq!(decoded.monitors[1].left, 1920);
    }

    #[test]
    fn client_monitor_extended_data_roundtrip() {
        let ext = ClientMonitorExtendedData {
            monitors: alloc::vec![MonitorAttributeDef {
                physical_width: 530,
                physical_height: 300,
                orientation: 0,
                desktop_scale_factor: 100,
                device_scale_factor: 100,
            }],
        };
        let size = ext.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        ext.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientMonitorExtendedData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.monitors[0].physical_width, 530);
    }

    #[test]
    fn client_message_channel_roundtrip() {
        let msg = ClientMessageChannelData { flags: 0 };
        let mut buf = [0u8; CLIENT_MSG_CHANNEL_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        msg.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientMessageChannelData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.flags, 0);
    }

    #[test]
    fn client_multitransport_roundtrip() {
        let mt = ClientMultitransportChannelData { flags: 0x01 };
        let mut buf = [0u8; CLIENT_MULTITRANSPORT_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        mt.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientMultitransportChannelData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.flags, 0x01);
    }

    #[test]
    fn channel_def_name() {
        let ch = ChannelDef::new("rdpsnd", 0);
        assert_eq!(ch.name_str(), "rdpsnd");
    }

    #[test]
    fn client_network_data_zero_channels() {
        let net = ClientNetworkData { channels: alloc::vec![] };
        let size = net.size();
        assert_eq!(size, DATA_BLOCK_HEADER_SIZE + 4); // header + channelCount
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        net.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientNetworkData::decode(&mut cursor).unwrap();
        assert!(decoded.channels.is_empty());
    }

    #[test]
    fn channel_def_7char_boundary() {
        let ch = ChannelDef::new("1234567", 0);
        assert_eq!(ch.name_str(), "1234567");

        // 8+ chars should be truncated to 7
        let ch = ChannelDef::new("12345678", 0);
        assert_eq!(ch.name_str(), "1234567");
    }
}
