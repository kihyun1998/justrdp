//! T.124 GCC Conference Create user data — the client/server settings blocks carried inside the
//! MCS Connect-Initial / Connect-Response (MS-RDPBCGR 2.2.1.3 / 2.2.1.4, plan.md §5 Layer 3).
//!
//! The client sends Core (0xC001), Security (0xC002), and Network (0xC003) blocks; the server
//! answers with its own Core (0x0C01), Network (0x0C03), and Security (0x0C02) blocks (plus
//! optional Message Channel / Multitransport blocks). Block bodies are little-endian RDP
//! structures; the T.124 wrapper around them is ALIGNED PER ([`crate::per`]).
//!
//! **The anti-hardcode invariant (plan.md §0):** every policy-bearing field — most critically
//! `earlyCapabilityFlags`, the EGFX gate — is a plain struct field filled by the caller. This
//! module only serializes; it never decides a flag.

use crate::cursor::ReadCursor;
use crate::error::DecodeError;
use crate::nego::SecurityProtocol;
use crate::per;

/// `earlyCapabilityFlags` in the Client Core Data (MS-RDPBCGR 2.2.1.3.2). A dependency-free
/// bitflag newtype (decision 6), mirroring [`SecurityProtocol`]'s shape. All twelve flags are
/// caller-set; justrdp never adds or strips one (plan.md §0 — the EGFX gate trap that motivated
/// this project).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientEarlyCapabilityFlags(u16);

impl ClientEarlyCapabilityFlags {
    /// Client supports the Set Error Info PDU (`RNS_UD_CS_SUPPORT_ERRINFO_PDU`).
    pub const SUPPORT_ERR_INFO_PDU: Self = Self(0x0001);
    /// Client wants a 32-bpp session (`RNS_UD_CS_WANT_32BPP_SESSION`).
    pub const WANT_32_BPP_SESSION: Self = Self(0x0002);
    /// Client supports the Server Status Info PDU (`RNS_UD_CS_SUPPORT_STATUSINFO_PDU`).
    pub const SUPPORT_STATUS_INFO_PDU: Self = Self(0x0004);
    /// Client supports asymmetric keys larger than 512 bits (`RNS_UD_CS_STRONG_ASYMMETRIC_KEYS`).
    pub const STRONG_ASYMMETRIC_KEYS: Self = Self(0x0008);
    /// Client supports relative mouse input (`RNS_UD_CS_RELATIVE_MOUSE_INPUT`).
    pub const RELATIVE_MOUSE_INPUT: Self = Self(0x0010);
    /// The connectionType field is valid (`RNS_UD_CS_VALID_CONNECTION_TYPE`).
    pub const VALID_CONNECTION_TYPE: Self = Self(0x0020);
    /// Client supports the Monitor Layout PDU (`RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU`).
    pub const SUPPORT_MONITOR_LAYOUT_PDU: Self = Self(0x0040);
    /// Client supports network characteristics autodetection
    /// (`RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT`).
    pub const SUPPORT_NET_CHAR_AUTODETECT: Self = Self(0x0080);
    /// Client supports the Graphics Pipeline DVC — **the EGFX gate**
    /// (`RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL`).
    pub const SUPPORT_DYN_VC_GFX_PROTOCOL: Self = Self(0x0100);
    /// Client supports dynamic time zone updates (`RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE`).
    pub const SUPPORT_DYNAMIC_TIME_ZONE: Self = Self(0x0200);
    /// Client supports the Heartbeat PDU (`RNS_UD_CS_SUPPORT_HEARTBEAT_PDU`).
    pub const SUPPORT_HEART_BEAT_PDU: Self = Self(0x0400);
    /// Client supports skipping the channel join sequence
    /// (`RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN`).
    pub const SUPPORT_SKIP_CHANNELJOIN: Self = Self(0x0800);

    /// No flags set. Nothing is advertised unless the caller asks for it.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// The raw bitmask.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Build from a raw bitmask (unknown bits are preserved — the spec reserves them).
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// True if every bit in `other` is set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for ClientEarlyCapabilityFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// `earlyCapabilityFlags` in the Server Core Data (MS-RDPBCGR 2.2.1.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServerEarlyCapabilityFlags(u32);

impl ServerEarlyCapabilityFlags {
    /// `RNS_UD_SC_EDGE_ACTIONS_SUPPORTED` (v1).
    pub const EDGE_ACTIONS_SUPPORTED_V1: Self = Self(0x0000_0001);
    /// `RNS_UD_SC_DYNAMIC_DST_SUPPORTED`.
    pub const DYNAMIC_DST_SUPPORTED: Self = Self(0x0000_0002);
    /// `RNS_UD_SC_EDGE_ACTIONS_SUPPORTED_V2`.
    pub const EDGE_ACTIONS_SUPPORTED_V2: Self = Self(0x0000_0004);
    /// `RNS_UD_SC_SKIP_CHANNELJOIN_SUPPORTED` — the server allows the client to skip the MCS
    /// channel join sequence.
    pub const SKIP_CHANNELJOIN_SUPPORTED: Self = Self(0x0000_0008);

    /// The raw bitmask.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Build from a raw bitmask.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// True if every bit in `other` is set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// `rdpVersion` values for the Core Data blocks (a few common ones; the field is a plain `u32`).
pub const RDP_VERSION_5_PLUS: u32 = 0x0008_0004;
/// RDP 10.12 — what current Windows clients report.
pub const RDP_VERSION_10_12: u32 = 0x0008_0011;

/// `highColorDepth` — 24 bpp.
pub const HIGH_COLOR_DEPTH_24BPP: u16 = 0x0018;
/// `supportedColorDepths` bits: 24, 16, 15, 32 bpp respectively.
pub const SUPPORTED_COLOR_DEPTH_24BPP: u16 = 0x0001;
pub const SUPPORTED_COLOR_DEPTH_16BPP: u16 = 0x0002;
pub const SUPPORTED_COLOR_DEPTH_15BPP: u16 = 0x0004;
pub const SUPPORTED_COLOR_DEPTH_32BPP: u16 = 0x0008;
/// `postBeta2ColorDepth` / `colorDepth` — 8 bpp (`RNS_UD_COLOR_8BPP`). The required-part
/// `colorDepth` is ignored by servers when the post-beta2 field is present, but must hold a
/// valid enum value.
pub const COLOR_DEPTH_8BPP: u16 = 0xCA01;
/// `keyboardType` — IBM enhanced (101/102-key), the common PC keyboard.
pub const KEYBOARD_TYPE_IBM_ENHANCED: u32 = 4;
/// `connectionType` — LAN.
pub const CONNECTION_TYPE_LAN: u8 = 6;

/// `secAccessSequence` — the only defined value, `RNS_UD_SAS_DEL` (protocol constant).
const SAS_SEQUENCE_DEL: u16 = 0xAA03;

/// Channel option bits for [`ChannelDef`] (MS-RDPBCGR 2.2.1.3.4.1 CHANNEL_DEF).
pub const CHANNEL_OPTION_INITIALIZED: u32 = 0x8000_0000;
pub const CHANNEL_OPTION_ENCRYPT_RDP: u32 = 0x4000_0000;
pub const CHANNEL_OPTION_COMPRESS_RDP: u32 = 0x0080_0000;
pub const CHANNEL_OPTION_SHOW_PROTOCOL: u32 = 0x0020_0000;

/// A static virtual channel definition in the Client Network Data: a 7-character ANSI name
/// (null-padded to 8 bytes on the wire) plus option bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelDef {
    /// The 8-byte on-wire name; the last byte is always the null terminator.
    pub name: [u8; 8],
    /// `CHANNEL_OPTION_*` bits.
    pub options: u32,
}

impl ChannelDef {
    /// Build a channel definition from an ASCII name of at most 7 characters. Returns `None` if
    /// the name is too long or not ASCII.
    pub fn new(name: &str, options: u32) -> Option<Self> {
        if name.len() > 7 || !name.is_ascii() {
            return None;
        }
        let mut bytes = [0u8; 8];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Some(Self {
            name: bytes,
            options,
        })
    }

    /// The channel name as a string (bytes before the first null).
    pub fn name_str(&self) -> &str {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.name[..end]).unwrap_or("")
    }
}

/// Client Core Data (TS_UD_CS_CORE, 0xC001). All policy-bearing fields are caller-supplied; the
/// encoder always emits the optional chain through `serverSelectedProtocol` (the fields modern
/// servers expect), and never beyond. The DPI tail (physical size / orientation / scale) is the
/// multi-monitor epic's scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCoreData {
    /// `rdpVersion` (e.g. [`RDP_VERSION_10_12`]).
    pub version: u32,
    /// Requested desktop width in pixels.
    pub desktop_width: u16,
    /// Requested desktop height in pixels.
    pub desktop_height: u16,
    /// Active input locale identifier (e.g. 0x0409 en-US, 0x0412 ko-KR).
    pub keyboard_layout: u32,
    /// Client build number (informational).
    pub client_build: u32,
    /// Client machine name (truncated to 15 UTF-16 units on the wire).
    pub client_name: String,
    /// Keyboard type (e.g. [`KEYBOARD_TYPE_IBM_ENHANCED`]).
    pub keyboard_type: u32,
    /// Keyboard subtype (OEM-dependent).
    pub keyboard_subtype: u32,
    /// Number of function keys.
    pub keyboard_functional_keys_count: u32,
    /// IME file name (usually empty).
    pub ime_file_name: String,
    /// `postBeta2ColorDepth` (e.g. [`COLOR_DEPTH_8BPP`]); servers ignore it when
    /// `highColorDepth` is present, but it must hold a valid enum value.
    pub post_beta2_color_depth: u16,
    /// `clientProductId` (informational, typically 1).
    pub client_product_id: u16,
    /// `serialNumber` (informational, typically 0).
    pub serial_number: u32,
    /// `highColorDepth` (e.g. [`HIGH_COLOR_DEPTH_24BPP`]).
    pub high_color_depth: u16,
    /// `supportedColorDepths` bits (`SUPPORTED_COLOR_DEPTH_*`).
    pub supported_color_depths: u16,
    /// **`earlyCapabilityFlags` — fully caller-controlled, all twelve flags** (plan.md §0).
    pub early_capability_flags: ClientEarlyCapabilityFlags,
    /// `clientDigProductId` (informational, usually empty).
    pub dig_product_id: String,
    /// `connectionType` (meaningful only with
    /// [`ClientEarlyCapabilityFlags::VALID_CONNECTION_TYPE`]).
    pub connection_type: u8,
    /// `serverSelectedProtocol` — echoes the protocol the server chose in the X.224 confirm.
    /// The connect state machine fills this with the negotiated value; it is protocol fact, not
    /// caller policy.
    pub server_selected_protocol: SecurityProtocol,
}

/// Write `s` as UTF-16LE into exactly `total` bytes: truncated to `total/2 - 1` code units,
/// zero-padded, always null-terminated.
fn put_utf16_fixed(out: &mut Vec<u8>, s: &str, total: usize) {
    let max_units = total / 2 - 1;
    let mut written = 0;
    for unit in s.encode_utf16().take(max_units) {
        out.extend_from_slice(&unit.to_le_bytes());
        written += 1;
    }
    out.extend(std::iter::repeat_n(0u8, (max_units - written) * 2));
    out.extend_from_slice(&[0, 0]); // null terminator
}

/// Read a fixed UTF-16LE field of `total` bytes, trimming trailing nulls.
fn read_utf16_fixed(cur: &mut ReadCursor<'_>, total: usize) -> Result<String, DecodeError> {
    let bytes = cur.read_slice(total)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    Ok(String::from_utf16_lossy(&units[..end]))
}

impl Default for ClientCoreData {
    /// A sensible host-facing starting point that **advertises every early-capability flag
    /// justrdp can actually honour** — Set Error Info ([`ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU`]),
    /// the EGFX gate ([`ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL`]), and channel-join
    /// skip ([`ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN`]) — per the "advertise
    /// everything we can handle" rule (plan.md §0, §5b).
    ///
    /// This is a **default, not a hardcode** (plan.md §0): every field, including
    /// `early_capability_flags`, may be overridden — set, cleared, or extended — and the encoder
    /// passes whatever bits remain through verbatim (see `early_capability_flags_pass_through_verbatim`).
    /// A default-configured client therefore advertises `SUPPORT_ERR_INFO_PDU` and receives
    /// attributable Set Error Info PDUs without the host opting in (issue #42 C4 / #71), while a
    /// host that wants a leaner advertisement can still clear the flags.
    ///
    /// `server_selected_protocol` is left empty — the connect state machine fills it with the
    /// negotiated value (it is protocol fact, not caller policy).
    fn default() -> Self {
        Self {
            version: RDP_VERSION_10_12,
            desktop_width: 1280,
            desktop_height: 800,
            keyboard_layout: 0x0409, // en-US
            client_build: 18363,
            client_name: "justrdp".to_string(),
            keyboard_type: KEYBOARD_TYPE_IBM_ENHANCED,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            ime_file_name: String::new(),
            post_beta2_color_depth: COLOR_DEPTH_8BPP,
            client_product_id: 1,
            serial_number: 0,
            high_color_depth: HIGH_COLOR_DEPTH_24BPP,
            supported_color_depths: SUPPORTED_COLOR_DEPTH_24BPP
                | SUPPORTED_COLOR_DEPTH_16BPP
                | SUPPORTED_COLOR_DEPTH_32BPP,
            early_capability_flags: ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU
                | ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL
                | ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN,
            dig_product_id: String::new(),
            connection_type: CONNECTION_TYPE_LAN,
            server_selected_protocol: SecurityProtocol::from_bits(0),
        }
    }
}

impl ClientCoreData {
    /// Append the block body (without the user-data header) to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.desktop_width.to_le_bytes());
        out.extend_from_slice(&self.desktop_height.to_le_bytes());
        out.extend_from_slice(&COLOR_DEPTH_8BPP.to_le_bytes()); // required-part colorDepth (ignored)
        out.extend_from_slice(&SAS_SEQUENCE_DEL.to_le_bytes());
        out.extend_from_slice(&self.keyboard_layout.to_le_bytes());
        out.extend_from_slice(&self.client_build.to_le_bytes());
        put_utf16_fixed(out, &self.client_name, 32);
        out.extend_from_slice(&self.keyboard_type.to_le_bytes());
        out.extend_from_slice(&self.keyboard_subtype.to_le_bytes());
        out.extend_from_slice(&self.keyboard_functional_keys_count.to_le_bytes());
        put_utf16_fixed(out, &self.ime_file_name, 64);
        // Optional chain (each field requires all previous ones — MS-RDPBCGR 2.2.1.3.2):
        out.extend_from_slice(&self.post_beta2_color_depth.to_le_bytes());
        out.extend_from_slice(&self.client_product_id.to_le_bytes());
        out.extend_from_slice(&self.serial_number.to_le_bytes());
        out.extend_from_slice(&self.high_color_depth.to_le_bytes());
        out.extend_from_slice(&self.supported_color_depths.to_le_bytes());
        out.extend_from_slice(&self.early_capability_flags.bits().to_le_bytes());
        put_utf16_fixed(out, &self.dig_product_id, 64);
        out.push(self.connection_type);
        out.push(0); // pad1octet
        out.extend_from_slice(&self.server_selected_protocol.bits().to_le_bytes());
    }

    /// Decode a block body of exactly the shape [`ClientCoreData::encode_into`] produces
    /// (through `serverSelectedProtocol`). Round-trip aid; lenient decoding of foreign clients
    /// is not this crate's job.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(body, "client core data");
        let version = cur.read_u32_le()?;
        let desktop_width = cur.read_u16_le()?;
        let desktop_height = cur.read_u16_le()?;
        cur.read_u16_le()?; // colorDepth (superseded)
        cur.read_u16_le()?; // SASSequence
        let keyboard_layout = cur.read_u32_le()?;
        let client_build = cur.read_u32_le()?;
        let client_name = read_utf16_fixed(&mut cur, 32)?;
        let keyboard_type = cur.read_u32_le()?;
        let keyboard_subtype = cur.read_u32_le()?;
        let keyboard_functional_keys_count = cur.read_u32_le()?;
        let ime_file_name = read_utf16_fixed(&mut cur, 64)?;
        let post_beta2_color_depth = cur.read_u16_le()?;
        let client_product_id = cur.read_u16_le()?;
        let serial_number = cur.read_u32_le()?;
        let high_color_depth = cur.read_u16_le()?;
        let supported_color_depths = cur.read_u16_le()?;
        let early_capability_flags = ClientEarlyCapabilityFlags::from_bits(cur.read_u16_le()?);
        let dig_product_id = read_utf16_fixed(&mut cur, 64)?;
        let connection_type = cur.read_u8()?;
        cur.read_u8()?; // pad1octet
        let server_selected_protocol = SecurityProtocol::from_bits(cur.read_u32_le()?);

        Ok(Self {
            version,
            desktop_width,
            desktop_height,
            keyboard_layout,
            client_build,
            client_name,
            keyboard_type,
            keyboard_subtype,
            keyboard_functional_keys_count,
            ime_file_name,
            post_beta2_color_depth,
            client_product_id,
            serial_number,
            high_color_depth,
            supported_color_depths,
            early_capability_flags,
            dig_product_id,
            connection_type,
            server_selected_protocol,
        })
    }
}

/// Client Security Data (TS_UD_CS_SEC, 0xC002). With TLS/NLA transport security both fields are
/// zero — RDP-level encryption is never negotiated (ADR-0002 forbids RC4 Standard Security).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientSecurityData {
    /// `encryptionMethods` bitmask (0 with TLS).
    pub encryption_methods: u32,
    /// `extEncryptionMethods` (French-locale legacy field; 0 with TLS).
    pub ext_encryption_methods: u32,
}

impl ClientSecurityData {
    /// Append the block body to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.encryption_methods.to_le_bytes());
        out.extend_from_slice(&self.ext_encryption_methods.to_le_bytes());
    }

    /// Decode a block body.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(body, "client security data");
        Ok(Self {
            encryption_methods: cur.read_u32_le()?,
            ext_encryption_methods: cur.read_u32_le()?,
        })
    }
}

/// Client Network Data (TS_UD_CS_NET, 0xC003): the static virtual channel request list. The
/// server answers with one channel ID per requested channel, in order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientNetworkData {
    /// Requested static channels (at most 31 per spec).
    pub channels: Vec<ChannelDef>,
}

impl ClientNetworkData {
    /// Append the block body to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.channels.len() as u32).to_le_bytes());
        for channel in &self.channels {
            out.extend_from_slice(&channel.name);
            out.extend_from_slice(&channel.options.to_le_bytes());
        }
    }

    /// Decode a block body.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(body, "client network data");
        let count = cur.read_u32_le()? as usize;
        if count > 31 {
            return Err(DecodeError::InvalidField {
                field: "channelCount",
                reason: "more than 31 static channels",
            });
        }
        let mut channels = Vec::with_capacity(count);
        for _ in 0..count {
            let name_slice = cur.read_slice(8)?;
            let mut name = [0u8; 8];
            name.copy_from_slice(name_slice);
            let options = cur.read_u32_le()?;
            channels.push(ChannelDef { name, options });
        }
        Ok(Self { channels })
    }
}

/// GCC user-data block types the client sends.
const CS_CORE: u16 = 0xC001;
const CS_SECURITY: u16 = 0xC002;
const CS_NET: u16 = 0xC003;
/// GCC user-data block types the server sends.
const SC_CORE: u16 = 0x0C01;
const SC_SECURITY: u16 = 0x0C02;
const SC_NET: u16 = 0x0C03;
const SC_MCS_MSGCHANNEL: u16 = 0x0C04;
const SC_MULTITRANSPORT: u16 = 0x0C08;

/// The full set of client GCC blocks for the Connect-Initial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGccBlocks {
    pub core: ClientCoreData,
    pub security: ClientSecurityData,
    /// Always sent (MS-RDPBCGR mandates Core/Security/Network), possibly with zero channels.
    pub network: ClientNetworkData,
}

/// Write one user-data block: TS_UD_HEADER (type LE, length LE including the 4-byte header)
/// followed by the body.
fn write_block(out: &mut Vec<u8>, block_type: u16, body: &[u8]) {
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&((body.len() + 4) as u16).to_le_bytes());
    out.extend_from_slice(body);
}

impl ClientGccBlocks {
    /// Encode all blocks (Core, Security, Network) back to back.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        let mut body = Vec::with_capacity(216);
        self.core.encode_into(&mut body);
        write_block(&mut out, CS_CORE, &body);
        body.clear();
        self.security.encode_into(&mut body);
        write_block(&mut out, CS_SECURITY, &body);
        body.clear();
        self.network.encode_into(&mut body);
        write_block(&mut out, CS_NET, &body);
        out
    }

    /// Decode a block sequence (round-trip aid).
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(bytes, "client gcc blocks");
        let mut core = None;
        let mut security = None;
        let mut network = None;
        while cur.remaining() >= 4 {
            let (block_type, body) = read_block(&mut cur)?;
            match block_type {
                CS_CORE => core = Some(ClientCoreData::decode(body)?),
                CS_SECURITY => security = Some(ClientSecurityData::decode(body)?),
                CS_NET => network = Some(ClientNetworkData::decode(body)?),
                _ => {} // unknown blocks are skipped (length-prefixed)
            }
        }
        Ok(Self {
            core: core.ok_or(DecodeError::InvalidField {
                field: "gcc.core",
                reason: "Client Core Data block missing",
            })?,
            security: security.ok_or(DecodeError::InvalidField {
                field: "gcc.security",
                reason: "Client Security Data block missing",
            })?,
            network: network.unwrap_or_default(),
        })
    }
}

/// Read one user-data block header + body.
fn read_block<'a>(cur: &mut ReadCursor<'a>) -> Result<(u16, &'a [u8]), DecodeError> {
    let block_type = cur.read_u16_le()?;
    let block_len = cur.read_u16_le()? as usize;
    let body_len = block_len.checked_sub(4).ok_or(DecodeError::InvalidField {
        field: "gcc.blockLen",
        reason: "shorter than the 4-byte user-data header",
    })?;
    Ok((block_type, cur.read_slice(body_len)?))
}

/// Server Core Data (TS_UD_SC_CORE, 0x0C01). The optional fields appear in order; truncation at
/// any boundary is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerCoreData {
    /// The server's `rdpVersion`.
    pub version: u32,
    /// `clientRequestedProtocols` echoed back, if present.
    pub client_requested_protocols: Option<SecurityProtocol>,
    /// The server's `earlyCapabilityFlags`, if present — carries
    /// [`ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED`].
    pub early_capability_flags: Option<ServerEarlyCapabilityFlags>,
}

impl ServerCoreData {
    /// Decode a block body, tolerating the optional-field truncation points.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(body, "server core data");
        let version = cur.read_u32_le()?;
        let client_requested_protocols = if cur.remaining() >= 4 {
            Some(SecurityProtocol::from_bits(cur.read_u32_le()?))
        } else {
            None
        };
        let early_capability_flags = if cur.remaining() >= 4 {
            Some(ServerEarlyCapabilityFlags::from_bits(cur.read_u32_le()?))
        } else {
            None
        };
        Ok(Self {
            version,
            client_requested_protocols,
            early_capability_flags,
        })
    }
}

/// Server Network Data (TS_UD_SC_NET, 0x0C03): the I/O channel ID plus one channel ID per
/// requested static channel (0 marks a refused channel).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerNetworkData {
    /// `MCSChannelId` of the I/O channel (conventionally 1003).
    pub io_channel: u16,
    /// Channel IDs answering the client's channel list, in request order.
    pub channel_ids: Vec<u16>,
}

impl ServerNetworkData {
    /// Decode a block body (the trailing 2-byte pad for odd counts is tolerated).
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(body, "server network data");
        let io_channel = cur.read_u16_le()?;
        let count = cur.read_u16_le()? as usize;
        let mut channel_ids = Vec::with_capacity(count);
        for _ in 0..count {
            channel_ids.push(cur.read_u16_le()?);
        }
        Ok(Self {
            io_channel,
            channel_ids,
        })
    }
}

/// Server Security Data (TS_UD_SC_SEC1, 0x0C02). With TLS both fields are zero and no server
/// random / certificate follows; the legacy RC4 fields are skipped if a server sends them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerSecurityData {
    /// `encryptionMethod` the server selected (0 with TLS).
    pub encryption_method: u32,
    /// `encryptionLevel` (0 = none, with TLS).
    pub encryption_level: u32,
}

impl ServerSecurityData {
    /// Decode a block body, skipping the legacy serverRandom / serverCertificate if present.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(body, "server security data");
        let encryption_method = cur.read_u32_le()?;
        let encryption_level = cur.read_u32_le()?;
        if encryption_method != 0 || encryption_level != 0 {
            // Legacy RDP security material we never use (ADR-0002): skip random + certificate.
            let random_len = cur.read_u32_le()? as usize;
            let cert_len = cur.read_u32_le()? as usize;
            cur.read_slice(random_len)?;
            cur.read_slice(cert_len)?;
        }
        Ok(Self {
            encryption_method,
            encryption_level,
        })
    }
}

/// The server GCC blocks from the Connect-Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerGccBlocks {
    pub core: ServerCoreData,
    pub network: ServerNetworkData,
    pub security: ServerSecurityData,
    /// `MCSChannelId` of the message channel (0x0C04), if the server opened one.
    pub message_channel_id: Option<u16>,
    /// Multitransport flags (0x0C08), if advertised.
    pub multi_transport_flags: Option<u32>,
}

impl ServerGccBlocks {
    /// Decode the block sequence. Unknown block types are skipped (forward compatibility);
    /// Core, Network, and Security are required.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(bytes, "server gcc blocks");
        let mut core = None;
        let mut network = None;
        let mut security = None;
        let mut message_channel_id = None;
        let mut multi_transport_flags = None;
        while cur.remaining() >= 4 {
            let (block_type, body) = read_block(&mut cur)?;
            match block_type {
                SC_CORE => core = Some(ServerCoreData::decode(body)?),
                SC_NET => network = Some(ServerNetworkData::decode(body)?),
                SC_SECURITY => security = Some(ServerSecurityData::decode(body)?),
                SC_MCS_MSGCHANNEL => {
                    let mut c = ReadCursor::new(body, "server message channel data");
                    message_channel_id = Some(c.read_u16_le()?);
                }
                SC_MULTITRANSPORT => {
                    let mut c = ReadCursor::new(body, "server multitransport data");
                    multi_transport_flags = Some(c.read_u32_le()?);
                }
                _ => {} // unknown blocks are skipped
            }
        }
        Ok(Self {
            core: core.ok_or(DecodeError::InvalidField {
                field: "gcc.server_core",
                reason: "Server Core Data block missing",
            })?,
            network: network.ok_or(DecodeError::InvalidField {
                field: "gcc.server_network",
                reason: "Server Network Data block missing",
            })?,
            security: security.ok_or(DecodeError::InvalidField {
                field: "gcc.server_security",
                reason: "Server Security Data block missing",
            })?,
            message_channel_id,
            multi_transport_flags,
        })
    }
}

/// The T.124 key identifying GCC conference PDUs: `{ itu-t(0) recommendation(0) t(20) t124(124)
/// version(0) 1 }`.
const T124_OBJECT_ID: [u8; 6] = [0, 0, 20, 124, 0, 1];
/// `ConnectGCCPDU` CHOICE indices.
const CONFERENCE_CREATE_REQUEST_CHOICE: u8 = 0x00;
const CONFERENCE_CREATE_RESPONSE_CHOICE: u8 = 0x14;
/// `ConferenceCreateRequest` selection bitmap: the optional `userData` field is present.
const USER_DATA_SELECTION: u8 = 0x08;
/// `UserData` SET OF: exactly one set, keyed h221NonStandard.
const USER_DATA_NUMBER_OF_SETS: u8 = 1;
const H221_NON_STANDARD_CHOICE: u8 = 0xC0;
/// The fixed connectPDU prefix size the oracle counts for the request (choice + selection +
/// conference name + padding + sets + choice + "Duca" octet string).
const REQUEST_CONNECT_PDU_SIZE: usize = 12;

/// Encode a GCC Conference Create Request wrapping `blocks` — the `userData` payload of the MCS
/// Connect-Initial. The wrapper bytes (T.124 key, conference name "1", the "Duca" H.221 key)
/// are protocol constants fixed by MS-RDPBCGR 2.2.1.3.1.
pub fn encode_conference_create_request(blocks: &ClientGccBlocks) -> Vec<u8> {
    let gcc = blocks.encode();
    let mut out = Vec::with_capacity(gcc.len() + 24);
    // ConnectData::Key — CHOICE object (0), then the T.124 OBJECT IDENTIFIER.
    per::write_choice(&mut out, 0);
    per::write_object_id(&mut out, T124_OBJECT_ID);
    // ConnectData::connectPDU length. Mirrors the oracle: the fixed prefix + the gcc bytes
    // (the gcc length determinant itself is not counted; receivers ignore this field).
    per::write_length(&mut out, (gcc.len() + REQUEST_CONNECT_PDU_SIZE) as u16);
    // ConnectGCCPDU CHOICE: conferenceCreateRequest, with the optional userData selected.
    per::write_choice(&mut out, CONFERENCE_CREATE_REQUEST_CHOICE);
    per::write_choice(&mut out, USER_DATA_SELECTION);
    // ConferenceName: the NumericString "1" + one alignment pad byte.
    per::write_numeric_string(&mut out, b"1", 1).expect("\"1\" satisfies SIZE >= 1");
    per::write_padding(&mut out, 1);
    // UserData: one set, h221NonStandard key "Duca" (client-to-server), then the blocks.
    out.push(USER_DATA_NUMBER_OF_SETS);
    per::write_choice(&mut out, H221_NON_STANDARD_CHOICE);
    per::write_octet_string(&mut out, b"Duca", 4).expect("\"Duca\" satisfies SIZE >= 4");
    per::write_length(&mut out, gcc.len() as u16);
    out.extend_from_slice(&gcc);
    out
}

/// A decoded GCC Conference Create Response — the `userData` payload of the MCS
/// Connect-Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConferenceCreateResponse {
    /// `nodeID` the GCC provider assigned (PER u16, base 1001).
    pub node_id: u16,
    /// The server's settings blocks.
    pub blocks: ServerGccBlocks,
}

impl ConferenceCreateResponse {
    /// Decode the wrapper + server blocks (MS-RDPBCGR 2.2.1.4.1).
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(bytes, "conference create response");
        if per::read_choice(&mut cur)? != 0 {
            return Err(DecodeError::InvalidField {
                field: "ConnectData.key",
                reason: "expected the OBJECT IDENTIFIER key choice",
            });
        }
        if per::read_object_id(&mut cur)? != T124_OBJECT_ID {
            return Err(DecodeError::InvalidField {
                field: "ConnectData.key",
                reason: "unexpected T.124 object identifier",
            });
        }
        per::read_length(&mut cur)?; // connectPDU length — MUST be ignored per MS-RDPBCGR
        if per::read_choice(&mut cur)? != CONFERENCE_CREATE_RESPONSE_CHOICE {
            return Err(DecodeError::InvalidField {
                field: "ConnectGCCPDU",
                reason: "expected the conferenceCreateResponse choice",
            });
        }
        let node_id = per::read_u16(&mut cur, 1001)?;
        if per::read_u32(&mut cur)? != 1 {
            return Err(DecodeError::InvalidField {
                field: "ConferenceCreateResponse.tag",
                reason: "expected tag 1",
            });
        }
        if per::read_enum(&mut cur, 16)? != 0 {
            return Err(DecodeError::InvalidField {
                field: "ConferenceCreateResponse.result",
                reason: "conference create was not successful",
            });
        }
        if cur.read_u8()? != USER_DATA_NUMBER_OF_SETS {
            return Err(DecodeError::InvalidField {
                field: "ConferenceCreateResponse.userData",
                reason: "expected exactly one user data set",
            });
        }
        if per::read_choice(&mut cur)? != H221_NON_STANDARD_CHOICE {
            return Err(DecodeError::InvalidField {
                field: "ConferenceCreateResponse.userData",
                reason: "expected the h221NonStandard choice",
            });
        }
        if per::read_octet_string(&mut cur, 4)? != b"McDn" {
            return Err(DecodeError::InvalidField {
                field: "ConferenceCreateResponse.userData",
                reason: "expected the server-to-client H.221 key \"McDn\"",
            });
        }
        per::read_length(&mut cur)?; // gcc blocks length (the remainder)
        let blocks = ServerGccBlocks::decode(cur.read_slice(cur.remaining())?)?;
        Ok(Self { node_id, blocks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core_data() -> ClientCoreData {
        ClientCoreData {
            version: RDP_VERSION_10_12,
            desktop_width: 1280,
            desktop_height: 800,
            keyboard_layout: 0x0412, // ko-KR
            client_build: 18363,
            client_name: "justrdp-test".to_string(),
            keyboard_type: KEYBOARD_TYPE_IBM_ENHANCED,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            ime_file_name: String::new(),
            post_beta2_color_depth: COLOR_DEPTH_8BPP,
            client_product_id: 1,
            serial_number: 0,
            high_color_depth: HIGH_COLOR_DEPTH_24BPP,
            supported_color_depths: SUPPORTED_COLOR_DEPTH_24BPP
                | SUPPORTED_COLOR_DEPTH_16BPP
                | SUPPORTED_COLOR_DEPTH_32BPP,
            early_capability_flags: ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU
                | ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL
                | ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN,
            dig_product_id: String::new(),
            connection_type: CONNECTION_TYPE_LAN,
            server_selected_protocol: SecurityProtocol::HYBRID,
        }
    }

    #[test]
    fn client_core_data_round_trips() {
        let core = core_data();
        let mut body = Vec::new();
        core.encode_into(&mut body);
        // 212 bytes: the fixed part (128) + the optional chain through serverSelectedProtocol
        // (84 — post-beta2 depth through the 4-byte protocol echo).
        assert_eq!(body.len(), 212);
        assert_eq!(ClientCoreData::decode(&body).unwrap(), core);
    }

    #[test]
    fn early_capability_flags_pass_through_verbatim() {
        // The anti-hardcode invariant: whatever bits the caller sets appear on the wire,
        // including "impossible" combinations — the encoder must not normalize them.
        let mut core = core_data();
        core.early_capability_flags = ClientEarlyCapabilityFlags::from_bits(0x0FFF);
        let mut body = Vec::new();
        core.encode_into(&mut body);
        let decoded = ClientCoreData::decode(&body).unwrap();
        assert_eq!(decoded.early_capability_flags.bits(), 0x0FFF);

        core.early_capability_flags = ClientEarlyCapabilityFlags::empty();
        body.clear();
        core.encode_into(&mut body);
        assert_eq!(
            ClientCoreData::decode(&body)
                .unwrap()
                .early_capability_flags
                .bits(),
            0
        );
    }

    #[test]
    fn default_core_advertises_set_error_info_and_stays_overridable() {
        // issue #42 C4 / #71: a default-configured client must advertise SUPPORT_ERR_INFO_PDU,
        // so it receives attributable Set Error Info PDUs without the host opting in — and the
        // flag must survive the encode (not be normalized away).
        let core = ClientCoreData::default();
        assert!(
            core.early_capability_flags
                .contains(ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU),
            "the default must advertise the Set Error Info PDU support flag"
        );
        let mut body = Vec::new();
        core.encode_into(&mut body);
        assert!(
            ClientCoreData::decode(&body)
                .unwrap()
                .early_capability_flags
                .contains(ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU)
        );

        // It is a default, not a hardcode: the caller can still clear it (plan.md §0).
        let leaner = ClientCoreData {
            early_capability_flags: ClientEarlyCapabilityFlags::empty(),
            ..ClientCoreData::default()
        };
        assert_eq!(
            leaner.early_capability_flags,
            ClientEarlyCapabilityFlags::empty()
        );
    }

    #[test]
    fn client_gcc_blocks_round_trip_with_channels() {
        let blocks = ClientGccBlocks {
            core: core_data(),
            security: ClientSecurityData::default(),
            network: ClientNetworkData {
                channels: vec![
                    ChannelDef::new("cliprdr", CHANNEL_OPTION_INITIALIZED).unwrap(),
                    ChannelDef::new("drdynvc", CHANNEL_OPTION_INITIALIZED).unwrap(),
                ],
            },
        };
        let bytes = blocks.encode();
        let decoded = ClientGccBlocks::decode(&bytes).unwrap();
        assert_eq!(decoded, blocks);
        assert_eq!(decoded.network.channels[0].name_str(), "cliprdr");
    }

    #[test]
    fn channel_def_rejects_long_or_non_ascii_names() {
        assert!(ChannelDef::new("rdpdr", 0).is_some());
        assert!(ChannelDef::new("eightcha", 0).is_none()); // 8 chars: too long
        assert!(ChannelDef::new("채널", 0).is_none());
    }

    #[test]
    fn server_security_data_skips_legacy_crypto_material() {
        // encryptionMethod=2 (128-bit), level=1, a 4-byte "random" and 2-byte "certificate".
        let body = [
            0x02, 0x00, 0x00, 0x00, // method
            0x01, 0x00, 0x00, 0x00, // level
            0x04, 0x00, 0x00, 0x00, // serverRandomLen = 4
            0x02, 0x00, 0x00, 0x00, // serverCertLen = 2
            0xAA, 0xBB, 0xCC, 0xDD, // random
            0xEE, 0xFF, // certificate
        ];
        let decoded = ServerSecurityData::decode(&body).unwrap();
        assert_eq!(decoded.encryption_method, 2);
        assert_eq!(decoded.encryption_level, 1);
    }
}
