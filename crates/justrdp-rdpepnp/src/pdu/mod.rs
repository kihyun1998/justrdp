//! MS-RDPEPNP §2.2 — wire-format PDUs for the PNPDR control channel.
//!
//! Every PNPDR message begins with an 8-byte [`PnpInfoHeader`]. Fixed-size
//! messages ([`ServerVersionMsg`], [`ClientVersionMsg`],
//! [`AuthenticatedClientMsg`], [`ClientDeviceRemovalMsg`]) expose their
//! complete wire encoding in a single type. The variable-size
//! [`ClientDeviceAdditionMsg`] owns a `Vec<PnpDeviceDescription>` whose
//! elements each have their own encode/decode routine.

mod header;
pub mod io;
pub mod io_header;

use alloc::vec::Vec;

use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor};

use crate::constants::{
    packet_id, CONTAINER_ID_BLOCK_SIZE, DEVICE_CAPS_BLOCK_SIZE, MAX_COMPAT_ID_BYTES, MAX_DEVICES,
    MAX_DEVICE_DESCRIPTION_BYTES, MAX_HARDWARE_ID_BYTES, MAX_INTERFACE_BYTES, PNP_INFO_HEADER_SIZE,
};

pub use header::PnpInfoHeader;
pub use io::{
    ClientCapabilitiesReply, ClientDeviceCustomEvent, CreateFileReply, CreateFileRequest,
    IoControlReply, IoControlRequest, ReadReply, ReadRequest, ServerCapabilitiesRequest,
    SpecificIoCancelRequest, WriteReply, WriteRequest, CLIENT_CAPS_REPLY_SIZE,
    CREATE_FILE_REPLY_SIZE, CREATE_FILE_REQUEST_SIZE, CUSTOM_EVENT_MIN_SIZE,
    IOCONTROL_REPLY_MIN_SIZE, IOCONTROL_REQUEST_MIN_SIZE, READ_REPLY_MIN_SIZE, READ_REQUEST_SIZE,
    SERVER_CAPS_REQUEST_SIZE, SPECIFIC_IOCANCEL_REQUEST_SIZE, WRITE_REPLY_SIZE,
    WRITE_REQUEST_MIN_SIZE,
};
pub use io_header::{ClientIoHeader, ServerIoHeader};

// ── Fixed sizes (bytes, post-header unless otherwise noted) ──

/// Wire size of the [`ServerVersionMsg`] and [`ClientVersionMsg`] PDUs
/// (MS-RDPEPNP §2.2.1.2.1 / §2.2.1.2.2).
pub const VERSION_MSG_SIZE: usize = PNP_INFO_HEADER_SIZE + 12;

/// Wire size of the [`AuthenticatedClientMsg`] PDU (MS-RDPEPNP §2.2.1.2.3).
pub const AUTHENTICATED_CLIENT_MSG_SIZE: usize = PNP_INFO_HEADER_SIZE;

/// Wire size of the [`ClientDeviceRemovalMsg`] PDU (MS-RDPEPNP §2.2.1.3.2).
pub const DEVICE_REMOVAL_MSG_SIZE: usize = PNP_INFO_HEADER_SIZE + 4;

/// Minimum wire size of a [`ClientDeviceAdditionMsg`] with zero devices
/// (MS-RDPEPNP §2.2.1.3.1): header + `DeviceCount` u32.
pub const DEVICE_ADDITION_FIXED_SIZE: usize = PNP_INFO_HEADER_SIZE + 4;

/// Minimum wire size of a `PNP_DEVICE_DESCRIPTION` (MS-RDPEPNP §2.2.1.3.1.1)
/// with all optional data absent:
/// `ClientDeviceID(4) + DataSize(4) + 4 length fields(16) +
///  CustomFlagLength(4) + CustomFlag(4)` = 32 bytes.
pub const PNP_DEVICE_DESCRIPTION_MIN_SIZE: usize = 32;

// ── VersionMsg (MS-RDPEPNP §2.2.1.2.1 / §2.2.1.2.2) ──

/// Shared wire shape for the Server Version Message (S→C, §2.2.1.2.1)
/// and the Client Version Message (C→S, §2.2.1.2.2). The spec gives both
/// directions an identical body (`MajorVersion` / `MinorVersion` /
/// `Capabilities`) under the same `PacketId` (`IRPDR_ID_VERSION`); only
/// the direction and the state machine position distinguish them.
///
/// The [`ServerVersionMsg`] and [`ClientVersionMsg`] type aliases exist
/// for readability at call sites that want to name which side of the
/// handshake a value represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionMsg {
    pub major_version: u32,
    pub minor_version: u32,
    pub capabilities: u32,
}

const VER_CTX: &str = "VersionMsg";

impl VersionMsg {
    /// Construct with the Windows server-side defaults (Appendix A §<2>,
    /// §<3>) and the only defined capability bit.
    pub fn new_server_windows_default() -> Self {
        Self {
            major_version: crate::constants::version::SERVER_MAJOR,
            minor_version: crate::constants::version::SERVER_MINOR,
            capabilities: crate::constants::PNP_CAP_DYNAMIC_DEVICE_ADDITION,
        }
    }

    /// Construct with the Windows client-side defaults (Appendix A §<4>,
    /// §<5>) and the only defined capability bit.
    pub fn new_client_windows_default() -> Self {
        Self {
            major_version: crate::constants::version::CLIENT_MAJOR,
            minor_version: crate::constants::version::CLIENT_MINOR,
            capabilities: crate::constants::PNP_CAP_DYNAMIC_DEVICE_ADDITION,
        }
    }
}

impl Encode for VersionMsg {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        PnpInfoHeader::new(VERSION_MSG_SIZE as u32, packet_id::IRPDR_ID_VERSION).encode(dst)?;
        dst.write_u32_le(self.major_version, VER_CTX)?;
        dst.write_u32_le(self.minor_version, VER_CTX)?;
        dst.write_u32_le(self.capabilities, VER_CTX)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        VER_CTX
    }

    fn size(&self) -> usize {
        VERSION_MSG_SIZE
    }
}

impl<'de> Decode<'de> for VersionMsg {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = PnpInfoHeader::decode(src)?;
        hdr.expect(packet_id::IRPDR_ID_VERSION, VERSION_MSG_SIZE as u32, VER_CTX)?;
        Ok(Self {
            major_version: src.read_u32_le(VER_CTX)?,
            minor_version: src.read_u32_le(VER_CTX)?,
            capabilities: src.read_u32_le(VER_CTX)?,
        })
    }
}

/// Alias for [`VersionMsg`] when it represents the S→C Server Version
/// Message (§2.2.1.2.1).
pub type ServerVersionMsg = VersionMsg;

/// Alias for [`VersionMsg`] when it represents the C→S Client Version
/// Message (§2.2.1.2.2).
pub type ClientVersionMsg = VersionMsg;

// ── AuthenticatedClientMsg (S→C, MS-RDPEPNP §2.2.1.2.3) ──

/// Header-only message informing the client that user authentication
/// has completed and device announcements are now allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedClientMsg;

const AUTH_CTX: &str = "AuthenticatedClientMsg";

impl Encode for AuthenticatedClientMsg {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        PnpInfoHeader::new(
            AUTHENTICATED_CLIENT_MSG_SIZE as u32,
            packet_id::IRPDR_ID_SERVER_LOGON,
        )
        .encode(dst)
    }

    fn name(&self) -> &'static str {
        AUTH_CTX
    }

    fn size(&self) -> usize {
        AUTHENTICATED_CLIENT_MSG_SIZE
    }
}

impl<'de> Decode<'de> for AuthenticatedClientMsg {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = PnpInfoHeader::decode(src)?;
        hdr.expect(
            packet_id::IRPDR_ID_SERVER_LOGON,
            AUTHENTICATED_CLIENT_MSG_SIZE as u32,
            AUTH_CTX,
        )?;
        Ok(Self)
    }
}

// ── PnpDeviceDescription (MS-RDPEPNP §2.2.1.3.1.1) ──

/// `PNP_DEVICE_DESCRIPTION` — variable-size structure embedded in
/// [`ClientDeviceAdditionMsg`].
///
/// Byte arrays are stored verbatim to avoid lossy re-encoding: the spec
/// calls out multisz UTF-16LE layouts for several of them but never
/// requires the receiver to re-parse the strings, so round-trip fidelity
/// is preserved by keeping the raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PnpDeviceDescription {
    /// `ClientDeviceID` — client-chosen unique identifier referenced by
    /// subsequent I/O traffic on `FileRedirectorChannel`.
    pub client_device_id: u32,
    /// `InterfaceGUIDArray` — concatenation of 16-byte GUIDs; its length
    /// MUST be a multiple of 16 per spec (§2.2.1.3.1.1).
    pub interface_guid_array: Vec<u8>,
    /// `HardwareId` — multisz UTF-16LE string (bytes).
    pub hardware_id: Vec<u8>,
    /// `CompatibilityID` — multisz UTF-16LE string (bytes).
    pub compatibility_id: Vec<u8>,
    /// `DeviceDescription` — UTF-16LE string (non-null-terminated).
    pub device_description: Vec<u8>,
    /// `CustomFlag` — redirectability flag (see [`crate::constants::custom_flag`]).
    pub custom_flag: u32,
    /// Optional `ContainerId` (RDP 7.0+, Appendix A §<6>): composite-device
    /// GUID. `Some` ↔ the optional `cbContainerId`/`ContainerId` pair is
    /// present on the wire.
    pub container_id: Option<[u8; 16]>,
    /// Optional `DeviceCaps` bitmask (RDP 7.0+, Appendix A §<7>).
    /// `Some` ↔ the optional `cbDeviceCaps`/`DeviceCaps` pair is present.
    pub device_caps: Option<u32>,
}

const DD_CTX: &str = "PnpDeviceDescription";

impl PnpDeviceDescription {
    /// Total encoded size of this description, equal to the `DataSize`
    /// field the spec requires the encoder to set.
    pub fn size(&self) -> usize {
        let mut n = PNP_DEVICE_DESCRIPTION_MIN_SIZE
            + self.interface_guid_array.len()
            + self.hardware_id.len()
            + self.compatibility_id.len()
            + self.device_description.len();
        if self.container_id.is_some() {
            n += CONTAINER_ID_BLOCK_SIZE;
        }
        if self.device_caps.is_some() {
            n += DEVICE_CAPS_BLOCK_SIZE;
        }
        n
    }

    pub(crate) fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.interface_guid_array.len() % 16 != 0 {
            return Err(EncodeError::invalid_value(
                DD_CTX,
                "InterfaceGUIDArray length not multiple of 16",
            ));
        }
        let total = self.size();
        if total > u32::MAX as usize {
            return Err(EncodeError::invalid_value(DD_CTX, "DataSize overflow"));
        }
        dst.write_u32_le(self.client_device_id, DD_CTX)?;
        dst.write_u32_le(total as u32, DD_CTX)?;
        dst.write_u32_le(self.interface_guid_array.len() as u32, DD_CTX)?;
        dst.write_slice(&self.interface_guid_array, DD_CTX)?;
        dst.write_u32_le(self.hardware_id.len() as u32, DD_CTX)?;
        dst.write_slice(&self.hardware_id, DD_CTX)?;
        dst.write_u32_le(self.compatibility_id.len() as u32, DD_CTX)?;
        dst.write_slice(&self.compatibility_id, DD_CTX)?;
        dst.write_u32_le(self.device_description.len() as u32, DD_CTX)?;
        dst.write_slice(&self.device_description, DD_CTX)?;
        dst.write_u32_le(crate::constants::CUSTOM_FLAG_LENGTH, DD_CTX)?;
        dst.write_u32_le(self.custom_flag, DD_CTX)?;
        if let Some(container) = &self.container_id {
            dst.write_u32_le(crate::constants::CB_CONTAINER_ID, DD_CTX)?;
            dst.write_slice(container, DD_CTX)?;
        }
        if let Some(caps) = self.device_caps {
            dst.write_u32_le(crate::constants::CB_DEVICE_CAPS, DD_CTX)?;
            dst.write_u32_le(caps, DD_CTX)?;
        }
        Ok(())
    }

    pub(crate) fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        if src.remaining() < PNP_DEVICE_DESCRIPTION_MIN_SIZE {
            return Err(DecodeError::invalid_value(DD_CTX, "truncated"));
        }
        let client_device_id = src.read_u32_le(DD_CTX)?;
        let data_size = src.read_u32_le(DD_CTX)? as usize;
        // Anything smaller than the mandatory fixed fields is a protocol
        // violation; anything exceeding what remains in the buffer would
        // make us over-read.
        if data_size < PNP_DEVICE_DESCRIPTION_MIN_SIZE {
            return Err(DecodeError::invalid_value(DD_CTX, "DataSize too small"));
        }
        // `data_size` counts the `ClientDeviceID` + `DataSize` fields we
        // just consumed, so the remaining body we're allowed to read is
        // `data_size - 8`.
        let body_remaining = data_size - 8;
        if body_remaining > src.remaining() {
            return Err(DecodeError::invalid_value(DD_CTX, "DataSize > buffer"));
        }
        // Snapshot the pre-body position so we can check the declared
        // `DataSize` matches what we actually consume.
        let before_body = src.remaining();

        // Each variable-length field is bounded by a named cap before
        // allocation. Without these caps a compromised server could
        // inflate one field to the full DVC payload size (potentially
        // tens of MiB), causing an allocation DoS on the client.
        let cb_interface = src.read_u32_le(DD_CTX)? as usize;
        if cb_interface % 16 != 0 {
            return Err(DecodeError::invalid_value(
                DD_CTX,
                "cbInterfaceLength not multiple of 16",
            ));
        }
        if cb_interface > MAX_INTERFACE_BYTES {
            return Err(DecodeError::invalid_value(DD_CTX, "cbInterfaceLength cap"));
        }
        let interface_guid_array = read_vec(src, cb_interface)?;

        let cb_hw = src.read_u32_le(DD_CTX)? as usize;
        if cb_hw > MAX_HARDWARE_ID_BYTES {
            return Err(DecodeError::invalid_value(DD_CTX, "cbHardwareIdLength cap"));
        }
        let hardware_id = read_vec(src, cb_hw)?;

        let cb_compat = src.read_u32_le(DD_CTX)? as usize;
        if cb_compat > MAX_COMPAT_ID_BYTES {
            return Err(DecodeError::invalid_value(DD_CTX, "cbCompatIdLength cap"));
        }
        let compatibility_id = read_vec(src, cb_compat)?;

        let cb_desc = src.read_u32_le(DD_CTX)? as usize;
        if cb_desc > MAX_DEVICE_DESCRIPTION_BYTES {
            return Err(DecodeError::invalid_value(
                DD_CTX,
                "cbDeviceDescriptionLength cap",
            ));
        }
        let device_description = read_vec(src, cb_desc)?;

        let custom_flag_length = src.read_u32_le(DD_CTX)?;
        if custom_flag_length != crate::constants::CUSTOM_FLAG_LENGTH {
            return Err(DecodeError::invalid_value(DD_CTX, "CustomFlagLength"));
        }
        let custom_flag = src.read_u32_le(DD_CTX)?;

        // Determine which optional tail fields are present by comparing
        // bytes consumed against the declared DataSize. Spec allows four
        // shapes: none, ContainerId only, DeviceCaps only, or both.
        let consumed_so_far = before_body - src.remaining();
        let mut remaining_body = body_remaining
            .checked_sub(consumed_so_far)
            .ok_or_else(|| DecodeError::invalid_value(DD_CTX, "DataSize underflow"))?;

        let mut container_id = None;
        let mut device_caps = None;

        // Optional tail (§2.2.1.3.1.1): ContainerId MUST precede DeviceCaps
        // when both are present. Each block carries a sentinel `cb*` length
        // (CB_CONTAINER_ID=0x10, CB_DEVICE_CAPS=0x04) that we verify to
        // reject truncated or malformed tails.
        if remaining_body >= CONTAINER_ID_BLOCK_SIZE {
            let cb_container = src.read_u32_le(DD_CTX)?;
            if cb_container != crate::constants::CB_CONTAINER_ID {
                return Err(DecodeError::invalid_value(DD_CTX, "cbContainerId"));
            }
            let mut buf = [0u8; 16];
            buf.copy_from_slice(src.read_slice(16, DD_CTX)?);
            container_id = Some(buf);
            remaining_body -= CONTAINER_ID_BLOCK_SIZE;
        }
        if remaining_body >= DEVICE_CAPS_BLOCK_SIZE {
            let cb_caps = src.read_u32_le(DD_CTX)?;
            if cb_caps != crate::constants::CB_DEVICE_CAPS {
                return Err(DecodeError::invalid_value(DD_CTX, "cbDeviceCaps"));
            }
            device_caps = Some(src.read_u32_le(DD_CTX)?);
            remaining_body -= DEVICE_CAPS_BLOCK_SIZE;
        }
        if remaining_body != 0 {
            return Err(DecodeError::invalid_value(DD_CTX, "DataSize mismatch"));
        }

        Ok(Self {
            client_device_id,
            interface_guid_array,
            hardware_id,
            compatibility_id,
            device_description,
            custom_flag,
            container_id,
            device_caps,
        })
    }
}

fn read_vec(src: &mut ReadCursor<'_>, n: usize) -> DecodeResult<Vec<u8>> {
    let slice = src.read_slice(n, DD_CTX)?;
    Ok(slice.to_vec())
}

// ── ClientDeviceAdditionMsg (C→S, MS-RDPEPNP §2.2.1.3.1) ──

/// Client Device Addition Message — announces zero or more PnP devices
/// for redirection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientDeviceAdditionMsg {
    pub devices: Vec<PnpDeviceDescription>,
}

const ADD_CTX: &str = "ClientDeviceAdditionMsg";

impl ClientDeviceAdditionMsg {
    pub fn new(devices: Vec<PnpDeviceDescription>) -> Self {
        Self { devices }
    }
}

impl Encode for ClientDeviceAdditionMsg {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let total = self.size();
        if total > u32::MAX as usize {
            return Err(EncodeError::invalid_value(ADD_CTX, "Size overflow"));
        }
        PnpInfoHeader::new(total as u32, packet_id::IRPDR_ID_REDIRECT_DEVICES).encode(dst)?;
        dst.write_u32_le(self.devices.len() as u32, ADD_CTX)?;
        for d in &self.devices {
            d.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        ADD_CTX
    }

    fn size(&self) -> usize {
        DEVICE_ADDITION_FIXED_SIZE + self.devices.iter().map(|d| d.size()).sum::<usize>()
    }
}

impl<'de> Decode<'de> for ClientDeviceAdditionMsg {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = PnpInfoHeader::decode(src)?;
        if hdr.packet_id != packet_id::IRPDR_ID_REDIRECT_DEVICES {
            return Err(DecodeError::invalid_value(ADD_CTX, "PacketId"));
        }
        let declared_body = (hdr.size as usize)
            .checked_sub(PNP_INFO_HEADER_SIZE)
            .ok_or_else(|| DecodeError::invalid_value(ADD_CTX, "Size < header"))?;
        if declared_body < 4 {
            return Err(DecodeError::invalid_value(ADD_CTX, "Size < header + count"));
        }
        if declared_body > src.remaining() {
            return Err(DecodeError::invalid_value(ADD_CTX, "Size > buffer"));
        }
        let before_body = src.remaining();
        let count = src.read_u32_le(ADD_CTX)? as usize;
        // Enforce the hard DoS cap first — MAX_DEVICES is the ceiling
        // shared with the outbound registry — so malicious `DeviceCount`
        // values cannot pre-allocate a huge `Vec`.
        if count > MAX_DEVICES {
            return Err(DecodeError::invalid_value(ADD_CTX, "DeviceCount > MAX_DEVICES"));
        }
        // Additional check: each described device costs at least
        // PNP_DEVICE_DESCRIPTION_MIN_SIZE bytes, so the count must also
        // fit inside the declared body (after the 4-byte DeviceCount
        // field we just consumed).
        if count
            .checked_mul(PNP_DEVICE_DESCRIPTION_MIN_SIZE)
            .map(|min| min + 4 > declared_body)
            .unwrap_or(true)
        {
            return Err(DecodeError::invalid_value(ADD_CTX, "DeviceCount too large"));
        }
        let mut devices = Vec::with_capacity(count);
        for _ in 0..count {
            devices.push(PnpDeviceDescription::decode(src)?);
        }
        let consumed = before_body - src.remaining();
        if consumed != declared_body {
            return Err(DecodeError::invalid_value(ADD_CTX, "Size mismatch"));
        }
        Ok(Self { devices })
    }
}

// ── ClientDeviceRemovalMsg (C→S, MS-RDPEPNP §2.2.1.3.2) ──

/// Client Device Removal Message — requests removal of a single
/// previously announced device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientDeviceRemovalMsg {
    pub client_device_id: u32,
}

const REM_CTX: &str = "ClientDeviceRemovalMsg";

impl Encode for ClientDeviceRemovalMsg {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        PnpInfoHeader::new(
            DEVICE_REMOVAL_MSG_SIZE as u32,
            packet_id::IRPDR_ID_UNREDIRECT_DEVICE,
        )
        .encode(dst)?;
        dst.write_u32_le(self.client_device_id, REM_CTX)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        REM_CTX
    }

    fn size(&self) -> usize {
        DEVICE_REMOVAL_MSG_SIZE
    }
}

impl<'de> Decode<'de> for ClientDeviceRemovalMsg {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = PnpInfoHeader::decode(src)?;
        hdr.expect(
            packet_id::IRPDR_ID_UNREDIRECT_DEVICE,
            DEVICE_REMOVAL_MSG_SIZE as u32,
            REM_CTX,
        )?;
        Ok(Self {
            client_device_id: src.read_u32_le(REM_CTX)?,
        })
    }
}

