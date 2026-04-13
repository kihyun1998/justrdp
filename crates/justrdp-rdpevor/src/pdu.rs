//! MS-RDPEVOR §2.2 Message Syntax — wire-format PDUs.
//!
//! All multi-byte integer fields are little-endian. All PDUs share the
//! 8-byte `TSMM_VIDEO_PACKET_HEADER` (§2.2.1.1) consisting of a total
//! byte-size and a packet type tag.

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

// ── DVC channel names (MS-RDPEVOR §2.1) ──

/// Control channel name.
pub const CONTROL_CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Video::Control::v08.01";

/// Data channel name.
pub const DATA_CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Video::Data::v08.01";

// ── TSMM packet types (§2.2.1.1) ──

pub const TSMM_PACKET_TYPE_PRESENTATION_REQUEST: u32 = 1;
pub const TSMM_PACKET_TYPE_PRESENTATION_RESPONSE: u32 = 2;
pub const TSMM_PACKET_TYPE_CLIENT_NOTIFICATION: u32 = 3;
pub const TSMM_PACKET_TYPE_VIDEO_DATA: u32 = 4;

// ── Command and flag constants (§2.2.1.2 – §2.2.1.6) ──

pub const TSMM_VIDEO_PLAYBACK_COMMAND_START: u8 = 1;
pub const TSMM_VIDEO_PLAYBACK_COMMAND_STOP: u8 = 2;

pub const TSMM_VIDEO_DATA_FLAG_HAS_TIMESTAMPS: u8 = 0x01;
pub const TSMM_VIDEO_DATA_FLAG_KEYFRAME: u8 = 0x02;
pub const TSMM_VIDEO_DATA_FLAG_NEW_FRAMERATE: u8 = 0x04;

pub const TSMM_FRAMERATE_FLAG_UNRESTRICTED: u32 = 1;
pub const TSMM_FRAMERATE_FLAG_OVERRIDE: u32 = 2;

pub const TSMM_CLIENT_NOTIFICATION_TYPE_NETWORK_ERROR: u8 = 1;
pub const TSMM_CLIENT_NOTIFICATION_TYPE_FRAMERATE_OVERRIDE: u8 = 2;

pub const TSMM_PROTOCOL_VERSION_RDP8: u8 = 0x01;

/// Wire layout of `MFVideoFormat_H264`:
/// GUID `{34363248-0000-0010-8000-00AA00389B71}`.
///
/// First 4 bytes are Data1 (u32 LE `0x34363248` → bytes `48 32 36 34` = "H264"),
/// then Data2/Data3 (u16 LE), then the 8 big-endian Data4 bytes.
pub const MF_VIDEO_FORMAT_H264_BYTES: [u8; 16] = [
    0x48, 0x32, 0x36, 0x34, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

// ── DoS caps (§9) ──

pub const MAX_CONCURRENT_PRESENTATIONS: usize = 16;
pub const MAX_CBSAMPLE: u32 = 1_048_576;
pub const MAX_CBEXTRA: u32 = 65_536;
pub const MAX_PACKETS_IN_SAMPLE: u16 = 1024;
pub const MAX_PENDING_REASSEMBLY_SAMPLES: usize = 32;
/// Hard byte budget for in-flight reassembly state, per presentation.
///
/// The count-based cap (`MAX_PENDING_REASSEMBLY_SAMPLES`) on its own is
/// insufficient because a single slot can accumulate up to
/// `MAX_PACKETS_IN_SAMPLE × MAX_CBSAMPLE` bytes. This cap bounds the
/// actual heap footprint an attacker can hold per presentation at
/// approximately 32 MiB.
pub const MAX_PER_PRESENTATION_REASSEMBLY_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_SCALED_WIDTH: u32 = 1920;
pub const MAX_SCALED_HEIGHT: u32 = 1080;
pub const MAX_DESIRED_FRAMERATE: u32 = 30;

// ── TsmmHeader (§2.2.1.1) ──

/// 8-byte common header prepended to every TSMM PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsmmHeader {
    pub cb_size: u32,
    pub packet_type: u32,
}

impl TsmmHeader {
    pub const WIRE_SIZE: usize = 8;

    pub fn new(packet_type: u32, cb_size: u32) -> Self {
        Self { cb_size, packet_type }
    }
}

impl Encode for TsmmHeader {
    fn name(&self) -> &'static str {
        "TSMM_VIDEO_PACKET_HEADER"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "TSMM_VIDEO_PACKET_HEADER";
        dst.write_u32_le(self.cb_size, CTX)?;
        dst.write_u32_le(self.packet_type, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for TsmmHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "TSMM_VIDEO_PACKET_HEADER";
        let cb_size = src.read_u32_le(CTX)?;
        let packet_type = src.read_u32_le(CTX)?;
        Ok(Self { cb_size, packet_type })
    }
}

// ── PresentationRequest (§2.2.1.2) ──

/// `TSMM_PRESENTATION_REQUEST` — server→client on the Control channel.
///
/// Total wire size is always `68 + extra_data.len()`. For Stop commands
/// all trailing fields are zero and `extra_data` is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationRequest {
    pub presentation_id: u8,
    pub version: u8,
    pub command: u8,
    pub frame_rate: u8,
    pub average_bitrate_kbps: u16,
    pub reserved: u16,
    pub source_width: u32,
    pub source_height: u32,
    pub scaled_width: u32,
    pub scaled_height: u32,
    pub hns_timestamp_offset: u64,
    pub geometry_mapping_id: u64,
    pub video_subtype_id: [u8; 16],
    pub extra_data: Vec<u8>,
}

impl PresentationRequest {
    /// Minimum (Stop) wire size, in bytes.
    pub const MIN_WIRE_SIZE: u32 = 68;

    /// Build a Start request for the H.264 subtype.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        presentation_id: u8,
        source_width: u32,
        source_height: u32,
        scaled_width: u32,
        scaled_height: u32,
        hns_timestamp_offset: u64,
        geometry_mapping_id: u64,
        extra_data: Vec<u8>,
    ) -> Self {
        Self {
            presentation_id,
            version: TSMM_PROTOCOL_VERSION_RDP8,
            command: TSMM_VIDEO_PLAYBACK_COMMAND_START,
            frame_rate: 0,
            average_bitrate_kbps: 0,
            reserved: 0,
            source_width,
            source_height,
            scaled_width,
            scaled_height,
            hns_timestamp_offset,
            geometry_mapping_id,
            video_subtype_id: MF_VIDEO_FORMAT_H264_BYTES,
            extra_data,
        }
    }

    /// Build a Stop request; all fields after `command` are zeroed.
    pub fn stop(presentation_id: u8) -> Self {
        Self {
            presentation_id,
            version: TSMM_PROTOCOL_VERSION_RDP8,
            command: TSMM_VIDEO_PLAYBACK_COMMAND_STOP,
            frame_rate: 0,
            average_bitrate_kbps: 0,
            reserved: 0,
            source_width: 0,
            source_height: 0,
            scaled_width: 0,
            scaled_height: 0,
            hns_timestamp_offset: 0,
            geometry_mapping_id: 0,
            video_subtype_id: [0u8; 16],
            extra_data: Vec::new(),
        }
    }

    fn cb_size(&self) -> EncodeResult<u32> {
        let extra = u32::try_from(self.extra_data.len()).map_err(|_| {
            EncodeError::invalid_value("TSMM_PRESENTATION_REQUEST", "cbExtra overflow")
        })?;
        if extra > MAX_CBEXTRA {
            return Err(EncodeError::invalid_value(
                "TSMM_PRESENTATION_REQUEST",
                "cbExtra > MAX_CBEXTRA",
            ));
        }
        Ok(Self::MIN_WIRE_SIZE + extra)
    }
}

impl Encode for PresentationRequest {
    fn name(&self) -> &'static str {
        "TSMM_PRESENTATION_REQUEST"
    }
    fn size(&self) -> usize {
        Self::MIN_WIRE_SIZE as usize + self.extra_data.len()
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "TSMM_PRESENTATION_REQUEST";
        let cb_size = self.cb_size()?;
        TsmmHeader::new(TSMM_PACKET_TYPE_PRESENTATION_REQUEST, cb_size).encode(dst)?;
        dst.write_u8(self.presentation_id, CTX)?;
        dst.write_u8(self.version, CTX)?;
        dst.write_u8(self.command, CTX)?;
        dst.write_u8(self.frame_rate, CTX)?;
        dst.write_u16_le(self.average_bitrate_kbps, CTX)?;
        dst.write_u16_le(self.reserved, CTX)?;
        dst.write_u32_le(self.source_width, CTX)?;
        dst.write_u32_le(self.source_height, CTX)?;
        dst.write_u32_le(self.scaled_width, CTX)?;
        dst.write_u32_le(self.scaled_height, CTX)?;
        dst.write_u64_le(self.hns_timestamp_offset, CTX)?;
        dst.write_u64_le(self.geometry_mapping_id, CTX)?;
        dst.write_slice(&self.video_subtype_id, CTX)?;
        let cb_extra = u32::try_from(self.extra_data.len())
            .map_err(|_| EncodeError::invalid_value(CTX, "cbExtra"))?;
        if cb_extra > MAX_CBEXTRA {
            return Err(EncodeError::invalid_value(CTX, "cbExtra cap"));
        }
        dst.write_u32_le(cb_extra, CTX)?;
        dst.write_slice(&self.extra_data, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for PresentationRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "TSMM_PRESENTATION_REQUEST";
        let header = TsmmHeader::decode(src)?;
        if header.packet_type != TSMM_PACKET_TYPE_PRESENTATION_REQUEST {
            return Err(DecodeError::invalid_value(CTX, "PacketType"));
        }
        if header.cb_size < 68 {
            return Err(DecodeError::invalid_value(CTX, "cbSize < 68"));
        }
        let presentation_id = src.read_u8(CTX)?;
        let version = src.read_u8(CTX)?;
        let command = src.read_u8(CTX)?;
        let frame_rate = src.read_u8(CTX)?;
        let average_bitrate_kbps = src.read_u16_le(CTX)?;
        let reserved = src.read_u16_le(CTX)?;
        let source_width = src.read_u32_le(CTX)?;
        let source_height = src.read_u32_le(CTX)?;
        let scaled_width = src.read_u32_le(CTX)?;
        let scaled_height = src.read_u32_le(CTX)?;
        let hns_timestamp_offset = src.read_u64_le(CTX)?;
        let geometry_mapping_id = src.read_u64_le(CTX)?;
        let subtype_slice = src.read_slice(16, CTX)?;
        let mut video_subtype_id = [0u8; 16];
        video_subtype_id.copy_from_slice(subtype_slice);
        let cb_extra = src.read_u32_le(CTX)?;

        if command != TSMM_VIDEO_PLAYBACK_COMMAND_START
            && command != TSMM_VIDEO_PLAYBACK_COMMAND_STOP
        {
            return Err(DecodeError::invalid_value(CTX, "Command"));
        }

        if command == TSMM_VIDEO_PLAYBACK_COMMAND_STOP {
            if header.cb_size != 68 || cb_extra != 0 {
                return Err(DecodeError::invalid_value(CTX, "Stop cbSize must be 68"));
            }
        } else {
            if cb_extra > MAX_CBEXTRA {
                return Err(DecodeError::invalid_value(CTX, "cbExtra cap"));
            }
            if header.cb_size != 68u32.saturating_add(cb_extra) {
                return Err(DecodeError::invalid_value(CTX, "cbSize != 68 + cbExtra"));
            }
            if scaled_width == 0 || scaled_width > MAX_SCALED_WIDTH {
                return Err(DecodeError::invalid_value(CTX, "ScaledWidth"));
            }
            if scaled_height == 0 || scaled_height > MAX_SCALED_HEIGHT {
                return Err(DecodeError::invalid_value(CTX, "ScaledHeight"));
            }
        }

        let cb_extra_usize = usize::try_from(cb_extra)
            .map_err(|_| DecodeError::invalid_value(CTX, "cbExtra usize"))?;
        let extra = src.read_slice(cb_extra_usize, CTX)?.to_vec();

        Ok(Self {
            presentation_id,
            version,
            command,
            frame_rate,
            average_bitrate_kbps,
            reserved,
            source_width,
            source_height,
            scaled_width,
            scaled_height,
            hns_timestamp_offset,
            geometry_mapping_id,
            video_subtype_id,
            extra_data: extra,
        })
    }
}

// ── PresentationResponse (§2.2.1.3) ──

/// `TSMM_PRESENTATION_RESPONSE` — client→server, 12 bytes fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationResponse {
    pub presentation_id: u8,
    pub response_flags: u8,
    pub result_flags: u16,
}

impl PresentationResponse {
    pub const WIRE_SIZE: u32 = 12;

    pub fn new(presentation_id: u8) -> Self {
        Self { presentation_id, response_flags: 0, result_flags: 0 }
    }
}

impl Encode for PresentationResponse {
    fn name(&self) -> &'static str {
        "TSMM_PRESENTATION_RESPONSE"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE as usize
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "TSMM_PRESENTATION_RESPONSE";
        TsmmHeader::new(TSMM_PACKET_TYPE_PRESENTATION_RESPONSE, Self::WIRE_SIZE).encode(dst)?;
        dst.write_u8(self.presentation_id, CTX)?;
        dst.write_u8(self.response_flags, CTX)?;
        dst.write_u16_le(self.result_flags, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for PresentationResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "TSMM_PRESENTATION_RESPONSE";
        let header = TsmmHeader::decode(src)?;
        if header.packet_type != TSMM_PACKET_TYPE_PRESENTATION_RESPONSE {
            return Err(DecodeError::invalid_value(CTX, "PacketType"));
        }
        if header.cb_size != Self::WIRE_SIZE {
            return Err(DecodeError::invalid_value(CTX, "cbSize != 12"));
        }
        let presentation_id = src.read_u8(CTX)?;
        let response_flags = src.read_u8(CTX)?;
        let result_flags = src.read_u16_le(CTX)?;
        if response_flags != 0 || result_flags != 0 {
            return Err(DecodeError::invalid_value(CTX, "Reserved must be zero"));
        }
        Ok(Self { presentation_id, response_flags, result_flags })
    }
}

// ── FrameRateOverride (§2.2.1.5) ──

/// Inner payload of a `FrameRateOverride` client notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRateOverride {
    pub flags: u32,
    pub desired_frame_rate: u32,
    pub reserved1: u32,
    pub reserved2: u32,
}

impl FrameRateOverride {
    pub const WIRE_SIZE: u32 = 16;

    pub fn unrestricted() -> Self {
        Self {
            flags: TSMM_FRAMERATE_FLAG_UNRESTRICTED,
            desired_frame_rate: 0,
            reserved1: 0,
            reserved2: 0,
        }
    }

    pub fn override_rate(desired_frame_rate: u32) -> Self {
        Self {
            flags: TSMM_FRAMERATE_FLAG_OVERRIDE,
            desired_frame_rate,
            reserved1: 0,
            reserved2: 0,
        }
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "TSMM_FRAMERATE_OVERRIDE";
        dst.write_u32_le(self.flags, CTX)?;
        dst.write_u32_le(self.desired_frame_rate, CTX)?;
        dst.write_u32_le(self.reserved1, CTX)?;
        dst.write_u32_le(self.reserved2, CTX)?;
        Ok(())
    }

    fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        const CTX: &str = "TSMM_FRAMERATE_OVERRIDE";
        let flags = src.read_u32_le(CTX)?;
        let desired_frame_rate = src.read_u32_le(CTX)?;
        let reserved1 = src.read_u32_le(CTX)?;
        let reserved2 = src.read_u32_le(CTX)?;
        Self::validate(flags, desired_frame_rate)?;
        Ok(Self { flags, desired_frame_rate, reserved1, reserved2 })
    }

    fn validate(flags: u32, desired: u32) -> DecodeResult<()> {
        const CTX: &str = "TSMM_FRAMERATE_OVERRIDE";
        // Spec §2.2.1.5: only the exact values 1 (UNRESTRICTED) and 2
        // (OVERRIDE) are defined. Reject any other bit pattern, including
        // combinations and stray high bits.
        match flags {
            TSMM_FRAMERATE_FLAG_UNRESTRICTED => Ok(()),
            TSMM_FRAMERATE_FLAG_OVERRIDE => {
                if (1..=MAX_DESIRED_FRAMERATE).contains(&desired) {
                    Ok(())
                } else {
                    Err(DecodeError::invalid_value(CTX, "DesiredFrameRate out of range"))
                }
            }
            _ => Err(DecodeError::invalid_value(CTX, "Flags")),
        }
    }
}

// ── ClientNotification (§2.2.1.4) ──

/// Typed payload of a `ClientNotification`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationData {
    NetworkError,
    FrameRateOverride(FrameRateOverride),
}

/// `TSMM_CLIENT_NOTIFICATION` — client→server on the Control channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientNotification {
    pub presentation_id: u8,
    pub notification_type: u8,
    pub reserved: u16,
    pub data: NotificationData,
}

impl ClientNotification {
    pub const HEADER_SIZE: u32 = 16;

    pub fn network_error(presentation_id: u8) -> Self {
        Self {
            presentation_id,
            notification_type: TSMM_CLIENT_NOTIFICATION_TYPE_NETWORK_ERROR,
            reserved: 0,
            data: NotificationData::NetworkError,
        }
    }

    pub fn frame_rate_override(presentation_id: u8, override_: FrameRateOverride) -> Self {
        Self {
            presentation_id,
            notification_type: TSMM_CLIENT_NOTIFICATION_TYPE_FRAMERATE_OVERRIDE,
            reserved: 0,
            data: NotificationData::FrameRateOverride(override_),
        }
    }

    fn cb_size(&self) -> u32 {
        match self.data {
            NotificationData::NetworkError => 16,
            NotificationData::FrameRateOverride(_) => 32,
        }
    }

    fn cb_data(&self) -> u32 {
        match self.data {
            NotificationData::NetworkError => 0,
            NotificationData::FrameRateOverride(_) => FrameRateOverride::WIRE_SIZE,
        }
    }
}

impl Encode for ClientNotification {
    fn name(&self) -> &'static str {
        "TSMM_CLIENT_NOTIFICATION"
    }
    fn size(&self) -> usize {
        self.cb_size() as usize
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "TSMM_CLIENT_NOTIFICATION";
        TsmmHeader::new(TSMM_PACKET_TYPE_CLIENT_NOTIFICATION, self.cb_size()).encode(dst)?;
        dst.write_u8(self.presentation_id, CTX)?;
        dst.write_u8(self.notification_type, CTX)?;
        dst.write_u16_le(self.reserved, CTX)?;
        dst.write_u32_le(self.cb_data(), CTX)?;
        if let NotificationData::FrameRateOverride(ref f) = self.data {
            f.encode(dst)?;
        }
        Ok(())
    }
}

impl<'de> Decode<'de> for ClientNotification {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "TSMM_CLIENT_NOTIFICATION";
        let header = TsmmHeader::decode(src)?;
        if header.packet_type != TSMM_PACKET_TYPE_CLIENT_NOTIFICATION {
            return Err(DecodeError::invalid_value(CTX, "PacketType"));
        }
        let presentation_id = src.read_u8(CTX)?;
        let notification_type = src.read_u8(CTX)?;
        let reserved = src.read_u16_le(CTX)?;
        let cb_data = src.read_u32_le(CTX)?;
        if header.cb_size != Self::HEADER_SIZE.saturating_add(cb_data) {
            return Err(DecodeError::invalid_value(CTX, "cbSize mismatch"));
        }
        let data = match notification_type {
            TSMM_CLIENT_NOTIFICATION_TYPE_NETWORK_ERROR => {
                if cb_data != 0 {
                    return Err(DecodeError::invalid_value(CTX, "NetworkError cbData != 0"));
                }
                NotificationData::NetworkError
            }
            TSMM_CLIENT_NOTIFICATION_TYPE_FRAMERATE_OVERRIDE => {
                if cb_data != FrameRateOverride::WIRE_SIZE {
                    return Err(DecodeError::invalid_value(
                        CTX,
                        "FrameRateOverride cbData != 16",
                    ));
                }
                NotificationData::FrameRateOverride(FrameRateOverride::decode(src)?)
            }
            _ => return Err(DecodeError::invalid_value(CTX, "NotificationType")),
        };
        Ok(Self { presentation_id, notification_type, reserved, data })
    }
}

// ── VideoData (§2.2.1.6) ──

/// `TSMM_VIDEO_DATA` — server→client on the Data channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoData {
    pub presentation_id: u8,
    pub version: u8,
    pub flags: u8,
    pub reserved: u8,
    pub hns_timestamp: u64,
    pub hns_duration: u64,
    pub current_packet_index: u16,
    pub packets_in_sample: u16,
    pub sample_number: u32,
    pub sample: Vec<u8>,
}

impl VideoData {
    /// Fixed prefix size (header + all pre-sample fields).
    pub const HEADER_SIZE: u32 = 40;

    fn cb_size(&self) -> EncodeResult<u32> {
        let cb_sample = u32::try_from(self.sample.len())
            .map_err(|_| EncodeError::invalid_value("TSMM_VIDEO_DATA", "cbSample overflow"))?;
        if cb_sample > MAX_CBSAMPLE {
            return Err(EncodeError::invalid_value("TSMM_VIDEO_DATA", "cbSample cap"));
        }
        Ok(Self::HEADER_SIZE + cb_sample)
    }
}

impl Encode for VideoData {
    fn name(&self) -> &'static str {
        "TSMM_VIDEO_DATA"
    }
    fn size(&self) -> usize {
        Self::HEADER_SIZE as usize + self.sample.len()
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "TSMM_VIDEO_DATA";
        let cb_size = self.cb_size()?;
        let cb_sample = cb_size - Self::HEADER_SIZE;
        TsmmHeader::new(TSMM_PACKET_TYPE_VIDEO_DATA, cb_size).encode(dst)?;
        dst.write_u8(self.presentation_id, CTX)?;
        dst.write_u8(self.version, CTX)?;
        dst.write_u8(self.flags, CTX)?;
        dst.write_u8(self.reserved, CTX)?;
        dst.write_u64_le(self.hns_timestamp, CTX)?;
        dst.write_u64_le(self.hns_duration, CTX)?;
        dst.write_u16_le(self.current_packet_index, CTX)?;
        dst.write_u16_le(self.packets_in_sample, CTX)?;
        dst.write_u32_le(self.sample_number, CTX)?;
        dst.write_u32_le(cb_sample, CTX)?;
        dst.write_slice(&self.sample, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for VideoData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "TSMM_VIDEO_DATA";
        let header = TsmmHeader::decode(src)?;
        if header.packet_type != TSMM_PACKET_TYPE_VIDEO_DATA {
            return Err(DecodeError::invalid_value(CTX, "PacketType"));
        }
        if header.cb_size < Self::HEADER_SIZE {
            return Err(DecodeError::invalid_value(CTX, "cbSize < 40"));
        }
        let presentation_id = src.read_u8(CTX)?;
        let version = src.read_u8(CTX)?;
        let flags = src.read_u8(CTX)?;
        let reserved = src.read_u8(CTX)?;
        let hns_timestamp = src.read_u64_le(CTX)?;
        let hns_duration = src.read_u64_le(CTX)?;
        let current_packet_index = src.read_u16_le(CTX)?;
        let packets_in_sample = src.read_u16_le(CTX)?;
        let sample_number = src.read_u32_le(CTX)?;
        let cb_sample = src.read_u32_le(CTX)?;

        if cb_sample > MAX_CBSAMPLE {
            return Err(DecodeError::invalid_value(CTX, "cbSample cap"));
        }
        if header.cb_size != Self::HEADER_SIZE.saturating_add(cb_sample) {
            return Err(DecodeError::invalid_value(CTX, "cbSize != 40 + cbSample"));
        }
        if packets_in_sample == 0 || packets_in_sample > MAX_PACKETS_IN_SAMPLE {
            return Err(DecodeError::invalid_value(CTX, "PacketsInSample"));
        }
        if current_packet_index == 0 || current_packet_index > packets_in_sample {
            return Err(DecodeError::invalid_value(CTX, "CurrentPacketIndex"));
        }
        if sample_number == 0 {
            return Err(DecodeError::invalid_value(CTX, "SampleNumber"));
        }

        let cb_sample_usize = usize::try_from(cb_sample)
            .map_err(|_| DecodeError::invalid_value(CTX, "cbSample usize"))?;
        let sample = src.read_slice(cb_sample_usize, CTX)?.to_vec();

        Ok(Self {
            presentation_id,
            version,
            flags,
            reserved,
            hns_timestamp,
            hns_duration,
            current_packet_index,
            packets_in_sample,
            sample_number,
            sample,
        })
    }
}

// Helper: encode any PDU into an owned Vec.
pub(crate) fn encode_to_vec<E: Encode>(pdu: &E) -> EncodeResult<Vec<u8>> {
    let mut buf = vec![0u8; pdu.size()];
    let mut cur = WriteCursor::new(&mut buf);
    pdu.encode(&mut cur)?;
    debug_assert_eq!(cur.pos(), pdu.size());
    Ok(buf)
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_enc<E: Encode>(pdu: &E) -> Vec<u8> {
        encode_to_vec(pdu).unwrap()
    }

    #[test]
    fn header_roundtrip() {
        let h = TsmmHeader::new(TSMM_PACKET_TYPE_VIDEO_DATA, 40);
        let b = roundtrip_enc(&h);
        assert_eq!(b.len(), 8);
        let mut cur = ReadCursor::new(&b);
        let d = TsmmHeader::decode(&mut cur).unwrap();
        assert_eq!(d, h);
    }

    #[test]
    fn spec_4_1_start_roundtrip() {
        // §4.1 TSMM_PRESENTATION_REQUEST Start, 105 bytes (68 fixed + 37 extra).
        let extra: Vec<u8> = (0u8..37).collect();
        let req = PresentationRequest::start(
            3,
            480,
            244,
            480,
            244,
            0x0F3B_7AA4,
            0x8000_7ABA_0004_0222,
            extra.clone(),
        );
        let bytes = roundtrip_enc(&req);
        assert_eq!(bytes.len(), 105);
        assert_eq!(&bytes[0..4], &0x69u32.to_le_bytes()); // cbSize=105
        assert_eq!(&bytes[4..8], &1u32.to_le_bytes());
        assert_eq!(bytes[8], 3); // PresentationId
        assert_eq!(bytes[9], 1); // Version
        assert_eq!(bytes[10], 1); // Command=Start
        // ScaledWidth at offset 24..28
        assert_eq!(&bytes[24..28], &480u32.to_le_bytes());
        // GeometryMappingId at offset 40..48
        assert_eq!(
            &bytes[40..48],
            &0x8000_7ABA_0004_0222u64.to_le_bytes()
        );
        // VideoSubtypeId at offset 48..64
        assert_eq!(&bytes[48..64], &MF_VIDEO_FORMAT_H264_BYTES);
        // cbExtra at offset 64..68
        assert_eq!(&bytes[64..68], &37u32.to_le_bytes());

        let mut cur = ReadCursor::new(&bytes);
        let decoded = PresentationRequest::decode(&mut cur).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn spec_4_2_response_exact() {
        // §4.2: 0C000000 02000000 03000000
        let resp = PresentationResponse::new(3);
        let bytes = roundtrip_enc(&resp);
        let expected: [u8; 12] = [
            0x0C, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        ];
        assert_eq!(bytes, expected);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = PresentationResponse::decode(&mut cur).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn spec_4_4_stop_exact() {
        // §4.4: 68 bytes, PresentationId=3, Command=2, rest zero.
        let req = PresentationRequest::stop(3);
        let bytes = roundtrip_enc(&req);
        assert_eq!(bytes.len(), 68);
        assert_eq!(&bytes[0..4], &68u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &1u32.to_le_bytes());
        assert_eq!(bytes[8], 3);
        assert_eq!(bytes[9], 1);
        assert_eq!(bytes[10], 2);
        // Everything after byte 11 should be zero.
        assert!(bytes[11..].iter().all(|b| *b == 0));

        let mut cur = ReadCursor::new(&bytes);
        let decoded = PresentationRequest::decode(&mut cur).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn spec_4_3_video_data_header() {
        // §4.3 first 40 bytes: 33030000 04000000 03010300 C7C60600 00000000 00000000
        //                      00000000 01000100 01000000 0B030000
        // cbSize=0x333=819, cbSample=779.
        let sample = vec![0u8; 779];
        let vd = VideoData {
            presentation_id: 3,
            version: 1,
            flags: TSMM_VIDEO_DATA_FLAG_HAS_TIMESTAMPS | TSMM_VIDEO_DATA_FLAG_KEYFRAME,
            reserved: 0,
            hns_timestamp: 0x0006_C6C7,
            hns_duration: 0,
            current_packet_index: 1,
            packets_in_sample: 1,
            sample_number: 1,
            sample,
        };
        let bytes = roundtrip_enc(&vd);
        assert_eq!(bytes.len(), 819);

        let expected_header: [u8; 40] = [
            0x33, 0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0x00, 0xC7, 0xC6,
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0B, 0x03, 0x00, 0x00,
        ];
        assert_eq!(&bytes[..40], &expected_header);

        let mut cur = ReadCursor::new(&bytes);
        let decoded = VideoData::decode(&mut cur).unwrap();
        assert_eq!(decoded, vd);
    }

    #[test]
    fn request_reject_bad_cb_size() {
        let req = PresentationRequest::start(1, 100, 100, 100, 100, 0, 0, vec![0u8; 10]);
        let mut bytes = roundtrip_enc(&req);
        bytes[0..4].copy_from_slice(&99u32.to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        assert!(PresentationRequest::decode(&mut cur).is_err());
    }

    #[test]
    fn request_reject_scaled_width_too_large() {
        let mut req = PresentationRequest::start(1, 100, 100, 1921, 100, 0, 0, Vec::new());
        // Manually encode bypassing validation (start() is just a ctor).
        req.scaled_width = 1921;
        let bytes = roundtrip_enc(&req);
        let mut cur = ReadCursor::new(&bytes);
        assert!(PresentationRequest::decode(&mut cur).is_err());
    }

    #[test]
    fn request_reject_scaled_height_zero() {
        let req = PresentationRequest::start(1, 100, 100, 100, 0, 0, 0, Vec::new());
        let bytes = roundtrip_enc(&req);
        let mut cur = ReadCursor::new(&bytes);
        assert!(PresentationRequest::decode(&mut cur).is_err());
    }

    #[test]
    fn request_reject_bad_command() {
        let mut req = PresentationRequest::start(1, 100, 100, 100, 100, 0, 0, Vec::new());
        req.command = 77;
        let bytes = roundtrip_enc(&req);
        let mut cur = ReadCursor::new(&bytes);
        assert!(PresentationRequest::decode(&mut cur).is_err());
    }

    #[test]
    fn request_start_empty_extra_data() {
        let req = PresentationRequest::start(1, 100, 100, 100, 100, 0, 0, Vec::new());
        let bytes = roundtrip_enc(&req);
        assert_eq!(bytes.len(), 68);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = PresentationRequest::decode(&mut cur).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_cb_extra_cap_enforced() {
        // Build a byte buffer directly with cbExtra = MAX_CBEXTRA + 1.
        let mut bytes = Vec::new();
        let bad = MAX_CBEXTRA + 1;
        bytes.extend_from_slice(&(68u32 + bad).to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 1, 1, 0]); // id, ver, cmd=Start, fr
        bytes.extend_from_slice(&[0u8; 4]); // avg, reserved
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&MF_VIDEO_FORMAT_H264_BYTES);
        bytes.extend_from_slice(&bad.to_le_bytes());
        // don't bother adding the trailing bytes; cap check fires first.
        let mut cur = ReadCursor::new(&bytes);
        assert!(PresentationRequest::decode(&mut cur).is_err());
    }

    #[test]
    fn response_reject_bad_cb_size() {
        let mut bytes = roundtrip_enc(&PresentationResponse::new(1));
        bytes[0..4].copy_from_slice(&16u32.to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        assert!(PresentationResponse::decode(&mut cur).is_err());
    }

    #[test]
    fn response_reject_nonzero_reserved() {
        let mut bytes = roundtrip_enc(&PresentationResponse::new(1));
        bytes[9] = 1;
        let mut cur = ReadCursor::new(&bytes);
        assert!(PresentationResponse::decode(&mut cur).is_err());
    }

    #[test]
    fn notification_network_error_roundtrip() {
        let n = ClientNotification::network_error(5);
        let bytes = roundtrip_enc(&n);
        assert_eq!(bytes.len(), 16);
        assert_eq!(&bytes[0..4], &16u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &3u32.to_le_bytes()); // PacketType=3
        let mut cur = ReadCursor::new(&bytes);
        let d = ClientNotification::decode(&mut cur).unwrap();
        assert_eq!(d, n);
    }

    #[test]
    fn notification_framerate_override_roundtrip() {
        let n = ClientNotification::frame_rate_override(
            2,
            FrameRateOverride::override_rate(24),
        );
        let bytes = roundtrip_enc(&n);
        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes[0..4], &32u32.to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        let d = ClientNotification::decode(&mut cur).unwrap();
        assert_eq!(d, n);
    }

    #[test]
    fn notification_framerate_unrestricted_roundtrip() {
        let n = ClientNotification::frame_rate_override(
            2,
            FrameRateOverride::unrestricted(),
        );
        let bytes = roundtrip_enc(&n);
        let mut cur = ReadCursor::new(&bytes);
        let d = ClientNotification::decode(&mut cur).unwrap();
        assert_eq!(d, n);
    }

    #[test]
    fn notification_framerate_rejects_out_of_range() {
        // Manually craft bytes with DesiredFrameRate=31.
        let n = ClientNotification::frame_rate_override(
            2,
            FrameRateOverride { flags: 2, desired_frame_rate: 31, reserved1: 0, reserved2: 0 },
        );
        let bytes = roundtrip_enc(&n);
        let mut cur = ReadCursor::new(&bytes);
        assert!(ClientNotification::decode(&mut cur).is_err());
    }

    #[test]
    fn notification_framerate_rejects_no_flags() {
        let n = ClientNotification::frame_rate_override(
            2,
            FrameRateOverride { flags: 0, desired_frame_rate: 0, reserved1: 0, reserved2: 0 },
        );
        let bytes = roundtrip_enc(&n);
        let mut cur = ReadCursor::new(&bytes);
        assert!(ClientNotification::decode(&mut cur).is_err());
    }

    #[test]
    fn notification_framerate_rejects_both_flags() {
        let n = ClientNotification::frame_rate_override(
            2,
            FrameRateOverride { flags: 3, desired_frame_rate: 24, reserved1: 0, reserved2: 0 },
        );
        let bytes = roundtrip_enc(&n);
        let mut cur = ReadCursor::new(&bytes);
        assert!(ClientNotification::decode(&mut cur).is_err());
    }

    #[test]
    fn notification_reject_bad_type() {
        let mut bytes = roundtrip_enc(&ClientNotification::network_error(1));
        bytes[9] = 7;
        let mut cur = ReadCursor::new(&bytes);
        assert!(ClientNotification::decode(&mut cur).is_err());
    }

    #[test]
    fn video_data_small_roundtrip() {
        let vd = VideoData {
            presentation_id: 1,
            version: 1,
            flags: TSMM_VIDEO_DATA_FLAG_KEYFRAME,
            reserved: 0,
            hns_timestamp: 0,
            hns_duration: 0,
            current_packet_index: 1,
            packets_in_sample: 1,
            sample_number: 1,
            sample: vec![0xAA, 0xBB, 0xCC],
        };
        let bytes = roundtrip_enc(&vd);
        assert_eq!(bytes.len(), 43);
        let mut cur = ReadCursor::new(&bytes);
        let d = VideoData::decode(&mut cur).unwrap();
        assert_eq!(d, vd);
    }

    #[test]
    fn video_data_reject_zero_packets_in_sample() {
        let mut vd = VideoData {
            presentation_id: 1,
            version: 1,
            flags: 0,
            reserved: 0,
            hns_timestamp: 0,
            hns_duration: 0,
            current_packet_index: 1,
            packets_in_sample: 1,
            sample_number: 1,
            sample: vec![1, 2, 3],
        };
        vd.packets_in_sample = 0;
        vd.current_packet_index = 0;
        let bytes = roundtrip_enc(&vd);
        let mut cur = ReadCursor::new(&bytes);
        assert!(VideoData::decode(&mut cur).is_err());
    }

    #[test]
    fn video_data_reject_zero_sample_number() {
        let vd = VideoData {
            presentation_id: 1,
            version: 1,
            flags: 0,
            reserved: 0,
            hns_timestamp: 0,
            hns_duration: 0,
            current_packet_index: 1,
            packets_in_sample: 1,
            sample_number: 0,
            sample: vec![1],
        };
        let bytes = roundtrip_enc(&vd);
        let mut cur = ReadCursor::new(&bytes);
        assert!(VideoData::decode(&mut cur).is_err());
    }

    #[test]
    fn video_data_reject_index_out_of_range() {
        let vd = VideoData {
            presentation_id: 1,
            version: 1,
            flags: 0,
            reserved: 0,
            hns_timestamp: 0,
            hns_duration: 0,
            current_packet_index: 3,
            packets_in_sample: 2,
            sample_number: 1,
            sample: vec![1],
        };
        let bytes = roundtrip_enc(&vd);
        let mut cur = ReadCursor::new(&bytes);
        assert!(VideoData::decode(&mut cur).is_err());
    }

    #[test]
    fn video_data_reject_cb_sample_cap() {
        // Manually craft a header with cbSample over cap.
        let mut bytes = Vec::new();
        let bad = MAX_CBSAMPLE + 1;
        bytes.extend_from_slice(&(40u32 + bad).to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 1, 0, 0]);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&bad.to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        assert!(VideoData::decode(&mut cur).is_err());
    }

    #[test]
    fn presentation_request_reject_bad_packet_type() {
        let req = PresentationRequest::stop(1);
        let mut bytes = roundtrip_enc(&req);
        bytes[4..8].copy_from_slice(&99u32.to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        assert!(PresentationRequest::decode(&mut cur).is_err());
    }

    #[test]
    fn stop_must_be_68_bytes_no_extra() {
        // Build a Stop whose Command=2 but cbExtra != 0 → must reject.
        let mut req = PresentationRequest::stop(1);
        req.extra_data = vec![0u8; 4];
        let bytes = roundtrip_enc(&req);
        let mut cur = ReadCursor::new(&bytes);
        assert!(PresentationRequest::decode(&mut cur).is_err());
    }
}
