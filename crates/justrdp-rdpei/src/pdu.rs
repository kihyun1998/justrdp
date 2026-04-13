#![forbid(unsafe_code)]

//! Touch Input PDU types -- MS-RDPEI 2.2
//!
//! Wire-format PDUs for the Touch Input Virtual Channel Extension
//! (`Microsoft::Windows::RDS::Input`).

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

// =============================================================================
// Header & Event ID constants (MS-RDPEI 2.2.2.6)
// =============================================================================

/// Size of `RDPINPUT_HEADER` in bytes. MS-RDPEI 2.2.2.6
pub const HEADER_SIZE: usize = 6;

/// Server → client: RDPINPUT_SC_READY_PDU. MS-RDPEI 2.2.3.1
pub const EVENTID_SC_READY: u16 = 0x0001;
/// Client → server: RDPINPUT_CS_READY_PDU. MS-RDPEI 2.2.3.2
pub const EVENTID_CS_READY: u16 = 0x0002;
/// Client → server: RDPINPUT_TOUCH_EVENT_PDU. MS-RDPEI 2.2.3.3
pub const EVENTID_TOUCH: u16 = 0x0003;
/// Server → client: RDPINPUT_SUSPEND_INPUT_PDU. MS-RDPEI 2.2.3.4
pub const EVENTID_SUSPEND_INPUT: u16 = 0x0004;
/// Server → client: RDPINPUT_RESUME_INPUT_PDU. MS-RDPEI 2.2.3.5
pub const EVENTID_RESUME_INPUT: u16 = 0x0005;
/// Client → server: RDPINPUT_DISMISS_HOVERING_TOUCH_CONTACT_PDU. MS-RDPEI 2.2.3.6
pub const EVENTID_DISMISS_HOVERING_TOUCH_CONTACT: u16 = 0x0006;

// ── Protocol versions (MS-RDPEI 2.2.3.1 / 2.2.3.2) ──

/// Multitouch only. MS-RDPEI 2.2.3.1
pub const RDPINPUT_PROTOCOL_V100: u32 = 0x0001_0000;
/// Multitouch only. MS-RDPEI 2.2.3.1
pub const RDPINPUT_PROTOCOL_V101: u32 = 0x0001_0001;
/// Multitouch + pen. MS-RDPEI 2.2.3.1
pub const RDPINPUT_PROTOCOL_V200: u32 = 0x0002_0000;
/// Multitouch + pen + feature negotiation. MS-RDPEI 2.2.3.1
pub const RDPINPUT_PROTOCOL_V300: u32 = 0x0003_0000;

// =============================================================================
// Variable-length integer encoding (MS-RDPEI 2.2.2.{1..5})
// =============================================================================

/// Max value for TWO_BYTE_UNSIGNED_INTEGER (15-bit). MS-RDPEI 2.2.2.1
pub const TWO_BYTE_UNSIGNED_MAX: u16 = 0x7FFF;
/// Max value for FOUR_BYTE_UNSIGNED_INTEGER (30-bit). MS-RDPEI 2.2.2.3
pub const FOUR_BYTE_UNSIGNED_MAX: u32 = 0x3FFF_FFFF;
/// Max value for EIGHT_BYTE_UNSIGNED_INTEGER (61-bit). MS-RDPEI 2.2.2.5
pub const EIGHT_BYTE_UNSIGNED_MAX: u64 = 0x1FFF_FFFF_FFFF_FFFF;
/// Max magnitude for TWO_BYTE_SIGNED_INTEGER (14-bit). MS-RDPEI 2.2.2.2
pub const TWO_BYTE_SIGNED_MAX: i16 = 0x3FFF;
/// Max magnitude for FOUR_BYTE_SIGNED_INTEGER (29-bit). MS-RDPEI 2.2.2.4
pub const FOUR_BYTE_SIGNED_MAX: i32 = 0x1FFF_FFFF;

/// Return the encoded size (in bytes) of a TWO_BYTE_UNSIGNED_INTEGER.
pub fn two_byte_unsigned_size(value: u16) -> usize {
    if value <= 0x7F { 1 } else { 2 }
}

/// Return the encoded size of a FOUR_BYTE_UNSIGNED_INTEGER.
pub fn four_byte_unsigned_size(value: u32) -> usize {
    if value <= 0x3F {
        1
    } else if value <= 0x3FFF {
        2
    } else if value <= 0x003F_FFFF {
        3
    } else {
        4
    }
}

/// Return the encoded size of an EIGHT_BYTE_UNSIGNED_INTEGER.
pub fn eight_byte_unsigned_size(value: u64) -> usize {
    // 1 + c bytes where c is the smallest value such that magnitude fits in
    // 5 + 8*c bits.
    if value <= 0x1F {
        1
    } else if value <= 0x1FFF {
        2
    } else if value <= 0x001F_FFFF {
        3
    } else if value <= 0x1FFF_FFFF {
        4
    } else if value <= 0x001F_FFFF_FFFF {
        5
    } else if value <= 0x1FFF_FFFF_FFFF {
        6
    } else if value <= 0x001F_FFFF_FFFF_FFFF {
        7
    } else {
        8
    }
}

/// Return the encoded size of a TWO_BYTE_SIGNED_INTEGER.
pub fn two_byte_signed_size(value: i16) -> usize {
    let mag = value.unsigned_abs();
    if mag <= 0x3F { 1 } else { 2 }
}

/// Return the encoded size of a FOUR_BYTE_SIGNED_INTEGER.
pub fn four_byte_signed_size(value: i32) -> usize {
    let mag = value.unsigned_abs();
    if mag <= 0x1F {
        1
    } else if mag <= 0x1FFF {
        2
    } else if mag <= 0x001F_FFFF {
        3
    } else {
        4
    }
}

/// Encode a TWO_BYTE_UNSIGNED_INTEGER (MS-RDPEI 2.2.2.1).
pub fn encode_two_byte_unsigned(
    dst: &mut WriteCursor<'_>,
    value: u16,
    ctx: &'static str,
) -> EncodeResult<()> {
    if value > TWO_BYTE_UNSIGNED_MAX {
        return Err(EncodeError::invalid_value(ctx, "TWO_BYTE_UNSIGNED range"));
    }
    if value <= 0x7F {
        dst.write_u8(value as u8, ctx)?;
    } else {
        dst.write_u8(0x80 | (value >> 8) as u8, ctx)?;
        dst.write_u8((value & 0xFF) as u8, ctx)?;
    }
    Ok(())
}

/// Decode a TWO_BYTE_UNSIGNED_INTEGER.
pub fn decode_two_byte_unsigned(
    src: &mut ReadCursor<'_>,
    ctx: &'static str,
) -> DecodeResult<u16> {
    let b0 = src.read_u8(ctx)?;
    if b0 & 0x80 == 0 {
        Ok((b0 & 0x7F) as u16)
    } else {
        let b1 = src.read_u8(ctx)? as u16;
        Ok(((b0 & 0x7F) as u16) << 8 | b1)
    }
}

/// Encode a FOUR_BYTE_UNSIGNED_INTEGER (MS-RDPEI 2.2.2.3).
pub fn encode_four_byte_unsigned(
    dst: &mut WriteCursor<'_>,
    value: u32,
    ctx: &'static str,
) -> EncodeResult<()> {
    if value > FOUR_BYTE_UNSIGNED_MAX {
        return Err(EncodeError::invalid_value(ctx, "FOUR_BYTE_UNSIGNED range"));
    }
    if value <= 0x3F {
        dst.write_u8(value as u8, ctx)?;
    } else if value <= 0x3FFF {
        dst.write_u8(0x40 | (value >> 8) as u8, ctx)?;
        dst.write_u8((value & 0xFF) as u8, ctx)?;
    } else if value <= 0x003F_FFFF {
        dst.write_u8(0x80 | (value >> 16) as u8, ctx)?;
        dst.write_u8(((value >> 8) & 0xFF) as u8, ctx)?;
        dst.write_u8((value & 0xFF) as u8, ctx)?;
    } else {
        dst.write_u8(0xC0 | (value >> 24) as u8, ctx)?;
        dst.write_u8(((value >> 16) & 0xFF) as u8, ctx)?;
        dst.write_u8(((value >> 8) & 0xFF) as u8, ctx)?;
        dst.write_u8((value & 0xFF) as u8, ctx)?;
    }
    Ok(())
}

/// Decode a FOUR_BYTE_UNSIGNED_INTEGER.
pub fn decode_four_byte_unsigned(
    src: &mut ReadCursor<'_>,
    ctx: &'static str,
) -> DecodeResult<u32> {
    let b0 = src.read_u8(ctx)?;
    let c = (b0 >> 6) & 0x03;
    let val1 = (b0 & 0x3F) as u32;
    let value = match c {
        0 => val1,
        1 => (val1 << 8) | src.read_u8(ctx)? as u32,
        2 => {
            let v2 = src.read_u8(ctx)? as u32;
            let v3 = src.read_u8(ctx)? as u32;
            (val1 << 16) | (v2 << 8) | v3
        }
        _ => {
            let v2 = src.read_u8(ctx)? as u32;
            let v3 = src.read_u8(ctx)? as u32;
            let v4 = src.read_u8(ctx)? as u32;
            (val1 << 24) | (v2 << 16) | (v3 << 8) | v4
        }
    };
    Ok(value)
}

/// Encode an EIGHT_BYTE_UNSIGNED_INTEGER (MS-RDPEI 2.2.2.5).
pub fn encode_eight_byte_unsigned(
    dst: &mut WriteCursor<'_>,
    value: u64,
    ctx: &'static str,
) -> EncodeResult<()> {
    if value > EIGHT_BYTE_UNSIGNED_MAX {
        return Err(EncodeError::invalid_value(ctx, "EIGHT_BYTE_UNSIGNED range"));
    }
    let total = eight_byte_unsigned_size(value);
    let c = (total - 1) as u8; // 0..=7
    let shift = (total - 1) * 8;
    let val1 = ((value >> shift) & 0x1F) as u8;
    dst.write_u8((c << 5) | val1, ctx)?;
    for i in (0..(total - 1)).rev() {
        dst.write_u8(((value >> (i * 8)) & 0xFF) as u8, ctx)?;
    }
    Ok(())
}

/// Decode an EIGHT_BYTE_UNSIGNED_INTEGER.
pub fn decode_eight_byte_unsigned(
    src: &mut ReadCursor<'_>,
    ctx: &'static str,
) -> DecodeResult<u64> {
    let b0 = src.read_u8(ctx)?;
    let c = ((b0 >> 5) & 0x07) as usize;
    let mut value = (b0 & 0x1F) as u64;
    for _ in 0..c {
        value = (value << 8) | src.read_u8(ctx)? as u64;
    }
    Ok(value)
}

/// Encode a TWO_BYTE_SIGNED_INTEGER (MS-RDPEI 2.2.2.2).
pub fn encode_two_byte_signed(
    dst: &mut WriteCursor<'_>,
    value: i16,
    ctx: &'static str,
) -> EncodeResult<()> {
    let mag = value.unsigned_abs();
    if mag > TWO_BYTE_SIGNED_MAX as u16 {
        return Err(EncodeError::invalid_value(ctx, "TWO_BYTE_SIGNED range"));
    }
    let s: u8 = if value < 0 { 0x40 } else { 0x00 };
    if mag <= 0x3F {
        dst.write_u8(s | mag as u8, ctx)?;
    } else {
        dst.write_u8(0x80 | s | ((mag >> 8) as u8), ctx)?;
        dst.write_u8((mag & 0xFF) as u8, ctx)?;
    }
    Ok(())
}

/// Decode a TWO_BYTE_SIGNED_INTEGER.
pub fn decode_two_byte_signed(
    src: &mut ReadCursor<'_>,
    ctx: &'static str,
) -> DecodeResult<i16> {
    let b0 = src.read_u8(ctx)?;
    let has_second = b0 & 0x80 != 0;
    let negative = b0 & 0x40 != 0;
    let val1 = (b0 & 0x3F) as u16;
    let mag = if has_second {
        let b1 = src.read_u8(ctx)? as u16;
        (val1 << 8) | b1
    } else {
        val1
    };
    // mag max is 0x3FFF, fits in i16 (max 0x7FFF).
    let value = mag as i16;
    Ok(if negative { -value } else { value })
}

/// Encode a FOUR_BYTE_SIGNED_INTEGER (MS-RDPEI 2.2.2.4).
pub fn encode_four_byte_signed(
    dst: &mut WriteCursor<'_>,
    value: i32,
    ctx: &'static str,
) -> EncodeResult<()> {
    let mag = value.unsigned_abs();
    if mag > FOUR_BYTE_SIGNED_MAX as u32 {
        return Err(EncodeError::invalid_value(ctx, "FOUR_BYTE_SIGNED range"));
    }
    let s: u8 = if value < 0 { 0x20 } else { 0x00 };
    if mag <= 0x1F {
        dst.write_u8(s | mag as u8, ctx)?;
    } else if mag <= 0x1FFF {
        dst.write_u8(0x40 | s | (mag >> 8) as u8, ctx)?;
        dst.write_u8((mag & 0xFF) as u8, ctx)?;
    } else if mag <= 0x001F_FFFF {
        dst.write_u8(0x80 | s | (mag >> 16) as u8, ctx)?;
        dst.write_u8(((mag >> 8) & 0xFF) as u8, ctx)?;
        dst.write_u8((mag & 0xFF) as u8, ctx)?;
    } else {
        dst.write_u8(0xC0 | s | (mag >> 24) as u8, ctx)?;
        dst.write_u8(((mag >> 16) & 0xFF) as u8, ctx)?;
        dst.write_u8(((mag >> 8) & 0xFF) as u8, ctx)?;
        dst.write_u8((mag & 0xFF) as u8, ctx)?;
    }
    Ok(())
}

/// Decode a FOUR_BYTE_SIGNED_INTEGER.
pub fn decode_four_byte_signed(
    src: &mut ReadCursor<'_>,
    ctx: &'static str,
) -> DecodeResult<i32> {
    let b0 = src.read_u8(ctx)?;
    let c = ((b0 >> 6) & 0x03) as usize;
    let negative = b0 & 0x20 != 0;
    let val1 = (b0 & 0x1F) as u32;
    let mag: u32 = match c {
        0 => val1,
        1 => (val1 << 8) | src.read_u8(ctx)? as u32,
        2 => {
            let v2 = src.read_u8(ctx)? as u32;
            let v3 = src.read_u8(ctx)? as u32;
            (val1 << 16) | (v2 << 8) | v3
        }
        _ => {
            let v2 = src.read_u8(ctx)? as u32;
            let v3 = src.read_u8(ctx)? as u32;
            let v4 = src.read_u8(ctx)? as u32;
            (val1 << 24) | (v2 << 16) | (v3 << 8) | v4
        }
    };
    // mag max is 0x1FFF_FFFF, fits in i32 positive range.
    let value = mag as i32;
    Ok(if negative { -value } else { value })
}

// =============================================================================
// RDPINPUT_HEADER (MS-RDPEI 2.2.2.6)
// =============================================================================

/// Common 6-byte header present at the start of every RDPEI PDU.
/// MS-RDPEI 2.2.2.6
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdpeiHeader {
    /// Event ID (PDU discriminator).
    pub event_id: u16,
    /// Total PDU length *including* this 6-byte header.
    pub pdu_length: u32,
}

impl RdpeiHeader {
    /// Decode the header.
    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let event_id = src.read_u16_le("RdpeiHeader::EventId")?;
        let pdu_length = src.read_u32_le("RdpeiHeader::PduLength")?;
        if (pdu_length as usize) < HEADER_SIZE {
            return Err(DecodeError::invalid_value(
                "RdpeiHeader",
                "PduLength < 6",
            ));
        }
        Ok(Self {
            event_id,
            pdu_length,
        })
    }

    /// Encode the header.
    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.event_id, "RdpeiHeader::EventId")?;
        dst.write_u32_le(self.pdu_length, "RdpeiHeader::PduLength")?;
        Ok(())
    }
}

// =============================================================================
// RDPINPUT_SC_READY_PDU (MS-RDPEI 2.2.3.1) — server → client
// =============================================================================

/// `supportedFeatures` bit: multipen injection.
/// MS-RDPEI 2.2.3.1
pub const SC_READY_MULTIPEN_INJECTION_SUPPORTED: u32 = 0x0000_0001;

/// Marker for all `supportedFeatures` flag bits.
/// MS-RDPEI 2.2.3.1
pub struct ScReadyFlags;

impl ScReadyFlags {
    /// Multipen injection supported by the server.
    pub const MULTIPEN_INJECTION_SUPPORTED: u32 = SC_READY_MULTIPEN_INJECTION_SUPPORTED;
}

/// RDPINPUT_SC_READY_PDU (server → client).
///
/// MS-RDPEI 2.2.3.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScReadyPdu {
    /// Server's protocol version (see `RDPINPUT_PROTOCOL_V*`).
    pub protocol_version: u32,
    /// Optional `supportedFeatures` mask. Present iff `pdu_length == 14`
    /// (only meaningful for V300). MS-RDPEI 2.2.3.1
    pub supported_features: Option<u32>,
}

impl ScReadyPdu {
    const BASE_SIZE: usize = HEADER_SIZE + 4;
    const V300_SIZE: usize = HEADER_SIZE + 8;

    /// Decode a full PDU from a DVC payload.
    pub fn decode_from(payload: &[u8]) -> DecodeResult<Self> {
        let mut src = ReadCursor::new(payload);
        let header = RdpeiHeader::decode(&mut src)?;
        if header.event_id != EVENTID_SC_READY {
            return Err(DecodeError::unexpected_value(
                "ScReadyPdu",
                "EventId",
                "expected EVENTID_SC_READY (0x0001)",
            ));
        }
        // Presence of `supportedFeatures` is determined by pdu_length, not
        // protocol_version (MS-RDPEI 2.2.3.1 uses SHOULD, not MUST).
        let protocol_version = src.read_u32_le("ScReadyPdu::ProtocolVersion")?;
        let supported_features = match header.pdu_length as usize {
            Self::BASE_SIZE => None,
            Self::V300_SIZE => Some(src.read_u32_le("ScReadyPdu::SupportedFeatures")?),
            _ => {
                return Err(DecodeError::invalid_value(
                    "ScReadyPdu",
                    "PduLength (expected 10 or 14)",
                ));
            }
        };
        Ok(Self {
            protocol_version,
            supported_features,
        })
    }
}

impl Encode for ScReadyPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let pdu_length = self.size() as u32;
        RdpeiHeader {
            event_id: EVENTID_SC_READY,
            pdu_length,
        }
        .encode(dst)?;
        dst.write_u32_le(self.protocol_version, "ScReadyPdu::ProtocolVersion")?;
        if let Some(feat) = self.supported_features {
            dst.write_u32_le(feat, "ScReadyPdu::SupportedFeatures")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ScReadyPdu"
    }

    fn size(&self) -> usize {
        if self.supported_features.is_some() {
            Self::V300_SIZE
        } else {
            Self::BASE_SIZE
        }
    }
}

// =============================================================================
// RDPINPUT_CS_READY_PDU (MS-RDPEI 2.2.3.2) — client → server
// =============================================================================

/// `CS_READY flags` constants. MS-RDPEI 2.2.3.2
pub struct CsReadyFlags;

impl CsReadyFlags {
    /// Show touch visuals on the remote session.
    pub const SHOW_TOUCH_VISUALS: u32 = 0x0000_0001;
    /// Disable server-side timestamp injection.
    pub const DISABLE_TIMESTAMP_INJECTION: u32 = 0x0000_0002;
    /// Enable multipen injection (V300 + server advertises support).
    pub const ENABLE_MULTIPEN_INJECTION: u32 = 0x0000_0004;
}

/// RDPINPUT_CS_READY_PDU (client → server). Fixed 16-byte PDU.
///
/// MS-RDPEI 2.2.3.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsReadyPdu {
    /// `CS_READY_FLAGS_*` bitmask.
    pub flags: u32,
    /// Client's chosen protocol version.
    pub protocol_version: u32,
    /// Maximum simultaneous touch contacts the client can report.
    pub max_touch_contacts: u16,
}

impl CsReadyPdu {
    /// Fixed wire size. MS-RDPEI 2.2.3.2
    pub const WIRE_SIZE: usize = 16;

    /// Decode from a DVC payload.
    pub fn decode_from(payload: &[u8]) -> DecodeResult<Self> {
        let mut src = ReadCursor::new(payload);
        let header = RdpeiHeader::decode(&mut src)?;
        if header.event_id != EVENTID_CS_READY {
            return Err(DecodeError::unexpected_value(
                "CsReadyPdu",
                "EventId",
                "expected EVENTID_CS_READY (0x0002)",
            ));
        }
        if header.pdu_length as usize != Self::WIRE_SIZE {
            return Err(DecodeError::invalid_value(
                "CsReadyPdu",
                "PduLength (expected 16)",
            ));
        }
        let flags = src.read_u32_le("CsReadyPdu::Flags")?;
        let protocol_version = src.read_u32_le("CsReadyPdu::ProtocolVersion")?;
        let max_touch_contacts = src.read_u16_le("CsReadyPdu::MaxTouchContacts")?;
        Ok(Self {
            flags,
            protocol_version,
            max_touch_contacts,
        })
    }
}

impl Encode for CsReadyPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        RdpeiHeader {
            event_id: EVENTID_CS_READY,
            pdu_length: Self::WIRE_SIZE as u32,
        }
        .encode(dst)?;
        dst.write_u32_le(self.flags, "CsReadyPdu::Flags")?;
        dst.write_u32_le(self.protocol_version, "CsReadyPdu::ProtocolVersion")?;
        dst.write_u16_le(self.max_touch_contacts, "CsReadyPdu::MaxTouchContacts")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CsReadyPdu"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// =============================================================================
// RDPINPUT_TOUCH_CONTACT (MS-RDPEI 2.2.3.3.1.1)
// =============================================================================

/// `fieldsPresent` bit flags for `TouchContact`. MS-RDPEI 2.2.3.3.1.1
pub struct FieldsPresent;

impl FieldsPresent {
    /// All four `contactRect*` fields are present.
    pub const CONTACTRECT: u16 = 0x0001;
    /// `orientation` is present.
    pub const ORIENTATION: u16 = 0x0002;
    /// `pressure` is present.
    pub const PRESSURE: u16 = 0x0004;
}

/// `contactFlags` bit flags. MS-RDPEI 2.2.3.3.1.1
pub struct ContactFlags;

impl ContactFlags {
    pub const DOWN: u32 = 0x0001;
    pub const UPDATE: u32 = 0x0002;
    pub const UP: u32 = 0x0004;
    pub const INRANGE: u32 = 0x0008;
    pub const INCONTACT: u32 = 0x0010;
    pub const CANCELED: u32 = 0x0020;
}

/// The eight valid `contactFlags` combinations.
///
/// MS-RDPEI 2.2.3.3.1.1 "The contactFlags field MUST be set to one of the
/// following combinations".
pub const VALID_CONTACT_FLAG_COMBINATIONS: [u32; 8] = [
    ContactFlags::UP,                                              // 0x04
    ContactFlags::UP | ContactFlags::CANCELED,                     // 0x24
    ContactFlags::UPDATE,                                          // 0x02
    ContactFlags::UPDATE | ContactFlags::CANCELED,                 // 0x22
    ContactFlags::DOWN | ContactFlags::INRANGE | ContactFlags::INCONTACT, // 0x19
    ContactFlags::UPDATE | ContactFlags::INRANGE | ContactFlags::INCONTACT, // 0x1A
    ContactFlags::UP | ContactFlags::INRANGE,                      // 0x0C
    ContactFlags::UPDATE | ContactFlags::INRANGE,                  // 0x0A
];

/// `orientation` maximum (degrees). MS-RDPEI 2.2.3.3.1.1
pub const ORIENTATION_MAX: u32 = 359;
/// `pressure` maximum (normalized). MS-RDPEI 2.2.3.3.1.1
pub const PRESSURE_MAX: u32 = 1024;

/// A single touch contact within a `TouchFrame`.
///
/// MS-RDPEI 2.2.3.3.1.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TouchContact {
    /// Contact identifier (0..=255).
    pub contact_id: u8,
    /// X position (virtual-desktop pixels).
    pub x: i32,
    /// Y position (virtual-desktop pixels).
    pub y: i32,
    /// State bits — must be one of `VALID_CONTACT_FLAG_COMBINATIONS`.
    pub contact_flags: u32,
    /// Contact bounding rectangle, all four coordinates together.
    pub contact_rect: Option<ContactRect>,
    /// Orientation in degrees (0..=359).
    pub orientation: Option<u32>,
    /// Pressure (0..=1024).
    pub pressure: Option<u32>,
}

/// Contact bounding rectangle, all four fields travel together.
///
/// MS-RDPEI 2.2.3.3.1.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactRect {
    pub left: i16,
    pub top: i16,
    pub right: i16,
    pub bottom: i16,
}

impl TouchContact {
    fn fields_present_mask(&self) -> u16 {
        let mut mask = 0u16;
        if self.contact_rect.is_some() {
            mask |= FieldsPresent::CONTACTRECT;
        }
        if self.orientation.is_some() {
            mask |= FieldsPresent::ORIENTATION;
        }
        if self.pressure.is_some() {
            mask |= FieldsPresent::PRESSURE;
        }
        mask
    }

    fn validate(&self) -> Result<(), EncodeError> {
        if !VALID_CONTACT_FLAG_COMBINATIONS.contains(&self.contact_flags) {
            return Err(EncodeError::invalid_value(
                "TouchContact",
                "contactFlags not a valid combination",
            ));
        }
        if let Some(o) = self.orientation
            && o > ORIENTATION_MAX
        {
            return Err(EncodeError::invalid_value(
                "TouchContact",
                "orientation > 359",
            ));
        }
        if let Some(p) = self.pressure
            && p > PRESSURE_MAX
        {
            return Err(EncodeError::invalid_value("TouchContact", "pressure > 1024"));
        }
        Ok(())
    }
}

impl Encode for TouchContact {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        self.validate()?;
        dst.write_u8(self.contact_id, "TouchContact::ContactId")?;
        encode_two_byte_unsigned(
            dst,
            self.fields_present_mask(),
            "TouchContact::FieldsPresent",
        )?;
        encode_four_byte_signed(dst, self.x, "TouchContact::X")?;
        encode_four_byte_signed(dst, self.y, "TouchContact::Y")?;
        encode_four_byte_unsigned(dst, self.contact_flags, "TouchContact::ContactFlags")?;
        if let Some(rect) = self.contact_rect {
            encode_two_byte_signed(dst, rect.left, "TouchContact::ContactRectLeft")?;
            encode_two_byte_signed(dst, rect.top, "TouchContact::ContactRectTop")?;
            encode_two_byte_signed(dst, rect.right, "TouchContact::ContactRectRight")?;
            encode_two_byte_signed(dst, rect.bottom, "TouchContact::ContactRectBottom")?;
        }
        if let Some(o) = self.orientation {
            encode_four_byte_unsigned(dst, o, "TouchContact::Orientation")?;
        }
        if let Some(p) = self.pressure {
            encode_four_byte_unsigned(dst, p, "TouchContact::Pressure")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TouchContact"
    }

    fn size(&self) -> usize {
        let mut n = 1; // contactId
        n += two_byte_unsigned_size(self.fields_present_mask());
        n += four_byte_signed_size(self.x);
        n += four_byte_signed_size(self.y);
        n += four_byte_unsigned_size(self.contact_flags);
        if let Some(rect) = self.contact_rect {
            n += two_byte_signed_size(rect.left);
            n += two_byte_signed_size(rect.top);
            n += two_byte_signed_size(rect.right);
            n += two_byte_signed_size(rect.bottom);
        }
        if let Some(o) = self.orientation {
            n += four_byte_unsigned_size(o);
        }
        if let Some(p) = self.pressure {
            n += four_byte_unsigned_size(p);
        }
        n
    }
}

impl<'de> Decode<'de> for TouchContact {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let contact_id = src.read_u8("TouchContact::ContactId")?;
        let fields_present = decode_two_byte_unsigned(src, "TouchContact::FieldsPresent")?;
        let x = decode_four_byte_signed(src, "TouchContact::X")?;
        let y = decode_four_byte_signed(src, "TouchContact::Y")?;
        let contact_flags = decode_four_byte_unsigned(src, "TouchContact::ContactFlags")?;
        if !VALID_CONTACT_FLAG_COMBINATIONS.contains(&contact_flags) {
            return Err(DecodeError::invalid_value(
                "TouchContact",
                "contactFlags not a valid combination",
            ));
        }
        let contact_rect = if fields_present & FieldsPresent::CONTACTRECT != 0 {
            Some(ContactRect {
                left: decode_two_byte_signed(src, "TouchContact::ContactRectLeft")?,
                top: decode_two_byte_signed(src, "TouchContact::ContactRectTop")?,
                right: decode_two_byte_signed(src, "TouchContact::ContactRectRight")?,
                bottom: decode_two_byte_signed(src, "TouchContact::ContactRectBottom")?,
            })
        } else {
            None
        };
        let orientation = if fields_present & FieldsPresent::ORIENTATION != 0 {
            let o = decode_four_byte_unsigned(src, "TouchContact::Orientation")?;
            if o > ORIENTATION_MAX {
                return Err(DecodeError::invalid_value(
                    "TouchContact",
                    "orientation > 359",
                ));
            }
            Some(o)
        } else {
            None
        };
        let pressure = if fields_present & FieldsPresent::PRESSURE != 0 {
            let p = decode_four_byte_unsigned(src, "TouchContact::Pressure")?;
            if p > PRESSURE_MAX {
                return Err(DecodeError::invalid_value("TouchContact", "pressure > 1024"));
            }
            Some(p)
        } else {
            None
        };
        Ok(Self {
            contact_id,
            x,
            y,
            contact_flags,
            contact_rect,
            orientation,
            pressure,
        })
    }
}

// =============================================================================
// RDPINPUT_TOUCH_FRAME (MS-RDPEI 2.2.3.3.1)
// =============================================================================

/// A single touch frame within a `TouchEventPdu`.
///
/// MS-RDPEI 2.2.3.3.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TouchFrame {
    /// Microseconds since the previous frame (0 for the first frame).
    pub frame_offset: u64,
    /// Contacts in this frame.
    pub contacts: Vec<TouchContact>,
}

impl Encode for TouchFrame {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let count = u16::try_from(self.contacts.len()).map_err(|_| {
            EncodeError::invalid_value("TouchFrame", "contactCount exceeds u16")
        })?;
        encode_two_byte_unsigned(dst, count, "TouchFrame::ContactCount")?;
        encode_eight_byte_unsigned(dst, self.frame_offset, "TouchFrame::FrameOffset")?;
        for c in &self.contacts {
            c.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TouchFrame"
    }

    fn size(&self) -> usize {
        // Saturate to u16::MAX for oversized vectors; `encode()` will reject
        // them via `u16::try_from`, so exact size() only matters when encode
        // succeeds (len <= u16::MAX). Keeps the size()/encode() invariant
        // correct on the success path.
        let count = u16::try_from(self.contacts.len()).unwrap_or(u16::MAX);
        let mut n = two_byte_unsigned_size(count);
        n += eight_byte_unsigned_size(self.frame_offset);
        for c in &self.contacts {
            n += c.size();
        }
        n
    }
}

impl<'de> Decode<'de> for TouchFrame {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let count = decode_two_byte_unsigned(src, "TouchFrame::ContactCount")?;
        let frame_offset = decode_eight_byte_unsigned(src, "TouchFrame::FrameOffset")?;
        let mut contacts = Vec::with_capacity(count as usize);
        for _ in 0..count {
            contacts.push(TouchContact::decode(src)?);
        }
        Ok(Self {
            frame_offset,
            contacts,
        })
    }
}

// =============================================================================
// RDPINPUT_TOUCH_EVENT_PDU (MS-RDPEI 2.2.3.3) — client → server
// =============================================================================

/// RDPINPUT_TOUCH_EVENT_PDU (client → server).
///
/// MS-RDPEI 2.2.3.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TouchEventPdu {
    /// Milliseconds between oldest frame generation and PDU encode time.
    pub encode_time: u32,
    /// Ordered oldest → newest.
    pub frames: Vec<TouchFrame>,
}

impl TouchEventPdu {
    fn body_size(&self) -> usize {
        let frame_count = u16::try_from(self.frames.len()).unwrap_or(u16::MAX);
        let mut n = four_byte_unsigned_size(self.encode_time);
        n += two_byte_unsigned_size(frame_count);
        for f in &self.frames {
            n += f.size();
        }
        n
    }

    /// Decode from a DVC payload.
    pub fn decode_from(payload: &[u8]) -> DecodeResult<Self> {
        let mut src = ReadCursor::new(payload);
        let header = RdpeiHeader::decode(&mut src)?;
        if header.event_id != EVENTID_TOUCH {
            return Err(DecodeError::unexpected_value(
                "TouchEventPdu",
                "EventId",
                "expected EVENTID_TOUCH (0x0003)",
            ));
        }
        let encode_time = decode_four_byte_unsigned(&mut src, "TouchEventPdu::EncodeTime")?;
        let frame_count = decode_two_byte_unsigned(&mut src, "TouchEventPdu::FrameCount")?;
        let mut frames = Vec::with_capacity(frame_count as usize);
        for _ in 0..frame_count {
            frames.push(TouchFrame::decode(&mut src)?);
        }
        Ok(Self {
            encode_time,
            frames,
        })
    }
}

impl Encode for TouchEventPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let frame_count = u16::try_from(self.frames.len()).map_err(|_| {
            EncodeError::invalid_value("TouchEventPdu", "frameCount exceeds u16")
        })?;
        let pdu_length = u32::try_from(self.size())
            .map_err(|_| EncodeError::invalid_value("TouchEventPdu", "pdu_length exceeds u32"))?;
        RdpeiHeader {
            event_id: EVENTID_TOUCH,
            pdu_length,
        }
        .encode(dst)?;
        encode_four_byte_unsigned(dst, self.encode_time, "TouchEventPdu::EncodeTime")?;
        encode_two_byte_unsigned(dst, frame_count, "TouchEventPdu::FrameCount")?;
        for f in &self.frames {
            f.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TouchEventPdu"
    }

    fn size(&self) -> usize {
        HEADER_SIZE + self.body_size()
    }
}

// =============================================================================
// RDPINPUT_SUSPEND_INPUT_PDU / RESUME_INPUT_PDU (2.2.3.4 / 2.2.3.5)
// =============================================================================

/// RDPINPUT_SUSPEND_INPUT_PDU (server → client). Header only.
/// MS-RDPEI 2.2.3.4
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SuspendInputPdu;

impl SuspendInputPdu {
    pub const WIRE_SIZE: usize = HEADER_SIZE;

    pub fn decode_from(payload: &[u8]) -> DecodeResult<Self> {
        let mut src = ReadCursor::new(payload);
        let header = RdpeiHeader::decode(&mut src)?;
        if header.event_id != EVENTID_SUSPEND_INPUT {
            return Err(DecodeError::unexpected_value(
                "SuspendInputPdu",
                "EventId",
                "expected EVENTID_SUSPEND_INPUT (0x0004)",
            ));
        }
        if header.pdu_length as usize != Self::WIRE_SIZE {
            return Err(DecodeError::invalid_value(
                "SuspendInputPdu",
                "PduLength (expected 6)",
            ));
        }
        Ok(Self)
    }
}

impl Encode for SuspendInputPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        RdpeiHeader {
            event_id: EVENTID_SUSPEND_INPUT,
            pdu_length: Self::WIRE_SIZE as u32,
        }
        .encode(dst)
    }

    fn name(&self) -> &'static str {
        "SuspendInputPdu"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

/// RDPINPUT_RESUME_INPUT_PDU (server → client). Header only.
/// MS-RDPEI 2.2.3.5
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResumeInputPdu;

impl ResumeInputPdu {
    pub const WIRE_SIZE: usize = HEADER_SIZE;

    pub fn decode_from(payload: &[u8]) -> DecodeResult<Self> {
        let mut src = ReadCursor::new(payload);
        let header = RdpeiHeader::decode(&mut src)?;
        if header.event_id != EVENTID_RESUME_INPUT {
            return Err(DecodeError::unexpected_value(
                "ResumeInputPdu",
                "EventId",
                "expected EVENTID_RESUME_INPUT (0x0005)",
            ));
        }
        if header.pdu_length as usize != Self::WIRE_SIZE {
            return Err(DecodeError::invalid_value(
                "ResumeInputPdu",
                "PduLength (expected 6)",
            ));
        }
        Ok(Self)
    }
}

impl Encode for ResumeInputPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        RdpeiHeader {
            event_id: EVENTID_RESUME_INPUT,
            pdu_length: Self::WIRE_SIZE as u32,
        }
        .encode(dst)
    }

    fn name(&self) -> &'static str {
        "ResumeInputPdu"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// =============================================================================
// RDPINPUT_DISMISS_HOVERING_TOUCH_CONTACT_PDU (MS-RDPEI 2.2.3.6)
// =============================================================================

/// RDPINPUT_DISMISS_HOVERING_TOUCH_CONTACT_PDU (client → server).
/// MS-RDPEI 2.2.3.6
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DismissHoveringContactPdu {
    pub contact_id: u8,
}

impl DismissHoveringContactPdu {
    pub const WIRE_SIZE: usize = HEADER_SIZE + 1;

    pub fn decode_from(payload: &[u8]) -> DecodeResult<Self> {
        let mut src = ReadCursor::new(payload);
        let header = RdpeiHeader::decode(&mut src)?;
        if header.event_id != EVENTID_DISMISS_HOVERING_TOUCH_CONTACT {
            return Err(DecodeError::unexpected_value(
                "DismissHoveringContactPdu",
                "EventId",
                "expected EVENTID_DISMISS_HOVERING_TOUCH_CONTACT (0x0006)",
            ));
        }
        if header.pdu_length as usize != Self::WIRE_SIZE {
            return Err(DecodeError::invalid_value(
                "DismissHoveringContactPdu",
                "PduLength (expected 7)",
            ));
        }
        let contact_id = src.read_u8("DismissHoveringContactPdu::ContactId")?;
        Ok(Self { contact_id })
    }
}

impl Encode for DismissHoveringContactPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        RdpeiHeader {
            event_id: EVENTID_DISMISS_HOVERING_TOUCH_CONTACT,
            pdu_length: Self::WIRE_SIZE as u32,
        }
        .encode(dst)?;
        dst.write_u8(self.contact_id, "DismissHoveringContactPdu::ContactId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DismissHoveringContactPdu"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn encode_to_vec<E: Encode>(pdu: &E) -> Vec<u8> {
        let size = pdu.size();
        let mut buf = vec![0u8; size];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(dst.remaining(), 0, "{}: size() mismatch", pdu.name());
        buf
    }

    // ── Variable-length integer spec examples (MS-RDPEI 2.2.2.*) ──

    #[test]
    fn two_byte_unsigned_spec_example() {
        let mut buf = [0u8; 2];
        let mut dst = WriteCursor::new(&mut buf);
        encode_two_byte_unsigned(&mut dst, 0x1A1B, "test").unwrap();
        assert_eq!(buf, [0x9A, 0x1B]);
        let mut src = ReadCursor::new(&buf);
        assert_eq!(decode_two_byte_unsigned(&mut src, "test").unwrap(), 0x1A1B);
    }

    #[test]
    fn two_byte_unsigned_boundaries() {
        // 1-byte form
        for v in [0u16, 1, 0x7F] {
            let mut buf = [0u8; 2];
            let mut dst = WriteCursor::new(&mut buf);
            encode_two_byte_unsigned(&mut dst, v, "t").unwrap();
            assert_eq!(two_byte_unsigned_size(v), 1);
            let mut src = ReadCursor::new(&buf[..1]);
            assert_eq!(decode_two_byte_unsigned(&mut src, "t").unwrap(), v);
        }
        // 2-byte form
        for v in [0x80u16, 0x1A1B, 0x7FFF] {
            let mut buf = [0u8; 2];
            let mut dst = WriteCursor::new(&mut buf);
            encode_two_byte_unsigned(&mut dst, v, "t").unwrap();
            assert_eq!(two_byte_unsigned_size(v), 2);
            let mut src = ReadCursor::new(&buf);
            assert_eq!(decode_two_byte_unsigned(&mut src, "t").unwrap(), v);
        }
    }

    #[test]
    fn two_byte_unsigned_out_of_range() {
        let mut buf = [0u8; 2];
        let mut dst = WriteCursor::new(&mut buf);
        assert!(encode_two_byte_unsigned(&mut dst, 0x8000, "t").is_err());
    }

    #[test]
    fn four_byte_unsigned_spec_example() {
        let mut buf = [0u8; 4];
        let mut dst = WriteCursor::new(&mut buf);
        encode_four_byte_unsigned(&mut dst, 0x001A_1B1C, "t").unwrap();
        assert_eq!(buf[..3], [0x9A, 0x1B, 0x1C]);
        let mut src = ReadCursor::new(&buf[..3]);
        assert_eq!(
            decode_four_byte_unsigned(&mut src, "t").unwrap(),
            0x001A_1B1C
        );
    }

    #[test]
    fn four_byte_unsigned_all_forms() {
        let cases: [(u32, usize); 8] = [
            (0, 1),
            (0x3F, 1),
            (0x40, 2),
            (0x3FFF, 2),
            (0x0000_4000, 3),
            (0x003F_FFFF, 3),
            (0x0040_0000, 4),
            (0x3FFF_FFFF, 4),
        ];
        for (v, sz) in cases {
            assert_eq!(four_byte_unsigned_size(v), sz, "size for {v:#x}");
            let mut buf = [0u8; 4];
            let mut dst = WriteCursor::new(&mut buf);
            encode_four_byte_unsigned(&mut dst, v, "t").unwrap();
            let mut src = ReadCursor::new(&buf[..sz]);
            assert_eq!(decode_four_byte_unsigned(&mut src, "t").unwrap(), v);
        }
    }

    #[test]
    fn four_byte_unsigned_out_of_range() {
        let mut buf = [0u8; 4];
        let mut dst = WriteCursor::new(&mut buf);
        assert!(encode_four_byte_unsigned(&mut dst, 0x4000_0000, "t").is_err());
    }

    #[test]
    fn eight_byte_unsigned_spec_example() {
        let mut buf = [0u8; 8];
        let mut dst = WriteCursor::new(&mut buf);
        encode_eight_byte_unsigned(&mut dst, 0x001A_1B1C_1D1E_1F2A, "t").unwrap();
        assert_eq!(
            &buf[..7],
            &[0xDA, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x2A]
        );
        let mut src = ReadCursor::new(&buf[..7]);
        assert_eq!(
            decode_eight_byte_unsigned(&mut src, "t").unwrap(),
            0x001A_1B1C_1D1E_1F2A
        );
    }

    #[test]
    fn eight_byte_unsigned_all_forms() {
        let cases: [(u64, usize); 8] = [
            (0x1F, 1),
            (0x1FFF, 2),
            (0x001F_FFFF, 3),
            (0x1FFF_FFFF, 4),
            (0x0000_001F_FFFF_FFFF, 5),
            (0x0000_1FFF_FFFF_FFFF, 6),
            (0x001F_FFFF_FFFF_FFFF, 7),
            (0x1FFF_FFFF_FFFF_FFFF, 8),
        ];
        for (v, sz) in cases {
            assert_eq!(eight_byte_unsigned_size(v), sz, "size for {v:#x}");
            let mut buf = [0u8; 8];
            let mut dst = WriteCursor::new(&mut buf);
            encode_eight_byte_unsigned(&mut dst, v, "t").unwrap();
            let mut src = ReadCursor::new(&buf[..sz]);
            assert_eq!(decode_eight_byte_unsigned(&mut src, "t").unwrap(), v);
        }
    }

    #[test]
    fn eight_byte_unsigned_out_of_range() {
        let mut buf = [0u8; 8];
        let mut dst = WriteCursor::new(&mut buf);
        assert!(encode_eight_byte_unsigned(&mut dst, 0x2000_0000_0000_0000, "t").is_err());
    }

    #[test]
    fn two_byte_signed_spec_examples() {
        let cases: [(i16, &[u8]); 2] = [(-0x1A1B, &[0xDA, 0x1B]), (-0x0002, &[0x42])];
        for (v, expected) in cases {
            let mut buf = [0u8; 2];
            let mut dst = WriteCursor::new(&mut buf);
            encode_two_byte_signed(&mut dst, v, "t").unwrap();
            assert_eq!(&buf[..expected.len()], expected, "v={v}");
            let mut src = ReadCursor::new(expected);
            assert_eq!(decode_two_byte_signed(&mut src, "t").unwrap(), v);
        }
    }

    #[test]
    fn two_byte_signed_boundaries() {
        for v in [0i16, 1, -1, 0x3F, -0x3F, 0x40, -0x40, 0x3FFF, -0x3FFF] {
            let mut buf = [0u8; 2];
            let mut dst = WriteCursor::new(&mut buf);
            encode_two_byte_signed(&mut dst, v, "t").unwrap();
            let sz = two_byte_signed_size(v);
            let mut src = ReadCursor::new(&buf[..sz]);
            assert_eq!(decode_two_byte_signed(&mut src, "t").unwrap(), v);
        }
    }

    #[test]
    fn two_byte_signed_out_of_range() {
        let mut buf = [0u8; 2];
        let mut dst = WriteCursor::new(&mut buf);
        assert!(encode_two_byte_signed(&mut dst, 0x4000, "t").is_err());
        let mut buf2 = [0u8; 2];
        let mut dst2 = WriteCursor::new(&mut buf2);
        assert!(encode_two_byte_signed(&mut dst2, -0x4000, "t").is_err());
    }

    #[test]
    fn four_byte_signed_spec_examples() {
        let cases: [(i32, &[u8]); 2] = [
            (-0x001A_1B1C, &[0xBA, 0x1B, 0x1C]),
            (-0x0000_0002, &[0x22]),
        ];
        for (v, expected) in cases {
            let mut buf = [0u8; 4];
            let mut dst = WriteCursor::new(&mut buf);
            encode_four_byte_signed(&mut dst, v, "t").unwrap();
            assert_eq!(&buf[..expected.len()], expected, "v={v}");
            let mut src = ReadCursor::new(expected);
            assert_eq!(decode_four_byte_signed(&mut src, "t").unwrap(), v);
        }
    }

    #[test]
    fn four_byte_signed_all_forms() {
        let cases: [(i32, usize); 8] = [
            (0x1F, 1),
            (-0x1F, 1),
            (0x1FFF, 2),
            (-0x1FFF, 2),
            (0x001F_FFFF, 3),
            (-0x001F_FFFF, 3),
            (0x1FFF_FFFF, 4),
            (-0x1FFF_FFFF, 4),
        ];
        for (v, sz) in cases {
            assert_eq!(four_byte_signed_size(v), sz, "size for {v}");
            let mut buf = [0u8; 4];
            let mut dst = WriteCursor::new(&mut buf);
            encode_four_byte_signed(&mut dst, v, "t").unwrap();
            let mut src = ReadCursor::new(&buf[..sz]);
            assert_eq!(decode_four_byte_signed(&mut src, "t").unwrap(), v);
        }
    }

    #[test]
    fn four_byte_signed_out_of_range() {
        let mut buf = [0u8; 4];
        let mut dst = WriteCursor::new(&mut buf);
        assert!(encode_four_byte_signed(&mut dst, 0x2000_0000, "t").is_err());
        let mut buf2 = [0u8; 4];
        let mut dst2 = WriteCursor::new(&mut buf2);
        assert!(encode_four_byte_signed(&mut dst2, i32::MIN, "t").is_err());
    }

    // ── SC_READY ──

    #[test]
    fn sc_ready_v100_wire_format() {
        let pdu = ScReadyPdu {
            protocol_version: RDPINPUT_PROTOCOL_V100,
            supported_features: None,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(
            bytes,
            vec![0x01, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]
        );
        let decoded = ScReadyPdu::decode_from(&bytes).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn sc_ready_v300_with_features_roundtrip() {
        let pdu = ScReadyPdu {
            protocol_version: RDPINPUT_PROTOCOL_V300,
            supported_features: Some(SC_READY_MULTIPEN_INJECTION_SUPPORTED),
        };
        assert_eq!(pdu.size(), 14);
        let bytes = encode_to_vec(&pdu);
        // pduLength = 14
        assert_eq!(bytes[2..6], [0x0E, 0x00, 0x00, 0x00]);
        let decoded = ScReadyPdu::decode_from(&bytes).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn sc_ready_decode_wrong_event_id() {
        let buf = [0x02u8, 0x00, 0x0A, 0x00, 0x00, 0x00, 0, 0, 1, 0];
        assert!(ScReadyPdu::decode_from(&buf).is_err());
    }

    #[test]
    fn sc_ready_decode_bad_length() {
        let buf = [0x01u8, 0x00, 0x0B, 0x00, 0x00, 0x00, 0, 0, 1, 0, 0];
        assert!(ScReadyPdu::decode_from(&buf).is_err());
    }

    // ── CS_READY ──

    #[test]
    fn cs_ready_wire_format() {
        let pdu = CsReadyPdu {
            flags: CsReadyFlags::SHOW_TOUCH_VISUALS,
            protocol_version: RDPINPUT_PROTOCOL_V100,
            max_touch_contacts: 10,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(
            bytes,
            vec![
                0x02, 0x00, 0x10, 0x00, 0x00, 0x00, // header
                0x01, 0x00, 0x00, 0x00, // flags
                0x00, 0x00, 0x01, 0x00, // protocolVersion
                0x0A, 0x00, // maxTouchContacts
            ]
        );
        let decoded = CsReadyPdu::decode_from(&bytes).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn cs_ready_max_contacts_boundary() {
        for mc in [0u16, 1, 10, 255, 256, u16::MAX] {
            let pdu = CsReadyPdu {
                flags: 0,
                protocol_version: RDPINPUT_PROTOCOL_V101,
                max_touch_contacts: mc,
            };
            let bytes = encode_to_vec(&pdu);
            let decoded = CsReadyPdu::decode_from(&bytes).unwrap();
            assert_eq!(decoded.max_touch_contacts, mc);
        }
    }

    // ── SUSPEND / RESUME ──

    #[test]
    fn suspend_input_wire_format() {
        let bytes = encode_to_vec(&SuspendInputPdu);
        assert_eq!(bytes, vec![0x04, 0x00, 0x06, 0x00, 0x00, 0x00]);
        SuspendInputPdu::decode_from(&bytes).unwrap();
    }

    #[test]
    fn resume_input_wire_format() {
        let bytes = encode_to_vec(&ResumeInputPdu);
        assert_eq!(bytes, vec![0x05, 0x00, 0x06, 0x00, 0x00, 0x00]);
        ResumeInputPdu::decode_from(&bytes).unwrap();
    }

    // ── DISMISS_HOVERING ──

    #[test]
    fn dismiss_hovering_wire_format() {
        let pdu = DismissHoveringContactPdu { contact_id: 0x02 };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes, vec![0x06, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02]);
        let decoded = DismissHoveringContactPdu::decode_from(&bytes).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn dismiss_hovering_contact_id_bounds() {
        for id in [0u8, 1, 127, 255] {
            let pdu = DismissHoveringContactPdu { contact_id: id };
            let bytes = encode_to_vec(&pdu);
            let decoded = DismissHoveringContactPdu::decode_from(&bytes).unwrap();
            assert_eq!(decoded.contact_id, id);
        }
    }

    // ── TouchContact ──

    fn minimal_contact() -> TouchContact {
        TouchContact {
            contact_id: 0,
            x: 0,
            y: 0,
            contact_flags: ContactFlags::DOWN | ContactFlags::INRANGE | ContactFlags::INCONTACT,
            contact_rect: None,
            orientation: None,
            pressure: None,
        }
    }

    #[test]
    fn touch_contact_minimal_roundtrip() {
        let c = minimal_contact();
        let bytes = encode_to_vec(&c);
        let mut src = ReadCursor::new(&bytes);
        let decoded = TouchContact::decode(&mut src).unwrap();
        assert_eq!(decoded, c);
    }

    #[test]
    fn touch_contact_all_optional_fields_roundtrip() {
        let c = TouchContact {
            contact_id: 5,
            x: 1920,
            y: -1080,
            contact_flags: ContactFlags::UPDATE | ContactFlags::INRANGE | ContactFlags::INCONTACT,
            contact_rect: Some(ContactRect {
                left: -10,
                top: -20,
                right: 30,
                bottom: 40,
            }),
            orientation: Some(180),
            pressure: Some(512),
        };
        let bytes = encode_to_vec(&c);
        let mut src = ReadCursor::new(&bytes);
        let decoded = TouchContact::decode(&mut src).unwrap();
        assert_eq!(decoded, c);
    }

    #[test]
    fn touch_contact_all_valid_flag_combinations() {
        for flags in VALID_CONTACT_FLAG_COMBINATIONS {
            let c = TouchContact {
                contact_flags: flags,
                ..minimal_contact()
            };
            let bytes = encode_to_vec(&c);
            let mut src = ReadCursor::new(&bytes);
            let decoded = TouchContact::decode(&mut src).unwrap();
            assert_eq!(decoded.contact_flags, flags);
        }
    }

    #[test]
    fn touch_contact_invalid_flag_combination_rejected_on_encode() {
        let c = TouchContact {
            contact_flags: ContactFlags::DOWN, // missing INRANGE|INCONTACT
            ..minimal_contact()
        };
        let mut buf = vec![0u8; 32];
        let mut dst = WriteCursor::new(&mut buf);
        assert!(c.encode(&mut dst).is_err());
    }

    #[test]
    fn touch_contact_invalid_flag_combination_rejected_on_decode() {
        // Hand-craft a contact with contact_flags = DOWN (0x01) alone.
        let bytes: [u8; 7] = [
            0x00, // contactId
            0x00, // fieldsPresent = 0
            0x00, // x = 0
            0x00, // y = 0
            0x01, // contactFlags = DOWN alone (invalid)
            0x00, // padding — won't be read
            0x00,
        ];
        let mut src = ReadCursor::new(&bytes);
        assert!(TouchContact::decode(&mut src).is_err());
    }

    #[test]
    fn touch_contact_orientation_bounds() {
        for o in [0u32, 1, 90, 180, 270, 359] {
            let c = TouchContact {
                orientation: Some(o),
                ..minimal_contact()
            };
            encode_to_vec(&c);
        }
        // 360 rejected
        let c = TouchContact {
            orientation: Some(360),
            ..minimal_contact()
        };
        let mut buf = vec![0u8; 32];
        let mut dst = WriteCursor::new(&mut buf);
        assert!(c.encode(&mut dst).is_err());
    }

    #[test]
    fn touch_contact_pressure_bounds() {
        for p in [0u32, 1, 512, 1024] {
            let c = TouchContact {
                pressure: Some(p),
                ..minimal_contact()
            };
            encode_to_vec(&c);
        }
        let c = TouchContact {
            pressure: Some(1025),
            ..minimal_contact()
        };
        let mut buf = vec![0u8; 32];
        let mut dst = WriteCursor::new(&mut buf);
        assert!(c.encode(&mut dst).is_err());
    }

    #[test]
    fn touch_contact_contact_id_255() {
        let c = TouchContact {
            contact_id: 255,
            ..minimal_contact()
        };
        let bytes = encode_to_vec(&c);
        let mut src = ReadCursor::new(&bytes);
        let decoded = TouchContact::decode(&mut src).unwrap();
        assert_eq!(decoded.contact_id, 255);
    }

    // ── TouchEventPdu ──

    #[test]
    fn touch_event_pdu_single_frame_single_contact() {
        let pdu = TouchEventPdu {
            encode_time: 42,
            frames: vec![TouchFrame {
                frame_offset: 0,
                contacts: vec![minimal_contact()],
            }],
        };
        let bytes = encode_to_vec(&pdu);
        // Header eventId = 0x03
        assert_eq!(bytes[0..2], [0x03, 0x00]);
        let decoded = TouchEventPdu::decode_from(&bytes).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn touch_event_pdu_zero_frames() {
        let pdu = TouchEventPdu {
            encode_time: 0,
            frames: vec![],
        };
        let bytes = encode_to_vec(&pdu);
        let decoded = TouchEventPdu::decode_from(&bytes).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn touch_event_pdu_multiple_frames_multiple_contacts() {
        let pdu = TouchEventPdu {
            encode_time: 12345,
            frames: vec![
                TouchFrame {
                    frame_offset: 0,
                    contacts: vec![
                        TouchContact {
                            contact_id: 1,
                            x: 100,
                            y: 200,
                            contact_flags: ContactFlags::DOWN
                                | ContactFlags::INRANGE
                                | ContactFlags::INCONTACT,
                            contact_rect: None,
                            orientation: None,
                            pressure: Some(800),
                        },
                        TouchContact {
                            contact_id: 2,
                            x: -50,
                            y: 1500,
                            contact_flags: ContactFlags::UPDATE
                                | ContactFlags::INRANGE
                                | ContactFlags::INCONTACT,
                            contact_rect: Some(ContactRect {
                                left: -5,
                                top: -5,
                                right: 5,
                                bottom: 5,
                            }),
                            orientation: Some(90),
                            pressure: None,
                        },
                    ],
                },
                TouchFrame {
                    frame_offset: 16_000, // 16 ms later
                    contacts: vec![TouchContact {
                        contact_id: 1,
                        x: 101,
                        y: 201,
                        contact_flags: ContactFlags::UPDATE
                            | ContactFlags::INRANGE
                            | ContactFlags::INCONTACT,
                        contact_rect: None,
                        orientation: None,
                        pressure: Some(810),
                    }],
                },
            ],
        };
        let bytes = encode_to_vec(&pdu);
        let decoded = TouchEventPdu::decode_from(&bytes).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn touch_event_pdu_pdu_length_matches_size() {
        let pdu = TouchEventPdu {
            encode_time: 100,
            frames: vec![TouchFrame {
                frame_offset: 0,
                contacts: vec![minimal_contact()],
            }],
        };
        let bytes = encode_to_vec(&pdu);
        let pdu_length = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        assert_eq!(pdu_length as usize, bytes.len());
        assert_eq!(pdu_length as usize, pdu.size());
    }

    #[test]
    fn touch_event_pdu_wrong_event_id_rejected() {
        let mut bytes = encode_to_vec(&TouchEventPdu {
            encode_time: 0,
            frames: vec![],
        });
        bytes[0] = 0xFF; // corrupt event id
        assert!(TouchEventPdu::decode_from(&bytes).is_err());
    }

    // ── Header negative cases ──

    #[test]
    fn header_rejects_short_pdu_length() {
        let buf = [0x01u8, 0x00, 0x05, 0x00, 0x00, 0x00]; // pdu_length = 5 < 6
        let mut src = ReadCursor::new(&buf);
        assert!(RdpeiHeader::decode(&mut src).is_err());
    }

    // ── Critical gap tests (from @test-gap-finder) ──

    // 1. Partial `fields_present` combinations — each optional field alone
    //    and every pair, to exercise all decoder branches independently.

    #[test]
    fn touch_contact_rect_only_roundtrip() {
        let c = TouchContact {
            contact_id: 1,
            x: 500,
            y: -200,
            contact_flags: ContactFlags::UPDATE
                | ContactFlags::INRANGE
                | ContactFlags::INCONTACT,
            contact_rect: Some(ContactRect {
                left: -10,
                top: -20,
                right: 10,
                bottom: 20,
            }),
            orientation: None,
            pressure: None,
        };
        let bytes = encode_to_vec(&c);
        // fieldsPresent byte must encode only CONTACTRECT (0x01).
        assert_eq!(bytes[1] & 0x7F, FieldsPresent::CONTACTRECT as u8);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(TouchContact::decode(&mut src).unwrap(), c);
    }

    #[test]
    fn touch_contact_orientation_only_roundtrip() {
        let c = TouchContact {
            contact_id: 2,
            x: 10,
            y: 20,
            contact_flags: ContactFlags::UPDATE | ContactFlags::INRANGE,
            contact_rect: None,
            orientation: Some(45),
            pressure: None,
        };
        let bytes = encode_to_vec(&c);
        assert_eq!(bytes[1] & 0x7F, FieldsPresent::ORIENTATION as u8);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(TouchContact::decode(&mut src).unwrap(), c);
    }

    #[test]
    fn touch_contact_pressure_only_roundtrip() {
        let c = TouchContact {
            contact_id: 3,
            x: 0,
            y: 0,
            contact_flags: ContactFlags::DOWN
                | ContactFlags::INRANGE
                | ContactFlags::INCONTACT,
            contact_rect: None,
            orientation: None,
            pressure: Some(512),
        };
        let bytes = encode_to_vec(&c);
        assert_eq!(bytes[1] & 0x7F, FieldsPresent::PRESSURE as u8);
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(TouchContact::decode(&mut src).unwrap(), c);
    }

    #[test]
    fn touch_contact_rect_and_orientation_no_pressure() {
        let c = TouchContact {
            contact_rect: Some(ContactRect {
                left: -1,
                top: -2,
                right: 3,
                bottom: 4,
            }),
            orientation: Some(270),
            pressure: None,
            ..minimal_contact()
        };
        let bytes = encode_to_vec(&c);
        assert_eq!(
            bytes[1] & 0x7F,
            (FieldsPresent::CONTACTRECT | FieldsPresent::ORIENTATION) as u8
        );
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(TouchContact::decode(&mut src).unwrap(), c);
    }

    #[test]
    fn touch_contact_rect_and_pressure_no_orientation() {
        let c = TouchContact {
            contact_rect: Some(ContactRect {
                left: 0,
                top: 0,
                right: 1,
                bottom: 1,
            }),
            orientation: None,
            pressure: Some(100),
            ..minimal_contact()
        };
        let bytes = encode_to_vec(&c);
        assert_eq!(
            bytes[1] & 0x7F,
            (FieldsPresent::CONTACTRECT | FieldsPresent::PRESSURE) as u8
        );
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(TouchContact::decode(&mut src).unwrap(), c);
    }

    #[test]
    fn touch_contact_orientation_and_pressure_no_rect() {
        let c = TouchContact {
            contact_rect: None,
            orientation: Some(90),
            pressure: Some(800),
            ..minimal_contact()
        };
        let bytes = encode_to_vec(&c);
        assert_eq!(
            bytes[1] & 0x7F,
            (FieldsPresent::ORIENTATION | FieldsPresent::PRESSURE) as u8
        );
        let mut src = ReadCursor::new(&bytes);
        assert_eq!(TouchContact::decode(&mut src).unwrap(), c);
    }

    // 2. FOUR_BYTE_UNSIGNED boundary wire-byte patterns.

    #[test]
    fn four_byte_unsigned_boundary_wire_bytes() {
        let cases: [(u32, &[u8]); 8] = [
            (0x00, &[0x00]),
            (0x3F, &[0x3F]),
            (0x40, &[0x40, 0x40]),
            (0x3FFF, &[0x7F, 0xFF]),
            (0x0000_4000, &[0x80, 0x40, 0x00]),
            (0x003F_FFFF, &[0xBF, 0xFF, 0xFF]),
            (0x0040_0000, &[0xC0, 0x40, 0x00, 0x00]),
            (0x3FFF_FFFF, &[0xFF, 0xFF, 0xFF, 0xFF]),
        ];
        for (value, expected) in cases {
            let mut buf = [0u8; 4];
            let mut dst = WriteCursor::new(&mut buf);
            encode_four_byte_unsigned(&mut dst, value, "t").unwrap();
            assert_eq!(&buf[..expected.len()], expected, "encode {value:#x}");
            let mut src = ReadCursor::new(expected);
            assert_eq!(
                decode_four_byte_unsigned(&mut src, "t").unwrap(),
                value,
                "decode {value:#x}"
            );
        }
    }

    // 3. TouchContact with x and y in different FOUR_BYTE_SIGNED forms.
    //    Catches off-by-one cursor-advance bugs in the decoder.

    #[test]
    fn touch_contact_x_y_different_form_sizes() {
        // x=5 (1-byte form, mag<=0x1F), y=5000 (2-byte form, mag<=0x1FFF).
        let c = TouchContact {
            contact_id: 0,
            x: 5,
            y: 5000,
            contact_flags: ContactFlags::UP,
            contact_rect: None,
            orientation: None,
            pressure: None,
        };
        let bytes = encode_to_vec(&c);
        let mut src = ReadCursor::new(&bytes);
        let decoded = TouchContact::decode(&mut src).unwrap();
        assert_eq!(decoded.x, 5);
        assert_eq!(decoded.y, 5000);
    }

    #[test]
    fn touch_contact_x_y_mixed_signs_and_forms() {
        // x=-0x1FFF (2-byte form), y=0x1F_FFFF (3-byte form).
        let c = TouchContact {
            x: -0x1FFF,
            y: 0x1F_FFFF,
            ..minimal_contact()
        };
        let bytes = encode_to_vec(&c);
        let mut src = ReadCursor::new(&bytes);
        let decoded = TouchContact::decode(&mut src).unwrap();
        assert_eq!(decoded.x, -0x1FFF);
        assert_eq!(decoded.y, 0x1F_FFFF);
    }

    #[test]
    fn touch_contact_x_y_all_four_form_combinations() {
        // Every pair of (x_form, y_form) ∈ {1,2,3,4} bytes — verifies the
        // decoder's cursor advance is independent of x's encoded length.
        let mags: [i32; 4] = [0x10, 0x1000, 0x0010_0000, 0x1000_0000];
        for &xv in &mags {
            for &yv in &mags {
                let c = TouchContact {
                    x: xv,
                    y: -yv,
                    ..minimal_contact()
                };
                let bytes = encode_to_vec(&c);
                let mut src = ReadCursor::new(&bytes);
                let decoded = TouchContact::decode(&mut src).unwrap();
                assert_eq!(decoded.x, xv, "x for ({xv:#x},{yv:#x})");
                assert_eq!(decoded.y, -yv, "y for ({xv:#x},{yv:#x})");
            }
        }
    }

    // 4. ScReadyPdu — presence of `supportedFeatures` is driven by pduLength,
    //    not by protocol_version (MS-RDPEI 2.2.3.1 uses SHOULD).

    #[test]
    fn sc_ready_v200_with_pdu_length_14_reads_features() {
        // Server is V200 but (non-conformant or future) sends pdu_length=14.
        // Decoder must still read supportedFeatures — presence is
        // pduLength-gated per spec SHOULD, not version-gated.
        let pdu = ScReadyPdu {
            protocol_version: RDPINPUT_PROTOCOL_V200,
            supported_features: Some(0),
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 14);
        let decoded = ScReadyPdu::decode_from(&bytes).unwrap();
        assert_eq!(decoded.protocol_version, RDPINPUT_PROTOCOL_V200);
        assert_eq!(decoded.supported_features, Some(0));
    }

    #[test]
    fn sc_ready_v300_with_pdu_length_10_yields_no_features() {
        // V300 server omits supportedFeatures (spec SHOULD — not MUST).
        let pdu = ScReadyPdu {
            protocol_version: RDPINPUT_PROTOCOL_V300,
            supported_features: None,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 10);
        let decoded = ScReadyPdu::decode_from(&bytes).unwrap();
        assert_eq!(decoded.protocol_version, RDPINPUT_PROTOCOL_V300);
        assert_eq!(decoded.supported_features, None);
    }

    // Additional cheap negatives surfaced by the gap analysis.

    #[test]
    fn cs_ready_decode_wrong_length_rejected() {
        // Build a CS_READY with pduLength=15 (wrong; must be 16).
        let buf = [
            0x02, 0x00, 0x0F, 0x00, 0x00, 0x00, // header with wrong length
            0, 0, 0, 0, 0, 0, 1, 0, 0xA, 0,
        ];
        assert!(CsReadyPdu::decode_from(&buf).is_err());
    }

    #[test]
    fn suspend_resume_decode_wrong_length_rejected() {
        let bad_suspend = [0x04u8, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00];
        assert!(SuspendInputPdu::decode_from(&bad_suspend).is_err());
        let bad_resume = [0x05u8, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00];
        assert!(ResumeInputPdu::decode_from(&bad_resume).is_err());
    }

    #[test]
    fn header_accepts_exact_minimum_pdu_length() {
        // pdu_length = 6 is valid (header-only PDU, e.g., SUSPEND).
        let buf = [0x04u8, 0x00, 0x06, 0x00, 0x00, 0x00];
        let mut src = ReadCursor::new(&buf);
        let h = RdpeiHeader::decode(&mut src).unwrap();
        assert_eq!(h.pdu_length, 6);
    }
}
