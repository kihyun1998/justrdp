//! Property API PDUs (MS-RDPECAM §2.2.3.16 – §2.2.3.20).
//!
//! The property API is v2-only: every PDU in this module carries
//! `Version = 2` on the wire and MUST NOT be sent on a channel where
//! version 1 was negotiated. The enumeration splits into two sets:
//!
//! - [`PropertySet::CameraControl`] (0x01) -- Exposure, Focus, Pan, ...
//! - [`PropertySet::VideoProcAmp`]  (0x02) -- Brightness, Contrast, ...
//!
//! Property values are signed 32-bit integers (i32 LE), which allows for
//! signed control ranges like Pan `-180..=180`. Every `PROPERTY_VALUE`
//! also carries a `Mode` byte: `Manual` means the bundled integer is the
//! value to use, `Auto` means the device picks its own and the integer
//! value MUST be ignored (but is still preserved by round-trip so the
//! encoder is not forced to zero it out).

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{
    MSG_PROPERTY_LIST_REQUEST, MSG_PROPERTY_LIST_RESPONSE, MSG_PROPERTY_VALUE_REQUEST,
    MSG_PROPERTY_VALUE_RESPONSE, MSG_SET_PROPERTY_VALUE_REQUEST, VERSION_2,
};
use crate::pdu::header::{decode_header, encode_header, expect_message_id, HEADER_SIZE};

// ── Safety caps (checklist §10) ──

/// Maximum number of property descriptions accepted per response.
///
/// The spec defines 11 properties total (6 `CameraControl` + 5
/// `VideoProcAmp`); 64 is generous and bounds decode-time allocation.
pub const MAX_PROPERTIES: usize = 64;

// ── PropertySet (§2.2.3.17.1 / checklist §5.5) ──

/// `PropertySet` byte of a property description / request. Unknown values
/// are preserved as [`PropertySet::Other`] for forward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertySet {
    /// 0x01 -- Exposure, Focus, Pan, Roll, Tilt, Zoom.
    CameraControl,
    /// 0x02 -- BacklightCompensation, Brightness, Contrast, Hue, WhiteBalance.
    VideoProcAmp,
    Other(u8),
}

impl PropertySet {
    pub const CAMERA_CONTROL_RAW: u8 = 0x01;
    pub const VIDEO_PROC_AMP_RAW: u8 = 0x02;

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            Self::CAMERA_CONTROL_RAW => Self::CameraControl,
            Self::VIDEO_PROC_AMP_RAW => Self::VideoProcAmp,
            other => Self::Other(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::CameraControl => Self::CAMERA_CONTROL_RAW,
            Self::VideoProcAmp => Self::VIDEO_PROC_AMP_RAW,
            Self::Other(raw) => raw,
        }
    }
}

// ── PropertyId constants (checklist §5.6 / §5.7) ──

/// Property ids for `PropertySet::CameraControl`.
pub mod camera_control_property_id {
    pub const EXPOSURE: u8 = 0x01;
    pub const FOCUS: u8 = 0x02;
    pub const PAN: u8 = 0x03;
    pub const ROLL: u8 = 0x04;
    pub const TILT: u8 = 0x05;
    pub const ZOOM: u8 = 0x06;
}

/// Property ids for `PropertySet::VideoProcAmp`.
pub mod video_proc_amp_property_id {
    /// Value MUST be 0 (disabled) or 1 (enabled).
    pub const BACKLIGHT_COMPENSATION: u8 = 0x01;
    pub const BRIGHTNESS: u8 = 0x02;
    pub const CONTRAST: u8 = 0x03;
    pub const HUE: u8 = 0x04;
    pub const WHITE_BALANCE: u8 = 0x05;
}

// ── PropertyCapabilities (§2.2.3.17.1 / checklist §5.9) ──

/// u8 bitmask indicating which modes the property supports.
pub mod property_capabilities {
    /// The property can be driven manually with a value.
    pub const MANUAL: u8 = 0x01;
    /// The property can be put in auto mode.
    pub const AUTO: u8 = 0x02;
}

// ── PropertyMode (§2.2.3.19.1 / checklist §5.8) ──

/// Mode byte of a `PROPERTY_VALUE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyMode {
    /// 0x01 -- caller supplied explicit integer value.
    Manual,
    /// 0x02 -- device drives the property automatically; the bundled
    /// integer is ignored (but preserved by round-trip).
    Auto,
    Other(u8),
}

impl PropertyMode {
    pub const MANUAL_RAW: u8 = 0x01;
    pub const AUTO_RAW: u8 = 0x02;

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            Self::MANUAL_RAW => Self::Manual,
            Self::AUTO_RAW => Self::Auto,
            other => Self::Other(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Manual => Self::MANUAL_RAW,
            Self::Auto => Self::AUTO_RAW,
            Self::Other(raw) => raw,
        }
    }
}

// ── PropertyValue (§2.2.3.19.1) — 5 bytes ──

/// A property value pair: the effective mode plus a signed integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyValue {
    pub mode: PropertyMode,
    /// Signed 32-bit integer (i32 LE on the wire).
    pub value: i32,
}

impl PropertyValue {
    pub const WIRE_SIZE: usize = 5;

    pub fn manual(value: i32) -> Self {
        Self { mode: PropertyMode::Manual, value }
    }

    pub fn auto() -> Self {
        Self { mode: PropertyMode::Auto, value: 0 }
    }

    fn encode(&self, dst: &mut WriteCursor<'_>, ctx: &'static str) -> EncodeResult<()> {
        dst.write_u8(self.mode.to_u8(), ctx)?;
        dst.write_i32_le(self.value, ctx)?;
        Ok(())
    }

    fn decode(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<Self> {
        let mode = PropertyMode::from_u8(src.read_u8(ctx)?);
        let value = src.read_i32_le(ctx)?;
        Ok(Self { mode, value })
    }
}

// ── PropertyDescription (§2.2.3.17.1) — 19 bytes ──

/// Full description of one property advertised in a
/// [`PropertyListResponse`]. All value fields are **signed** 32-bit LE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyDescription {
    pub property_set: PropertySet,
    pub property_id: u8,
    /// Bitmask -- see [`property_capabilities`].
    pub capabilities: u8,
    pub min_value: i32,
    pub max_value: i32,
    pub step: i32,
    pub default_value: i32,
}

impl PropertyDescription {
    /// Wire size of a single `PROPERTY_DESCRIPTION`.
    ///
    /// Layout is 3 × u8 (PropertySet, PropertyId, Capabilities) followed by
    /// 4 × i32 LE (Min/Max/Step/Default) = 3 + 16 = 19 bytes. The
    /// `ms-rdpecam-checklist.md` §4.21 table reports "18" but the field
    /// offsets it lists (0, 1, 2, 3, 7, 11, 15) and the 2-entry `§9.7`
    /// spec vector (19 bytes per row) both agree that the real size is 19.
    pub const WIRE_SIZE: usize = 19;

    fn encode(&self, dst: &mut WriteCursor<'_>, ctx: &'static str) -> EncodeResult<()> {
        dst.write_u8(self.property_set.to_u8(), ctx)?;
        dst.write_u8(self.property_id, ctx)?;
        dst.write_u8(self.capabilities, ctx)?;
        dst.write_i32_le(self.min_value, ctx)?;
        dst.write_i32_le(self.max_value, ctx)?;
        dst.write_i32_le(self.step, ctx)?;
        dst.write_i32_le(self.default_value, ctx)?;
        Ok(())
    }

    fn decode(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<Self> {
        let property_set = PropertySet::from_u8(src.read_u8(ctx)?);
        let property_id = src.read_u8(ctx)?;
        let capabilities = src.read_u8(ctx)?;
        let min_value = src.read_i32_le(ctx)?;
        let max_value = src.read_i32_le(ctx)?;
        let step = src.read_i32_le(ctx)?;
        let default_value = src.read_i32_le(ctx)?;
        Ok(Self {
            property_set,
            property_id,
            capabilities,
            min_value,
            max_value,
            step,
            default_value,
        })
    }
}

// ── PropertyListRequest (§2.2.3.16) — 2 bytes fixed ──

/// Server asks the client to enumerate all properties it supports. v2 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyListRequest;

impl PropertyListRequest {
    pub const WIRE_SIZE: usize = HEADER_SIZE;
}

impl Encode for PropertyListRequest {
    fn name(&self) -> &'static str {
        "CAM::PropertyListRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        encode_header(dst, VERSION_2, MSG_PROPERTY_LIST_REQUEST, self.name())
    }
}

impl<'de> Decode<'de> for PropertyListRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::PropertyListRequest";
        let (version, message_id) = decode_header(src, CTX)?;
        if version != VERSION_2 {
            return Err(DecodeError::invalid_value(CTX, "Version != 2"));
        }
        expect_message_id(message_id, MSG_PROPERTY_LIST_REQUEST, CTX)?;
        Ok(Self)
    }
}

// ── PropertyListResponse (§2.2.3.17) — variable ──

/// Client reply enumerating every property the device supports. v2 only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyListResponse {
    pub properties: Vec<PropertyDescription>,
}

impl PropertyListResponse {
    fn wire_size(&self) -> usize {
        HEADER_SIZE + self.properties.len() * PropertyDescription::WIRE_SIZE
    }
}

impl Encode for PropertyListResponse {
    fn name(&self) -> &'static str {
        "CAM::PropertyListResponse"
    }

    fn size(&self) -> usize {
        self.wire_size()
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::PropertyListResponse";
        if self.properties.len() > MAX_PROPERTIES {
            return Err(EncodeError::invalid_value(CTX, "properties.len() > cap"));
        }
        encode_header(dst, VERSION_2, MSG_PROPERTY_LIST_RESPONSE, CTX)?;
        for p in &self.properties {
            p.encode(dst, CTX)?;
        }
        Ok(())
    }
}

impl<'de> Decode<'de> for PropertyListResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::PropertyListResponse";
        let (version, message_id) = decode_header(src, CTX)?;
        if version != VERSION_2 {
            return Err(DecodeError::invalid_value(CTX, "Version != 2"));
        }
        expect_message_id(message_id, MSG_PROPERTY_LIST_RESPONSE, CTX)?;
        let remaining = src.remaining();
        if remaining % PropertyDescription::WIRE_SIZE != 0 {
            return Err(DecodeError::invalid_value(
                CTX,
                "payload length not a multiple of 19",
            ));
        }
        let count = remaining / PropertyDescription::WIRE_SIZE;
        if count > MAX_PROPERTIES {
            return Err(DecodeError::invalid_value(CTX, "count > cap"));
        }
        let mut properties = Vec::with_capacity(count);
        for _ in 0..count {
            properties.push(PropertyDescription::decode(src, CTX)?);
        }
        Ok(Self { properties })
    }
}

// ── PropertyValueRequest (§2.2.3.18) — 4 bytes fixed ──

/// Server asks the client for the current value of a specific property.
/// v2 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyValueRequest {
    pub property_set: PropertySet,
    pub property_id: u8,
}

impl PropertyValueRequest {
    pub const WIRE_SIZE: usize = HEADER_SIZE + 2;

    pub fn new(property_set: PropertySet, property_id: u8) -> Self {
        Self { property_set, property_id }
    }
}

impl Encode for PropertyValueRequest {
    fn name(&self) -> &'static str {
        "CAM::PropertyValueRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::PropertyValueRequest";
        encode_header(dst, VERSION_2, MSG_PROPERTY_VALUE_REQUEST, CTX)?;
        dst.write_u8(self.property_set.to_u8(), CTX)?;
        dst.write_u8(self.property_id, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for PropertyValueRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::PropertyValueRequest";
        let (version, message_id) = decode_header(src, CTX)?;
        if version != VERSION_2 {
            return Err(DecodeError::invalid_value(CTX, "Version != 2"));
        }
        expect_message_id(message_id, MSG_PROPERTY_VALUE_REQUEST, CTX)?;
        let property_set = PropertySet::from_u8(src.read_u8(CTX)?);
        let property_id = src.read_u8(CTX)?;
        Ok(Self { property_set, property_id })
    }
}

// ── PropertyValueResponse (§2.2.3.19) — 7 bytes fixed ──

/// Client reply carrying the current value of the requested property.
/// v2 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyValueResponse {
    pub value: PropertyValue,
}

impl PropertyValueResponse {
    pub const WIRE_SIZE: usize = HEADER_SIZE + PropertyValue::WIRE_SIZE;

    pub fn new(value: PropertyValue) -> Self {
        Self { value }
    }
}

impl Encode for PropertyValueResponse {
    fn name(&self) -> &'static str {
        "CAM::PropertyValueResponse"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::PropertyValueResponse";
        encode_header(dst, VERSION_2, MSG_PROPERTY_VALUE_RESPONSE, CTX)?;
        self.value.encode(dst, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for PropertyValueResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::PropertyValueResponse";
        let (version, message_id) = decode_header(src, CTX)?;
        if version != VERSION_2 {
            return Err(DecodeError::invalid_value(CTX, "Version != 2"));
        }
        expect_message_id(message_id, MSG_PROPERTY_VALUE_RESPONSE, CTX)?;
        let value = PropertyValue::decode(src, CTX)?;
        Ok(Self { value })
    }
}

// ── SetPropertyValueRequest (§2.2.3.20) — 9 bytes fixed ──

/// Server asks the client to change a property. If `value.mode` is
/// `Auto`, `value.value` is preserved on the wire but MUST be ignored
/// semantically per §2.2.3.20.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetPropertyValueRequest {
    pub property_set: PropertySet,
    pub property_id: u8,
    pub value: PropertyValue,
}

impl SetPropertyValueRequest {
    pub const WIRE_SIZE: usize = HEADER_SIZE + 2 + PropertyValue::WIRE_SIZE;

    pub fn new(property_set: PropertySet, property_id: u8, value: PropertyValue) -> Self {
        Self { property_set, property_id, value }
    }
}

impl Encode for SetPropertyValueRequest {
    fn name(&self) -> &'static str {
        "CAM::SetPropertyValueRequest"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "CAM::SetPropertyValueRequest";
        encode_header(dst, VERSION_2, MSG_SET_PROPERTY_VALUE_REQUEST, CTX)?;
        dst.write_u8(self.property_set.to_u8(), CTX)?;
        dst.write_u8(self.property_id, CTX)?;
        self.value.encode(dst, CTX)?;
        Ok(())
    }
}

impl<'de> Decode<'de> for SetPropertyValueRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "CAM::SetPropertyValueRequest";
        let (version, message_id) = decode_header(src, CTX)?;
        if version != VERSION_2 {
            return Err(DecodeError::invalid_value(CTX, "Version != 2"));
        }
        expect_message_id(message_id, MSG_SET_PROPERTY_VALUE_REQUEST, CTX)?;
        let property_set = PropertySet::from_u8(src.read_u8(CTX)?);
        let property_id = src.read_u8(CTX)?;
        let value = PropertyValue::decode(src, CTX)?;
        Ok(Self { property_set, property_id, value })
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn encode<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = alloc::vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        assert_eq!(w.pos(), pdu.size());
        buf
    }

    // ── PropertySet / PropertyMode round-trip ──

    #[test]
    fn property_set_preserves_unknown() {
        assert_eq!(PropertySet::from_u8(0xFE), PropertySet::Other(0xFE));
        assert_eq!(PropertySet::Other(0xFE).to_u8(), 0xFE);
        assert_eq!(PropertySet::from_u8(1), PropertySet::CameraControl);
        assert_eq!(PropertySet::from_u8(2), PropertySet::VideoProcAmp);
    }

    #[test]
    fn property_mode_preserves_unknown() {
        assert_eq!(PropertyMode::from_u8(0xAA), PropertyMode::Other(0xAA));
        assert_eq!(PropertyMode::Other(0xAA).to_u8(), 0xAA);
    }

    // ── PropertyListRequest/Response ──

    #[test]
    fn property_list_request_roundtrip() {
        let pdu = PropertyListRequest;
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x02, 0x14]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(PropertyListRequest::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn property_list_request_rejects_v1() {
        let bytes = [0x01u8, 0x14];
        let mut r = ReadCursor::new(&bytes);
        assert!(PropertyListRequest::decode(&mut r).is_err());
    }

    #[test]
    fn property_list_response_spec_sample_2_entries() {
        // Spec §4.6.2 vector: 38 bytes.
        // [0]: CameraControl(1), Focus(2), Manual+Auto(3), Min=0, Max=250, Step=5, Default=0
        // [1]: VideoProcAmp(2), Brightness(2), Manual(1), Min=0, Max=255, Step=1, Default=128
        let pdu = PropertyListResponse {
            properties: alloc::vec![
                PropertyDescription {
                    property_set: PropertySet::CameraControl,
                    property_id: camera_control_property_id::FOCUS,
                    capabilities: property_capabilities::MANUAL | property_capabilities::AUTO,
                    min_value: 0,
                    max_value: 250,
                    step: 5,
                    default_value: 0,
                },
                PropertyDescription {
                    property_set: PropertySet::VideoProcAmp,
                    property_id: video_proc_amp_property_id::BRIGHTNESS,
                    capabilities: property_capabilities::MANUAL,
                    min_value: 0,
                    max_value: 255,
                    step: 1,
                    default_value: 128,
                },
            ],
        };
        let bytes = encode(&pdu);
        assert_eq!(bytes.len(), 2 + 2 * PropertyDescription::WIRE_SIZE);
        assert_eq!(&bytes[..2], &[0x02, 0x15]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(PropertyListResponse::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn property_list_response_zero_entries() {
        let pdu = PropertyListResponse {
            properties: Vec::new(),
        };
        assert_eq!(encode(&pdu), [0x02, 0x15]);
    }

    #[test]
    fn property_list_response_rejects_partial_element() {
        let mut bytes: Vec<u8> = alloc::vec![0x02, 0x15];
        bytes.extend(core::iter::repeat_n(0u8, PropertyDescription::WIRE_SIZE - 1));
        let mut r = ReadCursor::new(&bytes);
        assert!(PropertyListResponse::decode(&mut r).is_err());
    }

    #[test]
    fn property_list_response_rejects_over_cap() {
        let mut bytes: Vec<u8> = alloc::vec![0x02, 0x15];
        bytes.extend(core::iter::repeat_n(
            0u8,
            (MAX_PROPERTIES + 1) * PropertyDescription::WIRE_SIZE,
        ));
        let mut r = ReadCursor::new(&bytes);
        assert!(PropertyListResponse::decode(&mut r).is_err());
    }

    // ── PropertyValueRequest ──

    #[test]
    fn property_value_request_roundtrip() {
        let pdu = PropertyValueRequest::new(
            PropertySet::CameraControl,
            camera_control_property_id::ZOOM,
        );
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x02, 0x16, 0x01, 0x06]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(PropertyValueRequest::decode(&mut r).unwrap(), pdu);
    }

    // ── PropertyValueResponse ──

    #[test]
    fn property_value_response_spec_sample() {
        // Spec §4.6.4: `02 17 01 64 00 00 00` — Manual, Value=100.
        let pdu = PropertyValueResponse::new(PropertyValue::manual(100));
        let bytes = encode(&pdu);
        assert_eq!(bytes, [0x02, 0x17, 0x01, 0x64, 0x00, 0x00, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(PropertyValueResponse::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn property_value_response_auto_roundtrip_preserves_value() {
        // Auto mode: value field is ignored semantically but MUST round-trip byte-exact.
        let pdu = PropertyValueResponse::new(PropertyValue {
            mode: PropertyMode::Auto,
            value: -42,
        });
        let bytes = encode(&pdu);
        let mut r = ReadCursor::new(&bytes);
        let decoded = PropertyValueResponse::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(decoded.value.value, -42);
    }

    #[test]
    fn property_value_signed_range_roundtrip() {
        for v in [i32::MIN, -1, 0, 1, i32::MAX] {
            let pdu = PropertyValueResponse::new(PropertyValue::manual(v));
            let bytes = encode(&pdu);
            let mut r = ReadCursor::new(&bytes);
            assert_eq!(PropertyValueResponse::decode(&mut r).unwrap().value.value, v);
        }
    }

    // ── SetPropertyValueRequest ──

    #[test]
    fn set_property_value_request_roundtrip() {
        let pdu = SetPropertyValueRequest::new(
            PropertySet::VideoProcAmp,
            video_proc_amp_property_id::BRIGHTNESS,
            PropertyValue::manual(128),
        );
        let bytes = encode(&pdu);
        assert_eq!(bytes.len(), SetPropertyValueRequest::WIRE_SIZE);
        assert_eq!(&bytes[..4], &[0x02, 0x18, 0x02, 0x02]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(SetPropertyValueRequest::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn set_property_value_request_auto_mode() {
        let pdu = SetPropertyValueRequest::new(
            PropertySet::CameraControl,
            camera_control_property_id::FOCUS,
            PropertyValue::auto(),
        );
        let bytes = encode(&pdu);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(SetPropertyValueRequest::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn set_property_value_request_rejects_v1_version_byte() {
        // Wire layout is valid except Version = 1.
        let bytes = [0x01u8, 0x18, 0x02, 0x02, 0x01, 0x80, 0x00, 0x00, 0x00];
        let mut r = ReadCursor::new(&bytes);
        assert!(SetPropertyValueRequest::decode(&mut r).is_err());
    }
}
