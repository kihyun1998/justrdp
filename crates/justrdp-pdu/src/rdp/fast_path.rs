#![forbid(unsafe_code)]

//! Fast-Path PDUs -- MS-RDPBCGR 2.2.9

use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

// ── Constants (MS-RDPBCGR 2.2.9) ──

/// Fast-Path Output action value (bits 0-1 of first byte). MS-RDPBCGR 2.2.9.1.2
pub const FASTPATH_OUTPUT_ACTION_FASTPATH: u8 = 0x00;

/// Fast-Path Output encryption flag. MS-RDPBCGR 2.2.9.1.2
pub const FASTPATH_OUTPUT_ENCRYPTED: u8 = 0x01;

/// Fast-Path Output secure checksum flag. MS-RDPBCGR 2.2.9.1.2
pub const FASTPATH_OUTPUT_SECURE_CHECKSUM: u8 = 0x02;

/// Fast-Path Input action value (bits 0-1 of first byte). MS-RDPBCGR 2.2.8.1.2
pub const FASTPATH_INPUT_ACTION_FASTPATH: u8 = 0x00;

/// Fast-Path Input encryption flag (bits 6-7). MS-RDPBCGR 2.2.8.1.2
pub const FASTPATH_INPUT_ENCRYPTED: u8 = 0x01;

/// Fast-Path Input secure checksum flag (bits 6-7). MS-RDPBCGR 2.2.8.1.2
pub const FASTPATH_INPUT_SECURE_CHECKSUM: u8 = 0x02;

// ── Input event wire sizes ──

/// Scancode event: eventHeader(1) + keyCode(1). MS-RDPBCGR 2.2.8.1.2.2.1
pub const FASTPATH_SCANCODE_EVENT_SIZE: usize = 2;
/// Mouse event: eventHeader(1) + pointerFlags(2) + xPos(2) + yPos(2). MS-RDPBCGR 2.2.8.1.2.2.3
pub const FASTPATH_MOUSE_EVENT_SIZE: usize = 7;
/// Extended mouse event: eventHeader(1) + pointerFlags(2) + xPos(2) + yPos(2). MS-RDPBCGR 2.2.8.1.2.2.4
pub const FASTPATH_MOUSEX_EVENT_SIZE: usize = 7;
/// Relative mouse event: eventHeader(1) + xDelta(2) + yDelta(2). MS-RDPBCGR 2.2.8.1.2.2.5
pub const FASTPATH_RELATIVE_MOUSE_EVENT_SIZE: usize = 5;
/// Sync event: eventHeader(1). MS-RDPBCGR 2.2.8.1.2.2.6
pub const FASTPATH_SYNC_EVENT_SIZE: usize = 1;
/// Unicode event: eventHeader(1) + unicodeCode(2). MS-RDPBCGR 2.2.8.1.2.2.2
pub const FASTPATH_UNICODE_EVENT_SIZE: usize = 3;
/// QoE Timestamp event: eventHeader(1) + timestamp(4). MS-RDPBCGR 2.2.8.1.2.2.7
pub const FASTPATH_QOE_TIMESTAMP_EVENT_SIZE: usize = 5;

// ── Fast-Path Output Update Types ──

/// Fast-Path update types (lower 4 bits of updateHeader).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FastPathUpdateType {
    Orders = 0x0,
    Bitmap = 0x1,
    Palette = 0x2,
    Synchronize = 0x3,
    SurfaceCommands = 0x4,
    PointerHidden = 0x5,
    PointerDefault = 0x6,
    PointerPosition = 0x8,
    PointerColor = 0x9,
    PointerCached = 0xA,
    PointerNew = 0xB,
    PointerLarge = 0xC,
}

impl FastPathUpdateType {
    pub fn from_u8(val: u8) -> DecodeResult<Self> {
        match val {
            0x0 => Ok(Self::Orders),
            0x1 => Ok(Self::Bitmap),
            0x2 => Ok(Self::Palette),
            0x3 => Ok(Self::Synchronize),
            0x4 => Ok(Self::SurfaceCommands),
            0x5 => Ok(Self::PointerHidden),
            0x6 => Ok(Self::PointerDefault),
            0x8 => Ok(Self::PointerPosition),
            0x9 => Ok(Self::PointerColor),
            0xA => Ok(Self::PointerCached),
            0xB => Ok(Self::PointerNew),
            0xC => Ok(Self::PointerLarge),
            _ => Err(DecodeError::unexpected_value(
                "FastPathUpdateType",
                "updateCode",
                "unknown fast-path update type",
            )),
        }
    }
}

// ── Fragmentation ──

/// Fast-Path fragmentation values (bits 4-5 of updateHeader).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Fragmentation {
    Single = 0x0,
    Last = 0x1,
    First = 0x2,
    Next = 0x3,
}

impl Fragmentation {
    pub fn from_u8(val: u8) -> DecodeResult<Self> {
        match val {
            0x0 => Ok(Self::Single),
            0x1 => Ok(Self::Last),
            0x2 => Ok(Self::First),
            0x3 => Ok(Self::Next),
            _ => Err(DecodeError::unexpected_value(
                "Fragmentation",
                "fragmentation",
                "unknown fragmentation value",
            )),
        }
    }
}

// ── Fast-Path Output Header ──

/// Fast-Path Output Header (first byte + length).
///
/// MS-RDPBCGR 2.2.9.1.2 (Server Fast-Path Update PDU). Bit layout:
///
/// ```text
/// ┌──────────────────────────────────────────────────┐
/// │ byte 0: action(2) | reserved(4) | flags(2)       │
/// │ byte 1: length1                                  │
/// │ byte 2: length2 (optional, when length1 has high bit set) │
/// └──────────────────────────────────────────────────┘
/// ```
///
/// **Important:** Unlike the *input* header (`FastPathInputHeader`), the
/// output header's middle 4 bits are **reserved** — they are not a
/// `numEvents` field, and there is no extended-byte mechanism following
/// the length. Server Fast-Path Update PDUs are length-delimited and the
/// number of inner updates is determined by parsing until `length` bytes
/// are exhausted (per MS-RDPBCGR 2.2.9.1.2 Remarks). Reading bits 2-5 as
/// `numEvents` and chasing an extended byte misaligns the cursor by one
/// byte and causes garbage parsing of every subsequent field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPathOutputHeader {
    /// Action field (bits 0-1), should be FASTPATH_OUTPUT_ACTION_FASTPATH.
    pub action: u8,
    /// Encryption flags (bits 6-7).
    pub flags: u8,
    /// Total length of the fast-path output PDU.
    pub length: u16,
}

impl Encode for FastPathOutputHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // Bits 2-5 are reserved per spec; always emit zero.
        let byte0 = (self.action & 0x03) | ((self.flags & 0x03) << 6);
        dst.write_u8(byte0, "FastPathOutputHeader::byte0")?;
        encode_length(dst, self.length)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "FastPathOutputHeader"
    }
    fn size(&self) -> usize {
        1 + length_field_size(self.length)
    }
}

impl<'de> Decode<'de> for FastPathOutputHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let byte0 = src.read_u8("FastPathOutputHeader::byte0")?;
        let action = byte0 & 0x03;
        // bits 2-5 reserved per MS-RDPBCGR 2.2.9.1.2 — ignore.
        let flags = (byte0 >> 6) & 0x03;
        let length = decode_length(src)?;
        Ok(Self {
            action,
            flags,
            length,
        })
    }
}

// ── Fast-Path Output Update ──

/// A single Fast-Path Output Update PDU.
///
/// ```text
/// ┌────────────────────────────────────────────────────┐
/// │ updateHeader(1): updateCode(4) | frag(2) | comp(2) │
/// │ compressionFlags(optional 1 byte)                   │
/// │ size(u16 LE)                                        │
/// │ updateData(variable)                                │
/// └────────────────────────────────────────────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPathOutputUpdate {
    pub update_code: FastPathUpdateType,
    pub fragmentation: Fragmentation,
    pub compression: u8,
    pub compression_flags: Option<u8>,
    pub update_data: Vec<u8>,
}

impl Encode for FastPathOutputUpdate {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = (self.update_code as u8 & 0x0F)
            | ((self.fragmentation as u8 & 0x03) << 4)
            | ((self.compression & 0x03) << 6);
        dst.write_u8(header, "FastPathOutputUpdate::updateHeader")?;
        if let Some(cf) = self.compression_flags {
            dst.write_u8(cf, "FastPathOutputUpdate::compressionFlags")?;
        }
        if self.update_data.len() > u16::MAX as usize {
            return Err(justrdp_core::EncodeError::other("FastPathOutputUpdate", "update_data too large for u16"));
        }
        dst.write_u16_le(
            self.update_data.len() as u16,
            "FastPathOutputUpdate::size",
        )?;
        dst.write_slice(&self.update_data, "FastPathOutputUpdate::updateData")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "FastPathOutputUpdate" }

    fn size(&self) -> usize {
        1 // updateHeader
        + if self.compression_flags.is_some() { 1 } else { 0 }
        + 2 // size field
        + self.update_data.len()
    }
}

impl<'de> Decode<'de> for FastPathOutputUpdate {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("FastPathOutputUpdate::updateHeader")?;
        let update_code = FastPathUpdateType::from_u8(header & 0x0F)?;
        let fragmentation = Fragmentation::from_u8((header >> 4) & 0x03)?;
        let compression = (header >> 6) & 0x03;

        let compression_flags = if compression != 0 {
            Some(src.read_u8("FastPathOutputUpdate::compressionFlags")?)
        } else {
            None
        };

        let size = src.read_u16_le("FastPathOutputUpdate::size")? as usize;
        let data = src.read_slice(size, "FastPathOutputUpdate::updateData")?;
        Ok(Self {
            update_code,
            fragmentation,
            compression,
            compression_flags,
            update_data: data.to_vec(),
        })
    }
}

// ── Fast-Path Input Header ──

/// Fast-Path Input Header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPathInputHeader {
    /// Action field (bits 0-1), should be FASTPATH_INPUT_ACTION_FASTPATH.
    pub action: u8,
    /// Number of input events (bits 2-5). If 0, the numEvents field follows the length.
    pub num_events: u8,
    /// Encryption flags (bits 6-7).
    pub flags: u8,
    /// Total length of the fast-path input PDU.
    pub length: u16,
}

impl Encode for FastPathInputHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let use_extended = self.num_events > 15 || self.num_events == 0;
        let hdr_num = if use_extended { 0 } else { self.num_events };
        let byte0 = (self.action & 0x03)
            | ((hdr_num & 0x0F) << 2)
            | ((self.flags & 0x03) << 6);
        dst.write_u8(byte0, "FastPathInputHeader::byte0")?;
        encode_length(dst, self.length)?;
        if use_extended {
            dst.write_u8(self.num_events, "FastPathInputHeader::numEventsExt")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str { "FastPathInputHeader" }
    fn size(&self) -> usize {
        let use_extended = self.num_events > 15 || self.num_events == 0;
        1 + length_field_size(self.length) + if use_extended { 1 } else { 0 }
    }
}

impl<'de> Decode<'de> for FastPathInputHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let byte0 = src.read_u8("FastPathInputHeader::byte0")?;
        let action = byte0 & 0x03;
        let mut num_events = (byte0 >> 2) & 0x0F;
        let flags = (byte0 >> 6) & 0x03;
        let length = decode_length(src)?;
        if num_events == 0 {
            num_events = src.read_u8("FastPathInputHeader::numEventsExt")?;
        }
        Ok(Self { action, num_events, flags, length })
    }
}

// ── Fast-Path Input Event Codes ──

/// Fast-Path input event codes (bits 5-7 of eventHeader).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FastPathInputEventCode {
    Scancode = 0x0,
    Mouse = 0x1,
    MouseX = 0x2,
    Sync = 0x3,
    Unicode = 0x4,
    RelativeMouse = 0x5,
    QoeTimestamp = 0x6,
}

impl FastPathInputEventCode {
    pub fn from_u8(val: u8) -> DecodeResult<Self> {
        match val {
            0x0 => Ok(Self::Scancode),
            0x1 => Ok(Self::Mouse),
            0x2 => Ok(Self::MouseX),
            0x3 => Ok(Self::Sync),
            0x4 => Ok(Self::Unicode),
            0x5 => Ok(Self::RelativeMouse),
            0x6 => Ok(Self::QoeTimestamp),
            _ => Err(DecodeError::unexpected_value(
                "FastPathInputEventCode",
                "eventCode",
                "unknown fast-path input event code",
            )),
        }
    }
}

// ── Fast-Path Input Events ──

/// Scancode input event (eventCode = 0x0).
///
/// eventFlags (5 bits) contain keyboard flags (release, extended, etc.).
/// Followed by keyCode (1 byte).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPathScancodeEvent {
    pub event_flags: u8,
    pub key_code: u8,
}

impl Encode for FastPathScancodeEvent {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = (self.event_flags & 0x1F)
            | ((FastPathInputEventCode::Scancode as u8) << 5);
        dst.write_u8(header, "FastPathScancodeEvent::eventHeader")?;
        dst.write_u8(self.key_code, "FastPathScancodeEvent::keyCode")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "FastPathScancodeEvent" }
    fn size(&self) -> usize { FASTPATH_SCANCODE_EVENT_SIZE }
}

impl<'de> Decode<'de> for FastPathScancodeEvent {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("FastPathScancodeEvent::eventHeader")?;
        let event_flags = header & 0x1F;
        let code = (header >> 5) & 0x07;
        if code != FastPathInputEventCode::Scancode as u8 {
            return Err(DecodeError::unexpected_value(
                "FastPathScancodeEvent", "eventCode", "expected Scancode event code",
            ));
        }
        let key_code = src.read_u8("FastPathScancodeEvent::keyCode")?;
        Ok(Self { event_flags, key_code })
    }
}

/// Mouse input event (eventCode = 0x1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPathMouseEvent {
    pub event_flags: u8,
    pub pointer_flags: u16,
    pub x_pos: u16,
    pub y_pos: u16,
}

impl Encode for FastPathMouseEvent {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = (self.event_flags & 0x1F)
            | ((FastPathInputEventCode::Mouse as u8) << 5);
        dst.write_u8(header, "FastPathMouseEvent::eventHeader")?;
        dst.write_u16_le(self.pointer_flags, "FastPathMouseEvent::pointerFlags")?;
        dst.write_u16_le(self.x_pos, "FastPathMouseEvent::xPos")?;
        dst.write_u16_le(self.y_pos, "FastPathMouseEvent::yPos")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "FastPathMouseEvent" }
    fn size(&self) -> usize { FASTPATH_MOUSE_EVENT_SIZE }
}

impl<'de> Decode<'de> for FastPathMouseEvent {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("FastPathMouseEvent::eventHeader")?;
        let event_flags = header & 0x1F;
        let code = (header >> 5) & 0x07;
        if code != FastPathInputEventCode::Mouse as u8 {
            return Err(DecodeError::unexpected_value(
                "FastPathMouseEvent", "eventCode", "expected Mouse event code",
            ));
        }
        let pointer_flags = src.read_u16_le("FastPathMouseEvent::pointerFlags")?;
        let x_pos = src.read_u16_le("FastPathMouseEvent::xPos")?;
        let y_pos = src.read_u16_le("FastPathMouseEvent::yPos")?;
        Ok(Self { event_flags, pointer_flags, x_pos, y_pos })
    }
}

/// Extended mouse input event (eventCode = 0x2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPathMouseXEvent {
    pub event_flags: u8,
    pub pointer_flags: u16,
    pub x_pos: u16,
    pub y_pos: u16,
}

impl Encode for FastPathMouseXEvent {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = (self.event_flags & 0x1F)
            | ((FastPathInputEventCode::MouseX as u8) << 5);
        dst.write_u8(header, "FastPathMouseXEvent::eventHeader")?;
        dst.write_u16_le(self.pointer_flags, "FastPathMouseXEvent::pointerFlags")?;
        dst.write_u16_le(self.x_pos, "FastPathMouseXEvent::xPos")?;
        dst.write_u16_le(self.y_pos, "FastPathMouseXEvent::yPos")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "FastPathMouseXEvent" }
    fn size(&self) -> usize { FASTPATH_MOUSEX_EVENT_SIZE }
}

impl<'de> Decode<'de> for FastPathMouseXEvent {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("FastPathMouseXEvent::eventHeader")?;
        let event_flags = header & 0x1F;
        let code = (header >> 5) & 0x07;
        if code != FastPathInputEventCode::MouseX as u8 {
            return Err(DecodeError::unexpected_value(
                "FastPathMouseXEvent", "eventCode", "expected MouseX event code",
            ));
        }
        let pointer_flags = src.read_u16_le("FastPathMouseXEvent::pointerFlags")?;
        let x_pos = src.read_u16_le("FastPathMouseXEvent::xPos")?;
        let y_pos = src.read_u16_le("FastPathMouseXEvent::yPos")?;
        Ok(Self { event_flags, pointer_flags, x_pos, y_pos })
    }
}

/// Relative mouse input event (eventCode = 0x5).
///
/// MS-RDPBCGR 2.2.8.1.2.2.5: carries signed delta coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPathRelativeMouseEvent {
    pub event_flags: u8,
    pub x_delta: i16,
    pub y_delta: i16,
}

impl Encode for FastPathRelativeMouseEvent {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = (self.event_flags & 0x1F)
            | ((FastPathInputEventCode::RelativeMouse as u8) << 5);
        dst.write_u8(header, "FastPathRelativeMouseEvent::eventHeader")?;
        dst.write_i16_le(self.x_delta, "FastPathRelativeMouseEvent::xDelta")?;
        dst.write_i16_le(self.y_delta, "FastPathRelativeMouseEvent::yDelta")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "FastPathRelativeMouseEvent" }
    fn size(&self) -> usize { FASTPATH_RELATIVE_MOUSE_EVENT_SIZE }
}

impl<'de> Decode<'de> for FastPathRelativeMouseEvent {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("FastPathRelativeMouseEvent::eventHeader")?;
        let event_flags = header & 0x1F;
        let code = (header >> 5) & 0x07;
        if code != FastPathInputEventCode::RelativeMouse as u8 {
            return Err(DecodeError::unexpected_value(
                "FastPathRelativeMouseEvent", "eventCode", "expected RelativeMouse event code",
            ));
        }
        let x_delta = src.read_i16_le("FastPathRelativeMouseEvent::xDelta")?;
        let y_delta = src.read_i16_le("FastPathRelativeMouseEvent::yDelta")?;
        Ok(Self { event_flags, x_delta, y_delta })
    }
}

/// Synchronize input event (eventCode = 0x3).
///
/// The eventFlags field contains the toggle key states directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPathSyncEvent {
    pub event_flags: u8,
}

impl Encode for FastPathSyncEvent {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = (self.event_flags & 0x1F)
            | ((FastPathInputEventCode::Sync as u8) << 5);
        dst.write_u8(header, "FastPathSyncEvent::eventHeader")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "FastPathSyncEvent" }
    fn size(&self) -> usize { FASTPATH_SYNC_EVENT_SIZE }
}

impl<'de> Decode<'de> for FastPathSyncEvent {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("FastPathSyncEvent::eventHeader")?;
        let event_flags = header & 0x1F;
        let code = (header >> 5) & 0x07;
        if code != FastPathInputEventCode::Sync as u8 {
            return Err(DecodeError::unexpected_value(
                "FastPathSyncEvent", "eventCode", "expected Sync event code",
            ));
        }
        Ok(Self { event_flags })
    }
}

/// Unicode input event (eventCode = 0x4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPathUnicodeEvent {
    pub event_flags: u8,
    pub unicode_code: u16,
}

impl Encode for FastPathUnicodeEvent {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = (self.event_flags & 0x1F)
            | ((FastPathInputEventCode::Unicode as u8) << 5);
        dst.write_u8(header, "FastPathUnicodeEvent::eventHeader")?;
        dst.write_u16_le(self.unicode_code, "FastPathUnicodeEvent::unicodeCode")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "FastPathUnicodeEvent" }
    fn size(&self) -> usize { FASTPATH_UNICODE_EVENT_SIZE }
}

impl<'de> Decode<'de> for FastPathUnicodeEvent {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("FastPathUnicodeEvent::eventHeader")?;
        let event_flags = header & 0x1F;
        let code = (header >> 5) & 0x07;
        if code != FastPathInputEventCode::Unicode as u8 {
            return Err(DecodeError::unexpected_value(
                "FastPathUnicodeEvent", "eventCode", "expected Unicode event code",
            ));
        }
        let unicode_code = src.read_u16_le("FastPathUnicodeEvent::unicodeCode")?;
        Ok(Self { event_flags, unicode_code })
    }
}

/// QoE Timestamp input event (eventCode = 0x6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastPathQoeTimestampEvent {
    pub event_flags: u8,
    pub timestamp: u32,
}

impl Encode for FastPathQoeTimestampEvent {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = (self.event_flags & 0x1F)
            | ((FastPathInputEventCode::QoeTimestamp as u8) << 5);
        dst.write_u8(header, "FastPathQoeTimestampEvent::eventHeader")?;
        dst.write_u32_le(self.timestamp, "FastPathQoeTimestampEvent::timestamp")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "FastPathQoeTimestampEvent" }
    fn size(&self) -> usize { FASTPATH_QOE_TIMESTAMP_EVENT_SIZE }
}

impl<'de> Decode<'de> for FastPathQoeTimestampEvent {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("FastPathQoeTimestampEvent::eventHeader")?;
        let event_flags = header & 0x1F;
        let code = (header >> 5) & 0x07;
        if code != FastPathInputEventCode::QoeTimestamp as u8 {
            return Err(DecodeError::unexpected_value(
                "FastPathQoeTimestampEvent", "eventCode", "expected QoeTimestamp event code",
            ));
        }
        let timestamp = src.read_u32_le("FastPathQoeTimestampEvent::timestamp")?;
        Ok(Self { event_flags, timestamp })
    }
}

/// Enum covering all Fast-Path input event types for generic decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastPathInputEvent {
    Scancode(FastPathScancodeEvent),
    Mouse(FastPathMouseEvent),
    MouseX(FastPathMouseXEvent),
    RelativeMouse(FastPathRelativeMouseEvent),
    Sync(FastPathSyncEvent),
    Unicode(FastPathUnicodeEvent),
    QoeTimestamp(FastPathQoeTimestampEvent),
}

impl Encode for FastPathInputEvent {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        match self {
            FastPathInputEvent::Scancode(e) => e.encode(dst),
            FastPathInputEvent::Mouse(e) => e.encode(dst),
            FastPathInputEvent::MouseX(e) => e.encode(dst),
            FastPathInputEvent::RelativeMouse(e) => e.encode(dst),
            FastPathInputEvent::Sync(e) => e.encode(dst),
            FastPathInputEvent::Unicode(e) => e.encode(dst),
            FastPathInputEvent::QoeTimestamp(e) => e.encode(dst),
        }
    }

    fn name(&self) -> &'static str { "FastPathInputEvent" }

    fn size(&self) -> usize {
        match self {
            FastPathInputEvent::Scancode(e) => e.size(),
            FastPathInputEvent::Mouse(e) => e.size(),
            FastPathInputEvent::MouseX(e) => e.size(),
            FastPathInputEvent::RelativeMouse(e) => e.size(),
            FastPathInputEvent::Sync(e) => e.size(),
            FastPathInputEvent::Unicode(e) => e.size(),
            FastPathInputEvent::QoeTimestamp(e) => e.size(),
        }
    }
}

impl<'de> Decode<'de> for FastPathInputEvent {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        // Peek the event header to determine the event code.
        let header = src.peek_u8("FastPathInputEvent::header")?;
        let code = (header >> 5) & 0x07;
        match FastPathInputEventCode::from_u8(code)? {
            FastPathInputEventCode::Scancode => {
                Ok(FastPathInputEvent::Scancode(FastPathScancodeEvent::decode(src)?))
            }
            FastPathInputEventCode::Mouse => {
                Ok(FastPathInputEvent::Mouse(FastPathMouseEvent::decode(src)?))
            }
            FastPathInputEventCode::MouseX => {
                Ok(FastPathInputEvent::MouseX(FastPathMouseXEvent::decode(src)?))
            }
            FastPathInputEventCode::RelativeMouse => {
                Ok(FastPathInputEvent::RelativeMouse(FastPathRelativeMouseEvent::decode(src)?))
            }
            FastPathInputEventCode::Sync => {
                Ok(FastPathInputEvent::Sync(FastPathSyncEvent::decode(src)?))
            }
            FastPathInputEventCode::Unicode => {
                Ok(FastPathInputEvent::Unicode(FastPathUnicodeEvent::decode(src)?))
            }
            FastPathInputEventCode::QoeTimestamp => {
                Ok(FastPathInputEvent::QoeTimestamp(FastPathQoeTimestampEvent::decode(src)?))
            }
        }
    }
}

// ── Length encoding helpers ──
// Fast-Path uses a variable-length encoding: if bit 7 of byte 1 is set,
// the length spans 2 bytes (big-endian, high bit masked off); otherwise 1 byte.

fn length_field_size(length: u16) -> usize {
    if length > 0x7F { 2 } else { 1 }
}

fn encode_length(dst: &mut WriteCursor<'_>, length: u16) -> EncodeResult<()> {
    if length > 0x7F {
        // Two-byte form: set high bit on first byte.
        let hi = ((length >> 8) as u8) | 0x80;
        let lo = (length & 0xFF) as u8;
        dst.write_u8(hi, "FastPath::length[0]")?;
        dst.write_u8(lo, "FastPath::length[1]")?;
    } else {
        dst.write_u8(length as u8, "FastPath::length")?;
    }
    Ok(())
}

fn decode_length(src: &mut ReadCursor<'_>) -> DecodeResult<u16> {
    let byte1 = src.read_u8("FastPath::length[0]")?;
    if byte1 & 0x80 != 0 {
        let byte2 = src.read_u8("FastPath::length[1]")?;
        Ok((u16::from(byte1 & 0x7F) << 8) | u16::from(byte2))
    } else {
        Ok(u16::from(byte1))
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // Helper to encode then decode, returning the decoded value.
    fn roundtrip_encode<T: Encode>(val: &T) -> Vec<u8> {
        let mut buf = vec![0u8; val.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        val.encode(&mut cursor).unwrap();
        buf
    }

    // ── Output Update roundtrip ──

    #[test]
    fn fast_path_output_update_roundtrip() {
        let update = FastPathOutputUpdate {
            update_code: FastPathUpdateType::Bitmap,
            fragmentation: Fragmentation::Single,
            compression: 0,
            compression_flags: None,
            update_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let buf = roundtrip_encode(&update);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathOutputUpdate::decode(&mut cursor).unwrap();
        assert_eq!(decoded, update);
    }

    #[test]
    fn fast_path_output_update_with_compression_roundtrip() {
        let update = FastPathOutputUpdate {
            update_code: FastPathUpdateType::Orders,
            fragmentation: Fragmentation::First,
            compression: 0x02,
            compression_flags: Some(0x61),
            update_data: vec![0x01, 0x02, 0x03],
        };
        let buf = roundtrip_encode(&update);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathOutputUpdate::decode(&mut cursor).unwrap();
        assert_eq!(decoded, update);
    }

    // ── Output Header roundtrip ──

    #[test]
    fn fast_path_output_header_roundtrip_short_length() {
        let hdr = FastPathOutputHeader {
            action: FASTPATH_OUTPUT_ACTION_FASTPATH,
            flags: 0,
            length: 50,
        };
        let buf = roundtrip_encode(&hdr);
        assert_eq!(buf.len(), 2); // 1 byte header + 1 byte length
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathOutputHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn fast_path_output_header_roundtrip_long_length() {
        let hdr = FastPathOutputHeader {
            action: FASTPATH_OUTPUT_ACTION_FASTPATH,
            flags: FASTPATH_OUTPUT_ENCRYPTED,
            length: 300,
        };
        let buf = roundtrip_encode(&hdr);
        assert_eq!(buf.len(), 3); // 1 byte header + 2 byte length
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathOutputHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn fast_path_output_header_decodes_zero_reserved_without_extended_byte() {
        // Regression test: real Windows servers send the reserved 4 bits
        // in the output header as zero. Earlier versions of this decoder
        // misread the reserved bits as a numEvents field and tried to
        // consume an extended-byte after the length, shifting the cursor
        // by one byte and producing garbage decodes for the inner update
        // structures (e.g. ERRINFO_FastPathOutputUpdate::updateData
        // NotEnoughBytes against a real RDP server).
        //
        // Wire bytes from a real Windows RDS server (192.168.136.136):
        //   00 9e ca 01 c4 1e 01 00 ...
        //   ^^                        action=0, reserved=0, flags=0
        //      ^^ ^^                  length = 0x9e/0xca two-byte form = 7882
        //            ^^               first update header (Bitmap, frag=0, comp=0)
        //               ^^ ^^         first update size LE u16 = 0x1ec4 = 7876
        //                     ...     7876 bytes of bitmap update data
        let bytes: [u8; 3] = [0x00, 0x9e, 0xca];
        let mut cursor = ReadCursor::new(&bytes);
        let hdr = FastPathOutputHeader::decode(&mut cursor).unwrap();
        assert_eq!(hdr.action, 0);
        assert_eq!(hdr.flags, 0);
        assert_eq!(hdr.length, 7882);
        // The cursor must be positioned exactly after the length field —
        // no extended numEvents byte was consumed.
        assert_eq!(cursor.pos(), 3);
    }

    // ── Input Header roundtrip ──

    #[test]
    fn fast_path_input_header_roundtrip() {
        let hdr = FastPathInputHeader {
            action: FASTPATH_INPUT_ACTION_FASTPATH,
            num_events: 2,
            flags: 0,
            length: 100,
        };
        let buf = roundtrip_encode(&hdr);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathInputHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded, hdr);
    }

    // ── Input Event roundtrips ──

    #[test]
    fn scancode_event_roundtrip() {
        let evt = FastPathScancodeEvent { event_flags: 0x01, key_code: 0x1E };
        let buf = roundtrip_encode(&evt);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathScancodeEvent::decode(&mut cursor).unwrap();
        assert_eq!(decoded, evt);
    }

    #[test]
    fn mouse_event_roundtrip() {
        let evt = FastPathMouseEvent {
            event_flags: 0,
            pointer_flags: 0x8000,
            x_pos: 640,
            y_pos: 480,
        };
        let buf = roundtrip_encode(&evt);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathMouseEvent::decode(&mut cursor).unwrap();
        assert_eq!(decoded, evt);
    }

    #[test]
    fn mousex_event_roundtrip() {
        let evt = FastPathMouseXEvent {
            event_flags: 0,
            pointer_flags: 0x0001,
            x_pos: 100,
            y_pos: 200,
        };
        let buf = roundtrip_encode(&evt);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathMouseXEvent::decode(&mut cursor).unwrap();
        assert_eq!(decoded, evt);
    }

    #[test]
    fn sync_event_roundtrip() {
        let evt = FastPathSyncEvent { event_flags: 0x07 };
        let buf = roundtrip_encode(&evt);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathSyncEvent::decode(&mut cursor).unwrap();
        assert_eq!(decoded, evt);
    }

    #[test]
    fn relative_mouse_event_roundtrip() {
        let evt = FastPathRelativeMouseEvent { event_flags: 0, x_delta: -10, y_delta: 25 };
        let buf = roundtrip_encode(&evt);
        assert_eq!(buf.len(), 5);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathRelativeMouseEvent::decode(&mut cursor).unwrap();
        assert_eq!(decoded, evt);
    }

    #[test]
    fn relative_mouse_generic_dispatch() {
        let evt = FastPathRelativeMouseEvent { event_flags: 0x03, x_delta: 100, y_delta: -50 };
        let buf = roundtrip_encode(&evt);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathInputEvent::decode(&mut cursor).unwrap();
        match decoded {
            FastPathInputEvent::RelativeMouse(e) => {
                assert_eq!(e.x_delta, 100);
                assert_eq!(e.y_delta, -50);
            }
            other => panic!("expected RelativeMouse, got {:?}", other),
        }
    }

    #[test]
    fn unicode_event_roundtrip() {
        let evt = FastPathUnicodeEvent { event_flags: 0, unicode_code: 0x0041 };
        let buf = roundtrip_encode(&evt);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathUnicodeEvent::decode(&mut cursor).unwrap();
        assert_eq!(decoded, evt);
    }

    #[test]
    fn qoe_timestamp_event_roundtrip() {
        let evt = FastPathQoeTimestampEvent { event_flags: 0, timestamp: 123456 };
        let buf = roundtrip_encode(&evt);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathQoeTimestampEvent::decode(&mut cursor).unwrap();
        assert_eq!(decoded, evt);
    }

    // ── Generic input event decode ──

    #[test]
    fn generic_input_event_decode_scancode() {
        let evt = FastPathScancodeEvent { event_flags: 0x01, key_code: 0x1E };
        let buf = roundtrip_encode(&evt);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathInputEvent::decode(&mut cursor).unwrap();
        assert_eq!(decoded, FastPathInputEvent::Scancode(evt));
    }

    #[test]
    fn generic_input_event_decode_mouse() {
        let evt = FastPathMouseEvent {
            event_flags: 0,
            pointer_flags: 0x8000,
            x_pos: 640,
            y_pos: 480,
        };
        let buf = roundtrip_encode(&evt);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathInputEvent::decode(&mut cursor).unwrap();
        assert_eq!(decoded, FastPathInputEvent::Mouse(evt));
    }

    // ── Error tests ──

    #[test]
    fn relative_mouse_event_short_buffer_error() {
        // eventCode = 0x5 (RelativeMouse) with insufficient data (needs x_delta/y_delta)
        let buf = [0x05 << 5]; // eventCode=5, eventFlags=0, but no delta bytes
        let mut cursor = ReadCursor::new(&buf);
        let result = FastPathInputEvent::decode(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_input_event_code_7_error() {
        // eventCode = 0x7 (bits 5-7), which is not a valid code
        let buf = [0x07 << 5];
        let mut cursor = ReadCursor::new(&buf);
        let result = FastPathInputEvent::decode(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_update_type_error() {
        assert!(FastPathUpdateType::from_u8(0x07).is_err());
        assert!(FastPathUpdateType::from_u8(0x0D).is_err());
        assert!(FastPathUpdateType::from_u8(0x0F).is_err());
    }

    // ── Length encoding ──

    #[test]
    fn length_encoding_single_byte() {
        let mut buf = [0u8; 1];
        let mut cursor = WriteCursor::new(&mut buf);
        encode_length(&mut cursor, 0x50).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(decode_length(&mut cursor).unwrap(), 0x50);
    }

    #[test]
    fn length_encoding_two_bytes() {
        let mut buf = [0u8; 2];
        let mut cursor = WriteCursor::new(&mut buf);
        encode_length(&mut cursor, 0x1234).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(decode_length(&mut cursor).unwrap(), 0x1234);
    }

    #[test]
    fn length_boundary_0x7f_single_byte() {
        let mut buf = [0u8; 1];
        let mut cursor = WriteCursor::new(&mut buf);
        encode_length(&mut cursor, 0x7F).unwrap();
        assert_eq!(buf[0], 0x7F);
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(decode_length(&mut cursor).unwrap(), 0x7F);
    }

    #[test]
    fn length_boundary_0x80_two_bytes() {
        let mut buf = [0u8; 2];
        let mut cursor = WriteCursor::new(&mut buf);
        encode_length(&mut cursor, 0x80).unwrap();
        assert_eq!(buf[0] & 0x80, 0x80); // high bit set
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(decode_length(&mut cursor).unwrap(), 0x80);
    }

    #[test]
    fn length_max_0x7fff() {
        let mut buf = [0u8; 2];
        let mut cursor = WriteCursor::new(&mut buf);
        encode_length(&mut cursor, 0x7FFF).unwrap();
        let mut cursor = ReadCursor::new(&buf);
        assert_eq!(decode_length(&mut cursor).unwrap(), 0x7FFF);
    }

    #[test]
    fn input_header_extended_num_events() {
        // num_events = 20 (> 15) uses extended byte
        let hdr = FastPathInputHeader {
            action: FASTPATH_INPUT_ACTION_FASTPATH,
            num_events: 20,
            flags: 0,
            length: 100,
        };
        let size = hdr.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        hdr.encode(&mut cursor).unwrap();

        // 4-bit field in byte0 should be 0
        assert_eq!((buf[0] >> 2) & 0x0F, 0);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathInputHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded.num_events, 20);
    }

    #[test]
    fn input_header_num_events_15_max_4bit() {
        let hdr = FastPathInputHeader {
            action: FASTPATH_INPUT_ACTION_FASTPATH,
            num_events: 15,
            flags: 0,
            length: 50,
        };
        let mut buf = vec![0u8; hdr.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        hdr.encode(&mut cursor).unwrap();

        // 4-bit field should be 15 (0x0F), no extended byte
        assert_eq!((buf[0] >> 2) & 0x0F, 15);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathInputHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded.num_events, 15);
    }

    #[test]
    fn output_header_reserved_bits_round_trip_as_zero() {
        // The output header has no num_events field — bits 2-5 are reserved
        // and MUST be encoded as zero per MS-RDPBCGR 2.2.9.1.2.
        let hdr = FastPathOutputHeader {
            action: 0,
            flags: 0,
            length: 10,
        };
        let size = hdr.size();
        // No extended byte: 1 (byte0) + 1 (length<0x80) = 2
        assert_eq!(size, 2);

        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        hdr.encode(&mut cursor).unwrap();

        // Reserved 4-bit slot in byte0 must be zero.
        assert_eq!((buf[0] >> 2) & 0x0F, 0);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathOutputHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded.length, 10);
    }

    #[test]
    fn input_header_num_events_zero_roundtrip() {
        let hdr = FastPathInputHeader {
            action: FASTPATH_INPUT_ACTION_FASTPATH,
            num_events: 0,
            flags: 0,
            length: 5,
        };
        let size = hdr.size();
        assert_eq!(size, 3); // 1 + 1 + 1 (extended byte)

        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        hdr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = FastPathInputHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded.num_events, 0);
    }

    #[test]
    fn generic_input_event_empty_input_returns_error() {
        let buf: &[u8] = &[];
        let mut cursor = ReadCursor::new(buf);
        assert!(FastPathInputEvent::decode(&mut cursor).is_err());
    }
}
