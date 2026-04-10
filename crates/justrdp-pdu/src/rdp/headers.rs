#![forbid(unsafe_code)]

//! RDP Share Control and Share Data PDU headers -- MS-RDPBCGR 2.2.8.1

use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

// ── Share Control Header ──

/// Share Control PDU types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ShareControlPduType {
    DemandActivePdu = 0x0001,
    ConfirmActivePdu = 0x0003,
    DeactivateAllPdu = 0x0006,
    Data = 0x0007,
    ServerRedirect = 0x000A,
}

impl ShareControlPduType {
    pub fn from_u16(val: u16) -> DecodeResult<Self> {
        // pduType field: lower 4 bits = pdu type, bits 4-15 = protocol version (always 0x10)
        match val & 0x000F {
            0x0001 => Ok(Self::DemandActivePdu),
            0x0003 => Ok(Self::ConfirmActivePdu),
            0x0006 => Ok(Self::DeactivateAllPdu),
            0x0007 => Ok(Self::Data),
            0x000A => Ok(Self::ServerRedirect),
            _ => Err(DecodeError::unexpected_value(
                "ShareControlPduType",
                "pduType",
                "unknown share control PDU type",
            )),
        }
    }

    /// Encode with protocol version (0x10 in bits 4-15).
    pub fn to_u16(self) -> u16 {
        (self as u16) | 0x0010
    }
}

/// Share Control Header (6 bytes).
///
/// ```text
/// ┌──────────────┬──────────┬───────────┐
/// │ totalLength  │ pduType  │ pduSource │
/// │   2B LE      │  2B LE   │  2B LE    │
/// └──────────────┴──────────┴───────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareControlHeader {
    pub total_length: u16,
    pub pdu_type: ShareControlPduType,
    pub pdu_source: u16,
}

pub const SHARE_CONTROL_HEADER_SIZE: usize = 6;

impl Encode for ShareControlHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.total_length, "ShareControlHeader::totalLength")?;
        dst.write_u16_le(self.pdu_type.to_u16(), "ShareControlHeader::pduType")?;
        dst.write_u16_le(self.pdu_source, "ShareControlHeader::pduSource")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "ShareControlHeader" }
    fn size(&self) -> usize { SHARE_CONTROL_HEADER_SIZE }
}

impl<'de> Decode<'de> for ShareControlHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let total_length = src.read_u16_le("ShareControlHeader::totalLength")?;
        let pdu_type_raw = src.read_u16_le("ShareControlHeader::pduType")?;
        let pdu_type = ShareControlPduType::from_u16(pdu_type_raw)?;
        let pdu_source = src.read_u16_le("ShareControlHeader::pduSource")?;
        Ok(Self { total_length, pdu_type, pdu_source })
    }
}

// ── Share Data Header ──

/// Share Data PDU types (pduType2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShareDataPduType {
    Update = 2,
    Control = 20,
    Pointer = 27,
    Input = 28,
    Synchronize = 31,
    RefreshRect = 33,
    PlaySound = 34,
    SuppressOutput = 35,
    ShutdownRequest = 36,
    ShutdownDenied = 37,
    SaveSessionInfo = 38,
    FontList = 39,
    FontMap = 40,
    SetKeyboardIndicators = 41,
    PersistentKeyList = 43,
    BitmapCacheErrorPdu = 44,
    SetKeyboardImeStatus = 45,
    OffscreenCacheError = 46,
    SetErrorInfo = 47,
    DrawNineGridError = 48,
    DrawGdiPlusError = 49,
    ArcStatusPdu = 50,
    StatusInfoPdu = 54,
    MonitorLayoutPdu = 55,
    FrameAcknowledgePdu = 56,
}

impl ShareDataPduType {
    pub fn from_u8(val: u8) -> DecodeResult<Self> {
        match val {
            2 => Ok(Self::Update),
            20 => Ok(Self::Control),
            27 => Ok(Self::Pointer),
            28 => Ok(Self::Input),
            31 => Ok(Self::Synchronize),
            33 => Ok(Self::RefreshRect),
            34 => Ok(Self::PlaySound),
            35 => Ok(Self::SuppressOutput),
            36 => Ok(Self::ShutdownRequest),
            37 => Ok(Self::ShutdownDenied),
            38 => Ok(Self::SaveSessionInfo),
            39 => Ok(Self::FontList),
            40 => Ok(Self::FontMap),
            41 => Ok(Self::SetKeyboardIndicators),
            43 => Ok(Self::PersistentKeyList),
            44 => Ok(Self::BitmapCacheErrorPdu),
            45 => Ok(Self::SetKeyboardImeStatus),
            46 => Ok(Self::OffscreenCacheError),
            47 => Ok(Self::SetErrorInfo),
            48 => Ok(Self::DrawNineGridError),
            49 => Ok(Self::DrawGdiPlusError),
            50 => Ok(Self::ArcStatusPdu),
            54 => Ok(Self::StatusInfoPdu),
            55 => Ok(Self::MonitorLayoutPdu),
            56 => Ok(Self::FrameAcknowledgePdu),
            _ => Err(DecodeError::unexpected_value(
                "ShareDataPduType",
                "pduType2",
                "unknown share data PDU type",
            )),
        }
    }
}

/// Stream priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamPriority {
    Undefined = 0,
    Low = 1,
    Medium = 2,
    High = 4,
}

/// Share Data Header (18 bytes).
///
/// ```text
/// ┌─────────┬──────┬───────────┬──────┬──────────────────────┬──────────┬────────────────┬──────────────────┐
/// │ shareId │ pad1 │ streamId  │ uLen │ pduType2             │ compType │ compLength     │                  │
/// │  4B LE  │  1B  │   1B      │ 2B LE│  1B                  │   1B     │  2B LE         │                  │
/// └─────────┴──────┴───────────┴──────┴──────────────────────┴──────────┴────────────────┴──────────────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareDataHeader {
    pub share_id: u32,
    pub stream_id: u8,
    pub uncompressed_length: u16,
    pub pdu_type2: ShareDataPduType,
    pub compressed_type: u8,
    pub compressed_length: u16,
}

pub const SHARE_DATA_HEADER_SIZE: usize = 12;

impl Encode for ShareDataHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.share_id, "ShareDataHeader::shareId")?;
        dst.write_u8(0, "ShareDataHeader::pad1")?;
        dst.write_u8(self.stream_id, "ShareDataHeader::streamId")?;
        dst.write_u16_le(self.uncompressed_length, "ShareDataHeader::uncompressedLength")?;
        dst.write_u8(self.pdu_type2 as u8, "ShareDataHeader::pduType2")?;
        dst.write_u8(self.compressed_type, "ShareDataHeader::compressedType")?;
        dst.write_u16_le(self.compressed_length, "ShareDataHeader::compressedLength")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "ShareDataHeader" }
    fn size(&self) -> usize { SHARE_DATA_HEADER_SIZE }
}

impl<'de> Decode<'de> for ShareDataHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let share_id = src.read_u32_le("ShareDataHeader::shareId")?;
        let _pad1 = src.read_u8("ShareDataHeader::pad1")?;
        let stream_id = src.read_u8("ShareDataHeader::streamId")?;
        let uncompressed_length = src.read_u16_le("ShareDataHeader::uncompressedLength")?;
        let pdu_type2 = ShareDataPduType::from_u8(src.read_u8("ShareDataHeader::pduType2")?)?;
        let compressed_type = src.read_u8("ShareDataHeader::compressedType")?;
        let compressed_length = src.read_u16_le("ShareDataHeader::compressedLength")?;
        Ok(Self {
            share_id, stream_id, uncompressed_length,
            pdu_type2, compressed_type, compressed_length,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_control_header_roundtrip() {
        let hdr = ShareControlHeader {
            total_length: 100,
            pdu_type: ShareControlPduType::Data,
            pdu_source: 0x03EC,
        };
        let mut buf = [0u8; SHARE_CONTROL_HEADER_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        hdr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ShareControlHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded.total_length, 100);
        assert_eq!(decoded.pdu_type, ShareControlPduType::Data);
        assert_eq!(decoded.pdu_source, 0x03EC);
    }

    #[test]
    fn share_control_pdu_type_encoding() {
        // pduType field includes protocol version 0x10 in upper bits
        assert_eq!(ShareControlPduType::Data.to_u16(), 0x0017);
        assert_eq!(ShareControlPduType::DemandActivePdu.to_u16(), 0x0011);
    }

    #[test]
    fn share_data_header_roundtrip() {
        let hdr = ShareDataHeader {
            share_id: 0x00040006,
            stream_id: StreamPriority::Low as u8,
            uncompressed_length: 50,
            pdu_type2: ShareDataPduType::Synchronize,
            compressed_type: 0,
            compressed_length: 0,
        };
        let mut buf = [0u8; SHARE_DATA_HEADER_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        hdr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ShareDataHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded.share_id, 0x00040006);
        assert_eq!(decoded.pdu_type2, ShareDataPduType::Synchronize);
    }

    #[test]
    fn share_control_unknown_type() {
        assert!(ShareControlPduType::from_u16(0x00FF).is_err());
    }

    #[test]
    fn share_data_unknown_type() {
        assert!(ShareDataPduType::from_u8(0xFF).is_err());
    }

    #[test]
    fn share_control_all_types_roundtrip() {
        use ShareControlPduType::*;
        for pdu_type in [DemandActivePdu, ConfirmActivePdu, DeactivateAllPdu, Data, ServerRedirect] {
            let hdr = ShareControlHeader { total_length: 6, pdu_type, pdu_source: 0x03EC };
            let mut buf = [0u8; SHARE_CONTROL_HEADER_SIZE];
            let mut cursor = WriteCursor::new(&mut buf);
            hdr.encode(&mut cursor).unwrap();
            let mut cursor = ReadCursor::new(&buf);
            let decoded = ShareControlHeader::decode(&mut cursor).unwrap();
            assert_eq!(decoded.pdu_type, pdu_type, "failed for {:?}", pdu_type);
        }
    }
}

// ── Slow-Path Update PDU (MS-RDPBCGR 2.2.9.1.1.3) ──

/// Slow-path update type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SlowPathUpdateType {
    Orders = 0x0000,
    Bitmap = 0x0001,
    Palette = 0x0002,
    Synchronize = 0x0003,
}

impl SlowPathUpdateType {
    pub fn from_u16(val: u16) -> DecodeResult<Self> {
        match val {
            0 => Ok(Self::Orders),
            1 => Ok(Self::Bitmap),
            2 => Ok(Self::Palette),
            3 => Ok(Self::Synchronize),
            _ => Err(DecodeError::unexpected_value("SlowPathUpdateType", "type", "unknown")),
        }
    }
}

/// Slow-Path Graphics Update PDU (pduType2 = Update).
///
/// MS-RDPBCGR 2.2.9.1.1.3
///
/// Decode-only: this is a server-to-client update; clients do not send this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowPathUpdatePdu {
    pub update_type: SlowPathUpdateType,
    /// Raw update data (type-specific).
    pub data: Vec<u8>,
}

impl<'de> Decode<'de> for SlowPathUpdatePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let update_type = SlowPathUpdateType::from_u16(src.read_u16_le("UpdatePdu::type")?)?;
        let remaining = src.remaining();
        let data = src.read_slice(remaining, "UpdatePdu::data")?.to_vec();
        Ok(Self { update_type, data })
    }
}

// ── Slow-Path Pointer Update PDU (MS-RDPBCGR 2.2.9.1.1.4) ──

/// Slow-path pointer update type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SlowPathPointerUpdateType {
    Position = 0x0003,
    System = 0x0001,
    Color = 0x0006,
    Cached = 0x0007,
    New = 0x0008,
    Large = 0x0009,
}

impl SlowPathPointerUpdateType {
    pub fn from_u16(val: u16) -> DecodeResult<Self> {
        match val {
            0x0003 => Ok(Self::Position),
            0x0001 => Ok(Self::System),
            0x0006 => Ok(Self::Color),
            0x0007 => Ok(Self::Cached),
            0x0008 => Ok(Self::New),
            0x0009 => Ok(Self::Large),
            _ => Err(DecodeError::unexpected_value("PointerUpdateType", "type", "unknown")),
        }
    }
}

/// Slow-Path Pointer Update PDU (pduType2 = Pointer).
///
/// MS-RDPBCGR 2.2.9.1.1.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowPathPointerUpdatePdu {
    pub update_type: SlowPathPointerUpdateType,
    /// Raw pointer data (type-specific).
    pub data: Vec<u8>,
}

impl<'de> Decode<'de> for SlowPathPointerUpdatePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let update_type = SlowPathPointerUpdateType::from_u16(src.read_u16_le("PointerPdu::type")?)?;
        let _pad2 = src.read_u16_le("PointerPdu::pad2")?;
        let remaining = src.remaining();
        let data = src.read_slice(remaining, "PointerPdu::data")?.to_vec();
        Ok(Self { update_type, data })
    }
}

// ── Set Keyboard Indicators PDU (MS-RDPBCGR 2.2.8.2.1.1) ──

/// Set Keyboard Indicators PDU (pduType2 = SetKeyboardIndicators).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetKeyboardIndicatorsPdu {
    /// LED flags: bit 0 = Scroll Lock, bit 1 = Num Lock, bit 2 = Caps Lock.
    pub led_flags: u16,
}

impl<'de> Decode<'de> for SetKeyboardIndicatorsPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let _unit_id = src.read_u16_le("KbdIndicators::unitId")?;
        let led_flags = src.read_u16_le("KbdIndicators::ledFlags")?;
        Ok(Self { led_flags })
    }
}

// ── Set Keyboard IME Status PDU (MS-RDPBCGR 2.2.8.2.2.1) ──

/// Set Keyboard IME Status PDU (pduType2 = SetKeyboardImeStatus).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetKeyboardImeStatusPdu {
    /// IME state (MS-RDPBCGR 2.2.8.2.2.1: DWORD, non-zero = open).
    pub ime_state: u32,
    /// IME conversion mode bitfield (DWORD).
    pub ime_conv_mode: u32,
}

impl<'de> Decode<'de> for SetKeyboardImeStatusPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let _unit_id = src.read_u16_le("KbdImeStatus::unitId")?;
        // MS-RDPBCGR 2.2.8.2.2.1: ImeState is a 4-byte DWORD.
        let ime_state = src.read_u32_le("KbdImeStatus::imeState")?;
        let ime_conv_mode = src.read_u32_le("KbdImeStatus::imeConvMode")?;
        Ok(Self { ime_state, ime_conv_mode })
    }
}
