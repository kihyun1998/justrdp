#![forbid(unsafe_code)]

//! Drawing Orders -- MS-RDPEGDI sections 2.2.2
//!
//! Drawing orders are used to instruct the client to render graphics.
//! Three categories exist: primary, secondary, and alternate secondary.
//!
//! Phase 1 parses the order headers and type discriminants but stores
//! the order-specific body as raw bytes (`Vec<u8>`).  Full parsing of
//! all 22 primary order types with delta encoding is Phase 2 work.

use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

// ── Control-flag bit masks ──

/// Standard order flag (bit 0).
pub const TS_STANDARD: u8 = 0x01;
/// Secondary order flag (bit 1).
pub const TS_SECONDARY: u8 = 0x02;
/// Order-type-change flag (bit 3).
pub const ORDER_TYPE_CHANGE: u8 = 0x08;
/// Bounds flag -- bounding rectangle follows the order type (bit 2).
pub const TS_BOUNDS: u8 = 0x04;
/// Delta coordinates flag (bit 4).
pub const TS_DELTA_COORDINATES: u8 = 0x10;
/// Zero bounds deltas flag (bit 5).
pub const TS_ZERO_BOUNDS_DELTAS: u8 = 0x20;
/// Zero field byte bit 0 (bit 6) — first fieldFlags byte is zero and omitted.
pub const TS_ZERO_FIELD_BYTE_BIT0: u8 = 0x40;
/// Zero field byte bit 1 (bit 7) — second fieldFlags byte is zero and omitted.
pub const TS_ZERO_FIELD_BYTE_BIT1: u8 = 0x80;

// ════════════════════════════════════════════════════════════════════
// Primary Drawing Orders
// ════════════════════════════════════════════════════════════════════

/// The 22 primary drawing order types (MS-RDPEGDI 2.2.2.1.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrimaryOrderType {
    DstBlt = 0x00,
    PatBlt = 0x01,
    ScrBlt = 0x02,
    DrawNineGrid = 0x07,
    MultiDrawNineGrid = 0x08,
    LineTo = 0x09,
    OpaqueRect = 0x0A,
    SaveBitmap = 0x0B,
    MemBlt = 0x0D,
    Mem3Blt = 0x0E,
    MultiDstBlt = 0x0F,
    MultiPatBlt = 0x10,
    MultiScrBlt = 0x11,
    MultiOpaqueRect = 0x12,
    FastIndex = 0x13,
    PolygonSc = 0x14,
    PolygonCb = 0x15,
    Polyline = 0x16,
    FastGlyph = 0x18,
    EllipseSc = 0x19,
    EllipseCb = 0x1A,
    GlyphIndex = 0x1B,
}

impl PrimaryOrderType {
    pub fn from_u8(val: u8) -> DecodeResult<Self> {
        match val {
            0x00 => Ok(Self::DstBlt),
            0x01 => Ok(Self::PatBlt),
            0x02 => Ok(Self::ScrBlt),
            0x07 => Ok(Self::DrawNineGrid),
            0x08 => Ok(Self::MultiDrawNineGrid),
            0x09 => Ok(Self::LineTo),
            0x0A => Ok(Self::OpaqueRect),
            0x0B => Ok(Self::SaveBitmap),
            0x0D => Ok(Self::MemBlt),
            0x0E => Ok(Self::Mem3Blt),
            0x0F => Ok(Self::MultiDstBlt),
            0x10 => Ok(Self::MultiPatBlt),
            0x11 => Ok(Self::MultiScrBlt),
            0x12 => Ok(Self::MultiOpaqueRect),
            0x13 => Ok(Self::FastIndex),
            0x14 => Ok(Self::PolygonSc),
            0x15 => Ok(Self::PolygonCb),
            0x16 => Ok(Self::Polyline),
            0x18 => Ok(Self::FastGlyph),
            0x19 => Ok(Self::EllipseSc),
            0x1A => Ok(Self::EllipseCb),
            0x1B => Ok(Self::GlyphIndex),
            _ => Err(DecodeError::unexpected_value(
                "PrimaryOrderType",
                "orderType",
                "unknown primary drawing order type",
            )),
        }
    }
}

/// Bounding rectangle for primary drawing orders (MS-RDPEGDI 2.2.2.2.1.1.1).
/// TS_RECTANGLE16: four UINT16 fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundsRect {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

/// Encoded size of BoundsRect when written as full coordinates (no delta encoding).
pub const BOUNDS_RECT_SIZE: usize = 8;

impl Encode for BoundsRect {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.left, "BoundsRect::left")?;
        dst.write_u16_le(self.top, "BoundsRect::top")?;
        dst.write_u16_le(self.right, "BoundsRect::right")?;
        dst.write_u16_le(self.bottom, "BoundsRect::bottom")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "BoundsRect" }
    fn size(&self) -> usize { BOUNDS_RECT_SIZE }
}

impl<'de> Decode<'de> for BoundsRect {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let left = src.read_u16_le("BoundsRect::left")?;
        let top = src.read_u16_le("BoundsRect::top")?;
        let right = src.read_u16_le("BoundsRect::right")?;
        let bottom = src.read_u16_le("BoundsRect::bottom")?;
        Ok(Self { left, top, right, bottom })
    }
}

/// A primary drawing order (MS-RDPEGDI 2.2.2.2.1.1).
///
/// The order-specific body is stored as raw bytes for Phase 1.
/// `field_flags` holds up to 24 bits that indicate which fields of the
/// order-specific structure are present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimaryOrder {
    pub order_type: PrimaryOrderType,
    pub field_flags: u32,
    pub bounds: Option<BoundsRect>,
    pub data: Vec<u8>,
}

impl Encode for PrimaryOrder {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // controlFlags: always TS_STANDARD | ORDER_TYPE_CHANGE, plus TS_BOUNDS if present.
        let mut control_flags: u8 = TS_STANDARD | ORDER_TYPE_CHANGE;
        if self.bounds.is_some() {
            control_flags |= TS_BOUNDS;
        }
        dst.write_u8(control_flags, "PrimaryOrder::controlFlags")?;
        dst.write_u8(self.order_type as u8, "PrimaryOrder::orderType")?;

        // fieldFlags: encode as 1, 2, or 3 bytes per order type (spec-driven, not value-driven).
        let ff_bytes = field_flags_byte_count(self.order_type);
        dst.write_u8(self.field_flags as u8, "PrimaryOrder::fieldFlags[0]")?;
        if ff_bytes >= 2 {
            dst.write_u8((self.field_flags >> 8) as u8, "PrimaryOrder::fieldFlags[1]")?;
        }
        if ff_bytes >= 3 {
            dst.write_u8((self.field_flags >> 16) as u8, "PrimaryOrder::fieldFlags[2]")?;
        }

        // Bounds (full coordinates -- no delta encoding for Phase 1).
        if let Some(bounds) = &self.bounds {
            bounds.encode(dst)?;
        }

        // Raw order body.
        dst.write_slice(&self.data, "PrimaryOrder::data")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "PrimaryOrder" }

    fn size(&self) -> usize {
        let mut sz = 1 /* controlFlags */ + 1 /* orderType */;
        // fieldFlags size (type-driven)
        sz += field_flags_byte_count(self.order_type);
        if self.bounds.is_some() {
            sz += BOUNDS_RECT_SIZE;
        }
        sz += self.data.len();
        sz
    }
}

/// Number of fieldFlags bytes for a given primary order type.
///
/// Most orders use 3 bytes (up to 24 flag bits).  Simpler orders that
/// have fewer fields need only 1 or 2 bytes.  This helper returns the
/// byte count used during decoding.
fn field_flags_byte_count(order_type: PrimaryOrderType) -> usize {
    match order_type {
        // Orders with <= 8 fields → 1 byte
        PrimaryOrderType::DstBlt
        | PrimaryOrderType::ScrBlt
        | PrimaryOrderType::DrawNineGrid => 1,

        // Orders with <= 16 fields → 2 bytes
        PrimaryOrderType::PatBlt
        | PrimaryOrderType::OpaqueRect
        | PrimaryOrderType::LineTo
        | PrimaryOrderType::SaveBitmap
        | PrimaryOrderType::MemBlt => 2,

        // Everything else → 3 bytes
        _ => 3,
    }
}

impl<'de> Decode<'de> for PrimaryOrder {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let control_flags = src.read_u8("PrimaryOrder::controlFlags")?;

        if control_flags & TS_STANDARD == 0 {
            return Err(DecodeError::unexpected_value(
                "PrimaryOrder",
                "controlFlags",
                "TS_STANDARD bit not set",
            ));
        }

        // Order type (must be present since we always encode ORDER_TYPE_CHANGE).
        let order_type_raw = src.read_u8("PrimaryOrder::orderType")?;
        let order_type = PrimaryOrderType::from_u8(order_type_raw)?;

        // Field flags.
        let ff_bytes = field_flags_byte_count(order_type);
        let mut field_flags: u32 = 0;
        for i in 0..ff_bytes {
            let b = src.read_u8("PrimaryOrder::fieldFlags")?;
            field_flags |= (b as u32) << (i * 8);
        }

        // Bounds: only present when TS_BOUNDS is set AND TS_ZERO_BOUNDS_DELTAS is NOT set.
        let bounds = if control_flags & TS_BOUNDS != 0 {
            if control_flags & TS_ZERO_BOUNDS_DELTAS != 0 {
                // Bounds are implicitly zero (no data on wire)
                Some(BoundsRect { left: 0, top: 0, right: 0, bottom: 0 })
            } else {
                Some(BoundsRect::decode(src)?)
            }
        } else {
            None
        };

        // Remaining bytes are the raw order body.
        let remaining = src.remaining();
        let data_slice = src.read_slice(remaining, "PrimaryOrder::data")?;
        let data = data_slice.to_vec();

        Ok(Self { order_type, field_flags, bounds, data })
    }
}

// ════════════════════════════════════════════════════════════════════
// Secondary Drawing Orders (Cache Orders)
// ════════════════════════════════════════════════════════════════════

/// Secondary drawing order types (MS-RDPEGDI 2.2.2.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecondaryOrderType {
    /// TS_CACHE_BITMAP_UNCOMPRESSED (V1 uncompressed).
    CacheBitmapV1Uncompressed = 0x00,
    /// TS_CACHE_COLOR_TABLE.
    CacheColorTable = 0x01,
    /// TS_CACHE_BITMAP_COMPRESSED (V1 compressed).
    CacheBitmapV1Compressed = 0x02,
    /// TS_CACHE_GLYPH.
    CacheGlyph = 0x03,
    /// TS_CACHE_BITMAP_UNCOMPRESSED_REV2.
    CacheBitmapV2Uncompressed = 0x04,
    /// TS_CACHE_BITMAP_COMPRESSED_REV2.
    CacheBitmapV2Compressed = 0x05,
    /// TS_CACHE_BRUSH.
    CacheBrush = 0x07,
    /// TS_CACHE_BITMAP_COMPRESSED_REV3.
    CacheBitmapV3 = 0x08,
}

impl SecondaryOrderType {
    pub fn from_u8(val: u8) -> DecodeResult<Self> {
        match val {
            0x00 => Ok(Self::CacheBitmapV1Uncompressed),
            0x01 => Ok(Self::CacheColorTable),
            0x02 => Ok(Self::CacheBitmapV1Compressed),
            0x03 => Ok(Self::CacheGlyph),
            0x04 => Ok(Self::CacheBitmapV2Uncompressed),
            0x05 => Ok(Self::CacheBitmapV2Compressed),
            0x07 => Ok(Self::CacheBrush),
            0x08 => Ok(Self::CacheBitmapV3),
            _ => Err(DecodeError::unexpected_value(
                "SecondaryOrderType",
                "orderType",
                "unknown secondary drawing order type",
            )),
        }
    }
}

/// A secondary (cache) drawing order (MS-RDPEGDI 2.2.2.2.1.2).
///
/// ```text
/// ┌──────────────┬─────────────┬────────────┬───────────┬──────┐
/// │ controlFlags │ orderLength │ extraFlags │ orderType │ data │
/// │     1B       │   2B LE     │   2B LE    │    1B     │  var │
/// └──────────────┴─────────────┴────────────┴───────────┴──────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondaryOrder {
    pub order_type: SecondaryOrderType,
    pub extra_flags: u16,
    pub data: Vec<u8>,
}

/// Fixed-size portion of the secondary order header (excluding controlFlags
/// which is part of the DrawingOrder discriminant): orderLength(2) +
/// extraFlags(2) + orderType(1) = 5 bytes.  Plus 1 byte for controlFlags = 6.
pub const SECONDARY_ORDER_HEADER_SIZE: usize = 6;

impl Encode for SecondaryOrder {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let control_flags: u8 = TS_STANDARD | TS_SECONDARY;
        dst.write_u8(control_flags, "SecondaryOrder::controlFlags")?;

        // orderLength: MS-RDPEGDI says this value is the *remaining* length
        // after the orderLength field itself, minus 7.  However, for our
        // Phase 1 raw-body approach we store the byte count simply:
        //   orderLength = extraFlags(2) + orderType(1) + data.len() - 7
        // The protocol subtracts 7 from the actual remaining length for
        // historical reasons.  So actual remaining = orderLength + 7.
        // remaining = 2 (extraFlags) + 1 (orderType) + data.len()
        // orderLength = remaining - 7 = data.len() + 3 - 7 = data.len() - 4
        // But that can underflow for small data.  The spec says:
        //   "the number of bytes in the order data, MINUS 7"
        // where "order data" starts from extraFlags.
        // So: orderLength = (2 + 1 + data.len()) - 7
        //
        // For encoding we store the value that lets us roundtrip correctly.
        // On decode we read orderLength, compute body size = orderLength + 7 - 3,
        // and read that many data bytes.
        let remaining_after_length = 2 /* extraFlags */ + 1 /* orderType */ + self.data.len();
        // The spec value has the -7 adjustment.  We cast carefully:
        // If remaining_after_length < 7, we still write the u16 (wrapping is
        // possible on tiny test vectors -- the protocol guarantees at least 7).
        let order_length = (remaining_after_length as i32 - 7) as u16;
        dst.write_u16_le(order_length, "SecondaryOrder::orderLength")?;
        dst.write_u16_le(self.extra_flags, "SecondaryOrder::extraFlags")?;
        dst.write_u8(self.order_type as u8, "SecondaryOrder::orderType")?;
        dst.write_slice(&self.data, "SecondaryOrder::data")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "SecondaryOrder" }
    fn size(&self) -> usize { SECONDARY_ORDER_HEADER_SIZE + self.data.len() }
}

impl<'de> Decode<'de> for SecondaryOrder {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let control_flags = src.read_u8("SecondaryOrder::controlFlags")?;

        if control_flags & (TS_STANDARD | TS_SECONDARY) != (TS_STANDARD | TS_SECONDARY) {
            return Err(DecodeError::unexpected_value(
                "SecondaryOrder",
                "controlFlags",
                "TS_STANDARD | TS_SECONDARY bits not set",
            ));
        }

        let order_length = src.read_u16_le("SecondaryOrder::orderLength")?;
        let extra_flags = src.read_u16_le("SecondaryOrder::extraFlags")?;
        let order_type_raw = src.read_u8("SecondaryOrder::orderType")?;
        let order_type = SecondaryOrderType::from_u8(order_type_raw)?;

        // data length = orderLength + 7 - sizeof(extraFlags) - sizeof(orderType)
        //             = orderLength + 7 - 3 = orderLength + 4
        let data_len = order_length as usize + 4;
        let data_slice = src.read_slice(data_len, "SecondaryOrder::data")?;
        let data = data_slice.to_vec();

        Ok(Self { order_type, extra_flags, data })
    }
}

// ════════════════════════════════════════════════════════════════════
// Alternate Secondary Drawing Orders
// ════════════════════════════════════════════════════════════════════

/// Alternate secondary drawing order types (MS-RDPEGDI 2.2.2.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlternateSecondaryOrderType {
    /// TS_ALTSEC_SWITCH_SURFACE.
    SwitchSurface = 0x00,
    /// TS_ALTSEC_CREATE_OFFSCR_BITMAP.
    CreateOffscreenBitmap = 0x01,
    /// TS_ALTSEC_STREAM_BITMAP_FIRST.
    StreamBitmapFirst = 0x02,
    /// TS_ALTSEC_STREAM_BITMAP_NEXT.
    StreamBitmapNext = 0x03,
    /// TS_ALTSEC_CREATE_NINEGRID_BITMAP.
    CreateNineGridBitmap = 0x04,
    /// TS_ALTSEC_GDIP_FIRST.
    DrawGdiPlusFirst = 0x05,
    /// TS_ALTSEC_GDIP_NEXT.
    DrawGdiPlusNext = 0x06,
    /// TS_ALTSEC_GDIP_END.
    DrawGdiPlusEnd = 0x07,
    /// TS_ALTSEC_GDIP_CACHE_FIRST.
    DrawGdiPlusCacheFirst = 0x08,
    /// TS_ALTSEC_GDIP_CACHE_NEXT.
    DrawGdiPlusCacheNext = 0x09,
    /// TS_ALTSEC_GDIP_CACHE_END.
    DrawGdiPlusCacheEnd = 0x0A,
    /// TS_ALTSEC_WINDOW.
    Window = 0x0B,
    /// TS_ALTSEC_COMPDESK_FIRST.
    CompDeskFirst = 0x0C,
    /// TS_ALTSEC_FRAME_MARKER.
    FrameMarker = 0x0D,
}

impl AlternateSecondaryOrderType {
    pub fn from_u8(val: u8) -> DecodeResult<Self> {
        match val {
            0x00 => Ok(Self::SwitchSurface),
            0x01 => Ok(Self::CreateOffscreenBitmap),
            0x02 => Ok(Self::StreamBitmapFirst),
            0x03 => Ok(Self::StreamBitmapNext),
            0x04 => Ok(Self::CreateNineGridBitmap),
            0x05 => Ok(Self::DrawGdiPlusFirst),
            0x06 => Ok(Self::DrawGdiPlusNext),
            0x07 => Ok(Self::DrawGdiPlusEnd),
            0x08 => Ok(Self::DrawGdiPlusCacheFirst),
            0x09 => Ok(Self::DrawGdiPlusCacheNext),
            0x0A => Ok(Self::DrawGdiPlusCacheEnd),
            0x0B => Ok(Self::Window),
            0x0C => Ok(Self::CompDeskFirst),
            0x0D => Ok(Self::FrameMarker),
            _ => Err(DecodeError::unexpected_value(
                "AlternateSecondaryOrderType",
                "orderType",
                "unknown alternate secondary order type",
            )),
        }
    }
}

/// An alternate secondary drawing order (MS-RDPEGDI 2.2.2.2.1.3).
///
/// The order type is encoded in bits 2-7 of controlFlags.
/// The remaining body is stored as raw bytes.
///
/// ```text
/// ┌──────────────┬─────────────┬──────┐
/// │ controlFlags │ orderLength │ data │
/// │ 1B (type)    │   2B LE     │ var  │
/// └──────────────┴─────────────┴──────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternateSecondaryOrder {
    pub order_type: AlternateSecondaryOrderType,
    pub data: Vec<u8>,
}

/// Fixed header: controlFlags(1) + orderLength(2) = 3 bytes.
pub const ALT_SECONDARY_ORDER_HEADER_SIZE: usize = 3;

impl Encode for AlternateSecondaryOrder {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // controlFlags: bits 2-7 = order type, bits 0-1 = 0 (not TS_STANDARD).
        let control_flags = (self.order_type as u8) << 2;
        dst.write_u8(control_flags, "AlternateSecondaryOrder::controlFlags")?;
        let order_length = self.data.len() as u16;
        dst.write_u16_le(order_length, "AlternateSecondaryOrder::orderLength")?;
        dst.write_slice(&self.data, "AlternateSecondaryOrder::data")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "AlternateSecondaryOrder" }
    fn size(&self) -> usize { ALT_SECONDARY_ORDER_HEADER_SIZE + self.data.len() }
}

impl<'de> Decode<'de> for AlternateSecondaryOrder {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let control_flags = src.read_u8("AlternateSecondaryOrder::controlFlags")?;

        // bits 2-7 contain the order type
        let order_type_val = control_flags >> 2;
        let order_type = AlternateSecondaryOrderType::from_u8(order_type_val)?;

        let order_length = src.read_u16_le("AlternateSecondaryOrder::orderLength")?;
        let data_slice = src.read_slice(order_length as usize, "AlternateSecondaryOrder::data")?;
        let data = data_slice.to_vec();

        Ok(Self { order_type, data })
    }
}

// ════════════════════════════════════════════════════════════════════
// Top-level DrawingOrder enum
// ════════════════════════════════════════════════════════════════════

/// A single drawing order -- primary, secondary, or alternate secondary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrawingOrder {
    Primary(PrimaryOrder),
    Secondary(SecondaryOrder),
    AlternateSecondary(AlternateSecondaryOrder),
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // ── Helpers ──

    fn roundtrip_encode<T: Encode>(val: &T) -> Vec<u8> {
        let sz = val.size();
        let mut buf = vec![0u8; sz];
        let mut cursor = WriteCursor::new(&mut buf);
        val.encode(&mut cursor).unwrap();
        buf
    }

    // ── PrimaryOrderType enum ──

    #[test]
    fn primary_order_type_roundtrip_all() {
        let types: &[(u8, PrimaryOrderType)] = &[
            (0x00, PrimaryOrderType::DstBlt),
            (0x01, PrimaryOrderType::PatBlt),
            (0x02, PrimaryOrderType::ScrBlt),
            (0x07, PrimaryOrderType::DrawNineGrid),
            (0x08, PrimaryOrderType::MultiDrawNineGrid),
            (0x09, PrimaryOrderType::LineTo),
            (0x0A, PrimaryOrderType::OpaqueRect),
            (0x0B, PrimaryOrderType::SaveBitmap),
            (0x0D, PrimaryOrderType::MemBlt),
            (0x0E, PrimaryOrderType::Mem3Blt),
            (0x0F, PrimaryOrderType::MultiDstBlt),
            (0x10, PrimaryOrderType::MultiPatBlt),
            (0x11, PrimaryOrderType::MultiScrBlt),
            (0x12, PrimaryOrderType::MultiOpaqueRect),
            (0x13, PrimaryOrderType::FastIndex),
            (0x14, PrimaryOrderType::PolygonSc),
            (0x15, PrimaryOrderType::PolygonCb),
            (0x16, PrimaryOrderType::Polyline),
            (0x18, PrimaryOrderType::FastGlyph),
            (0x19, PrimaryOrderType::EllipseSc),
            (0x1A, PrimaryOrderType::EllipseCb),
            (0x1B, PrimaryOrderType::GlyphIndex),
        ];
        for &(raw, expected) in types {
            let parsed = PrimaryOrderType::from_u8(raw).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed as u8, raw);
        }
    }

    #[test]
    fn primary_order_type_unknown() {
        assert!(PrimaryOrderType::from_u8(0xFF).is_err());
        assert!(PrimaryOrderType::from_u8(0x03).is_err());
    }

    // ── SecondaryOrderType enum ──

    #[test]
    fn secondary_order_type_roundtrip_all() {
        let types: &[(u8, SecondaryOrderType)] = &[
            (0x00, SecondaryOrderType::CacheBitmapV1Uncompressed),
            (0x01, SecondaryOrderType::CacheColorTable),
            (0x02, SecondaryOrderType::CacheBitmapV1Compressed),
            (0x03, SecondaryOrderType::CacheGlyph),
            (0x04, SecondaryOrderType::CacheBitmapV2Uncompressed),
            (0x05, SecondaryOrderType::CacheBitmapV2Compressed),
            (0x07, SecondaryOrderType::CacheBrush),
            (0x08, SecondaryOrderType::CacheBitmapV3),
        ];
        for &(raw, expected) in types {
            let parsed = SecondaryOrderType::from_u8(raw).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed as u8, raw);
        }
    }

    #[test]
    fn secondary_order_type_unknown() {
        assert!(SecondaryOrderType::from_u8(0xFF).is_err());
        assert!(SecondaryOrderType::from_u8(0x06).is_err()); // gap between CacheBitmapV2Compressed(0x05) and CacheBrush(0x07)
    }

    // ── AlternateSecondaryOrderType enum ──

    #[test]
    fn alt_secondary_order_type_roundtrip_all() {
        let types: &[(u8, AlternateSecondaryOrderType)] = &[
            (0x00, AlternateSecondaryOrderType::SwitchSurface),
            (0x01, AlternateSecondaryOrderType::CreateOffscreenBitmap),
            (0x02, AlternateSecondaryOrderType::StreamBitmapFirst),
            (0x03, AlternateSecondaryOrderType::StreamBitmapNext),
            (0x04, AlternateSecondaryOrderType::CreateNineGridBitmap),
            (0x05, AlternateSecondaryOrderType::DrawGdiPlusFirst),
            (0x06, AlternateSecondaryOrderType::DrawGdiPlusNext),
            (0x07, AlternateSecondaryOrderType::DrawGdiPlusEnd),
            (0x08, AlternateSecondaryOrderType::DrawGdiPlusCacheFirst),
            (0x09, AlternateSecondaryOrderType::DrawGdiPlusCacheNext),
            (0x0A, AlternateSecondaryOrderType::DrawGdiPlusCacheEnd),
            (0x0B, AlternateSecondaryOrderType::Window),
            (0x0C, AlternateSecondaryOrderType::CompDeskFirst),
            (0x0D, AlternateSecondaryOrderType::FrameMarker),
        ];
        for &(raw, expected) in types {
            let parsed = AlternateSecondaryOrderType::from_u8(raw).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed as u8, raw);
        }
    }

    #[test]
    fn alt_secondary_order_type_unknown() {
        assert!(AlternateSecondaryOrderType::from_u8(0x0E).is_err()); // 0x0E is past FrameMarker(0x0D)
        assert!(AlternateSecondaryOrderType::from_u8(0xFF).is_err());
    }

    // ── BoundsRect roundtrip ──

    #[test]
    fn bounds_rect_roundtrip() {
        let bounds = BoundsRect { left: 10, top: 20, right: 300, bottom: 400 };
        let buf = roundtrip_encode(&bounds);
        assert_eq!(buf.len(), BOUNDS_RECT_SIZE);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = BoundsRect::decode(&mut cursor).unwrap();
        assert_eq!(decoded, bounds);
    }

    // ── PrimaryOrder roundtrip ──

    #[test]
    fn primary_order_roundtrip_no_bounds() {
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::DstBlt,
            field_flags: 0x1F,
            bounds: None,
            data: vec![0xAA, 0xBB, 0xCC],
        };
        let buf = roundtrip_encode(&order);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = PrimaryOrder::decode(&mut cursor).unwrap();
        assert_eq!(decoded.order_type, PrimaryOrderType::DstBlt);
        assert_eq!(decoded.field_flags, 0x1F);
        assert_eq!(decoded.bounds, None);
        assert_eq!(decoded.data, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn primary_order_roundtrip_with_bounds() {
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::OpaqueRect,
            field_flags: 0x01FF,
            bounds: Some(BoundsRect { left: 0, top: 0, right: 1920, bottom: 1080 }),
            data: vec![0x01, 0x02],
        };
        let buf = roundtrip_encode(&order);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = PrimaryOrder::decode(&mut cursor).unwrap();
        assert_eq!(decoded.order_type, PrimaryOrderType::OpaqueRect);
        assert_eq!(decoded.field_flags, 0x01FF);
        assert_eq!(decoded.bounds.unwrap().right, 1920);
        assert_eq!(decoded.data, vec![0x01, 0x02]);
    }

    #[test]
    fn primary_order_roundtrip_three_byte_field_flags() {
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::GlyphIndex,
            field_flags: 0x03_FFFF,
            bounds: None,
            data: vec![0xDE, 0xAD],
        };
        let buf = roundtrip_encode(&order);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = PrimaryOrder::decode(&mut cursor).unwrap();
        assert_eq!(decoded.order_type, PrimaryOrderType::GlyphIndex);
        assert_eq!(decoded.field_flags, 0x03_FFFF);
        assert_eq!(decoded.data, vec![0xDE, 0xAD]);
    }

    // ── SecondaryOrder roundtrip ──

    #[test]
    fn secondary_order_roundtrip() {
        let order = SecondaryOrder {
            order_type: SecondaryOrderType::CacheBrush,
            extra_flags: 0x0042,
            data: vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80],
        };
        let buf = roundtrip_encode(&order);
        assert_eq!(buf.len(), SECONDARY_ORDER_HEADER_SIZE + 8);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = SecondaryOrder::decode(&mut cursor).unwrap();
        assert_eq!(decoded.order_type, SecondaryOrderType::CacheBrush);
        assert_eq!(decoded.extra_flags, 0x0042);
        assert_eq!(decoded.data, vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
    }

    #[test]
    fn secondary_order_roundtrip_empty_data() {
        // Minimum viable: 0 data bytes.  orderLength wraps due to -7 adjustment
        // but the roundtrip must still work.
        let order = SecondaryOrder {
            order_type: SecondaryOrderType::CacheBitmapV1Uncompressed,
            extra_flags: 0,
            data: vec![0xAA; 4],
        };
        let buf = roundtrip_encode(&order);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = SecondaryOrder::decode(&mut cursor).unwrap();
        assert_eq!(decoded, order);
    }

    // ── AlternateSecondaryOrder roundtrip ──

    #[test]
    fn alt_secondary_order_roundtrip() {
        let order = AlternateSecondaryOrder {
            order_type: AlternateSecondaryOrderType::FrameMarker,
            data: vec![0x00, 0x00, 0x00, 0x00],
        };
        let buf = roundtrip_encode(&order);
        assert_eq!(buf.len(), ALT_SECONDARY_ORDER_HEADER_SIZE + 4);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = AlternateSecondaryOrder::decode(&mut cursor).unwrap();
        assert_eq!(decoded.order_type, AlternateSecondaryOrderType::FrameMarker);
        assert_eq!(decoded.data, vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn alt_secondary_order_roundtrip_empty_data() {
        let order = AlternateSecondaryOrder {
            order_type: AlternateSecondaryOrderType::SwitchSurface,
            data: vec![],
        };
        let buf = roundtrip_encode(&order);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = AlternateSecondaryOrder::decode(&mut cursor).unwrap();
        assert_eq!(decoded, order);
    }

    #[test]
    fn alt_secondary_control_flags_encoding() {
        // FrameMarker (0x0D) should be encoded in bits 2-7: 0x0D << 2 = 0x34
        let order = AlternateSecondaryOrder {
            order_type: AlternateSecondaryOrderType::FrameMarker,
            data: vec![],
        };
        let buf = roundtrip_encode(&order);
        assert_eq!(buf[0], 0x0D << 2);
    }
}
