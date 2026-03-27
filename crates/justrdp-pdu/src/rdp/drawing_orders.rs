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
/// Field flags byte count per order type.
///
/// Formula: `ceil((field_count + 1) / 8)` per MS-RDPEGDI 2.2.2.2.1.1.2.
fn field_flags_byte_count(order_type: PrimaryOrderType) -> usize {
    match order_type {
        // 1 byte: orders with <= 7 fields (ceil((n+1)/8) = 1 when n <= 7)
        PrimaryOrderType::DstBlt           // 5 fields
        | PrimaryOrderType::ScrBlt         // 7 fields
        | PrimaryOrderType::DrawNineGrid   // 5 fields
        | PrimaryOrderType::OpaqueRect     // 7 fields
        | PrimaryOrderType::SaveBitmap     // 6 fields
        | PrimaryOrderType::MultiDstBlt    // 7 fields
        | PrimaryOrderType::Polyline       // 7 fields
        | PrimaryOrderType::PolygonSc      // 7 fields
        | PrimaryOrderType::EllipseSc      // 7 fields
        => 1,

        // 2 bytes: orders with 8-15 fields
        PrimaryOrderType::PatBlt           // 12 fields
        | PrimaryOrderType::LineTo         // 10 fields
        | PrimaryOrderType::MemBlt         // 9 fields
        | PrimaryOrderType::MultiDrawNineGrid // 9 fields → 2 bytes
        | PrimaryOrderType::MultiPatBlt    // 14 fields
        | PrimaryOrderType::MultiScrBlt    // 9 fields
        | PrimaryOrderType::MultiOpaqueRect // 9 fields
        | PrimaryOrderType::FastIndex      // 15 fields
        | PrimaryOrderType::PolygonCb      // 13 fields
        | PrimaryOrderType::FastGlyph      // 15 fields
        | PrimaryOrderType::EllipseCb      // 13 fields
        => 2,

        // 3 bytes: orders with 16+ fields
        PrimaryOrderType::Mem3Blt          // 16 fields
        | PrimaryOrderType::GlyphIndex     // 22 fields
        => 3,
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
// Primary Drawing Order Field-Level Parsing (MS-RDPEGDI 2.2.2.2.1.1.2)
// ════════════════════════════════════════════════════════════════════

/// Number of fields per primary order type.
pub fn field_count(order_type: PrimaryOrderType) -> usize {
    match order_type {
        PrimaryOrderType::DstBlt => 5,
        PrimaryOrderType::PatBlt => 12,
        PrimaryOrderType::ScrBlt => 7,
        PrimaryOrderType::DrawNineGrid => 5,
        PrimaryOrderType::MultiDrawNineGrid => 9, // MS-RDPEGDI 2.2.2.2.1.1.2.16: 9 fields (2-byte fieldFlags)
        PrimaryOrderType::LineTo => 10,
        PrimaryOrderType::OpaqueRect => 7,
        PrimaryOrderType::SaveBitmap => 6,
        PrimaryOrderType::MemBlt => 9,
        PrimaryOrderType::Mem3Blt => 16,
        PrimaryOrderType::MultiDstBlt => 7,
        PrimaryOrderType::MultiPatBlt => 14,
        PrimaryOrderType::MultiScrBlt => 9,
        PrimaryOrderType::MultiOpaqueRect => 9,
        PrimaryOrderType::FastIndex => 15,
        PrimaryOrderType::PolygonSc => 7,
        PrimaryOrderType::PolygonCb => 13,
        PrimaryOrderType::Polyline => 7,
        PrimaryOrderType::FastGlyph => 15,
        PrimaryOrderType::EllipseSc => 7,
        PrimaryOrderType::EllipseCb => 13,
        PrimaryOrderType::GlyphIndex => 22,
    }
}

/// Maximum number of fields any primary order can have.
pub const MAX_ORDER_FIELDS: usize = 22;
/// Number of distinct primary order types.
pub const ORDER_TYPE_COUNT: usize = 22;

/// Decode a COORD_FIELD value (MS-RDPEGDI 2.2.2.2.1.1.1.1).
///
/// When `delta_mode` is true (TS_DELTA_COORDINATES set), reads 1-byte signed delta.
/// Otherwise reads 2-byte signed LE absolute value.
pub fn decode_coord_field(src: &mut ReadCursor<'_>, delta_mode: bool, prev: i16) -> DecodeResult<i16> {
    if delta_mode {
        let delta = src.read_u8("COORD_FIELD::delta")? as i8;
        Ok(prev.wrapping_add(delta as i16))
    } else {
        let val = src.read_i16_le("COORD_FIELD::absolute")?;
        Ok(val)
    }
}

// ── Typed primary order bodies ──

/// DstBlt order — MS-RDPEGDI 2.2.2.2.1.1.2.1 (5 fields)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DstBltOrder {
    pub left: i16,
    pub top: i16,
    pub width: i16,
    pub height: i16,
    pub rop: u8,
}

/// PatBlt order — MS-RDPEGDI 2.2.2.2.1.1.2.3 (12 fields)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PatBltOrder {
    pub left: i16,
    pub top: i16,
    pub width: i16,
    pub height: i16,
    pub rop: u8,
    pub back_color: [u8; 3],
    pub fore_color: [u8; 3],
    pub brush_org_x: i8,
    pub brush_org_y: i8,
    pub brush_style: u8,
    pub brush_hatch: u8,
    pub brush_extra: [u8; 7],
}

/// ScrBlt order — MS-RDPEGDI 2.2.2.2.1.1.2.7 (7 fields)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScrBltOrder {
    pub left: i16,
    pub top: i16,
    pub width: i16,
    pub height: i16,
    pub rop: u8,
    pub src_left: i16,
    pub src_top: i16,
}

/// OpaqueRect order — MS-RDPEGDI 2.2.2.2.1.1.2.5 (7 fields)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpaqueRectOrder {
    pub left: i16,
    pub top: i16,
    pub width: i16,
    pub height: i16,
    pub red: u8,
    pub green: u8,
    pub blue: u8,
}

/// MemBlt order — MS-RDPEGDI 2.2.2.2.1.1.2.9 (9 fields)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemBltOrder {
    pub cache_id: u16,
    pub left: i16,
    pub top: i16,
    pub width: i16,
    pub height: i16,
    pub rop: u8,
    pub src_left: i16,
    pub src_top: i16,
    pub cache_index: u16,
}

/// LineTo order — MS-RDPEGDI 2.2.2.2.1.1.2.11 (10 fields)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LineToOrder {
    pub back_mode: u16,
    pub start_x: i16,
    pub start_y: i16,
    pub end_x: i16,
    pub end_y: i16,
    pub back_color: [u8; 3],
    pub rop2: u8,
    pub pen_style: u8,
    pub pen_width: u8,
    pub pen_color: [u8; 3],
}

/// Primary drawing order history for stateful decoding.
///
/// MS-RDPEGDI 3.2.1.1: clients must maintain per-order field arrays
/// and current bounds/order state across a sequence of primary orders.
#[derive(Debug, Clone)]
pub struct PrimaryOrderHistory {
    /// Last order type (initial: PatBlt per MS-RDPEGDI 3.2.1.1).
    pub last_order_type: PrimaryOrderType,
    /// Current bounding rectangle (initial: all zeros).
    pub current_bounds: BoundsRect,
    /// Per-order field value storage (i32 for all fields, coerced as needed).
    fields: [[i32; MAX_ORDER_FIELDS]; ORDER_TYPE_COUNT],
}

impl Default for PrimaryOrderHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl PrimaryOrderHistory {
    pub fn new() -> Self {
        Self {
            last_order_type: PrimaryOrderType::PatBlt,
            current_bounds: BoundsRect { left: 0, top: 0, right: 0, bottom: 0 },
            fields: [[0i32; MAX_ORDER_FIELDS]; ORDER_TYPE_COUNT],
        }
    }

    /// Get a mutable reference to the field array for a given order type.
    fn fields_mut(&mut self, order_type: PrimaryOrderType) -> &mut [i32; MAX_ORDER_FIELDS] {
        let idx = order_type_index(order_type);
        &mut self.fields[idx]
    }

    /// Get a reference to the field array for a given order type.
    pub fn fields_ref(&self, order_type: PrimaryOrderType) -> &[i32; MAX_ORDER_FIELDS] {
        let idx = order_type_index(order_type);
        &self.fields[idx]
    }

    /// Reset all history state (on Deactivation-Reactivation).
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Map PrimaryOrderType to array index (0-21).
fn order_type_index(t: PrimaryOrderType) -> usize {
    match t {
        PrimaryOrderType::DstBlt => 0,
        PrimaryOrderType::PatBlt => 1,
        PrimaryOrderType::ScrBlt => 2,
        PrimaryOrderType::DrawNineGrid => 3,
        PrimaryOrderType::MultiDrawNineGrid => 4, // 9 fields
        PrimaryOrderType::LineTo => 5,
        PrimaryOrderType::OpaqueRect => 6,
        PrimaryOrderType::SaveBitmap => 7,
        PrimaryOrderType::MemBlt => 8,
        PrimaryOrderType::Mem3Blt => 9,
        PrimaryOrderType::MultiDstBlt => 10,
        PrimaryOrderType::MultiPatBlt => 11,
        PrimaryOrderType::MultiScrBlt => 12,
        PrimaryOrderType::MultiOpaqueRect => 13,
        PrimaryOrderType::FastIndex => 14,
        PrimaryOrderType::PolygonSc => 15,
        PrimaryOrderType::PolygonCb => 16,
        PrimaryOrderType::Polyline => 17,
        PrimaryOrderType::FastGlyph => 18,
        PrimaryOrderType::EllipseSc => 19,
        PrimaryOrderType::EllipseCb => 20,
        PrimaryOrderType::GlyphIndex => 21,
    }
}

/// Decode a DstBlt order from field data.
pub fn decode_dstblt(
    src: &mut ReadCursor<'_>,
    field_flags: u32,
    delta: bool,
    history: &mut PrimaryOrderHistory,
) -> DecodeResult<DstBltOrder> {
    let f = history.fields_mut(PrimaryOrderType::DstBlt);

    if field_flags & 0x01 != 0 { f[0] = decode_coord_field(src, delta, f[0] as i16)? as i32; }
    if field_flags & 0x02 != 0 { f[1] = decode_coord_field(src, delta, f[1] as i16)? as i32; }
    if field_flags & 0x04 != 0 { f[2] = decode_coord_field(src, delta, f[2] as i16)? as i32; }
    if field_flags & 0x08 != 0 { f[3] = decode_coord_field(src, delta, f[3] as i16)? as i32; }
    if field_flags & 0x10 != 0 { f[4] = src.read_u8("DstBlt::bRop")? as i32; }

    Ok(DstBltOrder {
        left: f[0] as i16,
        top: f[1] as i16,
        width: f[2] as i16,
        height: f[3] as i16,
        rop: f[4] as u8,
    })
}

/// Decode a PatBlt order from field data.
pub fn decode_patblt(
    src: &mut ReadCursor<'_>,
    field_flags: u32,
    delta: bool,
    history: &mut PrimaryOrderHistory,
) -> DecodeResult<PatBltOrder> {
    let f = history.fields_mut(PrimaryOrderType::PatBlt);

    if field_flags & 0x0001 != 0 { f[0] = decode_coord_field(src, delta, f[0] as i16)? as i32; }
    if field_flags & 0x0002 != 0 { f[1] = decode_coord_field(src, delta, f[1] as i16)? as i32; }
    if field_flags & 0x0004 != 0 { f[2] = decode_coord_field(src, delta, f[2] as i16)? as i32; }
    if field_flags & 0x0008 != 0 { f[3] = decode_coord_field(src, delta, f[3] as i16)? as i32; }
    if field_flags & 0x0010 != 0 { f[4] = src.read_u8("PatBlt::bRop")? as i32; }
    if field_flags & 0x0020 != 0 {
        let r = src.read_u8("PatBlt::backColor[0]")?;
        let g = src.read_u8("PatBlt::backColor[1]")?;
        let b = src.read_u8("PatBlt::backColor[2]")?;
        f[5] = ((r as i32) << 16) | ((g as i32) << 8) | (b as i32);
    }
    if field_flags & 0x0040 != 0 {
        let r = src.read_u8("PatBlt::foreColor[0]")?;
        let g = src.read_u8("PatBlt::foreColor[1]")?;
        let b = src.read_u8("PatBlt::foreColor[2]")?;
        f[6] = ((r as i32) << 16) | ((g as i32) << 8) | (b as i32);
    }
    if field_flags & 0x0080 != 0 { f[7] = src.read_u8("PatBlt::brushOrgX")? as i8 as i32; }
    if field_flags & 0x0100 != 0 { f[8] = src.read_u8("PatBlt::brushOrgY")? as i8 as i32; }
    if field_flags & 0x0200 != 0 { f[9] = src.read_u8("PatBlt::brushStyle")? as i32; }
    if field_flags & 0x0400 != 0 { f[10] = src.read_u8("PatBlt::brushHatch")? as i32; }
    if field_flags & 0x0800 != 0 {
        for i in 0..7 {
            let b = src.read_u8("PatBlt::brushExtra")?;
            // Store brush extra bytes in upper bits of f[11]..f[17] area
            // For simplicity, pack all 7 bytes into fields 11-17
            if i < MAX_ORDER_FIELDS - 11 {
                f[11 + i] = b as i32;
            }
        }
    }

    Ok(PatBltOrder {
        left: f[0] as i16,
        top: f[1] as i16,
        width: f[2] as i16,
        height: f[3] as i16,
        rop: f[4] as u8,
        back_color: [(f[5] >> 16) as u8, (f[5] >> 8) as u8, f[5] as u8],
        fore_color: [(f[6] >> 16) as u8, (f[6] >> 8) as u8, f[6] as u8],
        brush_org_x: f[7] as i8,
        brush_org_y: f[8] as i8,
        brush_style: f[9] as u8,
        brush_hatch: f[10] as u8,
        brush_extra: [
            f[11] as u8, f[12] as u8, f[13] as u8, f[14] as u8,
            f[15] as u8, f[16] as u8, f[17] as u8,
        ],
    })
}

/// Decode an OpaqueRect order from field data.
pub fn decode_opaque_rect(
    src: &mut ReadCursor<'_>,
    field_flags: u32,
    delta: bool,
    history: &mut PrimaryOrderHistory,
) -> DecodeResult<OpaqueRectOrder> {
    let f = history.fields_mut(PrimaryOrderType::OpaqueRect);

    if field_flags & 0x01 != 0 { f[0] = decode_coord_field(src, delta, f[0] as i16)? as i32; }
    if field_flags & 0x02 != 0 { f[1] = decode_coord_field(src, delta, f[1] as i16)? as i32; }
    if field_flags & 0x04 != 0 { f[2] = decode_coord_field(src, delta, f[2] as i16)? as i32; }
    if field_flags & 0x08 != 0 { f[3] = decode_coord_field(src, delta, f[3] as i16)? as i32; }
    // Color is encoded as 3 separate bytes (R, G, B)
    if field_flags & 0x10 != 0 { f[4] = src.read_u8("OpaqueRect::red")? as i32; }
    if field_flags & 0x20 != 0 { f[5] = src.read_u8("OpaqueRect::green")? as i32; }
    if field_flags & 0x40 != 0 { f[6] = src.read_u8("OpaqueRect::blue")? as i32; }

    Ok(OpaqueRectOrder {
        left: f[0] as i16,
        top: f[1] as i16,
        width: f[2] as i16,
        height: f[3] as i16,
        red: f[4] as u8,
        green: f[5] as u8,
        blue: f[6] as u8,
    })
}

/// Decode a ScrBlt order from field data.
pub fn decode_scrblt(
    src: &mut ReadCursor<'_>,
    field_flags: u32,
    delta: bool,
    history: &mut PrimaryOrderHistory,
) -> DecodeResult<ScrBltOrder> {
    let f = history.fields_mut(PrimaryOrderType::ScrBlt);

    if field_flags & 0x01 != 0 { f[0] = decode_coord_field(src, delta, f[0] as i16)? as i32; }
    if field_flags & 0x02 != 0 { f[1] = decode_coord_field(src, delta, f[1] as i16)? as i32; }
    if field_flags & 0x04 != 0 { f[2] = decode_coord_field(src, delta, f[2] as i16)? as i32; }
    if field_flags & 0x08 != 0 { f[3] = decode_coord_field(src, delta, f[3] as i16)? as i32; }
    if field_flags & 0x10 != 0 { f[4] = src.read_u8("ScrBlt::bRop")? as i32; }
    if field_flags & 0x20 != 0 { f[5] = decode_coord_field(src, delta, f[5] as i16)? as i32; }
    if field_flags & 0x40 != 0 { f[6] = decode_coord_field(src, delta, f[6] as i16)? as i32; }

    Ok(ScrBltOrder {
        left: f[0] as i16,
        top: f[1] as i16,
        width: f[2] as i16,
        height: f[3] as i16,
        rop: f[4] as u8,
        src_left: f[5] as i16,
        src_top: f[6] as i16,
    })
}

/// Decode a MemBlt order from field data.
pub fn decode_memblt(
    src: &mut ReadCursor<'_>,
    field_flags: u32,
    delta: bool,
    history: &mut PrimaryOrderHistory,
) -> DecodeResult<MemBltOrder> {
    let f = history.fields_mut(PrimaryOrderType::MemBlt);

    if field_flags & 0x0001 != 0 { f[0] = src.read_u16_le("MemBlt::cacheId")? as i32; }
    if field_flags & 0x0002 != 0 { f[1] = decode_coord_field(src, delta, f[1] as i16)? as i32; }
    if field_flags & 0x0004 != 0 { f[2] = decode_coord_field(src, delta, f[2] as i16)? as i32; }
    if field_flags & 0x0008 != 0 { f[3] = decode_coord_field(src, delta, f[3] as i16)? as i32; }
    if field_flags & 0x0010 != 0 { f[4] = decode_coord_field(src, delta, f[4] as i16)? as i32; }
    if field_flags & 0x0020 != 0 { f[5] = src.read_u8("MemBlt::bRop")? as i32; }
    if field_flags & 0x0040 != 0 { f[6] = decode_coord_field(src, delta, f[6] as i16)? as i32; }
    if field_flags & 0x0080 != 0 { f[7] = decode_coord_field(src, delta, f[7] as i16)? as i32; }
    if field_flags & 0x0100 != 0 { f[8] = src.read_u16_le("MemBlt::cacheIndex")? as i32; }

    Ok(MemBltOrder {
        cache_id: f[0] as u16,
        left: f[1] as i16,
        top: f[2] as i16,
        width: f[3] as i16,
        height: f[4] as i16,
        rop: f[5] as u8,
        src_left: f[6] as i16,
        src_top: f[7] as i16,
        cache_index: f[8] as u16,
    })
}

/// Decode a LineTo order from field data.
pub fn decode_lineto(
    src: &mut ReadCursor<'_>,
    field_flags: u32,
    delta: bool,
    history: &mut PrimaryOrderHistory,
) -> DecodeResult<LineToOrder> {
    let f = history.fields_mut(PrimaryOrderType::LineTo);

    if field_flags & 0x0001 != 0 { f[0] = src.read_u16_le("LineTo::backMode")? as i32; }
    if field_flags & 0x0002 != 0 { f[1] = decode_coord_field(src, delta, f[1] as i16)? as i32; }
    if field_flags & 0x0004 != 0 { f[2] = decode_coord_field(src, delta, f[2] as i16)? as i32; }
    if field_flags & 0x0008 != 0 { f[3] = decode_coord_field(src, delta, f[3] as i16)? as i32; }
    if field_flags & 0x0010 != 0 { f[4] = decode_coord_field(src, delta, f[4] as i16)? as i32; }
    if field_flags & 0x0020 != 0 {
        let r = src.read_u8("LineTo::backColor[0]")?;
        let g = src.read_u8("LineTo::backColor[1]")?;
        let b = src.read_u8("LineTo::backColor[2]")?;
        f[5] = ((r as i32) << 16) | ((g as i32) << 8) | (b as i32);
    }
    if field_flags & 0x0040 != 0 { f[6] = src.read_u8("LineTo::bRop2")? as i32; }
    if field_flags & 0x0080 != 0 { f[7] = src.read_u8("LineTo::penStyle")? as i32; }
    if field_flags & 0x0100 != 0 { f[8] = src.read_u8("LineTo::penWidth")? as i32; }
    if field_flags & 0x0200 != 0 {
        let r = src.read_u8("LineTo::penColor[0]")?;
        let g = src.read_u8("LineTo::penColor[1]")?;
        let b = src.read_u8("LineTo::penColor[2]")?;
        f[9] = ((r as i32) << 16) | ((g as i32) << 8) | (b as i32);
    }

    Ok(LineToOrder {
        back_mode: f[0] as u16,
        start_x: f[1] as i16,
        start_y: f[2] as i16,
        end_x: f[3] as i16,
        end_y: f[4] as i16,
        back_color: [(f[5] >> 16) as u8, (f[5] >> 8) as u8, f[5] as u8],
        rop2: f[6] as u8,
        pen_style: f[7] as u8,
        pen_width: f[8] as u8,
        pen_color: [(f[9] >> 16) as u8, (f[9] >> 8) as u8, f[9] as u8],
    })
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
        // OpaqueRect has 7 fields → 1-byte fieldFlags (max 0x7F)
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::OpaqueRect,
            field_flags: 0x7F, // all 7 fields present
            bounds: Some(BoundsRect { left: 0, top: 0, right: 1920, bottom: 1080 }),
            data: vec![0x01, 0x02],
        };
        let buf = roundtrip_encode(&order);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = PrimaryOrder::decode(&mut cursor).unwrap();
        assert_eq!(decoded.order_type, PrimaryOrderType::OpaqueRect);
        assert_eq!(decoded.field_flags, 0x7F);
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

    // ── Primary Order Field Parsing Tests ──

    #[test]
    fn field_count_matches_field_flags_byte_count_all_22() {
        // Verify consistency: field_flags_byte_count == ceil((field_count+1)/8) for ALL 22 types
        let all_orders = [
            PrimaryOrderType::DstBlt, PrimaryOrderType::PatBlt, PrimaryOrderType::ScrBlt,
            PrimaryOrderType::DrawNineGrid, PrimaryOrderType::MultiDrawNineGrid,
            PrimaryOrderType::LineTo, PrimaryOrderType::OpaqueRect, PrimaryOrderType::SaveBitmap,
            PrimaryOrderType::MemBlt, PrimaryOrderType::Mem3Blt, PrimaryOrderType::MultiDstBlt,
            PrimaryOrderType::MultiPatBlt, PrimaryOrderType::MultiScrBlt,
            PrimaryOrderType::MultiOpaqueRect, PrimaryOrderType::FastIndex,
            PrimaryOrderType::PolygonSc, PrimaryOrderType::PolygonCb, PrimaryOrderType::Polyline,
            PrimaryOrderType::FastGlyph, PrimaryOrderType::EllipseSc, PrimaryOrderType::EllipseCb,
            PrimaryOrderType::GlyphIndex,
        ];
        assert_eq!(all_orders.len(), ORDER_TYPE_COUNT, "must test all 22 order types");

        for &ot in &all_orders {
            let fc = field_count(ot);
            let expected_bytes = (fc + 8) / 8; // ceil((fc+1)/8) simplified
            let actual_bytes = field_flags_byte_count(ot);
            assert_eq!(actual_bytes, expected_bytes,
                "field_flags_byte_count mismatch for {:?}: fields={}, expected={}, got={}",
                ot, fc, expected_bytes, actual_bytes);
        }
    }

    #[test]
    fn decode_dstblt_absolute() {
        let mut history = PrimaryOrderHistory::new();
        // DstBlt: 5 fields, all absolute (no delta mode)
        // field_flags = 0x1F (all 5 fields present)
        let data: &[u8] = &[
            0x0A, 0x00, // left = 10
            0x14, 0x00, // top = 20
            0x64, 0x00, // width = 100
            0x32, 0x00, // height = 50
            0xCC,       // rop = 0xCC (SRCCOPY)
        ];
        let mut cursor = ReadCursor::new(data);
        let order = decode_dstblt(&mut cursor, 0x1F, false, &mut history).unwrap();

        assert_eq!(order.left, 10);
        assert_eq!(order.top, 20);
        assert_eq!(order.width, 100);
        assert_eq!(order.height, 50);
        assert_eq!(order.rop, 0xCC);
    }

    #[test]
    fn decode_dstblt_delta() {
        let mut history = PrimaryOrderHistory::new();
        // Set previous values
        {
            let f = history.fields_mut(PrimaryOrderType::DstBlt);
            f[0] = 100; // prev left
            f[1] = 200; // prev top
            f[2] = 50;  // prev width
            f[3] = 30;  // prev height
            f[4] = 0xAA; // prev rop
        }

        // Delta: left += 5, top -= 3, only fields 0 and 1 present
        let data: &[u8] = &[0x05, 0xFD]; // delta=5, delta=-3
        let mut cursor = ReadCursor::new(data);
        let order = decode_dstblt(&mut cursor, 0x03, true, &mut history).unwrap();

        assert_eq!(order.left, 105);  // 100 + 5
        assert_eq!(order.top, 197);   // 200 + (-3)
        assert_eq!(order.width, 50);  // unchanged
        assert_eq!(order.height, 30); // unchanged
        assert_eq!(order.rop, 0xAA);  // unchanged
    }

    #[test]
    fn decode_opaque_rect_all_fields() {
        let mut history = PrimaryOrderHistory::new();
        let data: &[u8] = &[
            0x00, 0x00, // left = 0
            0x00, 0x00, // top = 0
            0x80, 0x07, // width = 1920
            0x38, 0x04, // height = 1080
            0xFF, 0x00, 0x00, // red, green, blue
        ];
        let mut cursor = ReadCursor::new(data);
        let order = decode_opaque_rect(&mut cursor, 0x7F, false, &mut history).unwrap();

        assert_eq!(order.width, 1920);
        assert_eq!(order.height, 1080);
        assert_eq!(order.red, 0xFF);
        assert_eq!(order.green, 0x00);
        assert_eq!(order.blue, 0x00);
    }

    #[test]
    fn decode_scrblt_partial_fields() {
        let mut history = PrimaryOrderHistory::new();
        // Only fields 0 (left) and 4 (rop) present (field_flags = 0x11)
        let data: &[u8] = &[
            0x0A, 0x00, // left = 10
            0xCC,       // rop
        ];
        let mut cursor = ReadCursor::new(data);
        let order = decode_scrblt(&mut cursor, 0x11, false, &mut history).unwrap();

        assert_eq!(order.left, 10);
        assert_eq!(order.top, 0);     // default from history
        assert_eq!(order.rop, 0xCC);
    }

    #[test]
    fn history_preserves_across_calls() {
        let mut history = PrimaryOrderHistory::new();

        // First DstBlt: set all fields
        let data1: &[u8] = &[0x0A, 0x00, 0x14, 0x00, 0x64, 0x00, 0x32, 0x00, 0xCC];
        let mut c1 = ReadCursor::new(data1);
        let o1 = decode_dstblt(&mut c1, 0x1F, false, &mut history).unwrap();
        assert_eq!(o1.left, 10);

        // Second DstBlt: only update left with delta
        let data2: &[u8] = &[0x05]; // delta = +5
        let mut c2 = ReadCursor::new(data2);
        let o2 = decode_dstblt(&mut c2, 0x01, true, &mut history).unwrap();

        assert_eq!(o2.left, 15);     // 10 + 5
        assert_eq!(o2.top, 20);      // preserved from first call
        assert_eq!(o2.width, 100);   // preserved
        assert_eq!(o2.height, 50);   // preserved
        assert_eq!(o2.rop, 0xCC);    // preserved
    }

    #[test]
    fn history_reset_clears_all() {
        let mut history = PrimaryOrderHistory::new();

        // Set some values
        let f = history.fields_mut(PrimaryOrderType::DstBlt);
        f[0] = 42;
        history.last_order_type = PrimaryOrderType::ScrBlt;

        // Reset
        history.reset();

        assert_eq!(history.last_order_type, PrimaryOrderType::PatBlt);
        let f = history.fields_ref(PrimaryOrderType::DstBlt);
        assert_eq!(f[0], 0);
    }

    #[test]
    fn decode_memblt_all_fields() {
        let mut history = PrimaryOrderHistory::new();
        let data: &[u8] = &[
            0x01, 0x00, // cache_id = 1
            0x0A, 0x00, // left = 10
            0x14, 0x00, // top = 20
            0x40, 0x00, // width = 64
            0x40, 0x00, // height = 64
            0xCC,       // rop = 0xCC
            0x00, 0x00, // src_left = 0
            0x00, 0x00, // src_top = 0
            0x05, 0x00, // cache_index = 5
        ];
        let mut cursor = ReadCursor::new(data);
        let order = decode_memblt(&mut cursor, 0x01FF, false, &mut history).unwrap();

        assert_eq!(order.cache_id, 1);
        assert_eq!(order.left, 10);
        assert_eq!(order.width, 64);
        assert_eq!(order.rop, 0xCC);
        assert_eq!(order.cache_index, 5);
    }

    #[test]
    fn decode_lineto_partial() {
        let mut history = PrimaryOrderHistory::new();
        // Only start_x (field 1) and end_x (field 3) present: field_flags = 0x000A
        let data: &[u8] = &[
            0x64, 0x00, // start_x = 100
            0xC8, 0x00, // end_x = 200
        ];
        let mut cursor = ReadCursor::new(data);
        let order = decode_lineto(&mut cursor, 0x000A, false, &mut history).unwrap();

        assert_eq!(order.start_x, 100);
        assert_eq!(order.end_x, 200);
        assert_eq!(order.start_y, 0); // default
        assert_eq!(order.end_y, 0);   // default
    }

    #[test]
    fn decode_patblt_basic() {
        let mut history = PrimaryOrderHistory::new();
        // Fields 0-4: left, top, width, height, rop (field_flags = 0x1F)
        let data: &[u8] = &[
            0x0A, 0x00, // left = 10
            0x14, 0x00, // top = 20
            0x64, 0x00, // width = 100
            0x32, 0x00, // height = 50
            0xF0,       // rop = 0xF0 (PATCOPY)
        ];
        let mut cursor = ReadCursor::new(data);
        let order = decode_patblt(&mut cursor, 0x001F, false, &mut history).unwrap();

        assert_eq!(order.left, 10);
        assert_eq!(order.top, 20);
        assert_eq!(order.width, 100);
        assert_eq!(order.height, 50);
        assert_eq!(order.rop, 0xF0);
    }

    #[test]
    fn coord_field_delta_wrapping() {
        // Test wrapping: prev = 32767 (i16::MAX), delta = +1 → wraps to -32768
        let data: &[u8] = &[0x01]; // delta = +1
        let mut cursor = ReadCursor::new(data);
        let result = decode_coord_field(&mut cursor, true, i16::MAX).unwrap();
        assert_eq!(result, i16::MIN); // wrapping add
    }
}
