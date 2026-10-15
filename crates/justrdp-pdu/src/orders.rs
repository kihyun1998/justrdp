//! Drawing orders (`[MS-RDPEGDI]` 2.2.2): the Orders Update on both transports, the primary
//! order field encoding with its history, and the orders the bitmap cache path needs: MemBlt,
//! Mem3Blt and Cache Bitmap (Revision 2). Decode only: orders flow server → client.
//!
//! A primary order carries no length. Its field-flag width depends on its type, so an order of a
//! type this module does not decode leaves the rest of the update unreadable:
//! [`OrderError::Unsupported`] says so, and the caller stops there (3.2.5.1.1.1 step 2). A
//! secondary order carries its length and is skipped whole when its type is not decoded.

use crate::DecodeError;
use crate::cursor::ReadCursor;

/// `controlFlags`: a primary order, or with [`TS_SECONDARY`] a secondary one.
pub const TS_STANDARD: u8 = 0x01;
/// `controlFlags`: a secondary order with [`TS_STANDARD`], an alternate secondary one alone.
pub const TS_SECONDARY: u8 = 0x02;
/// `controlFlags` (primary): the order has a bounding rectangle.
pub const TS_BOUNDS: u8 = 0x04;
/// `controlFlags` (primary): the `orderType` field is present.
pub const TS_TYPE_CHANGE: u8 = 0x08;
/// `controlFlags` (primary): every Coord field is a 1-byte signed delta.
pub const TS_DELTA_COORDINATES: u8 = 0x10;
/// `controlFlags` (primary): the previous bounding rectangle applies; no `bounds` field.
pub const TS_ZERO_BOUNDS_DELTAS: u8 = 0x20;
/// `controlFlags` (primary): low bit of the count of trailing zero field-flag bytes.
pub const TS_ZERO_FIELD_BYTE_BIT0: u8 = 0x40;
/// `controlFlags` (primary): high bit of the count of trailing zero field-flag bytes.
pub const TS_ZERO_FIELD_BYTE_BIT1: u8 = 0x80;

/// `orderType` (primary): PatBlt, the type both ends start from.
pub const TS_ENC_PATBLT_ORDER: u8 = 0x01;
/// `orderType` (primary): MemBlt.
pub const TS_ENC_MEMBLT_ORDER: u8 = 0x0D;
/// `orderType` (primary): Mem3Blt.
pub const TS_ENC_MEM3BLT_ORDER: u8 = 0x0E;

/// `orderType` (secondary): Cache Bitmap (Revision 2), uncompressed.
pub const TS_CACHE_BITMAP_UNCOMPRESSED_REV2: u8 = 0x04;
/// `orderType` (secondary): Cache Bitmap (Revision 2), compressed.
pub const TS_CACHE_BITMAP_COMPRESSED_REV2: u8 = 0x05;

/// Cache Bitmap (Revision 2) `flags`: no `bitmapHeight`, the bitmap is square.
pub const CBR2_HEIGHT_SAME_AS_WIDTH: u16 = 0x01;
/// Cache Bitmap (Revision 2) `flags`: `key1` and `key2` are present.
pub const CBR2_PERSISTENT_KEY_PRESENT: u16 = 0x02;
/// Cache Bitmap (Revision 2) `flags`: no `bitmapComprHdr`.
pub const CBR2_NO_BITMAP_COMPRESSION_HDR: u16 = 0x08;
/// Cache Bitmap (Revision 2) `flags`: store in the waiting-list entry, not at `cacheIndex`.
pub const CBR2_DO_NOT_CACHE: u16 = 0x10;

/// The `cacheIndex` naming a bitmap cache's waiting-list entry
/// (`BITMAPCACHE_WAITING_LIST_INDEX`).
pub const BITMAPCACHE_WAITING_LIST_INDEX: u16 = 32767;
/// The MemBlt/Mem3Blt `cacheId` low byte naming the offscreen bitmap cache
/// (`TS_BITMAPCACHE_SCREEN_ID`).
pub const TS_BITMAPCACHE_SCREEN_ID: u8 = 0xFF;

/// The three classes of drawing order (2.2.2.2.1 `controlFlags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderClass {
    /// [`TS_STANDARD`] alone.
    Primary,
    /// [`TS_STANDARD`] and [`TS_SECONDARY`].
    Secondary,
    /// [`TS_SECONDARY`] alone.
    AlternateSecondary,
}

/// Why a drawing order did not decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderError {
    /// The bytes are malformed or short.
    Decode(DecodeError),
    /// An order of a type this module does not decode, of a class with no length field, so
    /// nothing after it in the update can be found.
    Unsupported {
        /// Its class.
        class: OrderClass,
        /// Its `orderType`.
        order_type: u8,
    },
}

impl From<DecodeError> for OrderError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl core::fmt::Display for OrderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(f),
            Self::Unsupported { class, order_type } => {
                write!(
                    f,
                    "{class:?} drawing order {order_type:#04x} is not decoded"
                )
            }
        }
    }
}

impl core::error::Error for OrderError {}

/// The orders of one Orders Update, on either transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrdersUpdate<'a> {
    /// `numberOrders`.
    pub number_orders: u16,
    /// `orderData`: the packed orders, decoded one at a time with [`decode_order`].
    pub order_data: &'a [u8],
}

impl<'a> OrdersUpdate<'a> {
    /// Decode a slow-path TS_UPDATE_ORDERS_PDU_DATA after its `updateType` (2.2.2.1).
    pub fn decode_slow_path(cur: &mut ReadCursor<'a>) -> Result<Self, DecodeError> {
        cur.read_u16_le()?; // pad2OctetsA
        let number_orders = cur.read_u16_le()?;
        cur.read_u16_le()?; // pad2OctetsB
        let order_data = cur.read_slice(cur.remaining())?;
        Ok(Self {
            number_orders,
            order_data,
        })
    }

    /// Decode a TS_FP_UPDATE_ORDERS body, the bytes after its `size` (2.2.2.2).
    pub fn decode_fast_path(cur: &mut ReadCursor<'a>) -> Result<Self, DecodeError> {
        let number_orders = cur.read_u16_le()?;
        let order_data = cur.read_slice(cur.remaining())?;
        Ok(Self {
            number_orders,
            order_data,
        })
    }
}

/// A bounding rectangle, inclusive on every edge (2.2.2.2.1.1.2 `bounds`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bounds {
    /// Left column.
    pub left: i16,
    /// Top row.
    pub top: i16,
    /// Right column (inclusive).
    pub right: i16,
    /// Bottom row (inclusive).
    pub bottom: i16,
}

/// What clips a primary order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clip {
    /// No [`TS_BOUNDS`]: the order is unclipped.
    None,
    /// The order's bounding rectangle.
    Bounds(Bounds),
    /// [`TS_BOUNDS`] built on a rectangle an order of an undecoded type may have changed, so
    /// the rectangle is not known ([`OrderHistory`]).
    Unknown,
}

/// The fields of a MemBlt order (2.2.2.2.1.1.2.9), as the history holds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemBlt {
    /// `cacheId`: the bitmap cache ID in the low byte, the color table entry in the high byte.
    pub cache_id: u16,
    /// `nLeftRect`.
    pub left: i16,
    /// `nTopRect`.
    pub top: i16,
    /// `nWidth`.
    pub width: i16,
    /// `nHeight`.
    pub height: i16,
    /// `bRop`: the ROP3 index.
    pub rop: u8,
    /// `nXSrc`.
    pub x_src: i16,
    /// `nYSrc`, a top-down row of the cached bitmap: the spec's inversion
    /// (`ActualYSrc = (SourceBitmapHeight - nHeight) - nYSrc`) addresses bottom-up storage.
    pub y_src: i16,
    /// `cacheIndex`.
    pub cache_index: u16,
}

/// An 8×8 brush (2.2.2.2.1.1.2.3 `BrushOrgX` … `BrushExtra`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Brush {
    /// `BrushOrgX`.
    pub org_x: i8,
    /// `BrushOrgY`.
    pub org_y: i8,
    /// `BrushStyle`.
    pub style: u8,
    /// `BrushHatch`: a hatch identifier, the bottom row of a pattern, or a brush cache index.
    pub hatch: u8,
    /// `BrushExtra`: the pattern's other rows, penultimate row first.
    pub extra: [u8; 7],
}

/// The fields of a Mem3Blt order (2.2.2.2.1.1.2.10), as the history holds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mem3Blt {
    /// The fields Mem3Blt shares with MemBlt.
    pub blt: MemBlt,
    /// `BackColor`, the three wire bytes little-endian (TS_COLOR).
    pub back_color: u32,
    /// `ForeColor`, the three wire bytes little-endian (TS_COLOR).
    pub fore_color: u32,
    /// The brush.
    pub brush: Brush,
}

/// Cache Bitmap (Revision 2) (2.2.2.2.1.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheBitmapRev2<'a> {
    /// `cacheId`.
    pub cache_id: u8,
    /// The color depth `bitsPerPixelId` names: 8, 16, 24 or 32.
    pub bits_per_pixel: u16,
    /// `flags` (`CBR2_*`).
    pub flags: u16,
    /// `key1` and `key2` as one 64-bit key, when [`CBR2_PERSISTENT_KEY_PRESENT`].
    pub key: Option<u64>,
    /// `bitmapWidth`.
    pub width: u16,
    /// `bitmapHeight`.
    pub height: u16,
    /// `cacheIndex`, or [`BITMAPCACHE_WAITING_LIST_INDEX`] under [`CBR2_DO_NOT_CACHE`].
    pub cache_index: u16,
    /// The order type was [`TS_CACHE_BITMAP_COMPRESSED_REV2`].
    pub compressed: bool,
    /// The bitmap stream, any `bitmapComprHdr` already stripped.
    pub data: &'a [u8],
}

/// One decoded drawing order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrawingOrder<'a> {
    /// MemBlt.
    MemBlt {
        /// The order.
        order: MemBlt,
        /// Its clip.
        clip: Clip,
    },
    /// Mem3Blt.
    Mem3Blt {
        /// The order.
        order: Mem3Blt,
        /// Its clip.
        clip: Clip,
    },
    /// Cache Bitmap (Revision 2).
    CacheBitmapRev2(CacheBitmapRev2<'a>),
    /// A secondary order of a type not decoded here, skipped by its length.
    SkippedSecondary {
        /// Its `orderType`.
        order_type: u8,
    },
}

/// The Primary Drawing Order History (3.2.1.1): the last order type, the last bounding
/// rectangle and every decoded order type's last field values. It belongs to the connection and
/// spans updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderHistory {
    order_type: u8,
    bounds: Bounds,
    /// False once an order of an undecoded type may have moved the rectangle; true again when
    /// a `bounds` field gives all four edges absolutely.
    bounds_known: bool,
    memblt: MemBlt,
    mem3blt: Mem3Blt,
}

impl Default for OrderHistory {
    /// The agreed initial state: PatBlt, a zero rectangle, zero fields.
    fn default() -> Self {
        Self {
            order_type: TS_ENC_PATBLT_ORDER,
            bounds: Bounds::default(),
            bounds_known: true,
            memblt: MemBlt::default(),
            mem3blt: Mem3Blt::default(),
        }
    }
}

/// The number of field-flag bytes of a primary order type (2.2.2.2.1.1.2), for the types
/// decoded here.
fn field_bytes(order_type: u8) -> Option<usize> {
    match order_type {
        TS_ENC_MEMBLT_ORDER => Some(2),
        TS_ENC_MEM3BLT_ORDER => Some(3),
        _ => None,
    }
}

/// Decode the next drawing order from `cur`, updating `history`.
pub fn decode_order<'a>(
    cur: &mut ReadCursor<'a>,
    history: &mut OrderHistory,
) -> Result<DrawingOrder<'a>, OrderError> {
    let control = cur.read_u8()?;
    match control & (TS_STANDARD | TS_SECONDARY) {
        TS_STANDARD => decode_primary(control, cur, history),
        0x03 => decode_secondary(cur),
        TS_SECONDARY => Err(OrderError::Unsupported {
            class: OrderClass::AlternateSecondary,
            order_type: control >> 2,
        }),
        _ => Err(DecodeError::InvalidField {
            field: "DRAWING_ORDER.controlFlags",
            reason: "neither TS_STANDARD nor TS_SECONDARY",
        }
        .into()),
    }
}

fn decode_primary<'a>(
    control: u8,
    cur: &mut ReadCursor<'a>,
    history: &mut OrderHistory,
) -> Result<DrawingOrder<'a>, OrderError> {
    if control & TS_TYPE_CHANGE != 0 {
        history.order_type = cur.read_u8()?;
    }
    let order_type = history.order_type;
    let Some(width) = field_bytes(order_type) else {
        // Its field flags and bounds cannot be told apart from its fields, so a new rectangle in
        // it is lost to every later order that builds on it.
        if control & TS_BOUNDS != 0 && control & TS_ZERO_BOUNDS_DELTAS == 0 {
            history.bounds_known = false;
        }
        return Err(OrderError::Unsupported {
            class: OrderClass::Primary,
            order_type,
        });
    };
    let zero_bytes =
        usize::from((control & (TS_ZERO_FIELD_BYTE_BIT0 | TS_ZERO_FIELD_BYTE_BIT1)) >> 6);
    let mut fields = 0u32;
    for index in 0..width.saturating_sub(zero_bytes) {
        fields |= u32::from(cur.read_u8()?) << (8 * index);
    }
    let clip = if control & TS_BOUNDS == 0 {
        Clip::None
    } else {
        if control & TS_ZERO_BOUNDS_DELTAS == 0 {
            read_bounds(cur, history)?;
        }
        if history.bounds_known {
            Clip::Bounds(history.bounds)
        } else {
            Clip::Unknown
        }
    };
    let delta = control & TS_DELTA_COORDINATES != 0;
    let mut fields = Fields { cur, fields, delta };
    Ok(match order_type {
        TS_ENC_MEMBLT_ORDER => {
            let order = &mut history.memblt;
            fields.u16(0x0001, &mut order.cache_id)?;
            fields.blt_rect(0x0002, order)?;
            fields.u8(0x0020, &mut order.rop)?;
            fields.coord(0x0040, &mut order.x_src)?;
            fields.coord(0x0080, &mut order.y_src)?;
            fields.u16(0x0100, &mut order.cache_index)?;
            DrawingOrder::MemBlt {
                order: *order,
                clip,
            }
        }
        _ => {
            let order = &mut history.mem3blt;
            fields.u16(0x0001, &mut order.blt.cache_id)?;
            fields.blt_rect(0x0002, &mut order.blt)?;
            fields.u8(0x0020, &mut order.blt.rop)?;
            fields.coord(0x0040, &mut order.blt.x_src)?;
            fields.coord(0x0080, &mut order.blt.y_src)?;
            fields.color(0x0100, &mut order.back_color)?;
            fields.color(0x0200, &mut order.fore_color)?;
            fields.brush(0x0400, &mut order.brush)?;
            fields.u16(0x8000, &mut order.blt.cache_index)?;
            DrawingOrder::Mem3Blt {
                order: *order,
                clip,
            }
        }
    })
}

/// Read a `bounds` field into the history (2.2.2.2.1.1.2): a description byte, then each edge
/// it names, absolute or as a delta, left, top, right, bottom.
fn read_bounds(cur: &mut ReadCursor<'_>, history: &mut OrderHistory) -> Result<(), DecodeError> {
    let description = cur.read_u8()?;
    let bounds = &mut history.bounds;
    let mut absolute = 0;
    for (bit, edge) in [
        &mut bounds.left,
        &mut bounds.top,
        &mut bounds.right,
        &mut bounds.bottom,
    ]
    .into_iter()
    .enumerate()
    {
        // With both flags, the absolute one is ignored.
        if description & (0x10 << bit) != 0 {
            *edge = edge.wrapping_add(i16::from(cur.read_u8()? as i8));
        } else if description & (0x01 << bit) != 0 {
            *edge = cur.read_u16_le()? as i16;
            absolute += 1;
        }
    }
    if absolute == 4 {
        history.bounds_known = true;
    }
    Ok(())
}

/// The present fields of one primary order, read in order.
struct Fields<'c, 'a> {
    cur: &'c mut ReadCursor<'a>,
    fields: u32,
    delta: bool,
}

impl Fields<'_, '_> {
    fn present(&self, flag: u32) -> bool {
        self.fields & flag != 0
    }

    fn u8(&mut self, flag: u32, value: &mut u8) -> Result<(), DecodeError> {
        if self.present(flag) {
            *value = self.cur.read_u8()?;
        }
        Ok(())
    }

    fn u16(&mut self, flag: u32, value: &mut u16) -> Result<(), DecodeError> {
        if self.present(flag) {
            *value = self.cur.read_u16_le()?;
        }
        Ok(())
    }

    /// A Coord field (2.2.2.2.1.1.1.1): a 1-byte delta under [`TS_DELTA_COORDINATES`], else
    /// the 2-byte value. A delta wraps at the 16-bit range.
    fn coord(&mut self, flag: u32, value: &mut i16) -> Result<(), DecodeError> {
        if self.present(flag) {
            *value = if self.delta {
                value.wrapping_add(i16::from(self.cur.read_u8()? as i8))
            } else {
                self.cur.read_u16_le()? as i16
            };
        }
        Ok(())
    }

    /// `nLeftRect`, `nTopRect`, `nWidth`, `nHeight` under four consecutive flags from `first`.
    fn blt_rect(&mut self, first: u32, blt: &mut MemBlt) -> Result<(), DecodeError> {
        self.coord(first, &mut blt.left)?;
        self.coord(first << 1, &mut blt.top)?;
        self.coord(first << 2, &mut blt.width)?;
        self.coord(first << 3, &mut blt.height)
    }

    /// A TS_COLOR (2.2.2.2.1.1.1.8), its three bytes little-endian.
    fn color(&mut self, flag: u32, value: &mut u32) -> Result<(), DecodeError> {
        if self.present(flag) {
            let bytes = self.cur.read_slice(3)?;
            *value = u32::from(bytes[0]) | u32::from(bytes[1]) << 8 | u32::from(bytes[2]) << 16;
        }
        Ok(())
    }

    /// `BrushOrgX` … `BrushExtra` under five consecutive flags from `first`.
    fn brush(&mut self, first: u32, brush: &mut Brush) -> Result<(), DecodeError> {
        if self.present(first) {
            brush.org_x = self.cur.read_u8()? as i8;
        }
        if self.present(first << 1) {
            brush.org_y = self.cur.read_u8()? as i8;
        }
        self.u8(first << 2, &mut brush.style)?;
        self.u8(first << 3, &mut brush.hatch)?;
        if self.present(first << 4) {
            brush.extra.copy_from_slice(self.cur.read_slice(7)?);
        }
        Ok(())
    }
}

/// Decode a secondary order after its `controlFlags` (2.2.2.2.1.2.1.1). The body is read from
/// its own bounded cursor, so an order that lies about its fields cannot reach its neighbours.
fn decode_secondary<'a>(cur: &mut ReadCursor<'a>) -> Result<DrawingOrder<'a>, OrderError> {
    let order_length = cur.read_u16_le()? as i16;
    let extra_flags = cur.read_u16_le()?;
    let order_type = cur.read_u8()?;
    // `orderLength` is the whole order's length less 13; the header is 6 of those bytes.
    let body_length =
        usize::try_from(i32::from(order_length) + 7).map_err(|_| DecodeError::InvalidField {
            field: "SECONDARY_DRAWING_ORDER_HEADER.orderLength",
            reason: "shorter than the header",
        })?;
    let body = cur.read_slice(body_length)?;
    let mut body = ReadCursor::new(body, "secondary drawing order");
    Ok(match order_type {
        TS_CACHE_BITMAP_UNCOMPRESSED_REV2 | TS_CACHE_BITMAP_COMPRESSED_REV2 => {
            DrawingOrder::CacheBitmapRev2(decode_cache_bitmap_rev2(
                &mut body,
                extra_flags,
                order_type == TS_CACHE_BITMAP_COMPRESSED_REV2,
            )?)
        }
        _ => DrawingOrder::SkippedSecondary { order_type },
    })
}

fn decode_cache_bitmap_rev2<'a>(
    cur: &mut ReadCursor<'a>,
    extra_flags: u16,
    compressed: bool,
) -> Result<CacheBitmapRev2<'a>, DecodeError> {
    let cache_id = (extra_flags & 0x0007) as u8;
    let bits_per_pixel = match (extra_flags & 0x0078) >> 3 {
        0x3 => 8,
        0x4 => 16,
        0x5 => 24,
        0x6 => 32,
        _ => {
            return Err(DecodeError::InvalidField {
                field: "CACHE_BITMAP_REV2_ORDER.bitsPerPixelId",
                reason: "not CBR2_8BPP, CBR2_16BPP, CBR2_24BPP or CBR2_32BPP",
            });
        }
    };
    let flags = extra_flags >> 7;
    let key = if flags & CBR2_PERSISTENT_KEY_PRESENT != 0 {
        let low = cur.read_u32_le()?;
        let high = cur.read_u32_le()?;
        Some(u64::from(high) << 32 | u64::from(low))
    } else {
        None
    };
    let width = two_byte_unsigned(cur)?;
    let height = if flags & CBR2_HEIGHT_SAME_AS_WIDTH != 0 {
        width
    } else {
        two_byte_unsigned(cur)?
    };
    let bitmap_length = four_byte_unsigned(cur)?;
    let mut cache_index = two_byte_unsigned(cur)?;
    if flags & CBR2_DO_NOT_CACHE != 0 {
        cache_index = BITMAPCACHE_WAITING_LIST_INDEX;
    }
    let data = if compressed && flags & CBR2_NO_BITMAP_COMPRESSION_HDR == 0 {
        // TS_CD_HEADER: cbCompFirstRowSize, cbCompMainBodySize, cbScanWidth,
        // cbUncompressedSize. The main body follows it.
        cur.read_u16_le()?;
        let main_body = cur.read_u16_le()?;
        cur.read_u16_le()?;
        cur.read_u16_le()?;
        cur.read_slice(usize::from(main_body))?
    } else {
        cur.read_slice(bitmap_length as usize)?
    };
    Ok(CacheBitmapRev2 {
        cache_id,
        bits_per_pixel,
        flags,
        key,
        width,
        height,
        cache_index,
        compressed,
        data,
    })
}

/// A TWO_BYTE_UNSIGNED_ENCODING (2.2.2.2.1.2.1.2).
fn two_byte_unsigned(cur: &mut ReadCursor<'_>) -> Result<u16, DecodeError> {
    let first = cur.read_u8()?;
    let high = u16::from(first & 0x7F);
    Ok(if first & 0x80 != 0 {
        high << 8 | u16::from(cur.read_u8()?)
    } else {
        high
    })
}

/// A FOUR_BYTE_UNSIGNED_ENCODING (2.2.2.2.1.2.1.4).
fn four_byte_unsigned(cur: &mut ReadCursor<'_>) -> Result<u32, DecodeError> {
    let first = cur.read_u8()?;
    let mut value = u32::from(first & 0x3F);
    for _ in 0..first >> 6 {
        value = value << 8 | u32::from(cur.read_u8()?);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all<'a>(
        bytes: &'a [u8],
        history: &mut OrderHistory,
    ) -> Vec<Result<DrawingOrder<'a>, OrderError>> {
        let mut cur = ReadCursor::new(bytes, "test orders");
        let mut out = Vec::new();
        while cur.remaining() > 0 {
            let order = decode_order(&mut cur, history);
            let stop = order.is_err();
            out.push(order);
            if stop {
                break;
            }
        }
        out
    }

    /// 2.2.2.2.1.2.1.2 and .4 give one example each.
    #[test]
    fn variable_length_encodings_match_the_spec_examples() {
        let mut cur = ReadCursor::new(&[0x9A, 0x1B], "two-byte");
        assert_eq!(two_byte_unsigned(&mut cur).unwrap(), 0x1A1B);
        let mut cur = ReadCursor::new(&[0x9A, 0x1B, 0x1C], "four-byte");
        assert_eq!(four_byte_unsigned(&mut cur).unwrap(), 0x001A_1B1C);
        let mut cur = ReadCursor::new(&[0x05], "four-byte");
        assert_eq!(four_byte_unsigned(&mut cur).unwrap(), 5);
    }

    /// A MemBlt with every field, then one that changes only `nLeftRect` by a delta: the
    /// second carries the first's other fields (3.2.5.1.1.1).
    #[test]
    fn memblt_fields_carry_over_between_orders() {
        let mut bytes = vec![
            TS_STANDARD | TS_TYPE_CHANGE,
            TS_ENC_MEMBLT_ORDER,
            0xFF,
            0x01, // all nine field flags
        ];
        bytes.extend_from_slice(&0x0102u16.to_le_bytes()); // cacheId
        for value in [10i16, 20, 64, 32] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.push(0xCC); // bRop
        for value in [1i16, 2] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&7u16.to_le_bytes()); // cacheIndex
        // Second order: same type, delta coordinates, only nLeftRect; the trailing zero
        // field-flag byte is dropped.
        bytes.extend_from_slice(&[
            TS_STANDARD | TS_DELTA_COORDINATES | TS_ZERO_FIELD_BYTE_BIT0,
            0x02,
            (-3i8) as u8,
        ]);
        let mut history = OrderHistory::default();
        let orders = decode_all(&bytes, &mut history);
        let expected = MemBlt {
            cache_id: 0x0102,
            left: 10,
            top: 20,
            width: 64,
            height: 32,
            rop: 0xCC,
            x_src: 1,
            y_src: 2,
            cache_index: 7,
        };
        assert_eq!(
            orders[0],
            Ok(DrawingOrder::MemBlt {
                order: expected,
                clip: Clip::None
            })
        );
        assert_eq!(
            orders[1],
            Ok(DrawingOrder::MemBlt {
                order: MemBlt {
                    left: 7,
                    ..expected
                },
                clip: Clip::None
            })
        );
    }

    /// Bounds: absolute edges, then deltas, then TS_ZERO_BOUNDS_DELTAS reusing them.
    #[test]
    fn bounds_are_absolute_delta_or_reused() {
        let mut bytes = vec![
            TS_STANDARD | TS_TYPE_CHANGE | TS_BOUNDS | TS_ZERO_FIELD_BYTE_BIT1,
            TS_ENC_MEMBLT_ORDER,
            0x0F,
        ];
        for edge in [1i16, 2, 300, 400] {
            bytes.extend_from_slice(&edge.to_le_bytes());
        }
        // Delta left and bottom; with both flags for left, only the delta is read.
        bytes.extend_from_slice(&[
            TS_STANDARD | TS_BOUNDS | TS_ZERO_FIELD_BYTE_BIT1,
            0x10 | 0x01 | 0x80,
            5,
            (-10i8) as u8,
        ]);
        bytes.extend_from_slice(&[TS_STANDARD
            | TS_BOUNDS
            | TS_ZERO_BOUNDS_DELTAS
            | TS_ZERO_FIELD_BYTE_BIT1]);
        let mut history = OrderHistory::default();
        let clips: Vec<Clip> = decode_all(&bytes, &mut history)
            .into_iter()
            .map(|order| match order.unwrap() {
                DrawingOrder::MemBlt { clip, .. } => clip,
                other => panic!("{other:?}"),
            })
            .collect();
        let moved = Bounds {
            left: 6,
            top: 2,
            right: 300,
            bottom: 390,
        };
        assert_eq!(
            clips,
            [
                Clip::Bounds(Bounds {
                    left: 1,
                    top: 2,
                    right: 300,
                    bottom: 400
                }),
                Clip::Bounds(moved),
                Clip::Bounds(moved),
            ]
        );
    }

    /// An undecoded primary that sends a rectangle leaves later delta bounds unknown, until a
    /// rectangle arrives whole.
    #[test]
    fn an_undecoded_primary_makes_later_bounds_unknown() {
        let mut history = OrderHistory::default();
        let unsupported = [TS_STANDARD | TS_TYPE_CHANGE | TS_BOUNDS, 0x0A];
        assert_eq!(
            decode_all(&unsupported, &mut history),
            [Err(OrderError::Unsupported {
                class: OrderClass::Primary,
                order_type: 0x0A
            })]
        );
        // Same type again, no TS_TYPE_CHANGE: still that type, still unsupported.
        assert!(matches!(
            decode_all(&[TS_STANDARD], &mut history)[0],
            Err(OrderError::Unsupported {
                order_type: 0x0A,
                ..
            })
        ));
        let mut reused = vec![
            TS_STANDARD | TS_TYPE_CHANGE | TS_BOUNDS | TS_ZERO_BOUNDS_DELTAS,
            TS_ENC_MEMBLT_ORDER,
        ];
        reused.extend_from_slice(&[0, 0]);
        assert!(matches!(
            decode_all(&reused, &mut history)[0],
            Ok(DrawingOrder::MemBlt {
                clip: Clip::Unknown,
                ..
            })
        ));
        let mut whole = vec![TS_STANDARD | TS_BOUNDS | TS_ZERO_FIELD_BYTE_BIT1, 0x0F];
        for edge in [0i16, 0, 9, 9] {
            whole.extend_from_slice(&edge.to_le_bytes());
        }
        assert!(matches!(
            decode_all(&whole, &mut history)[0],
            Ok(DrawingOrder::MemBlt {
                clip: Clip::Bounds(_),
                ..
            })
        ));
    }

    /// Mem3Blt's colours and brush, from its third field-flag byte.
    #[test]
    fn mem3blt_reads_colors_and_brush() {
        let mut bytes = vec![
            TS_STANDARD | TS_TYPE_CHANGE,
            TS_ENC_MEM3BLT_ORDER,
            0x00,
            0xFF, // BackColor … BrushExtra, cacheIndex
            0x00,
        ];
        bytes.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        bytes.extend_from_slice(&[(-1i8) as u8, 3, 0x03, 0x01, 2, 4, 8, 16, 32, 64, 128]);
        bytes.extend_from_slice(&9u16.to_le_bytes());
        let mut history = OrderHistory::default();
        let Ok(DrawingOrder::Mem3Blt { order, .. }) = decode_all(&bytes, &mut history)[0] else {
            panic!();
        };
        assert_eq!(order.back_color, 0x33_2211);
        assert_eq!(order.fore_color, 0x66_5544);
        assert_eq!(
            order.brush,
            Brush {
                org_x: -1,
                org_y: 3,
                style: 0x03,
                hatch: 0x01,
                extra: [2, 4, 8, 16, 32, 64, 128]
            }
        );
        assert_eq!(order.blt.cache_index, 9);
    }

    fn cache_bitmap_rev2(order_type: u8, extra_flags: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![TS_STANDARD | TS_SECONDARY];
        bytes.extend_from_slice(&((body.len() as i16) - 7).to_le_bytes());
        bytes.extend_from_slice(&extra_flags.to_le_bytes());
        bytes.push(order_type);
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn cache_bitmap_rev2_decodes_its_header_and_strips_the_compression_header() {
        // cacheId 2, 16 bpp, square; width 64, bitmapLength 8 + 3, cacheIndex 0x1234.
        let extra = 2 | (0x4 << 3) | (CBR2_HEIGHT_SAME_AS_WIDTH << 7);
        let mut body = vec![64, 11, 0x92, 0x34];
        body.extend_from_slice(&[0, 0, 3, 0, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC]);
        let bytes = cache_bitmap_rev2(TS_CACHE_BITMAP_COMPRESSED_REV2, extra, &body);
        let mut history = OrderHistory::default();
        assert_eq!(
            decode_all(&bytes, &mut history),
            [Ok(DrawingOrder::CacheBitmapRev2(CacheBitmapRev2 {
                cache_id: 2,
                bits_per_pixel: 16,
                flags: CBR2_HEIGHT_SAME_AS_WIDTH,
                key: None,
                width: 64,
                height: 64,
                cache_index: 0x1234,
                compressed: true,
                data: &[0xAA, 0xBB, 0xCC],
            }))]
        );
    }

    /// CBR2_DO_NOT_CACHE overrides the wire `cacheIndex`; the key is `key2:key1`.
    #[test]
    fn cache_bitmap_rev2_keys_and_waiting_list() {
        let flags = CBR2_PERSISTENT_KEY_PRESENT | CBR2_DO_NOT_CACHE;
        let extra = 1 | (0x6 << 3) | (flags << 7);
        let mut body = Vec::new();
        body.extend_from_slice(&0x1111_2222u32.to_le_bytes());
        body.extend_from_slice(&0x3333_4444u32.to_le_bytes());
        body.extend_from_slice(&[2, 1, 4, 0x05]);
        body.extend_from_slice(&[1, 2, 3, 4]);
        let bytes = cache_bitmap_rev2(TS_CACHE_BITMAP_UNCOMPRESSED_REV2, extra, &body);
        let mut history = OrderHistory::default();
        let Ok(DrawingOrder::CacheBitmapRev2(order)) = decode_all(&bytes, &mut history)[0] else {
            panic!();
        };
        assert_eq!(order.key, Some(0x3333_4444_1111_2222));
        assert_eq!((order.width, order.height), (2, 1));
        assert_eq!(order.cache_index, BITMAPCACHE_WAITING_LIST_INDEX);
        assert_eq!(order.data, &[1, 2, 3, 4]);
    }

    /// A secondary order of another type is skipped by its length, and the next order decodes.
    #[test]
    fn other_secondary_orders_are_skipped_by_length() {
        let mut bytes = cache_bitmap_rev2(0x07, 0, &[0; 9]);
        bytes.extend_from_slice(&[TS_STANDARD | TS_TYPE_CHANGE, TS_ENC_MEMBLT_ORDER, 0, 0]);
        let mut history = OrderHistory::default();
        let orders = decode_all(&bytes, &mut history);
        assert_eq!(
            orders[0],
            Ok(DrawingOrder::SkippedSecondary { order_type: 0x07 })
        );
        assert!(matches!(orders[1], Ok(DrawingOrder::MemBlt { .. })));
    }

    #[test]
    fn alternate_secondary_orders_stop_the_update() {
        let mut history = OrderHistory::default();
        assert_eq!(
            decode_all(&[0x0D << 2 | TS_SECONDARY], &mut history),
            [Err(OrderError::Unsupported {
                class: OrderClass::AlternateSecondary,
                order_type: 0x0D
            })]
        );
    }

    proptest::proptest! {
        /// Arbitrary bytes decode to orders or a typed error, never a panic (ADR-0008).
        #[test]
        fn orders_never_panic(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            let mut history = OrderHistory::default();
            let _ = decode_all(&bytes, &mut history);
        }
    }
}
