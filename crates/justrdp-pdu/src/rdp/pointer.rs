#![forbid(unsafe_code)]

//! Pointer Attribute PDU types -- MS-RDPBCGR 2.2.9.1.1.4.x (slow-path) /
//! 2.2.9.1.2.1.5–11 (fast-path payloads).
//!
//! These structures are the inner payloads of either a slow-path
//! `TS_POINTER_PDU` (MS-RDPBCGR 2.2.9.1.1.4) or one of the fast-path
//! pointer update types (`FASTPATH_UPDATETYPE_PTR_*`).

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

// ── Slow-path TS_POINTER_PDU messageType constants ──
// MS-RDPBCGR 2.2.9.1.1.4

/// `TS_PTRMSGTYPE_SYSTEM` -- system pointer update.
pub const TS_PTRMSGTYPE_SYSTEM: u16 = 0x0001;
/// `TS_PTRMSGTYPE_POSITION` -- pointer position update.
pub const TS_PTRMSGTYPE_POSITION: u16 = 0x0003;
/// `TS_PTRMSGTYPE_COLOR` -- color pointer update (24-bpp XOR mask).
pub const TS_PTRMSGTYPE_COLOR: u16 = 0x0006;
/// `TS_PTRMSGTYPE_CACHED` -- cached pointer update (cacheIndex only).
pub const TS_PTRMSGTYPE_CACHED: u16 = 0x0007;
/// `TS_PTRMSGTYPE_POINTER` -- new-style pointer update with explicit `xorBpp`.
pub const TS_PTRMSGTYPE_POINTER: u16 = 0x0008;
/// `TS_PTRMSGTYPE_LARGE_POINTER` -- 384x384 pointer (MS-RDPBCGR 2.2.9.1.1.4.7).
pub const TS_PTRMSGTYPE_LARGE_POINTER: u16 = 0x0009;

/// `SYSPTR_NULL` -- hide the pointer (for `TS_SYSTEMPOINTERATTRIBUTE`).
pub const SYSPTR_NULL: u32 = 0x0000_0000;
/// `SYSPTR_DEFAULT` -- show the default pointer.
pub const SYSPTR_DEFAULT: u32 = 0x0000_7F00;

// ── TS_POINT16 ──

/// 2-D point with `u16` coordinates -- MS-RDPBCGR 2.2.9.1.1.4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TsPoint16 {
    pub x_pos: u16,
    pub y_pos: u16,
}

/// Wire size of `TS_POINT16`.
pub const TS_POINT16_SIZE: usize = 4;

impl Encode for TsPoint16 {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.x_pos, "TsPoint16::xPos")?;
        dst.write_u16_le(self.y_pos, "TsPoint16::yPos")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TsPoint16"
    }

    fn size(&self) -> usize {
        TS_POINT16_SIZE
    }
}

impl<'de> Decode<'de> for TsPoint16 {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            x_pos: src.read_u16_le("TsPoint16::xPos")?,
            y_pos: src.read_u16_le("TsPoint16::yPos")?,
        })
    }
}

// ── TS_CACHEDPOINTERATTRIBUTE ──

/// Cached pointer attribute -- MS-RDPBCGR 2.2.9.1.1.4.6.
///
/// Refers to a previously-sent color or new-style pointer by cache index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TsCachedPointerAttribute {
    pub cache_index: u16,
}

/// Wire size of `TS_CACHEDPOINTERATTRIBUTE`.
pub const TS_CACHED_POINTER_ATTRIBUTE_SIZE: usize = 2;

impl Encode for TsCachedPointerAttribute {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.cache_index, "TsCachedPointerAttribute::cacheIndex")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TsCachedPointerAttribute"
    }

    fn size(&self) -> usize {
        TS_CACHED_POINTER_ATTRIBUTE_SIZE
    }
}

impl<'de> Decode<'de> for TsCachedPointerAttribute {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            cache_index: src.read_u16_le("TsCachedPointerAttribute::cacheIndex")?,
        })
    }
}

// ── TS_COLORPOINTERATTRIBUTE ──

/// Color pointer attribute -- MS-RDPBCGR 2.2.9.1.1.4.4.
///
/// The `xor_mask_data` byte stream is interpreted as 24-bpp pixel data when
/// used directly via [`TS_PTRMSGTYPE_COLOR`] / `FASTPATH_UPDATETYPE_PTR_COLOR`.
/// When wrapped inside a [`TsPointerAttribute`] (new-style pointer), the
/// pixel format is given by the outer `xor_bpp` field.
///
/// `width` and `height` are pixel dimensions of the cursor:
/// - For `TS_PTRMSGTYPE_COLOR` callers: MUST be at most 32×32 per the spec.
/// - For `TS_PTRMSGTYPE_POINTER` callers: bounded by the negotiated
///   `pointerCacheSize` from the Pointer Capability Set.
///
/// The optional trailing `pad` byte from MS-RDPBCGR 2.2.9.1.1.4.4 is **not**
/// emitted by [`Encode`] and is **not** consumed by [`Decode`]; receivers
/// MUST ignore any extra trailing byte per the spec, and senders that need
/// the padding MUST add it at the wrapping layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsColorPointerAttribute {
    pub cache_index: u16,
    pub hot_spot: TsPoint16,
    pub width: u16,
    pub height: u16,
    /// `xorMaskData` -- variable-length pixel data for the visible cursor
    /// (24-bpp for color pointer; outer `xor_bpp` controls interpretation in
    /// `TS_POINTERATTRIBUTE`). The buffer length MUST equal the value the
    /// encoder will emit in the `lengthXorMask` field.
    pub xor_mask_data: Vec<u8>,
    /// `andMaskData` -- 1-bpp transparency mask, bottom-up, each scan-line
    /// padded to a 2-byte boundary per the spec.
    pub and_mask_data: Vec<u8>,
}

/// Fixed prefix size of `TS_COLORPOINTERATTRIBUTE`
/// (cacheIndex + hotSpot + width + height + lengthAndMask + lengthXorMask).
pub const TS_COLOR_POINTER_ATTRIBUTE_FIXED_SIZE: usize = 2 + TS_POINT16_SIZE + 2 + 2 + 2 + 2;

impl Encode for TsColorPointerAttribute {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.and_mask_data.len() > u16::MAX as usize {
            return Err(EncodeError::other(
                "TsColorPointerAttribute",
                "andMaskData exceeds u16::MAX",
            ));
        }
        if self.xor_mask_data.len() > u16::MAX as usize {
            return Err(EncodeError::other(
                "TsColorPointerAttribute",
                "xorMaskData exceeds u16::MAX",
            ));
        }
        dst.write_u16_le(self.cache_index, "TsColorPointerAttribute::cacheIndex")?;
        self.hot_spot.encode(dst)?;
        dst.write_u16_le(self.width, "TsColorPointerAttribute::width")?;
        dst.write_u16_le(self.height, "TsColorPointerAttribute::height")?;
        dst.write_u16_le(
            self.and_mask_data.len() as u16,
            "TsColorPointerAttribute::lengthAndMask",
        )?;
        dst.write_u16_le(
            self.xor_mask_data.len() as u16,
            "TsColorPointerAttribute::lengthXorMask",
        )?;
        dst.write_slice(&self.xor_mask_data, "TsColorPointerAttribute::xorMaskData")?;
        dst.write_slice(&self.and_mask_data, "TsColorPointerAttribute::andMaskData")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TsColorPointerAttribute"
    }

    fn size(&self) -> usize {
        TS_COLOR_POINTER_ATTRIBUTE_FIXED_SIZE + self.xor_mask_data.len() + self.and_mask_data.len()
    }
}

impl TsColorPointerAttribute {
    /// Decode a color pointer attribute whose XOR mask uses the given
    /// bit depth. `TS_PTRMSGTYPE_COLOR` callers go through the
    /// [`Decode`] trait (which assumes 24 bpp); `TsPointerAttribute`
    /// (new-style) calls this with the outer `xor_bpp` field so the
    /// embedded mask length check picks the right stride.
    ///
    /// Validates `lengthXorMask == xor_mask_row_stride(width, xor_bpp) *
    /// height` and `lengthAndMask == and_mask_row_stride(width) *
    /// height` (both per MS-RDPBCGR §2.2.9.1.1.4.4 / §2.2.9.1.1.4.5).
    /// A wire-supplied length that disagrees with the declared
    /// dimensions is a hostile or corrupt PDU and is rejected before
    /// the slice is read.
    pub fn decode_with_bpp(src: &mut ReadCursor<'_>, xor_bpp: u16) -> DecodeResult<Self> {
        let cache_index = src.read_u16_le("TsColorPointerAttribute::cacheIndex")?;
        let hot_spot = TsPoint16::decode(src)?;
        let width = src.read_u16_le("TsColorPointerAttribute::width")?;
        let height = src.read_u16_le("TsColorPointerAttribute::height")?;
        let length_and_mask =
            src.read_u16_le("TsColorPointerAttribute::lengthAndMask")? as usize;
        let length_xor_mask =
            src.read_u16_le("TsColorPointerAttribute::lengthXorMask")? as usize;
        let expected_xor = xor_mask_row_stride(width, xor_bpp)
            .saturating_mul(usize::from(height));
        let expected_and = and_mask_row_stride(width).saturating_mul(usize::from(height));
        if length_xor_mask != expected_xor {
            return Err(DecodeError::invalid_value(
                "TsColorPointerAttribute",
                "lengthXorMask disagrees with width * xor_bpp / 8 padded * height",
            ));
        }
        if length_and_mask != expected_and {
            return Err(DecodeError::invalid_value(
                "TsColorPointerAttribute",
                "lengthAndMask disagrees with ceil(width / 8) padded * height",
            ));
        }
        let xor_mask_data = src
            .read_slice(length_xor_mask, "TsColorPointerAttribute::xorMaskData")?
            .to_vec();
        let and_mask_data = src
            .read_slice(length_and_mask, "TsColorPointerAttribute::andMaskData")?
            .to_vec();
        Ok(Self {
            cache_index,
            hot_spot,
            width,
            height,
            xor_mask_data,
            and_mask_data,
        })
    }
}

impl<'de> Decode<'de> for TsColorPointerAttribute {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        // TS_PTRMSGTYPE_COLOR mandates 24-bpp XOR data per
        // MS-RDPBCGR §2.2.9.1.1.4.4.
        Self::decode_with_bpp(src, 24)
    }
}

// ── TS_POINTERATTRIBUTE ──

/// New-style pointer attribute -- MS-RDPBCGR 2.2.9.1.1.4.5.
///
/// Wraps a [`TsColorPointerAttribute`] with an explicit `xor_bpp` field that
/// controls the pixel format of the inner `xor_mask_data`. Valid values for
/// `xor_bpp`: `1`, `4`, `8`, `16`, `24`, `32` per the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsPointerAttribute {
    pub xor_bpp: u16,
    pub color_ptr_attr: TsColorPointerAttribute,
}

impl Encode for TsPointerAttribute {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.xor_bpp, "TsPointerAttribute::xorBpp")?;
        self.color_ptr_attr.encode(dst)
    }

    fn name(&self) -> &'static str {
        "TsPointerAttribute"
    }

    fn size(&self) -> usize {
        2 + self.color_ptr_attr.size()
    }
}

impl<'de> Decode<'de> for TsPointerAttribute {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let xor_bpp = src.read_u16_le("TsPointerAttribute::xorBpp")?;
        // Validate xor_bpp is one of the spec's legal values before
        // propagating it into the mask-length check; an invalid value
        // would otherwise compute nonsensical expected strides.
        if !matches!(xor_bpp, 1 | 4 | 8 | 16 | 24 | 32) {
            return Err(DecodeError::invalid_value(
                "TsPointerAttribute",
                "xorBpp must be one of 1/4/8/16/24/32",
            ));
        }
        let color_ptr_attr = TsColorPointerAttribute::decode_with_bpp(src, xor_bpp)?;
        Ok(Self {
            xor_bpp,
            color_ptr_attr,
        })
    }
}

// ── Helpers ──

/// Per-row stride (in bytes) for an AND mask, padded to a 2-byte boundary
/// per MS-RDPBCGR 2.2.9.1.1.4.4.
pub fn and_mask_row_stride(width: u16) -> usize {
    let row_bytes = (usize::from(width) + 7) / 8;
    (row_bytes + 1) & !1
}

/// Per-row stride (in bytes) for an XOR mask of the given bit depth.
///
/// Per MS-RDPBCGR 2.2.9.1.1.4.4 / 2.2.9.1.1.4.5: scan-lines are padded to a
/// 2-byte boundary. For depths that are an integral multiple of 16 bits per
/// pixel (16/32) the natural stride is already even, so the pad is a no-op.
pub fn xor_mask_row_stride(width: u16, xor_bpp: u16) -> usize {
    let row_bytes = (usize::from(width) * usize::from(xor_bpp) + 7) / 8;
    (row_bytes + 1) & !1
}

/// Reject [`DecodeError`] when the spec's hard 32×32 bound for
/// `TS_PTRMSGTYPE_COLOR` is violated. Convenience helper for callers that
/// validate the slow-path color-pointer path.
pub fn validate_color_pointer_dimensions(width: u16, height: u16) -> DecodeResult<()> {
    if width > 32 || height > 32 {
        return Err(DecodeError::invalid_value(
            "TsColorPointerAttribute",
            "width/height (must be <= 32 for TS_PTRMSGTYPE_COLOR)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn encode_to_vec<E: Encode>(v: &E) -> Vec<u8> {
        let mut buf = vec![0u8; v.size()];
        let mut c = WriteCursor::new(&mut buf);
        v.encode(&mut c).unwrap();
        buf
    }

    #[test]
    fn ts_point16_roundtrip() {
        let p = TsPoint16 { x_pos: 0x1234, y_pos: 0x5678 };
        let buf = encode_to_vec(&p);
        assert_eq!(buf, [0x34, 0x12, 0x78, 0x56]);
        let mut c = ReadCursor::new(&buf);
        assert_eq!(TsPoint16::decode(&mut c).unwrap(), p);
    }

    #[test]
    fn ts_cached_pointer_roundtrip() {
        let p = TsCachedPointerAttribute { cache_index: 5 };
        let buf = encode_to_vec(&p);
        assert_eq!(buf, [0x05, 0x00]);
        let mut c = ReadCursor::new(&buf);
        assert_eq!(TsCachedPointerAttribute::decode(&mut c).unwrap(), p);
    }

    #[test]
    fn ts_color_pointer_roundtrip_minimal() {
        // 1×1 cursor:
        //   XOR mask @ 24bpp: row_bytes = 3 → padded to 4-byte stride.
        //   AND mask:         row_bytes = 1 → padded to 2-byte stride.
        let p = TsColorPointerAttribute {
            cache_index: 0,
            hot_spot: TsPoint16 { x_pos: 0, y_pos: 0 },
            width: 1,
            height: 1,
            xor_mask_data: vec![0xFF, 0x00, 0x00, 0x00],
            and_mask_data: vec![0x00, 0x00],
        };
        let buf = encode_to_vec(&p);
        assert_eq!(
            buf.len(),
            TS_COLOR_POINTER_ATTRIBUTE_FIXED_SIZE + 4 + 2
        );
        let mut c = ReadCursor::new(&buf);
        assert_eq!(TsColorPointerAttribute::decode(&mut c).unwrap(), p);
    }

    #[test]
    fn ts_color_pointer_roundtrip_max_size() {
        // 32×32 color cursor: XOR=32×32×3=3072 bytes, AND=ceil(32/8)=4×32=128 bytes
        let p = TsColorPointerAttribute {
            cache_index: 1,
            hot_spot: TsPoint16 { x_pos: 16, y_pos: 16 },
            width: 32,
            height: 32,
            xor_mask_data: vec![0xAA; 32 * 32 * 3],
            and_mask_data: vec![0xBB; 4 * 32],
        };
        let buf = encode_to_vec(&p);
        let mut c = ReadCursor::new(&buf);
        assert_eq!(TsColorPointerAttribute::decode(&mut c).unwrap(), p);
    }

    #[test]
    fn ts_pointer_attribute_roundtrip_32bpp() {
        // 16×16 new-style cursor at 32 bpp: XOR = 16×16×4 = 1024, AND = 2×16 = 32
        let p = TsPointerAttribute {
            xor_bpp: 32,
            color_ptr_attr: TsColorPointerAttribute {
                cache_index: 7,
                hot_spot: TsPoint16 { x_pos: 8, y_pos: 8 },
                width: 16,
                height: 16,
                xor_mask_data: vec![0x11; 16 * 16 * 4],
                and_mask_data: vec![0x22; 2 * 16],
            },
        };
        let buf = encode_to_vec(&p);
        let mut c = ReadCursor::new(&buf);
        assert_eq!(TsPointerAttribute::decode(&mut c).unwrap(), p);
    }

    #[test]
    fn ts_pointer_attribute_roundtrip_1bpp() {
        // 96×96 new-style cursor at 1 bpp: XOR = 12×96 = 1152, AND = 12×96 = 1152
        let p = TsPointerAttribute {
            xor_bpp: 1,
            color_ptr_attr: TsColorPointerAttribute {
                cache_index: 0,
                hot_spot: TsPoint16 { x_pos: 0, y_pos: 0 },
                width: 96,
                height: 96,
                xor_mask_data: vec![0xFF; 12 * 96],
                and_mask_data: vec![0x00; 12 * 96],
            },
        };
        let buf = encode_to_vec(&p);
        let mut c = ReadCursor::new(&buf);
        assert_eq!(TsPointerAttribute::decode(&mut c).unwrap(), p);
    }

    #[test]
    fn and_mask_stride_pad() {
        assert_eq!(and_mask_row_stride(1), 2); // 1 px → 1 byte → padded to 2
        assert_eq!(and_mask_row_stride(7), 2); // 7 px → 1 byte → padded to 2
        assert_eq!(and_mask_row_stride(8), 2); // 8 px → 1 byte → padded to 2
        assert_eq!(and_mask_row_stride(9), 2); // 9 px → 2 bytes (already aligned)
        assert_eq!(and_mask_row_stride(16), 2);
        assert_eq!(and_mask_row_stride(17), 4); // 17 px → 3 bytes → padded to 4
        assert_eq!(and_mask_row_stride(32), 4);
        assert_eq!(and_mask_row_stride(96), 12);
    }

    #[test]
    fn xor_mask_stride_various_bpp() {
        // 32 px @ 24 bpp = 96 bytes (already even)
        assert_eq!(xor_mask_row_stride(32, 24), 96);
        // 7 px @ 24 bpp = 21 → padded to 22
        assert_eq!(xor_mask_row_stride(7, 24), 22);
        // 32 px @ 32 bpp = 128 (even)
        assert_eq!(xor_mask_row_stride(32, 32), 128);
        // 17 px @ 1 bpp = 3 → padded to 4
        assert_eq!(xor_mask_row_stride(17, 1), 4);
        // 9 px @ 4 bpp = 5 → padded to 6
        assert_eq!(xor_mask_row_stride(9, 4), 6);
    }

    #[test]
    fn ts_color_pointer_decode_rejects_mismatched_xor_length() {
        // W-2 regression: a hostile peer sets lengthXorMask to 65535 on
        // a 1x1 cursor. The decoder MUST refuse before reading the
        // 64 KiB slice -- otherwise downstream callers that derive the
        // stride from width/height would mis-slice the buffer.
        let mut buf = vec![0u8; TS_COLOR_POINTER_ATTRIBUTE_FIXED_SIZE];
        let mut c = WriteCursor::new(&mut buf);
        c.write_u16_le(0, "cacheIndex").unwrap();
        c.write_u16_le(0, "hotSpot.x").unwrap();
        c.write_u16_le(0, "hotSpot.y").unwrap();
        c.write_u16_le(1, "width").unwrap();
        c.write_u16_le(1, "height").unwrap();
        c.write_u16_le(2, "lengthAndMask (correct)").unwrap();
        c.write_u16_le(0xFFFF, "lengthXorMask (bogus)").unwrap();
        let mut rc = ReadCursor::new(&buf);
        assert!(TsColorPointerAttribute::decode(&mut rc).is_err());
    }

    #[test]
    fn ts_color_pointer_decode_rejects_mismatched_and_length() {
        let mut buf = vec![0u8; TS_COLOR_POINTER_ATTRIBUTE_FIXED_SIZE];
        let mut c = WriteCursor::new(&mut buf);
        c.write_u16_le(0, "cacheIndex").unwrap();
        c.write_u16_le(0, "hotSpot.x").unwrap();
        c.write_u16_le(0, "hotSpot.y").unwrap();
        c.write_u16_le(1, "width").unwrap();
        c.write_u16_le(1, "height").unwrap();
        c.write_u16_le(0xFFFF, "lengthAndMask (bogus)").unwrap();
        c.write_u16_le(4, "lengthXorMask (correct)").unwrap();
        let mut rc = ReadCursor::new(&buf);
        assert!(TsColorPointerAttribute::decode(&mut rc).is_err());
    }

    #[test]
    fn ts_pointer_attribute_decode_rejects_invalid_xor_bpp() {
        // W-2 regression: TsPointerAttribute MUST validate xor_bpp ∈
        // {1,4,8,16,24,32} before propagating it to the inner mask
        // length check (which would otherwise compute a stride from a
        // garbage bpp).
        let mut buf = vec![0u8; 2];
        let mut c = WriteCursor::new(&mut buf);
        c.write_u16_le(64, "xorBpp invalid").unwrap();
        let mut rc = ReadCursor::new(&buf);
        assert!(TsPointerAttribute::decode(&mut rc).is_err());
    }

    #[test]
    fn ts_pointer_attribute_decode_with_xor_bpp_propagates_to_mask_check() {
        // Build a 4x4 @ 1bpp pointer (XOR stride = 2 bytes/row * 4 = 8;
        // AND stride = 2 bytes/row * 4 = 8). A correct PDU MUST round-trip;
        // mutating lengthXorMask to be wrong (e.g., 4) MUST be rejected.
        let attr = TsPointerAttribute {
            xor_bpp: 1,
            color_ptr_attr: TsColorPointerAttribute {
                cache_index: 0,
                hot_spot: TsPoint16::default(),
                width: 4,
                height: 4,
                xor_mask_data: vec![0xAA; 8],
                and_mask_data: vec![0x55; 8],
            },
        };
        let buf = encode_to_vec(&attr);
        // Sanity: round-trips via Decode trait.
        let mut rc = ReadCursor::new(&buf);
        assert_eq!(TsPointerAttribute::decode(&mut rc).unwrap(), attr);
    }

    #[test]
    fn validate_color_pointer_bounds() {
        assert!(validate_color_pointer_dimensions(32, 32).is_ok());
        assert!(validate_color_pointer_dimensions(33, 32).is_err());
        assert!(validate_color_pointer_dimensions(32, 33).is_err());
        assert!(validate_color_pointer_dimensions(0, 0).is_ok());
    }

    #[test]
    fn ts_color_pointer_size_matches_encoded() {
        let p = TsColorPointerAttribute {
            cache_index: 0,
            hot_spot: TsPoint16::default(),
            width: 32,
            height: 32,
            xor_mask_data: vec![0; 32 * 32 * 3],
            and_mask_data: vec![0; 4 * 32],
        };
        assert_eq!(encode_to_vec(&p).len(), p.size());
    }

    #[test]
    fn ts_pointer_attribute_size_matches_encoded() {
        let p = TsPointerAttribute {
            xor_bpp: 32,
            color_ptr_attr: TsColorPointerAttribute {
                cache_index: 0,
                hot_spot: TsPoint16::default(),
                width: 16,
                height: 16,
                xor_mask_data: vec![0; 16 * 16 * 4],
                and_mask_data: vec![0; 2 * 16],
            },
        };
        assert_eq!(encode_to_vec(&p).len(), p.size());
    }
}
