#![forbid(unsafe_code)]

//! Pointer/cursor bitmap decoder (MS-RDPBCGR §2.2.9.1.1.4).
//!
//! Decodes XOR/AND mask pointer bitmaps into BGRA pixel buffers.
//! Supports 1bpp, 24bpp, 32bpp pointers and large pointers (up to 384×384).

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

// ── Error type ──

/// Pointer decode error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerError {
    TruncatedData,
    UnsupportedBpp(u16),
    /// Pointer dimensions exceed the maximum (384×384, MS-RDPBCGR §2.2.9.1.1.4.4).
    DimensionTooLarge,
    InvalidCacheIndex(u16),
    EmptyCacheSlot(u16),
    MaskSizeMismatch,
}

impl fmt::Display for PointerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedData => write!(f, "Pointer: truncated data"),
            Self::UnsupportedBpp(bpp) => write!(f, "Pointer: unsupported bpp {bpp}"),
            Self::DimensionTooLarge => write!(f, "Pointer: dimensions exceed 384×384"),
            Self::InvalidCacheIndex(idx) => write!(f, "Pointer: invalid cache index {idx}"),
            Self::EmptyCacheSlot(idx) => write!(f, "Pointer: empty cache slot {idx}"),
            Self::MaskSizeMismatch => write!(f, "Pointer: mask size mismatch"),
        }
    }
}

// ── Decoded pointer shape ──

/// A decoded pointer/cursor shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerShape {
    /// Cursor width in pixels.
    pub width: u16,
    /// Cursor height in pixels.
    pub height: u16,
    /// Hotspot X coordinate.
    pub hotspot_x: u16,
    /// Hotspot Y coordinate.
    pub hotspot_y: u16,
    /// BGRA pixels, top-down row-major, `width * height * 4` bytes.
    pub pixels: Vec<u8>,
    /// Invert mask: 1 bit per pixel (packed, MSB-first), `ceil(width * height / 8)` bytes.
    /// A set bit means the pixel should be XOR-blended with the destination
    /// (AND=1, XOR=non-black). The `pixels` field contains the XOR color for
    /// these pixels (typically white). Callers that support invert cursors
    /// should check this mask; others can ignore it and render opaque.
    pub invert_mask: Vec<u8>,
}

// ── Stride calculation ──

/// Compute scanline stride padded to 2-byte boundary.
#[inline]
fn padded_stride(bytes_per_row: usize) -> usize {
    (bytes_per_row + 1) & !1
}

/// AND mask stride for a given width (1bpp, padded to 2-byte boundary).
#[inline]
fn and_mask_stride(width: usize) -> usize {
    padded_stride((width + 7) / 8)
}

/// XOR mask stride for a given width and bpp (padded to 2-byte boundary).
/// XOR mask stride for a given width and bpp (padded to 2-byte boundary).
/// Only called after bpp is validated to be in {1, 16, 24, 32}.
fn xor_mask_stride(width: usize, bpp: u16) -> usize {
    let bytes_per_row = match bpp {
        1 => (width + 7) / 8,
        16 => width * 2,
        24 => width * 3,
        32 => width * 4,
        // Caller must validate bpp before calling this function.
        _ => unreachable!("xor_mask_stride called with unsupported bpp: {bpp}"),
    };
    padded_stride(bytes_per_row)
}

// ── XOR pixel extraction ──

/// Extract a pixel at column `x` from a scanline in the XOR mask.
/// Returns (B, G, R, A).
fn extract_xor_pixel(row: &[u8], x: usize, bpp: u16) -> (u8, u8, u8, u8) {
    match bpp {
        1 => {
            let byte_idx = x / 8;
            let bit_idx = 7 - (x % 8);
            if byte_idx < row.len() {
                let bit = (row[byte_idx] >> bit_idx) & 1;
                let val = if bit != 0 { 0xFF } else { 0x00 };
                (val, val, val, 0xFF)
            } else {
                (0, 0, 0, 0xFF)
            }
        }
        16 => {
            let off = x * 2;
            if off + 2 <= row.len() {
                let word = u16::from_le_bytes([row[off], row[off + 1]]);
                // BGR565: bits[4:0]=B(5), bits[10:5]=G(6), bits[15:11]=R(5)
                // Shift to 8-bit: B<<3, G via (word>>3)&0xFC, R via (word>>8)&0xF8
                let b = ((word & 0x001F) << 3) as u8;
                let g = ((word >> 3) & 0xFC) as u8;
                let r = ((word >> 8) & 0xF8) as u8;
                (b, g, r, 0xFF)
            } else {
                (0, 0, 0, 0xFF)
            }
        }
        24 => {
            let off = x * 3;
            if off + 3 <= row.len() {
                (row[off], row[off + 1], row[off + 2], 0xFF)
            } else {
                (0, 0, 0, 0xFF)
            }
        }
        32 => {
            let off = x * 4;
            if off + 4 <= row.len() {
                (row[off], row[off + 1], row[off + 2], row[off + 3])
            } else {
                (0, 0, 0, 0)
            }
        }
        _ => (0, 0, 0, 0xFF),
    }
}

/// Extract AND mask bit at column `x` from a scanline row.
/// Returns 0 or 1.
fn extract_and_bit(row: &[u8], x: usize) -> u8 {
    let byte_idx = x / 8;
    let bit_idx = 7 - (x % 8);
    if byte_idx < row.len() {
        (row[byte_idx] >> bit_idx) & 1
    } else {
        1 // default: transparent
    }
}

// ── Main decode function ──

/// Decode a pointer bitmap from XOR and AND mask data.
///
/// # Arguments
///
/// * `width` - Pointer width in pixels (max 384)
/// * `height` - Pointer height in pixels (max 384)
/// * `hotspot_x` - Hotspot X
/// * `hotspot_y` - Hotspot Y
/// * `xor_bpp` - Color depth of XOR mask (1, 16, 24, or 32)
/// * `xor_mask` - XOR mask data (bottom-up scanlines)
/// * `and_mask` - AND mask data (1bpp bottom-up scanlines; ignored for 32bpp)
pub fn decode_pointer(
    width: u16,
    height: u16,
    hotspot_x: u16,
    hotspot_y: u16,
    xor_bpp: u16,
    xor_mask: &[u8],
    and_mask: &[u8],
) -> Result<PointerShape, PointerError> {
    let w = width as usize;
    let h = height as usize;

    if w == 0 || h == 0 {
        return Ok(PointerShape {
            width,
            height,
            hotspot_x,
            hotspot_y,
            pixels: Vec::new(),
            invert_mask: Vec::new(),
        });
    }

    // MS-RDPBCGR §2.2.9.1.1.4.4: large pointer max is 384×384
    const MAX_POINTER_DIM: usize = 384;
    if w > MAX_POINTER_DIM || h > MAX_POINTER_DIM {
        return Err(PointerError::DimensionTooLarge);
    }

    match xor_bpp {
        1 | 16 | 24 | 32 => {}
        // 4bpp and 8bpp require a palette which is not available in this context
        _ => return Err(PointerError::UnsupportedBpp(xor_bpp)),
    }

    let xor_stride = xor_mask_stride(w, xor_bpp);
    let and_stride = and_mask_stride(w);
    let use_and_mask = xor_bpp != 32; // 32bpp uses alpha from XOR data

    let expected_xor = xor_stride.checked_mul(h).ok_or(PointerError::DimensionTooLarge)?;
    let expected_and = and_stride.checked_mul(h).ok_or(PointerError::DimensionTooLarge)?;

    if xor_mask.len() < expected_xor {
        return Err(PointerError::MaskSizeMismatch);
    }
    if use_and_mask && and_mask.len() < expected_and {
        return Err(PointerError::MaskSizeMismatch);
    }

    let pixel_count = w.checked_mul(h).ok_or(PointerError::DimensionTooLarge)?;
    let mut pixels = vec![0u8; pixel_count * 4];
    // Only allocate invert_mask when AND mask is used (non-32bpp).
    // For 32bpp, alpha comes directly from XOR data and invert is never set.
    let mut invert_mask = if use_and_mask {
        vec![0u8; (pixel_count + 7) / 8]
    } else {
        Vec::new()
    };

    for y in 0..h {
        // Bottom-up: wire row 0 = bottom row
        let src_row = h - 1 - y;
        let xor_row_start = src_row * xor_stride;
        let xor_row = &xor_mask[xor_row_start..xor_row_start + xor_stride];

        let and_row = if use_and_mask {
            let and_row_start = src_row * and_stride;
            &and_mask[and_row_start..and_row_start + and_stride]
        } else {
            &[]
        };

        for x in 0..w {
            let (b, g, r, mut a) = extract_xor_pixel(xor_row, x, xor_bpp);
            let mut is_invert = false;

            if use_and_mask {
                let and_bit = extract_and_bit(and_row, x);
                if and_bit == 0 {
                    if b == 0 && g == 0 && r == 0 {
                        a = 0; // transparent
                    } else {
                        a = 0xFF; // opaque
                    }
                } else {
                    // AND=1: transparent or invert
                    if b == 0 && g == 0 && r == 0 {
                        a = 0; // transparent
                    } else {
                        a = 0xFF; // invert pixel — mark in invert_mask
                        is_invert = true;
                    }
                }
            }

            let pixel_idx = y * w + x;
            let dst = pixel_idx * 4;
            pixels[dst] = b;
            pixels[dst + 1] = g;
            pixels[dst + 2] = r;
            pixels[dst + 3] = a;

            if is_invert {
                let byte_idx = pixel_idx / 8;
                let bit_idx = 7 - (pixel_idx % 8);
                invert_mask[byte_idx] |= 1 << bit_idx;
            }
        }
    }

    Ok(PointerShape {
        width,
        height,
        hotspot_x,
        hotspot_y,
        pixels,
        invert_mask,
    })
}

// ── Pointer cache ──

/// Pointer shape cache.
#[derive(Debug, Clone)]
pub struct PointerCache {
    slots: Vec<Option<PointerShape>>,
}

impl PointerCache {
    /// Create a new cache with the given capacity.
    ///
    /// A capacity of 0 produces an empty cache where all operations return `InvalidCacheIndex`.
    pub fn new(capacity: usize) -> Self {
        debug_assert!(capacity > 0, "PointerCache created with zero capacity");
        let mut slots = Vec::with_capacity(capacity);
        slots.resize_with(capacity, || None);
        Self { slots }
    }

    /// Store a pointer shape at the given cache index.
    pub fn set(&mut self, index: u16, shape: PointerShape) -> Result<(), PointerError> {
        let idx = index as usize;
        if idx >= self.slots.len() {
            return Err(PointerError::InvalidCacheIndex(index));
        }
        self.slots[idx] = Some(shape);
        Ok(())
    }

    /// Retrieve a pointer shape from the cache.
    pub fn get(&self, index: u16) -> Result<&PointerShape, PointerError> {
        let idx = index as usize;
        if idx >= self.slots.len() {
            return Err(PointerError::InvalidCacheIndex(index));
        }
        self.slots[idx].as_ref().ok_or(PointerError::EmptyCacheSlot(index))
    }

    /// Clear all cache slots.
    pub fn clear(&mut self) {
        for slot in &mut self.slots {
            *slot = None;
        }
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stride_calculations() {
        // 24bpp, width=3: bytes_per_row=9, padded=10
        assert_eq!(xor_mask_stride(3, 24), 10);
        // 32bpp, width=3: bytes_per_row=12, padded=12 (already even)
        assert_eq!(xor_mask_stride(3, 32), 12);
        // 1bpp, width=7: bytes_per_row=1, padded=2
        assert_eq!(xor_mask_stride(7, 1), 2);
        // AND mask, width=7: (7+7)/8=1, padded=2
        assert_eq!(and_mask_stride(7), 2);
        // AND mask, width=16: (16+7)/8=2, padded=2
        assert_eq!(and_mask_stride(16), 2);
        // AND mask, width=17: (17+7)/8=3, padded=4
        assert_eq!(and_mask_stride(17), 4);
    }

    #[test]
    fn decode_1x1_32bpp() {
        // 1×1 32bpp pointer: XOR=[B=0x00, G=0x00, R=0xFF, A=0x80]
        // 32bpp ignores AND mask
        let xor = [0x00, 0x00, 0xFF, 0x80];
        let and = [0x00, 0x00]; // padded to 2 bytes
        let shape = decode_pointer(1, 1, 0, 0, 32, &xor, &and).unwrap();
        assert_eq!(shape.pixels, [0x00, 0x00, 0xFF, 0x80]);
    }

    #[test]
    fn decode_1x1_24bpp_opaque() {
        // 1×1 24bpp: XOR=[B=0xFF, G=0x00, R=0x00], AND bit=0 → opaque
        let xor = [0xFF, 0x00, 0x00, 0x00]; // 3 bytes + 1 pad = stride 4
        let and = [0x00, 0x00]; // AND bit 0 = 0 → opaque
        let shape = decode_pointer(1, 1, 0, 0, 24, &xor, &and).unwrap();
        assert_eq!(shape.pixels, [0xFF, 0x00, 0x00, 0xFF]);
        assert_eq!(shape.invert_mask[0], 0, "no invert pixels");
    }

    #[test]
    fn decode_1x1_24bpp_transparent() {
        // XOR=black, AND=0 → transparent (alpha=0)
        let xor = [0x00, 0x00, 0x00, 0x00]; // stride 4
        let and = [0x00, 0x00]; // AND=0
        let shape = decode_pointer(1, 1, 0, 0, 24, &xor, &and).unwrap();
        assert_eq!(shape.pixels[3], 0); // transparent
    }

    #[test]
    fn decode_1x1_24bpp_and_transparent() {
        // AND=1, XOR=black → transparent
        let xor = [0x00, 0x00, 0x00, 0x00];
        let and = [0x80, 0x00]; // bit 7 = 1 (MSB-first for pixel 0)
        let shape = decode_pointer(1, 1, 0, 0, 24, &xor, &and).unwrap();
        assert_eq!(shape.pixels[3], 0); // transparent
    }

    #[test]
    fn decode_1x1_1bpp_white() {
        // 1bpp: XOR bit=1 → white, AND bit=0 → opaque
        let xor = [0x80, 0x00]; // bit 7 = 1 → white
        let and = [0x00, 0x00]; // AND=0
        let shape = decode_pointer(1, 1, 0, 0, 1, &xor, &and).unwrap();
        assert_eq!(shape.pixels, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn decode_2x2_24bpp_bottom_up() {
        // 2×2, 24bpp. XOR stride = (2*3+1)&!1 = 8? No: (6+1)&!1 = 6. Already even.
        // Actually: bytes_per_row=6, (6+1)&!1 = 6. Correct.
        // Bottom-up: wire row 0 = bottom row, wire row 1 = top row
        // Wire row 0 (bottom): pixel(0,1) and pixel(1,1)
        // Wire row 1 (top): pixel(0,0) and pixel(1,0)
        let mut xor = vec![0u8; 12]; // 2 rows × 6 bytes
        // Wire row 0 (bottom row in output, y=1):
        xor[0] = 0xFF; xor[1] = 0x00; xor[2] = 0x00; // pixel(0,1) = blue
        xor[3] = 0x00; xor[4] = 0xFF; xor[5] = 0x00; // pixel(1,1) = green
        // Wire row 1 (top row in output, y=0):
        xor[6] = 0x00; xor[7] = 0x00; xor[8] = 0xFF; // pixel(0,0) = red
        xor[9] = 0xFF; xor[10] = 0xFF; xor[11] = 0xFF; // pixel(1,0) = white
        // AND mask: all 0 (opaque)
        let and = vec![0x00; 4]; // 2 rows × 2 bytes

        let shape = decode_pointer(2, 2, 0, 0, 24, &xor, &and).unwrap();
        // Output top-down: y=0 first
        // pixel(0,0) = red: B=0, G=0, R=0xFF
        assert_eq!(shape.pixels[0..4], [0x00, 0x00, 0xFF, 0xFF]);
        // pixel(1,0) = white
        assert_eq!(shape.pixels[4..8], [0xFF, 0xFF, 0xFF, 0xFF]);
        // pixel(0,1) = blue
        assert_eq!(shape.pixels[8..12], [0xFF, 0x00, 0x00, 0xFF]);
        // pixel(1,1) = green
        assert_eq!(shape.pixels[12..16], [0x00, 0xFF, 0x00, 0xFF]);
    }

    #[test]
    fn decode_empty_pointer() {
        let shape = decode_pointer(0, 0, 1, 1, 32, &[], &[]).unwrap();
        assert!(shape.pixels.is_empty());
        assert_eq!(shape.hotspot_x, 1);
    }

    #[test]
    fn unsupported_bpp() {
        let result = decode_pointer(1, 1, 0, 0, 7, &[], &[]);
        assert_eq!(result, Err(PointerError::UnsupportedBpp(7)));
    }

    #[test]
    fn mask_size_mismatch() {
        // 1×1 24bpp needs stride 4 for XOR, but provide empty
        let result = decode_pointer(1, 1, 0, 0, 24, &[], &[0, 0]);
        assert_eq!(result, Err(PointerError::MaskSizeMismatch));
    }

    // ── Cache tests ──

    #[test]
    fn cache_set_get() {
        let mut cache = PointerCache::new(25);
        let shape = PointerShape {
            width: 1, height: 1,
            hotspot_x: 0, hotspot_y: 0,
            pixels: vec![0xFF; 4],
            invert_mask: vec![0],
        };
        cache.set(0, shape.clone()).unwrap();
        let retrieved = cache.get(0).unwrap();
        assert_eq!(retrieved.pixels, shape.pixels);
    }

    #[test]
    fn cache_invalid_index() {
        let cache = PointerCache::new(25);
        assert_eq!(cache.get(25), Err(PointerError::InvalidCacheIndex(25)));
    }

    #[test]
    fn cache_empty_slot() {
        let cache = PointerCache::new(25);
        assert_eq!(cache.get(0), Err(PointerError::EmptyCacheSlot(0)));
    }

    #[test]
    fn cache_clear() {
        let mut cache = PointerCache::new(5);
        let shape = PointerShape {
            width: 1, height: 1,
            hotspot_x: 0, hotspot_y: 0,
            pixels: vec![0xFF; 4],
            invert_mask: vec![0],
        };
        cache.set(0, shape).unwrap();
        cache.clear();
        assert_eq!(cache.get(0), Err(PointerError::EmptyCacheSlot(0)));
    }

    #[test]
    fn hotspot_preserved() {
        let shape = decode_pointer(1, 1, 5, 10, 32, &[0; 4], &[0; 2]).unwrap();
        assert_eq!(shape.hotspot_x, 5);
        assert_eq!(shape.hotspot_y, 10);
    }

    // ── Gap tests ──

    #[test]
    fn and_1_xor_white_invert_24bpp() {
        // AND=1, XOR=white → invert cursor → opaque white + invert bit set
        let xor = [0xFF, 0xFF, 0xFF, 0x00]; // stride=4
        let and = [0x80, 0x00]; // bit 7 = 1
        let shape = decode_pointer(1, 1, 0, 0, 24, &xor, &and).unwrap();
        assert_eq!(shape.pixels, [0xFF, 0xFF, 0xFF, 0xFF]);
        // Invert mask: bit 0 (pixel 0) should be set
        assert_eq!(shape.invert_mask[0] & 0x80, 0x80, "invert bit must be set");
    }

    #[test]
    fn decode_1x1_16bpp_red() {
        // BGR565 pure red: 0xF800
        let xor = [0x00, 0xF8];
        let and = [0x00, 0x00];
        let shape = decode_pointer(1, 1, 0, 0, 16, &xor, &and).unwrap();
        assert_eq!(shape.pixels[0], 0x00); // B
        assert_eq!(shape.pixels[1], 0x00); // G
        assert_eq!(shape.pixels[2], 0xF8); // R
        assert_eq!(shape.pixels[3], 0xFF);
    }

    #[test]
    fn decode_1x1_16bpp_green() {
        // BGR565 pure green: 0x07E0
        let xor = [0xE0, 0x07];
        let and = [0x00, 0x00];
        let shape = decode_pointer(1, 1, 0, 0, 16, &xor, &and).unwrap();
        assert_eq!(shape.pixels[0], 0x00); // B
        assert_eq!(shape.pixels[1], 0xFC); // G
        assert_eq!(shape.pixels[2], 0x00); // R
    }

    #[test]
    fn decode_1x1_16bpp_blue() {
        // BGR565 pure blue: 0x001F
        let xor = [0x1F, 0x00];
        let and = [0x00, 0x00];
        let shape = decode_pointer(1, 1, 0, 0, 16, &xor, &and).unwrap();
        assert_eq!(shape.pixels[0], 0xF8); // B
        assert_eq!(shape.pixels[1], 0x00); // G
        assert_eq!(shape.pixels[2], 0x00); // R
    }

    #[test]
    fn decode_1bpp_and1_xor_white_invert() {
        let xor = [0x80, 0x00]; // bit 7 = 1 → white
        let and = [0x80, 0x00]; // AND=1
        let shape = decode_pointer(1, 1, 0, 0, 1, &xor, &and).unwrap();
        assert_eq!(shape.pixels, [0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(shape.invert_mask[0] & 0x80, 0x80, "invert bit must be set");
    }

    #[test]
    fn decode_1bpp_and1_xor_black_transparent() {
        let xor = [0x00, 0x00]; // black
        let and = [0x80, 0x00]; // AND=1
        let shape = decode_pointer(1, 1, 0, 0, 1, &xor, &and).unwrap();
        assert_eq!(shape.pixels[3], 0); // transparent
    }

    #[test]
    fn decode_32bpp_ignores_empty_and_mask() {
        let xor = [0x11, 0x22, 0x33, 0x80];
        let shape = decode_pointer(1, 1, 0, 0, 32, &xor, &[]).unwrap();
        assert_eq!(shape.pixels, [0x11, 0x22, 0x33, 0x80]);
    }

    #[test]
    fn and_mask_truncated_error() {
        // 24bpp: valid XOR, empty AND → MaskSizeMismatch
        let result = decode_pointer(1, 1, 0, 0, 24, &[0xFF, 0x00, 0x00, 0x00], &[]);
        assert_eq!(result, Err(PointerError::MaskSizeMismatch));
    }

    #[test]
    fn cache_overwrite() {
        let mut cache = PointerCache::new(4);
        let a = PointerShape { width: 1, height: 1, hotspot_x: 0, hotspot_y: 0, pixels: vec![0xAA; 4], invert_mask: vec![0] };
        let b = PointerShape { width: 1, height: 1, hotspot_x: 0, hotspot_y: 0, pixels: vec![0xBB; 4], invert_mask: vec![0] };
        cache.set(2, a).unwrap();
        cache.set(2, b).unwrap();
        assert_eq!(cache.get(2).unwrap().pixels, vec![0xBB; 4]);
    }

    #[test]
    fn bpp_4_rejected() {
        let result = decode_pointer(1, 1, 0, 0, 4, &[0; 2], &[0; 2]);
        assert_eq!(result, Err(PointerError::UnsupportedBpp(4)));
    }

    #[test]
    fn bpp_8_rejected() {
        let result = decode_pointer(1, 1, 0, 0, 8, &[0; 2], &[0; 2]);
        assert_eq!(result, Err(PointerError::UnsupportedBpp(8)));
    }

    #[test]
    fn decode_zero_width_nonzero_height() {
        // width=0, height=5 → early return with empty pixels
        let shape = decode_pointer(0, 5, 0, 0, 32, &[], &[]).unwrap();
        assert!(shape.pixels.is_empty());
        assert_eq!(shape.width, 0);
        assert_eq!(shape.height, 5);
    }

    #[test]
    fn decode_nonzero_width_zero_height() {
        let shape = decode_pointer(5, 0, 0, 0, 32, &[], &[]).unwrap();
        assert!(shape.pixels.is_empty());
    }
}
