#![forbid(unsafe_code)]

//! Image processing utilities for JustRDP.
//!
//! Rectangle operations, pixel format conversion, image diffing, and scaling.

use alloc::vec;
use alloc::vec::Vec;

// ══════════════════════════════════════════════════════════════
// Rectangle operations
// ══════════════════════════════════════════════════════════════

/// Axis-aligned rectangle (inclusive coordinates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl Rect {
    /// Create a new rectangle.
    pub const fn new(x: u16, y: u16, width: u16, height: u16) -> Self {
        Self { x, y, width, height }
    }

    /// Right edge (exclusive).
    #[inline]
    pub const fn right(&self) -> u32 {
        self.x as u32 + self.width as u32
    }

    /// Bottom edge (exclusive).
    #[inline]
    pub const fn bottom(&self) -> u32 {
        self.y as u32 + self.height as u32
    }

    /// Whether this rectangle has zero area.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// Whether two rectangles overlap.
    pub fn intersects(&self, other: &Rect) -> bool {
        !self.is_empty()
            && !other.is_empty()
            && (self.x as u32) < other.right()
            && (other.x as u32) < self.right()
            && (self.y as u32) < other.bottom()
            && (other.y as u32) < self.bottom()
    }

    /// Compute the intersection of two rectangles.
    /// Returns `None` if they don't overlap.
    pub fn intersection(&self, other: &Rect) -> Option<Rect> {
        if !self.intersects(other) {
            return None;
        }

        let x1 = core::cmp::max(self.x, other.x);
        let y1 = core::cmp::max(self.y, other.y);
        let x2 = core::cmp::min(self.right(), other.right());
        let y2 = core::cmp::min(self.bottom(), other.bottom());

        Some(Rect {
            x: x1,
            y: y1,
            width: (x2 - x1 as u32) as u16,
            height: (y2 - y1 as u32) as u16,
        })
    }

    /// Compute the bounding box (union) of two rectangles.
    pub fn union(&self, other: &Rect) -> Rect {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }

        let x1 = core::cmp::min(self.x, other.x);
        let y1 = core::cmp::min(self.y, other.y);
        let x2 = core::cmp::max(self.right(), other.right());
        let y2 = core::cmp::max(self.bottom(), other.bottom());

        Rect {
            x: x1,
            y: y1,
            width: (x2 - x1 as u32) as u16,
            height: (y2 - y1 as u32) as u16,
        }
    }

    /// Whether this rectangle fully contains another.
    pub fn contains(&self, other: &Rect) -> bool {
        if other.is_empty() {
            return true;
        }
        (self.x as u32) <= other.x as u32
            && (self.y as u32) <= other.y as u32
            && self.right() >= other.right()
            && self.bottom() >= other.bottom()
    }

    /// Split this rectangle by subtracting `cut` from it.
    /// Returns up to 4 rectangles (top, bottom, left, right strips).
    pub fn subtract(&self, cut: &Rect) -> Vec<Rect> {
        let mut result = Vec::new();
        let inter = match self.intersection(cut) {
            Some(i) => i,
            None => {
                result.push(*self);
                return result;
            }
        };

        // Top strip
        if inter.y > self.y {
            result.push(Rect::new(self.x, self.y, self.width, inter.y - self.y));
        }
        // Bottom strip
        if inter.bottom() < self.bottom() {
            let by = inter.bottom() as u16;
            result.push(Rect::new(self.x, by, self.width, (self.bottom() - inter.bottom()) as u16));
        }
        // Left strip (between top and bottom)
        if inter.x > self.x {
            result.push(Rect::new(self.x, inter.y, inter.x - self.x, inter.height));
        }
        // Right strip (between top and bottom)
        if inter.right() < self.right() {
            let rx = inter.right() as u16;
            result.push(Rect::new(rx, inter.y, (self.right() - inter.right()) as u16, inter.height));
        }

        result
    }
}

// ══════════════════════════════════════════════════════════════
// Color space conversion
// ══════════════════════════════════════════════════════════════

/// Swap R and B channels in a BGRA/RGBA buffer in-place.
/// Works for both BGRA→RGBA and RGBA→BGRA (symmetric swap).
pub fn swap_rb_inplace(buf: &mut [u8]) {
    let mut i = 0;
    while i + 3 <= buf.len() {
        buf.swap(i, i + 2);
        i += 4;
    }
}

/// Convert BGR (3 bytes/pixel) to BGRA (4 bytes/pixel), setting alpha to 0xFF.
pub fn bgr_to_bgra(src: &[u8], dst: &mut Vec<u8>) {
    let pixel_count = src.len() / 3;
    dst.clear();
    dst.reserve(pixel_count * 4);
    let mut i = 0;
    while i + 3 <= src.len() {
        dst.push(src[i]);     // B
        dst.push(src[i + 1]); // G
        dst.push(src[i + 2]); // R
        dst.push(0xFF);       // A
        i += 3;
    }
}

/// Convert BGRA (4 bytes/pixel) to BGR (3 bytes/pixel), discarding alpha.
pub fn bgra_to_bgr(src: &[u8], dst: &mut Vec<u8>) {
    let pixel_count = src.len() / 4;
    dst.clear();
    dst.reserve(pixel_count * 3);
    let mut i = 0;
    while i + 4 <= src.len() {
        dst.push(src[i]);     // B
        dst.push(src[i + 1]); // G
        dst.push(src[i + 2]); // R
        i += 4;
    }
}

// ══════════════════════════════════════════════════════════════
// Image diff (changed region detection)
// ══════════════════════════════════════════════════════════════

/// Compare two BGRA images and return a list of changed tile rectangles.
///
/// Divides the image into `tile_size × tile_size` tiles and returns
/// rectangles for tiles that differ between `old` and `new`.
///
/// # Arguments
///
/// * `old` - Previous frame BGRA pixels
/// * `new` - Current frame BGRA pixels
/// * `width` - Image width in pixels
/// * `height` - Image height in pixels
/// * `tile_size` - Tile size for comparison granularity (e.g., 64)
pub fn diff_tiles(
    old: &[u8],
    new: &[u8],
    width: u16,
    height: u16,
    tile_size: u16,
) -> Vec<Rect> {
    let w = width as usize;
    let h = height as usize;
    let ts = tile_size as usize;
    let stride = w * 4;
    let mut changed = Vec::new();

    if old.len() != new.len() || old.len() < stride * h {
        return changed;
    }

    let tiles_x = (w + ts - 1) / ts;
    let tiles_y = (h + ts - 1) / ts;

    for ty in 0..tiles_y {
        for tx in 0..tiles_x {
            let x0 = tx * ts;
            let y0 = ty * ts;
            let tw = core::cmp::min(ts, w - x0);
            let th = core::cmp::min(ts, h - y0);

            let mut differs = false;
            'outer: for row in 0..th {
                let row_offset = (y0 + row) * stride + x0 * 4;
                let row_len = tw * 4;
                if old[row_offset..row_offset + row_len] != new[row_offset..row_offset + row_len] {
                    differs = true;
                    break 'outer;
                }
            }

            if differs {
                changed.push(Rect::new(x0 as u16, y0 as u16, tw as u16, th as u16));
            }
        }
    }

    changed
}

// ══════════════════════════════════════════════════════════════
// Scaling / resizing (nearest-neighbor)
// ══════════════════════════════════════════════════════════════

/// Scale a BGRA image using nearest-neighbor interpolation.
///
/// # Arguments
///
/// * `src` - Source BGRA pixels
/// * `src_width` - Source width
/// * `src_height` - Source height
/// * `dst_width` - Destination width
/// * `dst_height` - Destination height
pub fn scale_nearest(
    src: &[u8],
    src_width: u16,
    src_height: u16,
    dst_width: u16,
    dst_height: u16,
) -> Vec<u8> {
    let sw = src_width as usize;
    let sh = src_height as usize;
    let dw = dst_width as usize;
    let dh = dst_height as usize;

    if sw == 0 || sh == 0 || dw == 0 || dh == 0 {
        return vec![0u8; dw * dh * 4];
    }

    let mut dst = vec![0u8; dw * dh * 4];

    for dy in 0..dh {
        let sy = (dy * sh / dh).min(sh - 1);
        for dx in 0..dw {
            let sx = (dx * sw / dw).min(sw - 1);
            let src_off = (sy * sw + sx) * 4;
            let dst_off = (dy * dw + dx) * 4;
            dst[dst_off..dst_off + 4].copy_from_slice(&src[src_off..src_off + 4]);
        }
    }

    dst
}

// ══════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Rect ──

    #[test]
    fn rect_basic() {
        let r = Rect::new(10, 20, 30, 40);
        assert_eq!(r.right(), 40);
        assert_eq!(r.bottom(), 60);
        assert!(!r.is_empty());
    }

    #[test]
    fn rect_empty() {
        assert!(Rect::new(0, 0, 0, 10).is_empty());
        assert!(Rect::new(0, 0, 10, 0).is_empty());
    }

    #[test]
    fn rect_intersects() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(5, 5, 10, 10);
        assert!(a.intersects(&b));
        assert!(b.intersects(&a));
    }

    #[test]
    fn rect_no_intersect() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(20, 20, 10, 10);
        assert!(!a.intersects(&b));
    }

    #[test]
    fn rect_intersection() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(5, 5, 10, 10);
        let i = a.intersection(&b).unwrap();
        assert_eq!(i, Rect::new(5, 5, 5, 5));
    }

    #[test]
    fn rect_intersection_none() {
        let a = Rect::new(0, 0, 5, 5);
        let b = Rect::new(10, 10, 5, 5);
        assert!(a.intersection(&b).is_none());
    }

    #[test]
    fn rect_union() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(5, 5, 10, 10);
        let u = a.union(&b);
        assert_eq!(u, Rect::new(0, 0, 15, 15));
    }

    #[test]
    fn rect_union_empty() {
        let a = Rect::new(5, 5, 10, 10);
        let b = Rect::new(0, 0, 0, 0);
        assert_eq!(a.union(&b), a);
        assert_eq!(b.union(&a), a);
    }

    #[test]
    fn rect_contains() {
        let outer = Rect::new(0, 0, 20, 20);
        let inner = Rect::new(5, 5, 10, 10);
        assert!(outer.contains(&inner));
        assert!(!inner.contains(&outer));
    }

    #[test]
    fn rect_subtract_no_overlap() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(20, 20, 5, 5);
        let result = a.subtract(&b);
        assert_eq!(result, vec![a]);
    }

    #[test]
    fn rect_subtract_center() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(3, 3, 4, 4);
        let result = a.subtract(&b);
        // Should produce 4 strips: top, bottom, left, right
        assert_eq!(result.len(), 4);
        // Verify total area = 100 - 16 = 84
        let total_area: u32 = result.iter().map(|r| r.width as u32 * r.height as u32).sum();
        assert_eq!(total_area, 84);
    }

    #[test]
    fn rect_subtract_full_cover() {
        let a = Rect::new(5, 5, 10, 10);
        let b = Rect::new(0, 0, 20, 20);
        let result = a.subtract(&b);
        assert!(result.is_empty()); // fully subtracted
    }

    // ── Color conversion ──

    #[test]
    fn swap_rb() {
        let mut buf = [0x11, 0x22, 0x33, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD];
        swap_rb_inplace(&mut buf);
        assert_eq!(buf, [0x33, 0x22, 0x11, 0xFF, 0xCC, 0xBB, 0xAA, 0xDD]);
    }

    #[test]
    fn bgr_to_bgra_conversion() {
        let src = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mut dst = Vec::new();
        bgr_to_bgra(&src, &mut dst);
        assert_eq!(dst, [0x11, 0x22, 0x33, 0xFF, 0x44, 0x55, 0x66, 0xFF]);
    }

    #[test]
    fn bgra_to_bgr_conversion() {
        let src = [0x11, 0x22, 0x33, 0xFF, 0x44, 0x55, 0x66, 0x80];
        let mut dst = Vec::new();
        bgra_to_bgr(&src, &mut dst);
        assert_eq!(dst, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    // ── Image diff ──

    #[test]
    fn diff_identical_images() {
        let img = vec![0xAA; 4 * 4 * 4]; // 4×4 BGRA
        let changed = diff_tiles(&img, &img, 4, 4, 2);
        assert!(changed.is_empty());
    }

    #[test]
    fn diff_one_tile_changed() {
        let old = vec![0x00; 4 * 4 * 4];
        let mut new = old.clone();
        // Change pixel at (0,0)
        new[0] = 0xFF;
        let changed = diff_tiles(&old, &new, 4, 4, 2);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0], Rect::new(0, 0, 2, 2));
    }

    #[test]
    fn diff_all_tiles_changed() {
        let old = vec![0x00; 4 * 4 * 4];
        let new = vec![0xFF; 4 * 4 * 4];
        let changed = diff_tiles(&old, &new, 4, 4, 2);
        assert_eq!(changed.len(), 4); // 2×2 tiles
    }

    // ── Scaling ──

    #[test]
    fn scale_identity() {
        let src = [
            0x11, 0x22, 0x33, 0xFF,
            0x44, 0x55, 0x66, 0xFF,
            0x77, 0x88, 0x99, 0xFF,
            0xAA, 0xBB, 0xCC, 0xFF,
        ];
        let dst = scale_nearest(&src, 2, 2, 2, 2);
        assert_eq!(dst, src);
    }

    #[test]
    fn scale_up_2x() {
        // 1×1 → 2×2: all pixels same as source
        let src = [0x11, 0x22, 0x33, 0xFF];
        let dst = scale_nearest(&src, 1, 1, 2, 2);
        assert_eq!(dst.len(), 16);
        for i in 0..4 {
            assert_eq!(dst[i * 4..i * 4 + 4], src);
        }
    }

    #[test]
    fn scale_down_2x() {
        // 2×2 → 1×1: picks (0,0)
        let src = [
            0x11, 0x22, 0x33, 0xFF,
            0xAA, 0xBB, 0xCC, 0xFF,
            0x44, 0x55, 0x66, 0xFF,
            0x77, 0x88, 0x99, 0xFF,
        ];
        let dst = scale_nearest(&src, 2, 2, 1, 1);
        assert_eq!(dst, [0x11, 0x22, 0x33, 0xFF]);
    }

    #[test]
    fn scale_empty() {
        let dst = scale_nearest(&[], 0, 0, 2, 2);
        assert_eq!(dst.len(), 16);
    }

    // ── Gap tests ──

    #[test]
    fn rect_adjacent_x_no_intersect() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(10, 0, 10, 10);
        assert!(!a.intersects(&b));
        assert!(a.intersection(&b).is_none());
    }

    #[test]
    fn rect_adjacent_y_no_intersect() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(0, 10, 10, 10);
        assert!(!a.intersects(&b));
        assert!(a.intersection(&b).is_none());
    }

    #[test]
    fn rect_subtract_top_edge_cut() {
        let a = Rect::new(0, 0, 10, 10);
        let cut = Rect::new(0, 0, 10, 4);
        let result = a.subtract(&cut);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], Rect::new(0, 4, 10, 6));
    }

    #[test]
    fn rect_subtract_corner_cut() {
        let a = Rect::new(0, 0, 10, 10);
        let cut = Rect::new(0, 0, 4, 4);
        let result = a.subtract(&cut);
        assert_eq!(result.len(), 2);
        let total: u32 = result.iter().map(|r| r.width as u32 * r.height as u32).sum();
        assert_eq!(total, 84); // 100 - 16
    }

    #[test]
    fn rect_contains_empty_self() {
        let empty = Rect::new(5, 5, 0, 0);
        let nonempty = Rect::new(0, 0, 10, 10);
        assert!(!empty.contains(&nonempty));
    }

    #[test]
    fn diff_tiles_non_aligned_width() {
        let w: usize = 5;
        let h: usize = 4;
        let old = vec![0x00u8; w * h * 4];
        let mut new_img = old.clone();
        // Change pixel at (4, 0)
        new_img[(0 * w + 4) * 4] = 0xFF;
        let changed = diff_tiles(&old, &new_img, w as u16, h as u16, 2);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0], Rect::new(4, 0, 1, 2));
    }

    #[test]
    fn diff_tiles_non_aligned_height() {
        let w: usize = 4;
        let h: usize = 5;
        let old = vec![0x00u8; w * h * 4];
        let mut new_img = old.clone();
        new_img[(4 * w + 0) * 4] = 0xFF;
        let changed = diff_tiles(&old, &new_img, w as u16, h as u16, 2);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0], Rect::new(0, 4, 2, 1));
    }

    #[test]
    fn scale_nearest_asymmetric() {
        // 3×1 → 6×1: [A, B, C] → [A, A, B, B, C, C]
        let a = [0x11u8, 0x22, 0x33, 0xFF];
        let b = [0x44u8, 0x55, 0x66, 0xFF];
        let c = [0x77u8, 0x88, 0x99, 0xFF];
        let mut src = Vec::new();
        src.extend_from_slice(&a);
        src.extend_from_slice(&b);
        src.extend_from_slice(&c);
        let dst = scale_nearest(&src, 3, 1, 6, 1);
        assert_eq!(&dst[0..4], &a);
        assert_eq!(&dst[4..8], &a);
        assert_eq!(&dst[8..12], &b);
        assert_eq!(&dst[12..16], &b);
        assert_eq!(&dst[16..20], &c);
        assert_eq!(&dst[20..24], &c);
    }

    #[test]
    fn swap_rb_non_multiple_of_4() {
        // Length 6: only first pixel (4 bytes) gets swapped, bytes 4-5 untouched
        let mut buf = [0x11, 0x22, 0x33, 0xFF, 0xAA, 0xBB];
        swap_rb_inplace(&mut buf);
        assert_eq!(buf[0], 0x33);
        assert_eq!(buf[2], 0x11);
        assert_eq!(buf[4], 0xAA); // untouched
        assert_eq!(buf[5], 0xBB);
    }
}
