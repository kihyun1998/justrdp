#![forbid(unsafe_code)]
#![no_std]

//! Cursor sprite decoder for RDP pointer update PDUs.
//!
//! Decodes the four cursor message types defined in MS-RDPBCGR
//! §2.2.9.1.1.4 — Color (legacy 24bpp + AND/XOR mask), New
//! (variable bpp + optional alpha), Cached (cache index lookup),
//! and Large (96×96 variant) — into a top-down RGBA
//! [`DecodedCursor`] that an embedder can hand to its UI layer.
//!
//! The crate is `no_std + alloc` so it composes with both
//! `justrdp-async` (native + WASM) and `justrdp-blocking` (sync
//! native).
//!
//! Slice scope:
//! - This file (Slice β): `DecodedCursor`, `CursorError`,
//!   `decode_color` for `TS_PTRMSGTYPE_COLOR`, plus a basic
//!   `CursorCache`.
//! - Slice γ (#11): `decode_new` + `decode_large` (variable bpp +
//!   alpha + 96×96).
//! - Slice δ (#12): `decode_cached` + LRU eviction in `CursorCache`.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Default capacity matching MS-RDPBCGR `pointerCapabilitySet.colorPointerCacheSize`
/// and what `mstsc` / FreeRDP advertise when the negotiated value is absent.
pub const DEFAULT_CACHE_CAPACITY: usize = 25;

/// Per-session sprite cache keyed by the server's pointer cache
/// index. Slice β ships placeholder eviction (drops oldest entry
/// by insertion order); Slice δ replaces this with LRU.
pub struct CursorCache {
    entries: BTreeMap<u16, DecodedCursor>,
    /// Insertion order — first element is oldest. Mutated alongside
    /// `entries` so capacity-bound eviction is O(1).
    order: Vec<u16>,
    max_entries: usize,
}

impl CursorCache {
    /// Create a cache with [`DEFAULT_CACHE_CAPACITY`] (25) entries.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CACHE_CAPACITY)
    }

    /// Create a cache that holds at most `max_entries` sprites.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            order: Vec::new(),
            max_entries,
        }
    }

    /// Insert (or overwrite) a sprite at `index`. If insertion
    /// would exceed capacity, the oldest entry is evicted first.
    /// (Slice δ replaces "oldest" with "least-recently-used".)
    pub fn add(&mut self, index: u16, cursor: DecodedCursor) {
        if self.entries.contains_key(&index) {
            // Overwrite — refresh order position to "youngest".
            self.order.retain(|i| *i != index);
        } else if self.entries.len() >= self.max_entries {
            if let Some(oldest) = self.order.first().copied() {
                self.entries.remove(&oldest);
                self.order.remove(0);
            }
        }
        self.entries.insert(index, cursor);
        self.order.push(index);
    }

    /// Look up a previously-added sprite. Returns `None` on miss.
    pub fn lookup(&self, index: u16) -> Option<&DecodedCursor> {
        self.entries.get(&index)
    }

    /// Drop every entry — used on session reconnect.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    /// Number of sprites currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Empty-state predicate.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for CursorCache {
    fn default() -> Self {
        Self::new()
    }
}

/// A fully-decoded cursor sprite — what the embedder applies to its
/// UI layer (e.g. canvas CSS cursor URL).
///
/// `rgba` is row-major top-down RGBA8, length = `width * height * 4`.
/// `(hotspot_x, hotspot_y)` is the click point in the sprite's own
/// coordinate space (0..width × 0..height).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCursor {
    pub width: u16,
    pub height: u16,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    pub rgba: Vec<u8>,
}

/// Failures raised by the decoder. All variants carry enough
/// context for the embedder to log usefully without re-parsing the
/// payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorError {
    /// Payload is shorter than the fixed header or the declared
    /// mask lengths.
    Truncated { expected: usize, got: usize },
    /// `width` or `height` is zero, or the hotspot is outside the
    /// sprite rectangle.
    BadDimensions {
        width: u16,
        height: u16,
        hotspot_x: u16,
        hotspot_y: u16,
    },
    /// Pointer message type the decoder does not yet handle. Slices
    /// γ / δ replace these.
    Unsupported { msg_type: u16 },
}

/// Decode a `TS_PTRMSGTYPE_COLOR` (Color Pointer Update) payload —
/// MS-RDPBCGR §2.2.9.1.1.4.4.
///
/// Wire layout (little-endian):
///
/// ```text
/// cacheIndex      u16
/// hotSpot.x       u16
/// hotSpot.y       u16
/// width           u16
/// height          u16
/// lengthAndMask   u16
/// lengthXorMask   u16
/// xorMaskData     u8 * lengthXorMask   // 24bpp BGR, bottom-up DIB
/// andMaskData     u8 * lengthAndMask   // 1bpp packed, bottom-up
/// ```
///
/// The XOR mask is the cursor's color data; the AND mask drives
/// transparency. Per §2.2.9.1.1.4.4: AND=0 → use XOR pixel,
/// AND=1 + XOR=0 → transparent, AND=1 + XOR≠0 → inverted (we
/// approximate as transparent for this slice — XOR-blit pass is
/// production-grade work).
/// Read the `cacheIndex` field (first 2 LE bytes) from any pointer
/// update payload that has the standard cache-index header (Color,
/// New, Large, Cached). Returns `None` if the payload is shorter
/// than 2 bytes.
pub fn extract_cache_index(payload: &[u8]) -> Option<u16> {
    if payload.len() < 2 {
        return None;
    }
    Some(u16::from_le_bytes([payload[0], payload[1]]))
}

pub fn decode_color(payload: &[u8]) -> Result<DecodedCursor, CursorError> {
    const HEADER_LEN: usize = 14;
    if payload.len() < HEADER_LEN {
        return Err(CursorError::Truncated {
            expected: HEADER_LEN,
            got: payload.len(),
        });
    }
    let _cache_index = u16::from_le_bytes([payload[0], payload[1]]);
    let hotspot_x = u16::from_le_bytes([payload[2], payload[3]]);
    let hotspot_y = u16::from_le_bytes([payload[4], payload[5]]);
    let width = u16::from_le_bytes([payload[6], payload[7]]);
    let height = u16::from_le_bytes([payload[8], payload[9]]);
    let length_and = u16::from_le_bytes([payload[10], payload[11]]) as usize;
    let length_xor = u16::from_le_bytes([payload[12], payload[13]]) as usize;

    if width == 0
        || height == 0
        || hotspot_x >= width
        || hotspot_y >= height
    {
        return Err(CursorError::BadDimensions {
            width,
            height,
            hotspot_x,
            hotspot_y,
        });
    }

    let total = HEADER_LEN + length_xor + length_and;
    if payload.len() < total {
        return Err(CursorError::Truncated {
            expected: total,
            got: payload.len(),
        });
    }

    let xor_data = &payload[HEADER_LEN..HEADER_LEN + length_xor];
    let and_data = &payload[HEADER_LEN + length_xor..HEADER_LEN + length_xor + length_and];

    // 24bpp BGR rows are 4-byte-aligned (DIB convention).
    let w = width as usize;
    let h = height as usize;
    let xor_row_stride = (w * 3 + 3) & !3;
    // 1bpp AND mask packed MSB-first; row stride is 2-byte-aligned.
    let and_row_unpadded = (w + 7) / 8;
    let and_row_stride = (and_row_unpadded + 1) & !1;

    let mut rgba = alloc::vec![0u8; w * h * 4];
    for src_y in 0..h {
        // Bottom-up DIB → flip into top-down RGBA.
        let dst_y = h - 1 - src_y;
        let xor_off = src_y * xor_row_stride;
        let and_off = src_y * and_row_stride;
        for x in 0..w {
            let bgr = &xor_data[xor_off + x * 3..xor_off + x * 3 + 3];
            let (b, g, r) = (bgr[0], bgr[1], bgr[2]);
            let and_byte = and_data[and_off + x / 8];
            let and_bit = (and_byte >> (7 - (x % 8))) & 1;

            let dst = (dst_y * w + x) * 4;
            if and_bit == 0 {
                // Use XOR pixel as opaque RGBA.
                rgba[dst] = r;
                rgba[dst + 1] = g;
                rgba[dst + 2] = b;
                rgba[dst + 3] = 0xFF;
            } else {
                // AND=1: transparent (XOR=0) or inverted (XOR≠0).
                // Both approximated as fully transparent for this
                // slice; XOR-blit pass is a follow-up.
                rgba[dst] = 0;
                rgba[dst + 1] = 0;
                rgba[dst + 2] = 0;
                rgba[dst + 3] = 0;
            }
        }
    }

    Ok(DecodedCursor {
        width,
        height,
        hotspot_x,
        hotspot_y,
        rgba,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use alloc::vec;

    /// Build a minimal 1×1 opaque red Color Pointer Update payload.
    /// XOR row = `[0x00, 0x00, 0xFF]` (24bpp BGR red), padded to
    /// 4-byte-aligned row stride (4 bytes total). AND row = `0x00`
    /// (one bit zero = "use XOR pixel"), padded to 2-byte-aligned
    /// row stride (2 bytes total).
    fn one_by_one_red() -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&0u16.to_le_bytes()); // cacheIndex
        v.extend_from_slice(&0u16.to_le_bytes()); // hotSpot.x
        v.extend_from_slice(&0u16.to_le_bytes()); // hotSpot.y
        v.extend_from_slice(&1u16.to_le_bytes()); // width
        v.extend_from_slice(&1u16.to_le_bytes()); // height
        v.extend_from_slice(&2u16.to_le_bytes()); // lengthAndMask
        v.extend_from_slice(&4u16.to_le_bytes()); // lengthXorMask
        v.extend_from_slice(&[0x00, 0x00, 0xFF, 0x00]); // XOR: BGR red + 1 pad
        v.extend_from_slice(&[0x00, 0x00]); // AND: 0-bit + 1-byte pad
        v
    }

    /// Cycle 1 tracer — 1×1 opaque red pixel decodes to a single
    /// RGBA8 pixel with red at full opacity.
    #[test]
    fn decode_color_single_red_opaque_pixel() {
        let payload = one_by_one_red();
        let cursor = decode_color(&payload).expect("decode ok");
        assert_eq!(cursor.width, 1);
        assert_eq!(cursor.height, 1);
        assert_eq!(cursor.hotspot_x, 0);
        assert_eq!(cursor.hotspot_y, 0);
        // RGBA8: R=0xFF, G=0, B=0, A=0xFF (opaque)
        assert_eq!(cursor.rgba, vec![0xFF, 0x00, 0x00, 0xFF]);
    }

    /// Cycle 2 — 2×2 opaque sprite verifies (a) row stride padding
    /// (XOR rows align to 4 bytes), (b) bottom-up DIB → top-down
    /// RGBA flip, (c) BGR → RGB channel swap. Bottom row of the
    /// wire = top row of the decoded sprite.
    #[test]
    fn decode_color_two_by_two_flips_rows_and_swaps_channels() {
        let mut v = vec![];
        v.extend_from_slice(&0u16.to_le_bytes()); // cacheIndex
        v.extend_from_slice(&0u16.to_le_bytes()); // hotSpot.x
        v.extend_from_slice(&0u16.to_le_bytes()); // hotSpot.y
        v.extend_from_slice(&2u16.to_le_bytes()); // width
        v.extend_from_slice(&2u16.to_le_bytes()); // height
        v.extend_from_slice(&4u16.to_le_bytes()); // lengthAndMask (2 bytes/row * 2 rows)
        v.extend_from_slice(&16u16.to_le_bytes()); // lengthXorMask (8 bytes/row * 2 rows)
        // XOR row 0 (bottom of sprite): Red, Green + 2 pad
        v.extend_from_slice(&[0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00]);
        // XOR row 1 (top of sprite): Blue, Yellow + 2 pad
        v.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00]);
        // AND row 0 + AND row 1 — all bits zero (every pixel opaque) + pad
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let cursor = decode_color(&v).expect("decode ok");
        assert_eq!(cursor.width, 2);
        assert_eq!(cursor.height, 2);
        // Top-down RGBA — top row first.
        // (0,0) Blue, (1,0) Yellow, (0,1) Red, (1,1) Green.
        assert_eq!(
            cursor.rgba,
            vec![
                0x00, 0x00, 0xFF, 0xFF, // Blue
                0xFF, 0xFF, 0x00, 0xFF, // Yellow
                0xFF, 0x00, 0x00, 0xFF, // Red
                0x00, 0xFF, 0x00, 0xFF, // Green
            ]
        );
    }

    /// Cycle 3 — AND mask bit set + XOR=0 produces a transparent
    /// pixel. Slice β approximates AND=1 + XOR≠0 the same way (full
    /// XOR-blit is a follow-up).
    #[test]
    fn decode_color_and_mask_bit_set_produces_transparent_pixel() {
        let mut v = vec![];
        v.extend_from_slice(&0u16.to_le_bytes()); // cacheIndex
        v.extend_from_slice(&0u16.to_le_bytes()); // hotSpot.x
        v.extend_from_slice(&0u16.to_le_bytes()); // hotSpot.y
        v.extend_from_slice(&1u16.to_le_bytes()); // width
        v.extend_from_slice(&1u16.to_le_bytes()); // height
        v.extend_from_slice(&2u16.to_le_bytes()); // lengthAndMask
        v.extend_from_slice(&4u16.to_le_bytes()); // lengthXorMask
        // XOR: black (any value, AND mask makes it transparent)
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // AND: 0x80 = MSB set → first pixel transparent
        v.extend_from_slice(&[0x80, 0x00]);

        let cursor = decode_color(&v).expect("decode ok");
        assert_eq!(cursor.rgba, vec![0x00, 0x00, 0x00, 0x00]);
    }

    /// Cycle 4 — defensive validation. Zero dimensions and
    /// out-of-bounds hotspot must surface as `BadDimensions` rather
    /// than panic; truncated payload (header-only, no mask data)
    /// must surface as `Truncated`.
    #[test]
    fn decode_color_rejects_zero_dimensions() {
        let mut v = vec![0u8; 14];
        v[6..8].copy_from_slice(&0u16.to_le_bytes()); // width = 0
        v[8..10].copy_from_slice(&1u16.to_le_bytes()); // height = 1
        let err = decode_color(&v).unwrap_err();
        assert!(matches!(err, CursorError::BadDimensions { width: 0, .. }));
    }

    #[test]
    fn decode_color_rejects_hotspot_outside_sprite() {
        let mut v = vec![0u8; 14];
        v[2..4].copy_from_slice(&5u16.to_le_bytes()); // hotspot_x = 5
        v[6..8].copy_from_slice(&3u16.to_le_bytes()); // width = 3 (< 5)
        v[8..10].copy_from_slice(&3u16.to_le_bytes()); // height = 3
        let err = decode_color(&v).unwrap_err();
        assert!(matches!(
            err,
            CursorError::BadDimensions {
                hotspot_x: 5,
                width: 3,
                ..
            }
        ));
    }

    #[test]
    fn decode_color_rejects_truncated_header() {
        let v = vec![0u8; 13]; // one byte short of fixed header
        let err = decode_color(&v).unwrap_err();
        assert!(matches!(
            err,
            CursorError::Truncated { expected: 14, got: 13 }
        ));
    }

    #[test]
    fn decode_color_rejects_truncated_mask_data() {
        // Header announces 4 bytes XOR + 2 bytes AND but body absent.
        let mut v = vec![0u8; 14];
        v[6..8].copy_from_slice(&1u16.to_le_bytes()); // width = 1
        v[8..10].copy_from_slice(&1u16.to_le_bytes()); // height = 1
        v[10..12].copy_from_slice(&2u16.to_le_bytes()); // lengthAndMask
        v[12..14].copy_from_slice(&4u16.to_le_bytes()); // lengthXorMask
        let err = decode_color(&v).unwrap_err();
        assert!(matches!(err, CursorError::Truncated { expected: 20, got: 14 }));
    }

    fn fake_sprite(width: u16) -> DecodedCursor {
        DecodedCursor {
            width,
            height: 1,
            hotspot_x: 0,
            hotspot_y: 0,
            rgba: alloc::vec![0u8; width as usize * 4],
        }
    }

    /// Cycle 6 — add then lookup returns the same sprite.
    #[test]
    fn cache_add_then_lookup_returns_some() {
        let mut cache = CursorCache::new();
        let sprite = fake_sprite(8);
        cache.add(3, sprite.clone());
        assert_eq!(cache.lookup(3), Some(&sprite));
        assert_eq!(cache.lookup(99), None);
    }

    #[test]
    fn cache_default_capacity_is_25() {
        let cache = CursorCache::new();
        assert_eq!(cache.max_entries, DEFAULT_CACHE_CAPACITY);
    }

    /// Cycle 7 — adding past capacity drops the oldest entry by
    /// insertion order. (LRU lands in Slice δ; this slice's
    /// invariant is "oldest by insertion".)
    #[test]
    fn cache_eviction_drops_oldest_when_over_capacity() {
        let mut cache = CursorCache::with_capacity(3);
        cache.add(1, fake_sprite(1));
        cache.add(2, fake_sprite(2));
        cache.add(3, fake_sprite(3));
        // Inserting a fourth evicts index 1 (oldest).
        cache.add(4, fake_sprite(4));
        assert_eq!(cache.len(), 3);
        assert!(cache.lookup(1).is_none(), "oldest entry should be evicted");
        assert!(cache.lookup(2).is_some());
        assert!(cache.lookup(3).is_some());
        assert!(cache.lookup(4).is_some());
    }

    #[test]
    fn cache_overwrite_does_not_count_against_capacity() {
        let mut cache = CursorCache::with_capacity(2);
        cache.add(1, fake_sprite(1));
        cache.add(2, fake_sprite(2));
        // Overwriting index 1 should not evict — same key.
        cache.add(1, fake_sprite(11));
        assert_eq!(cache.len(), 2);
        assert!(cache.lookup(2).is_some());
        assert_eq!(cache.lookup(1).map(|c| c.width), Some(11));
    }

    #[test]
    fn cache_clear_empties_entries_and_order() {
        let mut cache = CursorCache::new();
        cache.add(1, fake_sprite(1));
        cache.add(2, fake_sprite(2));
        cache.clear();
        assert!(cache.is_empty());
        assert!(cache.lookup(1).is_none());
    }
}
