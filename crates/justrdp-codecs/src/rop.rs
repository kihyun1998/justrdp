//! Ternary raster operations and 8×8 brushes (`[MS-RDPEGDI]` 2.2.2.2.1.1.1.7, 2.2.2.2.1.1.2.3)
//! over RGBA8888 pixels.
//!
//! A ROP3 index is its own truth table: bit `(P << 2) | (S << 1) | D` of the index is the result
//! for pattern bit P, source bit S and destination bit D. [`rop3`] evaluates all 256 that way,
//! bitwise across the three colour channels; alpha stays opaque.

/// `BrushStyle`: solid colour.
pub const BS_SOLID: u8 = 0x00;
/// `BrushStyle`: hollow.
pub const BS_NULL: u8 = 0x01;
/// `BrushStyle`: one of the six hatches in `BrushHatch`.
pub const BS_HATCHED: u8 = 0x02;
/// `BrushStyle`: the 1-bpp pattern in `BrushHatch` and `BrushExtra`.
pub const BS_PATTERN: u8 = 0x03;
/// `BrushStyle` flag: a brush from the brush cache.
pub const TS_CACHED_BRUSH: u8 = 0x80;

/// The six hatches (`HS_HORIZONTAL` … `HS_DIACROSS`), top row first, most significant bit
/// leftmost; a set bit is background. The same table as FreeRDP's `GDI_BS_HATCHED_PATTERNS`.
pub const HATCH_PATTERNS: [[u8; 8]; 6] = [
    [0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
    [0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7],
    [0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x7F],
    [0x7F, 0xBF, 0xDF, 0xEF, 0xF7, 0xFB, 0xFD, 0xFE],
    [0xF7, 0xF7, 0xF7, 0x00, 0xF7, 0xF7, 0xF7, 0xF7],
    [0x7E, 0xBD, 0xDB, 0xE7, 0xE7, 0xDB, 0xBD, 0x7E],
];

const ALPHA: u32 = 0xFF00_0000;

/// Apply ROP3 `rop` to one RGBA8888 pixel of each input, as little-endian words. The result is
/// opaque.
pub fn rop3(rop: u8, pattern: u32, source: u32, dest: u32) -> u32 {
    let mut result = 0;
    for minterm in 0..8 {
        if rop >> minterm & 1 == 0 {
            continue;
        }
        let pick = |set: bool, value: u32| if set { value } else { !value };
        result |= pick(minterm & 4 != 0, pattern)
            & pick(minterm & 2 != 0, source)
            & pick(minterm & 1 != 0, dest);
    }
    result | ALPHA
}

/// Whether the result of `rop` depends on the pattern.
pub fn uses_pattern(rop: u8) -> bool {
    rop >> 4 != rop & 0x0F
}

/// Whether the result of `rop` depends on the destination.
pub fn uses_dest(rop: u8) -> bool {
    rop >> 1 & 0x55 != rop & 0x55
}

/// The rows of a [`BS_PATTERN`] brush, top row first: `BrushExtra` holds the top seven in
/// reverse order and `BrushHatch` the bottom one (2.2.2.2.1.1.2.3).
pub fn pattern_rows(hatch: u8, extra: &[u8; 7]) -> [u8; 8] {
    let mut rows = [0; 8];
    for (row, &byte) in rows[..7].iter_mut().zip(extra.iter().rev()) {
        *row = byte;
    }
    rows[7] = hatch;
    rows
}

/// A brush ready to paint: a colour, or a 1-bpp 8×8 pattern anchored at its origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    /// Every pixel this colour.
    Solid(u32),
    /// `rows` tiled from `(org_x, org_y)`; a set bit is `back`, a clear one `fore`.
    Mono {
        /// Top row first, most significant bit leftmost.
        rows: [u8; 8],
        /// Foreground colour.
        fore: u32,
        /// Background colour.
        back: u32,
        /// `BrushOrgX`.
        org_x: i8,
        /// `BrushOrgY`.
        org_y: i8,
    },
}

impl Pattern {
    /// The pattern's pixel at destination `(x, y)`.
    pub fn pixel(&self, x: i32, y: i32) -> u32 {
        match *self {
            Pattern::Solid(color) => color,
            Pattern::Mono {
                rows,
                fore,
                back,
                org_x,
                org_y,
            } => {
                let column = (x - i32::from(org_x)).rem_euclid(8);
                let row = rows[(y - i32::from(org_y)).rem_euclid(8) as usize];
                if row & (0x80 >> column) != 0 {
                    back
                } else {
                    fore
                }
            }
        }
    }

    /// The eight pixels of row `y` from column `left`. A pattern repeats every eight pixels
    /// across and every eight rows down.
    pub fn period(&self, left: i32, y: i32) -> [u32; 8] {
        core::array::from_fn(|column| self.pixel(left + column as i32, y))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: u32 = 0xFFF0_F0F0;
    const S: u32 = 0xFFCC_CCCC;
    const D: u32 = 0xFFAA_AAAA;

    /// Every ROP3 index against its own truth table, read one bit at a time.
    #[test]
    fn every_rop3_matches_its_truth_table() {
        for rop in 0..=255u8 {
            let result = rop3(rop, P, S, D);
            for bit in 0..24 {
                let index = (P >> bit & 1) << 2 | (S >> bit & 1) << 1 | (D >> bit & 1);
                assert_eq!(
                    result >> bit & 1,
                    u32::from(rop) >> index & 1,
                    "rop {rop:#04x}"
                );
            }
            assert_eq!(result >> 24, 0xFF, "alpha stays opaque");
        }
    }

    /// The named codes 2.2.2.2.1.1.1.7 lists, as GDI defines them.
    #[test]
    fn named_rops() {
        let (p, s, d) = (0xFF12_3456, 0xFF65_4321, 0xFF0F_0F0F);
        assert_eq!(rop3(0xCC, p, s, d), s); // SRCCOPY
        assert_eq!(rop3(0xF0, p, s, d), p); // PATCOPY
        assert_eq!(rop3(0xAA, p, s, d), d); // D
        assert_eq!(rop3(0x66, p, s, d), (s ^ d) | ALPHA); // SRCINVERT
        assert_eq!(rop3(0x88, p, s, d), (s & d) | ALPHA); // SRCAND
        assert_eq!(rop3(0xC0, p, s, d), (p & s) | ALPHA); // MERGECOPY
        assert_eq!(rop3(0x55, p, s, d), !d | ALPHA); // DSTINVERT
        assert_eq!(rop3(0x00, p, s, d), ALPHA); // BLACKNESS
        assert_eq!(rop3(0xFF, p, s, d), 0xFFFF_FFFF); // WHITENESS
    }

    #[test]
    fn dependence_on_the_pattern() {
        assert!(!uses_pattern(0xCC) && uses_pattern(0xF0) && uses_pattern(0xB8));
        assert!(!uses_pattern(0x66) && !uses_pattern(0x00));
    }

    /// 2.2.2.2.1.1.2.3's example: a 45-degree line sloping down left to right.
    #[test]
    fn pattern_rows_follow_the_spec_example() {
        let rows = pattern_rows(0x01, &[0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]);
        assert_eq!(rows, [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]);
    }

    /// The pattern tiles from its origin, and a set bit is the background.
    #[test]
    fn mono_patterns_tile_from_their_origin() {
        let pattern = Pattern::Mono {
            rows: [0x80, 0, 0, 0, 0, 0, 0, 0],
            fore: 1,
            back: 2,
            org_x: 3,
            org_y: -1,
        };
        assert_eq!(pattern.pixel(3, -1), 2);
        assert_eq!(pattern.pixel(11, 7), 2);
        assert_eq!(pattern.pixel(-5, -9), 2);
        assert_eq!(pattern.pixel(4, -1), 1);
        assert_eq!(pattern.pixel(3, 0), 1);
    }

    /// `uses_dest` says whether the destination can change [`rop3`]'s result, for every ROP3.
    #[test]
    fn uses_dest_says_whether_the_destination_changes_the_result() {
        let ones = 0x00FF_FFFF;
        for rop in 0..=255u8 {
            let reads = [(0, 0), (0, ones), (ones, 0), (ones, ones)]
                .iter()
                .any(|&(p, s)| rop3(rop, p, s, 0) != rop3(rop, p, s, ones));
            assert_eq!(uses_dest(rop), reads, "rop {rop:#04x}");
        }
    }

    /// A pattern's period is its pixels, and repeats every eight pixels across and down.
    #[test]
    fn a_pattern_repeats_its_period_every_eight_pixels() {
        let mono = Pattern::Mono {
            rows: HATCH_PATTERNS[2],
            fore: 1,
            back: 2,
            org_x: -3,
            org_y: 5,
        };
        for pattern in [Pattern::Solid(7), mono] {
            for (left, y) in [(0, 0), (-5, 3), (13, -9)] {
                let period = pattern.period(left, y);
                for column in 0..24 {
                    let x = left + column;
                    assert_eq!(period[column as usize % 8], pattern.pixel(x, y));
                    assert_eq!(pattern.pixel(x, y + 8), pattern.pixel(x, y));
                }
            }
        }
        assert_ne!(mono.period(0, 0), mono.period(0, 1));
    }
}
