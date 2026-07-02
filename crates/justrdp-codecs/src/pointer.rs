//! Pointer shape decoding: XOR color mask + 1-bpp AND mask → straight-alpha RGBA8888 with the
//! cursor semantics of MS-RDPBCGR 2.2.9.1.1.4.4 (and the Windows pointer-drawing rules):
//!
//! - `AND = 0` — the XOR pixel is the cursor pixel (opaque, or carrying its own alpha at
//!   32 bpp).
//! - `AND = 1, XOR = black` — transparent (the only transparency non-32-bpp cursors have).
//! - `AND = 1, XOR = white` — **inverted** screen pixel. RGBA cannot express inversion, so the
//!   pixel renders as a contrasting checkerboard (white/black by `(row + col) % 2`) — visible
//!   on any background, matching `ironrdp-graphics`' accelerated-target convention so the
//!   differential oracle can demand byte identity.
//!
//! Both masks are stored bottom-up with each scan line padded to a 2-byte boundary; output is
//! top-down, tightly packed. Self-owned from the start (like [`crate::rle`] / [`crate::planar`]),
//! with `ironrdp-graphics` as the differential oracle — except 8 bpp (palettized), which the
//! oracle does not implement, and 1 bpp, where the oracle skips the spec's bottom-up flip;
//! those two are pinned by hand-computed vectors instead.

use crate::color::Palette;

/// Why a pointer shape failed to decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerError {
    /// `xorBpp` is not 1, 8, 16, 24 or 32.
    UnsupportedBpp {
        /// The offending `xorBpp`.
        bpp: u16,
    },
    /// A mask's length does not match its stride × height.
    BadMaskSize {
        /// Which mask (`"xorMaskData"` / `"andMaskData"`).
        mask: &'static str,
        /// Bytes required.
        expected: usize,
        /// Bytes received.
        got: usize,
    },
}

impl core::fmt::Display for PointerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PointerError::UnsupportedBpp { bpp } => {
                write!(f, "unsupported pointer xorBpp: {bpp}")
            }
            PointerError::BadMaskSize {
                mask,
                expected,
                got,
            } => write!(f, "{mask} is {got} bytes, expected {expected}"),
        }
    }
}

impl core::error::Error for PointerError {}

/// Decode one pointer shape into top-down, straight-alpha RGBA8888 (`width × height × 4`
/// bytes; empty for a zero-sized shape, which servers use as "no shape"). `xor_bpp` is 1, 8,
/// 16, 24 or 32; `palette` resolves 8-bpp indices (the session palette — pointer shapes have
/// no palette of their own). An empty `and_mask` means fully opaque (servers may omit it).
pub fn decode_pointer(
    width: u16,
    height: u16,
    xor_bpp: u16,
    xor_mask: &[u8],
    and_mask: &[u8],
    palette: &Palette,
) -> Result<Vec<u8>, PointerError> {
    if width == 0 || height == 0 {
        return Ok(Vec::new());
    }
    if !matches!(xor_bpp, 1 | 8 | 16 | 24 | 32) {
        return Err(PointerError::UnsupportedBpp { bpp: xor_bpp });
    }

    let (width, height) = (usize::from(width), usize::from(height));
    // Scan lines are padded to 2-byte boundaries — for the AND mask (1 bpp) and the XOR mask
    // (xorBpp) alike.
    let and_stride = width.div_ceil(16) * 2;
    let xor_stride = (width * usize::from(xor_bpp)).div_ceil(16) * 2;

    if xor_mask.len() != xor_stride * height {
        return Err(PointerError::BadMaskSize {
            mask: "xorMaskData",
            expected: xor_stride * height,
            got: xor_mask.len(),
        });
    }
    if !and_mask.is_empty() && and_mask.len() != and_stride * height {
        return Err(PointerError::BadMaskSize {
            mask: "andMaskData",
            expected: and_stride * height,
            got: and_mask.len(),
        });
    }

    let mut out = Vec::with_capacity(width * height * 4);
    for out_row in 0..height {
        // Both masks are bottom-up (MS-RDPBCGR 2.2.9.1.1.4.4: "bottom-up XOR mask scan-line
        // data", at every xorBpp).
        let src_row = height - 1 - out_row;
        let xor_row = &xor_mask[src_row * xor_stride..(src_row + 1) * xor_stride];
        let and_row = (!and_mask.is_empty())
            .then(|| &and_mask[src_row * and_stride..(src_row + 1) * and_stride]);

        for col in 0..width {
            let and_bit = and_row.is_some_and(|row| row[col / 8] >> (7 - col % 8) & 1 == 1);
            let color = xor_pixel(xor_row, col, xor_bpp, palette);
            match (and_bit, color) {
                // The only transparency non-32-bpp cursors have.
                (true, [0, 0, 0, 0xFF]) => out.extend_from_slice(&[0, 0, 0, 0]),
                // Inversion: RGBA cannot express it, so render a contrasting checkerboard
                // (the ironrdp accelerated-target convention — see the module docs).
                (true, [0xFF, 0xFF, 0xFF, 0xFF]) => {
                    out.extend_from_slice(if (out_row + col) % 2 == 0 {
                        &[0xFF, 0xFF, 0xFF, 0xFF]
                    } else {
                        &[0, 0, 0, 0xFF]
                    });
                }
                (_, color) => out.extend_from_slice(&color),
            }
        }
    }
    Ok(out)
}

/// The XOR pixel at `col` of one scan line, as straight-alpha RGBA.
fn xor_pixel(row: &[u8], col: usize, xor_bpp: u16, palette: &Palette) -> [u8; 4] {
    match xor_bpp {
        1 => {
            if row[col / 8] >> (7 - col % 8) & 1 == 1 {
                [0xFF, 0xFF, 0xFF, 0xFF]
            } else {
                [0, 0, 0, 0xFF]
            }
        }
        8 => {
            let [r, g, b] = palette.entries[usize::from(row[col])];
            [r, g, b, 0xFF]
        }
        16 => {
            let v = u16::from_le_bytes([row[col * 2], row[col * 2 + 1]]);
            // Rounding 5/6-bit widening — deliberately the oracle's formula rather than
            // `color::to_rgba`'s bit replication, so the 16-bpp differential test can demand
            // byte identity (the two methods differ by 1 LSB on some channel values; for
            // cursor shapes the oracle convention wins, see the module docs).
            let r = ((u32::from(v >> 11 & 0x1F) * 527 + 23) >> 6) as u8;
            let g = ((u32::from(v >> 5 & 0x3F) * 259 + 33) >> 6) as u8;
            let b = ((u32::from(v & 0x1F) * 527 + 23) >> 6) as u8;
            [r, g, b, 0xFF]
        }
        24 => [row[col * 3 + 2], row[col * 3 + 1], row[col * 3], 0xFF],
        32 => [
            row[col * 4 + 2],
            row[col * 4 + 1],
            row[col * 4],
            row[col * 4 + 3],
        ],
        _ => unreachable!("decode_pointer validated xor_bpp"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // ADR-0008 / issue #97 — the no-panic robustness property. `PointerError`'s contract is
        // the codecs' shared one: malformed input is always a typed error, never a panic. Both
        // masks are the unbounded, attacker-controlled blobs (their lengths must match the
        // stride × height the header implies, but nothing stops a server from lying), so they are
        // fully arbitrary; width/height/xor_bpp are bounded because they arrive from fixed u16
        // `TS_*POINTERATTRIBUTE` header fields. xor_bpp is biased toward the five real depths so
        // the per-bpp pixel paths are actually exercised (not just the UnsupportedBpp early-out),
        // with arbitrary values mixed in. The palette is the fixed session default — pointer
        // shapes carry none of their own. Reaching the end without unwinding IS the assertion:
        // proptest fails (and shrinks to a minimal counterexample) on any panic / OOB.
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn decode_pointer_never_panics_on_arbitrary_input(
            width in 0u16..=64,
            height in 0u16..=64,
            xor_bpp in prop_oneof![
                Just(1u16), Just(8), Just(16), Just(24), Just(32), any::<u16>(),
            ],
            xor_mask in proptest::collection::vec(any::<u8>(), 0..=512),
            and_mask in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = decode_pointer(width, height, xor_bpp, &xor_mask, &and_mask, &Palette::default());
        }
    }

    #[test]
    fn monochrome_cursor_decodes_all_four_mask_combinations() {
        // 2×2 @1bpp, masks bottom-up (spec: scan lines run bottom-up at *every* bpp), each
        // row padded to 2 bytes. Output (top-down):
        //   (0,0) AND=0 XOR=1 → opaque white      (0,1) AND=0 XOR=0 → opaque black
        //   (1,0) AND=1 XOR=0 → transparent       (1,1) AND=1 XOR=1 → inverted
        // Source rows are therefore output row 1 first, then output row 0.
        let xor_mask = [0x40, 0x00, 0x80, 0x00]; // bottom row [0,1], top row [1,0]
        let and_mask = [0xC0, 0x00, 0x00, 0x00]; // bottom row [1,1], top row [0,0]

        let rgba = decode_pointer(2, 2, 1, &xor_mask, &and_mask, &Palette::default()).unwrap();

        #[rustfmt::skip]
        assert_eq!(rgba, [
            255, 255, 255, 255,   0, 0, 0, 255, // top row: white, black
            0, 0, 0, 0,           255, 255, 255, 255, // bottom: transparent, inverted at (1,1) → white
        ]);
    }

    #[test]
    fn inverted_pixels_render_as_a_checkerboard() {
        // 2×1 @24bpp, both pixels AND=1 + XOR=white → inversion. (row+col) parity makes the
        // first white and the second black — a contrasting pattern on any background, never
        // transparent (the issue-41 acceptance criterion).
        let xor_mask = [0xFF; 6]; // one row of two white 24bpp pixels, 6 bytes (2-aligned)
        let and_mask = [0xC0, 0x00];

        let rgba = decode_pointer(2, 1, 24, &xor_mask, &and_mask, &Palette::default()).unwrap();

        #[rustfmt::skip]
        assert_eq!(rgba, [
            255, 255, 255, 255,
            0, 0, 0, 255,
        ]);
    }

    #[test]
    fn thirty_two_bpp_keeps_the_source_alpha_and_flips_bottom_up() {
        // 1×2 @32bpp (BGRA source): output row 0 = source bottom row.
        //   output (0,0): B=10 G=20 R=30 A=200, AND=0 → [30,20,10,200]
        //   output (1,0): AND=1, XOR=opaque black → transparent
        let xor_mask = [
            0, 0, 0, 0xFF, // source row 0 = output bottom: black, alpha 255
            10, 20, 30, 200, // source row 1 = output top
        ];
        let and_mask = [
            0x80, 0x00, // source row 0 = output bottom: AND=1
            0x00, 0x00,
        ];

        let rgba = decode_pointer(1, 2, 32, &xor_mask, &and_mask, &Palette::default()).unwrap();

        assert_eq!(rgba, [30, 20, 10, 200, 0, 0, 0, 0]);
    }

    #[test]
    fn eight_bpp_resolves_through_the_palette() {
        // 1×1 @8bpp: index 5 → the palette entry, opaque. The xor stride pads 1 byte to 2.
        let mut palette = Palette::default();
        palette.entries[5] = [9, 8, 7];

        let rgba = decode_pointer(1, 1, 8, &[5, 0], &[0x00, 0x00], &palette).unwrap();

        assert_eq!(rgba, [9, 8, 7, 255]);
    }

    #[test]
    fn eight_bpp_multi_row_flips_bottom_up_and_honors_stride_padding() {
        // 3×2 @8bpp. Odd width forces xor_stride = (3*8).div_ceil(16)*2 = 4 (3 index bytes + 1 pad
        // byte per row), and two rows exercise the bottom-up flip (src_row = height-1-out_row) — the
        // multi-row + odd-width coverage the single 1×1 vector above lacks (#124). Hand-computed:
        // the differential oracle does not implement 8 bpp, so this stands on the spec, not a diff.
        let mut palette = Palette::default();
        palette.entries[1] = [10, 11, 12];
        palette.entries[2] = [20, 21, 22];
        palette.entries[3] = [30, 31, 32];
        palette.entries[4] = [40, 41, 42];
        palette.entries[5] = [50, 51, 52];
        palette.entries[6] = [60, 61, 62];
        // Bottom-up storage, each 4-byte row = 3 indices + 1 pad: stored row 0 = [1,2,3], row 1 = [4,5,6].
        let xor_mask = [1, 2, 3, 0, 4, 5, 6, 0];

        // Empty AND mask → fully opaque, so every pixel is its palette colour (no transparency/invert).
        let rgba = decode_pointer(3, 2, 8, &xor_mask, &[], &palette).unwrap();

        #[rustfmt::skip]
        assert_eq!(rgba, [
            // top row (out_row 0) = stored bottom row, indices 4,5,6 — proves the flip:
            40, 41, 42, 255,  50, 51, 52, 255,  60, 61, 62, 255,
            // bottom row (out_row 1) = stored top row, indices 1,2,3 (pad byte at [3]/[7] not read):
            10, 11, 12, 255,  20, 21, 22, 255,  30, 31, 32, 255,
        ]);
    }

    #[test]
    fn odd_widths_skip_the_stride_padding() {
        // 3×1 @24bpp: 9 data bytes padded to a 10-byte stride. The pad byte must not bleed
        // into the pixels. Pixels: red, green, blue (BGR source order).
        let xor_mask = [
            0, 0, 255, // red
            0, 255, 0, // green
            255, 0, 0,    // blue
            0xEE, // stride padding
        ];
        let and_mask = [0x00, 0x00];

        let rgba = decode_pointer(3, 1, 24, &xor_mask, &and_mask, &Palette::default()).unwrap();

        #[rustfmt::skip]
        assert_eq!(rgba, [
            255, 0, 0, 255,
            0, 255, 0, 255,
            0, 0, 255, 255,
        ]);
    }

    #[test]
    fn an_empty_and_mask_means_fully_opaque() {
        // Some servers omit andMaskData entirely (length 0): every pixel is then a plain XOR
        // pixel.
        let rgba = decode_pointer(1, 1, 24, &[1, 2, 3, 0], &[], &Palette::default()).unwrap();
        assert_eq!(rgba, [3, 2, 1, 255]);
    }

    #[test]
    fn a_zero_sized_shape_is_an_empty_bitmap() {
        assert_eq!(
            decode_pointer(0, 0, 32, &[], &[], &Palette::default()).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn malformed_shapes_yield_typed_errors() {
        // Wrong xor mask size for the declared dimensions.
        assert_eq!(
            decode_pointer(2, 2, 32, &[0; 7], &[0; 4], &Palette::default()),
            Err(PointerError::BadMaskSize {
                mask: "xorMaskData",
                expected: 16,
                got: 7
            })
        );
        // Wrong and mask size.
        assert_eq!(
            decode_pointer(2, 2, 32, &[0; 16], &[0; 3], &Palette::default()),
            Err(PointerError::BadMaskSize {
                mask: "andMaskData",
                expected: 4,
                got: 3
            })
        );
        // An unsupported depth.
        assert_eq!(
            decode_pointer(2, 2, 12, &[0; 16], &[0; 4], &Palette::default()),
            Err(PointerError::UnsupportedBpp { bpp: 12 })
        );
    }
}
