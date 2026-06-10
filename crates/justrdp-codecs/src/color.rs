//! Pixel-format conversion to the framebuffer's RGBA8888 — the single seam every decoded
//! bitmap passes through (MS-RDPBCGR slow-path color depths: 8-bit palettized, 15/16-bit
//! high color, 24/32-bit true color).
//!
//! Source conventions (the GDI DIB lineage all slow-path bitmaps share):
//! - 8 bpp: palette indices; the palette arrives separately (Palette Update PDU).
//! - 15 bpp: little-endian `u16`, `0RRRRRGG GGGBBBBB` (5/5/5, red high).
//! - 16 bpp: little-endian `u16`, `RRRRRGGG GGGBBBBB` (5/6/5, red high).
//! - 24 bpp: `B G R` byte order.
//! - 32 bpp: `B G R X` byte order (the server's X/alpha byte is ignored; output alpha is 255).

/// A 256-entry RGB palette (Palette Update PDU, MS-RDPBCGR 2.2.9.1.1.3.1.1). Entries default
/// to black until the server's first palette update — the server always sends one before any
/// 8-bpp bitmap it expects rendered faithfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Palette {
    /// `paletteEntries` as `[r, g, b]`.
    pub entries: [[u8; 3]; 256],
}

impl Default for Palette {
    fn default() -> Self {
        Self {
            entries: [[0; 3]; 256],
        }
    }
}

/// Why a conversion failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColorError {
    /// The source bits-per-pixel is not a slow-path depth (8/15/16/24/32).
    UnsupportedBitsPerPixel {
        /// The offending `bitsPerPixel`.
        bits_per_pixel: u16,
    },
    /// The source buffer does not hold `width × height` pixels at the given depth.
    SourceTooShort {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        got: usize,
    },
}

impl core::fmt::Display for ColorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ColorError::UnsupportedBitsPerPixel { bits_per_pixel } => {
                write!(f, "unsupported source depth: {bits_per_pixel} bpp")
            }
            ColorError::SourceTooShort { needed, got } => {
                write!(f, "source pixel buffer too short: need {needed}, have {got}")
            }
        }
    }
}

impl core::error::Error for ColorError {}

/// Bytes per pixel for a slow-path depth (15 bpp rides in 2 bytes).
pub fn bytes_per_pixel(bits_per_pixel: u16) -> Result<usize, ColorError> {
    match bits_per_pixel {
        8 => Ok(1),
        15 | 16 => Ok(2),
        24 => Ok(3),
        32 => Ok(4),
        bits_per_pixel => Err(ColorError::UnsupportedBitsPerPixel { bits_per_pixel }),
    }
}

/// Convert `src` (one of the slow-path source formats above) into top-down RGBA8888.
///
/// `bottom_up` says the source scanlines run bottom-to-top — true for uncompressed and
/// interleaved-RLE-decompressed slow-path bitmap data (the GDI legacy layout) — and makes
/// this function flip them. The source stride is assumed to be exactly
/// `width × bytes-per-pixel`. MS-RDPBCGR 2.2.9.1.1.3.1.2.2 pads each uncompressed row to a
/// multiple of four *bytes*; real servers satisfy that by 4-aligning the `width` field itself
/// (the up-to-3-pixel overhang), which makes the tight stride hold at every supported depth.
/// A spec-legal but non-4-aligned width at 8/24 bpp would carry per-row pad bytes this
/// function does not skip.
pub fn to_rgba(
    src: &[u8],
    width: usize,
    height: usize,
    bits_per_pixel: u16,
    palette: &Palette,
    bottom_up: bool,
) -> Result<Vec<u8>, ColorError> {
    let bpp = bytes_per_pixel(bits_per_pixel)?;
    let row_bytes = width * bpp;
    let needed = row_bytes * height;
    if src.len() < needed {
        return Err(ColorError::SourceTooShort {
            needed,
            got: src.len(),
        });
    }

    let mut out = Vec::with_capacity(width * height * 4);
    for out_row in 0..height {
        let src_row = if bottom_up { height - 1 - out_row } else { out_row };
        let row = &src[src_row * row_bytes..(src_row + 1) * row_bytes];
        match bits_per_pixel {
            8 => {
                for &index in row {
                    let [r, g, b] = palette.entries[index as usize];
                    out.extend_from_slice(&[r, g, b, 255]);
                }
            }
            15 => {
                for px in row.chunks_exact(2) {
                    let v = u16::from_le_bytes([px[0], px[1]]);
                    let r = scale5((v >> 10) as u8 & 0x1F);
                    let g = scale5((v >> 5) as u8 & 0x1F);
                    let b = scale5(v as u8 & 0x1F);
                    out.extend_from_slice(&[r, g, b, 255]);
                }
            }
            16 => {
                for px in row.chunks_exact(2) {
                    let v = u16::from_le_bytes([px[0], px[1]]);
                    let r = scale5((v >> 11) as u8 & 0x1F);
                    let g = scale6((v >> 5) as u8 & 0x3F);
                    let b = scale5(v as u8 & 0x1F);
                    out.extend_from_slice(&[r, g, b, 255]);
                }
            }
            24 => {
                for px in row.chunks_exact(3) {
                    out.extend_from_slice(&[px[2], px[1], px[0], 255]);
                }
            }
            32 => {
                for px in row.chunks_exact(4) {
                    out.extend_from_slice(&[px[2], px[1], px[0], 255]);
                }
            }
            _ => unreachable!("bytes_per_pixel validated the depth"),
        }
    }
    Ok(out)
}

/// Widen a 5-bit channel to 8 bits, replicating the high bits into the low ones so full
/// intensity maps to 255 (not 248).
fn scale5(c: u8) -> u8 {
    c << 3 | c >> 2
}

/// Widen a 6-bit channel to 8 bits.
fn scale6(c: u8) -> u8 {
    c << 2 | c >> 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palette_lookup_converts_8bpp() {
        let mut palette = Palette::default();
        palette.entries[7] = [10, 20, 30];
        palette.entries[255] = [200, 100, 50];
        let out = to_rgba(&[7, 255], 2, 1, 8, &palette, false).unwrap();
        assert_eq!(out, [10, 20, 30, 255, 200, 100, 50, 255]);
    }

    #[test]
    fn high_color_channels_scale_to_full_range() {
        // 16 bpp pure red / pure green / pure blue / white.
        let red = 0xF800u16.to_le_bytes();
        let green = 0x07E0u16.to_le_bytes();
        let blue = 0x001Fu16.to_le_bytes();
        let white = 0xFFFFu16.to_le_bytes();
        let src = [red, green, blue, white].concat();
        let out = to_rgba(&src, 4, 1, 16, &Palette::default(), false).unwrap();
        assert_eq!(
            out,
            [
                255, 0, 0, 255, //
                0, 255, 0, 255, //
                0, 0, 255, 255, //
                255, 255, 255, 255
            ]
        );

        // 15 bpp white: 0x7FFF must also reach 255 on every channel.
        let out = to_rgba(&0x7FFFu16.to_le_bytes(), 1, 1, 15, &Palette::default(), false).unwrap();
        assert_eq!(out, [255, 255, 255, 255]);
    }

    #[test]
    fn true_color_swaps_bgr_and_flips_bottom_up() {
        // Two rows of one 24-bpp pixel each, bottom-up: source row 0 is the screen's bottom.
        let src = [
            1, 2, 3, // bottom row (B=1 G=2 R=3)
            4, 5, 6, // top row
        ];
        let out = to_rgba(&src, 1, 2, 24, &Palette::default(), true).unwrap();
        assert_eq!(
            out,
            [
                6, 5, 4, 255, // top row first
                3, 2, 1, 255
            ]
        );
    }

    #[test]
    fn xrgb32_ignores_the_server_alpha_byte() {
        let out = to_rgba(&[9, 8, 7, 0], 1, 1, 32, &Palette::default(), false).unwrap();
        assert_eq!(out, [7, 8, 9, 255]);
    }

    #[test]
    fn short_source_is_a_typed_error() {
        assert_eq!(
            to_rgba(&[0; 5], 2, 1, 24, &Palette::default(), false),
            Err(ColorError::SourceTooShort { needed: 6, got: 5 })
        );
        assert!(matches!(
            to_rgba(&[], 1, 1, 12, &Palette::default(), false),
            Err(ColorError::UnsupportedBitsPerPixel { bits_per_pixel: 12 })
        ));
    }
}
