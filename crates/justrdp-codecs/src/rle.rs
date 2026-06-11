//! Interleaved RLE bitmap decompression (MS-RDPBCGR 2.2.9.1.1.3.1.2.4 `RLE_BITMAP_STREAM`,
//! algorithm 3.1.9) — the compression slow-path bitmap updates use at 8/15/16/24 bpp.
//!
//! The stream is a sequence of compression orders over a scanline-oriented pixel buffer:
//! background runs copy the scanline above (XOR-inserting the current foreground pixel when
//! two background runs are adjacent), foreground runs XOR a run with the foreground pixel,
//! FGBG images drive that XOR from a bitmask, color runs/images carry literal pixels. The
//! first scanline has no "line above" — those orders substitute black. Output scanlines are
//! in source order (bottom-up within `TS_BITMAP_DATA`); the color seam flips them.
//!
//! Self-owned (ADR-0003 phase 2 from the start); `ironrdp-graphics::rle` is the differential
//! oracle, never a dependency.

/// Why decompression failed. Malformed input is always a typed error, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RleError {
    /// `bitsPerPixel` is not an interleaved-RLE depth (8/15/16/24).
    UnsupportedBitsPerPixel {
        /// The offending depth.
        bits_per_pixel: u16,
    },
    /// `width` or `height` is zero.
    EmptyImage,
    /// The compressed stream ended inside an order.
    TruncatedInput,
    /// An order writes past the `width × height` output buffer.
    OutputOverflow,
    /// A MEGA_MEGA order declared a zero run length.
    ZeroRunLength,
    /// The compression order code is not defined by MS-RDPBCGR 2.2.9.1.1.3.1.2.4.
    UnknownOrder {
        /// The raw order header byte.
        header: u8,
    },
}

impl core::fmt::Display for RleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RleError::UnsupportedBitsPerPixel { bits_per_pixel } => {
                write!(f, "unsupported interleaved-RLE depth: {bits_per_pixel} bpp")
            }
            RleError::EmptyImage => write!(f, "empty image (zero width or height)"),
            RleError::TruncatedInput => write!(f, "compressed stream ended inside an order"),
            RleError::OutputOverflow => write!(f, "order writes past the output buffer"),
            RleError::ZeroRunLength => write!(f, "MEGA_MEGA order with zero run length"),
            RleError::UnknownOrder { header } => {
                write!(f, "unknown compression order header {header:#04x}")
            }
        }
    }
}

impl core::error::Error for RleError {}

// Canonical order codes after class extraction (MS-RDPBCGR 2.2.9.1.1.3.1.2.4).
const REGULAR_BG_RUN: u8 = 0x00;
const REGULAR_FG_RUN: u8 = 0x01;
const REGULAR_FGBG_IMAGE: u8 = 0x02;
const REGULAR_COLOR_RUN: u8 = 0x03;
const REGULAR_COLOR_IMAGE: u8 = 0x04;
const LITE_SET_FG_FG_RUN: u8 = 0x0C;
const LITE_SET_FG_FGBG_IMAGE: u8 = 0x0D;
const LITE_DITHERED_RUN: u8 = 0x0E;
const MEGA_BG_RUN: u8 = 0xF0;
const MEGA_FG_RUN: u8 = 0xF1;
const MEGA_FGBG_IMAGE: u8 = 0xF2;
const MEGA_COLOR_RUN: u8 = 0xF3;
const MEGA_COLOR_IMAGE: u8 = 0xF4;
const MEGA_SET_FG_RUN: u8 = 0xF6;
const MEGA_SET_FGBG_IMAGE: u8 = 0xF7;
const MEGA_DITHERED_RUN: u8 = 0xF8;
const SPECIAL_FGBG_1: u8 = 0xF9;
const SPECIAL_FGBG_2: u8 = 0xFA;
const SPECIAL_WHITE: u8 = 0xFD;
const SPECIAL_BLACK: u8 = 0xFE;

/// The fixed bitmasks of the two special FGBG orders.
const SPECIAL_FGBG_1_MASK: u8 = 0x03;
const SPECIAL_FGBG_2_MASK: u8 = 0x05;

/// Decompress an interleaved-RLE stream into `width × height` pixels at `bits_per_pixel`,
/// returning the raw pixel buffer (scanlines in source order, i.e. bottom-up within
/// `TS_BITMAP_DATA`; 15-bpp pixels occupy 2 bytes, 24-bpp pixels 3).
pub fn decompress(
    src: &[u8],
    width: usize,
    height: usize,
    bits_per_pixel: u16,
) -> Result<Vec<u8>, RleError> {
    let pixel_size = match bits_per_pixel {
        8 => 1,
        15 | 16 => 2,
        24 => 3,
        bits_per_pixel => return Err(RleError::UnsupportedBitsPerPixel { bits_per_pixel }),
    };
    if width == 0 || height == 0 {
        return Err(RleError::EmptyImage);
    }
    let row_bytes = width * pixel_size;
    let mut decoder = Decoder {
        src,
        src_pos: 0,
        dst: vec![0; row_bytes * height],
        dst_pos: 0,
        pixel_size,
        row_bytes,
        white: match bits_per_pixel {
            8 => 0xFF,
            15 => 0x7FFF,
            16 => 0xFFFF,
            _ => 0x00FF_FFFF,
        },
    };
    decoder.run()?;
    Ok(decoder.dst)
}

/// The decompression state: input/output cursors plus the per-depth constants.
struct Decoder<'a> {
    src: &'a [u8],
    src_pos: usize,
    dst: Vec<u8>,
    dst_pos: usize,
    pixel_size: usize,
    row_bytes: usize,
    white: u32,
}

impl Decoder<'_> {
    fn run(&mut self) -> Result<(), RleError> {
        // The current foreground pixel, white until a SET order changes it.
        let mut fg = self.white;
        // Two adjacent background runs must not merge: the second starts by inserting the
        // foreground pixel (MS-RDPBCGR 3.1.9: "insert an FG pel").
        let mut insert_fg = false;
        // First-scanline state, updated only *between* orders (the MS-RDPBCGR 3.1.9
        // pseudo-code semantics): an order issued on the first line keeps first-line
        // behavior even if it spills into the second, and a pending foreground insertion
        // is cancelled exactly once when the line boundary is crossed.
        let mut first_line = true;

        while self.src_pos < self.src.len() {
            if first_line && self.dst_pos >= self.row_bytes {
                first_line = false;
                insert_fg = false;
            }
            let header = self.read_u8()?;
            let code = decode_order(header);
            let run = self.run_length(code, header)?;

            if code == REGULAR_BG_RUN || code == MEGA_BG_RUN {
                self.ensure_out(run)?;
                let mut remaining = run;
                if insert_fg && remaining > 0 {
                    let pixel = if first_line {
                        fg
                    } else {
                        self.pixel_above() ^ fg
                    };
                    self.write_pixel(pixel);
                    remaining -= 1;
                }
                for _ in 0..remaining {
                    let pixel = if first_line { 0 } else { self.pixel_above() };
                    self.write_pixel(pixel);
                }
                insert_fg = true;
                continue;
            }
            // Every non-background order cancels the pending foreground insertion.
            insert_fg = false;

            match code {
                REGULAR_FG_RUN | MEGA_FG_RUN | LITE_SET_FG_FG_RUN | MEGA_SET_FG_RUN => {
                    if code == LITE_SET_FG_FG_RUN || code == MEGA_SET_FG_RUN {
                        fg = self.read_pixel()?;
                    }
                    self.ensure_out(run)?;
                    for _ in 0..run {
                        let pixel = if first_line {
                            fg
                        } else {
                            self.pixel_above() ^ fg
                        };
                        self.write_pixel(pixel);
                    }
                }
                LITE_DITHERED_RUN | MEGA_DITHERED_RUN => {
                    let a = self.read_pixel()?;
                    let b = self.read_pixel()?;
                    self.ensure_out(run * 2)?;
                    for _ in 0..run {
                        self.write_pixel(a);
                        self.write_pixel(b);
                    }
                }
                REGULAR_COLOR_RUN | MEGA_COLOR_RUN => {
                    let pixel = self.read_pixel()?;
                    self.ensure_out(run)?;
                    for _ in 0..run {
                        self.write_pixel(pixel);
                    }
                }
                REGULAR_FGBG_IMAGE
                | MEGA_FGBG_IMAGE
                | LITE_SET_FG_FGBG_IMAGE
                | MEGA_SET_FGBG_IMAGE => {
                    if code == LITE_SET_FG_FGBG_IMAGE || code == MEGA_SET_FGBG_IMAGE {
                        fg = self.read_pixel()?;
                    }
                    let mut remaining = run;
                    while remaining > 0 {
                        let bits = remaining.min(8);
                        let mask = self.read_u8()?;
                        self.fg_bg_image(mask, fg, bits, first_line)?;
                        remaining -= bits;
                    }
                }
                REGULAR_COLOR_IMAGE | MEGA_COLOR_IMAGE => {
                    let bytes = run * self.pixel_size;
                    if self.src.len() - self.src_pos < bytes {
                        return Err(RleError::TruncatedInput);
                    }
                    if self.dst.len() - self.dst_pos < bytes {
                        return Err(RleError::OutputOverflow);
                    }
                    self.dst[self.dst_pos..self.dst_pos + bytes]
                        .copy_from_slice(&self.src[self.src_pos..self.src_pos + bytes]);
                    self.src_pos += bytes;
                    self.dst_pos += bytes;
                }
                SPECIAL_FGBG_1 => self.fg_bg_image(SPECIAL_FGBG_1_MASK, fg, 8, first_line)?,
                SPECIAL_FGBG_2 => self.fg_bg_image(SPECIAL_FGBG_2_MASK, fg, 8, first_line)?,
                SPECIAL_WHITE => {
                    self.ensure_out(1)?;
                    self.write_pixel(self.white);
                }
                SPECIAL_BLACK => {
                    self.ensure_out(1)?;
                    self.write_pixel(0);
                }
                _ => return Err(RleError::UnknownOrder { header }),
            }
        }
        Ok(())
    }

    /// Write up to 8 pixels driven by `mask`: a set bit XORs the foreground pixel into the
    /// pixel above (foreground pixel itself on the first scanline), a clear bit copies the
    /// pixel above (black on the first scanline).
    fn fg_bg_image(
        &mut self,
        mask: u8,
        fg: u32,
        bits: usize,
        first_line: bool,
    ) -> Result<(), RleError> {
        self.ensure_out(bits)?;
        for bit in 0..bits {
            let set = mask & 1 << bit != 0;
            let pixel = match (first_line, set) {
                (true, true) => fg,
                (true, false) => 0,
                (false, true) => self.pixel_above() ^ fg,
                (false, false) => self.pixel_above(),
            };
            self.write_pixel(pixel);
        }
        Ok(())
    }

    /// Extract the run length encoded in (or after) the order header.
    fn run_length(&mut self, code: u8, header: u8) -> Result<usize, RleError> {
        match code {
            // FGBG images count *bits*: the 5/4-bit field holds length/8, zero means an
            // explicit byte + 1.
            REGULAR_FGBG_IMAGE => match header & 0x1F {
                0 => Ok(self.read_u8()? as usize + 1),
                n => Ok(n as usize * 8),
            },
            LITE_SET_FG_FGBG_IMAGE => match header & 0x0F {
                0 => Ok(self.read_u8()? as usize + 1),
                n => Ok(n as usize * 8),
            },
            REGULAR_BG_RUN | REGULAR_FG_RUN | REGULAR_COLOR_RUN | REGULAR_COLOR_IMAGE => {
                match header & 0x1F {
                    0 => Ok(self.read_u8()? as usize + 32), // extended (MEGA) form
                    n => Ok(n as usize),
                }
            }
            LITE_SET_FG_FG_RUN | LITE_DITHERED_RUN => match header & 0x0F {
                0 => Ok(self.read_u8()? as usize + 16),
                n => Ok(n as usize),
            },
            MEGA_BG_RUN | MEGA_FG_RUN | MEGA_SET_FG_RUN | MEGA_DITHERED_RUN | MEGA_COLOR_RUN
            | MEGA_FGBG_IMAGE | MEGA_SET_FGBG_IMAGE | MEGA_COLOR_IMAGE => {
                let lo = self.read_u8()? as usize;
                let hi = self.read_u8()? as usize;
                match hi << 8 | lo {
                    0 => Err(RleError::ZeroRunLength),
                    n => Ok(n),
                }
            }
            _ => Ok(0), // SPECIAL orders carry no run length
        }
    }

    fn read_u8(&mut self) -> Result<u8, RleError> {
        let byte = *self.src.get(self.src_pos).ok_or(RleError::TruncatedInput)?;
        self.src_pos += 1;
        Ok(byte)
    }

    /// Read one little-endian pixel from the source stream.
    fn read_pixel(&mut self) -> Result<u32, RleError> {
        if self.src.len() - self.src_pos < self.pixel_size {
            return Err(RleError::TruncatedInput);
        }
        let mut pixel = 0u32;
        for i in 0..self.pixel_size {
            pixel |= (self.src[self.src_pos + i] as u32) << (8 * i);
        }
        self.src_pos += self.pixel_size;
        Ok(pixel)
    }

    /// Write one little-endian pixel at the output cursor (bounds pre-checked by callers).
    fn write_pixel(&mut self, pixel: u32) {
        for i in 0..self.pixel_size {
            self.dst[self.dst_pos + i] = (pixel >> (8 * i)) as u8;
        }
        self.dst_pos += self.pixel_size;
    }

    /// The pixel exactly one scanline above the output cursor.
    fn pixel_above(&self) -> u32 {
        let pos = self.dst_pos - self.row_bytes;
        let mut pixel = 0u32;
        for i in 0..self.pixel_size {
            pixel |= (self.dst[pos + i] as u32) << (8 * i);
        }
        pixel
    }

    fn ensure_out(&self, pixels: usize) -> Result<(), RleError> {
        if self.dst.len() - self.dst_pos < pixels * self.pixel_size {
            return Err(RleError::OutputOverflow);
        }
        Ok(())
    }
}

/// Classify an order header byte (MS-RDPBCGR 2.2.9.1.1.3.1.2.4): regular orders keep their
/// top 3 bits, lite orders their top 4, MEGA/SPECIAL orders the whole byte.
fn decode_order(header: u8) -> u8 {
    if header & 0xC0 != 0xC0 {
        header >> 5
    } else if header & 0xF0 == 0xF0 {
        header
    } else {
        header >> 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_run_and_bg_run_copy_above() {
        // 2×2 @ 8bpp: line 1 = COLOR_RUN(2) of 0xAA; line 2 = BG_RUN(2) copies line 1.
        // COLOR_RUN header: code 3<<5 | run 2 = 0x62; pixel 0xAA. BG_RUN: 0x00<<5 | 2 = 0x02.
        let src = [0x62, 0xAA, 0x02];
        let out = decompress(&src, 2, 2, 8).unwrap();
        assert_eq!(out, [0xAA, 0xAA, 0xAA, 0xAA]);
    }

    #[test]
    fn adjacent_bg_runs_insert_the_foreground_pixel() {
        // First line: BG_RUN(4) = black (no line above). The follow-on BG_RUN(4) must insert
        // the (white) foreground pixel first, still on the first line of a 8-wide image.
        let src = [0x04, 0x04];
        let out = decompress(&src, 8, 1, 8).unwrap();
        assert_eq!(out, [0, 0, 0, 0, 0xFF, 0, 0, 0]);
    }

    #[test]
    fn fg_run_xors_with_the_line_above() {
        // 2×2 @ 8bpp: COLOR_RUN(2) of 0x0F, then SET_FG(0x33) + FG_RUN(2):
        // line 2 = line 1 ^ 0x33 = 0x3C. LITE_SET_FG_FG_RUN header: 0xC0 | run 2 = 0xC2.
        let src = [0x62, 0x0F, 0xC2, 0x33];
        let out = decompress(&src, 2, 2, 8).unwrap();
        assert_eq!(out, [0x0F, 0x0F, 0x3C, 0x3C]);
    }

    #[test]
    fn fgbg_image_drives_xor_from_the_bitmask() {
        // 8×2 @ 8bpp: line 1 raw zeros (COLOR_IMAGE run 8), then FGBG_IMAGE with one mask
        // byte 0b0101_0101 over 8 pixels: set bits become fg (white ^ 0), clear copy above.
        // REGULAR_FGBG_IMAGE header: 2<<5 | (8/8 = 1) = 0x41.
        let src = [0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0x41, 0x55];
        let out = decompress(&src, 8, 2, 8).unwrap();
        assert_eq!(&out[..8], &[0; 8]);
        assert_eq!(&out[8..], &[0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0]);
    }

    #[test]
    fn dithered_run_writes_pixel_pairs_16bpp() {
        // LITE_DITHERED_RUN header: 0xE0 | run 2 → 2 pairs of (0x1234, 0x5678).
        let src = [0xE2, 0x34, 0x12, 0x78, 0x56];
        let out = decompress(&src, 4, 1, 16).unwrap();
        assert_eq!(out, [0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56]);
    }

    #[test]
    fn white_and_black_specials() {
        let out = decompress(&[0xFD, 0xFE], 2, 1, 24).unwrap();
        assert_eq!(out, [0xFF, 0xFF, 0xFF, 0, 0, 0]);
    }

    #[test]
    fn malformed_streams_yield_typed_errors() {
        // Truncated: COLOR_RUN promises a pixel that is not there.
        assert_eq!(decompress(&[0x62], 2, 1, 8), Err(RleError::TruncatedInput));
        // Overflow: a run longer than the image.
        assert_eq!(decompress(&[0x1F], 4, 1, 8), Err(RleError::OutputOverflow));
        // Unknown order code.
        assert_eq!(
            decompress(&[0xFB], 4, 1, 8),
            Err(RleError::UnknownOrder { header: 0xFB })
        );
        // MEGA_MEGA zero length.
        assert_eq!(
            decompress(&[0xF0, 0x00, 0x00], 4, 1, 8),
            Err(RleError::ZeroRunLength)
        );
    }
}
