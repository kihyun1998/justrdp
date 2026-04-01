#![forbid(unsafe_code)]

//! Interleaved RLE bitmap decompression (RDP 4.0/5.0).
//!
//! Implements the decompression algorithm described in:
//! - MS-RDPBCGR §3.1.9 (Interleaved RLE-Based Bitmap Compression)
//! - MS-RDPBCGR §2.2.9.1.1.3.1.2.4 (RLE_BITMAP_STREAM)

use alloc::vec::Vec;
use core::fmt;

// ── Color depth ──

/// Bits-per-pixel for RLE decompression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitsPerPixel {
    /// 8 bits per pixel (1 byte).
    Bpp8,
    /// 15 bits per pixel (2 bytes, 5-5-5 RGB).
    Bpp15,
    /// 16 bits per pixel (2 bytes, 5-6-5 RGB).
    Bpp16,
    /// 24 bits per pixel (3 bytes, 8-8-8 RGB).
    Bpp24,
}

impl BitsPerPixel {
    /// Byte size of a single pixel.
    #[inline]
    pub const fn pixel_size(self) -> usize {
        match self {
            Self::Bpp8 => 1,
            Self::Bpp15 | Self::Bpp16 => 2,
            Self::Bpp24 => 3,
        }
    }

    /// Try to create from a raw bpp value.
    pub const fn from_raw(bpp: u16) -> Option<Self> {
        match bpp {
            8 => Some(Self::Bpp8),
            15 => Some(Self::Bpp15),
            16 => Some(Self::Bpp16),
            24 => Some(Self::Bpp24),
            _ => None,
        }
    }

    /// White pixel value for this color depth (MS-RDPBCGR §3.1.9).
    #[inline]
    const fn white(self) -> u32 {
        match self {
            Self::Bpp8 => 0xFF,
            Self::Bpp15 => 0x7FFF,
            Self::Bpp16 => 0xFFFF,
            Self::Bpp24 => 0xFF_FFFF,
        }
    }
}

// ── Error type ──

/// RLE decompression error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RleError {
    /// Compressed stream ended unexpectedly.
    TruncatedStream,
    /// Encountered an unknown or reserved order code.
    UnknownOrderCode(u8),
    /// Unsupported bits-per-pixel value.
    UnsupportedBitsPerPixel(u16),
    /// Decompressed output exceeds the expected buffer size.
    OutputOverflow,
}

impl fmt::Display for RleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedStream => write!(f, "RLE: truncated stream"),
            Self::UnknownOrderCode(code) => write!(f, "RLE: unknown order code 0x{code:02X}"),
            Self::UnsupportedBitsPerPixel(bpp) => write!(f, "RLE: unsupported bpp {bpp}"),
            Self::OutputOverflow => write!(f, "RLE: output buffer overflow"),
        }
    }
}

// ── Order codes (MS-RDPBCGR §2.2.9.1.1.3.1.2.4) ──

// MEGA_MEGA orders (full byte, MS-RDPBCGR §2.2.9.1.1.3.1.2.4)
const MEGA_MEGA_BG_RUN: u8 = 0xF0;
const MEGA_MEGA_FG_RUN: u8 = 0xF1;
const MEGA_MEGA_FGBG_IMAGE: u8 = 0xF2;
const MEGA_MEGA_COLOR_RUN: u8 = 0xF3;
const MEGA_MEGA_COLOR_IMAGE: u8 = 0xF4;
const MEGA_MEGA_SET_FG_RUN: u8 = 0xF6;
const MEGA_MEGA_SET_FGBG_IMAGE: u8 = 0xF7;
const MEGA_MEGA_DITHERED_RUN: u8 = 0xF8;

// Single-byte special orders
const SPECIAL_FGBG_1: u8 = 0xF9;
const SPECIAL_FGBG_2: u8 = 0xFA;
const WHITE: u8 = 0xFD;
const BLACK: u8 = 0xFE;

// ── Pixel helpers ──

/// Read a pixel value from a byte slice (little-endian) with bounds checking.
#[inline]
fn read_pixel(buf: &[u8], offset: usize, pixel_size: usize) -> Result<u32, RleError> {
    if offset + pixel_size > buf.len() {
        return Err(RleError::OutputOverflow);
    }
    let val = match pixel_size {
        1 => u32::from(buf[offset]),
        2 => u32::from(u16::from_le_bytes([buf[offset], buf[offset + 1]])),
        3 => {
            u32::from(buf[offset])
                | (u32::from(buf[offset + 1]) << 8)
                | (u32::from(buf[offset + 2]) << 16)
        }
        // pixel_size is always 1, 2, or 3 from BitsPerPixel::pixel_size()
        _ => unreachable!(),
    };
    Ok(val)
}

/// Write a pixel value to a byte slice (little-endian).
#[inline]
fn write_pixel(buf: &mut [u8], offset: usize, pixel_size: usize, value: u32) {
    match pixel_size {
        1 => buf[offset] = value as u8,
        2 => {
            let bytes = (value as u16).to_le_bytes();
            buf[offset] = bytes[0];
            buf[offset + 1] = bytes[1];
        }
        3 => {
            buf[offset] = value as u8;
            buf[offset + 1] = (value >> 8) as u8;
            buf[offset + 2] = (value >> 16) as u8;
        }
        // pixel_size is always 1, 2, or 3 from BitsPerPixel::pixel_size()
        _ => unreachable!(),
    }
}

// ── Stream reader ──

/// Helper to read from the compressed stream with bounds checking.
struct StreamReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> StreamReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    #[inline]
    fn read_u8(&mut self) -> Result<u8, RleError> {
        if self.pos >= self.data.len() {
            return Err(RleError::TruncatedStream);
        }
        let val = self.data[self.pos];
        self.pos += 1;
        Ok(val)
    }

    #[inline]
    fn read_u16_le(&mut self) -> Result<u16, RleError> {
        if self.pos + 2 > self.data.len() {
            return Err(RleError::TruncatedStream);
        }
        let val = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    /// Read a pixel (1, 2, or 3 bytes depending on pixel_size) from the compressed stream.
    #[inline]
    fn read_pixel(&mut self, pixel_size: usize) -> Result<u32, RleError> {
        if self.pos + pixel_size > self.data.len() {
            return Err(RleError::TruncatedStream);
        }
        // read_pixel won't fail: bounds already checked above
        let val = read_pixel(self.data, self.pos, pixel_size)?;
        self.pos += pixel_size;
        Ok(val)
    }

    /// Read raw bytes into destination buffer.
    #[inline]
    fn read_bytes(
        &mut self,
        dst: &mut [u8],
        dst_offset: usize,
        count: usize,
    ) -> Result<(), RleError> {
        if self.pos + count > self.data.len() {
            return Err(RleError::TruncatedStream);
        }
        if dst_offset + count > dst.len() {
            return Err(RleError::OutputOverflow);
        }
        dst[dst_offset..dst_offset + count].copy_from_slice(&self.data[self.pos..self.pos + count]);
        self.pos += count;
        Ok(())
    }
}

// ── Run length extraction (MS-RDPBCGR §2.2.9.1.1.3.1.2.4) ──

/// Extract run length for regular-form (non-FGBG) orders.
/// Top 3 bits = code, low 5 bits = run length.
#[inline]
fn extract_run_length_regular(
    header: u8,
    reader: &mut StreamReader<'_>,
) -> Result<usize, RleError> {
    let raw = (header & 0x1F) as usize;
    if raw != 0 {
        Ok(raw)
    } else {
        // MEGA: next byte + 32
        let next = reader.read_u8()?;
        Ok(next as usize + 32)
    }
}

/// Extract run length for lite-form (non-FGBG) orders.
/// Top 4 bits = code, low 4 bits = run length.
#[inline]
fn extract_run_length_lite(header: u8, reader: &mut StreamReader<'_>) -> Result<usize, RleError> {
    let raw = (header & 0x0F) as usize;
    if raw != 0 {
        Ok(raw)
    } else {
        // MEGA: next byte + 16
        let next = reader.read_u8()?;
        Ok(next as usize + 16)
    }
}

/// Extract run length for regular-form FGBG image orders.
/// run_length is in pixels; regular form encodes multiples of 8.
#[inline]
fn extract_run_length_regular_fgbg(
    header: u8,
    reader: &mut StreamReader<'_>,
) -> Result<usize, RleError> {
    let raw = (header & 0x1F) as usize;
    if raw != 0 {
        Ok(raw * 8)
    } else {
        // MEGA: next byte + 1
        let next = reader.read_u8()?;
        Ok(next as usize + 1)
    }
}

/// Extract run length for lite-form FGBG image orders.
#[inline]
fn extract_run_length_lite_fgbg(
    header: u8,
    reader: &mut StreamReader<'_>,
) -> Result<usize, RleError> {
    let raw = (header & 0x0F) as usize;
    if raw != 0 {
        Ok(raw * 8)
    } else {
        // MEGA: next byte + 1
        let next = reader.read_u8()?;
        Ok(next as usize + 1)
    }
}

/// Extract run length for MEGA_MEGA orders (2-byte LE after header).
#[inline]
fn extract_run_length_mega_mega(reader: &mut StreamReader<'_>) -> Result<usize, RleError> {
    let val = reader.read_u16_le()?;
    Ok(val as usize)
}

// ── Order processing helpers ──

/// Write a background run: copy from row above (or black on first line).
/// If `insert_fg_pel` is true, the first pixel is XOR'd with fg_pel.
fn write_bg_run(
    dst: &mut [u8],
    dest: &mut usize,
    run_length: usize,
    row_delta: usize,
    first_line: bool,
    fg_pel: u32,
    insert_fg_pel: bool,
    pixel_size: usize,
) -> Result<(), RleError> {
    let mut remaining = run_length;

    if insert_fg_pel && remaining > 0 {
        if *dest + pixel_size > dst.len() {
            return Err(RleError::OutputOverflow);
        }
        if first_line {
            write_pixel(dst, *dest, pixel_size, fg_pel);
        } else {
            let above = read_pixel(dst, *dest - row_delta, pixel_size)?;
            write_pixel(dst, *dest, pixel_size, above ^ fg_pel);
        }
        *dest += pixel_size;
        remaining -= 1;
    }

    for _ in 0..remaining {
        if *dest + pixel_size > dst.len() {
            return Err(RleError::OutputOverflow);
        }
        if first_line {
            // Black pixel = 0
            write_pixel(dst, *dest, pixel_size, 0);
        } else {
            let above = read_pixel(dst, *dest - row_delta, pixel_size)?;
            write_pixel(dst, *dest, pixel_size, above);
        }
        *dest += pixel_size;
    }

    Ok(())
}

/// Write a foreground run: XOR fg_pel with row above (or just fg_pel on first line).
fn write_fg_run(
    dst: &mut [u8],
    dest: &mut usize,
    run_length: usize,
    row_delta: usize,
    first_line: bool,
    fg_pel: u32,
    pixel_size: usize,
) -> Result<(), RleError> {
    for _ in 0..run_length {
        if *dest + pixel_size > dst.len() {
            return Err(RleError::OutputOverflow);
        }
        if first_line {
            write_pixel(dst, *dest, pixel_size, fg_pel);
        } else {
            let above = read_pixel(dst, *dest - row_delta, pixel_size)?;
            write_pixel(dst, *dest, pixel_size, above ^ fg_pel);
        }
        *dest += pixel_size;
    }
    Ok(())
}

/// Write an FGBG image using bitmask bytes from the stream.
fn write_fgbg_image(
    dst: &mut [u8],
    dest: &mut usize,
    run_length: usize,
    row_delta: usize,
    first_line: bool,
    fg_pel: u32,
    pixel_size: usize,
    reader: &mut StreamReader<'_>,
) -> Result<(), RleError> {
    let mut pixels_written = 0;

    while pixels_written < run_length {
        let bitmask = reader.read_u8()?;
        let chunk_size = core::cmp::min(8, run_length - pixels_written);

        for bit_idx in 0..chunk_size {
            if *dest + pixel_size > dst.len() {
                return Err(RleError::OutputOverflow);
            }

            if bitmask & (1 << bit_idx) != 0 {
                // Foreground
                if first_line {
                    write_pixel(dst, *dest, pixel_size, fg_pel);
                } else {
                    let above = read_pixel(dst, *dest - row_delta, pixel_size)?;
                    write_pixel(dst, *dest, pixel_size, above ^ fg_pel);
                }
            } else {
                // Background
                if first_line {
                    write_pixel(dst, *dest, pixel_size, 0);
                } else {
                    let above = read_pixel(dst, *dest - row_delta, pixel_size)?;
                    write_pixel(dst, *dest, pixel_size, above);
                }
            }
            *dest += pixel_size;
            pixels_written += 1;
        }
    }

    Ok(())
}

/// Write an FGBG image using a fixed bitmask (for SPECIAL_FGBG orders).
fn write_fgbg_image_fixed(
    dst: &mut [u8],
    dest: &mut usize,
    bitmask: u8,
    row_delta: usize,
    first_line: bool,
    fg_pel: u32,
    pixel_size: usize,
) -> Result<(), RleError> {
    for bit_idx in 0..8u8 {
        if *dest + pixel_size > dst.len() {
            return Err(RleError::OutputOverflow);
        }

        if bitmask & (1 << bit_idx) != 0 {
            if first_line {
                write_pixel(dst, *dest, pixel_size, fg_pel);
            } else {
                let above = read_pixel(dst, *dest - row_delta, pixel_size)?;
                write_pixel(dst, *dest, pixel_size, above ^ fg_pel);
            }
        } else {
            if first_line {
                write_pixel(dst, *dest, pixel_size, 0);
            } else {
                let above = read_pixel(dst, *dest - row_delta, pixel_size)?;
                write_pixel(dst, *dest, pixel_size, above);
            }
        }
        *dest += pixel_size;
    }

    Ok(())
}

// ── Main decoder ──

/// Interleaved RLE bitmap decompressor (RDP 4.0/5.0).
///
/// Stateless: each call to [`decompress`](Self::decompress) is independent.
#[derive(Debug, Clone)]
pub struct RleDecompressor;

impl RleDecompressor {
    /// Create a new RLE decompressor.
    pub const fn new() -> Self {
        Self
    }

    /// Decompress an Interleaved RLE bitmap stream.
    ///
    /// # Arguments
    ///
    /// * `src` - Compressed RLE_BITMAP_STREAM bytes (after TS_CD_HEADER, if present)
    /// * `width` - Bitmap width in pixels
    /// * `height` - Bitmap height in pixels
    /// * `bpp` - Color depth
    /// * `dst` - Output buffer; will be resized to `width * height * pixel_size`
    ///
    /// # Errors
    ///
    /// Returns [`RleError`] on malformed input or buffer overflow.
    pub fn decompress(
        &self,
        src: &[u8],
        width: u16,
        height: u16,
        bpp: BitsPerPixel,
        dst: &mut Vec<u8>,
    ) -> Result<(), RleError> {
        let pixel_size = bpp.pixel_size();
        let row_delta = (width as usize).checked_mul(pixel_size).ok_or(RleError::OutputOverflow)?;
        let total_size = row_delta.checked_mul(height as usize).ok_or(RleError::OutputOverflow)?;

        if width == 0 || height == 0 {
            dst.clear();
            return Ok(());
        }

        dst.clear();
        dst.resize(total_size, 0);

        let mut reader = StreamReader::new(src);
        let mut dest: usize = 0;
        let mut fg_pel: u32 = bpp.white();
        let mut insert_fg_pel = false;
        let mut first_line = true;

        while !reader.is_empty() {
            // Update first_line flag: transitions to false once dest crosses the first scanline.
            // Placed before header read so each order sees the correct flag for its starting position.
            if first_line && dest >= row_delta {
                first_line = false;
                insert_fg_pel = false;
            }

            let header = reader.read_u8()?;

            match header {
                // ── Regular orders (top 3 bits) ──

                // Background Run: 0x00–0x1F
                0x00..=0x1F => {
                    let run_length = extract_run_length_regular(header, &mut reader)?;
                    write_bg_run(
                        dst,
                        &mut dest,
                        run_length,
                        row_delta,
                        first_line,
                        fg_pel,
                        insert_fg_pel,
                        pixel_size,
                    )?;
                    insert_fg_pel = true;
                }

                // Foreground Run: 0x20–0x3F
                0x20..=0x3F => {
                    let run_length = extract_run_length_regular(header, &mut reader)?;
                    write_fg_run(
                        dst, &mut dest, run_length, row_delta, first_line, fg_pel, pixel_size,
                    )?;
                    insert_fg_pel = false;
                }

                // FGBG Image: 0x40–0x5F
                0x40..=0x5F => {
                    let run_length = extract_run_length_regular_fgbg(header, &mut reader)?;
                    write_fgbg_image(
                        dst,
                        &mut dest,
                        run_length,
                        row_delta,
                        first_line,
                        fg_pel,
                        pixel_size,
                        &mut reader,
                    )?;
                    insert_fg_pel = false;
                }

                // Color Run: 0x60–0x7F
                0x60..=0x7F => {
                    let run_length = extract_run_length_regular(header, &mut reader)?;
                    let color = reader.read_pixel(pixel_size)?;
                    for _ in 0..run_length {
                        if dest + pixel_size > dst.len() {
                            return Err(RleError::OutputOverflow);
                        }
                        write_pixel(dst, dest, pixel_size, color);
                        dest += pixel_size;
                    }
                    insert_fg_pel = false;
                }

                // Color Image: 0x80–0x9F
                0x80..=0x9F => {
                    let run_length = extract_run_length_regular(header, &mut reader)?;
                    let byte_count = run_length * pixel_size;
                    reader.read_bytes(dst, dest, byte_count)?;
                    dest += byte_count;
                    insert_fg_pel = false;
                }

                // 0xA0–0xBF: reserved/undefined (MS-RDPBCGR §2.2.9.1.1.3.1.2.4 — no order defined)
                0xA0..=0xBF => {
                    return Err(RleError::UnknownOrderCode(header));
                }

                // ── Lite orders (top 4 bits) ──

                // Set FG + FG Run: 0xC0–0xCF
                0xC0..=0xCF => {
                    let run_length = extract_run_length_lite(header, &mut reader)?;
                    fg_pel = reader.read_pixel(pixel_size)?;
                    write_fg_run(
                        dst, &mut dest, run_length, row_delta, first_line, fg_pel, pixel_size,
                    )?;
                    insert_fg_pel = false;
                }

                // Set FG + FGBG Image: 0xD0–0xDF
                0xD0..=0xDF => {
                    let run_length = extract_run_length_lite_fgbg(header, &mut reader)?;
                    fg_pel = reader.read_pixel(pixel_size)?;
                    write_fgbg_image(
                        dst,
                        &mut dest,
                        run_length,
                        row_delta,
                        first_line,
                        fg_pel,
                        pixel_size,
                        &mut reader,
                    )?;
                    insert_fg_pel = false;
                }

                // Dithered Run: 0xE0–0xEF
                0xE0..=0xEF => {
                    let run_length = extract_run_length_lite(header, &mut reader)?;
                    let pixel_a = reader.read_pixel(pixel_size)?;
                    let pixel_b = reader.read_pixel(pixel_size)?;
                    for _ in 0..run_length {
                        if dest + pixel_size * 2 > dst.len() {
                            return Err(RleError::OutputOverflow);
                        }
                        write_pixel(dst, dest, pixel_size, pixel_a);
                        dest += pixel_size;
                        write_pixel(dst, dest, pixel_size, pixel_b);
                        dest += pixel_size;
                    }
                    insert_fg_pel = false;
                }

                // ── MEGA_MEGA orders ──
                MEGA_MEGA_BG_RUN => {
                    let run_length = extract_run_length_mega_mega(&mut reader)?;
                    write_bg_run(
                        dst,
                        &mut dest,
                        run_length,
                        row_delta,
                        first_line,
                        fg_pel,
                        insert_fg_pel,
                        pixel_size,
                    )?;
                    insert_fg_pel = true;
                }

                MEGA_MEGA_FG_RUN => {
                    let run_length = extract_run_length_mega_mega(&mut reader)?;
                    write_fg_run(
                        dst, &mut dest, run_length, row_delta, first_line, fg_pel, pixel_size,
                    )?;
                    insert_fg_pel = false;
                }

                MEGA_MEGA_FGBG_IMAGE => {
                    let run_length = extract_run_length_mega_mega(&mut reader)?;
                    write_fgbg_image(
                        dst,
                        &mut dest,
                        run_length,
                        row_delta,
                        first_line,
                        fg_pel,
                        pixel_size,
                        &mut reader,
                    )?;
                    insert_fg_pel = false;
                }

                MEGA_MEGA_COLOR_RUN => {
                    let run_length = extract_run_length_mega_mega(&mut reader)?;
                    let color = reader.read_pixel(pixel_size)?;
                    for _ in 0..run_length {
                        if dest + pixel_size > dst.len() {
                            return Err(RleError::OutputOverflow);
                        }
                        write_pixel(dst, dest, pixel_size, color);
                        dest += pixel_size;
                    }
                    insert_fg_pel = false;
                }

                MEGA_MEGA_COLOR_IMAGE => {
                    let run_length = extract_run_length_mega_mega(&mut reader)?;
                    let byte_count = run_length * pixel_size;
                    reader.read_bytes(dst, dest, byte_count)?;
                    dest += byte_count;
                    insert_fg_pel = false;
                }

                // 0xF5: reserved
                0xF5 => {
                    return Err(RleError::UnknownOrderCode(header));
                }

                MEGA_MEGA_SET_FG_RUN => {
                    let run_length = extract_run_length_mega_mega(&mut reader)?;
                    fg_pel = reader.read_pixel(pixel_size)?;
                    write_fg_run(
                        dst, &mut dest, run_length, row_delta, first_line, fg_pel, pixel_size,
                    )?;
                    insert_fg_pel = false;
                }

                MEGA_MEGA_SET_FGBG_IMAGE => {
                    let run_length = extract_run_length_mega_mega(&mut reader)?;
                    fg_pel = reader.read_pixel(pixel_size)?;
                    write_fgbg_image(
                        dst,
                        &mut dest,
                        run_length,
                        row_delta,
                        first_line,
                        fg_pel,
                        pixel_size,
                        &mut reader,
                    )?;
                    insert_fg_pel = false;
                }

                MEGA_MEGA_DITHERED_RUN => {
                    let run_length = extract_run_length_mega_mega(&mut reader)?;
                    let pixel_a = reader.read_pixel(pixel_size)?;
                    let pixel_b = reader.read_pixel(pixel_size)?;
                    for _ in 0..run_length {
                        if dest + pixel_size * 2 > dst.len() {
                            return Err(RleError::OutputOverflow);
                        }
                        write_pixel(dst, dest, pixel_size, pixel_a);
                        dest += pixel_size;
                        write_pixel(dst, dest, pixel_size, pixel_b);
                        dest += pixel_size;
                    }
                    insert_fg_pel = false;
                }

                // ── Single-byte special orders ──
                SPECIAL_FGBG_1 => {
                    // 8 pixels with bitmask 0x03
                    write_fgbg_image_fixed(
                        dst, &mut dest, 0x03, row_delta, first_line, fg_pel, pixel_size,
                    )?;
                    insert_fg_pel = false;
                }

                SPECIAL_FGBG_2 => {
                    // 8 pixels with bitmask 0x05
                    write_fgbg_image_fixed(
                        dst, &mut dest, 0x05, row_delta, first_line, fg_pel, pixel_size,
                    )?;
                    insert_fg_pel = false;
                }

                // 0xFB, 0xFC: reserved
                0xFB | 0xFC => {
                    return Err(RleError::UnknownOrderCode(header));
                }

                WHITE => {
                    if dest + pixel_size > dst.len() {
                        return Err(RleError::OutputOverflow);
                    }
                    write_pixel(dst, dest, pixel_size, bpp.white());
                    dest += pixel_size;
                    insert_fg_pel = false;
                }

                BLACK => {
                    if dest + pixel_size > dst.len() {
                        return Err(RleError::OutputOverflow);
                    }
                    write_pixel(dst, dest, pixel_size, 0);
                    dest += pixel_size;
                    insert_fg_pel = false;
                }

                0xFF => {
                    return Err(RleError::UnknownOrderCode(header));
                }
            }
        }

        Ok(())
    }
}

impl Default for RleDecompressor {
    #[inline]
    fn default() -> Self {
        Self
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn decompress_8bpp(src: &[u8], width: u16, height: u16) -> Result<Vec<u8>, RleError> {
        let decoder = RleDecompressor::new();
        let mut dst = Vec::new();
        decoder.decompress(src, width, height, BitsPerPixel::Bpp8, &mut dst)?;
        Ok(dst)
    }

    fn decompress_16bpp(src: &[u8], width: u16, height: u16) -> Result<Vec<u8>, RleError> {
        let decoder = RleDecompressor::new();
        let mut dst = Vec::new();
        decoder.decompress(src, width, height, BitsPerPixel::Bpp16, &mut dst)?;
        Ok(dst)
    }

    fn decompress_24bpp(src: &[u8], width: u16, height: u16) -> Result<Vec<u8>, RleError> {
        let decoder = RleDecompressor::new();
        let mut dst = Vec::new();
        decoder.decompress(src, width, height, BitsPerPixel::Bpp24, &mut dst)?;
        Ok(dst)
    }

    // ── WHITE / BLACK single-byte orders ──

    #[test]
    fn white_order_8bpp() {
        let result = decompress_8bpp(&[WHITE], 1, 1).unwrap();
        assert_eq!(result, vec![0xFF]);
    }

    #[test]
    fn black_order_8bpp() {
        let result = decompress_8bpp(&[BLACK], 1, 1).unwrap();
        assert_eq!(result, vec![0x00]);
    }

    #[test]
    fn white_order_16bpp() {
        let result = decompress_16bpp(&[WHITE], 1, 1).unwrap();
        assert_eq!(result, vec![0xFF, 0xFF]);
    }

    #[test]
    fn white_order_24bpp() {
        let result = decompress_24bpp(&[WHITE], 1, 1).unwrap();
        assert_eq!(result, vec![0xFF, 0xFF, 0xFF]);
    }

    // ── Background Run (first line → black pixels) ──

    #[test]
    fn bg_run_first_line_regular() {
        // REGULAR_BG_RUN with run=3: header = 0x00 | 3 = 0x03
        let result = decompress_8bpp(&[0x03], 3, 1).unwrap();
        assert_eq!(result, vec![0x00, 0x00, 0x00]);
    }

    #[test]
    fn bg_run_mega() {
        // REGULAR_BG_RUN MEGA: header=0x00, next=0x01 → run=1+32=33
        let result = decompress_8bpp(&[0x00, 0x01], 33, 1).unwrap();
        assert_eq!(result, vec![0x00; 33]);
    }

    #[test]
    fn bg_run_mega_mega() {
        // MEGA_MEGA_BG_RUN: 0xF0, length=256 (LE: 0x00, 0x01)
        let result = decompress_8bpp(&[0xF0, 0x00, 0x01], 256, 1).unwrap();
        assert_eq!(result, vec![0x00; 256]);
    }

    // ── Foreground Run (first line → fg_pel = white) ──

    #[test]
    fn fg_run_first_line_regular() {
        // REGULAR_FG_RUN with run=3: header = 0x20 | 3 = 0x23
        let result = decompress_8bpp(&[0x23], 3, 1).unwrap();
        assert_eq!(result, vec![0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn fg_run_16bpp() {
        // REGULAR_FG_RUN with run=2: header = 0x20 | 2 = 0x22
        let result = decompress_16bpp(&[0x22], 2, 1).unwrap();
        // fg_pel for 16bpp = 0xFFFF → [0xFF, 0xFF] per pixel
        assert_eq!(result, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    // ── Color Run ──

    #[test]
    fn color_run_8bpp() {
        // REGULAR_COLOR_RUN with run=3: header = 0x60 | 3 = 0x63, color = 0x42
        let result = decompress_8bpp(&[0x63, 0x42], 3, 1).unwrap();
        assert_eq!(result, vec![0x42, 0x42, 0x42]);
    }

    #[test]
    fn color_run_16bpp() {
        // REGULAR_COLOR_RUN with run=2: header = 0x60 | 2 = 0x62, color = 0x1234 LE
        let result = decompress_16bpp(&[0x62, 0x34, 0x12], 2, 1).unwrap();
        assert_eq!(result, vec![0x34, 0x12, 0x34, 0x12]);
    }

    #[test]
    fn color_run_24bpp() {
        // REGULAR_COLOR_RUN with run=2: header = 0x62, color = [0xAA, 0xBB, 0xCC]
        let result = decompress_24bpp(&[0x62, 0xAA, 0xBB, 0xCC], 2, 1).unwrap();
        assert_eq!(result, vec![0xAA, 0xBB, 0xCC, 0xAA, 0xBB, 0xCC]);
    }

    // ── Color Image ──

    #[test]
    fn color_image_8bpp() {
        // REGULAR_COLOR_IMAGE with run=4: header = 0x80 | 4 = 0x84, then 4 raw bytes
        let result = decompress_8bpp(&[0x84, 0x11, 0x22, 0x33, 0x44], 4, 1).unwrap();
        assert_eq!(result, vec![0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn color_image_16bpp() {
        // REGULAR_COLOR_IMAGE with run=2: header = 0x82, then 4 raw bytes
        let result = decompress_16bpp(&[0x82, 0x11, 0x22, 0x33, 0x44], 2, 1).unwrap();
        assert_eq!(result, vec![0x11, 0x22, 0x33, 0x44]);
    }

    // ── FGBG Image ──

    #[test]
    fn fgbg_image_first_line_8bpp() {
        // REGULAR_FGBG_IMAGE: header = 0x40 | 1 = 0x41 → run = 1*8 = 8 pixels
        // bitmask = 0xAA = 0b10101010 → bits: 0,1,0,1,0,1,0,1
        let result = decompress_8bpp(&[0x41, 0xAA], 8, 1).unwrap();
        // bit0=0→black, bit1=1→fg(0xFF), bit2=0→black, bit3=1→fg, ...
        assert_eq!(result, vec![0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF]);
    }

    #[test]
    fn fgbg_image_all_fg() {
        // bitmask = 0xFF → all foreground
        let result = decompress_8bpp(&[0x41, 0xFF], 8, 1).unwrap();
        assert_eq!(result, vec![0xFF; 8]);
    }

    #[test]
    fn fgbg_image_all_bg() {
        // bitmask = 0x00 → all background (black on first line)
        let result = decompress_8bpp(&[0x41, 0x00], 8, 1).unwrap();
        assert_eq!(result, vec![0x00; 8]);
    }

    // ── SPECIAL_FGBG ──

    #[test]
    fn special_fgbg_1_first_line() {
        // SPECIAL_FGBG_1 = 0xF9, bitmask = 0x03 = 0b00000011
        // 8 pixels: bits 0,1 = fg, bits 2-7 = bg
        let result = decompress_8bpp(&[SPECIAL_FGBG_1], 8, 1).unwrap();
        assert_eq!(result, vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn special_fgbg_2_first_line() {
        // SPECIAL_FGBG_2 = 0xFA, bitmask = 0x05 = 0b00000101
        // 8 pixels: bits 0,2 = fg, rest = bg
        let result = decompress_8bpp(&[SPECIAL_FGBG_2], 8, 1).unwrap();
        assert_eq!(result, vec![0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    // ── Set FG + FG Run (Lite) ──

    #[test]
    fn set_fg_fg_run_8bpp() {
        // LITE_SET_FG_FG_RUN with run=3: header = 0xC0 | 3 = 0xC3, new fg = 0x42
        // On first line: writes 0x42 three times
        let result = decompress_8bpp(&[0xC3, 0x42], 3, 1).unwrap();
        assert_eq!(result, vec![0x42, 0x42, 0x42]);
    }

    #[test]
    fn set_fg_fg_run_16bpp() {
        // LITE_SET_FG_FG_RUN with run=2: header = 0xC2, new fg = 0x1234
        let result = decompress_16bpp(&[0xC2, 0x34, 0x12], 2, 1).unwrap();
        assert_eq!(result, vec![0x34, 0x12, 0x34, 0x12]);
    }

    // ── Dithered Run ──

    #[test]
    fn dithered_run_8bpp() {
        // LITE_DITHERED_RUN with run=2: header = 0xE0 | 2 = 0xE2
        // pixel_a = 0xAA, pixel_b = 0x55 → 2 pairs = 4 pixels
        let result = decompress_8bpp(&[0xE2, 0xAA, 0x55], 4, 1).unwrap();
        assert_eq!(result, vec![0xAA, 0x55, 0xAA, 0x55]);
    }

    #[test]
    fn dithered_run_16bpp() {
        // LITE_DITHERED_RUN with run=2: header = 0xE2
        // pixel_a = 0x1111, pixel_b = 0x2222 → 4 pixels
        let result = decompress_16bpp(&[0xE2, 0x11, 0x11, 0x22, 0x22], 4, 1).unwrap();
        assert_eq!(result, vec![0x11, 0x11, 0x22, 0x22, 0x11, 0x11, 0x22, 0x22]);
    }

    // ── Back-to-back BG runs (insert_fg_pel mechanism) ──

    #[test]
    fn back_to_back_bg_runs_first_line() {
        // Two consecutive BG runs on first line.
        // First: run=2 (header=0x02) → 2 black pixels, insert_fg_pel=true
        // Second: run=2 (header=0x02) → first pixel is fg_pel (white), then 1 black
        let result = decompress_8bpp(&[0x02, 0x02], 4, 1).unwrap();
        // First run: [0x00, 0x00]
        // Second run: insert_fg_pel → [0xFF], then 1 more bg → [0x00]
        assert_eq!(result, vec![0x00, 0x00, 0xFF, 0x00]);
    }

    #[test]
    fn bg_run_then_fg_run_no_insert() {
        // BG run followed by FG run: insert_fg_pel should be false for FG run
        // BG run=2 (0x02), FG run=2 (0x22)
        let result = decompress_8bpp(&[0x02, 0x22], 4, 1).unwrap();
        assert_eq!(result, vec![0x00, 0x00, 0xFF, 0xFF]);
    }

    // ── Multi-line: FG run XOR with row above ──

    #[test]
    fn fg_run_second_line_xor() {
        // 2x2 bitmap, 8bpp
        // Line 1: color run of 0xAA (2 pixels): [0x62, 0xAA]
        // Line 2: fg run of 2 (fg_pel=0xFF): [0x22]
        // Line 2 pixels: 0xAA ^ 0xFF = 0x55 each
        let result = decompress_8bpp(&[0x62, 0xAA, 0x22], 2, 2).unwrap();
        assert_eq!(result, vec![0xAA, 0xAA, 0x55, 0x55]);
    }

    #[test]
    fn bg_run_second_line_copies_above() {
        // 2x2 bitmap, 8bpp
        // Line 1: color image [0x82, 0x11, 0x22]
        // Line 2: bg run=2 [0x02] → copies from row above
        let result = decompress_8bpp(&[0x82, 0x11, 0x22, 0x02], 2, 2).unwrap();
        assert_eq!(result, vec![0x11, 0x22, 0x11, 0x22]);
    }

    // ── insert_fg_pel reset across scanline boundary ──

    #[test]
    fn insert_fg_pel_reset_at_scanline_boundary() {
        // 2x2 bitmap, 8bpp
        // Line 1: BG run=2 → [0x00, 0x00], insert_fg_pel=true
        // Line 2: BG run=2 → first_line transitions to false, insert_fg_pel reset to false
        //   → copies from above: [0x00, 0x00]
        let result = decompress_8bpp(&[0x02, 0x02], 2, 2).unwrap();
        assert_eq!(result, vec![0x00, 0x00, 0x00, 0x00]);
    }

    // ── Set FG + FGBG Image ──

    #[test]
    fn set_fg_fgbg_image_8bpp() {
        // LITE_SET_FG_FGBG_IMAGE with run=8: header = 0xD0 | 1 = 0xD1 → run = 1*8 = 8
        // new fg = 0x42, bitmask = 0x0F = 0b00001111
        let result = decompress_8bpp(&[0xD1, 0x42, 0x0F], 8, 1).unwrap();
        // bits 0-3 = fg(0x42), bits 4-7 = bg(0x00)
        assert_eq!(result, vec![0x42, 0x42, 0x42, 0x42, 0x00, 0x00, 0x00, 0x00]);
    }

    // ── MEGA_MEGA orders ──

    #[test]
    fn mega_mega_fg_run() {
        // MEGA_MEGA_FG_RUN: 0xF1, run=3 (LE: 0x03, 0x00)
        let result = decompress_8bpp(&[0xF1, 0x03, 0x00], 3, 1).unwrap();
        assert_eq!(result, vec![0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn mega_mega_color_run() {
        // MEGA_MEGA_COLOR_RUN: 0xF3, run=2 (LE: 0x02, 0x00), color=0x77
        let result = decompress_8bpp(&[0xF3, 0x02, 0x00, 0x77], 2, 1).unwrap();
        assert_eq!(result, vec![0x77, 0x77]);
    }

    #[test]
    fn mega_mega_color_image() {
        // MEGA_MEGA_COLOR_IMAGE: 0xF4, run=3, then 3 raw bytes
        let result = decompress_8bpp(&[0xF4, 0x03, 0x00, 0xAA, 0xBB, 0xCC], 3, 1).unwrap();
        assert_eq!(result, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn mega_mega_set_fg_run() {
        // MEGA_MEGA_SET_FG_RUN: 0xF6, run=2, new fg=0x42
        let result = decompress_8bpp(&[0xF6, 0x02, 0x00, 0x42], 2, 1).unwrap();
        assert_eq!(result, vec![0x42, 0x42]);
    }

    #[test]
    fn mega_mega_dithered_run() {
        // MEGA_MEGA_DITHERED_RUN: 0xF8, run=2, pixel_a=0x11, pixel_b=0x22
        let result = decompress_8bpp(&[0xF8, 0x02, 0x00, 0x11, 0x22], 4, 1).unwrap();
        assert_eq!(result, vec![0x11, 0x22, 0x11, 0x22]);
    }

    // ── Error cases ──

    #[test]
    fn truncated_stream_error() {
        // MEGA_MEGA needs 2 more bytes but stream ends
        let result = decompress_8bpp(&[0xF0], 1, 1);
        assert_eq!(result, Err(RleError::TruncatedStream));
    }

    #[test]
    fn unknown_order_code() {
        let result = decompress_8bpp(&[0xA0], 1, 1);
        assert_eq!(result, Err(RleError::UnknownOrderCode(0xA0)));
    }

    #[test]
    fn unknown_order_0xff() {
        let result = decompress_8bpp(&[0xFF], 1, 1);
        assert_eq!(result, Err(RleError::UnknownOrderCode(0xFF)));
    }

    // ── FGBG partial chunk (run_length not multiple of 8) ──

    #[test]
    fn fgbg_partial_chunk() {
        // REGULAR_FGBG_IMAGE MEGA form: header=0x40, next=0x04 → run = 4+1 = 5 pixels
        // bitmask byte: 0x15 = 0b00010101 → bits 0,2,4 = fg; bits 1,3 = bg
        // Only 5 pixels processed (bits 0-4)
        let result = decompress_8bpp(&[0x40, 0x04, 0x15], 5, 1).unwrap();
        assert_eq!(result, vec![0xFF, 0x00, 0xFF, 0x00, 0xFF]);
    }

    // ── Mixed orders in sequence ──

    #[test]
    fn mixed_orders_8bpp() {
        // 8x1 bitmap:
        // Color run=3 (0x63, 0xAA) → [0xAA, 0xAA, 0xAA]
        // FG run=2 (0x22) → [0xFF, 0xFF]
        // BLACK (0xFE) → [0x00]
        // WHITE (0xFD) → [0xFF]
        // BLACK (0xFE) → [0x00]
        let result = decompress_8bpp(&[0x63, 0xAA, 0x22, 0xFE, 0xFD, 0xFE], 8, 1).unwrap();
        assert_eq!(result, vec![0xAA, 0xAA, 0xAA, 0xFF, 0xFF, 0x00, 0xFF, 0x00]);
    }

    // ── 15bpp white pixel ──

    #[test]
    fn white_order_15bpp() {
        let decoder = RleDecompressor::new();
        let mut dst = Vec::new();
        decoder
            .decompress(&[WHITE], 1, 1, BitsPerPixel::Bpp15, &mut dst)
            .unwrap();
        // 15bpp white = 0x7FFF → LE bytes: [0xFF, 0x7F]
        assert_eq!(dst, vec![0xFF, 0x7F]);
    }

    // ── Boundary: zero-length stream produces zero-filled output ──

    #[test]
    fn empty_stream() {
        let result = decompress_8bpp(&[], 0, 0).unwrap();
        assert!(result.is_empty());
    }

    // ── MEGA_MEGA_FGBG_IMAGE ──

    #[test]
    fn mega_mega_fgbg_image() {
        // MEGA_MEGA_FGBG_IMAGE: 0xF2, run=8 (LE: 0x08, 0x00), bitmask=0xF0
        // 0xF0 = 0b11110000 → bits 0-3=bg, bits 4-7=fg
        let result = decompress_8bpp(&[0xF2, 0x08, 0x00, 0xF0], 8, 1).unwrap();
        assert_eq!(result, vec![0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    // ── MEGA_MEGA_SET_FGBG_IMAGE ──

    #[test]
    fn mega_mega_set_fgbg_image() {
        // MEGA_MEGA_SET_FGBG_IMAGE: 0xF7, run=8, new fg=0x42, bitmask=0x01
        let result = decompress_8bpp(&[0xF7, 0x08, 0x00, 0x42, 0x01], 8, 1).unwrap();
        // bit0=fg(0x42), bits 1-7=bg(0x00)
        assert_eq!(result, vec![0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    // ── FGBG second-line XOR ──

    #[test]
    fn fgbg_image_second_line_xor_8bpp() {
        // 8x2 bitmap: line 1 = 8 pixels of 0xAA, line 2 = FGBG all-fg
        // FGBG XOR: 0xAA ^ 0xFF = 0x55
        let src = [
            0x88, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // color image run=8
            0x41, 0xFF, // FGBG run=8, bitmask=0xFF (all fg)
        ];
        let result = decompress_8bpp(&src, 8, 2).unwrap();
        assert_eq!(&result[..8], &[0xAA; 8]);
        assert_eq!(&result[8..], &[0x55; 8]);
    }

    // ── BG run second-line with insert_fg_pel ──

    #[test]
    fn back_to_back_bg_runs_second_line_insert_fg_pel() {
        // 3x2: line 1 = color image [0x10, 0x20, 0x30]
        // line 2: BG run=2 → copies [0x10, 0x20], insert_fg_pel=true
        //         BG run=1 → first pixel = 0x30 ^ 0xFF = 0xCF
        let src = [
            0x83, 0x10, 0x20, 0x30, // color image run=3
            0x02, // BG run=2
            0x01, // BG run=1 (insert_fg_pel=true)
        ];
        let result = decompress_8bpp(&src, 3, 2).unwrap();
        assert_eq!(result, vec![0x10, 0x20, 0x30, 0x10, 0x20, 0xCF]);
    }

    // ── OutputOverflow ──

    #[test]
    fn color_run_output_overflow() {
        // 2x1 bitmap but color run=5 → overflows
        let result = decompress_8bpp(&[0x65, 0x42], 2, 1);
        assert_eq!(result, Err(RleError::OutputOverflow));
    }

    #[test]
    fn fg_run_output_overflow() {
        // 1x1 bitmap but FG run=2 → overflows
        let result = decompress_8bpp(&[0x22], 1, 1);
        assert_eq!(result, Err(RleError::OutputOverflow));
    }

    // ── MEGA boundary values ──

    #[test]
    fn bg_run_mega_boundary_min() {
        // MEGA form: header=0x00, next=0x00 → run = 0 + 32 = 32
        let result = decompress_8bpp(&[0x00, 0x00], 32, 1).unwrap();
        assert_eq!(result, vec![0x00; 32]);
    }

    #[test]
    fn fg_run_regular_max_inline() {
        // header = 0x20 | 0x1F = 0x3F → run=31 (max inline, must NOT trigger MEGA)
        let result = decompress_8bpp(&[0x3F], 31, 1).unwrap();
        assert_eq!(result, vec![0xFF; 31]);
    }

    #[test]
    fn fgbg_mega_run_length_1() {
        // FGBG MEGA: header=0x40 (inline=0), next=0x00 → run=0+1=1 pixel
        // bitmask=0xFF → bit0=fg
        let result = decompress_8bpp(&[0x40, 0x00, 0xFF], 1, 1).unwrap();
        assert_eq!(result, vec![0xFF]);
    }

    // ── Reserved order codes ──

    #[test]
    fn unknown_order_0xf5() {
        assert_eq!(
            decompress_8bpp(&[0xF5], 1, 1),
            Err(RleError::UnknownOrderCode(0xF5))
        );
    }

    #[test]
    fn unknown_order_0xfb() {
        assert_eq!(
            decompress_8bpp(&[0xFB], 1, 1),
            Err(RleError::UnknownOrderCode(0xFB))
        );
    }

    #[test]
    fn unknown_order_0xfc() {
        assert_eq!(
            decompress_8bpp(&[0xFC], 1, 1),
            Err(RleError::UnknownOrderCode(0xFC))
        );
    }

    // ── Truncated stream for color run ──

    #[test]
    fn truncated_color_run_pixel() {
        // Color run header says run=1 but no pixel data follows
        let result = decompress_8bpp(&[0x61], 1, 1);
        assert_eq!(result, Err(RleError::TruncatedStream));
    }

    // ── SPECIAL_FGBG on second line ──

    #[test]
    fn special_fgbg_1_second_line() {
        // 8x2: line 1 = 8 pixels of 0xAA, line 2 = SPECIAL_FGBG_1 (bitmask 0x03)
        // bits 0,1 → fg XOR: 0xAA ^ 0xFF = 0x55; bits 2-7 → bg copy: 0xAA
        let src = [
            0x88,
            0xAA,
            0xAA,
            0xAA,
            0xAA,
            0xAA,
            0xAA,
            0xAA,
            0xAA, // color image run=8
            SPECIAL_FGBG_1,
        ];
        let result = decompress_8bpp(&src, 8, 2).unwrap();
        assert_eq!(
            &result[8..],
            &[0x55, 0x55, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]
        );
    }

    // ── BitsPerPixel::from_raw ──

    #[test]
    fn bpp_from_raw() {
        assert_eq!(BitsPerPixel::from_raw(8), Some(BitsPerPixel::Bpp8));
        assert_eq!(BitsPerPixel::from_raw(15), Some(BitsPerPixel::Bpp15));
        assert_eq!(BitsPerPixel::from_raw(16), Some(BitsPerPixel::Bpp16));
        assert_eq!(BitsPerPixel::from_raw(24), Some(BitsPerPixel::Bpp24));
        assert_eq!(BitsPerPixel::from_raw(32), None);
        assert_eq!(BitsPerPixel::from_raw(0), None);
    }
}
