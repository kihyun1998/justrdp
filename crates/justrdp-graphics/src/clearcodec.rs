#![forbid(unsafe_code)]

//! ClearCodec bitmap decoder (MS-RDPEGFX §2.2.4).
//!
//! Multi-layer codec: Residual → Band → Subcodec, with VBar and Glyph caching.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

// ── Constants (MS-RDPEGFX §2.2.4.1) ──

const FLAG_GLYPH_INDEX: u8 = 0x01;  // MS-RDPEGFX §2.2.4.1 — CLEARCODEC_FLAG_GLYPH_INDEX
const FLAG_GLYPH_HIT: u8 = 0x02;    // MS-RDPEGFX §2.2.4.1 — CLEARCODEC_FLAG_GLYPH_HIT
const FLAG_CACHE_RESET: u8 = 0x04;   // MS-RDPEGFX §2.2.4.1 — CLEARCODEC_FLAG_CACHE_RESET

const MAX_GLYPH_INDEX: u16 = 3999;   // MS-RDPEGFX §2.2.4.1
const GLYPH_STORAGE_SIZE: usize = 4000;
const VBAR_STORAGE_SIZE: usize = 32768;       // MS-RDPEGFX §2.2.4.1.1.2
const SHORT_VBAR_STORAGE_SIZE: usize = 16384; // MS-RDPEGFX §2.2.4.1.1.2
const MAX_BAND_HEIGHT: usize = 52;            // MS-RDPEGFX §2.2.4.1.1.2

const COMPOSITE_HEADER_SIZE: usize = 12; // MS-RDPEGFX §2.2.4.1.1

// ── Error type ──

/// ClearCodec decompression error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearCodecError {
    TruncatedStream,
    InvalidFlags(u8),
    InvalidGlyphIndex(u16),
    EmptyGlyphSlot(u16),
    InvalidVBarIndex(u16),
    EmptyVBarSlot(u16),
    InvalidRunLength,
    InvalidBandCoordinates,
    BandHeightExceeded,
    InvalidSubCodecId(u8),
    InvalidRlexPaletteCount(u8),
    InvalidRlexIndex,
    BitmapDataTooLarge,
    InvalidShortVBar,
    OutputOverflow,
}

impl fmt::Display for ClearCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedStream => write!(f, "ClearCodec: truncated stream"),
            Self::InvalidFlags(v) => write!(f, "ClearCodec: invalid flags 0x{v:02X}"),
            Self::InvalidGlyphIndex(v) => write!(f, "ClearCodec: invalid glyph index {v}"),
            Self::EmptyGlyphSlot(v) => write!(f, "ClearCodec: empty glyph slot {v}"),
            Self::InvalidVBarIndex(v) => write!(f, "ClearCodec: invalid VBar index {v}"),
            Self::EmptyVBarSlot(v) => write!(f, "ClearCodec: empty VBar slot {v}"),
            Self::InvalidRunLength => write!(f, "ClearCodec: invalid run length (zero)"),
            Self::InvalidBandCoordinates => write!(f, "ClearCodec: invalid band coordinates"),
            Self::BandHeightExceeded => write!(f, "ClearCodec: band height > 52"),
            Self::InvalidSubCodecId(v) => write!(f, "ClearCodec: invalid subcodec ID {v}"),
            Self::InvalidRlexPaletteCount(v) => write!(f, "ClearCodec: invalid RLEX palette count {v}"),
            Self::InvalidRlexIndex => write!(f, "ClearCodec: invalid RLEX stop/suite index"),
            Self::BitmapDataTooLarge => write!(f, "ClearCodec: bitmap data too large"),
            Self::InvalidShortVBar => write!(f, "ClearCodec: invalid short VBar"),
            Self::OutputOverflow => write!(f, "ClearCodec: output overflow"),
        }
    }
}

// ── Run-length decoding (shared by residual and RLEX) ──

/// Read a ClearCodec run-length factor (1, 3, or 7 bytes).
///
/// When `allow_zero` is false, a decoded run length of 0 returns `InvalidRunLength`.
/// RLEX subcodec uses `allow_zero = true` because run_length=0 means "suite only, no run".
fn read_run_length(src: &[u8], pos: &mut usize, allow_zero: bool) -> Result<u32, ClearCodecError> {
    if *pos >= src.len() {
        return Err(ClearCodecError::TruncatedStream);
    }
    let factor1 = src[*pos];
    *pos += 1;

    if factor1 < 0xFF {
        if factor1 == 0 && !allow_zero {
            return Err(ClearCodecError::InvalidRunLength);
        }
        return Ok(factor1 as u32);
    }

    // factor1 == 0xFF → read factor2 (u16 LE)
    if *pos + 2 > src.len() {
        return Err(ClearCodecError::TruncatedStream);
    }
    let factor2 = u16::from_le_bytes([src[*pos], src[*pos + 1]]);
    *pos += 2;

    if factor2 < 0xFFFF {
        if factor2 == 0 && !allow_zero {
            return Err(ClearCodecError::InvalidRunLength);
        }
        return Ok(factor2 as u32);
    }

    // factor2 == 0xFFFF → read factor3 (u32 LE)
    if *pos + 4 > src.len() {
        return Err(ClearCodecError::TruncatedStream);
    }
    let factor3 = u32::from_le_bytes([src[*pos], src[*pos + 1], src[*pos + 2], src[*pos + 3]]);
    *pos += 4;

    if factor3 == 0 && !allow_zero {
        return Err(ClearCodecError::InvalidRunLength);
    }
    Ok(factor3)
}

fn read_u16_le(src: &[u8], pos: &mut usize) -> Result<u16, ClearCodecError> {
    if *pos + 2 > src.len() {
        return Err(ClearCodecError::TruncatedStream);
    }
    let val = u16::from_le_bytes([src[*pos], src[*pos + 1]]);
    *pos += 2;
    Ok(val)
}

fn read_u32_le(src: &[u8], pos: &mut usize) -> Result<u32, ClearCodecError> {
    if *pos + 4 > src.len() {
        return Err(ClearCodecError::TruncatedStream);
    }
    let val = u32::from_le_bytes([src[*pos], src[*pos + 1], src[*pos + 2], src[*pos + 3]]);
    *pos += 4;
    Ok(val)
}

fn read_u8(src: &[u8], pos: &mut usize) -> Result<u8, ClearCodecError> {
    if *pos >= src.len() {
        return Err(ClearCodecError::TruncatedStream);
    }
    let val = src[*pos];
    *pos += 1;
    Ok(val)
}

// ── Residual Layer (MS-RDPEGFX §2.2.4.1.1.1) ──

fn decode_residual(
    data: &[u8],
    output: &mut [u8], // BGR buffer, 3 bytes per pixel
    width: usize,
    height: usize,
) -> Result<(), ClearCodecError> {
    let pixel_count = width.checked_mul(height).ok_or(ClearCodecError::BitmapDataTooLarge)?;
    let mut pos = 0;
    let mut pixel_pos = 0;

    while pos < data.len() && pixel_pos < pixel_count {
        if pos + 3 > data.len() {
            return Err(ClearCodecError::TruncatedStream);
        }
        let b = data[pos];
        let g = data[pos + 1];
        let r = data[pos + 2];
        pos += 3;

        let run_length = read_run_length(data, &mut pos, false)? as usize;

        for _ in 0..run_length {
            if pixel_pos >= pixel_count {
                return Err(ClearCodecError::OutputOverflow);
            }
            let base = pixel_pos * 3;
            output[base] = b;
            output[base + 1] = g;
            output[base + 2] = r;
            pixel_pos += 1;
        }
    }

    Ok(())
}

// ── Band Layer (MS-RDPEGFX §2.2.4.1.1.2) ──

fn decode_bands(
    data: &[u8],
    output: &mut [u8],
    width: usize,
    height: usize,
    vbar_storage: &mut Vec<Vec<u8>>,
    vbar_cursor: &mut u16,
    short_vbar_storage: &mut Vec<Vec<u8>>,
    short_vbar_cursor: &mut u16,
) -> Result<(), ClearCodecError> {
    let mut pos = 0;

    while pos < data.len() {
        // Read band header (11 bytes)
        let x_start = read_u16_le(data, &mut pos)? as usize;
        let x_end = read_u16_le(data, &mut pos)? as usize;
        let y_start = read_u16_le(data, &mut pos)? as usize;
        let y_end = read_u16_le(data, &mut pos)? as usize;
        let blue_bkg = read_u8(data, &mut pos)?;
        let green_bkg = read_u8(data, &mut pos)?;
        let red_bkg = read_u8(data, &mut pos)?;

        if x_end < x_start {
            return Err(ClearCodecError::InvalidBandCoordinates);
        }
        if y_end < y_start || (y_end - y_start + 1) > MAX_BAND_HEIGHT {
            return Err(ClearCodecError::BandHeightExceeded);
        }

        // Validate band coordinates against frame dimensions
        if x_end >= width || y_end >= height {
            return Err(ClearCodecError::InvalidBandCoordinates);
        }

        let band_height = y_end - y_start + 1;
        let vbar_count = x_end - x_start + 1;

        for vbar_idx in 0..vbar_count {
            let x_pos = x_start + vbar_idx;

            // Read VBar header (2 bytes minimum)
            let header_word = read_u16_le(data, &mut pos)?;

            // Determine VBar type from bit pattern
            if header_word & 0x8000 != 0 {
                // VBAR_CACHE_HIT: bit 15 = 1 (MS-RDPEGFX §2.2.4.1.1.2)
                let vbar_index = (header_word & 0x7FFF) as usize;
                if vbar_index >= vbar_storage.len() {
                    return Err(ClearCodecError::InvalidVBarIndex(vbar_index as u16));
                }
                if vbar_storage[vbar_index].is_empty() {
                    return Err(ClearCodecError::EmptyVBarSlot(vbar_index as u16));
                }
                let vbar = &vbar_storage[vbar_index];
                write_vbar_to_output(output, width, x_pos, y_start, band_height, vbar)?;
                // No cursor update on cache hit
            } else if header_word & 0x4000 != 0 {
                // SHORT_VBAR_CACHE_HIT: bit 15=0 (checked above), bit 14=1
                let short_vbar_index = (header_word & 0x3FFF) as usize;
                let short_vbar_y_on = read_u8(data, &mut pos)? as usize;

                // Reconstruct full VBar from short VBar + background
                let full_vbar = reconstruct_vbar_from_short(
                    short_vbar_storage,
                    short_vbar_index,
                    short_vbar_y_on,
                    band_height,
                    blue_bkg,
                    green_bkg,
                    red_bkg,
                )?;

                write_vbar_to_output(output, width, x_pos, y_start, band_height, &full_vbar)?;

                // Store full VBar
                let cursor = *vbar_cursor as usize;
                if cursor < vbar_storage.len() {
                    vbar_storage[cursor] = full_vbar;
                }
                *vbar_cursor = ((*vbar_cursor) + 1) % VBAR_STORAGE_SIZE as u16;
            } else {
                // SHORT_VBAR_CACHE_MISS: bits[15:14] = 0b00
                // yOn = bits[5:0] (6 bits), yOff = bits[11:6] (6 bits)
                let short_vbar_y_on = (header_word & 0x3F) as usize;
                let short_vbar_y_off = ((header_word >> 6) & 0x3F) as usize;

                if short_vbar_y_off < short_vbar_y_on {
                    return Err(ClearCodecError::InvalidShortVBar);
                }

                let short_pixel_count = short_vbar_y_off - short_vbar_y_on;
                // short_pixel_count is at most 63 (6-bit fields), so *3 <= 189, always safe.
                let short_byte_count = short_pixel_count.checked_mul(3)
                    .ok_or(ClearCodecError::TruncatedStream)?;

                if pos + short_byte_count > data.len() {
                    return Err(ClearCodecError::TruncatedStream);
                }

                let short_pixels = data[pos..pos + short_byte_count].to_vec();
                pos += short_byte_count;

                // Reconstruct full VBar (before moving short_pixels into storage)
                let full_vbar = build_full_vbar(
                    &short_pixels,
                    short_vbar_y_on,
                    band_height,
                    blue_bkg,
                    green_bkg,
                    red_bkg,
                );

                write_vbar_to_output(output, width, x_pos, y_start, band_height, &full_vbar)?;

                // Store short VBar (move — no clone needed)
                let short_cursor = *short_vbar_cursor as usize;
                if short_cursor < short_vbar_storage.len() {
                    short_vbar_storage[short_cursor] = short_pixels;
                }
                *short_vbar_cursor = ((*short_vbar_cursor) + 1) % SHORT_VBAR_STORAGE_SIZE as u16;

                // Store full VBar
                let cursor = *vbar_cursor as usize;
                if cursor < vbar_storage.len() {
                    vbar_storage[cursor] = full_vbar;
                }
                *vbar_cursor = ((*vbar_cursor) + 1) % VBAR_STORAGE_SIZE as u16;
            }
        }
    }

    Ok(())
}

fn reconstruct_vbar_from_short(
    short_vbar_storage: &[Vec<u8>],
    short_vbar_index: usize,
    short_vbar_y_on: usize,
    band_height: usize,
    blue_bkg: u8,
    green_bkg: u8,
    red_bkg: u8,
) -> Result<Vec<u8>, ClearCodecError> {
    if short_vbar_index >= short_vbar_storage.len() {
        return Err(ClearCodecError::InvalidVBarIndex(short_vbar_index as u16));
    }
    if short_vbar_storage[short_vbar_index].is_empty() {
        return Err(ClearCodecError::EmptyVBarSlot(short_vbar_index as u16));
    }
    let short_pixels = &short_vbar_storage[short_vbar_index];
    Ok(build_full_vbar(short_pixels, short_vbar_y_on, band_height, blue_bkg, green_bkg, red_bkg))
}

#[inline]
fn build_full_vbar(
    short_pixels: &[u8],
    short_vbar_y_on: usize,
    band_height: usize,
    blue_bkg: u8,
    green_bkg: u8,
    red_bkg: u8,
) -> Vec<u8> {
    let short_pixel_count = short_pixels.len() / 3;
    let mut full = vec![0u8; band_height * 3];

    for y in 0..band_height {
        let base = y * 3;
        if y < short_vbar_y_on || y >= short_vbar_y_on + short_pixel_count {
            // Background
            full[base] = blue_bkg;
            full[base + 1] = green_bkg;
            full[base + 2] = red_bkg;
        } else {
            // Short VBar pixel
            let src_base = (y - short_vbar_y_on) * 3;
            full[base] = short_pixels[src_base];
            full[base + 1] = short_pixels[src_base + 1];
            full[base + 2] = short_pixels[src_base + 2];
        }
    }

    full
}

#[inline]
fn write_vbar_to_output(
    output: &mut [u8],
    width: usize,
    x: usize,
    y_start: usize,
    band_height: usize,
    vbar: &[u8],
) -> Result<(), ClearCodecError> {
    for y in 0..band_height {
        let src_base = y * 3;
        if src_base + 3 > vbar.len() {
            return Err(ClearCodecError::TruncatedStream);
        }
        let dst_base = ((y_start + y) * width + x) * 3;
        if dst_base + 3 > output.len() {
            return Err(ClearCodecError::OutputOverflow);
        }
        output[dst_base] = vbar[src_base];
        output[dst_base + 1] = vbar[src_base + 1];
        output[dst_base + 2] = vbar[src_base + 2];
    }
    Ok(())
}

// ── Subcodec Layer (MS-RDPEGFX §2.2.4.1.1.3) ──

fn decode_subcodecs(
    data: &[u8],
    output: &mut [u8],
    out_width: usize,
) -> Result<(), ClearCodecError> {
    let mut pos = 0;

    while pos < data.len() {
        let x_start = read_u16_le(data, &mut pos)? as usize;
        let y_start = read_u16_le(data, &mut pos)? as usize;
        let sc_width = read_u16_le(data, &mut pos)? as usize;
        let sc_height = read_u16_le(data, &mut pos)? as usize;
        let bitmap_data_byte_count = read_u32_le(data, &mut pos)? as usize;
        let sub_codec_id = read_u8(data, &mut pos)?;

        let max_bitmap_size = sc_width.checked_mul(sc_height)
            .and_then(|n| n.checked_mul(3))
            .ok_or(ClearCodecError::BitmapDataTooLarge)?;
        if bitmap_data_byte_count > max_bitmap_size {
            return Err(ClearCodecError::BitmapDataTooLarge);
        }
        if pos + bitmap_data_byte_count > data.len() {
            return Err(ClearCodecError::TruncatedStream);
        }

        let bitmap_data = &data[pos..pos + bitmap_data_byte_count];
        pos += bitmap_data_byte_count;

        match sub_codec_id {
            0x00 => {
                // Raw BGR
                decode_subcodec_raw(bitmap_data, output, out_width, x_start, y_start, sc_width, sc_height)?;
            }
            0x02 => {
                // RLEX
                let decoded = decode_subcodec_rlex(bitmap_data, sc_width, sc_height)?;
                blit_bgr(&decoded, output, out_width, x_start, y_start, sc_width, sc_height)?;
            }
            _ => {
                return Err(ClearCodecError::InvalidSubCodecId(sub_codec_id));
            }
        }
    }

    Ok(())
}

fn decode_subcodec_raw(
    data: &[u8],
    output: &mut [u8],
    out_width: usize,
    x_start: usize,
    y_start: usize,
    sc_width: usize,
    sc_height: usize,
) -> Result<(), ClearCodecError> {
    for row in 0..sc_height {
        for col in 0..sc_width {
            let src_base = (row * sc_width + col) * 3;
            if src_base + 3 > data.len() {
                return Err(ClearCodecError::TruncatedStream);
            }
            let dst_base = ((y_start + row) * out_width + (x_start + col)) * 3;
            if dst_base + 3 > output.len() {
                return Err(ClearCodecError::OutputOverflow);
            }
            output[dst_base] = data[src_base];
            output[dst_base + 1] = data[src_base + 1];
            output[dst_base + 2] = data[src_base + 2];
        }
    }
    Ok(())
}

fn blit_bgr(
    src: &[u8],
    dst: &mut [u8],
    dst_width: usize,
    x_start: usize,
    y_start: usize,
    sc_width: usize,
    sc_height: usize,
) -> Result<(), ClearCodecError> {
    for row in 0..sc_height {
        for col in 0..sc_width {
            let src_base = (row * sc_width + col) * 3;
            if src_base + 3 > src.len() {
                return Err(ClearCodecError::TruncatedStream);
            }
            let dst_base = ((y_start + row) * dst_width + (x_start + col)) * 3;
            if dst_base + 3 > dst.len() {
                return Err(ClearCodecError::OutputOverflow);
            }
            dst[dst_base] = src[src_base];
            dst[dst_base + 1] = src[src_base + 1];
            dst[dst_base + 2] = src[src_base + 2];
        }
    }
    Ok(())
}

// ── RLEX Subcodec (MS-RDPEGFX §2.2.4.1.1.3.1.1) ──

fn decode_subcodec_rlex(
    data: &[u8],
    width: usize,
    height: usize,
) -> Result<Vec<u8>, ClearCodecError> {
    let pixel_count = width.checked_mul(height).ok_or(ClearCodecError::BitmapDataTooLarge)?;
    let buf_size = pixel_count.checked_mul(3).ok_or(ClearCodecError::BitmapDataTooLarge)?;
    let mut output = vec![0u8; buf_size];
    let mut pos = 0;

    // Read palette (MS-RDPEGFX §2.2.4.1.1.3.1.1: paletteCount in [1, 127])
    let palette_count = read_u8(data, &mut pos)? as usize;
    if palette_count == 0 || palette_count > 127 {
        return Err(ClearCodecError::InvalidRlexPaletteCount(palette_count as u8));
    }

    let mut palette = Vec::with_capacity(palette_count);
    for _ in 0..palette_count {
        if pos + 3 > data.len() {
            return Err(ClearCodecError::TruncatedStream);
        }
        palette.push([data[pos], data[pos + 1], data[pos + 2]]);
        pos += 3;
    }

    // Compute bit widths for stop_index extraction.
    // palette_count is in [1, 127], so palette_count-1 is in [0, 126].
    // leading_zeros(126) = 25, so stop_index_bits is at most 32-25 = 7.
    // Guard: if stop_index_bits >= 8, the u8 shift would overflow.
    let stop_index_bits = if palette_count <= 1 { 0 } else { 32 - ((palette_count - 1) as u32).leading_zeros() };
    if stop_index_bits >= 8 {
        return Err(ClearCodecError::InvalidRlexPaletteCount(palette_count as u8));
    }
    let stop_index_mask = if stop_index_bits == 0 { 0u8 } else { (1u8 << stop_index_bits) - 1 };

    let mut pixel_pos = 0;

    while pos < data.len() && pixel_pos < pixel_count {
        let combined = read_u8(data, &mut pos)?;
        let stop_index = (combined & stop_index_mask) as usize;
        let suite_depth = (combined >> stop_index_bits) as usize;

        if stop_index >= palette_count {
            return Err(ClearCodecError::InvalidRlexIndex);
        }
        if stop_index < suite_depth {
            return Err(ClearCodecError::InvalidRlexIndex);
        }
        let start_index = stop_index - suite_depth;

        // Read run length (0 is valid for RLEX — means no run, just suite).
        // Run-length field is always present (MS-RDPEGFX §2.2.4.1.1.3.1.1).
        let run_length = read_run_length(data, &mut pos, true)?;

        // Emit run (repeat startIndex color)
        let run_color = &palette[start_index];
        for _ in 0..run_length {
            if pixel_pos >= pixel_count {
                break;
            }
            let base = pixel_pos * 3;
            output[base] = run_color[0];
            output[base + 1] = run_color[1];
            output[base + 2] = run_color[2];
            pixel_pos += 1;
        }

        // Emit suite (startIndex..=stopIndex)
        for idx in start_index..=stop_index {
            if pixel_pos >= pixel_count {
                break;
            }
            let color = &palette[idx];
            let base = pixel_pos * 3;
            output[base] = color[0];
            output[base + 1] = color[1];
            output[base + 2] = color[2];
            pixel_pos += 1;
        }
    }

    Ok(output)
}

// ── Main Decoder ──

/// ClearCodec bitmap decoder (MS-RDPEGFX §2.2.4).
///
/// Stateful: maintains glyph cache and VBar caches across decode calls.
pub struct ClearCodecDecoder {
    glyph_storage: Vec<Option<Vec<u8>>>,
    vbar_storage: Vec<Vec<u8>>,
    vbar_cursor: u16,
    short_vbar_storage: Vec<Vec<u8>>,
    short_vbar_cursor: u16,
}

impl ClearCodecDecoder {
    /// Create a new ClearCodec decoder with empty caches.
    pub fn new() -> Self {
        Self {
            glyph_storage: vec![None; GLYPH_STORAGE_SIZE],
            vbar_storage: vec![Vec::new(); VBAR_STORAGE_SIZE],
            vbar_cursor: 0,
            short_vbar_storage: vec![Vec::new(); SHORT_VBAR_STORAGE_SIZE],
            short_vbar_cursor: 0,
        }
    }

    /// Decode a ClearCodec-encoded bitmap.
    ///
    /// Returns BGR pixel buffer of `width * height * 3` bytes.
    pub fn decode(
        &mut self,
        src: &[u8],
        width: u16,
        height: u16,
    ) -> Result<Vec<u8>, ClearCodecError> {
        let w = width as usize;
        let h = height as usize;

        if w == 0 || h == 0 {
            return Ok(Vec::new());
        }

        let pixel_count = w.checked_mul(h).ok_or(ClearCodecError::BitmapDataTooLarge)?;

        if src.len() < 2 {
            return Err(ClearCodecError::TruncatedStream);
        }

        let mut pos = 0;
        let flags = read_u8(src, &mut pos)?;
        // Sequence number: not used for decoding, consumed to advance the cursor.
        let _seq_number = read_u8(src, &mut pos)?;

        // Cache reset (MS-RDPEGFX §2.2.4): resets VBar caches and glyph cache
        if flags & FLAG_CACHE_RESET != 0 {
            self.vbar_cursor = 0;
            self.short_vbar_cursor = 0;
            self.glyph_storage.fill(None);
        }

        // Glyph index
        let glyph_index = if flags & FLAG_GLYPH_INDEX != 0 {
            let idx = read_u16_le(src, &mut pos)?;
            if idx > MAX_GLYPH_INDEX {
                return Err(ClearCodecError::InvalidGlyphIndex(idx));
            }
            Some(idx)
        } else {
            None
        };

        // Glyph hit — return cached bitmap
        if flags & FLAG_GLYPH_HIT != 0 {
            if let Some(idx) = glyph_index {
                if let Some(ref cached) = self.glyph_storage[idx as usize] {
                    return Ok(cached.clone());
                } else {
                    return Err(ClearCodecError::EmptyGlyphSlot(idx));
                }
            } else {
                return Err(ClearCodecError::InvalidFlags(flags));
            }
        }

        // Decode composite payload
        let output_size = pixel_count.checked_mul(3).ok_or(ClearCodecError::BitmapDataTooLarge)?;
        let mut output = vec![0u8; output_size];

        if pos + COMPOSITE_HEADER_SIZE > src.len() {
            return Err(ClearCodecError::TruncatedStream);
        }

        let residual_byte_count = read_u32_le(src, &mut pos)? as usize;
        let bands_byte_count = read_u32_le(src, &mut pos)? as usize;
        let subcodec_byte_count = read_u32_le(src, &mut pos)? as usize;

        let residual_end = pos.checked_add(residual_byte_count)
            .ok_or(ClearCodecError::TruncatedStream)?;
        let bands_end = residual_end.checked_add(bands_byte_count)
            .ok_or(ClearCodecError::TruncatedStream)?;
        let subcodec_end = bands_end.checked_add(subcodec_byte_count)
            .ok_or(ClearCodecError::TruncatedStream)?;

        if subcodec_end > src.len() {
            return Err(ClearCodecError::TruncatedStream);
        }

        // Residual layer
        if residual_byte_count > 0 {
            decode_residual(&src[pos..residual_end], &mut output, w, h)?;
        }

        // Band layer
        if bands_byte_count > 0 {
            decode_bands(
                &src[residual_end..bands_end],
                &mut output,
                w,
                h,
                &mut self.vbar_storage,
                &mut self.vbar_cursor,
                &mut self.short_vbar_storage,
                &mut self.short_vbar_cursor,
            )?;
        }

        // Subcodec layer
        if subcodec_byte_count > 0 {
            decode_subcodecs(&src[bands_end..subcodec_end], &mut output, w)?;
        }

        // Store glyph and return. When glyph caching is active, store the output
        // and return a clone (symmetric with the glyph-hit path which also clones).
        if let Some(idx) = glyph_index {
            self.glyph_storage[idx as usize] = Some(output);
            // Clone from cache — one allocation instead of two
            Ok(self.glyph_storage[idx as usize].as_ref().unwrap().clone())
        } else {
            Ok(output)
        }
    }
}

impl Default for ClearCodecDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(flags: u8, seq: u8, glyph_idx: Option<u16>) -> Vec<u8> {
        let mut h = vec![flags, seq];
        if let Some(idx) = glyph_idx {
            h.extend_from_slice(&idx.to_le_bytes());
        }
        h
    }

    fn make_composite(residual: &[u8], bands: &[u8], subcodec: &[u8]) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(&(residual.len() as u32).to_le_bytes());
        c.extend_from_slice(&(bands.len() as u32).to_le_bytes());
        c.extend_from_slice(&(subcodec.len() as u32).to_le_bytes());
        c.extend_from_slice(residual);
        c.extend_from_slice(bands);
        c.extend_from_slice(subcodec);
        c
    }

    // ── Residual layer ──

    #[test]
    fn residual_solid_color() {
        // 2×2 solid red: BGR=(0x00, 0x00, 0xFF), run=4
        let residual = [0x00, 0x00, 0xFF, 0x04];
        let mut header = make_header(0x00, 0x00, None);
        header.extend(make_composite(&residual, &[], &[]));

        let mut decoder = ClearCodecDecoder::new();
        let result = decoder.decode(&header, 2, 2).unwrap();
        assert_eq!(result.len(), 12); // 4 pixels × 3 bytes
        for px in 0..4 {
            assert_eq!(result[px * 3], 0x00);     // B
            assert_eq!(result[px * 3 + 1], 0x00); // G
            assert_eq!(result[px * 3 + 2], 0xFF); // R
        }
    }

    #[test]
    fn residual_two_segments() {
        // 4×1: 2 red + 2 blue
        let mut residual = Vec::new();
        residual.extend_from_slice(&[0x00, 0x00, 0xFF, 0x02]); // red ×2
        residual.extend_from_slice(&[0xFF, 0x00, 0x00, 0x02]); // blue ×2

        let mut header = make_header(0x00, 0x00, None);
        header.extend(make_composite(&residual, &[], &[]));

        let mut decoder = ClearCodecDecoder::new();
        let result = decoder.decode(&header, 4, 1).unwrap();
        assert_eq!(result[0..3], [0x00, 0x00, 0xFF]); // red
        assert_eq!(result[6..9], [0xFF, 0x00, 0x00]); // blue
    }

    // ── Subcodec: Raw ──

    #[test]
    fn subcodec_raw() {
        // 2×1 subcodec at (0,0), raw BGR
        let mut subcodec = Vec::new();
        subcodec.extend_from_slice(&0u16.to_le_bytes()); // xStart=0
        subcodec.extend_from_slice(&0u16.to_le_bytes()); // yStart=0
        subcodec.extend_from_slice(&2u16.to_le_bytes()); // width=2
        subcodec.extend_from_slice(&1u16.to_le_bytes()); // height=1
        subcodec.extend_from_slice(&6u32.to_le_bytes()); // bitmapDataByteCount=6
        subcodec.push(0x00); // subCodecId=Raw
        subcodec.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // pixel 0
        subcodec.extend_from_slice(&[0x11, 0x22, 0x33]); // pixel 1

        let mut header = make_header(0x00, 0x00, None);
        header.extend(make_composite(&[], &[], &subcodec));

        let mut decoder = ClearCodecDecoder::new();
        let result = decoder.decode(&header, 2, 1).unwrap();
        assert_eq!(result[0..3], [0xAA, 0xBB, 0xCC]);
        assert_eq!(result[3..6], [0x11, 0x22, 0x33]);
    }

    // ── Glyph caching ──

    #[test]
    fn glyph_store_and_hit() {
        let residual = [0xFF, 0x00, 0x00, 0x01]; // 1 blue pixel
        let mut store_msg = make_header(FLAG_GLYPH_INDEX, 0x00, Some(42));
        store_msg.extend(make_composite(&residual, &[], &[]));

        let mut decoder = ClearCodecDecoder::new();
        let result1 = decoder.decode(&store_msg, 1, 1).unwrap();
        assert_eq!(result1, [0xFF, 0x00, 0x00]);

        // Glyph hit
        let hit_msg = make_header(FLAG_GLYPH_INDEX | FLAG_GLYPH_HIT, 0x01, Some(42));
        let result2 = decoder.decode(&hit_msg, 1, 1).unwrap();
        assert_eq!(result2, result1);
    }

    #[test]
    fn glyph_hit_empty_slot_error() {
        let mut decoder = ClearCodecDecoder::new();
        let msg = make_header(FLAG_GLYPH_INDEX | FLAG_GLYPH_HIT, 0x00, Some(100));
        let result = decoder.decode(&msg, 1, 1);
        assert_eq!(result, Err(ClearCodecError::EmptyGlyphSlot(100)));
    }

    #[test]
    fn invalid_glyph_index() {
        let mut decoder = ClearCodecDecoder::new();
        let msg = make_header(FLAG_GLYPH_INDEX, 0x00, Some(4000)); // out of range
        let result = decoder.decode(&msg, 1, 1);
        assert_eq!(result, Err(ClearCodecError::InvalidGlyphIndex(4000)));
    }

    // ── Cache reset ──

    #[test]
    fn cache_reset_clears_cursors() {
        let mut decoder = ClearCodecDecoder::new();
        decoder.vbar_cursor = 100;
        decoder.short_vbar_cursor = 50;

        let residual = [0x00, 0x00, 0x00, 0x01];
        let mut msg = make_header(FLAG_CACHE_RESET, 0x00, None);
        msg.extend(make_composite(&residual, &[], &[]));

        decoder.decode(&msg, 1, 1).unwrap();
        assert_eq!(decoder.vbar_cursor, 0);
        assert_eq!(decoder.short_vbar_cursor, 0);
    }

    // ── Truncated stream ──

    #[test]
    fn truncated_stream() {
        let mut decoder = ClearCodecDecoder::new();
        let result = decoder.decode(&[0x00], 1, 1);
        assert_eq!(result, Err(ClearCodecError::TruncatedStream));
    }

    // ── Run length: extended ──

    #[test]
    fn residual_extended_run_factor2() {
        // factor1=0xFF, factor2=300 (u16 LE)
        let mut residual = Vec::new();
        residual.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // BGR
        residual.push(0xFF); // factor1
        residual.extend_from_slice(&300u16.to_le_bytes()); // factor2

        let mut header = make_header(0x00, 0x00, None);
        header.extend(make_composite(&residual, &[], &[]));

        let mut decoder = ClearCodecDecoder::new();
        let result = decoder.decode(&header, 300, 1).unwrap();
        assert_eq!(result.len(), 900);
        assert_eq!(result[0..3], [0xAA, 0xBB, 0xCC]);
        assert_eq!(result[897..900], [0xAA, 0xBB, 0xCC]);
    }

    // ── Empty layers ──

    #[test]
    fn all_layers_empty() {
        let mut header = make_header(0x00, 0x00, None);
        header.extend(make_composite(&[], &[], &[]));

        let mut decoder = ClearCodecDecoder::new();
        let result = decoder.decode(&header, 2, 2).unwrap();
        assert_eq!(result.len(), 12);
        assert!(result.iter().all(|&b| b == 0)); // all black
    }

    // ── Band layer: SHORT_VBAR_CACHE_MISS ──

    #[test]
    fn band_short_vbar_cache_miss() {
        // 3×3 output. Band: x=[0,0], y=[0,2] (height=3), bkg=BGR(0x10,0x20,0x30).
        // SHORT_VBAR_CACHE_MISS: yOn=1, yOff=2 → 1 short pixel at y=1.
        // header_word: yOn=1 in bits[5:0], yOff=2 in bits[11:6], bits[15:14]=0b00
        // = (2 << 6) | 1 = 0x0081 (LE: 0x81, 0x00)
        let mut bands = Vec::new();
        bands.extend_from_slice(&0u16.to_le_bytes()); // xStart=0
        bands.extend_from_slice(&0u16.to_le_bytes()); // xEnd=0
        bands.extend_from_slice(&0u16.to_le_bytes()); // yStart=0
        bands.extend_from_slice(&2u16.to_le_bytes()); // yEnd=2
        bands.extend_from_slice(&[0x10, 0x20, 0x30]); // bkg BGR
        let header_word: u16 = (2 << 6) | 1; // yOn=1, yOff=2
        bands.extend_from_slice(&header_word.to_le_bytes());
        bands.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // 1 short pixel

        let mut msg = make_header(0x00, 0x00, None);
        msg.extend(make_composite(&[], &bands, &[]));

        let mut decoder = ClearCodecDecoder::new();
        let result = decoder.decode(&msg, 3, 3).unwrap();

        // Column 0: y=0 bkg, y=1 short pixel, y=2 bkg
        assert_eq!(result[0..3], [0x10, 0x20, 0x30], "y=0 bkg");
        assert_eq!(result[9..12], [0xAA, 0xBB, 0xCC], "y=1 short pixel");
        assert_eq!(result[18..21], [0x10, 0x20, 0x30], "y=2 bkg");
        assert_eq!(decoder.vbar_cursor, 1);
        assert_eq!(decoder.short_vbar_cursor, 1);
    }

    // ── Band layer: VBAR_CACHE_HIT after CACHE_MISS ──

    #[test]
    fn band_vbar_cache_hit_after_miss() {
        // Store VBar via CACHE_MISS, then hit it in a second decode.
        let mut bands_miss = Vec::new();
        bands_miss.extend_from_slice(&0u16.to_le_bytes());
        bands_miss.extend_from_slice(&0u16.to_le_bytes()); // xEnd=0
        bands_miss.extend_from_slice(&0u16.to_le_bytes());
        bands_miss.extend_from_slice(&1u16.to_le_bytes()); // yEnd=1, height=2
        bands_miss.extend_from_slice(&[0x00, 0x00, 0x00]); // bkg
        let hw: u16 = (2 << 6) | 0; // yOn=0, yOff=2 → 2 pixels
        bands_miss.extend_from_slice(&hw.to_le_bytes());
        bands_miss.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]); // 2 pixels

        let mut decoder = ClearCodecDecoder::new();
        let mut msg1 = make_header(0x00, 0x00, None);
        msg1.extend(make_composite(&[], &bands_miss, &[]));
        let first = decoder.decode(&msg1, 1, 2).unwrap();

        // VBAR_CACHE_HIT: bit15=1, index=0 → word = 0x8000
        let mut bands_hit = Vec::new();
        bands_hit.extend_from_slice(&0u16.to_le_bytes());
        bands_hit.extend_from_slice(&0u16.to_le_bytes());
        bands_hit.extend_from_slice(&0u16.to_le_bytes());
        bands_hit.extend_from_slice(&1u16.to_le_bytes());
        bands_hit.extend_from_slice(&[0x00, 0x00, 0x00]);
        bands_hit.extend_from_slice(&0x8000u16.to_le_bytes());

        let mut msg2 = make_header(0x00, 0x01, None);
        msg2.extend(make_composite(&[], &bands_hit, &[]));
        let second = decoder.decode(&msg2, 1, 2).unwrap();

        assert_eq!(first, second);
        assert_eq!(decoder.vbar_cursor, 1); // no advance on hit
    }

    // ── RLEX subcodec ──

    #[test]
    fn subcodec_rlex_basic() {
        // 4×1, 2-color palette: blue and green.
        // Segment 1: stop=1, suite_depth=0, run=2 → 2×green + 1×green (suite)
        // Segment 2: stop=0, suite_depth=0, run=0 → 1×blue (suite only)
        // Total: 3 green + 1 blue = 4 pixels
        let mut bitmap_data = Vec::new();
        bitmap_data.push(2u8); // paletteCount
        bitmap_data.extend_from_slice(&[0xFF, 0x00, 0x00]); // palette[0] = blue
        bitmap_data.extend_from_slice(&[0x00, 0xFF, 0x00]); // palette[1] = green
        // stop_index_bits = ceil(log2(2)) = 1, mask = 0x01
        bitmap_data.push(0x01); // stop=1, suite_depth=0
        bitmap_data.push(2u8);  // run=2
        bitmap_data.push(0x00); // stop=0, suite_depth=0
        bitmap_data.push(0u8);  // run=0

        let mut subcodec = Vec::new();
        subcodec.extend_from_slice(&0u16.to_le_bytes());
        subcodec.extend_from_slice(&0u16.to_le_bytes());
        subcodec.extend_from_slice(&4u16.to_le_bytes());
        subcodec.extend_from_slice(&1u16.to_le_bytes());
        subcodec.extend_from_slice(&(bitmap_data.len() as u32).to_le_bytes());
        subcodec.push(0x02); // RLEX
        subcodec.extend_from_slice(&bitmap_data);

        let mut msg = make_header(0x00, 0x00, None);
        msg.extend(make_composite(&[], &[], &subcodec));

        let mut decoder = ClearCodecDecoder::new();
        let result = decoder.decode(&msg, 4, 1).unwrap();
        assert_eq!(result[0..3], [0x00, 0xFF, 0x00]); // green
        assert_eq!(result[3..6], [0x00, 0xFF, 0x00]); // green
        assert_eq!(result[6..9], [0x00, 0xFF, 0x00]); // green
        assert_eq!(result[9..12], [0xFF, 0x00, 0x00]); // blue
    }

    // ── Multiple layers overwriting ──

    #[test]
    fn layers_overwrite_in_order() {
        // Residual fills all red, subcodec overwrites pixel 0 to blue.
        let residual = [0x00, 0x00, 0xFF, 0x02]; // 2 red pixels

        let mut subcodec = Vec::new();
        subcodec.extend_from_slice(&0u16.to_le_bytes()); // xStart=0
        subcodec.extend_from_slice(&0u16.to_le_bytes()); // yStart=0
        subcodec.extend_from_slice(&1u16.to_le_bytes()); // width=1
        subcodec.extend_from_slice(&1u16.to_le_bytes()); // height=1
        subcodec.extend_from_slice(&3u32.to_le_bytes()); // 3 bytes
        subcodec.push(0x00); // Raw
        subcodec.extend_from_slice(&[0xFF, 0x00, 0x00]); // blue

        let mut msg = make_header(0x00, 0x00, None);
        msg.extend(make_composite(&residual, &[], &subcodec));

        let mut decoder = ClearCodecDecoder::new();
        let result = decoder.decode(&msg, 2, 1).unwrap();
        assert_eq!(result[0..3], [0xFF, 0x00, 0x00]); // pixel 0: blue (overwritten)
        assert_eq!(result[3..6], [0x00, 0x00, 0xFF]); // pixel 1: red (from residual)
    }

    // ── Band height boundary ──

    #[test]
    fn band_height_exceeded_error() {
        let mut bands = Vec::new();
        bands.extend_from_slice(&0u16.to_le_bytes());
        bands.extend_from_slice(&0u16.to_le_bytes());
        bands.extend_from_slice(&0u16.to_le_bytes());
        bands.extend_from_slice(&52u16.to_le_bytes()); // yEnd=52 → height=53 > 52
        bands.extend_from_slice(&[0, 0, 0]);

        let mut msg = make_header(0x00, 0x00, None);
        msg.extend(make_composite(&[], &bands, &[]));

        let mut decoder = ClearCodecDecoder::new();
        let result = decoder.decode(&msg, 1, 53);
        assert_eq!(result, Err(ClearCodecError::BandHeightExceeded));
    }

    // ── FLAG_GLYPH_HIT without FLAG_GLYPH_INDEX ──

    #[test]
    fn glyph_hit_without_index_flag() {
        let mut decoder = ClearCodecDecoder::new();
        // FLAG_GLYPH_HIT set but FLAG_GLYPH_INDEX not set → InvalidFlags
        let msg = vec![FLAG_GLYPH_HIT, 0x00];
        let result = decoder.decode(&msg, 1, 1);
        assert_eq!(result, Err(ClearCodecError::InvalidFlags(FLAG_GLYPH_HIT)));
    }

    // ── RLEX with single-color palette ──

    #[test]
    fn subcodec_rlex_single_palette() {
        // 2×1, palette_count=1, color=green.
        // stop_index_bits=0, so combined byte is entirely suite_depth.
        // Segment: combined=0x00 (suite_depth=0, stop_index=0), run=2
        // → 2×green (run) + 1×green (suite of [0..=0]) = 3... but we need 2 pixels.
        // Actually: run=1, suite [0..=0] = 1 pixel. Total = 2.
        let mut bitmap_data = Vec::new();
        bitmap_data.push(1u8); // paletteCount = 1
        bitmap_data.extend_from_slice(&[0x00, 0xFF, 0x00]); // palette[0] = green
        bitmap_data.push(0x00); // combined: stop=0, suite_depth=0
        bitmap_data.push(1u8);  // run=1
        // Total: 1 (run) + 1 (suite [0..=0]) = 2 pixels

        let mut subcodec = Vec::new();
        subcodec.extend_from_slice(&0u16.to_le_bytes());
        subcodec.extend_from_slice(&0u16.to_le_bytes());
        subcodec.extend_from_slice(&2u16.to_le_bytes()); // width=2
        subcodec.extend_from_slice(&1u16.to_le_bytes()); // height=1
        subcodec.extend_from_slice(&(bitmap_data.len() as u32).to_le_bytes());
        subcodec.push(0x02); // RLEX
        subcodec.extend_from_slice(&bitmap_data);

        let mut msg = make_header(0x00, 0x00, None);
        msg.extend(make_composite(&[], &[], &subcodec));

        let mut decoder = ClearCodecDecoder::new();
        let result = decoder.decode(&msg, 2, 1).unwrap();
        assert_eq!(result[0..3], [0x00, 0xFF, 0x00]); // green
        assert_eq!(result[3..6], [0x00, 0xFF, 0x00]); // green
    }
}
