#![forbid(unsafe_code)]

//! RDP 6.0 Planar Bitmap Codec (MS-RDPEGDI §3.1.9).
//!
//! Decompresses planar-encoded bitmaps where each color plane (A, R, G, B)
//! is stored separately with optional RLE compression and delta encoding.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

// ── FormatHeader bit masks (MS-RDPEGDI §2.2.2.5.1) ──

/// Color Loss Level mask — bits [0-2].
pub const FORMAT_HEADER_CLL_MASK: u8 = 0x07;
/// Chroma subsampling flag — bit [3].
pub const FORMAT_HEADER_CS: u8 = 0x08;
/// RLE compression flag — bit [4].
pub const FORMAT_HEADER_RLE: u8 = 0x10;
/// No-alpha flag — bit [5]; alpha plane absent, assumed 0xFF.
pub const FORMAT_HEADER_NA: u8 = 0x20;

// ── Error type ──

/// Planar codec decompression error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanarError {
    /// Compressed stream ended unexpectedly.
    TruncatedStream,
    /// RLE control byte was zero (invalid per spec).
    InvalidControlByte,
    /// FormatHeader contains an invalid combination of flags.
    InvalidFormatHeader(u8),
    /// Decompressed output exceeds the expected buffer size.
    OutputOverflow,
}

impl fmt::Display for PlanarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedStream => write!(f, "Planar: truncated stream"),
            Self::InvalidControlByte => write!(f, "Planar: zero control byte"),
            Self::InvalidFormatHeader(h) => write!(f, "Planar: invalid format header 0x{h:02X}"),
            Self::OutputOverflow => write!(f, "Planar: output buffer overflow"),
        }
    }
}

// ── Stream reader (reusable helper) ──

struct StreamReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> StreamReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline]
    fn read_u8(&mut self) -> Result<u8, PlanarError> {
        if self.pos >= self.data.len() {
            return Err(PlanarError::TruncatedStream);
        }
        let val = self.data[self.pos];
        self.pos += 1;
        Ok(val)
    }

    /// Read exactly `count` bytes into `dst` starting at `dst_offset`.
    fn read_exact(&mut self, dst: &mut [u8], dst_offset: usize, count: usize) -> Result<(), PlanarError> {
        if self.pos + count > self.data.len() {
            return Err(PlanarError::TruncatedStream);
        }
        if dst_offset + count > dst.len() {
            return Err(PlanarError::OutputOverflow);
        }
        dst[dst_offset..dst_offset + count].copy_from_slice(&self.data[self.pos..self.pos + count]);
        self.pos += count;
        Ok(())
    }
}

// ── Delta decoding ──

/// Decode a delta-encoded byte (LSB = sign bit, upper 7 bits = magnitude).
/// MS-RDPEGDI §3.1.9.2: if LSB=1 → negative, if LSB=0 → positive.
#[inline]
fn decode_delta(raw: u8) -> i16 {
    let magnitude = (raw >> 1) as i16;
    if raw & 1 != 0 {
        -magnitude
    } else {
        magnitude
    }
}

/// Clamp an i16 to the u8 range [0, 255].
#[inline]
fn clamp_u8(val: i16) -> u8 {
    if val < 0 {
        0
    } else if val > 255 {
        255
    } else {
        val as u8
    }
}

// ── Per-plane RLE decoder (MS-RDPEGDI §3.1.9.2) ──

/// Decode one RLE-compressed color plane.
///
/// The plane is decoded scanline by scanline. The first scanline uses
/// absolute values; subsequent scanlines use delta encoding.
fn decode_plane_rle(
    reader: &mut StreamReader<'_>,
    plane: &mut [u8],
    width: usize,
    height: usize,
) -> Result<(), PlanarError> {
    if width == 0 || height == 0 {
        return Ok(());
    }

    for row in 0..height {
        let row_start = row * width;
        let is_first_row = row == 0;
        let mut col: usize = 0;

        while col < width {
            let control_byte = reader.read_u8()?;
            if control_byte == 0 {
                return Err(PlanarError::InvalidControlByte);
            }

            let n_run_length = control_byte & 0x0F;
            let c_raw_bytes = (control_byte >> 4) & 0x0F;

            // Determine actual run length and raw byte count
            let (raw_count, actual_run) = match n_run_length {
                1 => (0usize, 16 + c_raw_bytes as usize), // long run mode 1
                2 => (0usize, 32 + c_raw_bytes as usize), // long run mode 2
                _ => (c_raw_bytes as usize, n_run_length as usize),
            };

            // Decode raw bytes
            let mut last_raw_value: u8 = 0;
            let mut last_delta: i16 = 0;

            for _ in 0..raw_count {
                if col >= width {
                    return Err(PlanarError::OutputOverflow);
                }
                let raw_byte = reader.read_u8()?;
                let idx = row_start + col;

                if is_first_row {
                    plane[idx] = raw_byte;
                    last_raw_value = raw_byte;
                    last_delta = 0; // not used on first row
                } else {
                    let delta = decode_delta(raw_byte);
                    let prev = plane[(row - 1) * width + col] as i16;
                    let decoded = clamp_u8(prev + delta);
                    plane[idx] = decoded;
                    last_raw_value = decoded;
                    last_delta = delta;
                }
                col += 1;
            }

            // Decode run
            for _ in 0..actual_run {
                if col >= width {
                    return Err(PlanarError::OutputOverflow);
                }
                let idx = row_start + col;

                if is_first_row {
                    plane[idx] = last_raw_value;
                } else {
                    // Run repeats the last delta (or 0 if no raw bytes)
                    let delta = if raw_count == 0 { 0 } else { last_delta };
                    let prev = plane[(row - 1) * width + col] as i16;
                    plane[idx] = clamp_u8(prev + delta);
                }
                col += 1;
            }
        }
    }

    Ok(())
}

/// Read a raw (non-RLE) plane: width * height absolute bytes.
fn decode_plane_raw(
    reader: &mut StreamReader<'_>,
    plane: &mut [u8],
    width: usize,
    height: usize,
) -> Result<(), PlanarError> {
    let total = width * height;
    if total == 0 {
        return Ok(());
    }
    reader.read_exact(plane, 0, total)
}

// ── Chroma super-sampling (MS-RDPEGDI §3.1.9.1.3) ──

/// Upsample a subsampled plane from (sub_w × sub_h) to (full_w × full_h)
/// by nearest-neighbor 2× expansion.
fn super_sample(
    subsampled: &[u8],
    sub_w: usize,
    sub_h: usize,
    full_w: usize,
    full_h: usize,
) -> Vec<u8> {
    let mut out = vec![0u8; full_w * full_h];
    for y in 0..full_h {
        let sy = core::cmp::min(y / 2, sub_h.saturating_sub(1));
        for x in 0..full_w {
            let sx = core::cmp::min(x / 2, sub_w.saturating_sub(1));
            out[y * full_w + x] = subsampled[sy * sub_w + sx];
        }
    }
    out
}

// ── Color space conversion (MS-RDPEGDI §3.1.9.1.2) ──

/// Convert AYCoCg planes to ARGB output.
///
/// Co and Cg have already been Color Loss Reduction inverse-shifted by CLL.
fn aycocg_to_argb(
    alpha: &[u8],
    y_plane: &[u8],
    co_plane: &[i16],
    cg_plane: &[i16],
    dst: &mut [u8],
    pixel_count: usize,
) {
    for i in 0..pixel_count {
        let y = y_plane[i] as i16;
        let co = co_plane[i];
        let cg = cg_plane[i];

        // MS-RDPEGDI §3.1.9.1.2 inverse transform
        let r = clamp_u8(y + co - cg);
        let g = clamp_u8(y + cg);
        let b = clamp_u8(y - co - cg);
        let a = alpha[i];

        let base = i * 4;
        dst[base] = b;
        dst[base + 1] = g;
        dst[base + 2] = r;
        dst[base + 3] = a;
    }
}

/// Reassemble ARGB planes into BGRA pixel output.
fn argb_planes_to_bgra(
    alpha: &[u8],
    red: &[u8],
    green: &[u8],
    blue: &[u8],
    dst: &mut [u8],
    pixel_count: usize,
) {
    for i in 0..pixel_count {
        let base = i * 4;
        dst[base] = blue[i];
        dst[base + 1] = green[i];
        dst[base + 2] = red[i];
        dst[base + 3] = alpha[i];
    }
}

// ── Main decoder ──

/// RDP 6.0 Planar Bitmap decompressor (MS-RDPEGDI §3.1.9).
///
/// Stateless: each call to [`decompress`](Self::decompress) is independent.
#[derive(Debug, Clone)]
pub struct PlanarDecompressor;

impl PlanarDecompressor {
    /// Create a new Planar decompressor.
    pub const fn new() -> Self {
        Self
    }

    /// Decompress a planar-encoded bitmap stream.
    ///
    /// # Arguments
    ///
    /// * `src` - Compressed RDP6_BITMAP_STREAM bytes
    /// * `width` - Bitmap width in pixels
    /// * `height` - Bitmap height in pixels
    /// * `dst` - Output buffer; will be resized to `width * height * 4` (BGRA)
    ///
    /// # Errors
    ///
    /// Returns [`PlanarError`] on malformed input.
    pub fn decompress(
        &self,
        src: &[u8],
        width: u16,
        height: u16,
        dst: &mut Vec<u8>,
    ) -> Result<(), PlanarError> {
        let w = width as usize;
        let h = height as usize;
        let pixel_count = w * h;
        let total_output = pixel_count * 4;

        dst.clear();
        dst.resize(total_output, 0);

        if pixel_count == 0 {
            return Ok(());
        }

        let mut reader = StreamReader::new(src);

        // Step 1: Read FormatHeader
        let format_header = reader.read_u8()?;
        let cll = format_header & FORMAT_HEADER_CLL_MASK;
        let cs = format_header & FORMAT_HEADER_CS != 0;
        let rle = format_header & FORMAT_HEADER_RLE != 0;
        let na = format_header & FORMAT_HEADER_NA != 0;

        // Validate: CS requires CLL > 0
        if cs && cll == 0 {
            return Err(PlanarError::InvalidFormatHeader(format_header));
        }

        // Step 2-4: Determine plane dimensions
        let (chroma_w, chroma_h) = if cs {
            ((w + 1) / 2, (h + 1) / 2)
        } else {
            (w, h)
        };

        // Allocate plane buffers
        let mut alpha_plane = vec![0xFFu8; pixel_count];
        let mut plane2 = vec![0u8; pixel_count]; // R or Y
        let mut plane3_raw;                       // G or Co (possibly subsampled)
        let mut plane4_raw;                       // B or Cg (possibly subsampled)

        let chroma_size = chroma_w * chroma_h;
        plane3_raw = vec![0u8; chroma_size];
        plane4_raw = vec![0u8; chroma_size];

        // Step 5: Decode planes
        if rle {
            // Alpha plane
            if !na {
                decode_plane_rle(&mut reader, &mut alpha_plane, w, h)?;
            }
            // Plane 2 (R or Y)
            decode_plane_rle(&mut reader, &mut plane2, w, h)?;
            // Plane 3 (G or Co)
            decode_plane_rle(&mut reader, &mut plane3_raw, chroma_w, chroma_h)?;
            // Plane 4 (B or Cg)
            decode_plane_rle(&mut reader, &mut plane4_raw, chroma_w, chroma_h)?;
        } else {
            // Raw planes
            if !na {
                decode_plane_raw(&mut reader, &mut alpha_plane, w, h)?;
            }
            decode_plane_raw(&mut reader, &mut plane2, w, h)?;
            decode_plane_raw(&mut reader, &mut plane3_raw, chroma_w, chroma_h)?;
            decode_plane_raw(&mut reader, &mut plane4_raw, chroma_w, chroma_h)?;

            // Step 6: Read and discard Pad byte (mandatory per spec §2.2.2.5.1)
            let _ = reader.read_u8()?;
        }

        // Step 7-10: Color space conversion and reassembly
        if cll > 0 {
            // AYCoCg mode

            // Super-sample chroma planes if needed
            let plane3_full = if cs {
                super_sample(&plane3_raw, chroma_w, chroma_h, w, h)
            } else {
                plane3_raw
            };
            let plane4_full = if cs {
                super_sample(&plane4_raw, chroma_w, chroma_h, w, h)
            } else {
                plane4_raw
            };

            // Color Loss Reduction inverse: left-shift by CLL
            let mut co_plane = vec![0i16; pixel_count];
            let mut cg_plane = vec![0i16; pixel_count];
            for i in 0..pixel_count {
                co_plane[i] = (plane3_full[i] as i8 as i16) << cll;
                cg_plane[i] = (plane4_full[i] as i8 as i16) << cll;
            }

            // AYCoCg → ARGB → BGRA
            aycocg_to_argb(&alpha_plane, &plane2, &co_plane, &cg_plane, dst, pixel_count);
        } else {
            // ARGB mode: planes are R, G, B directly

            // Super-sampling doesn't apply in ARGB mode (CS must be 0)
            argb_planes_to_bgra(&alpha_plane, &plane2, &plane3_raw, &plane4_raw, dst, pixel_count);
        }

        Ok(())
    }
}

impl Default for PlanarDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Encoder ──

/// Encoder configuration for the Planar Codec.
#[derive(Debug, Clone)]
pub struct PlanarEncoderConfig {
    /// Use per-plane RLE compression (recommended: true).
    pub use_rle: bool,
    /// Skip the alpha plane (set NA flag; alpha assumed 0xFF).
    pub skip_alpha: bool,
}

impl Default for PlanarEncoderConfig {
    fn default() -> Self {
        Self {
            use_rle: true,
            skip_alpha: true,
        }
    }
}

/// Encode a delta value using the LSB-sign scheme (MS-RDPEGDI §3.1.9.2).
/// positive/zero → even byte, negative → odd byte.
///
/// Note: the scheme represents magnitudes 0–127 only. Deltas with
/// |magnitude| > 127 are truncated (matching FreeRDP behavior).
#[inline]
fn encode_delta(delta: i16) -> u8 {
    if delta >= 0 {
        ((delta as u16) << 1) as u8
    } else {
        (((-delta) as u16) << 1 | 1) as u8
    }
}

/// Encode one RLE-compressed color plane (MS-RDPEGDI §3.1.9.2).
///
/// First scanline uses absolute values; subsequent scanlines use delta encoding.
fn encode_plane_rle(plane: &[u8], width: usize, height: usize, out: &mut Vec<u8>) {
    if width == 0 || height == 0 {
        return;
    }

    for row in 0..height {
        let row_start = row * width;
        let is_first_row = row == 0;

        // Build the values to encode for this scanline
        let mut values = Vec::with_capacity(width);
        for col in 0..width {
            let idx = row_start + col;
            if is_first_row {
                values.push(plane[idx]);
            } else {
                let prev = plane[(row - 1) * width + col] as i16;
                let curr = plane[idx] as i16;
                let delta = curr - prev;
                values.push(encode_delta(delta));
            }
        }

        // Encode values into RLE segments
        encode_scanline_rle(&values, out);
    }
}

/// Encode a single scanline of values into RDP6_RLE_SEGMENT sequences.
fn encode_scanline_rle(values: &[u8], out: &mut Vec<u8>) {
    let len = values.len();
    let mut pos = 0;

    while pos < len {
        // Find how many distinct (raw) values we need before a run starts
        let raw_start = pos;
        let mut raw_end = pos;

        // Scan for a run of >= 3 identical values
        while raw_end < len {
            let remaining = len - raw_end;
            if remaining >= 3 && values[raw_end] == values[raw_end + 1] && values[raw_end] == values[raw_end + 2] {
                break; // Found a run start
            }
            raw_end += 1;
        }

        // Emit raw-only segments for raw_start..raw_end (max 15 raw per segment)
        let total_raw = raw_end - raw_start;
        let mut raw_emitted = 0;

        while raw_emitted < total_raw {
            let chunk = core::cmp::min(15, total_raw - raw_emitted);
            // controlByte: cRawBytes=chunk, nRunLength=0
            let control = (chunk as u8) << 4;
            out.push(control);
            for i in 0..chunk {
                out.push(values[raw_start + raw_emitted + i]);
            }
            raw_emitted += chunk;
        }
        pos = raw_end;

        if pos >= len {
            break;
        }

        // Count the run length
        let run_val = values[pos];
        let run_start = pos;
        while pos < len && values[pos] == run_val {
            pos += 1;
        }
        let run_len = pos - run_start;

        // Emit the run. We need at least some raw bytes to establish the run value,
        // unless the run value matches the last emitted raw byte.
        // Strategy: emit 1 raw byte + (run_len - 1) run, or use extended encodings.
        emit_run_segments(run_val, run_len, out);
    }
}

/// Emit RLE segments for a run of identical values.
///
/// Each segment must include at least 1 raw byte to establish the run
/// value, because the decoder resets the base value per segment.
/// Extended run modes (nRunLength=1,2) use base value 0, so they are
/// only used when the value IS 0.
fn emit_run_segments(value: u8, mut run_len: usize, out: &mut Vec<u8>) {
    while run_len > 0 {
        if value == 0 && run_len >= 16 {
            // Can use extended modes (base value = 0 matches our value)
            if run_len >= 32 {
                let excess = core::cmp::min(run_len - 32, 15);
                let control = ((excess as u8) << 4) | 2;
                out.push(control);
                run_len -= 32 + excess;
            } else {
                let excess = core::cmp::min(run_len - 16, 15);
                let control = ((excess as u8) << 4) | 1;
                out.push(control);
                run_len -= 16 + excess;
            }
        } else if run_len >= 4 {
            // 1 raw byte + up to 15 run = 16 values per segment.
            // min(run_len-1, 15) >= 3 since run_len >= 4, so nRunLength is always >= 3
            // (never hits reserved long-run codes 1 or 2).
            let run_part = core::cmp::min(run_len - 1, 15);
            let control = (1u8 << 4) | (run_part as u8);
            out.push(control);
            out.push(value);
            run_len -= 1 + run_part;
        } else {
            // Small remainder (1-3): emit as raw bytes
            let control = (run_len as u8) << 4;
            out.push(control);
            for _ in 0..run_len {
                out.push(value);
            }
            run_len = 0;
        }
    }
}

/// Write a raw (non-RLE) plane: just copy width * height bytes.
fn encode_plane_raw(plane: &[u8], width: usize, height: usize, out: &mut Vec<u8>) {
    let total = width * height;
    out.extend_from_slice(&plane[..total]);
}

/// RDP 6.0 Planar Bitmap compressor (MS-RDPEGDI §3.1.9).
///
/// Produces `RDP6_BITMAP_STREAM` bytes from BGRA pixel input.
#[derive(Debug, Clone)]
pub struct PlanarCompressor {
    config: PlanarEncoderConfig,
}

impl PlanarCompressor {
    /// Create a new Planar compressor with the given configuration.
    pub fn new(config: PlanarEncoderConfig) -> Self {
        Self { config }
    }

    /// Compress BGRA pixels into an RDP6_BITMAP_STREAM.
    ///
    /// # Arguments
    ///
    /// * `bgra` - Input pixels in BGRA order, `width * height * 4` bytes
    /// * `width` - Bitmap width in pixels
    /// * `height` - Bitmap height in pixels
    ///
    /// # Returns
    ///
    /// The compressed `RDP6_BITMAP_STREAM` bytes.
    pub fn compress(
        &self,
        bgra: &[u8],
        width: u16,
        height: u16,
    ) -> Result<Vec<u8>, PlanarError> {
        let w = width as usize;
        let h = height as usize;
        let pixel_count = w * h;

        if bgra.len() < pixel_count * 4 {
            return Err(PlanarError::OutputOverflow);
        }

        let mut out = Vec::new();

        // Build FormatHeader
        let mut format_header: u8 = 0;
        if self.config.use_rle {
            format_header |= FORMAT_HEADER_RLE;
        }
        if self.config.skip_alpha {
            format_header |= FORMAT_HEADER_NA;
        }
        // CLL=0 (ARGB mode), CS=0 (no chroma subsampling)
        out.push(format_header);

        if pixel_count == 0 {
            return Ok(out);
        }

        // Split BGRA into planes
        let mut alpha_plane = vec![0u8; pixel_count];
        let mut red_plane = vec![0u8; pixel_count];
        let mut green_plane = vec![0u8; pixel_count];
        let mut blue_plane = vec![0u8; pixel_count];

        for i in 0..pixel_count {
            let base = i * 4;
            blue_plane[i] = bgra[base];
            green_plane[i] = bgra[base + 1];
            red_plane[i] = bgra[base + 2];
            alpha_plane[i] = bgra[base + 3];
        }

        // Encode planes
        if self.config.use_rle {
            if !self.config.skip_alpha {
                encode_plane_rle(&alpha_plane, w, h, &mut out);
            }
            encode_plane_rle(&red_plane, w, h, &mut out);
            encode_plane_rle(&green_plane, w, h, &mut out);
            encode_plane_rle(&blue_plane, w, h, &mut out);
        } else {
            if !self.config.skip_alpha {
                encode_plane_raw(&alpha_plane, w, h, &mut out);
            }
            encode_plane_raw(&red_plane, w, h, &mut out);
            encode_plane_raw(&green_plane, w, h, &mut out);
            encode_plane_raw(&blue_plane, w, h, &mut out);
            // Pad byte (mandatory per spec §2.2.2.5.1)
            out.push(0x00);
        }

        Ok(out)
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn decompress(src: &[u8], width: u16, height: u16) -> Result<Vec<u8>, PlanarError> {
        let decoder = PlanarDecompressor::new();
        let mut dst = Vec::new();
        decoder.decompress(src, width, height, &mut dst)?;
        Ok(dst)
    }

    // ── Raw ARGB mode (CLL=0, RLE=0) ──

    #[test]
    fn raw_argb_1x1_no_alpha() {
        // FormatHeader: NA=1, RLE=0, CLL=0 → 0x20
        // Planes: R=0xAB, G=0xCD, B=0xEF, Pad=0x00
        let src = [0x20, 0xAB, 0xCD, 0xEF, 0x00];
        let result = decompress(&src, 1, 1).unwrap();
        // BGRA output
        assert_eq!(result, vec![0xEF, 0xCD, 0xAB, 0xFF]);
    }

    #[test]
    fn raw_argb_1x1_with_alpha() {
        // FormatHeader: NA=0, RLE=0, CLL=0 → 0x00
        // Planes: A=0x80, R=0xFF, G=0x00, B=0x7F, Pad=0x00
        let src = [0x00, 0x80, 0xFF, 0x00, 0x7F, 0x00];
        let result = decompress(&src, 1, 1).unwrap();
        assert_eq!(result, vec![0x7F, 0x00, 0xFF, 0x80]);
    }

    #[test]
    fn raw_argb_2x2_no_alpha() {
        // FormatHeader: NA=1, RLE=0, CLL=0 → 0x20
        // 2x2 = 4 pixels
        // R plane: [0x10, 0x20, 0x30, 0x40]
        // G plane: [0x50, 0x60, 0x70, 0x80]
        // B plane: [0x90, 0xA0, 0xB0, 0xC0]
        // Pad: [0x00]
        let mut src = vec![0x20];
        src.extend_from_slice(&[0x10, 0x20, 0x30, 0x40]); // R
        src.extend_from_slice(&[0x50, 0x60, 0x70, 0x80]); // G
        src.extend_from_slice(&[0x90, 0xA0, 0xB0, 0xC0]); // B
        src.push(0x00); // Pad

        let result = decompress(&src, 2, 2).unwrap();
        // BGRA for each pixel
        assert_eq!(result, vec![
            0x90, 0x50, 0x10, 0xFF, // pixel 0
            0xA0, 0x60, 0x20, 0xFF, // pixel 1
            0xB0, 0x70, 0x30, 0xFF, // pixel 2
            0xC0, 0x80, 0x40, 0xFF, // pixel 3
        ]);
    }

    // ── RLE ARGB mode (CLL=0, RLE=1) ──

    #[test]
    fn rle_argb_1x1_no_alpha() {
        // FormatHeader: NA=1, RLE=1, CLL=0 → 0x30
        // Each plane: 1 pixel → controlByte with 1 raw byte, 0 run
        // controlByte = (1 << 4) | 0 = 0x10, rawByte = value
        let src = [
            0x30,       // header
            0x10, 0xAB, // R plane: 1 raw byte
            0x10, 0xCD, // G plane: 1 raw byte
            0x10, 0xEF, // B plane: 1 raw byte
        ];
        let result = decompress(&src, 1, 1).unwrap();
        assert_eq!(result, vec![0xEF, 0xCD, 0xAB, 0xFF]);
    }

    #[test]
    fn rle_argb_1x1_with_alpha() {
        // FormatHeader: NA=0, RLE=1, CLL=0 → 0x10
        let src = [
            0x10,       // header
            0x10, 0x80, // A plane
            0x10, 0xFF, // R plane
            0x10, 0x00, // G plane
            0x10, 0x7F, // B plane
        ];
        let result = decompress(&src, 1, 1).unwrap();
        assert_eq!(result, vec![0x7F, 0x00, 0xFF, 0x80]);
    }

    // ── RLE with run (color fill) ──

    #[test]
    fn rle_color_fill_4x1() {
        // 4x1, NA=1, RLE=1, CLL=0 → 0x30
        // Each plane: 1 raw byte + 3 run
        // controlByte = (1 << 4) | 3 = 0x13, rawByte = value
        let src = [
            0x30,       // header
            0x13, 0xAA, // R: 1 raw + 3 run = 4 pixels of 0xAA
            0x13, 0xBB, // G: 4 pixels of 0xBB
            0x13, 0xCC, // B: 4 pixels of 0xCC
        ];
        let result = decompress(&src, 4, 1).unwrap();
        for i in 0..4 {
            assert_eq!(result[i * 4], 0xCC);     // B
            assert_eq!(result[i * 4 + 1], 0xBB); // G
            assert_eq!(result[i * 4 + 2], 0xAA); // R
            assert_eq!(result[i * 4 + 3], 0xFF); // A
        }
    }

    // ── RLE long run (nRunLength=1) ──

    #[test]
    fn rle_long_run_mode1() {
        // 20x1, NA=1, RLE=1, CLL=0 → 0x30
        // controlByte for long run mode 1: nRunLength=1, cRawBytes=4 → actual_run=20
        // controlByte = (4 << 4) | 1 = 0x41
        // No raw bytes follow, run produces 20 copies of base value (0 for first row)
        let src = [
            0x30,
            0x41, // R: long run 20 zeros
            0x41, // G: long run 20 zeros
            0x41, // B: long run 20 zeros
        ];
        let result = decompress(&src, 20, 1).unwrap();
        // All pixels should be B=0, G=0, R=0, A=0xFF
        for i in 0..20 {
            assert_eq!(result[i * 4..i * 4 + 4], [0x00, 0x00, 0x00, 0xFF]);
        }
    }

    // ── RLE long run (nRunLength=2) ──

    #[test]
    fn rle_long_run_mode2() {
        // 35x1, NA=1, RLE=1, CLL=0 → 0x30
        // controlByte: nRunLength=2, cRawBytes=3 → actual_run = 32+3 = 35
        // controlByte = (3 << 4) | 2 = 0x32
        let src = [
            0x30,
            0x32, // R: long run 35 zeros
            0x32, // G: long run 35 zeros
            0x32, // B: long run 35 zeros
        ];
        let result = decompress(&src, 35, 1).unwrap();
        for i in 0..35 {
            assert_eq!(result[i * 4..i * 4 + 4], [0x00, 0x00, 0x00, 0xFF]);
        }
    }

    // ── RLE pure raw segment (nRunLength=0) ──

    #[test]
    fn rle_pure_raw_segment() {
        // 3x1, NA=1, RLE=1, CLL=0 → 0x30
        // controlByte = (3 << 4) | 0 = 0x30 → 3 raw bytes, 0 run
        let src = [
            0x30,
            0x30, 0x11, 0x22, 0x33, // R: 3 raw
            0x30, 0x44, 0x55, 0x66, // G: 3 raw
            0x30, 0x77, 0x88, 0x99, // B: 3 raw
        ];
        let result = decompress(&src, 3, 1).unwrap();
        assert_eq!(result, vec![
            0x77, 0x44, 0x11, 0xFF,
            0x88, 0x55, 0x22, 0xFF,
            0x99, 0x66, 0x33, 0xFF,
        ]);
    }

    // ── Delta encoding (2 rows) ──

    #[test]
    fn rle_delta_encoding_2x2() {
        // 2x2, NA=1, RLE=1, CLL=0 → 0x30
        // R plane:
        //   Row 0: 2 raw bytes [0x10, 0x20] → absolute values 16, 32
        //   Row 1: 2 raw bytes, delta +5 each
        //     delta +5 → encoded as 5*2 = 10 = 0x0A
        //     decoded: 16+5=21, 32+5=37
        // G/B planes: all zeros (2 raw per row)
        // NOTE: nRunLength=1,2 are long-run modes; use 2 raw + 0 run for width-2 planes
        let src = [
            0x30,
            // R: row0 = 2 raw, row1 = 2 raw delta
            0x20, 0x10, 0x20,       // row 0: cRawBytes=2, nRunLength=0
            0x20, 0x0A, 0x0A,       // row 1: delta +5, +5
            // G: 2 raw per row
            0x20, 0x00, 0x00,       // row 0
            0x20, 0x00, 0x00,       // row 1 (delta 0)
            // B: same
            0x20, 0x00, 0x00,
            0x20, 0x00, 0x00,
        ];
        let result = decompress(&src, 2, 2).unwrap();
        assert_eq!(result[0..4], [0x00, 0x00, 0x10, 0xFF]); // (0,0)
        assert_eq!(result[4..8], [0x00, 0x00, 0x20, 0xFF]); // (1,0)
        assert_eq!(result[8..12], [0x00, 0x00, 0x15, 0xFF]); // (0,1) R=21=0x15
        assert_eq!(result[12..16], [0x00, 0x00, 0x25, 0xFF]); // (1,1) R=37=0x25
    }

    // ── Negative delta ──

    #[test]
    fn rle_negative_delta() {
        // 1x2, NA=1, RLE=1, CLL=0 → 0x30
        // R plane: row0 = 0x14 (20), row1 = delta -5 → encoded as (5 << 1) | 1 = 0x0B
        // decoded row1: 20 + (-5) = 15 = 0x0F
        let src = [
            0x30,
            0x10, 0x14,   // R row0: absolute 20
            0x10, 0x0B,   // R row1: delta -5
            0x10, 0x00,   // G row0
            0x10, 0x00,   // G row1
            0x10, 0x00,   // B row0
            0x10, 0x00,   // B row1
        ];
        let result = decompress(&src, 1, 2).unwrap();
        assert_eq!(result[2], 0x14); // row0 R=20
        assert_eq!(result[6], 0x0F); // row1 R=15
    }

    // ── Delta clamping ──

    #[test]
    fn rle_delta_clamp_to_zero() {
        // 1x2: R row0 = 3, row1 delta = -5 → 3+(-5) = -2 → clamped to 0
        let src = [
            0x30,
            0x10, 0x03,   // R row0: 3
            0x10, 0x0B,   // R row1: delta -5
            0x10, 0x00, 0x10, 0x00, // G
            0x10, 0x00, 0x10, 0x00, // B
        ];
        let result = decompress(&src, 1, 2).unwrap();
        assert_eq!(result[6], 0x00); // clamped to 0
    }

    #[test]
    fn rle_delta_clamp_to_255() {
        // 1x2: R row0 = 250, row1 delta = +10 → 260 → clamped to 255
        // delta +10 encoded as 10*2 = 20 = 0x14
        let src = [
            0x30,
            0x10, 0xFA,   // R row0: 250
            0x10, 0x14,   // R row1: delta +10
            0x10, 0x00, 0x10, 0x00,
            0x10, 0x00, 0x10, 0x00,
        ];
        let result = decompress(&src, 1, 2).unwrap();
        assert_eq!(result[6], 0xFF); // clamped to 255
    }

    // ── Run with zero raw bytes on second row (delta=0 → copy above) ──

    #[test]
    fn rle_run_zero_raw_second_row() {
        // 4x2, NA=1, RLE=1, CLL=0 → 0x30
        // R: row0 = [0x10, 0x20, 0x30, 0x40] (4 raw bytes)
        //    row1 = run of 4 with delta=0 → copies from above
        // Use long run mode 1 for row1: nRunLength=1, cRawBytes=4-16=-12... no.
        // Use nRunLength=4, cRawBytes=0: controlByte = (0 << 4) | 4 = 0x04
        let src = [
            0x30,
            // R
            0x40, 0x10, 0x20, 0x30, 0x40, // row0: 4 raw + 0 run
            0x04,                           // row1: 0 raw + 4 run (delta=0)
            // G
            0x40, 0x00, 0x00, 0x00, 0x00,
            0x04,
            // B
            0x40, 0x00, 0x00, 0x00, 0x00,
            0x04,
        ];
        let result = decompress(&src, 4, 2).unwrap();
        // Row 1 should be copy of row 0
        assert_eq!(result[16], 0x00); // (0,1) B
        assert_eq!(result[18], 0x10); // (0,1) R
        assert_eq!(result[22], 0x20); // (1,1) R
        assert_eq!(result[26], 0x30); // (2,1) R
        assert_eq!(result[30], 0x40); // (3,1) R
    }

    // ── Multiple segments per scanline ──

    #[test]
    fn rle_multiple_segments_per_scanline() {
        // 5x1: R plane → 2 raw + 0 run, then 3 raw + 0 run
        // controlByte1 = (2 << 4) | 0 = 0x20
        // controlByte2 = (3 << 4) | 0 = 0x30
        let src = [
            0x30,
            // R: 2 segments for 5 pixels
            0x20, 0x11, 0x22,             // 2 raw
            0x30, 0x33, 0x44, 0x55,       // 3 raw
            // G: 1 raw + 4 run
            0x14, 0xAA,
            // B: 1 raw + 4 run
            0x14, 0xBB,
        ];
        let result = decompress(&src, 5, 1).unwrap();
        assert_eq!(result[2], 0x11);  // pixel 0 R
        assert_eq!(result[6], 0x22);  // pixel 1 R
        assert_eq!(result[10], 0x33); // pixel 2 R
        assert_eq!(result[14], 0x44); // pixel 3 R
        assert_eq!(result[18], 0x55); // pixel 4 R
    }

    // ── Empty bitmap ──

    #[test]
    fn empty_bitmap() {
        let result = decompress(&[0x30], 0, 0).unwrap();
        assert!(result.is_empty());
    }

    // ── Error: truncated stream ──

    #[test]
    fn truncated_stream() {
        let result = decompress(&[], 1, 1);
        assert_eq!(result, Err(PlanarError::TruncatedStream));
    }

    #[test]
    fn truncated_plane_data() {
        // FormatHeader only, no plane data
        let result = decompress(&[0x30], 1, 1);
        assert_eq!(result, Err(PlanarError::TruncatedStream));
    }

    // ── Error: invalid control byte ──

    #[test]
    fn invalid_control_byte_zero() {
        let src = [
            0x30, // header: RLE=1, NA=1, CLL=0
            0x00, // invalid: zero control byte
        ];
        let result = decompress(&src, 1, 1);
        assert_eq!(result, Err(PlanarError::InvalidControlByte));
    }

    // ── Error: invalid format header (CS=1 with CLL=0) ──

    #[test]
    fn invalid_format_header_cs_without_cll() {
        // CS=1 (bit 3) with CLL=0 → invalid
        let src = [0x08];
        let result = decompress(&src, 1, 1);
        assert_eq!(result, Err(PlanarError::InvalidFormatHeader(0x08)));
    }

    // ── RLE with run extending a raw value on first row ──

    #[test]
    fn rle_raw_then_run_first_row() {
        // 5x1: 2 raw bytes [0xAA, 0xBB] + 3 run → [0xAA, 0xBB, 0xBB, 0xBB, 0xBB]
        // controlByte = (2 << 4) | 3 = 0x23
        let src = [
            0x30,
            0x23, 0xAA, 0xBB, // R: 2 raw + 3 run of 0xBB
            0x23, 0x00, 0x00, // G
            0x23, 0x00, 0x00, // B
        ];
        let result = decompress(&src, 5, 1).unwrap();
        assert_eq!(result[2], 0xAA);  // pixel 0 R
        assert_eq!(result[6], 0xBB);  // pixel 1 R
        assert_eq!(result[10], 0xBB); // pixel 2 R (run)
        assert_eq!(result[14], 0xBB); // pixel 3 R (run)
        assert_eq!(result[18], 0xBB); // pixel 4 R (run)
    }

    // ── Delta with run extending last delta ──

    #[test]
    fn rle_delta_run_extends_last_delta() {
        // 3x2: R plane
        // Row 0: [10, 20, 30] — 3 raw
        // Row 1: 3 raw with delta +5 each
        //   decoded: 10+5=15, 20+5=25, 30+5=35
        // delta +5 encoded as 0x0A
        // NOTE: nRunLength=2 is long-run mode; use 3 raw instead
        let src = [
            0x30,
            // R
            0x30, 0x0A, 0x14, 0x1E, // row0: 3 raw [10, 20, 30]
            0x30, 0x0A, 0x0A, 0x0A, // row1: 3 raw (delta +5 each)
            // G
            0x30, 0x00, 0x00, 0x00, // row0
            0x03,                    // row1: 0 raw + 3 run (delta=0)
            // B
            0x30, 0x00, 0x00, 0x00,
            0x03,
        ];
        let result = decompress(&src, 3, 2).unwrap();
        // Row 1 starts at pixel 3 → byte offset 12
        assert_eq!(result[12 + 2], 0x0F); // (0,1) R = 10+5 = 15
        assert_eq!(result[16 + 2], 0x19); // (1,1) R = 20+5 = 25
        assert_eq!(result[20 + 2], 0x23); // (2,1) R = 30+5 = 35
    }

    // ── AYCoCg mode (CLL > 0) ──

    #[test]
    fn aycocg_basic_1x1() {
        // FormatHeader: NA=1, RLE=1, CLL=1 → 0x30 | 0x01 = 0x31
        // Y=128, Co=0 (as signed byte → 0x00), Cg=0
        // After CLL shift: Co=0<<1=0, Cg=0<<1=0
        // R = 128 + 0 - 0 = 128, G = 128 + 0 = 128, B = 128 - 0 - 0 = 128
        let src = [
            0x31,
            0x10, 0x80, // Y=128
            0x10, 0x00, // Co=0
            0x10, 0x00, // Cg=0
        ];
        let result = decompress(&src, 1, 1).unwrap();
        // BGRA: B=128, G=128, R=128, A=0xFF
        assert_eq!(result, vec![0x80, 0x80, 0x80, 0xFF]);
    }

    // ── Chroma subsampling (CS=1) ──

    #[test]
    fn chroma_subsampling_2x2() {
        // 2x2, FormatHeader: NA=1, RLE=1, CLL=1, CS=1 → 0x30 | 0x08 | 0x01 = 0x39
        // Y plane: 2x2 full size (decoded row-by-row, each row width=2)
        // Co plane: ceil(2/2)×ceil(2/2) = 1x1
        // Cg plane: 1x1
        // All Y=128, Co=0, Cg=0 → all gray
        // NOTE: nRunLength=1 is long-run; use 2 raw per row for Y plane
        let src = [
            0x39,
            // Y: row0 = 2 raw, row1 = 2 raw (delta 0)
            0x20, 0x80, 0x80, // row 0
            0x20, 0x00, 0x00, // row 1 (delta 0 → same as above)
            // Co: 1x1 = 1 pixel
            0x10, 0x00,
            // Cg: 1x1 = 1 pixel
            0x10, 0x00,
        ];
        let result = decompress(&src, 2, 2).unwrap();
        for i in 0..4 {
            assert_eq!(result[i * 4], 0x80);     // B
            assert_eq!(result[i * 4 + 1], 0x80); // G
            assert_eq!(result[i * 4 + 2], 0x80); // R
            assert_eq!(result[i * 4 + 3], 0xFF); // A
        }
    }

    // ── decode_delta helper ──

    #[test]
    fn delta_encoding_values() {
        assert_eq!(decode_delta(0x00), 0);   // +0
        assert_eq!(decode_delta(0x02), 1);   // +1
        assert_eq!(decode_delta(0x04), 2);   // +2
        assert_eq!(decode_delta(0x0A), 5);   // +5
        assert_eq!(decode_delta(0x01), 0);   // -0
        assert_eq!(decode_delta(0x03), -1);  // -1
        assert_eq!(decode_delta(0x05), -2);  // -2
        assert_eq!(decode_delta(0x0B), -5);  // -5
        assert_eq!(decode_delta(0xFE), 127); // +127
        assert_eq!(decode_delta(0xFF), -127); // -127
    }

    // ── clamp_u8 ──

    #[test]
    fn clamp_values() {
        assert_eq!(clamp_u8(0), 0);
        assert_eq!(clamp_u8(255), 255);
        assert_eq!(clamp_u8(256), 255);
        assert_eq!(clamp_u8(-1), 0);
        assert_eq!(clamp_u8(128), 128);
    }

    // ── AYCoCg with non-zero Co/Cg ──

    #[test]
    fn aycocg_nonzero_co_cg_1x1() {
        // CLL=1: Co stored as i8=10 (0x0A), Cg stored as i8=20 (0x14)
        // Co_shifted = 10<<1 = 20, Cg_shifted = 20<<1 = 40
        // Y=100: R=clamp(100+20-40)=80, G=clamp(100+40)=140, B=clamp(100-20-40)=40
        let src = [
            0x31,
            0x10, 100,  // Y
            0x10, 0x0A, // Co=+10
            0x10, 0x14, // Cg=+20
        ];
        let result = decompress(&src, 1, 1).unwrap();
        assert_eq!(result, vec![40, 140, 80, 255]);
    }

    #[test]
    fn aycocg_negative_co_1x1() {
        // Co stored as i8=-10 → 0xF6. CLL=1 → Co_shifted=(-10)<<1=-20, Cg=0
        // Y=100: R=80, G=100, B=120
        let src = [
            0x31,
            0x10, 100,
            0x10, 0xF6, // Co=-10
            0x10, 0x00,
        ];
        let result = decompress(&src, 1, 1).unwrap();
        assert_eq!(result, vec![120, 100, 80, 255]);
    }

    // ── CLL shift > 1 ──

    #[test]
    fn aycocg_cll2_shift_1x1() {
        // CLL=2: Co=5→5<<2=20, Cg=3→3<<2=12
        // Y=128: R=clamp(128+20-12)=136, G=clamp(128+12)=140, B=clamp(128-20-12)=96
        let src = [
            0x32, // NA=1,RLE=1,CLL=2
            0x10, 128,
            0x10, 0x05,
            0x10, 0x03,
        ];
        let result = decompress(&src, 1, 1).unwrap();
        assert_eq!(result, vec![96, 140, 136, 255]);
    }

    // ── Long run on second row (delta=0 copies above) ──

    #[test]
    fn rle_long_run_mode1_second_row_copies_above() {
        // 16x2: R row0 = 1 raw (0xAB) + 15 run, row1 = long run mode1 (delta=0)
        // controlByte for 1 raw + 15 run: (1<<4)|15 = 0x1F
        // controlByte for long run 16: (0<<4)|1 = 0x01 → actual_run=16+0=16
        let src: &[u8] = &[
            0x30,
            0x1F, 0xAB, // R row0
            0x01,        // R row1: long run 16, delta=0 → copies 0xAB
            0x1F, 0x00, 0x01, // G
            0x1F, 0x00, 0x01, // B
        ];
        let result = decompress(src, 16, 2).unwrap();
        for i in 0..32 {
            assert_eq!(result[i * 4 + 2], 0xAB, "pixel {i} R mismatch");
        }
    }

    // ── OutputOverflow from over-wide run ──

    #[test]
    fn output_overflow_from_run() {
        // 2x1: R plane controlByte = (0<<4)|5 = 0x05 → 5 run on width-2 scanline
        let src = [0x30, 0x05];
        let result = decompress(&src, 2, 1);
        assert_eq!(result, Err(PlanarError::OutputOverflow));
    }

    // ── Multi-pixel RLE with alpha ──

    #[test]
    fn rle_argb_2x1_with_alpha() {
        // 2x1, NA=0, RLE=1, CLL=0 → 0x10
        let src = [
            0x10,
            0x20, 0x80, 0x40, // A: [0x80, 0x40]
            0x20, 0xFF, 0x00, // R: [0xFF, 0x00]
            0x20, 0x00, 0xCC, // G: [0x00, 0xCC]
            0x20, 0x7F, 0x11, // B: [0x7F, 0x11]
        ];
        let result = decompress(&src, 2, 1).unwrap();
        assert_eq!(result[0..4], [0x7F, 0x00, 0xFF, 0x80]);
        assert_eq!(result[4..8], [0x11, 0xCC, 0x00, 0x40]);
    }

    // ── AYCoCg clamping ──

    #[test]
    fn aycocg_clamp_negative_result() {
        // Y=10, Co=+70 (0x46), Cg=0, CLL=1
        // Co_shifted=140. B=clamp(10-140-0)=clamp(-130)=0
        let src = [
            0x31,
            0x10, 10,
            0x10, 0x46, // Co=+70
            0x10, 0x00,
        ];
        let result = decompress(&src, 1, 1).unwrap();
        assert_eq!(result, vec![0, 10, 150, 255]);
    }

    #[test]
    fn aycocg_clamp_overflow_result() {
        // Y=200, Co=+50 (0x32), Cg=+10 (0x0A), CLL=1
        // Co_shifted=100, Cg_shifted=20. R=clamp(200+100-20)=clamp(280)=255
        let src = [
            0x31,
            0x10, 200,
            0x10, 0x32,
            0x10, 0x0A,
        ];
        let result = decompress(&src, 1, 1).unwrap();
        assert_eq!(result, vec![80, 220, 255, 255]);
    }

    // ── Chroma subsampling with odd dimension ──

    #[test]
    fn chroma_subsampling_3x1_odd_width() {
        // 3x1, CLL=1, CS=1 → 0x39. chroma_w=2, chroma_h=1
        // Y=[100,100,100], Co=[10,20], Cg=[0,0]
        // super_sample: pixel0→Co=10<<1=20, pixel1→Co=20, pixel2→Co=20<<1=40
        // pixel0: R=120, G=100, B=80
        // pixel1: R=120, G=100, B=80
        // pixel2: R=140, G=100, B=60
        let src = [
            0x39,
            0x30, 100, 100, 100, // Y
            0x20, 10, 20,         // Co
            0x20, 0, 0,           // Cg
        ];
        let result = decompress(&src, 3, 1).unwrap();
        assert_eq!(result[0..4], [80, 100, 120, 255]);
        assert_eq!(result[4..8], [80, 100, 120, 255]);
        assert_eq!(result[8..12], [60, 100, 140, 255]);
    }

    // ── Raw mode pad byte mandatory ──

    #[test]
    fn raw_argb_missing_pad_byte() {
        // Raw mode stream without trailing pad byte → TruncatedStream
        let src = [0x20, 0xAB, 0xCD, 0xEF]; // header + R + G + B, no pad
        let result = decompress(&src, 1, 1);
        assert_eq!(result, Err(PlanarError::TruncatedStream));
    }

    // ═══════════════════════════════════════════════════════════════
    // Encoder tests
    // ═══════════════════════════════════════════════════════════════

    fn compress_rle(bgra: &[u8], w: u16, h: u16) -> Vec<u8> {
        let enc = PlanarCompressor::new(PlanarEncoderConfig {
            use_rle: true,
            skip_alpha: true,
        });
        enc.compress(bgra, w, h).unwrap()
    }

    fn compress_raw(bgra: &[u8], w: u16, h: u16) -> Vec<u8> {
        let enc = PlanarCompressor::new(PlanarEncoderConfig {
            use_rle: false,
            skip_alpha: true,
        });
        enc.compress(bgra, w, h).unwrap()
    }

    // ── encode_delta helper ──

    #[test]
    fn encode_delta_values() {
        assert_eq!(encode_delta(0), 0x00);
        assert_eq!(encode_delta(1), 0x02);
        assert_eq!(encode_delta(5), 0x0A);
        assert_eq!(encode_delta(-1), 0x03);
        assert_eq!(encode_delta(-5), 0x0B);
        assert_eq!(encode_delta(127), 0xFE);
        assert_eq!(encode_delta(-127), 0xFF);
    }

    // ── encode/decode delta roundtrip ──

    #[test]
    fn delta_encode_decode_roundtrip() {
        for delta in -127..=127i16 {
            let encoded = encode_delta(delta);
            let decoded = decode_delta(encoded);
            assert_eq!(decoded, delta, "delta {delta} roundtrip failed");
        }
    }

    // ── Compressor → Decompressor roundtrip (RLE, 1x1) ──

    #[test]
    fn roundtrip_rle_1x1() {
        let bgra = [0xEF, 0xCD, 0xAB, 0xFF]; // B=0xEF, G=0xCD, R=0xAB, A=0xFF
        let compressed = compress_rle(&bgra, 1, 1);
        let result = decompress(&compressed, 1, 1).unwrap();
        assert_eq!(result, bgra);
    }

    // ── Roundtrip (RLE, 4x1 solid color) ──

    #[test]
    fn roundtrip_rle_4x1_solid() {
        let pixel = [0x11, 0x22, 0x33, 0xFF];
        let bgra: Vec<u8> = pixel.iter().copied().cycle().take(16).collect();
        let compressed = compress_rle(&bgra, 4, 1);
        let result = decompress(&compressed, 4, 1).unwrap();
        assert_eq!(result, bgra);
    }

    // ── Roundtrip (RLE, 4x2 gradient) ──

    #[test]
    fn roundtrip_rle_4x2_gradient() {
        let bgra: Vec<u8> = (0..8u8)
            .flat_map(|i| [i * 30, i * 20, i * 10, 0xFF])
            .collect();
        let compressed = compress_rle(&bgra, 4, 2);
        let result = decompress(&compressed, 4, 2).unwrap();
        assert_eq!(result, bgra);
    }

    // ── Roundtrip (Raw mode, 2x2) ──

    #[test]
    fn roundtrip_raw_2x2() {
        let bgra = [
            0x10, 0x20, 0x30, 0xFF,
            0x40, 0x50, 0x60, 0xFF,
            0x70, 0x80, 0x90, 0xFF,
            0xA0, 0xB0, 0xC0, 0xFF,
        ];
        let compressed = compress_raw(&bgra, 2, 2);
        let result = decompress(&compressed, 2, 2).unwrap();
        assert_eq!(result, bgra);
    }

    // ── Roundtrip (RLE with alpha) ──

    #[test]
    fn roundtrip_rle_with_alpha() {
        let enc = PlanarCompressor::new(PlanarEncoderConfig {
            use_rle: true,
            skip_alpha: false,
        });
        let bgra = [
            0x10, 0x20, 0x30, 0x80,
            0x40, 0x50, 0x60, 0xC0,
        ];
        let compressed = enc.compress(&bgra, 2, 1).unwrap();
        let result = decompress(&compressed, 2, 1).unwrap();
        assert_eq!(result, bgra);
    }

    // ── Roundtrip large (16x16 varied) ──

    #[test]
    fn roundtrip_rle_16x16() {
        let mut bgra = vec![0u8; 16 * 16 * 4];
        for y in 0..16u8 {
            for x in 0..16u8 {
                let base = (y as usize * 16 + x as usize) * 4;
                bgra[base] = x.wrapping_mul(17);     // B
                bgra[base + 1] = y.wrapping_mul(13);  // G
                bgra[base + 2] = (x ^ y).wrapping_mul(7); // R
                bgra[base + 3] = 0xFF;                // A
            }
        }
        let compressed = compress_rle(&bgra, 16, 16);
        let result = decompress(&compressed, 16, 16).unwrap();
        assert_eq!(result, bgra);
    }

    // ── Roundtrip with long runs (all same color) ──

    #[test]
    fn roundtrip_rle_64x1_uniform() {
        let pixel = [0xAA, 0xBB, 0xCC, 0xFF];
        let bgra: Vec<u8> = pixel.iter().copied().cycle().take(64 * 4).collect();
        let compressed = compress_rle(&bgra, 64, 1);
        let result = decompress(&compressed, 64, 1).unwrap();
        assert_eq!(result, bgra);
    }

    // ── Empty bitmap ──

    #[test]
    fn encoder_empty_bitmap() {
        let compressed = compress_rle(&[], 0, 0);
        // Should have just the format header
        assert_eq!(compressed.len(), 1);
    }

    // ── Format header correctness ──

    #[test]
    fn encoder_format_header_rle_na() {
        let compressed = compress_rle(&[0, 0, 0, 0xFF], 1, 1);
        // RLE=1, NA=1 → 0x30
        assert_eq!(compressed[0], 0x30);
    }

    #[test]
    fn encoder_format_header_raw_na() {
        let compressed = compress_raw(&[0, 0, 0, 0xFF], 1, 1);
        // RLE=0, NA=1 → 0x20
        assert_eq!(compressed[0], 0x20);
    }

    #[test]
    fn encoder_format_header_rle_with_alpha() {
        let enc = PlanarCompressor::new(PlanarEncoderConfig {
            use_rle: true,
            skip_alpha: false,
        });
        let compressed = enc.compress(&[0, 0, 0, 0x80], 1, 1).unwrap();
        // RLE=1, NA=0 → 0x10
        assert_eq!(compressed[0], 0x10);
    }

    // ── Run of exactly 3 ──

    #[test]
    fn roundtrip_rle_run_of_exactly_3() {
        // Scanline with 2 distinct + 3 identical + 1 distinct in G channel
        let bgra: Vec<u8> = vec![
            0x00, 0x10, 0x00, 0xFF,
            0x00, 0x20, 0x00, 0xFF,
            0x00, 0xAA, 0x00, 0xFF,
            0x00, 0xAA, 0x00, 0xFF,
            0x00, 0xAA, 0x00, 0xFF,
            0x00, 0x30, 0x00, 0xFF,
        ];
        let compressed = compress_rle(&bgra, 6, 1);
        let result = decompress(&compressed, 6, 1).unwrap();
        assert_eq!(result, bgra);
    }

    // ── Compression ratio ──

    #[test]
    fn compression_ratio_uniform_color() {
        let pixel = [0x55u8, 0x55, 0x55, 0xFF];
        let bgra: Vec<u8> = pixel.iter().copied().cycle().take(64 * 4).collect();
        let compressed = compress_rle(&bgra, 64, 1);
        // Compressed planes must be smaller than raw (3 planes × 64 = 192 bytes)
        assert!(compressed.len() - 1 < 192, "no compression: {} bytes", compressed.len());
    }

    // ── Extended run modes (value=0) boundary values ──

    fn make_black_bgra(n: usize) -> Vec<u8> {
        // Black pixels with alpha=0xFF (encoder skips alpha, decoder fills 0xFF)
        let mut bgra = Vec::with_capacity(n * 4);
        for _ in 0..n {
            bgra.extend_from_slice(&[0x00, 0x00, 0x00, 0xFF]);
        }
        bgra
    }

    #[test]
    fn roundtrip_rle_zero_run_exactly_16() {
        let bgra = make_black_bgra(16);
        let compressed = compress_rle(&bgra, 16, 1);
        let result = decompress(&compressed, 16, 1).unwrap();
        assert_eq!(result, bgra);
    }

    #[test]
    fn roundtrip_rle_zero_run_exactly_32() {
        let bgra = make_black_bgra(32);
        let compressed = compress_rle(&bgra, 32, 1);
        let result = decompress(&compressed, 32, 1).unwrap();
        assert_eq!(result, bgra);
    }

    #[test]
    fn roundtrip_rle_zero_run_exactly_47() {
        let bgra = make_black_bgra(47);
        let compressed = compress_rle(&bgra, 47, 1);
        let result = decompress(&compressed, 47, 1).unwrap();
        assert_eq!(result, bgra);
    }

    #[test]
    fn roundtrip_rle_zero_run_48() {
        let bgra = make_black_bgra(48);
        let compressed = compress_rle(&bgra, 48, 1);
        let result = decompress(&compressed, 48, 1).unwrap();
        assert_eq!(result, bgra);
    }

    // ── Run boundary: 16 and 17 non-zero values ──

    #[test]
    fn roundtrip_rle_run_of_16_nonzero() {
        let pixel = [0xDD, 0x00, 0x00, 0xFF];
        let bgra: Vec<u8> = pixel.iter().copied().cycle().take(16 * 4).collect();
        let compressed = compress_rle(&bgra, 16, 1);
        let result = decompress(&compressed, 16, 1).unwrap();
        assert_eq!(result, bgra);
    }

    #[test]
    fn roundtrip_rle_run_of_17_nonzero() {
        let pixel = [0xDD, 0x00, 0x00, 0xFF];
        let bgra: Vec<u8> = pixel.iter().copied().cycle().take(17 * 4).collect();
        let compressed = compress_rle(&bgra, 17, 1);
        let result = decompress(&compressed, 17, 1).unwrap();
        assert_eq!(result, bgra);
    }

    // ── Mixed raw + run pattern ──

    #[test]
    fn roundtrip_rle_mixed_raw_and_run() {
        // [0x10, 0x20, 0xAA, 0xAA, 0xAA, 0xAA] in B channel
        let bgra: Vec<u8> = vec![
            0x10, 0x00, 0x00, 0xFF,
            0x20, 0x00, 0x00, 0xFF,
            0xAA, 0x00, 0x00, 0xFF,
            0xAA, 0x00, 0x00, 0xFF,
            0xAA, 0x00, 0x00, 0xFF,
            0xAA, 0x00, 0x00, 0xFF,
        ];
        let compressed = compress_rle(&bgra, 6, 1);
        let result = decompress(&compressed, 6, 1).unwrap();
        assert_eq!(result, bgra);
    }

    // ── Input buffer too small ──

    #[test]
    fn compress_input_too_small() {
        let enc = PlanarCompressor::new(PlanarEncoderConfig::default());
        let result = enc.compress(&[0u8; 4], 2, 1);
        assert_eq!(result, Err(PlanarError::OutputOverflow));
    }

    // ── Raw mode with alpha ──

    #[test]
    fn roundtrip_raw_with_alpha() {
        let enc = PlanarCompressor::new(PlanarEncoderConfig {
            use_rle: false,
            skip_alpha: false,
        });
        let bgra = [0x10, 0x20, 0x30, 0x80, 0x40, 0x50, 0x60, 0xC0];
        let compressed = enc.compress(&bgra, 2, 1).unwrap();
        let result = decompress(&compressed, 2, 1).unwrap();
        assert_eq!(result, bgra);
    }
}
