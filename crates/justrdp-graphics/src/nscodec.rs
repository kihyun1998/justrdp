#![forbid(unsafe_code)]

//! NSCodec bitmap decoder (MS-RDPNSC).
//!
//! Decodes NSCodec-compressed bitmaps using AYCoCg color space with
//! per-channel RLE compression and optional chroma subsampling.

use alloc::borrow::Cow;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

// ── Constants ──

/// Fixed header size (MS-RDPNSC §2.2.1):
/// LumaPlaneByteCount(4) + OrangeChromaPlaneByteCount(4) +
/// GreenChromaPlaneByteCount(4) + AlphaPlaneByteCount(4) +
/// ColorLossLevel(1) + ChromaSubsamplingLevel(1) + Reserved(2) = 20 bytes.
const STREAM_HEADER_SIZE: usize = 20;

/// EndData size at the end of each RLE-compressed plane (MS-RDPNSC §2.2.2.1).
const ENDDATA_SIZE: usize = 4;

// ── Error type ──

/// NSCodec decompression error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsCodecError {
    /// Stream ended unexpectedly.
    TruncatedStream,
    /// A plane's byte count exceeds the expected raw size.
    PlaneByteCountTooLarge,
    /// ColorLossLevel is not in [1, 7].
    InvalidColorLossLevel(u8),
    /// ChromaSubsamplingLevel is not 0 or 1.
    InvalidChromaSubsamplingLevel(u8),
    /// RLE decode produced wrong output size.
    RleOutputMismatch,
}

impl fmt::Display for NsCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedStream => write!(f, "NSCodec: truncated stream"),
            Self::PlaneByteCountTooLarge => write!(f, "NSCodec: plane byte count too large"),
            Self::InvalidColorLossLevel(v) => write!(f, "NSCodec: invalid color loss level {v}"),
            Self::InvalidChromaSubsamplingLevel(v) => write!(f, "NSCodec: invalid chroma subsampling level {v}"),
            Self::RleOutputMismatch => write!(f, "NSCodec: RLE output size mismatch"),
        }
    }
}

// ── Header parsing ──

struct NsCodecHeader {
    luma_byte_count: u32,
    orange_chroma_byte_count: u32,
    green_chroma_byte_count: u32,
    alpha_byte_count: u32,
    color_loss_level: u8,
    chroma_subsampling: bool,
}

fn parse_header(src: &[u8]) -> Result<NsCodecHeader, NsCodecError> {
    if src.len() < STREAM_HEADER_SIZE {
        return Err(NsCodecError::TruncatedStream);
    }

    let luma_byte_count = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
    let orange_chroma_byte_count = u32::from_le_bytes([src[4], src[5], src[6], src[7]]);
    let green_chroma_byte_count = u32::from_le_bytes([src[8], src[9], src[10], src[11]]);
    let alpha_byte_count = u32::from_le_bytes([src[12], src[13], src[14], src[15]]);
    let color_loss_level = src[16];
    let chroma_subsampling_level = src[17];
    // src[18..20] = reserved, ignored

    if color_loss_level < 1 || color_loss_level > 7 {
        return Err(NsCodecError::InvalidColorLossLevel(color_loss_level));
    }
    if chroma_subsampling_level > 1 {
        return Err(NsCodecError::InvalidChromaSubsamplingLevel(chroma_subsampling_level));
    }

    Ok(NsCodecHeader {
        luma_byte_count,
        orange_chroma_byte_count,
        green_chroma_byte_count,
        alpha_byte_count,
        color_loss_level,
        chroma_subsampling: chroma_subsampling_level == 1,
    })
}

// ── Dimension helpers ──

/// Round up to nearest multiple of 8.
#[inline]
fn round_up_8(n: usize) -> usize {
    (n + 7) & !7
}

/// Round up to nearest multiple of 2.
#[inline]
fn round_up_2(n: usize) -> usize {
    (n + 1) & !1
}

/// Compute expected raw plane sizes.
///
/// Returns `(luma_w, luma_h, chroma_w, chroma_h, expected_luma, expected_chroma)`.
/// Uses checked arithmetic to prevent overflow on 32-bit targets.
fn plane_dimensions(
    width: usize,
    height: usize,
    subsampling: bool,
) -> Result<(usize, usize, usize, usize, usize, usize), NsCodecError> {
    if subsampling {
        let luma_w = round_up_8(width);
        let chroma_w = luma_w / 2;
        let chroma_h = round_up_2(height) / 2;
        let expected_luma = luma_w.checked_mul(height).ok_or(NsCodecError::TruncatedStream)?;
        let expected_chroma = chroma_w.checked_mul(chroma_h).ok_or(NsCodecError::TruncatedStream)?;
        Ok((luma_w, height, chroma_w, chroma_h, expected_luma, expected_chroma))
    } else {
        let expected = width.checked_mul(height).ok_or(NsCodecError::TruncatedStream)?;
        Ok((width, height, width, height, expected, expected))
    }
}

// ── NSCodec RLE decoder (MS-RDPNSC §2.2.2.1) ──

/// Decode an NSCodec RLE-compressed plane.
///
/// The last 4 bytes of `src` are `EndData` (raw bytes appended to output).
/// Segments before that are either literal (1 byte) or run (3 or 7 bytes).
fn decode_plane_rle(src: &[u8], expected_size: usize) -> Result<Vec<u8>, NsCodecError> {
    if src.len() < ENDDATA_SIZE {
        return Err(NsCodecError::TruncatedStream);
    }

    let segments_end = src.len() - ENDDATA_SIZE;
    let end_data = &src[segments_end..];

    let mut output = Vec::with_capacity(expected_size);
    let mut pos = 0;

    while pos < segments_end {
        // Check if this is a run segment: byte[0] == byte[1].
        // When only 1 byte remains before EndData, it is always a literal.
        if pos + 1 < segments_end && src[pos] == src[pos + 1] {
            // Run segment: need at least 3 bytes (value, value, factor1)
            if pos + 3 > src.len() {
                return Err(NsCodecError::TruncatedStream);
            }
            let run_value = src[pos];
            let factor1 = src[pos + 2];

            let run_length;
            if factor1 == 0xFF {
                // Long run: need 7 bytes total (value, value, 0xFF, u32_le)
                if pos + 7 > src.len() {
                    return Err(NsCodecError::TruncatedStream);
                }
                run_length = u32::from_le_bytes([
                    src[pos + 3],
                    src[pos + 4],
                    src[pos + 5],
                    src[pos + 6],
                ]) as usize;
                pos += 7;
            } else {
                // Short run
                run_length = factor1 as usize + 2;
                pos += 3;
            }

            // Guard: reject runs that would exceed the expected plane size
            if output.len() + run_length > expected_size {
                return Err(NsCodecError::RleOutputMismatch);
            }
            let new_len = output.len() + run_length;
            output.resize(new_len, run_value);
        } else {
            // Literal segment: single byte
            output.push(src[pos]);
            pos += 1;
        }
    }

    // Append EndData
    output.extend_from_slice(end_data);

    if output.len() != expected_size {
        return Err(NsCodecError::RleOutputMismatch);
    }

    Ok(output)
}

// ── Chroma super-sampling ──

/// Upsample a subsampled plane from (sub_w × sub_h) to (full_w × full_h)
/// using nearest-neighbor 2× expansion.
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

// ── Color conversion ──

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

// ── Main decoder ──

/// NSCodec bitmap decompressor (MS-RDPNSC).
///
/// Stateless: each call to [`decompress`](Self::decompress) is independent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsCodecDecompressor;

impl NsCodecDecompressor {
    /// Create a new NSCodec decompressor.
    pub const fn new() -> Self {
        Self
    }

    /// Decompress an NSCodec-encoded bitmap stream.
    ///
    /// # Arguments
    ///
    /// * `src` - Raw NSCODEC_BITMAP_STREAM bytes
    /// * `width` - Bitmap width in pixels
    /// * `height` - Bitmap height in pixels
    /// * `dst` - Output buffer, resized to `width * height * 4` (BGRA)
    pub fn decompress(
        &self,
        src: &[u8],
        width: u16,
        height: u16,
        dst: &mut Vec<u8>,
    ) -> Result<(), NsCodecError> {
        let w = width as usize;
        let h = height as usize;
        let pixel_count = w.checked_mul(h).ok_or(NsCodecError::TruncatedStream)?;
        let total_output = pixel_count.checked_mul(4).ok_or(NsCodecError::TruncatedStream)?;

        if pixel_count == 0 {
            dst.clear();
            return Ok(());
        }

        dst.clear();
        dst.resize(total_output, 0);

        // Step 1: Parse header
        let header = parse_header(src)?;
        let data = &src[STREAM_HEADER_SIZE..];

        // Compute expected sizes
        let (luma_w, _luma_h, chroma_w, chroma_h, expected_luma, expected_chroma) =
            plane_dimensions(w, h, header.chroma_subsampling)?;
        let expected_alpha = pixel_count;

        // Validate byte counts
        if header.luma_byte_count as usize > expected_luma {
            return Err(NsCodecError::PlaneByteCountTooLarge);
        }
        if header.orange_chroma_byte_count as usize > expected_chroma {
            return Err(NsCodecError::PlaneByteCountTooLarge);
        }
        if header.green_chroma_byte_count as usize > expected_chroma {
            return Err(NsCodecError::PlaneByteCountTooLarge);
        }
        if header.alpha_byte_count != 0 && header.alpha_byte_count as usize > expected_alpha {
            return Err(NsCodecError::PlaneByteCountTooLarge);
        }

        // Step 2: Decode each plane — use checked_add to prevent overflow on 32-bit targets
        let luma_end = header.luma_byte_count as usize;
        let co_end = luma_end.checked_add(header.orange_chroma_byte_count as usize)
            .ok_or(NsCodecError::TruncatedStream)?;
        let cg_end = co_end.checked_add(header.green_chroma_byte_count as usize)
            .ok_or(NsCodecError::TruncatedStream)?;
        let alpha_end = cg_end.checked_add(header.alpha_byte_count as usize)
            .ok_or(NsCodecError::TruncatedStream)?;

        if alpha_end > data.len() {
            return Err(NsCodecError::TruncatedStream);
        }

        let luma_data = &data[..luma_end];
        let co_data = &data[luma_end..co_end];
        let cg_data = &data[co_end..cg_end];
        let alpha_data = if header.alpha_byte_count > 0 {
            Some(&data[cg_end..alpha_end])
        } else {
            None
        };

        // Decode planes (raw or RLE). Cow::Borrowed for raw, Cow::Owned for RLE.
        let y_plane = decode_plane(luma_data, expected_luma)?;
        let co_plane_raw = decode_plane(co_data, expected_chroma)?;
        let cg_plane_raw = decode_plane(cg_data, expected_chroma)?;
        let alpha_plane: Cow<'_, [u8]> = if let Some(ad) = alpha_data {
            decode_plane(ad, expected_alpha)?
        } else {
            Cow::Owned(vec![0xFF; expected_alpha])
        };

        // Step 3: Chroma super-sampling (if active)
        // super_sample returns Vec, so we use Cow::Owned for the upsampled path.
        let (co_full, cg_full): (Cow<'_, [u8]>, Cow<'_, [u8]>) = if header.chroma_subsampling {
            let co = super_sample(&co_plane_raw, chroma_w, chroma_h, luma_w, h);
            let cg = super_sample(&cg_plane_raw, chroma_w, chroma_h, luma_w, h);
            (Cow::Owned(co), Cow::Owned(cg))
        } else {
            (co_plane_raw, cg_plane_raw)
        };

        // Step 4: Color loss recovery + AYCoCg → BGRA
        let cll = header.color_loss_level;

        for row in 0..h {
            for col in 0..w {
                let pixel_idx = row * w + col;
                // Luma plane may be wider than image width when subsampling is active
                let plane_idx = if header.chroma_subsampling {
                    row * luma_w + col
                } else {
                    pixel_idx
                };

                let y = y_plane[plane_idx] as i16;
                // co_full/cg_full are luma_w-wide when subsampling, w-wide otherwise.
                // Color loss recovery: treat as signed i8 then left-shift
                let co = (co_full[plane_idx] as i8 as i16) << cll;
                let cg = (cg_full[plane_idx] as i8 as i16) << cll;
                let a = alpha_plane[pixel_idx];

                // AYCoCg → RGB (MS-RDPNSC §3.1.8.2.1)
                let r = clamp_u8(y + (co >> 1) - (cg >> 1));
                let g = clamp_u8(y + (cg >> 1));
                let b = clamp_u8(y - (co >> 1) - (cg >> 1));

                let base = pixel_idx * 4;
                dst[base] = b;
                dst[base + 1] = g;
                dst[base + 2] = r;
                dst[base + 3] = a;
            }
        }

        Ok(())
    }
}

/// Decode a single plane: raw if byte_count == expected_size, else RLE.
///
/// Returns `Cow::Borrowed` for raw planes (avoiding a copy) and
/// `Cow::Owned` for RLE-decompressed planes.
fn decode_plane<'a>(data: &'a [u8], expected_size: usize) -> Result<Cow<'a, [u8]>, NsCodecError> {
    if data.len() == expected_size {
        // Raw plane — borrow directly, no allocation
        Ok(Cow::Borrowed(data))
    } else {
        // RLE compressed
        Ok(Cow::Owned(decode_plane_rle(data, expected_size)?))
    }
}

impl Default for NsCodecDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn run_decompress(src: &[u8], w: u16, h: u16) -> Result<Vec<u8>, NsCodecError> {
        let decoder = NsCodecDecompressor::new();
        let mut dst = Vec::new();
        decoder.decompress(src, w, h, &mut dst)?;
        Ok(dst)
    }

    // ── RLE decoder unit tests ──

    #[test]
    fn rle_all_same_value() {
        // 10 bytes of 0xAA: run segment [0xAA, 0xAA, 0x04] → run=6, then EndData [0xAA; 4]
        let src = [0xAA, 0xAA, 0x04, 0xAA, 0xAA, 0xAA, 0xAA];
        let result = decode_plane_rle(&src, 10).unwrap();
        assert_eq!(result, vec![0xAA; 10]);
    }

    #[test]
    fn rle_mixed_literal_and_run() {
        // Output: [0x11, 0x22, 0x22, 0x22, ...EndData]
        // Literal: 0x11 (next byte 0x22 differs)
        // Run: [0x22, 0x22, 0x00] → run=2
        // EndData: [0x33, 0x44, 0x55, 0x66]
        let src = [0x11, 0x22, 0x22, 0x00, 0x33, 0x44, 0x55, 0x66];
        let result = decode_plane_rle(&src, 7).unwrap();
        assert_eq!(result, vec![0x11, 0x22, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn rle_long_run() {
        // Long run: [0xBB, 0xBB, 0xFF, 0x00, 0x02, 0x00, 0x00] → run=512
        // EndData: [0xBB, 0xBB, 0xBB, 0xBB]
        let mut src = vec![0xBB, 0xBB, 0xFF, 0x00, 0x02, 0x00, 0x00];
        src.extend_from_slice(&[0xBB, 0xBB, 0xBB, 0xBB]);
        let result = decode_plane_rle(&src, 516).unwrap();
        assert_eq!(result.len(), 516);
        assert!(result.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn rle_enddata_only() {
        // Plane with exactly 4 bytes → all EndData, no segments
        let src = [0x11, 0x22, 0x33, 0x44];
        let result = decode_plane_rle(&src, 4).unwrap();
        assert_eq!(result, vec![0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn rle_output_mismatch_error() {
        // 5 expected but only produce 4 (EndData only)
        let src = [0x11, 0x22, 0x33, 0x44];
        let result = decode_plane_rle(&src, 5);
        assert_eq!(result, Err(NsCodecError::RleOutputMismatch));
    }

    // ── Header parsing ──

    #[test]
    fn parse_valid_header() {
        let mut src = [0u8; 20];
        // LumaByteCount = 100
        src[0..4].copy_from_slice(&100u32.to_le_bytes());
        // OrangeChromaByteCount = 50
        src[4..8].copy_from_slice(&50u32.to_le_bytes());
        // GreenChromaByteCount = 50
        src[8..12].copy_from_slice(&50u32.to_le_bytes());
        // AlphaByteCount = 0
        src[12..16].copy_from_slice(&0u32.to_le_bytes());
        // ColorLossLevel = 3
        src[16] = 3;
        // ChromaSubsamplingLevel = 1
        src[17] = 1;

        let header = parse_header(&src).unwrap();
        assert_eq!(header.luma_byte_count, 100);
        assert_eq!(header.color_loss_level, 3);
        assert!(header.chroma_subsampling);
    }

    #[test]
    fn parse_invalid_color_loss_level() {
        let mut src = [0u8; 20];
        src[0..4].copy_from_slice(&1u32.to_le_bytes());
        src[4..8].copy_from_slice(&1u32.to_le_bytes());
        src[8..12].copy_from_slice(&1u32.to_le_bytes());
        src[16] = 0; // Invalid: must be 1..=7
        let result = parse_header(&src);
        assert_eq!(result.err(), Some(NsCodecError::InvalidColorLossLevel(0)));
    }

    #[test]
    fn parse_invalid_chroma_level() {
        let mut src = [0u8; 20];
        src[0..4].copy_from_slice(&1u32.to_le_bytes());
        src[4..8].copy_from_slice(&1u32.to_le_bytes());
        src[8..12].copy_from_slice(&1u32.to_le_bytes());
        src[16] = 1;
        src[17] = 2; // Invalid
        let result = parse_header(&src);
        assert_eq!(result.err(), Some(NsCodecError::InvalidChromaSubsamplingLevel(2)));
    }

    // ── Dimension helpers ──

    #[test]
    fn round_up_values() {
        assert_eq!(round_up_8(1), 8);
        assert_eq!(round_up_8(8), 8);
        assert_eq!(round_up_8(9), 16);
        assert_eq!(round_up_8(15), 16);
        assert_eq!(round_up_8(16), 16);
        assert_eq!(round_up_2(1), 2);
        assert_eq!(round_up_2(2), 2);
        assert_eq!(round_up_2(3), 4);
        assert_eq!(round_up_2(10), 10);
    }

    #[test]
    fn plane_dimensions_no_subsampling() {
        let (lw, lh, cw, ch, el, ec) = plane_dimensions(15, 10, false).unwrap();
        assert_eq!((lw, lh), (15, 10));
        assert_eq!((cw, ch), (15, 10));
        assert_eq!(el, 150);
        assert_eq!(ec, 150);
    }

    #[test]
    fn plane_dimensions_with_subsampling() {
        let (lw, lh, cw, ch, el, ec) = plane_dimensions(15, 10, true).unwrap();
        assert_eq!(lw, 16); // round_up_8(15)
        assert_eq!(lh, 10);
        assert_eq!(cw, 8);  // 16 / 2
        assert_eq!(ch, 5);  // round_up_2(10) / 2
        assert_eq!(el, 160);
        assert_eq!(ec, 40);
    }

    // ── Full decode: simple 1x1 no subsampling ──

    #[test]
    fn decode_1x1_raw_no_subsampling() {
        // 1x1, CLL=1, no subsampling
        // Y=128, Co=0, Cg=0 → R=128,G=128,B=128; A=0xFF (absent)
        let mut src = Vec::new();
        // Header
        src.extend_from_slice(&1u32.to_le_bytes()); // LumaByteCount = 1 (raw)
        src.extend_from_slice(&1u32.to_le_bytes()); // OrangeChroma = 1
        src.extend_from_slice(&1u32.to_le_bytes()); // GreenChroma = 1
        src.extend_from_slice(&0u32.to_le_bytes()); // Alpha = 0 (absent)
        src.push(1);  // CLL=1
        src.push(0);  // No subsampling
        src.extend_from_slice(&[0, 0]); // Reserved
        // Plane data
        src.push(128); // Y
        src.push(0);   // Co
        src.push(0);   // Cg

        let result = run_decompress(&src, 1, 1).unwrap();
        // Y=128, Co=0<<1=0, Cg=0<<1=0 → R=128, G=128, B=128
        assert_eq!(result[0], 128); // B
        assert_eq!(result[1], 128); // G
        assert_eq!(result[2], 128); // R
        assert_eq!(result[3], 0xFF); // A
    }

    // ── Empty bitmap ──

    #[test]
    fn decode_empty() {
        // 0x0 → empty output, just need the header
        let mut src = Vec::new();
        src.extend_from_slice(&0u32.to_le_bytes());
        src.extend_from_slice(&0u32.to_le_bytes());
        src.extend_from_slice(&0u32.to_le_bytes());
        src.extend_from_slice(&0u32.to_le_bytes());
        src.push(1);
        src.push(0);
        src.extend_from_slice(&[0, 0]);

        let result = run_decompress(&src, 0, 0).unwrap();
        assert!(result.is_empty());
    }

    // ── Truncated stream ──

    #[test]
    fn truncated_header() {
        let result = run_decompress(&[0; 10], 1, 1);
        assert_eq!(result, Err(NsCodecError::TruncatedStream));
    }

    // ── Spec test vector: Orange Chroma RLE decode ──

    #[test]
    fn rle_spec_vector_orange_chroma() {
        // MS-RDPNSC §4.1: Orange Chroma plane, 7 bytes → 40 bytes output
        // [0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22]
        // Run: [0x22, 0x22, 0x22] → factor1=0x22=34, run=36
        // EndData: [0x22, 0x22, 0x22, 0x22]
        let src = [0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22];
        let result = decode_plane_rle(&src, 40).unwrap();
        assert_eq!(result.len(), 40);
        assert!(result.iter().all(|&b| b == 0x22));
    }

    #[test]
    fn rle_spec_vector_green_chroma() {
        // MS-RDPNSC §4.1: Green Chroma, 11 bytes → 40 bytes
        // [0x37, 0x37, 0x19, 0x36, 0x37, 0x37, 0x06, 0x37, 0x37, 0x37, 0x37]
        // Run: [0x37, 0x37, 0x19] → factor1=0x19=25, run=27
        // Literal: [0x36]
        // Run: [0x37, 0x37, 0x06] → factor1=6, run=8
        // EndData: [0x37, 0x37, 0x37, 0x37]
        let src = [0x37, 0x37, 0x19, 0x36, 0x37, 0x37, 0x06, 0x37, 0x37, 0x37, 0x37];
        let result = decode_plane_rle(&src, 40).unwrap();
        assert_eq!(result.len(), 40);
        // 27 × 0x37, 1 × 0x36, 8 × 0x37, 4 × 0x37
        assert_eq!(result[0..27], vec![0x37; 27]);
        assert_eq!(result[27], 0x36);
        assert_eq!(result[28..36], vec![0x37; 8]);
        assert_eq!(result[36..40], vec![0x37; 4]);
    }

    #[test]
    fn rle_spec_vector_alpha() {
        // MS-RDPNSC §4.1: Alpha, 7 bytes → 150 bytes
        // [0xFF, 0xFF, 0x90, 0xFF, 0xFF, 0xFF, 0xFF]
        // Run: [0xFF, 0xFF, 0x90] → factor1=0x90=144, run=146
        // EndData: [0xFF, 0xFF, 0xFF, 0xFF]
        let src = [0xFF, 0xFF, 0x90, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = decode_plane_rle(&src, 150).unwrap();
        assert_eq!(result.len(), 150);
        assert!(result.iter().all(|&b| b == 0xFF));
    }

    // ── PlaneByteCountTooLarge ──

    #[test]
    fn plane_byte_count_too_large_error() {
        let mut src = Vec::new();
        src.extend_from_slice(&200u32.to_le_bytes()); // Luma = 200, expected = 1
        src.extend_from_slice(&1u32.to_le_bytes());
        src.extend_from_slice(&1u32.to_le_bytes());
        src.extend_from_slice(&0u32.to_le_bytes());
        src.push(1);
        src.push(0);
        src.extend_from_slice(&[0, 0]);

        let result = run_decompress(&src, 1, 1);
        assert_eq!(result, Err(NsCodecError::PlaneByteCountTooLarge));
    }

    // ── Decode with alpha present ──

    #[test]
    fn decode_1x1_with_alpha() {
        let mut src = Vec::new();
        src.extend_from_slice(&1u32.to_le_bytes()); // Luma
        src.extend_from_slice(&1u32.to_le_bytes()); // Co
        src.extend_from_slice(&1u32.to_le_bytes()); // Cg
        src.extend_from_slice(&1u32.to_le_bytes()); // Alpha = 1 (present)
        src.push(1); // CLL
        src.push(0); // No subsampling
        src.extend_from_slice(&[0, 0]);
        src.push(128); // Y
        src.push(0);   // Co
        src.push(0);   // Cg
        src.push(0x80); // Alpha = 128

        let result = run_decompress(&src, 1, 1).unwrap();
        assert_eq!(result[3], 0x80); // A=128
    }

    // ── Gap tests ──

    #[test]
    fn decode_2x1_colored_pixel() {
        // 2×1, CLL=1, no subsampling
        // Pixel 0: Y=128, Co=0x10 (i8=16), Cg=0x20 (i8=32)
        //   co_recovered = 16 << 1 = 32, cg_recovered = 32 << 1 = 64
        //   R = clamp(128 + 16 - 32) = 112, G = clamp(128 + 32) = 160, B = clamp(128 - 16 - 32) = 80
        // Pixel 1: Y=200, Co=0, Cg=0 → gray 200
        let mut src = Vec::new();
        src.extend_from_slice(&2u32.to_le_bytes());
        src.extend_from_slice(&2u32.to_le_bytes());
        src.extend_from_slice(&2u32.to_le_bytes());
        src.extend_from_slice(&0u32.to_le_bytes());
        src.push(1); src.push(0); src.extend_from_slice(&[0, 0]);
        src.extend_from_slice(&[128, 200]);      // Y
        src.extend_from_slice(&[0x10, 0x00]);    // Co
        src.extend_from_slice(&[0x20, 0x00]);    // Cg

        let result = run_decompress(&src, 2, 1).unwrap();
        assert_eq!(result[0], 80);   // pixel0 B
        assert_eq!(result[1], 160);  // pixel0 G
        assert_eq!(result[2], 112);  // pixel0 R
        assert_eq!(result[3], 0xFF);
        assert_eq!(result[4], 200);  // pixel1 B
        assert_eq!(result[5], 200);  // pixel1 G
        assert_eq!(result[6], 200);  // pixel1 R
    }

    #[test]
    fn decode_with_chroma_subsampling() {
        // 2×2, CLL=1, CSS=1
        // luma_w=8, chroma_w=4, chroma_h=1
        // All gray: Y=100, Co=0, Cg=0
        let luma_count = 8 * 2; // 16
        let chroma_count = 4 * 1; // 4
        let mut src = Vec::new();
        src.extend_from_slice(&(luma_count as u32).to_le_bytes());
        src.extend_from_slice(&(chroma_count as u32).to_le_bytes());
        src.extend_from_slice(&(chroma_count as u32).to_le_bytes());
        src.extend_from_slice(&0u32.to_le_bytes());
        src.push(1); src.push(1); src.extend_from_slice(&[0, 0]);
        src.extend(core::iter::repeat(100u8).take(luma_count));
        src.extend(core::iter::repeat(0u8).take(chroma_count));
        src.extend(core::iter::repeat(0u8).take(chroma_count));

        let result = run_decompress(&src, 2, 2).unwrap();
        for px in 0..4 {
            assert_eq!(result[px * 4], 100, "pixel {px} B");
            assert_eq!(result[px * 4 + 1], 100, "pixel {px} G");
            assert_eq!(result[px * 4 + 2], 100, "pixel {px} R");
        }
    }

    #[test]
    fn decode_rle_luma_full_pipeline() {
        // 10×1, CLL=1, no subsampling. expected_luma=10.
        // Luma RLE: Run [0xAA, 0xAA, 0x04] → run=6; EndData [0xAA; 4] → total output=10
        // RLE stream = 7 bytes < expected 10 → triggers RLE decode path
        let luma_rle: &[u8] = &[0xAA, 0xAA, 0x04, 0xAA, 0xAA, 0xAA, 0xAA];
        let mut src = Vec::new();
        src.extend_from_slice(&(luma_rle.len() as u32).to_le_bytes()); // 7 < 10
        src.extend_from_slice(&10u32.to_le_bytes()); // Co raw
        src.extend_from_slice(&10u32.to_le_bytes()); // Cg raw
        src.extend_from_slice(&0u32.to_le_bytes());
        src.push(1); src.push(0); src.extend_from_slice(&[0, 0]);
        src.extend_from_slice(luma_rle);
        src.extend(core::iter::repeat(0u8).take(10)); // Co
        src.extend(core::iter::repeat(0u8).take(10)); // Cg

        let result = run_decompress(&src, 10, 1).unwrap();
        for px in 0..10 {
            assert_eq!(result[px * 4 + 2], 0xAA, "pixel {px} R");
        }
    }

    #[test]
    fn decode_cll7_saturation() {
        // 1×1, CLL=7. Co=1 (i8) → 1<<7=128, Cg=1 → 128
        // Y=200: R=200+64-64=200, G=200+64=264→255, B=200-64-64=72
        let mut src = Vec::new();
        src.extend_from_slice(&1u32.to_le_bytes());
        src.extend_from_slice(&1u32.to_le_bytes());
        src.extend_from_slice(&1u32.to_le_bytes());
        src.extend_from_slice(&0u32.to_le_bytes());
        src.push(7); src.push(0); src.extend_from_slice(&[0, 0]);
        src.push(200); src.push(0x01); src.push(0x01);

        let result = run_decompress(&src, 1, 1).unwrap();
        assert_eq!(result[0], 72);   // B
        assert_eq!(result[1], 255);  // G (saturated)
        assert_eq!(result[2], 200);  // R
    }

    #[test]
    fn decode_width_3_with_subsampling_padding() {
        // 3×2, CSS=1, CLL=1. luma_w=8, chroma_w=4, chroma_h=1
        let luma_count = 8 * 2;
        let chroma_count = 4 * 1;
        let mut luma = vec![0u8; luma_count];
        luma[0] = 10; luma[1] = 20; luma[2] = 30; // row 0
        luma[8] = 40; luma[9] = 50; luma[10] = 60; // row 1

        let mut src = Vec::new();
        src.extend_from_slice(&(luma_count as u32).to_le_bytes());
        src.extend_from_slice(&(chroma_count as u32).to_le_bytes());
        src.extend_from_slice(&(chroma_count as u32).to_le_bytes());
        src.extend_from_slice(&0u32.to_le_bytes());
        src.push(1); src.push(1); src.extend_from_slice(&[0, 0]);
        src.extend_from_slice(&luma);
        src.extend(core::iter::repeat(0u8).take(chroma_count));
        src.extend(core::iter::repeat(0u8).take(chroma_count));

        let result = run_decompress(&src, 3, 2).unwrap();
        let expected_y = [10u8, 20, 30, 40, 50, 60];
        for (px, &y) in expected_y.iter().enumerate() {
            assert_eq!(result[px * 4 + 2], y, "pixel {px} R");
        }
    }
}
