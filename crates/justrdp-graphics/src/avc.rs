#![forbid(unsafe_code)]

//! H.264/AVC decoder abstraction and YUV-to-BGRA color conversion.
//!
//! This module provides:
//!
//! - **`AvcDecoder`** trait — abstraction over H.264 Annex B decoders (pure Rust,
//!   OpenH264, FFmpeg, or hardware-accelerated backends).
//! - **`Yuv420Frame`** — decoded YUV 4:2:0 frame with separate plane buffers.
//! - **YUV→BGRA conversion** — full-range BT.709 reverse transform
//!   (MS-RDPEGFX 3.3.8.3.1, ITU-BT.709-5 §4).
//! - **AVC444 / AVC444v2 YUV 4:4:4 plane combination** — reconstructing full
//!   Y/U/V 4:4:4 planes from two AVC420-decoded sub-frames
//!   (MS-RDPEGFX 3.3.8.3.2, 3.3.8.3.3).

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

// ── Constants ──

/// Minimum coded dimension (width or height) for AVC frames.
/// H.264 requires at least one 16×16 macroblock.
const MIN_AVC_DIMENSION: u32 = 16;

/// Maximum coded dimension (width or height) for AVC frames.
/// H.264 Level 5.2 supports up to 8192; we use this as a defensive limit
/// to prevent excessive memory allocation from attacker-controlled dimensions.
const MAX_AVC_DIMENSION: u32 = 8192;

/// Chroma neutral offset: U and V are unsigned [0,255] with 128 = neutral.
/// ITU-BT.709-5 §4, MS-RDPEGFX 3.3.8.3.1.
const YUV_CHROMA_NEUTRAL: i32 = 128;

/// Rounding addend for 12-bit fixed-point right-shift (2^11 = 0.5 ulp).
const FP12_ROUND: i32 = 1 << 11;

// ── Error ──

/// Errors produced by AVC decoding or YUV conversion.
#[derive(Debug)]
pub enum AvcError {
    /// The H.264 bitstream could not be decoded.
    DecodeFailed(String),
    /// Output buffer dimensions do not match or plane sizes are inconsistent.
    DimensionMismatch,
    /// Frame dimensions are too large (or too small) to process safely.
    DimensionOutOfRange,
    /// A required luma cache entry is missing (AVC444 LC=2 with no prior luma).
    MissingLumaCache,
}

impl fmt::Display for AvcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecodeFailed(msg) => write!(f, "AVC decode failed: {msg}"),
            Self::DimensionMismatch => write!(f, "AVC dimension mismatch"),
            Self::DimensionOutOfRange => write!(f, "AVC frame dimensions out of range"),
            Self::MissingLumaCache => write!(f, "AVC444 chroma-only frame with no cached luma"),
        }
    }
}

// ── Decoded frame ──

/// A decoded YUV 4:2:0 frame with three separate plane buffers.
///
/// - Y plane: `width × height` bytes
/// - U plane: `(width/2) × (height/2)` bytes
/// - V plane: `(width/2) × (height/2)` bytes
///
/// Width and height are the H.264 coded dimensions (multiples of 16).
/// Use the region rectangles from the metablock for the actual surface crop.
#[derive(Debug, Clone)]
pub struct Yuv420Frame {
    /// Luma plane (Y), `width * height` bytes.
    pub y: Vec<u8>,
    /// Chroma-blue plane (U / Cb), `(width/2) * (height/2)` bytes.
    pub u: Vec<u8>,
    /// Chroma-red plane (V / Cr), `(width/2) * (height/2)` bytes.
    pub v: Vec<u8>,
    /// Coded width in pixels (must be even, typically multiple of 16).
    pub width: u32,
    /// Coded height in pixels (must be even, typically multiple of 16).
    pub height: u32,
}

// ── Decoder trait ──

/// Trait for H.264 Annex B decoders.
///
/// Implementations decode a single H.264 access unit (one frame) from an
/// Annex B byte stream and return the YUV 4:2:0 planar output.
///
/// The decoder is stateful: it maintains reference frames across calls.
/// For AVC444/AVC444v2, both sub-streams (main and auxiliary views) must
/// be fed to the **same** decoder instance.
pub trait AvcDecoder: Send {
    /// Decode one H.264 access unit from `annex_b` byte stream.
    ///
    /// Returns the decoded YUV 4:2:0 frame.  An empty `annex_b` slice
    /// (e.g., an empty P-frame) may produce no output — return `Ok(None)`.
    fn decode_frame(&mut self, annex_b: &[u8]) -> Result<Option<Yuv420Frame>, AvcError>;
}

// ── BT.709 full-range YUV→BGRA conversion ──

// Fixed-point coefficients for BT.709 reverse transform (12-bit precision).
//
// From ITU-BT.709-5 §4 (Kr=0.2126, Kb=0.0722), MS-RDPEGFX 3.3.8.3.1:
//   R = Y + 1.5748 * V'
//   G = Y - 0.1873 * U' - 0.4681 * V'
//   B = Y + 1.8556 * U'
//
// where U' = U - 128, V' = V - 128 (full-range).
//
// Scaled by 4096 (2^12), rounded to nearest:
//   1.5748 × 4096 = 6450.94 → 6451
//   0.1873 × 4096 =  767.02 → 767
//   0.4681 × 4096 = 1917.34 → 1917
//   1.8556 × 4096 = 7600.54 → 7601
const BT709_CR_TO_R: i32 = 6451;
const BT709_CB_TO_G: i32 = 767;
const BT709_CR_TO_G: i32 = 1917;
const BT709_CB_TO_B: i32 = 7601;

#[inline]
fn clamp_u8(val: i32) -> u8 {
    val.clamp(0, 255) as u8
}

/// BT.709 full-range YCbCr → RGB (MS-RDPEGFX 3.3.8.3.1).
/// `u_off` = U - 128, `v_off` = V - 128.
#[inline]
fn bt709_to_rgb(y: i32, u_off: i32, v_off: i32) -> (u8, u8, u8) {
    let r = clamp_u8(y + ((BT709_CR_TO_R * v_off + FP12_ROUND) >> 12));
    // Single FP12_ROUND bias applied to the combined chroma sum.
    // This is a ~0.5-LSB approximation (not per-coefficient round-to-nearest),
    // acceptable given the downstream clamp_u8 to [0, 255].
    let g = clamp_u8(y - ((BT709_CB_TO_G * u_off + BT709_CR_TO_G * v_off + FP12_ROUND) >> 12));
    let b = clamp_u8(y + ((BT709_CB_TO_B * u_off + FP12_ROUND) >> 12));
    (r, g, b)
}

/// Checked computation of `a * b * 4`, returning `DimensionOutOfRange` on overflow.
fn checked_buf_size(a: usize, b: usize) -> Result<usize, AvcError> {
    a.checked_mul(b)
        .and_then(|n| n.checked_mul(4))
        .ok_or(AvcError::DimensionOutOfRange)
}

/// Checked computation of `a * b`, returning `DimensionOutOfRange` on overflow.
fn checked_area(a: usize, b: usize) -> Result<usize, AvcError> {
    a.checked_mul(b).ok_or(AvcError::DimensionOutOfRange)
}

/// Validate that a `Yuv420Frame` has even dimensions within bounds and
/// planes matching its declared dimensions.
fn validate_yuv420_planes(frame: &Yuv420Frame) -> Result<(usize, usize, usize), AvcError> {
    if frame.width < MIN_AVC_DIMENSION
        || frame.height < MIN_AVC_DIMENSION
        || frame.width > MAX_AVC_DIMENSION
        || frame.height > MAX_AVC_DIMENSION
    {
        return Err(AvcError::DimensionOutOfRange);
    }
    // H.264 coded frames always have even dimensions (macroblock-aligned).
    if frame.width % 2 != 0 || frame.height % 2 != 0 {
        return Err(AvcError::DimensionMismatch);
    }
    let w = frame.width as usize;
    let h = frame.height as usize;
    let half_w = w / 2;
    let half_h = h / 2;
    let full_size = checked_area(w, h)?;
    let uv_size = checked_area(half_w, half_h)?;
    if frame.y.len() < full_size || frame.u.len() < uv_size || frame.v.len() < uv_size {
        return Err(AvcError::DimensionMismatch);
    }
    Ok((w, h, full_size))
}

/// Validate inputs for AVC444/AVC444v2 plane combination.
/// Returns `(w, h, full_size, half_w, half_h)`.
fn validate_combine_inputs(
    main_view: &Yuv420Frame,
    aux_view: &Yuv420Frame,
) -> Result<(usize, usize, usize, usize, usize), AvcError> {
    let (w, h, full_size) = validate_yuv420_planes(main_view)?;
    validate_yuv420_planes(aux_view)?;

    if aux_view.width as usize != w || aux_view.height as usize != h {
        return Err(AvcError::DimensionMismatch);
    }

    Ok((w, h, full_size, w / 2, h / 2))
}

/// Convert a YUV 4:2:0 frame to BGRA pixels using the BT.709 full-range
/// reverse transform (MS-RDPEGFX 3.3.8.3.1).
///
/// # Arguments
///
/// * `frame` — Decoded YUV 4:2:0 frame from the H.264 decoder.
/// * `dst` — Output BGRA buffer. Must be at least `dst_width * dst_height * 4` bytes.
/// * `dst_width` — Stride width of the destination surface (pixels, not bytes).
/// * `dst_height` — Height of the destination surface.
///
/// # Errors
///
/// Returns `AvcError::DimensionMismatch` if the destination buffer is too small
/// or the frame planes do not match the expected sizes.
pub fn yuv420_to_bgra(
    frame: &Yuv420Frame,
    dst: &mut [u8],
    dst_width: u32,
    dst_height: u32,
) -> Result<(), AvcError> {
    let (frame_w, frame_h, _) = validate_yuv420_planes(frame)?;
    let dst_w = dst_width as usize;
    let dst_h = dst_height as usize;

    let needed = checked_buf_size(dst_w, dst_h)?;
    if dst.len() < needed {
        return Err(AvcError::DimensionMismatch);
    }

    // The coded frame may be larger than the destination (16-aligned).
    // Only convert the area that fits.
    let copy_w = frame_w.min(dst_w);
    let copy_h = frame_h.min(dst_h);
    let uv_stride = frame_w / 2;

    for row in 0..copy_h {
        let uv_row = row / 2;
        for col in 0..copy_w {
            let uv_col = col / 2;

            let y_val = frame.y[row * frame_w + col] as i32;
            let u_off = frame.u[uv_row * uv_stride + uv_col] as i32 - YUV_CHROMA_NEUTRAL;
            let v_off = frame.v[uv_row * uv_stride + uv_col] as i32 - YUV_CHROMA_NEUTRAL;

            let (r, g, b) = bt709_to_rgb(y_val, u_off, v_off);

            let base = (row * dst_w + col) * 4;
            dst[base] = b;
            dst[base + 1] = g;
            dst[base + 2] = r;
            dst[base + 3] = 0xFF;
        }
    }

    Ok(())
}

// ── AVC444 YUV 4:4:4 plane combination (MS-RDPEGFX 3.3.8.3.2) ──

/// Full YUV 4:4:4 planes at native resolution.
///
/// Each plane is `width × height` bytes. Positions not explicitly written
/// by the block mapping default to 128 (chroma-neutral).
#[derive(Debug, Clone)]
pub struct Yuv444Planes {
    /// Luma plane (Y), `width * height` bytes.
    pub y: Vec<u8>,
    /// Chroma-blue plane (U / Cb), `width * height` bytes.
    pub u: Vec<u8>,
    /// Chroma-red plane (V / Cr), `width * height` bytes.
    pub v: Vec<u8>,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

/// B1–B3 (MS-RDPEGFX 3.3.8.3.2 / 3.3.8.3.3): apply main-view planes.
/// Y444 = Y420; U444[2x][2y] = U420[x][y]; V444[2x][2y] = V420[x][y].
fn apply_main_view(
    y444: &mut [u8],
    u444: &mut [u8],
    v444: &mut [u8],
    main: &Yuv420Frame,
    w: usize,
    half_w: usize,
    half_h: usize,
    full_size: usize,
) {
    y444[..full_size].copy_from_slice(&main.y[..full_size]);

    for yy in 0..half_h {
        for xx in 0..half_w {
            let src_idx = yy * half_w + xx;
            let dst_idx = (yy * 2) * w + (xx * 2);
            u444[dst_idx] = main.u[src_idx];
            v444[dst_idx] = main.v[src_idx];
        }
    }
}

/// Combine two AVC420-decoded sub-frames into YUV 4:4:4 planes (AVC444 mode).
///
/// `main_view` = bitstream1 (luma): Y420 → Y444, U420 → even-x even-y U444,
/// V420 → even-x even-y V444.
///
/// `aux_view` = bitstream2 (chroma auxiliary):
/// - Y_aux even rows → odd-x columns of U444
/// - Y_aux odd rows → odd-x columns of V444
/// - U_aux → even-x odd-row U444
/// - V_aux → even-x odd-row V444
///
/// Positions not written by any block default to 128 (chroma-neutral).
///
/// See MS-RDPEGFX 3.3.8.3.2.
pub fn combine_avc444_planes(
    main_view: &Yuv420Frame,
    aux_view: &Yuv420Frame,
) -> Result<Yuv444Planes, AvcError> {
    let (w, h, full_size, half_w, half_h) = validate_combine_inputs(main_view, aux_view)?;

    let mut y444 = vec![0u8; full_size];
    let mut u444 = vec![128u8; full_size];
    let mut v444 = vec![128u8; full_size];

    // B1–B3: main view
    apply_main_view(&mut y444, &mut u444, &mut v444, main_view, w, half_w, half_h, full_size);

    // B4/B5 (MS-RDPEGFX 3.3.8.3.2):
    //   Y_aux[x][even_y] → U444[2x+1][even_y]  (odd-x columns of U)
    //   Y_aux[x][odd_y]  → V444[2x+1][odd_y]   (odd-x columns of V)
    // x ranges 0..W/2; aux_view.y has full-frame stride (W) but only the left
    // half_w columns of each row carry meaningful chroma data per spec.
    for yy in 0..h {
        for xx in 0..half_w {
            let src_idx = yy * w + xx;
            let dst_idx = yy * w + (xx * 2 + 1);
            if yy % 2 == 0 {
                u444[dst_idx] = aux_view.y[src_idx];
            } else {
                v444[dst_idx] = aux_view.y[src_idx];
            }
        }
    }

    // B6: U_aux[x][y] → U444[2x][2y+1]  (even-x, odd-row U)
    // B7: V_aux[x][y] → V444[2x][2y+1]  (even-x, odd-row V)
    for yy in 0..half_h {
        for xx in 0..half_w {
            let src_idx = yy * half_w + xx;
            let dst_idx = (yy * 2 + 1) * w + (xx * 2);
            u444[dst_idx] = aux_view.u[src_idx];
            v444[dst_idx] = aux_view.v[src_idx];
        }
    }

    Ok(Yuv444Planes {
        y: y444,
        u: u444,
        v: v444,
        width: main_view.width,
        height: main_view.height,
    })
}

// ── AVC444v2 YUV 4:4:4 plane combination (MS-RDPEGFX 3.3.8.3.3) ──

/// Combine two AVC420-decoded sub-frames into YUV 4:4:4 planes (AVC444v2 mode).
///
/// Same main view as AVC444. The auxiliary view uses a full-frame layout
/// instead of per-macroblock interleaving:
///
/// - B4: Y_aux upper half → U444 odd-x columns (top W/2 × H/2 block)
/// - B5: Y_aux lower half → V444 odd-x columns (bottom W/2 × H/2 block)
/// - B6: U_aux → U444 even-x odd-y rows
/// - B7: V_aux → V444 even-x odd-y rows
///
/// Positions not written by any block default to 128 (chroma-neutral).
///
/// See MS-RDPEGFX 3.3.8.3.3.
pub fn combine_avc444v2_planes(
    main_view: &Yuv420Frame,
    aux_view: &Yuv420Frame,
) -> Result<Yuv444Planes, AvcError> {
    let (w, _h, full_size, half_w, half_h) = validate_combine_inputs(main_view, aux_view)?;

    let mut y444 = vec![0u8; full_size];
    let mut u444 = vec![128u8; full_size];
    let mut v444 = vec![128u8; full_size];

    // B1–B3: main view (identical to AVC444)
    apply_main_view(&mut y444, &mut u444, &mut v444, main_view, w, half_w, half_h, full_size);

    // B4 (MS-RDPEGFX 3.3.8.3.3): Y_aux upper half (rows 0..half_h) → U444 odd-x columns.
    // aux_view.y uses full-frame stride (W); only left half_w columns are meaningful.
    for yy in 0..half_h {
        for xx in 0..half_w {
            let src_idx = yy * w + xx;
            let dst_idx = yy * w + (xx * 2 + 1);
            u444[dst_idx] = aux_view.y[src_idx];
        }
    }

    // B5: Y_aux lower half (rows half_h..h) → V444 odd-x columns
    for yy in 0..half_h {
        for xx in 0..half_w {
            let src_idx = (yy + half_h) * w + xx;
            let dst_idx = yy * w + (xx * 2 + 1);
            v444[dst_idx] = aux_view.y[src_idx];
        }
    }

    // B6: U_aux → U444 even-x odd-y rows
    // B7: V_aux → V444 even-x odd-y rows
    for yy in 0..half_h {
        for xx in 0..half_w {
            let src_idx = yy * half_w + xx;
            let dst_idx = (yy * 2 + 1) * w + (xx * 2);
            u444[dst_idx] = aux_view.u[src_idx];
            v444[dst_idx] = aux_view.v[src_idx];
        }
    }

    Ok(Yuv444Planes {
        y: y444,
        u: u444,
        v: v444,
        width: main_view.width,
        height: main_view.height,
    })
}

/// Convert YUV 4:4:4 planes to BGRA pixels using BT.709 full-range.
///
/// Each plane is `width × height` bytes at full resolution.
pub fn yuv444_to_bgra(
    planes: &Yuv444Planes,
    dst: &mut [u8],
    dst_width: u32,
    dst_height: u32,
) -> Result<(), AvcError> {
    if planes.width < MIN_AVC_DIMENSION
        || planes.height < MIN_AVC_DIMENSION
        || planes.width > MAX_AVC_DIMENSION
        || planes.height > MAX_AVC_DIMENSION
    {
        return Err(AvcError::DimensionOutOfRange);
    }
    if planes.width % 2 != 0 || planes.height % 2 != 0 {
        return Err(AvcError::DimensionMismatch);
    }
    let w = planes.width as usize;
    let h = planes.height as usize;
    let dst_w = dst_width as usize;
    let dst_h = dst_height as usize;

    let copy_w = w.min(dst_w);
    let copy_h = h.min(dst_h);

    let needed = checked_buf_size(dst_w, dst_h)?;
    if dst.len() < needed {
        return Err(AvcError::DimensionMismatch);
    }
    let full_size = checked_area(w, h)?;
    if planes.y.len() < full_size || planes.u.len() < full_size || planes.v.len() < full_size {
        return Err(AvcError::DimensionMismatch);
    }

    for row in 0..copy_h {
        for col in 0..copy_w {
            let idx = row * w + col;
            let y_val = planes.y[idx] as i32;
            let u_off = planes.u[idx] as i32 - YUV_CHROMA_NEUTRAL;
            let v_off = planes.v[idx] as i32 - YUV_CHROMA_NEUTRAL;

            let (r, g, b) = bt709_to_rgb(y_val, u_off, v_off);

            let base = (row * dst_w + col) * 4;
            dst[base] = b;
            dst[base + 1] = g;
            dst[base + 2] = r;
            dst[base + 3] = 0xFF;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bt709_white() {
        let frame = Yuv420Frame {
            y: vec![255; 16 * 16],
            u: vec![128; 8 * 8],
            v: vec![128; 8 * 8],
            width: 16,
            height: 16,
        };
        let mut dst = vec![0u8; 16 * 16 * 4];
        yuv420_to_bgra(&frame, &mut dst, 16, 16).unwrap();
        assert_eq!(dst[0], 255); // B
        assert_eq!(dst[1], 255); // G
        assert_eq!(dst[2], 255); // R
        assert_eq!(dst[3], 255); // A
    }

    #[test]
    fn bt709_black() {
        let frame = Yuv420Frame {
            y: vec![0; 16 * 16],
            u: vec![128; 8 * 8],
            v: vec![128; 8 * 8],
            width: 16,
            height: 16,
        };
        let mut dst = vec![0u8; 16 * 16 * 4];
        yuv420_to_bgra(&frame, &mut dst, 16, 16).unwrap();
        assert_eq!(dst[0], 0); // B
        assert_eq!(dst[1], 0); // G
        assert_eq!(dst[2], 0); // R
        assert_eq!(dst[3], 255); // A
    }

    #[test]
    fn bt709_mid_gray() {
        let frame = Yuv420Frame {
            y: vec![128; 16 * 16],
            u: vec![128; 8 * 8],
            v: vec![128; 8 * 8],
            width: 16,
            height: 16,
        };
        let mut dst = vec![0u8; 16 * 16 * 4];
        yuv420_to_bgra(&frame, &mut dst, 16, 16).unwrap();
        assert_eq!(dst[0], 128); // B
        assert_eq!(dst[1], 128); // G
        assert_eq!(dst[2], 128); // R
    }

    #[test]
    fn bt709_exact_values() {
        // Y=54, U=99 (U'=-29), V=255 (V'=127):
        //   R = 54 + (6451*127 + 2048) >> 12 = 54 + 821325>>12 = 54 + 200 = 254
        //   G = 54 - (767*(-29) + 1917*127 + 2048)>>12 = 54 - (223264>>12) = 54 - 54 = 0
        //   B = 54 + (7601*(-29) + 2048) >> 12 = 54 + (-218381>>12) = 54 + (-54) = 0
        let frame = Yuv420Frame {
            y: vec![54; 16 * 16],
            u: vec![99; 8 * 8],
            v: vec![255; 8 * 8],
            width: 16,
            height: 16,
        };
        let mut dst = vec![0u8; 16 * 16 * 4];
        yuv420_to_bgra(&frame, &mut dst, 16, 16).unwrap();
        assert_eq!(dst[2], 254); // R
        assert_eq!(dst[1], 0);   // G
        assert_eq!(dst[0], 0);   // B
    }

    #[test]
    fn yuv420_dimension_mismatch() {
        let frame = Yuv420Frame {
            y: vec![0; 16 * 16],
            u: vec![128; 8 * 8],
            v: vec![128; 8 * 8],
            width: 16,
            height: 16,
        };
        let mut dst = vec![0u8; 10]; // too small
        assert!(yuv420_to_bgra(&frame, &mut dst, 16, 16).is_err());
    }

    #[test]
    fn yuv420_rejects_odd_dimension() {
        let frame = Yuv420Frame {
            y: vec![0; 17 * 16],
            u: vec![128; 8 * 8],
            v: vec![128; 8 * 8],
            width: 17,
            height: 16,
        };
        let mut dst = vec![0u8; 17 * 16 * 4];
        assert!(yuv420_to_bgra(&frame, &mut dst, 17, 16).is_err());
    }

    #[test]
    fn yuv420_rejects_too_small() {
        let frame = Yuv420Frame {
            y: vec![0; 4],
            u: vec![128; 1],
            v: vec![128; 1],
            width: 2,
            height: 2,
        };
        let mut dst = vec![0u8; 2 * 2 * 4];
        assert!(yuv420_to_bgra(&frame, &mut dst, 2, 2).is_err());
    }

    #[test]
    fn yuv420_crop_to_smaller_surface() {
        let frame = Yuv420Frame {
            y: vec![200; 32 * 32],
            u: vec![128; 16 * 16],
            v: vec![128; 16 * 16],
            width: 32,
            height: 32,
        };
        let mut dst = vec![0u8; 20 * 20 * 4];
        yuv420_to_bgra(&frame, &mut dst, 20, 20).unwrap();
        assert_eq!(dst[0], 200);
        assert_eq!(dst[1], 200);
        assert_eq!(dst[2], 200);
    }

    #[test]
    fn combine_avc444_block_placement() {
        let w: u32 = 16;
        let h: u32 = 16;
        let half_w = (w / 2) as usize;

        let main = Yuv420Frame {
            y: vec![180; (w * h) as usize],
            u: vec![100; half_w * (h as usize / 2)],
            v: vec![150; half_w * (h as usize / 2)],
            width: w,
            height: h,
        };
        let aux = Yuv420Frame {
            y: vec![200; (w * h) as usize],
            u: vec![90; half_w * (h as usize / 2)],
            v: vec![110; half_w * (h as usize / 2)],
            width: w,
            height: h,
        };
        let planes = combine_avc444_planes(&main, &aux).unwrap();
        let ww = w as usize;

        // B1: Y444 = Y420
        assert_eq!(planes.y[0], 180);
        // B2: U444[0][0] (even-x, even-y) = main U
        assert_eq!(planes.u[0], 100);
        // B3: V444[0][0] (even-x, even-y) = main V
        assert_eq!(planes.v[0], 150);
        // B4: U444[1][0] (odd-x=1, even-y=0) = aux Y[0][0] = 200
        assert_eq!(planes.u[1], 200);
        // B5: V444[1][1] (odd-x=1, odd-y=1) = aux Y[0][1] = 200
        assert_eq!(planes.v[ww + 1], 200);
        // B6: U444[0][1] (even-x=0, odd-y=1) = aux U[0][0] = 90
        assert_eq!(planes.u[ww], 90);
        // B7: V444[0][1] (even-x=0, odd-y=1) = aux V[0][0] = 110
        assert_eq!(planes.v[ww], 110);
    }

    #[test]
    fn combine_avc444v2_block_placement() {
        let w: u32 = 16;
        let h: u32 = 16;
        let ww = w as usize;
        let hh = h as usize;
        let half_w = ww / 2;
        let half_h = hh / 2;

        let main = Yuv420Frame {
            y: vec![180; ww * hh],
            u: vec![100; half_w * half_h],
            v: vec![150; half_w * half_h],
            width: w,
            height: h,
        };
        let mut aux_y = vec![200u8; ww * hh];
        for yy in half_h..hh {
            for xx in 0..ww {
                aux_y[yy * ww + xx] = 50;
            }
        }
        let aux = Yuv420Frame {
            y: aux_y,
            u: vec![90; half_w * half_h],
            v: vec![110; half_w * half_h],
            width: w,
            height: h,
        };
        let planes = combine_avc444v2_planes(&main, &aux).unwrap();

        // B1: Y444 = Y420
        assert_eq!(planes.y[0], 180);
        // B2: U444[0][0] (even-x, even-y) = main U
        assert_eq!(planes.u[0], 100);
        // B3: V444[0][0] (even-x, even-y) = main V
        assert_eq!(planes.v[0], 150);
        // B4: U444[1][0] (odd-x=1, y=0) = aux Y upper-half[0][0] = 200
        assert_eq!(planes.u[1], 200);
        // B5: V444[1][0] (odd-x=1, y=0) = aux Y lower-half[0][0] = 50
        assert_eq!(planes.v[1], 50);
        // B6: U444[0][1] (even-x=0, odd-y=1) = aux U[0][0] = 90
        assert_eq!(planes.u[ww], 90);
        // B7: V444[0][1] (even-x=0, odd-y=1) = aux V[0][0] = 110
        assert_eq!(planes.v[ww], 110);
    }

    #[test]
    fn combine_avc444_dimension_mismatch() {
        let main = Yuv420Frame {
            y: vec![0; 16 * 16],
            u: vec![0; 8 * 8],
            v: vec![0; 8 * 8],
            width: 16,
            height: 16,
        };
        let aux = Yuv420Frame {
            y: vec![0; 32 * 32],
            u: vec![0; 16 * 16],
            v: vec![0; 16 * 16],
            width: 32,
            height: 32,
        };
        assert!(combine_avc444_planes(&main, &aux).is_err());
    }

    #[test]
    fn combine_avc444_rejects_oversized() {
        let main = Yuv420Frame {
            y: vec![],
            u: vec![],
            v: vec![],
            width: MAX_AVC_DIMENSION + 1,
            height: 16,
        };
        let aux = Yuv420Frame {
            y: vec![],
            u: vec![],
            v: vec![],
            width: MAX_AVC_DIMENSION + 1,
            height: 16,
        };
        assert!(combine_avc444_planes(&main, &aux).is_err());
    }

    #[test]
    fn combine_avc444_rejects_odd_dimension() {
        // Odd dimensions should be rejected even if planes are sized correctly
        let main = Yuv420Frame {
            y: vec![0; 17 * 16],
            u: vec![0; 8 * 8],
            v: vec![0; 8 * 8],
            width: 17,
            height: 16,
        };
        let aux = Yuv420Frame {
            y: vec![0; 17 * 16],
            u: vec![0; 8 * 8],
            v: vec![0; 8 * 8],
            width: 17,
            height: 16,
        };
        assert!(combine_avc444_planes(&main, &aux).is_err());
    }

    #[test]
    fn yuv444_to_bgra_white() {
        let planes = Yuv444Planes {
            y: vec![255; 16 * 16],
            u: vec![128; 16 * 16],
            v: vec![128; 16 * 16],
            width: 16,
            height: 16,
        };
        let mut dst = vec![0u8; 16 * 16 * 4];
        yuv444_to_bgra(&planes, &mut dst, 16, 16).unwrap();
        assert_eq!(dst[0], 255); // B
        assert_eq!(dst[1], 255); // G
        assert_eq!(dst[2], 255); // R
    }

    #[test]
    fn yuv444_to_bgra_dimension_mismatch() {
        let planes = Yuv444Planes {
            y: vec![128; 16 * 16],
            u: vec![128; 16 * 16],
            v: vec![128; 16 * 16],
            width: 16,
            height: 16,
        };
        let mut dst = vec![0u8; 10]; // too small
        assert!(yuv444_to_bgra(&planes, &mut dst, 16, 16).is_err());
    }

    #[test]
    fn yuv444_to_bgra_rejects_too_small() {
        let planes = Yuv444Planes {
            y: vec![128; 4],
            u: vec![128; 4],
            v: vec![128; 4],
            width: 2,
            height: 2,
        };
        let mut dst = vec![0u8; 2 * 2 * 4];
        assert!(yuv444_to_bgra(&planes, &mut dst, 2, 2).is_err());
    }

    #[test]
    fn yuv444_to_bgra_rejects_odd_dimension() {
        let planes = Yuv444Planes {
            y: vec![128; 17 * 16],
            u: vec![128; 17 * 16],
            v: vec![128; 17 * 16],
            width: 17,
            height: 16,
        };
        let mut dst = vec![0u8; 17 * 16 * 4];
        assert!(yuv444_to_bgra(&planes, &mut dst, 17, 16).is_err());
    }

    #[test]
    fn yuv444_to_bgra_exact_values() {
        // Y=128, U=255 (U'=127), V=128 (V'=0):
        //   R = 128 + (6451*0 + 2048) >> 12 = 128 + 0 = 128
        //   G = 128 - (767*127 + 1917*0 + 2048) >> 12 = 128 - (99457>>12) = 128 - 24 = 104
        //   B = 128 + (7601*127 + 2048) >> 12 = 128 + (967375>>12) = 128 + 236 = 364 → 255
        let planes = Yuv444Planes {
            y: vec![128; 16 * 16],
            u: vec![255; 16 * 16],
            v: vec![128; 16 * 16],
            width: 16,
            height: 16,
        };
        let mut dst = vec![0u8; 16 * 16 * 4];
        yuv444_to_bgra(&planes, &mut dst, 16, 16).unwrap();
        assert_eq!(dst[0], 255); // B (clamped)
        assert_eq!(dst[1], 104); // G
        assert_eq!(dst[2], 128); // R
    }
}
