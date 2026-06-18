//! RDP6 planar bitmap decompression (`RDP6_BITMAP_STREAM`, MS-RDPEGDI 2.2.2.5.1 /
//! algorithm 3.1.9) — the format 32-bpp slow-path bitmap data uses.
//!
//! The stream is one header byte, then color planes: an optional alpha plane, a full-resolution
//! luma/red plane, and two chroma/green/blue planes (optionally subsampled 2×2). Each plane is
//! either raw or RLE-compressed with the RDP6 scheme: scanline segments of raw bytes plus a
//! run of the last byte, and every scanline after the first stores **deltas** to the line
//! above (zigzag-folded into unsigned bytes). With a color-loss level > 0 the planes are
//! AYCoCg and pass through an inverse color transform; MS-RDPEGDI 3.1.9.1.2 swaps the R and B
//! planes when no alpha plane is present.
//!
//! Output is BGR24 in the stream's own scanline order — the same byte order and (bottom-up)
//! orientation slow-path 24-bpp bitmap data carries, so one color seam serves both.
//!
//! Self-owned (ADR-0003 phase 2 from the start); `ironrdp-graphics::rdp6` is the differential
//! oracle, never a dependency.

/// Why decompression failed. Malformed input is always a typed error, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanarError {
    /// `width` or `height` is zero.
    EmptyImage,
    /// The stream ended inside a header, segment, or plane.
    TruncatedInput,
    /// An RLE segment is malformed (zero control byte, or a segment overrunning its scanline).
    InvalidSegment,
}

impl core::fmt::Display for PlanarError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PlanarError::EmptyImage => write!(f, "empty image (zero width or height)"),
            PlanarError::TruncatedInput => write!(f, "planar stream ended early"),
            PlanarError::InvalidSegment => write!(f, "malformed RDP6 RLE segment"),
        }
    }
}

impl core::error::Error for PlanarError {}

/// `RDP6_BITMAP_STREAM` header bits.
const HEADER_CLL_MASK: u8 = 0x07;
const HEADER_CS: u8 = 0x08;
const HEADER_RLE: u8 = 0x10;
const HEADER_NA: u8 = 0x20;

/// Decompress an RDP6 planar stream into `width × height` BGR24 pixels (scanlines in stream
/// order; see the module docs for orientation).
pub fn decompress(src: &[u8], width: usize, height: usize) -> Result<Vec<u8>, PlanarError> {
    if width == 0 || height == 0 {
        return Err(PlanarError::EmptyImage);
    }
    let header = *src.first().ok_or(PlanarError::TruncatedInput)?;
    let body = &src[1..];

    let cll = header & HEADER_CLL_MASK;
    let use_alpha = header & HEADER_NA == 0;
    let rle = header & HEADER_RLE != 0;
    // Chroma subsampling only applies to the AYCoCg definition (CLL > 0).
    let subsampled = cll > 0 && header & HEADER_CS != 0;

    let (chroma_w, chroma_h) = if subsampled {
        (width.div_ceil(2), height.div_ceil(2))
    } else {
        (width, height)
    };
    let full_size = width * height;
    let chroma_size = chroma_w * chroma_h;

    // Decode the three color planes (the alpha plane is decoded only to advance the cursor —
    // slow-path bitmaps carry no meaningful alpha).
    let mut plane0 = vec![0u8; full_size];
    let mut plane1 = vec![0u8; chroma_size];
    let mut plane2 = vec![0u8; chroma_size];
    if rle {
        let mut pos = 0usize;
        if use_alpha {
            let mut alpha = vec![0u8; full_size];
            pos += decode_rle_plane(&body[pos.min(body.len())..], &mut alpha, width, height)?;
        }
        pos += decode_rle_plane(&body[pos.min(body.len())..], &mut plane0, width, height)?;
        pos += decode_rle_plane(
            &body[pos.min(body.len())..],
            &mut plane1,
            chroma_w,
            chroma_h,
        )?;
        decode_rle_plane(
            &body[pos.min(body.len())..],
            &mut plane2,
            chroma_w,
            chroma_h,
        )?;
    } else {
        let alpha_size = if use_alpha { full_size } else { 0 };
        // Raw planes are stored back to back; a single pad byte may trail the stream.
        let needed = alpha_size + full_size + 2 * chroma_size;
        if body.len() < needed {
            return Err(PlanarError::TruncatedInput);
        }
        plane0.copy_from_slice(&body[alpha_size..alpha_size + full_size]);
        let p1 = alpha_size + full_size;
        plane1.copy_from_slice(&body[p1..p1 + chroma_size]);
        plane2.copy_from_slice(&body[p1 + chroma_size..p1 + 2 * chroma_size]);
    }

    // Reassemble to BGR24.
    let mut out = Vec::with_capacity(full_size * 3);
    if cll == 0 {
        // ARGB definition: planes are literally R, G, B.
        for i in 0..full_size {
            out.extend_from_slice(&[plane2[i], plane1[i], plane0[i]]);
        }
    } else {
        // AYCoCg definition: inverse transform with color-loss correction. The CLL counts the
        // bits dropped from the chroma components; shifting by CLL-1 (instead of CLL then
        // halving) folds the matrix's /2 into the restoration.
        let shift = cll - 1;
        for row in 0..height {
            let chroma_row = if subsampled { row / 2 } else { row };
            for col in 0..width {
                let chroma_col = if subsampled { col / 2 } else { col };
                let y = plane0[row * width + col] as i16;
                let chroma_idx = chroma_row * chroma_w + chroma_col;
                let co = (plane1[chroma_idx] << shift) as i8 as i16;
                let cg = (plane2[chroma_idx] << shift) as i8 as i16;

                let t = y - cg;
                let r = (t + co).clamp(0, 255) as u8;
                let g = (y + cg).clamp(0, 255) as u8;
                let b = (t - co).clamp(0, 255) as u8;
                // MS-RDPEGDI 3.1.9.1.2: without an alpha plane the R and B planes arrive
                // swapped, so the "r" we computed is the blue channel and vice versa.
                if use_alpha {
                    out.extend_from_slice(&[b, g, r]);
                } else {
                    out.extend_from_slice(&[r, g, b]);
                }
            }
        }
    }
    Ok(out)
}

/// Decode one RLE-compressed plane, returning the number of source bytes consumed.
///
/// Each scanline is segments of `[control][raw bytes…]` where the control byte's high nibble
/// counts raw bytes and the low nibble a run of the last byte (1 → run 16+raw, raw 0;
/// 2 → run 32+raw, raw 0). Scanlines after the first hold zigzag-folded deltas to the line
/// above.
fn decode_rle_plane(
    src: &[u8],
    dst: &mut [u8],
    width: usize,
    height: usize,
) -> Result<usize, PlanarError> {
    let mut pos = 0usize;
    for row in 0..height {
        let mut col = 0usize;
        let mut last = 0u8;
        while col < width {
            let control = *src.get(pos).ok_or(PlanarError::TruncatedInput)?;
            pos += 1;
            if control == 0 {
                return Err(PlanarError::InvalidSegment);
            }
            let run_field = (control & 0x0F) as usize;
            let raw_field = (control >> 4) as usize;
            let (run, raw) = match run_field {
                1 => (16 + raw_field, 0),
                2 => (32 + raw_field, 0),
                run => (run, raw_field),
            };
            if col + raw + run > width {
                return Err(PlanarError::InvalidSegment);
            }
            if src.len() - pos < raw {
                return Err(PlanarError::TruncatedInput);
            }
            let out_base = row * width + col;
            dst[out_base..out_base + raw].copy_from_slice(&src[pos..pos + raw]);
            pos += raw;
            if raw > 0 {
                last = dst[out_base + raw - 1];
            }
            dst[out_base + raw..out_base + raw + run].fill(last);
            col += raw + run;
        }
        if row > 0 {
            // Resolve the deltas against the (already-resolved) line above.
            let (above, current) = dst.split_at_mut(row * width);
            let above = &above[(row - 1) * width..];
            for (value, &above_value) in current[..width].iter_mut().zip(above.iter()) {
                let delta = *value;
                let unfolded = if delta % 2 == 1 {
                    255u8.wrapping_sub((delta.wrapping_sub(1)) >> 1)
                } else {
                    delta >> 1
                };
                *value = above_value.wrapping_add(unfolded);
            }
        }
    }
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // ADR-0008 / issue #97 — the no-panic robustness property. `PlanarError`'s contract says
        // "malformed input is always a typed error, never a panic"; this asserts that contract
        // across the whole input space, not just the hand-picked vectors below. The planar `src`
        // is the unbounded, attacker-controlled blob (header byte + plane data), so it is fully
        // arbitrary; width/height are bounded because they arrive from fixed u16 `TS_BITMAP_DATA`
        // header fields, never the stream. Reaching the end without unwinding IS the assertion —
        // proptest fails (and shrinks to a minimal counterexample) on any panic / arithmetic
        // overflow / OOB. This is not hypothetical: FreeRDP's RDP6 planar decoder took an OOB
        // read here (CVE-2024-32458, `planar_skip_plane_rle`).
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn decompress_never_panics_on_arbitrary_input(
            width in 0usize..=64,
            height in 0usize..=64,
            src in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = decompress(&src, width, height);
        }
    }

    #[test]
    fn raw_argb_planes_reassemble_to_bgr() {
        // 2×1, no alpha (NA set), no RLE, CLL 0 → planes R, G, B raw + 1 pad byte.
        let src = [
            HEADER_NA, // header: raw ARGB without alpha
            1, 2, // R plane
            3, 4, // G plane
            5, 6, // B plane
            0, // pad
        ];
        let out = decompress(&src, 2, 1).unwrap();
        assert_eq!(out, [5, 3, 1, 6, 4, 2]); // BGR per pixel
    }

    #[test]
    fn rle_run_and_raw_segments() {
        // 4×2 single-logical-plane exercise via ARGB (decode three identical planes).
        // Plane scanline 1: control 0x13 → raw 1 (value 9), run 3 → 9,9,9,9.
        // Scanline 2: control 0x13 raw 1 (delta 2 → +1), run 3 → 10,10,10,10.
        let plane = [0x13, 9, 0x13, 2];
        let mut src = vec![HEADER_NA | HEADER_RLE];
        src.extend_from_slice(&plane); // R
        src.extend_from_slice(&plane); // G
        src.extend_from_slice(&plane); // B
        let out = decompress(&src, 4, 2).unwrap();
        assert_eq!(&out[..3], &[9, 9, 9]);
        assert_eq!(&out[12..15], &[10, 10, 10]);
        assert_eq!(out.len(), 4 * 2 * 3);
    }

    #[test]
    fn delta_unfolding_is_zigzag() {
        // Odd delta 1 → 255 - 0 = 255 ≡ -1; even delta 2 → +1.
        // Plane: row 1 raw 100; row 2 delta 1 → 99.
        let plane = [0x10, 100, 0x10, 1];
        let mut src = vec![HEADER_NA | HEADER_RLE];
        for _ in 0..3 {
            src.extend_from_slice(&plane);
        }
        let out = decompress(&src, 1, 2).unwrap();
        assert_eq!(out, [100, 100, 100, 99, 99, 99]);
    }

    #[test]
    fn aycocg_identity_luma_with_unit_cll() {
        // CLL 1, no subsampling, no alpha, raw: Y = 128, Co = Cg = 0 → gray 128 everywhere.
        let mut src = vec![HEADER_NA | 0x01];
        src.extend_from_slice(&[128, 128]); // Y plane (2×1)
        src.extend_from_slice(&[0, 0]); // Co
        src.extend_from_slice(&[0, 0]); // Cg
        src.push(0); // pad
        let out = decompress(&src, 2, 1).unwrap();
        assert_eq!(out, [128, 128, 128, 128, 128, 128]);
    }

    #[test]
    fn subsampled_chroma_upsamples_nearest() {
        // CLL 1 + CS, 2×2: Y full-res 4 values, chroma planes 1×1.
        let mut src = vec![HEADER_NA | HEADER_CS | 0x01];
        src.extend_from_slice(&[10, 20, 30, 40]); // Y
        src.push(0); // Co (1×1)
        src.push(0); // Cg (1×1)
        src.push(0); // pad
        let out = decompress(&src, 2, 2).unwrap();
        // Co=Cg=0 → gray of each Y.
        assert_eq!(out, [10, 10, 10, 20, 20, 20, 30, 30, 30, 40, 40, 40]);
    }

    #[test]
    fn malformed_streams_yield_typed_errors() {
        assert_eq!(decompress(&[], 1, 1), Err(PlanarError::TruncatedInput));
        // RLE control byte 0 is invalid.
        assert_eq!(
            decompress(&[HEADER_NA | HEADER_RLE, 0x00], 1, 1),
            Err(PlanarError::InvalidSegment)
        );
        // Segment overruns its scanline: raw 2 on a 1-wide plane.
        assert_eq!(
            decompress(&[HEADER_NA | HEADER_RLE, 0x20, 1, 2], 1, 1),
            Err(PlanarError::InvalidSegment)
        );
        // Raw mode short of a full plane set.
        assert_eq!(
            decompress(&[HEADER_NA, 1, 2], 2, 1),
            Err(PlanarError::TruncatedInput)
        );
    }
}
