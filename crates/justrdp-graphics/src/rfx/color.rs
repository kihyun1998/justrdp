#![forbid(unsafe_code)]

//! Color conversion for RemoteFX (MS-RDPRFX §3.1.8.1.3, §3.1.8.2.5).
//!
//! Implements the ICT (Irreversible Color Transform) between RGB and YCbCr.

use super::TILE_COEFFICIENTS;

/// Color converter for RemoteFX (ICT transform).
pub struct ColorConverter;

impl ColorConverter {
    /// Convert YCbCr planes to BGRA pixels (MS-RDPRFX §3.1.8.2.5).
    ///
    /// # Arguments
    ///
    /// * `y_plane` - Y component (level-shifted, range ~[-128, 127])
    /// * `cb_plane` - Cb component
    /// * `cr_plane` - Cr component
    /// * `dst` - Output BGRA buffer, must be at least 4096×4 bytes
    pub fn ycbcr_to_bgra(
        y_plane: &[i16; TILE_COEFFICIENTS],
        cb_plane: &[i16; TILE_COEFFICIENTS],
        cr_plane: &[i16; TILE_COEFFICIENTS],
        dst: &mut [u8],
    ) {
        for i in 0..TILE_COEFFICIENTS {
            // Level-shift Y back up by 128
            let y = y_plane[i] as i32 + 128;
            let cb = cb_plane[i] as i32;
            let cr = cr_plane[i] as i32;

            // Inverse ICT (MS-RDPRFX §3.1.8.2.5, integer approximation)
            // R = Y' + (5743 * Cr) >> 12
            // G = Y' - (1410 * Cb + 2925 * Cr) >> 12
            // B = Y' + (7258 * Cb) >> 12
            let r = clamp_u8(y + ((5743 * cr + 2048) >> 12));
            let g = clamp_u8(y - ((1410 * cb + 2925 * cr + 2048) >> 12));
            let b = clamp_u8(y + ((7258 * cb + 2048) >> 12));

            let base = i * 4;
            dst[base] = b;
            dst[base + 1] = g;
            dst[base + 2] = r;
            dst[base + 3] = 0xFF; // Alpha
        }
    }

    /// Convert BGRA pixels to YCbCr planes (MS-RDPRFX §3.1.8.1.3).
    ///
    /// # Arguments
    ///
    /// * `bgra` - Input BGRA pixels (4096×4 bytes)
    /// * `y_plane` - Output Y component (level-shifted)
    /// * `cb_plane` - Output Cb component
    /// * `cr_plane` - Output Cr component
    pub fn bgra_to_ycbcr(
        bgra: &[u8],
        y_plane: &mut [i16; TILE_COEFFICIENTS],
        cb_plane: &mut [i16; TILE_COEFFICIENTS],
        cr_plane: &mut [i16; TILE_COEFFICIENTS],
    ) {
        for i in 0..TILE_COEFFICIENTS {
            let base = i * 4;
            let b = bgra[base] as i32;
            let g = bgra[base + 1] as i32;
            let r = bgra[base + 2] as i32;

            // Forward ICT (MS-RDPRFX §3.1.8.1.3, integer approximation)
            // Y  = ((1225 * R + 2404 * G + 467 * B) >> 12) - 128
            // Cb = ((-691 * R - 1357 * G + 2048 * B) >> 12)
            // Cr = ((2048 * R - 1715 * G - 333 * B) >> 12)
            y_plane[i] = (((1225 * r + 2404 * g + 467 * b + 2048) >> 12) - 128) as i16;
            cb_plane[i] = ((-691 * r - 1357 * g + 2048 * b + 2048) >> 12) as i16;
            cr_plane[i] = ((2048 * r - 1715 * g - 333 * b + 2048) >> 12) as i16;
        }
    }
}

#[inline]
fn clamp_u8(val: i32) -> u8 {
    if val < 0 {
        0
    } else if val > 255 {
        255
    } else {
        val as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ycbcr_to_bgra_gray() {
        // Gray: Y=0 (level-shifted from 128), Cb=0, Cr=0
        // After level-shift: Y'=128, R=128, G=128, B=128
        let y = [0i16; TILE_COEFFICIENTS];
        let cb = [0i16; TILE_COEFFICIENTS];
        let cr = [0i16; TILE_COEFFICIENTS];
        let mut dst = [0u8; TILE_COEFFICIENTS * 4];

        ColorConverter::ycbcr_to_bgra(&y, &cb, &cr, &mut dst);

        assert_eq!(dst[0], 128); // B
        assert_eq!(dst[1], 128); // G
        assert_eq!(dst[2], 128); // R
        assert_eq!(dst[3], 0xFF); // A
    }

    #[test]
    fn bgra_to_ycbcr_gray() {
        // Pure gray: R=G=B=128
        let mut bgra = [0u8; TILE_COEFFICIENTS * 4];
        for i in 0..TILE_COEFFICIENTS {
            bgra[i * 4] = 128;     // B
            bgra[i * 4 + 1] = 128; // G
            bgra[i * 4 + 2] = 128; // R
            bgra[i * 4 + 3] = 0xFF;
        }

        let mut y = [0i16; TILE_COEFFICIENTS];
        let mut cb = [0i16; TILE_COEFFICIENTS];
        let mut cr = [0i16; TILE_COEFFICIENTS];

        ColorConverter::bgra_to_ycbcr(&bgra, &mut y, &mut cb, &mut cr);

        // Y should be ~0 (128 - 128 = 0), Cb and Cr should be ~0
        assert!((y[0] as i32).abs() <= 1);
        assert!((cb[0] as i32).abs() <= 1);
        assert!((cr[0] as i32).abs() <= 1);
    }

    #[test]
    fn color_conversion_roundtrip_gray() {
        let mut bgra = [0u8; TILE_COEFFICIENTS * 4];
        for i in 0..TILE_COEFFICIENTS {
            bgra[i * 4] = 128;
            bgra[i * 4 + 1] = 128;
            bgra[i * 4 + 2] = 128;
            bgra[i * 4 + 3] = 0xFF;
        }

        let mut y = [0i16; TILE_COEFFICIENTS];
        let mut cb = [0i16; TILE_COEFFICIENTS];
        let mut cr = [0i16; TILE_COEFFICIENTS];

        ColorConverter::bgra_to_ycbcr(&bgra, &mut y, &mut cb, &mut cr);

        let mut result = [0u8; TILE_COEFFICIENTS * 4];
        ColorConverter::ycbcr_to_bgra(&y, &cb, &cr, &mut result);

        // Should be close to original (within rounding error)
        for i in 0..TILE_COEFFICIENTS {
            let diff_b = (result[i * 4] as i32 - bgra[i * 4] as i32).abs();
            let diff_g = (result[i * 4 + 1] as i32 - bgra[i * 4 + 1] as i32).abs();
            let diff_r = (result[i * 4 + 2] as i32 - bgra[i * 4 + 2] as i32).abs();
            assert!(diff_b <= 2, "B diff too large at pixel {i}: {diff_b}");
            assert!(diff_g <= 2, "G diff too large at pixel {i}: {diff_g}");
            assert!(diff_r <= 2, "R diff too large at pixel {i}: {diff_r}");
        }
    }

    #[test]
    fn ycbcr_clamp_values() {
        // Extreme values should clamp to [0, 255]
        let y = [127i16; TILE_COEFFICIENTS]; // Y' = 255
        let cb = [0i16; TILE_COEFFICIENTS];
        let cr = [127i16; TILE_COEFFICIENTS]; // Large positive Cr

        let mut dst = [0u8; TILE_COEFFICIENTS * 4];
        ColorConverter::ycbcr_to_bgra(&y, &cb, &cr, &mut dst);

        // R = 255 + large → clamped to 255
        assert_eq!(dst[2], 255);
    }

    #[test]
    fn color_roundtrip_chromatic_pixels() {
        let test_pixels: &[(u8, u8, u8)] = &[
            (255, 0, 0),     // Red
            (0, 255, 0),     // Green
            (0, 0, 255),     // Blue
            (255, 255, 0),   // Yellow
            (0, 255, 255),   // Cyan
            (255, 0, 255),   // Magenta
            (255, 128, 64),  // Arbitrary
        ];

        for &(r, g, b) in test_pixels {
            let mut bgra = [0u8; TILE_COEFFICIENTS * 4];
            for i in 0..TILE_COEFFICIENTS {
                bgra[i * 4] = b;
                bgra[i * 4 + 1] = g;
                bgra[i * 4 + 2] = r;
                bgra[i * 4 + 3] = 0xFF;
            }

            let mut y = [0i16; TILE_COEFFICIENTS];
            let mut cb = [0i16; TILE_COEFFICIENTS];
            let mut cr = [0i16; TILE_COEFFICIENTS];
            ColorConverter::bgra_to_ycbcr(&bgra, &mut y, &mut cb, &mut cr);

            let mut result = [0u8; TILE_COEFFICIENTS * 4];
            ColorConverter::ycbcr_to_bgra(&y, &cb, &cr, &mut result);

            let diff_r = (result[2] as i32 - r as i32).abs();
            let diff_g = (result[1] as i32 - g as i32).abs();
            let diff_b = (result[0] as i32 - b as i32).abs();
            assert!(diff_r <= 3, "R mismatch for ({r},{g},{b}): got {}, diff={diff_r}", result[2]);
            assert!(diff_g <= 3, "G mismatch for ({r},{g},{b}): got {}, diff={diff_g}", result[1]);
            assert!(diff_b <= 3, "B mismatch for ({r},{g},{b}): got {}, diff={diff_b}", result[0]);
        }
    }
}
