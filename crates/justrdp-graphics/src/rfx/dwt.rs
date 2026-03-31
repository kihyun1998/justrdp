#![forbid(unsafe_code)]

//! Discrete Wavelet Transform (Le Gall 5/3) for RemoteFX (MS-RDPRFX §3.1.8.2.4).

use super::TILE_SIZE;

/// DWT transform operations.
pub struct DwtTransform;

impl DwtTransform {
    /// Apply 3-level 2D inverse DWT on a 64×64 coefficient matrix in-place.
    pub fn inverse_2d(matrix: &mut [i32; super::TILE_COEFFICIENTS], size: usize) {
        // Level 3: reconstruct 16×16 from 8×8 subbands
        Self::idwt_2d_level(matrix, size, 16);
        // Level 2: reconstruct 32×32 from 16×16 subbands
        Self::idwt_2d_level(matrix, size, 32);
        // Level 1: reconstruct 64×64 from 32×32 subbands
        Self::idwt_2d_level(matrix, size, 64);
    }

    /// Apply 3-level 2D forward DWT on a 64×64 matrix in-place.
    pub fn forward_2d(matrix: &mut [i32; super::TILE_COEFFICIENTS], size: usize) {
        // Level 1: decompose 64×64 into 32×32 subbands
        Self::dwt_2d_level(matrix, size, 64);
        // Level 2: decompose 32×32 LL into 16×16 subbands
        Self::dwt_2d_level(matrix, size, 32);
        // Level 3: decompose 16×16 LL into 8×8 subbands
        Self::dwt_2d_level(matrix, size, 16);
    }

    /// 2D inverse DWT for one level (MS-RDPRFX §3.1.8.2.4):
    /// First apply 1D IDWT vertically (columns), then horizontally (rows).
    fn idwt_2d_level(matrix: &mut [i32; super::TILE_COEFFICIENTS], stride: usize, n: usize) {
        let mut temp = [0i32; TILE_SIZE];
        let mut col_buf = [0i32; TILE_SIZE];

        // Step 1: Vertical IDWT on each column
        for col in 0..n {
            for row in 0..n {
                col_buf[row] = matrix[row * stride + col];
            }
            Self::idwt_1d(&col_buf[..n], n / 2, &mut temp[..n]);
            for row in 0..n {
                matrix[row * stride + col] = temp[row];
            }
        }

        // Step 2: Horizontal IDWT on each row
        for row in 0..n {
            let base = row * stride;
            Self::idwt_1d(&matrix[base..base + n], n / 2, &mut temp[..n]);
            matrix[base..base + n].copy_from_slice(&temp[..n]);
        }
    }

    /// 2D forward DWT for one level (MS-RDPRFX §3.1.8.1.4):
    /// First apply 1D DWT horizontally (rows), then vertically (columns).
    fn dwt_2d_level(matrix: &mut [i32; super::TILE_COEFFICIENTS], stride: usize, n: usize) {
        let mut temp = [0i32; TILE_SIZE];
        let mut col_buf = [0i32; TILE_SIZE];

        // Step 1: Horizontal DWT on each row
        for row in 0..n {
            let base = row * stride;
            let mut row_buf = [0i32; TILE_SIZE];
            row_buf[..n].copy_from_slice(&matrix[base..base + n]);
            Self::dwt_1d(&row_buf[..n], &mut temp[..n]);
            matrix[base..base + n].copy_from_slice(&temp[..n]);
        }

        // Step 2: Vertical DWT on each column
        for col in 0..n {
            for row in 0..n {
                col_buf[row] = matrix[row * stride + col];
            }
            Self::dwt_1d(&col_buf[..n], &mut temp[..n]);
            for row in 0..n {
                matrix[row * stride + col] = temp[row];
            }
        }
    }

    /// 1D inverse DWT (Le Gall 5/3 lifting).
    ///
    /// Input layout: `[L0, L1, ..., L_{n/2-1}, H0, H1, ..., H_{n/2-1}]`
    /// Output: reconstructed signal of length n.
    fn idwt_1d(input: &[i32], half: usize, output: &mut [i32]) {
        let n = half * 2;
        if n == 0 {
            return;
        }

        let l = &input[..half];
        let h = &input[half..n];

        // Working copies
        let mut even = [0i32; TILE_SIZE / 2];
        let mut odd = [0i32; TILE_SIZE / 2];
        even[..half].copy_from_slice(l);
        odd[..half].copy_from_slice(h);

        // Step 1: Inverse update — undo the update step
        // even[i] -= (odd[i-1] + odd[i] + 2) >> 2
        for i in 0..half {
            let h_prev = if i == 0 { odd[0] } else { odd[i - 1] };
            let h_cur = odd[i];
            even[i] -= (h_prev + h_cur + 2) >> 2;
        }

        // Step 2: Inverse predict — reconstruct odd samples
        // odd[i] += (even[i] + even[i+1] + 1) >> 1
        for i in 0..half {
            let e_cur = even[i];
            let e_next = if i + 1 < half { even[i + 1] } else { even[half - 1] };
            odd[i] += (e_cur + e_next + 1) >> 1;
        }

        // Interleave
        for i in 0..half {
            output[2 * i] = even[i];
            output[2 * i + 1] = odd[i];
        }
    }

    /// 1D forward DWT (Le Gall 5/3 lifting).
    ///
    /// Input: signal of length n (even).
    /// Output layout: `[L0, L1, ..., L_{n/2-1}, H0, H1, ..., H_{n/2-1}]`
    fn dwt_1d(input: &[i32], output: &mut [i32]) {
        let n = input.len();
        let half = n / 2;
        if n == 0 {
            return;
        }

        let mut even = [0i32; TILE_SIZE / 2];
        let mut odd = [0i32; TILE_SIZE / 2];

        // De-interleave
        for i in 0..half {
            even[i] = input[2 * i];
            odd[i] = input[2 * i + 1];
        }

        // Step 1: Predict — compute high-pass (odd samples)
        // odd[i] -= (even[i] + even[i+1] + 1) >> 1
        for i in 0..half {
            let e_cur = even[i];
            let e_next = if i + 1 < half { even[i + 1] } else { even[half - 1] };
            odd[i] -= (e_cur + e_next + 1) >> 1;
        }

        // Step 2: Update — compute low-pass (even samples)
        // even[i] += (odd[i-1] + odd[i] + 2) >> 2
        for i in 0..half {
            let h_prev = if i == 0 { odd[0] } else { odd[i - 1] };
            let h_cur = odd[i];
            even[i] += (h_prev + h_cur + 2) >> 2;
        }

        // Pack: L then H
        output[..half].copy_from_slice(&even[..half]);
        output[half..n].copy_from_slice(&odd[..half]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dwt_1d_roundtrip_simple() {
        let input = [10, 20, 30, 40, 50, 60, 70, 80];
        let mut dwt_out = [0i32; 8];
        let mut idwt_out = [0i32; 8];

        DwtTransform::dwt_1d(&input, &mut dwt_out);
        DwtTransform::idwt_1d(&dwt_out, 4, &mut idwt_out);

        assert_eq!(idwt_out, input);
    }

    #[test]
    fn dwt_1d_roundtrip_negative() {
        let input = [-50, 100, -30, 80, 0, -120, 60, -10];
        let mut dwt_out = [0i32; 8];
        let mut idwt_out = [0i32; 8];

        DwtTransform::dwt_1d(&input, &mut dwt_out);
        DwtTransform::idwt_1d(&dwt_out, 4, &mut idwt_out);

        assert_eq!(idwt_out, input);
    }

    #[test]
    fn dwt_2d_roundtrip_small() {
        // Use the full 64×64 pipeline
        let mut matrix = [0i32; super::super::TILE_COEFFICIENTS];
        for i in 0..super::super::TILE_COEFFICIENTS {
            matrix[i] = ((i as i32) % 256) - 128;
        }

        let original = matrix;
        DwtTransform::forward_2d(&mut matrix, TILE_SIZE);
        DwtTransform::inverse_2d(&mut matrix, TILE_SIZE);

        assert_eq!(matrix, original);
    }

    #[test]
    fn dwt_1d_constant_signal() {
        let input = [100, 100, 100, 100];
        let mut dwt_out = [0i32; 4];
        let mut idwt_out = [0i32; 4];

        DwtTransform::dwt_1d(&input, &mut dwt_out);
        // High-pass should be ~0 for constant signal
        assert_eq!(dwt_out[2], 0);
        assert_eq!(dwt_out[3], 0);

        DwtTransform::idwt_1d(&dwt_out, 2, &mut idwt_out);
        assert_eq!(idwt_out, input);
    }

    #[test]
    fn dwt_1d_known_answer_ramp() {
        // Ramp [2,4,6,8]. Le Gall 5/3 forward:
        // even=[2,6], odd=[4,8]
        // Predict: odd[0] -= (2+6+1)>>1=4 → 0; odd[1] -= (6+6+1)>>1=6 → 2
        // Update: even[0] += (0+0+2)>>2=0 → 2; even[1] += (0+2+2)>>2=1 → 7
        let input = [2i32, 4, 6, 8];
        let mut out = [0i32; 4];
        DwtTransform::dwt_1d(&input, &mut out);
        assert_eq!(out, [2, 7, 0, 2]);
    }

    #[test]
    fn idwt_1d_known_answer_ramp() {
        let dwt = [2i32, 7, 0, 2];
        let mut out = [0i32; 4];
        DwtTransform::idwt_1d(&dwt, 2, &mut out);
        assert_eq!(out, [2, 4, 6, 8]);
    }
}
