#![forbid(unsafe_code)]

//! Subband reconstruction for RemoteFX (MS-RDPRFX §3.1.8.1.7).
//!
//! Converts a flat 4096-element RLGR-decoded coefficient array into
//! the 2D DWT coefficient matrix with correct subband placement.

use super::TILE_SIZE;

// ── Subband sizes and offsets in the flat array ──

/// Subband descriptor: name, flat offset, width, height, matrix position.
struct SubbandInfo {
    flat_offset: usize,
    count: usize,
    width: usize,
    row_start: usize,
    col_start: usize,
}

/// Subband order in RLGR stream: LL3, HL3, LH3, HH3, HL2, LH2, HH2, HL1, LH1, HH1.
const SUBBANDS: [SubbandInfo; 10] = [
    SubbandInfo { flat_offset: 0,    count: 64,   width: 8,  row_start: 0,  col_start: 0 },   // LL3
    SubbandInfo { flat_offset: 64,   count: 64,   width: 8,  row_start: 0,  col_start: 8 },   // HL3
    SubbandInfo { flat_offset: 128,  count: 64,   width: 8,  row_start: 8,  col_start: 0 },   // LH3
    SubbandInfo { flat_offset: 192,  count: 64,   width: 8,  row_start: 8,  col_start: 8 },   // HH3
    SubbandInfo { flat_offset: 256,  count: 256,  width: 16, row_start: 0,  col_start: 16 },  // HL2
    SubbandInfo { flat_offset: 512,  count: 256,  width: 16, row_start: 16, col_start: 0 },   // LH2
    SubbandInfo { flat_offset: 768,  count: 256,  width: 16, row_start: 16, col_start: 16 },  // HH2
    SubbandInfo { flat_offset: 1024, count: 1024, width: 32, row_start: 0,  col_start: 32 },  // HL1
    SubbandInfo { flat_offset: 2048, count: 1024, width: 32, row_start: 32, col_start: 0 },   // LH1
    SubbandInfo { flat_offset: 3072, count: 1024, width: 32, row_start: 32, col_start: 32 },  // HH1
];

/// Subband reconstruction.
pub struct SubbandReconstructor;

impl SubbandReconstructor {
    /// Place the flat 4096-element RLGR-decoded array into the 64×64 coefficient matrix.
    ///
    /// The flat array has subbands in order: LL3, HL3, LH3, HH3, HL2, LH2, HH2, HL1, LH1, HH1.
    /// Each subband is placed at its correct position in the 2D DWT decomposition layout.
    pub fn reconstruct(flat: &[i16], matrix: &mut [i32; super::TILE_COEFFICIENTS]) {
        for sb in &SUBBANDS {
            let height = sb.count / sb.width;
            for row in 0..height {
                for col in 0..sb.width {
                    let flat_idx = sb.flat_offset + row * sb.width + col;
                    let mat_row = sb.row_start + row;
                    let mat_col = sb.col_start + col;
                    matrix[mat_row * TILE_SIZE + mat_col] = flat[flat_idx] as i32;
                }
            }
        }
    }

    /// Extract subbands from a 64×64 coefficient matrix into a flat array.
    /// (Inverse of `reconstruct`, used by the encoder.)
    pub fn decompose(matrix: &[i32; super::TILE_COEFFICIENTS], flat: &mut [i16]) {
        for sb in &SUBBANDS {
            let height = sb.count / sb.width;
            for row in 0..height {
                for col in 0..sb.width {
                    let flat_idx = sb.flat_offset + row * sb.width + col;
                    let mat_row = sb.row_start + row;
                    let mat_col = sb.col_start + col;
                    flat[flat_idx] = matrix[mat_row * TILE_SIZE + mat_col] as i16;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstruct_decompose_roundtrip() {
        // Fill flat array with unique values
        let mut flat = [0i16; super::super::TILE_COEFFICIENTS];
        for i in 0..flat.len() {
            flat[i] = i as i16;
        }

        let mut matrix = [0i32; super::super::TILE_COEFFICIENTS];
        SubbandReconstructor::reconstruct(&flat, &mut matrix);

        let mut flat2 = [0i16; super::super::TILE_COEFFICIENTS];
        SubbandReconstructor::decompose(&matrix, &mut flat2);

        assert_eq!(flat, flat2);
    }

    #[test]
    fn subband_sizes_sum_to_4096() {
        let total: usize = SUBBANDS.iter().map(|sb| sb.count).sum();
        assert_eq!(total, super::super::TILE_COEFFICIENTS);
    }

    #[test]
    fn subband_offsets_contiguous() {
        for i in 1..SUBBANDS.len() {
            assert_eq!(
                SUBBANDS[i].flat_offset,
                SUBBANDS[i - 1].flat_offset + SUBBANDS[i - 1].count
            );
        }
    }

    #[test]
    fn ll3_placed_at_top_left() {
        let mut flat = [0i16; super::super::TILE_COEFFICIENTS];
        flat[0] = 42; // LL3[0,0]
        flat[7] = 99; // LL3[0,7]

        let mut matrix = [0i32; super::super::TILE_COEFFICIENTS];
        SubbandReconstructor::reconstruct(&flat, &mut matrix);

        assert_eq!(matrix[0 * TILE_SIZE + 0], 42); // (0,0)
        assert_eq!(matrix[0 * TILE_SIZE + 7], 99); // (0,7)
    }

    #[test]
    fn hh1_placed_at_bottom_right() {
        let mut flat = [0i16; super::super::TILE_COEFFICIENTS];
        flat[3072] = 77; // HH1[0,0] → matrix[32,32]

        let mut matrix = [0i32; super::super::TILE_COEFFICIENTS];
        SubbandReconstructor::reconstruct(&flat, &mut matrix);

        assert_eq!(matrix[32 * TILE_SIZE + 32], 77);
    }
}
