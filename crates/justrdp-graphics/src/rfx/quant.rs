#![forbid(unsafe_code)]

//! Quantization/dequantization for RemoteFX (MS-RDPRFX §3.1.8.1.5, §3.1.8.2.3).

use super::TILE_SIZE;

/// Quantization values for all 10 subbands (MS-RDPRFX §2.2.2.1.5).
///
/// Each value is a 4-bit quantization factor in the range [6, 15].
/// The shift amount is `value - 6`, ranging from 0 to 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecQuant {
    pub ll3: u8,
    pub lh3: u8,
    pub hl3: u8,
    pub hh3: u8,
    pub lh2: u8,
    pub hl2: u8,
    pub hh2: u8,
    pub lh1: u8,
    pub hl1: u8,
    pub hh1: u8,
}

impl CodecQuant {
    /// Decode from 5 bytes (MS-RDPRFX §2.2.2.1.5).
    ///
    /// Byte 0: bits[3:0]=LL3, bits[7:4]=LH3
    /// Byte 1: bits[3:0]=HL3, bits[7:4]=HH3
    /// Byte 2: bits[3:0]=LH2, bits[7:4]=HL2
    /// Byte 3: bits[3:0]=HH2, bits[7:4]=LH1
    /// Byte 4: bits[3:0]=HL1, bits[7:4]=HH1
    pub fn from_bytes(bytes: &[u8; 5]) -> Self {
        Self {
            ll3: bytes[0] & 0x0F,
            lh3: (bytes[0] >> 4) & 0x0F,
            hl3: bytes[1] & 0x0F,
            hh3: (bytes[1] >> 4) & 0x0F,
            lh2: bytes[2] & 0x0F,
            hl2: (bytes[2] >> 4) & 0x0F,
            hh2: bytes[3] & 0x0F,
            lh1: (bytes[3] >> 4) & 0x0F,
            hl1: bytes[4] & 0x0F,
            hh1: (bytes[4] >> 4) & 0x0F,
        }
    }

    /// Encode to 5 bytes.
    pub fn to_bytes(&self) -> [u8; 5] {
        [
            (self.ll3 & 0x0F) | ((self.lh3 & 0x0F) << 4),
            (self.hl3 & 0x0F) | ((self.hh3 & 0x0F) << 4),
            (self.lh2 & 0x0F) | ((self.hl2 & 0x0F) << 4),
            (self.hh2 & 0x0F) | ((self.lh1 & 0x0F) << 4),
            (self.hl1 & 0x0F) | ((self.hh1 & 0x0F) << 4),
        ]
    }

    /// Get the shift amount (q - 6) for a subband by index.
    /// Subband order: LL3, HL3, LH3, HH3, HL2, LH2, HH2, HL1, LH1, HH1.
    fn shift_for_subband(&self, idx: usize) -> u32 {
        let q = match idx {
            0 => self.ll3,
            1 => self.hl3,
            2 => self.lh3,
            3 => self.hh3,
            4 => self.hl2,
            5 => self.lh2,
            6 => self.hh2,
            7 => self.hl1,
            8 => self.lh1,
            9 => self.hh1,
            _ => 6,
        };
        (q.saturating_sub(6)) as u32
    }
}

/// Subband info for dequantization: start position in the 64×64 matrix, width, height, subband index.
struct SubbandRegion {
    row_start: usize,
    col_start: usize,
    width: usize,
    height: usize,
    quant_idx: usize,
}

/// Subband regions in the 64×64 matrix with their quantization subband index.
const SUBBAND_REGIONS: [SubbandRegion; 10] = [
    SubbandRegion { row_start: 0,  col_start: 0,  width: 8,  height: 8,  quant_idx: 0 }, // LL3
    SubbandRegion { row_start: 0,  col_start: 8,  width: 8,  height: 8,  quant_idx: 1 }, // HL3
    SubbandRegion { row_start: 8,  col_start: 0,  width: 8,  height: 8,  quant_idx: 2 }, // LH3
    SubbandRegion { row_start: 8,  col_start: 8,  width: 8,  height: 8,  quant_idx: 3 }, // HH3
    SubbandRegion { row_start: 0,  col_start: 16, width: 16, height: 16, quant_idx: 4 }, // HL2
    SubbandRegion { row_start: 16, col_start: 0,  width: 16, height: 16, quant_idx: 5 }, // LH2
    SubbandRegion { row_start: 16, col_start: 16, width: 16, height: 16, quant_idx: 6 }, // HH2
    SubbandRegion { row_start: 0,  col_start: 32, width: 32, height: 32, quant_idx: 7 }, // HL1
    SubbandRegion { row_start: 32, col_start: 0,  width: 32, height: 32, quant_idx: 8 }, // LH1
    SubbandRegion { row_start: 32, col_start: 32, width: 32, height: 32, quant_idx: 9 }, // HH1
];

/// Apply dequantization to the 64×64 coefficient matrix in-place.
///
/// Each subband's coefficients are left-shifted by `(quant_value - 6)` bits.
pub fn dequantize(matrix: &mut [i32; super::TILE_COEFFICIENTS], quant: &CodecQuant) {
    for region in &SUBBAND_REGIONS {
        let shift = quant.shift_for_subband(region.quant_idx);
        if shift == 0 {
            continue;
        }
        for row in 0..region.height {
            for col in 0..region.width {
                let idx = (region.row_start + row) * TILE_SIZE + (region.col_start + col);
                matrix[idx] <<= shift;
            }
        }
    }
}

/// Apply quantization to the 64×64 coefficient matrix in-place (encoder).
///
/// Each subband's coefficients are right-shifted by `(quant_value - 6)` bits.
pub fn quantize(matrix: &mut [i32; super::TILE_COEFFICIENTS], quant: &CodecQuant) {
    for region in &SUBBAND_REGIONS {
        let shift = quant.shift_for_subband(region.quant_idx);
        if shift == 0 {
            continue;
        }
        for row in 0..region.height {
            for col in 0..region.width {
                let idx = (region.row_start + row) * TILE_SIZE + (region.col_start + col);
                matrix[idx] >>= shift;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_quant_roundtrip() {
        let bytes = [0x66, 0x66, 0x77, 0x88, 0x98];
        let quant = CodecQuant::from_bytes(&bytes);
        assert_eq!(quant.ll3, 6);
        assert_eq!(quant.lh3, 6);
        assert_eq!(quant.hl3, 6);
        assert_eq!(quant.hh3, 6);
        assert_eq!(quant.lh2, 7);
        assert_eq!(quant.hl2, 7);
        assert_eq!(quant.hh2, 8);
        assert_eq!(quant.lh1, 8);
        assert_eq!(quant.hl1, 8);
        assert_eq!(quant.hh1, 9);
        assert_eq!(quant.to_bytes(), bytes);
    }

    #[test]
    fn dequantize_shift_zero() {
        let quant = CodecQuant::from_bytes(&[0x66, 0x66, 0x66, 0x66, 0x66]);
        let mut matrix = [0i32; super::super::TILE_COEFFICIENTS];
        matrix[0] = 42; // LL3 position
        dequantize(&mut matrix, &quant);
        // q=6 → shift=0 → no change
        assert_eq!(matrix[0], 42);
    }

    #[test]
    fn dequantize_shift_nonzero() {
        let quant = CodecQuant::from_bytes(&[0x76, 0x66, 0x66, 0x66, 0x66]);
        // LL3=6 (shift=0), LH3=7 (shift=1)
        let mut matrix = [0i32; super::super::TILE_COEFFICIENTS];
        matrix[0] = 10; // LL3[0,0]
        matrix[8 * TILE_SIZE + 0] = 5; // LH3[0,0] at row=8, col=0
        dequantize(&mut matrix, &quant);
        assert_eq!(matrix[0], 10); // LL3: shift=0
        assert_eq!(matrix[8 * TILE_SIZE + 0], 5 << 1); // LH3: shift=1
    }

    #[test]
    fn quantize_dequantize_roundtrip() {
        let quant = CodecQuant::from_bytes(&[0x88, 0x88, 0x88, 0x88, 0x88]);
        let mut matrix = [0i32; super::super::TILE_COEFFICIENTS];
        // Set values that are multiples of 4 (shift=2 won't lose precision)
        matrix[0] = 100; // LL3
        matrix[32 * TILE_SIZE + 32] = -200; // HH1

        let original = matrix;
        quantize(&mut matrix, &quant);
        dequantize(&mut matrix, &quant);
        // shift=2: 100 >> 2 = 25, 25 << 2 = 100
        assert_eq!(matrix[0], original[0]);
        assert_eq!(matrix[32 * TILE_SIZE + 32], original[32 * TILE_SIZE + 32]);
    }
}
