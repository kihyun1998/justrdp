#![forbid(unsafe_code)]

//! RemoteFX (RFX) Codec (MS-RDPRFX).
//!
//! Implements the full RFX decode/encode pipeline:
//! RLGR → Subband Reconstruction → Dequantization → Inverse DWT → YCbCr→RGB

pub mod color;
pub mod dwt;
pub mod quant;
pub mod rlgr;
pub mod subband;
pub mod tile;

use alloc::vec::Vec;
use core::fmt;

use self::color::ColorConverter;
use self::dwt::DwtTransform;
use self::quant::{dequantize, quantize, CodecQuant};
use self::rlgr::{RlgrDecoder, RlgrEncoder, RlgrMode};
use self::subband::SubbandReconstructor;

/// Tile dimension (always 64×64 in RFX).
pub const TILE_SIZE: usize = 64;

/// Number of coefficients per tile component (64×64 = 4096).
pub const TILE_COEFFICIENTS: usize = TILE_SIZE * TILE_SIZE;

/// RFX codec error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfxError {
    /// RLGR bitstream error.
    RlgrError,
    /// Invalid quantization index.
    InvalidQuantIndex(u8),
    /// Invalid quantization value.
    InvalidQuantValue(u8),
}

impl fmt::Display for RfxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RlgrError => write!(f, "RFX: RLGR decode error"),
            Self::InvalidQuantIndex(idx) => write!(f, "RFX: invalid quant index {idx}"),
            Self::InvalidQuantValue(val) => write!(f, "RFX: invalid quant value {val}"),
        }
    }
}

/// RFX tile decoder — processes a single 64×64 tile.
///
/// Decode pipeline: RLGR → Subband → Dequant → IDWT → YCbCr→RGB
#[derive(Debug, Clone)]
pub struct RfxDecoder {
    mode: RlgrMode,
}

impl RfxDecoder {
    /// Create a new RFX decoder with the specified RLGR entropy mode.
    pub fn new(mode: RlgrMode) -> Self {
        Self { mode }
    }

    /// Decode a single RFX tile from RLGR-encoded Y, Cb, Cr component data.
    ///
    /// # Arguments
    ///
    /// * `y_data` - RLGR-encoded Y component bytes
    /// * `cb_data` - RLGR-encoded Cb component bytes
    /// * `cr_data` - RLGR-encoded Cr component bytes
    /// * `quant_y` - Quantization values for Y
    /// * `quant_cb` - Quantization values for Cb
    /// * `quant_cr` - Quantization values for Cr
    /// * `dst` - Output buffer, resized to 64×64×4 (BGRA)
    pub fn decode_tile(
        &self,
        y_data: &[u8],
        cb_data: &[u8],
        cr_data: &[u8],
        quant_y: &CodecQuant,
        quant_cb: &CodecQuant,
        quant_cr: &CodecQuant,
        dst: &mut Vec<u8>,
    ) -> Result<(), RfxError> {
        // Decode each component through the pipeline
        let y_plane = self.decode_component(y_data, quant_y)?;
        let cb_plane = self.decode_component(cb_data, quant_cb)?;
        let cr_plane = self.decode_component(cr_data, quant_cr)?;

        // Color conversion: YCbCr → BGRA
        dst.clear();
        dst.resize(TILE_COEFFICIENTS * 4, 0);
        ColorConverter::ycbcr_to_bgra(&y_plane, &cb_plane, &cr_plane, dst);

        Ok(())
    }

    /// Decode a single component through: RLGR → Subband → Dequant → IDWT.
    fn decode_component(
        &self,
        data: &[u8],
        quant: &CodecQuant,
    ) -> Result<[i16; TILE_COEFFICIENTS], RfxError> {
        // Step 1: RLGR decode → 4096 quantized coefficients
        let mut coeffs = [0i16; TILE_COEFFICIENTS];
        let decoder = RlgrDecoder::new(self.mode);
        let decoded = decoder.decode(data, TILE_COEFFICIENTS).map_err(|_| RfxError::RlgrError)?;

        // Copy to fixed-size array
        let len = core::cmp::min(decoded.len(), TILE_COEFFICIENTS);
        for i in 0..len {
            coeffs[i] = decoded[i];
        }

        // Step 2: Subband reconstruction (flat array → 2D coefficient matrix)
        let mut matrix = [0i32; TILE_COEFFICIENTS];
        SubbandReconstructor::reconstruct(&coeffs, &mut matrix);

        // Step 3: Dequantization
        dequantize(&mut matrix, quant);

        // Step 4: Inverse DWT (3-level)
        DwtTransform::inverse_2d(&mut matrix, TILE_SIZE);

        // Convert i32 back to i16 (clamped)
        let mut result = [0i16; TILE_COEFFICIENTS];
        for i in 0..TILE_COEFFICIENTS {
            result[i] = matrix[i].clamp(-32768, 32767) as i16;
        }

        Ok(result)
    }
}

/// RFX tile encoder — encodes a single 64×64 tile.
///
/// Encode pipeline: BGRA → YCbCr → Forward DWT → Quantize → Subband → RLGR
#[derive(Debug, Clone)]
pub struct RfxEncoder {
    mode: RlgrMode,
}

impl RfxEncoder {
    /// Create a new RFX encoder with the specified RLGR entropy mode.
    pub fn new(mode: RlgrMode) -> Self {
        Self { mode }
    }

    /// Encode a single 64×64 BGRA tile into RLGR-encoded Y, Cb, Cr component data.
    ///
    /// # Arguments
    ///
    /// * `bgra` - Input BGRA pixels (64×64×4 = 16384 bytes)
    /// * `quant_y` - Quantization values for Y
    /// * `quant_cb` - Quantization values for Cb
    /// * `quant_cr` - Quantization values for Cr
    ///
    /// # Returns
    ///
    /// `(y_data, cb_data, cr_data)` — RLGR-encoded byte streams for each component.
    pub fn encode_tile(
        &self,
        bgra: &[u8],
        quant_y: &CodecQuant,
        quant_cb: &CodecQuant,
        quant_cr: &CodecQuant,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), RfxError> {
        // Step 1: Color conversion BGRA → YCbCr
        let mut y_plane = [0i16; TILE_COEFFICIENTS];
        let mut cb_plane = [0i16; TILE_COEFFICIENTS];
        let mut cr_plane = [0i16; TILE_COEFFICIENTS];
        ColorConverter::bgra_to_ycbcr(bgra, &mut y_plane, &mut cb_plane, &mut cr_plane);

        // Step 2-5: Encode each component
        let y_data = self.encode_component(&y_plane, quant_y);
        let cb_data = self.encode_component(&cb_plane, quant_cb);
        let cr_data = self.encode_component(&cr_plane, quant_cr);

        Ok((y_data, cb_data, cr_data))
    }

    /// Encode a single component: Forward DWT → Quantize → Subband → RLGR.
    fn encode_component(&self, plane: &[i16; TILE_COEFFICIENTS], quant: &CodecQuant) -> Vec<u8> {
        // Step 2: Convert i16 plane to i32 working buffer
        let mut matrix = [0i32; TILE_COEFFICIENTS];
        for i in 0..TILE_COEFFICIENTS {
            matrix[i] = plane[i] as i32;
        }

        // Step 3: Forward DWT (3-level)
        DwtTransform::forward_2d(&mut matrix, TILE_SIZE);

        // Step 4: Quantization
        quantize(&mut matrix, quant);

        // Step 5: Subband decomposition (2D matrix → flat array)
        let mut flat = [0i16; TILE_COEFFICIENTS];
        SubbandReconstructor::decompose(&matrix, &mut flat);

        // Step 6: RLGR encode
        let encoder = RlgrEncoder::new(self.mode);
        encoder.encode(&flat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_quant() -> CodecQuant {
        CodecQuant::from_bytes(&[0x66, 0x66, 0x66, 0x66, 0x66])
    }

    #[test]
    fn decode_tile_all_zeros_produces_gray() {
        // All-zero RLGR → 4096 zero coefficients → IDWT all zero → Y=0 → Y'=128 → gray
        let decoder = RfxDecoder::new(RlgrMode::Rlgr3);
        let data = alloc::vec![0u8; 512];
        let quant = identity_quant();

        let mut dst = Vec::new();
        decoder.decode_tile(&data, &data, &data, &quant, &quant, &quant, &mut dst).unwrap();

        assert_eq!(dst.len(), TILE_COEFFICIENTS * 4);
        for i in 0..TILE_COEFFICIENTS {
            let r = dst[i * 4 + 2];
            let g = dst[i * 4 + 1];
            let b = dst[i * 4];
            let a = dst[i * 4 + 3];
            assert_eq!(a, 0xFF);
            assert!((r as i32 - 128).abs() <= 2, "R={r} not ~128 at pixel {i}");
            assert!((g as i32 - 128).abs() <= 2, "G={g} not ~128 at pixel {i}");
            assert!((b as i32 - 128).abs() <= 2, "B={b} not ~128 at pixel {i}");
        }
    }

    #[test]
    fn decode_tile_output_size() {
        let decoder = RfxDecoder::new(RlgrMode::Rlgr1);
        let data = alloc::vec![0u8; 512];
        let quant = identity_quant();
        let mut dst = alloc::vec![0xDEu8; 12345];
        decoder.decode_tile(&data, &data, &data, &quant, &quant, &quant, &mut dst).unwrap();
        assert_eq!(dst.len(), TILE_COEFFICIENTS * 4);
    }

    // ── Encoder → Decoder roundtrip tests ──

    #[test]
    fn encode_decode_roundtrip_gray_rlgr1() {
        let encoder = RfxEncoder::new(RlgrMode::Rlgr1);
        let decoder = RfxDecoder::new(RlgrMode::Rlgr1);
        let quant = identity_quant();

        // Solid gray tile
        let mut bgra = alloc::vec![0u8; TILE_COEFFICIENTS * 4];
        for i in 0..TILE_COEFFICIENTS {
            bgra[i * 4] = 128;     // B
            bgra[i * 4 + 1] = 128; // G
            bgra[i * 4 + 2] = 128; // R
            bgra[i * 4 + 3] = 0xFF;
        }

        let (y_data, cb_data, cr_data) = encoder.encode_tile(&bgra, &quant, &quant, &quant).unwrap();
        let mut dst = Vec::new();
        decoder.decode_tile(&y_data, &cb_data, &cr_data, &quant, &quant, &quant, &mut dst).unwrap();

        for i in 0..TILE_COEFFICIENTS {
            let diff_r = (dst[i * 4 + 2] as i32 - 128).abs();
            let diff_g = (dst[i * 4 + 1] as i32 - 128).abs();
            let diff_b = (dst[i * 4] as i32 - 128).abs();
            assert!(diff_r <= 2, "R={} not ~128 at pixel {i}", dst[i * 4 + 2]);
            assert!(diff_g <= 2, "G={} not ~128 at pixel {i}", dst[i * 4 + 1]);
            assert!(diff_b <= 2, "B={} not ~128 at pixel {i}", dst[i * 4]);
        }
    }

    #[test]
    fn encode_decode_roundtrip_gray_rlgr3() {
        let encoder = RfxEncoder::new(RlgrMode::Rlgr3);
        let decoder = RfxDecoder::new(RlgrMode::Rlgr3);
        let quant = identity_quant();

        let mut bgra = alloc::vec![0u8; TILE_COEFFICIENTS * 4];
        for i in 0..TILE_COEFFICIENTS {
            bgra[i * 4] = 128;
            bgra[i * 4 + 1] = 128;
            bgra[i * 4 + 2] = 128;
            bgra[i * 4 + 3] = 0xFF;
        }

        let (y_data, cb_data, cr_data) = encoder.encode_tile(&bgra, &quant, &quant, &quant).unwrap();
        let mut dst = Vec::new();
        decoder.decode_tile(&y_data, &cb_data, &cr_data, &quant, &quant, &quant, &mut dst).unwrap();

        for i in 0..TILE_COEFFICIENTS {
            let diff_r = (dst[i * 4 + 2] as i32 - 128).abs();
            let diff_g = (dst[i * 4 + 1] as i32 - 128).abs();
            let diff_b = (dst[i * 4] as i32 - 128).abs();
            assert!(diff_r <= 2, "R diff at {i}: {diff_r}");
            assert!(diff_g <= 2, "G diff at {i}: {diff_g}");
            assert!(diff_b <= 2, "B diff at {i}: {diff_b}");
        }
    }

    #[test]
    fn encode_decode_roundtrip_colored_rlgr3() {
        let encoder = RfxEncoder::new(RlgrMode::Rlgr3);
        let decoder = RfxDecoder::new(RlgrMode::Rlgr3);
        let quant = identity_quant();

        // Red tile
        let mut bgra = alloc::vec![0u8; TILE_COEFFICIENTS * 4];
        for i in 0..TILE_COEFFICIENTS {
            bgra[i * 4] = 0;       // B
            bgra[i * 4 + 1] = 0;   // G
            bgra[i * 4 + 2] = 255; // R
            bgra[i * 4 + 3] = 0xFF;
        }

        let (y_data, cb_data, cr_data) = encoder.encode_tile(&bgra, &quant, &quant, &quant).unwrap();
        let mut dst = Vec::new();
        decoder.decode_tile(&y_data, &cb_data, &cr_data, &quant, &quant, &quant, &mut dst).unwrap();

        // Allow larger tolerance for color conversion + quantization roundtrip
        for i in 0..TILE_COEFFICIENTS {
            let diff_r = (dst[i * 4 + 2] as i32 - 255).abs();
            let diff_g = (dst[i * 4 + 1] as i32).abs();
            let diff_b = (dst[i * 4] as i32).abs();
            assert!(diff_r <= 5, "R={} at pixel {i}", dst[i * 4 + 2]);
            assert!(diff_g <= 5, "G={} at pixel {i}", dst[i * 4 + 1]);
            assert!(diff_b <= 5, "B={} at pixel {i}", dst[i * 4]);
        }
    }

    #[test]
    fn rlgr_encode_decode_roundtrip_zeros() {
        // Test RLGR codec alone: all zeros
        let input = alloc::vec![0i16; 4096];
        for mode in [RlgrMode::Rlgr1, RlgrMode::Rlgr3] {
            let encoder = RlgrEncoder::new(mode);
            let decoder = RlgrDecoder::new(mode);
            let encoded = encoder.encode(&input);
            let decoded = decoder.decode(&encoded, 4096).unwrap();
            assert_eq!(decoded, input, "RLGR {mode:?} zero roundtrip failed");
        }
    }

    #[test]
    fn rlgr_encode_decode_roundtrip_mixed() {
        // Test RLGR codec: mixed values
        let mut input = alloc::vec![0i16; 64];
        input[0] = 5;
        input[1] = -3;
        input[5] = 10;
        input[10] = -1;
        input[20] = 100;

        for mode in [RlgrMode::Rlgr1, RlgrMode::Rlgr3] {
            let encoder = RlgrEncoder::new(mode);
            let decoder = RlgrDecoder::new(mode);
            let encoded = encoder.encode(&input);
            let decoded = decoder.decode(&encoded, input.len()).unwrap();
            assert_eq!(decoded, input, "RLGR {mode:?} mixed roundtrip failed");
        }
    }

    #[test]
    fn encode_decode_roundtrip_gradient() {
        let encoder = RfxEncoder::new(RlgrMode::Rlgr3);
        let decoder = RfxDecoder::new(RlgrMode::Rlgr3);
        let quant = identity_quant();

        let mut bgra = alloc::vec![0u8; TILE_COEFFICIENTS * 4];
        for row in 0..64usize {
            for col in 0..64usize {
                let v = (col * 4) as u8;
                let idx = (row * 64 + col) * 4;
                bgra[idx] = v;
                bgra[idx + 1] = v;
                bgra[idx + 2] = v;
                bgra[idx + 3] = 0xFF;
            }
        }

        let (y_data, cb_data, cr_data) = encoder.encode_tile(&bgra, &quant, &quant, &quant).unwrap();
        let mut dst = Vec::new();
        decoder.decode_tile(&y_data, &cb_data, &cr_data, &quant, &quant, &quant, &mut dst).unwrap();

        for i in 0..TILE_COEFFICIENTS {
            let col = i % 64;
            let expected = (col * 4) as i32;
            let r = dst[i * 4 + 2] as i32;
            assert!((r - expected).abs() <= 4, "R={r} expected~{expected} at pixel {i}");
        }
    }

    #[test]
    fn encode_decode_roundtrip_lossy_quant() {
        let encoder = RfxEncoder::new(RlgrMode::Rlgr3);
        let decoder = RfxDecoder::new(RlgrMode::Rlgr3);
        let quant = CodecQuant::from_bytes(&[0x88, 0x88, 0x88, 0x88, 0x88]); // q=8, shift=2

        let mut bgra = alloc::vec![0u8; TILE_COEFFICIENTS * 4];
        for i in 0..TILE_COEFFICIENTS {
            bgra[i * 4] = 128;
            bgra[i * 4 + 1] = 128;
            bgra[i * 4 + 2] = 128;
            bgra[i * 4 + 3] = 0xFF;
        }

        let (y_data, cb_data, cr_data) = encoder.encode_tile(&bgra, &quant, &quant, &quant).unwrap();
        let mut dst = Vec::new();
        decoder.decode_tile(&y_data, &cb_data, &cr_data, &quant, &quant, &quant, &mut dst).unwrap();

        for i in 0..TILE_COEFFICIENTS {
            let r = dst[i * 4 + 2] as i32;
            assert!((r - 128).abs() <= 8, "R={r} at pixel {i}");
        }
    }
}
