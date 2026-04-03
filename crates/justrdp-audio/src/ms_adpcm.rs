#![forbid(unsafe_code)]

//! MS-ADPCM decoder (wFormatTag = 0x0002).
//!
//! Decodes Microsoft ADPCM compressed audio to i16 PCM samples.

use crate::error::{AudioError, AudioResult};

/// Adaptation table for delta updates -- 16 entries.
/// `new_delta = AdaptationTable[nibble] * delta / 256`.
/// Microsoft ADPCM codec specification (MSDN Multimedia Data Standards Update).
const ADAPTATION_TABLE: [i32; 16] = [
    230, 230, 230, 230, 307, 409, 512, 614,
    768, 614, 512, 409, 307, 230, 230, 230,
];

/// Default coefficient table (7 standard pairs).
/// Microsoft ADPCM codec specification (MSDN Multimedia Data Standards Update).
const DEFAULT_COEF1: [i16; 7] = [256, 512, 0, 192, 240, 460, 392];
const DEFAULT_COEF2: [i16; 7] = [0, -256, 0, 64, 0, -208, -232];

/// Fixed-point coefficient base (divisor = 2^8).
/// Microsoft ADPCM codec specification (MSDN Multimedia Data Standards Update).
const COEF_BASE: i32 = 256;

/// Minimum delta value.
/// Microsoft ADPCM codec specification (MSDN Multimedia Data Standards Update).
const MIN_DELTA: i32 = 16;

/// Maximum supported channels (mono or stereo).
/// [MS-RDPEA] Section 2.2.2.1 — nChannels field.
const MAX_CHANNELS: u16 = 2;

/// Number of standard coefficient pairs used by MS-ADPCM.
/// Microsoft ADPCM codec specification (MSDN Multimedia Data Standards Update).
const NUM_DEFAULT_COEF: usize = 7;

/// Bytes per coefficient pair (coef1: i16, coef2: i16).
/// Microsoft ADPCM codec specification (MSDN Multimedia Data Standards Update).
const COEF_PAIR_BYTES: usize = 4;

/// Byte offset of first coefficient pair in extra_data
/// (after wSamplesPerBlock(2) + wNumCoef(2)).
/// Microsoft ADPCM codec specification (MSDN Multimedia Data Standards Update).
const COEF_DATA_OFFSET: usize = 4;

/// Mono block header size: bPredictor(1) + iDelta(2) + iSamp1(2) + iSamp2(2) = 7 bytes.
/// Microsoft ADPCM codec specification (MSDN Multimedia Data Standards Update).
const MONO_HEADER_BYTES: usize = 7;

/// Parsed MS-ADPCM block header.
struct BlockHeader {
    predictor_idx: [u8; 2],
    delta: [i32; 2],
    samp1: [i32; 2],
    samp2: [i32; 2],
}

/// MS-ADPCM decoder.
#[derive(Debug, Clone)]
pub struct MsAdpcmDecoder {
    n_channels: u16,
    sample_rate: u32,
    block_align: u16,
    samples_per_block: u16,
    coef1: [i16; 7],
    coef2: [i16; 7],
}

impl MsAdpcmDecoder {
    /// Create a new MS-ADPCM decoder.
    ///
    /// `extra_data` is the cbSize data from AUDIO_FORMAT containing
    /// wSamplesPerBlock, wNumCoef, and coefficient pairs.
    pub fn new(
        n_channels: u16,
        sample_rate: u32,
        block_align: u16,
        extra_data: &[u8],
    ) -> AudioResult<Self> {
        if n_channels == 0 || n_channels > MAX_CHANNELS {
            return Err(AudioError::InvalidFormat(
                "MS-ADPCM: only 1 or 2 channels supported",
            ));
        }

        if extra_data.len() < COEF_DATA_OFFSET {
            return Err(AudioError::InvalidFormat("MS-ADPCM extra data too short"));
        }

        let samples_per_block =
            u16::from_le_bytes([extra_data[0], extra_data[1]]);
        let num_coef = u16::from_le_bytes([extra_data[2], extra_data[3]]);

        if (num_coef as usize) < NUM_DEFAULT_COEF {
            return Err(AudioError::InvalidFormat("MS-ADPCM wNumCoef < 7"));
        }

        let coef_data_len = num_coef as usize * COEF_PAIR_BYTES;
        if extra_data.len() < COEF_DATA_OFFSET + coef_data_len {
            return Err(AudioError::InvalidFormat(
                "MS-ADPCM extra data too short for coefficients",
            ));
        }

        // MS-ADPCM header embeds 2 seed samples (samp1, samp2), so minimum is 2.
        if samples_per_block < 2 {
            return Err(AudioError::InvalidFormat(
                "MS-ADPCM: samples_per_block must be >= 2",
            ));
        }

        // Only the first 7 coefficient pairs are used; these are the standard
        // MS-ADPCM coefficients per the ACM spec. num_coef >= 7 guaranteed above.
        let mut coef1 = DEFAULT_COEF1;
        let mut coef2 = DEFAULT_COEF2;
        for i in 0..NUM_DEFAULT_COEF {
            let offset = COEF_DATA_OFFSET + i * COEF_PAIR_BYTES;
            coef1[i] = i16::from_le_bytes([extra_data[offset], extra_data[offset + 1]]);
            coef2[i] = i16::from_le_bytes([extra_data[offset + 2], extra_data[offset + 3]]);
        }

        Ok(Self {
            n_channels,
            sample_rate,
            block_align,
            samples_per_block,
            coef1,
            coef2,
        })
    }

    /// Number of channels.
    pub fn channels(&self) -> u16 {
        self.n_channels
    }

    /// Sample rate in Hz.
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Block alignment in bytes.
    pub fn block_align(&self) -> u16 {
        self.block_align
    }

    /// Samples per block.
    pub fn samples_per_block(&self) -> u16 {
        self.samples_per_block
    }

    /// Block header size in bytes.
    fn header_size(&self) -> usize {
        MONO_HEADER_BYTES * self.n_channels as usize
    }

    /// Parse the block header fields for mono or stereo layout.
    fn parse_header(&self, block: &[u8]) -> AudioResult<BlockHeader> {
        let ch = self.n_channels as usize;
        let mut hdr = BlockHeader {
            predictor_idx: [0; 2],
            delta: [0; 2],
            samp1: [0; 2],
            samp2: [0; 2],
        };

        if ch == 1 {
            hdr.predictor_idx[0] = block[0];
            hdr.delta[0] = i32::from(i16::from_le_bytes([block[1], block[2]]));
            hdr.samp1[0] = i32::from(i16::from_le_bytes([block[3], block[4]]));
            hdr.samp2[0] = i32::from(i16::from_le_bytes([block[5], block[6]]));
        } else {
            // Stereo: bPredictor[0], bPredictor[1], iDelta[0], iDelta[1], ...
            hdr.predictor_idx[0] = block[0];
            hdr.predictor_idx[1] = block[1];
            hdr.delta[0] = i32::from(i16::from_le_bytes([block[2], block[3]]));
            hdr.delta[1] = i32::from(i16::from_le_bytes([block[4], block[5]]));
            hdr.samp1[0] = i32::from(i16::from_le_bytes([block[6], block[7]]));
            hdr.samp1[1] = i32::from(i16::from_le_bytes([block[8], block[9]]));
            hdr.samp2[0] = i32::from(i16::from_le_bytes([block[10], block[11]]));
            hdr.samp2[1] = i32::from(i16::from_le_bytes([block[12], block[13]]));
        }

        // Validate predictor indices.
        for c in 0..ch {
            if hdr.predictor_idx[c] as usize >= NUM_DEFAULT_COEF {
                return Err(AudioError::InvalidBlock("bPredictor out of range"));
            }
        }

        // Clamp initial deltas.
        for c in 0..ch {
            hdr.delta[c] = hdr.delta[c].max(MIN_DELTA);
        }

        Ok(hdr)
    }

    /// Decode a single ADPCM block to i16 PCM samples.
    ///
    /// Returns the number of samples written to `output`.
    /// Output is interleaved for stereo (L, R, L, R, ...).
    pub fn decode_block(&self, block: &[u8], output: &mut [i16]) -> AudioResult<usize> {
        let ch = self.n_channels as usize;
        let hdr_size = self.header_size();

        if block.len() < hdr_size {
            return Err(AudioError::InvalidBlock("block too short for header"));
        }

        let total_samples = self.samples_per_block as usize * ch;
        if output.len() < total_samples {
            return Err(AudioError::BufferTooSmall {
                needed: total_samples,
                available: output.len(),
            });
        }

        let hdr = self.parse_header(block)?;
        let mut delta = hdr.delta;
        let mut samp1 = hdr.samp1;
        let mut samp2 = hdr.samp2;

        // Load coefficients.
        let mut c1 = [0i32; 2];
        let mut c2 = [0i32; 2];
        for c in 0..ch {
            c1[c] = i32::from(self.coef1[hdr.predictor_idx[c] as usize]);
            c2[c] = i32::from(self.coef2[hdr.predictor_idx[c] as usize]);
        }

        // Output initial samples: samp2 first, then samp1.
        // These values originate from i16 wire fields widened to i32, always in range.
        let mut out_idx = 0;
        for c in 0..ch {
            #[allow(clippy::cast_possible_truncation)]
            { output[out_idx + c] = samp2[c] as i16; }
        }
        out_idx += ch;
        for c in 0..ch {
            #[allow(clippy::cast_possible_truncation)]
            { output[out_idx + c] = samp1[c] as i16; }
        }
        out_idx += ch;

        // Decode nibbles.
        // MS-ADPCM packs samples upper-nibble-first within each byte.
        // [MS-ADPCM] ACM codec specification.
        let nibble_data = &block[hdr_size..];
        for byte in nibble_data {
            if out_idx >= total_samples {
                break;
            }

            let nibbles = [(*byte >> 4) & 0x0F, *byte & 0x0F];

            for &nibble in &nibbles {
                if out_idx >= total_samples {
                    break;
                }

                // For stereo, nibbles alternate L/R. out_idx starts at an even
                // value (4 for stereo: 2 samp2 + 2 samp1), so out_idx % 2 gives
                // the correct channel: 0=L, 1=R.
                let c = if ch == 2 { out_idx % 2 } else { 0 };

                // Sign-extend nibble.
                let signed = if nibble >= 8 {
                    nibble as i32 - 16
                } else {
                    nibble as i32
                };

                // Predict — use i64 throughout to prevent overflow when
                // wire-supplied coefficients and samples are at extreme i16 values.
                // Keep pred as i64 to avoid unnecessary i32 round-trip.
                let pred = ((samp1[c] as i64 * c1[c] as i64
                    + samp2[c] as i64 * c2[c] as i64)
                    / COEF_BASE as i64)
                    .clamp(-32768, 32767);

                // Apply error — delta can grow large via adaptation, so i64
                // prevents overflow. signed is in [-8, 7], delta is i32.
                let sample = (pred + signed as i64 * delta[c] as i64)
                    .clamp(-32768, 32767) as i32;

                #[allow(clippy::cast_possible_truncation)]
                { output[out_idx] = sample as i16; }
                out_idx += 1;

                // Update history.
                samp2[c] = samp1[c];
                samp1[c] = sample;

                // Update delta — use i64 to prevent overflow for large delta
                // values, then clamp to i32 range before narrowing.
                delta[c] = ((ADAPTATION_TABLE[nibble as usize] as i64
                    * delta[c] as i64)
                    / COEF_BASE as i64)
                    .clamp(MIN_DELTA as i64, i32::MAX as i64) as i32;
            }
        }

        Ok(out_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_extra_data() -> [u8; 32] {
        // wSamplesPerBlock=4, wNumCoef=7, then 7 coefficient pairs
        let mut data = [0u8; 32];
        // wSamplesPerBlock = 4
        data[0] = 4;
        data[1] = 0;
        // wNumCoef = 7
        data[2] = 7;
        data[3] = 0;
        // Default coefficients
        let coefs: [(i16, i16); 7] = [
            (256, 0),
            (512, -256),
            (0, 0),
            (192, 64),
            (240, 0),
            (460, -208),
            (392, -232),
        ];
        for (i, (c1, c2)) in coefs.iter().enumerate() {
            let off = 4 + i * 4;
            data[off..off + 2].copy_from_slice(&c1.to_le_bytes());
            data[off + 2..off + 4].copy_from_slice(&c2.to_le_bytes());
        }
        data
    }

    #[test]
    fn ms_adpcm_decoder_creation() {
        let extra = make_extra_data();
        let dec = MsAdpcmDecoder::new(1, 22050, 256, &extra).unwrap();
        assert_eq!(dec.channels(), 1);
        assert_eq!(dec.sample_rate(), 22050);
        assert_eq!(dec.samples_per_block(), 4);
    }

    #[test]
    fn ms_adpcm_extra_data_too_short() {
        let err = MsAdpcmDecoder::new(1, 22050, 256, &[0, 0]).unwrap_err();
        assert_eq!(
            err,
            AudioError::InvalidFormat("MS-ADPCM extra data too short")
        );
    }

    #[test]
    fn ms_adpcm_mono_block() {
        let extra = make_extra_data();
        let dec = MsAdpcmDecoder::new(1, 22050, 256, &extra).unwrap();

        // Minimal mono block: 7-byte header + 1 byte nibble data = 8 bytes
        // bPredictor=0, iDelta=16, iSamp1=100, iSamp2=50
        // Then 2 nibbles (upper=0, lower=0) → predictions based on coef[0]=(256,0)
        let mut block = [0u8; 8];
        block[0] = 0; // bPredictor
        block[1..3].copy_from_slice(&16i16.to_le_bytes()); // iDelta
        block[3..5].copy_from_slice(&100i16.to_le_bytes()); // iSamp1
        block[5..7].copy_from_slice(&50i16.to_le_bytes()); // iSamp2
        block[7] = 0x00; // 2 nibbles: both 0

        let mut output = [0i16; 4];
        let n = dec.decode_block(&block, &mut output).unwrap();
        assert_eq!(n, 4);
        // First outputs: samp2=50, samp1=100
        assert_eq!(output[0], 50);
        assert_eq!(output[1], 100);
        // Nibble 0 (upper): pred = (100*256 + 50*0)/256 = 100, error=0*16=0 → sample=100
        assert_eq!(output[2], 100);
        // Nibble 0 (lower): pred = (100*256 + 100*0)/256 = 100 → sample=100
        assert_eq!(output[3], 100);
    }

    #[test]
    fn adaptation_table_values() {
        assert_eq!(ADAPTATION_TABLE.len(), 16);
        // Spot check
        assert_eq!(ADAPTATION_TABLE[0], 230);
        assert_eq!(ADAPTATION_TABLE[4], 307);
        assert_eq!(ADAPTATION_TABLE[7], 614);
        assert_eq!(ADAPTATION_TABLE[8], 768);
    }

    #[test]
    fn delta_adaptation() {
        // delta=100, nibble=4 → (307 * 100) / 256 = 119
        let new_delta = (ADAPTATION_TABLE[4] * 100) / 256;
        assert_eq!(new_delta, 119);
    }

    #[test]
    fn delta_min_saturation() {
        // delta=10, nibble=0 → (230 * 10) / 256 = 8 → clamp to 16
        let new_delta = ((ADAPTATION_TABLE[0] * 10) / 256).max(MIN_DELTA);
        assert_eq!(new_delta, MIN_DELTA);
    }

    #[test]
    fn ms_adpcm_mono_nonzero_nibble() {
        let extra = make_extra_data();
        let dec = MsAdpcmDecoder::new(1, 22050, 256, &extra).unwrap();

        // bPredictor=0 (coef1=256, coef2=0), iDelta=100, iSamp1=0, iSamp2=0
        // nibble byte: 0x5A → upper=5 (signed=+5), lower=0xA (signed=-6)
        let mut block = [0u8; 8];
        block[0] = 0; // bPredictor
        block[1..3].copy_from_slice(&100i16.to_le_bytes()); // iDelta
        block[3..5].copy_from_slice(&0i16.to_le_bytes()); // iSamp1
        block[5..7].copy_from_slice(&0i16.to_le_bytes()); // iSamp2
        block[7] = 0x5A; // nibbles: upper=5, lower=A

        let mut output = [0i16; 4];
        let n = dec.decode_block(&block, &mut output).unwrap();
        assert_eq!(n, 4);
        assert_eq!(output[0], 0);   // samp2
        assert_eq!(output[1], 0);   // samp1

        // Nibble 5 (upper): pred = (0*256+0*0)/256 = 0, sample = 0+5*100 = 500
        assert_eq!(output[2], 500);
        // delta updated: AdaptationTable[5]=409, (409*100)/256 = 159

        // Nibble A (lower, signed = -6): pred = (500*256+0*0)/256 = 500
        // sample = 500 + (-6)*159 = 500 - 954 = -454
        assert_eq!(output[3], -454);
    }

    #[test]
    fn ms_adpcm_stereo_block() {
        let extra = make_extra_data();
        // samples_per_block=4 per channel = 8 total interleaved
        let dec = MsAdpcmDecoder::new(2, 22050, 256, &extra).unwrap();

        // 14-byte stereo header + 2 bytes nibble data = 16 bytes
        let mut block = [0u8; 16];
        block[0] = 0; // bPredictor[L]
        block[1] = 0; // bPredictor[R]
        block[2..4].copy_from_slice(&50i16.to_le_bytes()); // iDelta[L]
        block[4..6].copy_from_slice(&50i16.to_le_bytes()); // iDelta[R]
        block[6..8].copy_from_slice(&100i16.to_le_bytes()); // iSamp1[L]
        block[8..10].copy_from_slice(&200i16.to_le_bytes()); // iSamp1[R]
        block[10..12].copy_from_slice(&50i16.to_le_bytes()); // iSamp2[L]
        block[12..14].copy_from_slice(&150i16.to_le_bytes()); // iSamp2[R]
        block[14] = 0x00; // 2 nibbles: L=0, R=0
        block[15] = 0x00; // 2 nibbles: L=0, R=0

        let mut output = [0i16; 8]; // 4 samples × 2 channels
        let n = dec.decode_block(&block, &mut output).unwrap();
        assert_eq!(n, 8);
        // Initial: samp2[L], samp2[R], samp1[L], samp1[R]
        assert_eq!(output[0], 50);  // L samp2
        assert_eq!(output[1], 150); // R samp2
        assert_eq!(output[2], 100); // L samp1
        assert_eq!(output[3], 200); // R samp1
    }

    #[test]
    fn ms_adpcm_reject_zero_channels() {
        let extra = make_extra_data();
        let err = MsAdpcmDecoder::new(0, 22050, 256, &extra).unwrap_err();
        assert_eq!(
            err,
            AudioError::InvalidFormat("MS-ADPCM: only 1 or 2 channels supported")
        );
    }

    #[test]
    fn ms_adpcm_reject_three_channels() {
        let extra = make_extra_data();
        let err = MsAdpcmDecoder::new(3, 22050, 256, &extra).unwrap_err();
        assert_eq!(
            err,
            AudioError::InvalidFormat("MS-ADPCM: only 1 or 2 channels supported")
        );
    }

    #[test]
    fn ms_adpcm_reject_samples_per_block_zero() {
        let mut extra = make_extra_data();
        extra[0] = 0; // wSamplesPerBlock = 0
        extra[1] = 0;
        let err = MsAdpcmDecoder::new(1, 22050, 256, &extra).unwrap_err();
        assert_eq!(
            err,
            AudioError::InvalidFormat("MS-ADPCM: samples_per_block must be >= 2")
        );
    }

    #[test]
    fn ms_adpcm_reject_samples_per_block_one() {
        let mut extra = make_extra_data();
        extra[0] = 1; // wSamplesPerBlock = 1
        extra[1] = 0;
        let err = MsAdpcmDecoder::new(1, 22050, 256, &extra).unwrap_err();
        assert_eq!(
            err,
            AudioError::InvalidFormat("MS-ADPCM: samples_per_block must be >= 2")
        );
    }
}
