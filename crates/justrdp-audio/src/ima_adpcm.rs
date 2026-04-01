#![forbid(unsafe_code)]

//! IMA-ADPCM (DVI-ADPCM) decoder (wFormatTag = 0x0011).
//!
//! Decodes IMA/DVI ADPCM compressed audio to i16 PCM samples.

use crate::error::{AudioError, AudioResult};

/// IMA step size table -- 89 entries.
const IMA_STEP_TABLE: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17,
    19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
    50, 55, 60, 66, 73, 80, 88, 97, 107, 118,
    130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
    337, 371, 408, 449, 494, 544, 598, 658, 724, 796,
    876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066,
    2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358,
    5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899,
    15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];

/// IMA index adjustment table -- 16 entries (for nibble values 0-15).
const IMA_INDEX_TABLE: [i32; 16] = [
    -1, -1, -1, -1, 2, 4, 6, 8,
    -1, -1, -1, -1, 2, 4, 6, 8,
];

/// Per-channel decoder state.
#[derive(Debug, Clone)]
struct ChannelState {
    predictor: i32,
    step_index: i32,
}

impl ChannelState {
    fn new(predictor: i16, step_index: u8) -> AudioResult<Self> {
        if step_index > 88 {
            return Err(AudioError::InvalidBlock("step_index > 88"));
        }
        Ok(Self {
            predictor: predictor as i32,
            step_index: step_index as i32,
        })
    }

    /// Decode a single 4-bit nibble.
    fn decode_nibble(&mut self, nibble: u8) -> i16 {
        let step = IMA_STEP_TABLE[self.step_index as usize];
        let nibble = nibble & 0x0F;

        // Compute diff using integer bit manipulation.
        let delta = nibble & 7;
        let mut diff = step >> 3;
        if delta & 4 != 0 {
            diff += step;
        }
        if delta & 2 != 0 {
            diff += step >> 1;
        }
        if delta & 1 != 0 {
            diff += step >> 2;
        }

        // Apply sign.
        if nibble & 8 != 0 {
            self.predictor -= diff;
        } else {
            self.predictor += diff;
        }

        // Clamp.
        self.predictor = self.predictor.clamp(-32768, 32767);

        // Update step index.
        self.step_index += IMA_INDEX_TABLE[nibble as usize];
        self.step_index = self.step_index.clamp(0, 88);

        self.predictor as i16
    }
}

/// IMA-ADPCM decoder.
#[derive(Debug, Clone)]
pub struct ImaAdpcmDecoder {
    n_channels: u16,
    sample_rate: u32,
    block_align: u16,
    samples_per_block: u16,
}

impl ImaAdpcmDecoder {
    /// Create a new IMA-ADPCM decoder.
    ///
    /// `extra_data` must contain at least 2 bytes for wSamplesPerBlock.
    pub fn new(
        n_channels: u16,
        sample_rate: u32,
        block_align: u16,
        extra_data: &[u8],
    ) -> AudioResult<Self> {
        if extra_data.len() < 2 {
            return Err(AudioError::InvalidFormat(
                "IMA-ADPCM extra data too short",
            ));
        }

        let samples_per_block =
            u16::from_le_bytes([extra_data[0], extra_data[1]]);

        Ok(Self {
            n_channels,
            sample_rate,
            block_align,
            samples_per_block,
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

    /// Per-channel header size: 4 bytes (predictor i16 + step_index u8 + reserved u8).
    fn channel_header_size(&self) -> usize {
        4 * self.n_channels as usize
    }

    /// Decode a single IMA-ADPCM block to i16 PCM samples.
    ///
    /// Returns the number of samples written to `output`.
    /// Output is interleaved for stereo (L, R, L, R, ...).
    pub fn decode_block(&self, block: &[u8], output: &mut [i16]) -> AudioResult<usize> {
        let ch = self.n_channels as usize;
        let hdr_size = self.channel_header_size();

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

        // Parse per-channel headers.
        let mut states = [ChannelState { predictor: 0, step_index: 0 }; 1];
        let mut states_stereo = [
            ChannelState { predictor: 0, step_index: 0 },
            ChannelState { predictor: 0, step_index: 0 },
        ];

        if ch == 1 {
            let predictor = i16::from_le_bytes([block[0], block[1]]);
            let step_index = block[2];
            states[0] = ChannelState::new(predictor, step_index)?;
        } else {
            let pred_l = i16::from_le_bytes([block[0], block[1]]);
            let step_l = block[2];
            let pred_r = i16::from_le_bytes([block[4], block[5]]);
            let step_r = block[6];
            states_stereo[0] = ChannelState::new(pred_l, step_l)?;
            states_stereo[1] = ChannelState::new(pred_r, step_r)?;
        }

        let mut out_idx = 0;

        // Output initial predictor values.
        if ch == 1 {
            output[out_idx] = states[0].predictor as i16;
            out_idx += 1;
        } else {
            output[out_idx] = states_stereo[0].predictor as i16;
            output[out_idx + 1] = states_stereo[1].predictor as i16;
            out_idx += 2;
        }

        let nibble_data = &block[hdr_size..];

        if ch == 1 {
            // Mono: lower nibble first, then upper nibble.
            for &byte in nibble_data {
                if out_idx >= total_samples {
                    break;
                }
                output[out_idx] = states[0].decode_nibble(byte & 0x0F);
                out_idx += 1;
                if out_idx >= total_samples {
                    break;
                }
                output[out_idx] = states[0].decode_nibble(byte >> 4);
                out_idx += 1;
            }
        } else {
            // Stereo: 4 bytes L nibbles, 4 bytes R nibbles, alternating groups.
            // Each 4-byte group = 8 nibbles = 8 samples for one channel.
            // Decode into temp buffers then interleave into output.
            let mut data_offset = 0;
            while out_idx < total_samples && data_offset + 8 <= nibble_data.len() {
                // Decode 8 L samples from 4 bytes.
                let mut l_samples = [0i16; 8];
                let mut l_count = 0;
                for i in 0..4 {
                    let byte = nibble_data[data_offset + i];
                    l_samples[l_count] = states_stereo[0].decode_nibble(byte & 0x0F);
                    l_count += 1;
                    l_samples[l_count] = states_stereo[0].decode_nibble(byte >> 4);
                    l_count += 1;
                }

                // Decode 8 R samples from 4 bytes.
                let mut r_samples = [0i16; 8];
                let mut r_count = 0;
                for i in 0..4 {
                    let byte = nibble_data[data_offset + 4 + i];
                    r_samples[r_count] = states_stereo[1].decode_nibble(byte & 0x0F);
                    r_count += 1;
                    r_samples[r_count] = states_stereo[1].decode_nibble(byte >> 4);
                    r_count += 1;
                }

                // Interleave L,R into output.
                for i in 0..8 {
                    if out_idx + 1 >= total_samples {
                        break;
                    }
                    output[out_idx] = l_samples[i];
                    output[out_idx + 1] = r_samples[i];
                    out_idx += 2;
                }

                data_offset += 8;
            }
        }

        Ok(out_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_table_length() {
        assert_eq!(IMA_STEP_TABLE.len(), 89);
    }

    #[test]
    fn index_table_length() {
        assert_eq!(IMA_INDEX_TABLE.len(), 16);
    }

    #[test]
    fn step_table_bounds() {
        assert_eq!(IMA_STEP_TABLE[0], 7);
        assert_eq!(IMA_STEP_TABLE[88], 32767);
    }

    #[test]
    fn nibble_decode_zero() {
        // predictor=0, step_index=0 (step=7), nibble=0
        // diff = 7>>3 = 0, predictor stays 0, step_index = max(0, -1) = 0
        let mut state = ChannelState::new(0, 0).unwrap();
        let sample = state.decode_nibble(0);
        assert_eq!(sample, 0);
        assert_eq!(state.step_index, 0);
    }

    #[test]
    fn nibble_decode_max_positive() {
        // predictor=0, step_index=0 (step=7), nibble=0x7
        // delta=7, diff = (7>>3) + 7 + (7>>1) + (7>>2) = 0 + 7 + 3 + 1 = 11
        // predictor = 0 + 11 = 11, step_index = 0 + 8 = 8
        let mut state = ChannelState::new(0, 0).unwrap();
        let sample = state.decode_nibble(0x7);
        assert_eq!(sample, 11);
        assert_eq!(state.step_index, 8);
    }

    #[test]
    fn nibble_decode_negative() {
        // predictor=0, step_index=0 (step=7), nibble=0xF (sign=1, delta=7)
        // diff = 0 + 7 + 3 + 1 = 11, predictor = 0 - 11 = -11
        let mut state = ChannelState::new(0, 0).unwrap();
        let sample = state.decode_nibble(0xF);
        assert_eq!(sample, -11);
        assert_eq!(state.step_index, 8);
    }

    #[test]
    fn step_index_clamp_upper() {
        // step_index=88, nibble=0x7 → step_index = 88 + 8 = 96 → clamp to 88
        let mut state = ChannelState { predictor: 0, step_index: 88 };
        state.decode_nibble(0x7);
        assert_eq!(state.step_index, 88);
    }

    #[test]
    fn mono_block_decode() {
        // Create a minimal mono block:
        // Header: predictor=100, step_index=0, reserved=0
        // Nibble data: [0x00] → 2 nibbles (both 0)
        let extra = [5u8, 0]; // wSamplesPerBlock = 5 (but we'll only get 3 from 1 byte of nibbles)
        let dec = ImaAdpcmDecoder::new(1, 22050, 5, &extra).unwrap();

        let mut block = [0u8; 5];
        block[0..2].copy_from_slice(&100i16.to_le_bytes()); // predictor
        block[2] = 0; // step_index
        block[3] = 0; // reserved
        block[4] = 0x00; // nibble data

        let mut output = [0i16; 5];
        let n = dec.decode_block(&block, &mut output).unwrap();
        assert!(n >= 3); // at least: initial + 2 nibbles
        assert_eq!(output[0], 100); // initial predictor
    }

    #[test]
    fn invalid_step_index() {
        let extra = [5u8, 0];
        let dec = ImaAdpcmDecoder::new(1, 22050, 5, &extra).unwrap();

        let mut block = [0u8; 5];
        block[2] = 89; // step_index > 88 → error

        let mut output = [0i16; 5];
        let err = dec.decode_block(&block, &mut output).unwrap_err();
        assert_eq!(err, AudioError::InvalidBlock("step_index > 88"));
    }

    #[test]
    fn stereo_block_decode() {
        // Stereo block: 8-byte header + 8 bytes nibble data (1 group: 4L + 4R)
        // wSamplesPerBlock = 1 (initial) + 8 (nibbles per channel) = 9
        let extra = 9u16.to_le_bytes();
        let dec = ImaAdpcmDecoder::new(2, 22050, 16, &extra).unwrap();

        let mut block = [0u8; 16];
        // L header: predictor=100, step_index=0, reserved=0
        block[0..2].copy_from_slice(&100i16.to_le_bytes());
        block[2] = 0;
        block[3] = 0;
        // R header: predictor=200, step_index=0, reserved=0
        block[4..6].copy_from_slice(&200i16.to_le_bytes());
        block[6] = 0;
        block[7] = 0;
        // L nibble data: 4 bytes of zeros (8 nibbles)
        block[8..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // R nibble data: 4 bytes of zeros (8 nibbles)
        block[12..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let mut output = [0i16; 18]; // 9 samples × 2 channels
        let n = dec.decode_block(&block, &mut output).unwrap();
        assert_eq!(n, 18);
        // First pair: initial predictors
        assert_eq!(output[0], 100); // L
        assert_eq!(output[1], 200); // R
        // Remaining pairs: nibble=0 with step=7 → diff=0, predictor unchanged
        for i in (2..18).step_by(2) {
            assert_eq!(output[i], 100, "L sample at {i}");
            assert_eq!(output[i + 1], 200, "R sample at {i}+1");
        }
    }
}
