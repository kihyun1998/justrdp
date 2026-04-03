#![forbid(unsafe_code)]

//! PCM passthrough decoder.
//!
//! Converts raw PCM samples (u8, i16 LE, i24 LE, f32 LE) to i16.

use crate::error::{AudioError, AudioResult};

/// PCM decoder that converts various PCM formats to i16.
#[derive(Debug, Clone)]
pub struct PcmDecoder {
    bits_per_sample: u16,
    n_channels: u16,
    sample_rate: u32,
}

impl PcmDecoder {
    /// Create a new PCM decoder.
    ///
    /// `bits_per_sample` must be 8, 16, 24, or 32.
    pub fn new(
        bits_per_sample: u16,
        n_channels: u16,
        sample_rate: u32,
    ) -> AudioResult<Self> {
        if n_channels == 0 {
            return Err(AudioError::InvalidFormat("PCM: n_channels cannot be 0"));
        }
        match bits_per_sample {
            8 | 16 | 24 | 32 => {}
            _ => return Err(AudioError::UnsupportedCodec),
        }
        Ok(Self {
            bits_per_sample,
            n_channels,
            sample_rate,
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

    /// Bytes per sample.
    fn bytes_per_sample(&self) -> usize {
        self.bits_per_sample as usize / 8
    }

    /// Decode PCM data to i16 samples.
    ///
    /// Returns the number of samples written to `output`.
    pub fn decode(&self, input: &[u8], output: &mut [i16]) -> AudioResult<usize> {
        // bps is always 1/2/3/4 since bits_per_sample is validated in new().
        let bps = self.bytes_per_sample();
        if input.len() % bps != 0 {
            return Err(AudioError::InvalidBlock(
                "PCM input length not aligned to sample size",
            ));
        }
        let num_samples = input.len() / bps;
        if output.len() < num_samples {
            return Err(AudioError::BufferTooSmall {
                needed: num_samples,
                available: output.len(),
            });
        }

        match self.bits_per_sample {
            8 => {
                for (i, &byte) in input.iter().enumerate() {
                    // 8-bit unsigned → i16: center at 128, scale to i16 range.
                    output[i] = ((byte as i16) - 128) << 8;
                }
            }
            16 => {
                for (i, chunk) in input.chunks_exact(2).enumerate() {
                    output[i] = i16::from_le_bytes([chunk[0], chunk[1]]);
                }
            }
            24 => {
                for (i, chunk) in input.chunks_exact(3).enumerate() {
                    // Sign-extend 24-bit to i32, then take upper 16 bits.
                    // If bit 23 (sign) is set, OR with !0xFF_FFFF fills bits [31:24]
                    // with 1s, completing the two's complement sign extension.
                    let v = (chunk[0] as i32) | ((chunk[1] as i32) << 8) | ((chunk[2] as i32) << 16);
                    let v = if v & 0x80_0000 != 0 {
                        v | !0xFF_FFFF
                    } else {
                        v
                    };
                    // v >> 8 fits in i16 after 24-bit sign extension.
                    #[allow(clippy::cast_possible_truncation)]
                    { output[i] = (v >> 8) as i16; }
                }
            }
            32 => {
                for (i, chunk) in input.chunks_exact(4).enumerate() {
                    let f = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    // Clamp to [-1.0, 1.0] and scale to full i16 range.
                    let clamped = if f.is_nan() { 0.0 } else { f.clamp(-1.0, 1.0) };
                    // 1.0 * 32768 = 32768 which exceeds i16::MAX (32767);
                    // clamp to [-32768, 32767] handles the boundary.
                    #[allow(clippy::cast_possible_truncation)]
                    { output[i] = (clamped * 32768.0).clamp(-32768.0, 32767.0) as i16; }
                }
            }
            _ => return Err(AudioError::UnsupportedCodec),
        }

        Ok(num_samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcm_u8_conversion() {
        let dec = PcmDecoder::new(8, 1, 44100).unwrap();
        let input = [0x00u8, 0x80, 0xFF];
        let mut output = [0i16; 3];
        let n = dec.decode(&input, &mut output).unwrap();
        assert_eq!(n, 3);
        assert_eq!(output[0], -32768); // 0x00: (0 - 128) << 8
        assert_eq!(output[1], 0);      // 0x80: (128 - 128) << 8
        assert_eq!(output[2], 32512);  // 0xFF: (255 - 128) << 8 = 127 * 256
    }

    #[test]
    fn pcm_i16_passthrough() {
        let dec = PcmDecoder::new(16, 1, 44100).unwrap();
        let input = [0x00u8, 0x80]; // -32768 in LE
        let mut output = [0i16; 1];
        let n = dec.decode(&input, &mut output).unwrap();
        assert_eq!(n, 1);
        assert_eq!(output[0], -32768);
    }

    #[test]
    fn pcm_i16_max() {
        let dec = PcmDecoder::new(16, 1, 44100).unwrap();
        let input = [0xFF, 0x7F]; // 32767 in LE
        let mut output = [0i16; 1];
        dec.decode(&input, &mut output).unwrap();
        assert_eq!(output[0], 32767);
    }

    #[test]
    fn pcm_f32_clamp() {
        let dec = PcmDecoder::new(32, 1, 44100).unwrap();
        let pos_2 = 2.0f32.to_le_bytes();
        let neg_2 = (-2.0f32).to_le_bytes();
        let nan = f32::NAN.to_le_bytes();
        let mut input = [0u8; 12];
        input[0..4].copy_from_slice(&pos_2);
        input[4..8].copy_from_slice(&neg_2);
        input[8..12].copy_from_slice(&nan);
        let mut output = [0i16; 3];
        let n = dec.decode(&input, &mut output).unwrap();
        assert_eq!(n, 3);
        assert_eq!(output[0], 32767);  // clamped 2.0 → 1.0, scaled to 32767
        assert_eq!(output[1], -32768); // clamped -2.0 → -1.0, scaled to -32768
        assert_eq!(output[2], 0);      // NaN → 0
    }

    #[test]
    fn pcm_24bit() {
        let dec = PcmDecoder::new(24, 1, 44100).unwrap();
        // 0x7FFFFF = max positive 24-bit → upper 16 bits = 0x7FFF
        let input = [0xFF, 0xFF, 0x7F];
        let mut output = [0i16; 1];
        dec.decode(&input, &mut output).unwrap();
        assert_eq!(output[0], 32767);

        // 0x800000 = min negative 24-bit → upper 16 bits = -128 → 0x8000
        let input = [0x00, 0x00, 0x80];
        dec.decode(&input, &mut output).unwrap();
        assert_eq!(output[0], -32768);
    }

    #[test]
    fn pcm_empty_input() {
        let dec = PcmDecoder::new(16, 1, 44100).unwrap();
        let mut output = [0i16; 0];
        let n = dec.decode(&[], &mut output).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn pcm_buffer_too_small() {
        let dec = PcmDecoder::new(16, 1, 44100).unwrap();
        let input = [0u8; 4]; // 2 samples
        let mut output = [0i16; 1]; // only room for 1
        let err = dec.decode(&input, &mut output).unwrap_err();
        assert_eq!(
            err,
            AudioError::BufferTooSmall {
                needed: 2,
                available: 1
            }
        );
    }

    #[test]
    fn pcm_unsupported_bits() {
        let err = PcmDecoder::new(12, 1, 44100).unwrap_err();
        assert_eq!(err, AudioError::UnsupportedCodec);
    }

    #[test]
    fn pcm_reject_zero_channels() {
        let err = PcmDecoder::new(16, 0, 44100).unwrap_err();
        assert_eq!(
            err,
            AudioError::InvalidFormat("PCM: n_channels cannot be 0")
        );
    }
}
