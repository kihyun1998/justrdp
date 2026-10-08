//! Linear PCM (`WAVE_FORMAT_PCM`, `[MS-RDPEA]` 2.2.2.1.1) to and from interleaved signed 16-bit
//! samples. 8-bit samples are unsigned with silence at `0x80`; 16-bit samples are signed
//! little-endian.

/// Why PCM data could not be converted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcmError {
    /// `wBitsPerSample` is neither 8 nor 16.
    UnsupportedBitsPerSample {
        /// The offending depth.
        bits_per_sample: u16,
    },
    /// The data does not hold a whole number of samples.
    PartialSample {
        /// The data's length in bytes.
        len: usize,
    },
}

impl core::fmt::Display for PcmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PcmError::UnsupportedBitsPerSample { bits_per_sample } => {
                write!(
                    f,
                    "PCM at {bits_per_sample} bits per sample is not supported"
                )
            }
            PcmError::PartialSample { len } => {
                write!(
                    f,
                    "{len} bytes of PCM do not hold a whole number of samples"
                )
            }
        }
    }
}

impl core::error::Error for PcmError {}

/// Convert `data`, PCM at `bits_per_sample`, to signed 16-bit samples in the same order.
pub fn decode(bits_per_sample: u16, data: &[u8]) -> Result<Vec<i16>, PcmError> {
    match bits_per_sample {
        8 => Ok(data
            .iter()
            .map(|&sample| (i16::from(sample) - 0x80) << 8)
            .collect()),
        16 => {
            let (samples, rest) = data.as_chunks::<2>();
            if !rest.is_empty() {
                return Err(PcmError::PartialSample { len: data.len() });
            }
            Ok(samples.iter().map(|&s| i16::from_le_bytes(s)).collect())
        }
        bits_per_sample => Err(PcmError::UnsupportedBitsPerSample { bits_per_sample }),
    }
}

/// Convert signed 16-bit `samples` to PCM at `bits_per_sample`, in the same order. 8-bit PCM
/// keeps each sample's high byte.
pub fn encode(bits_per_sample: u16, samples: &[i16]) -> Result<Vec<u8>, PcmError> {
    match bits_per_sample {
        8 => Ok(samples
            .iter()
            .map(|&sample| ((sample >> 8) + 0x80) as u8)
            .collect()),
        16 => Ok(samples.iter().flat_map(|s| s.to_le_bytes()).collect()),
        bits_per_sample => Err(PcmError::UnsupportedBitsPerSample { bits_per_sample }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// 8-bit PCM is unsigned: 0x80 is silence, 0x00 the most negative, 0xFF the most positive.
    #[test]
    fn eight_bit_pcm_is_unsigned_around_0x80() {
        assert_eq!(
            decode(8, &[0x80, 0x00, 0xFF, 0x81]),
            Ok(vec![0, -32768, 32512, 256])
        );
    }

    /// 16-bit PCM is signed little-endian.
    #[test]
    fn sixteen_bit_pcm_is_signed_little_endian() {
        assert_eq!(
            decode(16, &[0x00, 0x00, 0xFF, 0x7F, 0x00, 0x80, 0x34, 0x12]),
            Ok(vec![0, 32767, -32768, 0x1234])
        );
    }

    #[test]
    fn a_partial_sample_and_other_depths_are_typed_errors() {
        assert_eq!(
            decode(16, &[1, 2, 3]),
            Err(PcmError::PartialSample { len: 3 })
        );
        for bits_per_sample in [0, 4, 12, 24, 32] {
            assert_eq!(
                decode(bits_per_sample, &[0; 12]),
                Err(PcmError::UnsupportedBitsPerSample { bits_per_sample })
            );
        }
    }

    /// Encoding 8-bit PCM keeps each sample's high byte, offset to unsigned around 0x80.
    #[test]
    fn eight_bit_encoding_keeps_the_high_byte_unsigned() {
        assert_eq!(
            encode(8, &[0, -32768, 32767, 256, -1]),
            Ok(vec![0x80, 0x00, 0xFF, 0x81, 0x7F])
        );
    }

    /// Encoding 16-bit PCM writes each sample signed little-endian.
    #[test]
    fn sixteen_bit_encoding_is_signed_little_endian() {
        assert_eq!(
            encode(16, &[0, 32767, -32768, 0x1234]),
            Ok(vec![0x00, 0x00, 0xFF, 0x7F, 0x00, 0x80, 0x34, 0x12])
        );
    }

    #[test]
    fn encoding_at_other_depths_is_a_typed_error() {
        for bits_per_sample in [0, 4, 12, 24, 32] {
            assert_eq!(
                encode(bits_per_sample, &[0; 4]),
                Err(PcmError::UnsupportedBitsPerSample { bits_per_sample })
            );
        }
    }

    proptest! {
        /// Encoding then decoding returns every 16-bit sample, and every 8-bit sample with its
        /// low byte cleared.
        #[test]
        fn encode_then_decode_round_trips(samples in proptest::collection::vec(any::<i16>(), 0..64)) {
            prop_assert_eq!(decode(16, &encode(16, &samples).unwrap()), Ok(samples.clone()));
            let truncated: Vec<i16> = samples.iter().map(|&s| s & !0xFF).collect();
            prop_assert_eq!(decode(8, &encode(8, &samples).unwrap()), Ok(truncated));
        }

        /// Untrusted PCM never panics, and a conversion keeps one sample per input sample.
        #[test]
        fn decode_never_panics(bits in prop_oneof![Just(8u16), Just(16u16), any::<u16>()],
                               data in proptest::collection::vec(any::<u8>(), 0..64)) {
            if let Ok(samples) = decode(bits, &data) {
                prop_assert_eq!(samples.len(), data.len() / usize::from(bits / 8));
            }
        }
    }
}
