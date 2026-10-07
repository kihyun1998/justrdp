//! 4-bit ADPCM audio to signed 16-bit samples: Microsoft ADPCM (`WAVE_FORMAT_ADPCM`) and IMA
//! ADPCM (`WAVE_FORMAT_DVI_ADPCM`). Both code a stream as blocks of `nBlockAlign` bytes, each
//! opening with a header per channel that restarts the predictor, so a block decodes alone.
//! A decoder is built from the format the server declared and checks that its `cbSize` extra
//! and block size agree before any block arrives.

/// Why an ADPCM format or block was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdpcmError {
    /// The format has no channels or more than two.
    UnsupportedChannels {
        /// `nChannels`.
        channels: u16,
    },
    /// The `cbSize` extra is not the length its fields require.
    MalformedExtra,
    /// `nBlockAlign` cannot hold the headers and whole groups of samples.
    BadBlockAlign {
        /// `nBlockAlign`.
        block_align: u16,
    },
    /// The extra's samples per block does not match what `nBlockAlign` holds.
    SamplesPerBlockMismatch {
        /// The extra's `wSamplesPerBlock`.
        declared: u16,
        /// What `nBlockAlign` holds.
        held: usize,
    },
    /// The data is not a whole number of blocks.
    PartialBlock {
        /// The data's length in bytes.
        len: usize,
    },
    /// A block header names a predictor the format's coefficient table does not have.
    PredictorOutOfRange {
        /// The header's predictor index.
        predictor: u8,
    },
    /// A block header's step index is past the IMA step table.
    StepIndexOutOfRange {
        /// The header's step index.
        index: u8,
    },
}

impl core::fmt::Display for AdpcmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AdpcmError::UnsupportedChannels { channels } => {
                write!(f, "ADPCM with {channels} channels is not supported")
            }
            AdpcmError::MalformedExtra => write!(f, "the ADPCM format's extra data is malformed"),
            AdpcmError::BadBlockAlign { block_align } => {
                write!(
                    f,
                    "an ADPCM nBlockAlign of {block_align} cannot hold a block"
                )
            }
            AdpcmError::SamplesPerBlockMismatch { declared, held } => write!(
                f,
                "the ADPCM format declares {declared} samples per block but a block holds {held}"
            ),
            AdpcmError::PartialBlock { len } => {
                write!(f, "{len} bytes of ADPCM are not a whole number of blocks")
            }
            AdpcmError::PredictorOutOfRange { predictor } => {
                write!(
                    f,
                    "MS-ADPCM predictor {predictor} is not in the coefficient table"
                )
            }
            AdpcmError::StepIndexOutOfRange { index } => {
                write!(f, "IMA-ADPCM step index {index} is past the step table")
            }
        }
    }
}

impl core::error::Error for AdpcmError {}

fn check_channels(channels: u16) -> Result<usize, AdpcmError> {
    match channels {
        1 | 2 => Ok(usize::from(channels)),
        channels => Err(AdpcmError::UnsupportedChannels { channels }),
    }
}

fn whole_blocks(
    data: &[u8],
    block_align: usize,
) -> Result<core::slice::ChunksExact<'_, u8>, AdpcmError> {
    if !data.len().is_multiple_of(block_align) {
        return Err(AdpcmError::PartialBlock { len: data.len() });
    }
    Ok(data.chunks_exact(block_align))
}

fn i16_at(bytes: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn clamp_i16(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

/// How Microsoft ADPCM scales its step after each nibble, in 1/256ths.
const MS_ADAPTATION: [i32; 16] = [
    230, 230, 230, 230, 307, 409, 512, 614, 768, 614, 512, 409, 307, 230, 230, 230,
];

/// The smallest step Microsoft ADPCM keeps.
const MS_MIN_DELTA: i32 = 16;

/// The largest step it keeps, so the next adaptation cannot overflow: ffmpeg's bound. A real
/// encoder's step stays far below it; only a hostile stream reaches it.
const MS_MAX_DELTA: i32 = i32::MAX / 768;

/// A Microsoft ADPCM format: its channels, block size and coefficient table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsAdpcm {
    channels: usize,
    block_align: usize,
    coefficients: Vec<(i32, i32)>,
}

impl MsAdpcm {
    /// The decoder for a Microsoft ADPCM format whose `cbSize` extra is `extra`:
    /// `wSamplesPerBlock`, `wNumCoef` and that many coefficient pairs. A block holds a 7-byte
    /// header per channel (predictor, step, two samples) and a nibble per sample after them.
    pub fn new(channels: u16, block_align: u16, extra: &[u8]) -> Result<Self, AdpcmError> {
        let channels_n = check_channels(channels)?;
        let [spb_lo, spb_hi, count_lo, count_hi, pairs @ ..] = extra else {
            return Err(AdpcmError::MalformedExtra);
        };
        let declared = u16::from_le_bytes([*spb_lo, *spb_hi]);
        let count = usize::from(u16::from_le_bytes([*count_lo, *count_hi]));
        if count == 0 || pairs.len() != 4 * count {
            return Err(AdpcmError::MalformedExtra);
        }
        let coefficients = pairs
            .as_chunks::<4>()
            .0
            .iter()
            .map(|p| (i32::from(i16_at(p, 0)), i32::from(i16_at(p, 2))))
            .collect();
        let block = usize::from(block_align);
        let header = 7 * channels_n;
        if block <= header {
            return Err(AdpcmError::BadBlockAlign { block_align });
        }
        let held = (block - header) * 2 / channels_n + 2;
        if usize::from(declared) != held || ((block - header) * 2) % channels_n != 0 {
            return Err(AdpcmError::SamplesPerBlockMismatch { declared, held });
        }
        Ok(Self {
            channels: channels_n,
            block_align: block,
            coefficients,
        })
    }

    /// Decode whole blocks to interleaved samples.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<i16>, AdpcmError> {
        let mut out = Vec::with_capacity(data.len() * 2);
        for block in whole_blocks(data, self.block_align)? {
            self.decode_block(block, &mut out)?;
        }
        Ok(out)
    }

    fn decode_block(&self, block: &[u8], out: &mut Vec<i16>) -> Result<(), AdpcmError> {
        let ch = self.channels;
        // Per channel: coefficient pair, step, the last sample and the one before it.
        let mut state = Vec::with_capacity(ch);
        for c in 0..ch {
            let predictor = block[c];
            let &(c1, c2) = self
                .coefficients
                .get(usize::from(predictor))
                .ok_or(AdpcmError::PredictorOutOfRange { predictor })?;
            let delta = i32::from(i16_at(block, ch + 2 * c));
            let sample1 = i32::from(i16_at(block, 3 * ch + 2 * c));
            let sample2 = i32::from(i16_at(block, 5 * ch + 2 * c));
            state.push((c1, c2, delta, sample1, sample2));
        }
        out.extend(state.iter().map(|s| s.4 as i16));
        out.extend(state.iter().map(|s| s.3 as i16));
        let nibbles = block[7 * ch..]
            .iter()
            .flat_map(|&byte| [byte >> 4, byte & 0x0F]);
        for (n, nibble) in nibbles.enumerate() {
            let (c1, c2, delta, sample1, sample2) = &mut state[n % ch];
            let signed = i32::from(nibble as i8) - if nibble & 0x08 != 0 { 16 } else { 0 };
            let predicted =
                (i64::from(*sample1) * i64::from(*c1) + i64::from(*sample2) * i64::from(*c2)) / 256
                    + i64::from(signed) * i64::from(*delta);
            let sample = predicted.clamp(i64::from(i16::MIN), i64::from(i16::MAX)) as i16;
            *sample2 = *sample1;
            *sample1 = i32::from(sample);
            *delta = (*delta * MS_ADAPTATION[usize::from(nibble)] / 256)
                .clamp(MS_MIN_DELTA, MS_MAX_DELTA);
            out.push(sample);
        }
        Ok(())
    }
}

/// IMA ADPCM's quantizer steps.
const IMA_STEPS: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449,
    494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272,
    2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493,
    10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];

/// How IMA ADPCM moves its step index after each nibble's magnitude.
const IMA_INDEX_MOVES: [i32; 8] = [-1, -1, -1, -1, 2, 4, 6, 8];

/// An IMA ADPCM format: its channels and block size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImaAdpcm {
    channels: usize,
    block_align: usize,
}

impl ImaAdpcm {
    /// The decoder for an IMA ADPCM format whose `cbSize` extra is `extra`, its
    /// `wSamplesPerBlock`. A block holds a 4-byte header per channel (a sample, which is the
    /// block's first, and a step index), then groups of four bytes per channel in turn.
    pub fn new(channels: u16, block_align: u16, extra: &[u8]) -> Result<Self, AdpcmError> {
        let channels_n = check_channels(channels)?;
        let &[spb_lo, spb_hi] = extra else {
            return Err(AdpcmError::MalformedExtra);
        };
        let declared = u16::from_le_bytes([spb_lo, spb_hi]);
        let block = usize::from(block_align);
        let header = 4 * channels_n;
        if block <= header || !(block - header).is_multiple_of(4 * channels_n) {
            return Err(AdpcmError::BadBlockAlign { block_align });
        }
        let held = (block - header) * 2 / channels_n + 1;
        if usize::from(declared) != held {
            return Err(AdpcmError::SamplesPerBlockMismatch { declared, held });
        }
        Ok(Self {
            channels: channels_n,
            block_align: block,
        })
    }

    /// Decode whole blocks to interleaved samples.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<i16>, AdpcmError> {
        let mut out = Vec::with_capacity(data.len() * 2);
        for block in whole_blocks(data, self.block_align)? {
            self.decode_block(block, &mut out)?;
        }
        Ok(out)
    }

    fn decode_block(&self, block: &[u8], out: &mut Vec<i16>) -> Result<(), AdpcmError> {
        let ch = self.channels;
        // Per channel: the last sample and the step index.
        let mut state = Vec::with_capacity(ch);
        for c in 0..ch {
            let index = block[4 * c + 2];
            if usize::from(index) >= IMA_STEPS.len() {
                return Err(AdpcmError::StepIndexOutOfRange { index });
            }
            state.push((i32::from(i16_at(block, 4 * c)), i32::from(index)));
        }
        let first = out.len();
        out.extend(state.iter().map(|&(sample, _)| sample as i16));
        let body = &block[4 * ch..];
        let frames = body.len() * 2 / ch;
        out.resize(first + (frames + 1) * ch, 0);
        // Each group holds eight samples of each channel: four bytes for one, then the next.
        for (g, group) in body.chunks_exact(4 * ch).enumerate() {
            for (c, bytes) in group.as_chunks::<4>().0.iter().enumerate() {
                let (sample, index) = &mut state[c];
                for (k, nibble) in bytes.iter().flat_map(|&b| [b & 0x0F, b >> 4]).enumerate() {
                    let step = IMA_STEPS[*index as usize];
                    let mut diff = step >> 3;
                    if nibble & 4 != 0 {
                        diff += step;
                    }
                    if nibble & 2 != 0 {
                        diff += step >> 1;
                    }
                    if nibble & 1 != 0 {
                        diff += step >> 2;
                    }
                    let next = if nibble & 8 != 0 {
                        *sample - diff
                    } else {
                        *sample + diff
                    };
                    *sample = i32::from(clamp_i16(next));
                    *index = (*index + IMA_INDEX_MOVES[usize::from(nibble & 7)])
                        .clamp(0, IMA_STEPS.len() as i32 - 1);
                    let frame = 1 + 8 * g + k;
                    out[first + frame * ch + c] = *sample as i16;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ms_extra(samples_per_block: u16, pairs: &[(i16, i16)]) -> Vec<u8> {
        let mut extra = samples_per_block.to_le_bytes().to_vec();
        extra.extend_from_slice(&(pairs.len() as u16).to_le_bytes());
        for (a, b) in pairs {
            extra.extend_from_slice(&a.to_le_bytes());
            extra.extend_from_slice(&b.to_le_bytes());
        }
        extra
    }

    const STANDARD: [(i16, i16); 7] = [
        (256, 0),
        (512, -256),
        (0, 0),
        (192, 64),
        (240, 0),
        (460, -208),
        (392, -232),
    ];

    /// The formats WS2022 offers (`[MS-RDPEA]` 4.1.1 and the #386 capture) are accepted:
    /// MS-ADPCM at `nBlockAlign` 1024 stereo declares 1012 samples per block, IMA 1017.
    #[test]
    fn the_servers_formats_are_accepted() {
        assert!(MsAdpcm::new(2, 1024, &ms_extra(1012, &STANDARD)).is_ok());
        assert!(ImaAdpcm::new(2, 1024, &1017u16.to_le_bytes()).is_ok());
    }

    #[test]
    fn malformed_formats_are_refused() {
        assert_eq!(
            MsAdpcm::new(3, 1024, &ms_extra(1012, &STANDARD)),
            Err(AdpcmError::UnsupportedChannels { channels: 3 })
        );
        assert_eq!(
            MsAdpcm::new(2, 1024, &ms_extra(1012, &STANDARD)[..10]),
            Err(AdpcmError::MalformedExtra)
        );
        assert_eq!(
            MsAdpcm::new(2, 1024, &ms_extra(1012, &[])),
            Err(AdpcmError::MalformedExtra)
        );
        assert_eq!(
            MsAdpcm::new(2, 1024, &ms_extra(1011, &STANDARD)),
            Err(AdpcmError::SamplesPerBlockMismatch {
                declared: 1011,
                held: 1012
            })
        );
        assert_eq!(
            MsAdpcm::new(2, 14, &ms_extra(2, &STANDARD)),
            Err(AdpcmError::BadBlockAlign { block_align: 14 })
        );
        assert_eq!(
            ImaAdpcm::new(2, 1024, &[0xf9]),
            Err(AdpcmError::MalformedExtra)
        );
        assert_eq!(
            ImaAdpcm::new(2, 1020, &1013u16.to_le_bytes()),
            Err(AdpcmError::BadBlockAlign { block_align: 1020 })
        );
        assert_eq!(
            ImaAdpcm::new(2, 1024, &1016u16.to_le_bytes()),
            Err(AdpcmError::SamplesPerBlockMismatch {
                declared: 1016,
                held: 1017
            })
        );
    }

    #[test]
    fn malformed_blocks_are_refused() {
        let ms = MsAdpcm::new(1, 16, &ms_extra(20, &STANDARD)).unwrap();
        assert_eq!(
            ms.decode(&[0; 15]),
            Err(AdpcmError::PartialBlock { len: 15 })
        );
        let mut block = [0u8; 16];
        block[0] = 7;
        assert_eq!(
            ms.decode(&block),
            Err(AdpcmError::PredictorOutOfRange { predictor: 7 })
        );
        let ima = ImaAdpcm::new(1, 8, &9u16.to_le_bytes()).unwrap();
        assert_eq!(
            ima.decode(&[0, 0, 89, 0, 0, 0, 0, 0]),
            Err(AdpcmError::StepIndexOutOfRange { index: 89 })
        );
    }

    /// A hostile stream of the largest nibbles grows the step to its cap, not past it, and
    /// predictor coefficients at the i16 extremes cannot overflow the prediction.
    #[test]
    fn hostile_ms_blocks_cannot_overflow() {
        let block_align = 7 + 1000;
        let spb = (block_align - 7) * 2 + 2;
        let ms = MsAdpcm::new(1, block_align, &ms_extra(spb, &[(i16::MAX, i16::MAX)])).unwrap();
        let mut block = vec![0u8, 0xFF, 0x7F, 0xFF, 0x7F, 0xFF, 0x7F];
        block.resize(usize::from(block_align), 0x77);
        let samples = ms.decode(&block).unwrap();
        assert_eq!(samples.len(), usize::from(spb));
        assert_eq!(*samples.last().unwrap(), i16::MAX);
    }

    proptest! {
        /// Untrusted blocks never panic, and a decoded block yields the samples it declares.
        #[test]
        fn decode_never_panics(
            channels in 1u16..=2,
            groups in 1u16..4,
            mut data in proptest::collection::vec(any::<u8>(), 0..96),
            in_table in any::<bool>(),
        ) {
            // Weight the MS predictor bytes into the table half the time, so blocks reach the
            // nibble loop rather than stopping at the header.
            if in_table {
                let ms_block = usize::from(7 * channels + 2 * channels * groups);
                for block in data.chunks_mut(ms_block) {
                    for byte in block.iter_mut().take(usize::from(channels)) {
                        *byte %= 7;
                    }
                }
            }
            let ms_block = 7 * channels + 2 * channels * groups;
            let ms_spb = (ms_block - 7 * channels) * 2 / channels + 2;
            if let Ok(ms) = MsAdpcm::new(channels, ms_block, &ms_extra(ms_spb, &STANDARD))
                && let Ok(samples) = ms.decode(&data)
            {
                prop_assert_eq!(
                    samples.len(),
                    data.len() / usize::from(ms_block) * usize::from(ms_spb) * usize::from(channels)
                );
            }
            let ima_block = 4 * channels + 4 * channels * groups;
            let ima_spb = (ima_block - 4 * channels) * 2 / channels + 1;
            let ima = ImaAdpcm::new(channels, ima_block, &ima_spb.to_le_bytes()).unwrap();
            if let Ok(samples) = ima.decode(&data) {
                prop_assert_eq!(
                    samples.len(),
                    data.len() / usize::from(ima_block) * usize::from(ima_spb) * usize::from(channels)
                );
            }
        }
    }
}
