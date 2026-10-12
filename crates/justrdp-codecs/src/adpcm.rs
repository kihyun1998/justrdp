//! 4-bit ADPCM audio to and from signed 16-bit samples: Microsoft ADPCM (`WAVE_FORMAT_ADPCM`)
//! and IMA ADPCM (`WAVE_FORMAT_DVI_ADPCM`). Both code a stream as blocks of `nBlockAlign` bytes,
//! each opening with a header per channel that restarts the predictor, so a block decodes alone.
//! A format is built from what the server declared and checks that its `cbSize` extra and block
//! size agree before any block arrives; it decodes blocks, and makes an encoder that carries its
//! step from one block to the next.

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
    /// The samples to encode are not a whole number of blocks.
    PartialBlockOfSamples {
        /// How many samples there are.
        samples: usize,
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
            AdpcmError::PartialBlockOfSamples { samples } => {
                write!(
                    f,
                    "{samples} samples are not a whole number of ADPCM blocks"
                )
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

    /// The frames one block holds.
    pub fn samples_per_block(&self) -> usize {
        (self.block_align - 7 * self.channels) * 2 / self.channels + 2
    }

    /// An encoder for this format, its step at the smallest.
    pub fn encoder(&self) -> MsAdpcmEncoder {
        MsAdpcmEncoder {
            format: self.clone(),
            delta: [MS_MIN_DELTA; 2],
        }
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

/// `samples`, interleaved over `channels`, cut into blocks of `samples_per_block` frames.
fn sample_blocks(
    samples: &[i16],
    channels: usize,
    samples_per_block: usize,
) -> Result<core::slice::ChunksExact<'_, i16>, AdpcmError> {
    let block = samples_per_block * channels;
    if !samples.len().is_multiple_of(block) {
        return Err(AdpcmError::PartialBlockOfSamples {
            samples: samples.len(),
        });
    }
    Ok(samples.chunks_exact(block))
}

/// A Microsoft ADPCM encoder. Every block uses the format's first coefficient pair, and a
/// channel's step runs on from one block into the next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsAdpcmEncoder {
    format: MsAdpcm,
    delta: [i32; 2],
}

impl MsAdpcmEncoder {
    /// Encode interleaved samples, a whole number of blocks of them, to blocks.
    pub fn encode(&mut self, samples: &[i16]) -> Result<Vec<u8>, AdpcmError> {
        let ch = self.format.channels;
        let blocks = sample_blocks(samples, ch, self.format.samples_per_block())?;
        let mut out = Vec::with_capacity(blocks.len() * self.format.block_align);
        for block in blocks {
            self.encode_block(block, &mut out);
        }
        Ok(out)
    }

    fn encode_block(&mut self, block: &[i16], out: &mut Vec<u8>) {
        let ch = self.format.channels;
        let (c1, c2) = self.format.coefficients[0];
        out.extend(core::iter::repeat_n(0u8, ch));
        for delta in &mut self.delta[..ch] {
            *delta = (*delta).clamp(MS_MIN_DELTA, i32::from(i16::MAX));
            out.extend_from_slice(&(*delta as i16).to_le_bytes());
        }
        // The header's samples are the block's first two frames, the later one first.
        for &sample in &block[ch..2 * ch] {
            out.extend_from_slice(&sample.to_le_bytes());
        }
        for &sample in &block[..ch] {
            out.extend_from_slice(&sample.to_le_bytes());
        }
        // Per channel: the last sample and the one before it, as the decoder will have them.
        let mut state: [(i64, i64); 2] = [(0, 0); 2];
        for (c, last) in state[..ch].iter_mut().enumerate() {
            *last = (i64::from(block[ch + c]), i64::from(block[c]));
        }
        let mut high = None;
        for (n, &sample) in block[2 * ch..].iter().enumerate() {
            let nibble = ms_nibble(
                &mut state[n % ch],
                &mut self.delta[n % ch],
                (c1, c2),
                sample,
            );
            match high.take() {
                None => high = Some(nibble),
                Some(high) => out.push(high << 4 | nibble),
            }
        }
    }
}

/// The MS-ADPCM nibble for `sample` after `last`, the last sample and the one before it, with
/// the coefficient pair `(c1, c2)` and step `delta`, moving both on as the decoder will. The
/// error is rounded to the nearest step, halves away from zero.
fn ms_nibble(last: &mut (i64, i64), delta: &mut i32, (c1, c2): (i32, i32), sample: i16) -> u8 {
    let (sample1, sample2) = last;
    let predicted = (*sample1 * i64::from(c1) + *sample2 * i64::from(c2)) / 256;
    let error = i64::from(sample) - predicted;
    let half = i64::from(*delta) / 2;
    let rounded = if error >= 0 {
        error + half
    } else {
        error - half
    };
    let signed = (rounded / i64::from(*delta)).clamp(-8, 7);
    *sample2 = *sample1;
    *sample1 =
        (predicted + signed * i64::from(*delta)).clamp(i64::from(i16::MIN), i64::from(i16::MAX));
    let nibble = signed as u8 & 0x0F;
    *delta = (*delta * MS_ADAPTATION[usize::from(nibble)] / 256).clamp(MS_MIN_DELTA, MS_MAX_DELTA);
    nibble
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

    /// The frames one block holds.
    pub fn samples_per_block(&self) -> usize {
        (self.block_align - 4 * self.channels) * 2 / self.channels + 1
    }

    /// An encoder for this format, its step index at zero.
    pub fn encoder(&self) -> ImaAdpcmEncoder {
        ImaAdpcmEncoder {
            format: self.clone(),
            index: [0; 2],
        }
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

/// An IMA ADPCM encoder. A block's header holds its first frame, and a channel's step index
/// runs on from one block into the next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImaAdpcmEncoder {
    format: ImaAdpcm,
    index: [i32; 2],
}

impl ImaAdpcmEncoder {
    /// Encode interleaved samples, a whole number of blocks of them, to blocks.
    pub fn encode(&mut self, samples: &[i16]) -> Result<Vec<u8>, AdpcmError> {
        let ch = self.format.channels;
        let blocks = sample_blocks(samples, ch, self.format.samples_per_block())?;
        let mut out = Vec::with_capacity(blocks.len() * self.format.block_align);
        for block in blocks {
            self.encode_block(block, &mut out);
        }
        Ok(out)
    }

    fn encode_block(&mut self, block: &[i16], out: &mut Vec<u8>) {
        let ch = self.format.channels;
        // Per channel: the last sample, as the decoder will have it.
        let mut last = [0i32; 2];
        for c in 0..ch {
            last[c] = i32::from(block[c]);
            out.extend_from_slice(&block[c].to_le_bytes());
            out.extend_from_slice(&[self.index[c] as u8, 0]);
        }
        // Each group holds eight frames: four bytes of one channel's, then the next's.
        let frames = &block[ch..];
        for group in frames.chunks_exact(8 * ch) {
            for c in 0..ch {
                for pair in group.chunks_exact(2 * ch) {
                    let low = ima_nibble(&mut last[c], &mut self.index[c], pair[c]);
                    let high = ima_nibble(&mut last[c], &mut self.index[c], pair[ch + c]);
                    out.push(high << 4 | low);
                }
            }
        }
    }
}

/// The IMA nibble for `sample` after `last` at step `index`, moving both on as the decoder
/// will.
fn ima_nibble(last: &mut i32, index: &mut i32, sample: i16) -> u8 {
    let step = IMA_STEPS[*index as usize];
    let mut error = i32::from(sample) - *last;
    let mut nibble = 0u8;
    if error < 0 {
        nibble = 8;
        error = -error;
    }
    let mut diff = step >> 3;
    if error >= step {
        nibble |= 4;
        error -= step;
        diff += step;
    }
    if error >= step >> 1 {
        nibble |= 2;
        error -= step >> 1;
        diff += step >> 1;
    }
    if error >= step >> 2 {
        nibble |= 1;
        diff += step >> 2;
    }
    let next = if nibble & 8 != 0 {
        *last - diff
    } else {
        *last + diff
    };
    *last = i32::from(clamp_i16(next));
    *index =
        (*index + IMA_INDEX_MOVES[usize::from(nibble & 7)]).clamp(0, IMA_STEPS.len() as i32 - 1);
    nibble
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// `frames` frames of a 440 Hz tone at 22,050 Hz, each channel a quarter turn behind the
    /// one before it.
    fn tone(channels: usize, frames: usize) -> Vec<i16> {
        (0..frames)
            .flat_map(|n| {
                (0..channels).map(move |c| {
                    let t = n as f64 / 22_050.0 + c as f64 / 1760.0;
                    (8000.0 * (2.0 * core::f64::consts::PI * 440.0 * t).sin()) as i16
                })
            })
            .collect()
    }

    /// The signal-to-noise ratio of `decoded` against `original`, in decibels.
    fn snr_db(original: &[i16], decoded: &[i16]) -> f64 {
        let signal: f64 = original.iter().map(|&s| f64::from(s).powi(2)).sum();
        let noise: f64 = original
            .iter()
            .zip(decoded)
            .map(|(&a, &b)| (f64::from(a) - f64::from(b)).powi(2))
            .sum();
        10.0 * (signal / noise).log10()
    }

    /// The Windows 11 server's 22.05 kHz formats (#403): `nBlockAlign` 512 a channel, MS-ADPCM
    /// 1012 frames a block, IMA 1017.
    fn ms(channels: u16) -> MsAdpcm {
        let block = 512 * channels;
        let spb = (block - 7 * channels) * 2 / channels + 2;
        MsAdpcm::new(channels, block, &ms_extra(spb, &STANDARD)).unwrap()
    }

    fn ima(channels: u16) -> ImaAdpcm {
        let block = 512 * channels;
        let spb = (block - 4 * channels) * 2 / channels + 1;
        ImaAdpcm::new(channels, block, &spb.to_le_bytes()).unwrap()
    }

    #[test]
    fn a_block_holds_the_frames_its_format_declares() {
        assert_eq!(ms(1).samples_per_block(), 1012);
        assert_eq!(ms(2).samples_per_block(), 1012);
        assert_eq!(ima(1).samples_per_block(), 1017);
        assert_eq!(ima(2).samples_per_block(), 1017);
    }

    /// A tone encodes to blocks of the format's size that decode back close to it, and each
    /// block's header holds its first frame exactly (its first two for MS-ADPCM).
    #[test]
    fn a_tone_round_trips_through_the_decoders() {
        for channels in [1u16, 2] {
            let ch = usize::from(channels);
            let ms = ms(channels);
            let spb = ms.samples_per_block();
            let samples = tone(ch, 3 * spb);
            let blocks = ms.encoder().encode(&samples).unwrap();
            assert_eq!(blocks.len(), 3 * 512 * ch);
            let decoded = ms.decode(&blocks).unwrap();
            assert_eq!(decoded.len(), samples.len());
            for b in 0..3 {
                let at = b * spb * ch;
                assert_eq!(decoded[at..at + 2 * ch], samples[at..at + 2 * ch]);
            }
            assert!(snr_db(&samples, &decoded) > 30.0, "MS {channels} channels");

            let ima = ima(channels);
            let spb = ima.samples_per_block();
            let samples = tone(ch, 3 * spb);
            let blocks = ima.encoder().encode(&samples).unwrap();
            assert_eq!(blocks.len(), 3 * 512 * ch);
            let decoded = ima.decode(&blocks).unwrap();
            assert_eq!(decoded.len(), samples.len());
            for b in 0..3 {
                let at = b * spb * ch;
                assert_eq!(decoded[at..at + ch], samples[at..at + ch]);
            }
            assert!(snr_db(&samples, &decoded) > 30.0, "IMA {channels} channels");
        }
    }

    /// An encoder carries its step into the next block, as FreeRDP's and ffmpeg's do: two
    /// blocks encoded one at a time are the two encoded together, and the second header's step
    /// is not the first's.
    #[test]
    fn an_encoder_carries_its_step_from_block_to_block() {
        let ms = ms(1);
        let samples = tone(1, 2 * ms.samples_per_block());
        let together = ms.encoder().encode(&samples).unwrap();
        let mut encoder = ms.encoder();
        let mut apart = encoder.encode(&samples[..1012]).unwrap();
        apart.extend(encoder.encode(&samples[1012..]).unwrap());
        assert_eq!(together, apart);
        assert_eq!(together[1..3], 16i16.to_le_bytes());
        assert_ne!(together[513..515], together[1..3]);

        let ima = ima(1);
        let samples = tone(1, 2 * ima.samples_per_block());
        let together = ima.encoder().encode(&samples).unwrap();
        let mut encoder = ima.encoder();
        let mut apart = encoder.encode(&samples[..1017]).unwrap();
        apart.extend(encoder.encode(&samples[1017..]).unwrap());
        assert_eq!(together, apart);
        assert_eq!(together[2], 0);
        assert_ne!(together[512 + 2], 0);
    }

    /// With the standard first pair a prediction is the last sample and the step stays far
    /// inside 16 bits, but a format may declare any first pair: one that predicts past the
    /// samples' range drives the step up until a header could not hold it, and the header
    /// holds the largest step it can.
    #[test]
    fn the_ms_step_a_header_carries_fits_it_whatever_the_coefficients() {
        let ms = MsAdpcm::new(1, 512, &ms_extra(1012, &[(i16::MAX, 0)])).unwrap();
        let samples: Vec<i16> = (0..4 * 1012)
            .map(|n| if (n / 3) % 2 == 0 { i16::MAX } else { i16::MIN })
            .collect();
        let blocks = ms.encoder().encode(&samples).unwrap();
        let deltas: Vec<i16> = blocks
            .as_chunks::<512>()
            .0
            .iter()
            .map(|b| i16_at(b, 1))
            .collect();
        assert_eq!(deltas[0], 16);
        assert!(deltas[1..].contains(&i16::MAX), "{deltas:?}");
    }

    /// FreeRDP's IMA sample encoder (`dsp_encode_ima_adpcm_sample`) over 20,000 states and
    /// samples: the same nibble, sample and step index after it, every time.
    #[test]
    fn the_ima_quantizer_matches_freerdps() {
        let cases = include_bytes!("../tests/fixtures/adpcm/ima_quantizer_freerdp.bin");
        for case in cases.as_chunks::<9>().0 {
            let (mut last, mut index) = (i32::from(i16_at(case, 0)), i32::from(case[2]));
            let nibble = ima_nibble(&mut last, &mut index, i16_at(case, 3));
            assert_eq!(
                (nibble, last, index),
                (case[5], i32::from(i16_at(case, 6)), i32::from(case[8])),
                "{case:?}"
            );
        }
    }

    /// MS-ADPCM over 20,000 states and samples: ffmpeg's `adpcm_ms_compress_sample` gives the
    /// same nibble, sample and step every time. FreeRDP's `freerdp_dsp_encode_ms_adpcm_sample`
    /// differs only where it rounds differently: it never rounds a negative error away from
    /// zero, and rounds a positive one only past half a step.
    #[test]
    fn the_ms_quantizer_matches_ffmpegs_and_freerdps_but_for_its_rounding() {
        let cases = include_bytes!("../tests/fixtures/adpcm/ms_quantizer_freerdp_ffmpeg.bin");
        let mut freerdp_rounds_differently = 0;
        for case in cases.as_chunks::<23>().0 {
            let (c1, c2) = STANDARD[usize::from(case[0])];
            let (sample1, sample2) = (i16_at(case, 1), i16_at(case, 3));
            let start = u16::from_le_bytes([case[5], case[6]]);
            let sample = i16_at(case, 7);
            let mut last = (i64::from(sample1), i64::from(sample2));
            let mut delta = i32::from(start);
            let nibble = ms_nibble(&mut last, &mut delta, (c1.into(), c2.into()), sample);
            let ours = (nibble, last.0, delta);
            let at = |o: usize| {
                let d = i32::from_le_bytes([case[o + 3], case[o + 4], case[o + 5], case[o + 6]]);
                (case[o], i64::from(i16_at(case, o + 1)), d)
            };
            assert_eq!(ours, at(16), "ffmpeg: {case:?}");
            if ours != at(9) {
                let predicted =
                    (i64::from(sample1) * i64::from(c1) + i64::from(sample2) * i64::from(c2)) / 256;
                let error = i64::from(sample) - predicted;
                let (rem, half) = (error.abs() % i64::from(start), i64::from(start) / 2);
                assert!(
                    (error < 0 && rem >= half) || (error >= 0 && rem == half),
                    "FreeRDP: {case:?}"
                );
                freerdp_rounds_differently += 1;
            }
        }
        assert!(freerdp_rounds_differently > 0);
    }

    /// CPython 3.12's `audioop.lin2adpcm` on whole mono blocks of the Windows 11 server's
    /// 22.05 kHz format, each started from its header's sample and step index: the same body,
    /// nibble for nibble.
    #[test]
    fn ima_blocks_match_audioops() {
        let cases = include_bytes!("../tests/fixtures/adpcm/ima_blocks_audioop.bin");
        let ima = ima(1);
        for case in cases.as_chunks::<2543>().0 {
            let samples: Vec<i16> = case[1..2035]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&s| i16::from_le_bytes(s))
                .collect();
            let mut encoder = ima.encoder();
            encoder.index[0] = i32::from(case[0]);
            let block = encoder.encode(&samples).unwrap();
            assert_eq!(block[..4], [case[1], case[2], case[0], 0]);
            assert_eq!(block[4..], case[2035..], "starting at step {}", case[0]);
        }
    }

    #[test]
    fn an_encoder_takes_whole_blocks_only() {
        assert_eq!(
            ms(2).encoder().encode(&[0; 1012 * 2 - 1]),
            Err(AdpcmError::PartialBlockOfSamples { samples: 2023 })
        );
        assert_eq!(
            ima(1).encoder().encode(&[0; 1018]),
            Err(AdpcmError::PartialBlockOfSamples { samples: 1018 })
        );
        assert_eq!(ima(1).encoder().encode(&[]), Ok(Vec::new()));
    }

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

    /// The formats WS2019 offers (`[MS-RDPEA]` 4.1.1 and the #386 capture) are accepted:
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
        /// Any samples, full-scale square waves included, encode to blocks that decode to as
        /// many samples, MS-ADPCM's step staying within its header's 16 bits.
        #[test]
        fn encoding_never_panics_and_decodes_back(
            channels in 1u16..=2,
            seed in proptest::collection::vec(any::<i16>(), 1..64),
            square in any::<bool>(),
        ) {
            let ch = usize::from(channels);
            let blocks_of = |samples_per_block: usize| -> Vec<i16> {
                (0..2 * samples_per_block * ch)
                    .map(|n| match (square, (n / 7) % 2) {
                        (true, 0) => i16::MAX,
                        (true, _) => i16::MIN,
                        (false, _) => seed[n % seed.len()],
                    })
                    .collect()
            };
            let ms = ms(channels);
            let samples = blocks_of(ms.samples_per_block());
            let blocks = ms.encoder().encode(&samples).unwrap();
            prop_assert_eq!(ms.decode(&blocks).unwrap().len(), samples.len());
            for block in blocks.chunks_exact(512 * ch) {
                for c in 0..ch {
                    prop_assert!(i16_at(block, ch + 2 * c) >= 16);
                }
            }
            let ima = ima(channels);
            let samples = blocks_of(ima.samples_per_block());
            let blocks = ima.encoder().encode(&samples).unwrap();
            prop_assert_eq!(ima.decode(&blocks).unwrap().len(), samples.len());
        }

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
