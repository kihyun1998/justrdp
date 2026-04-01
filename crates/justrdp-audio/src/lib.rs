#![no_std]
#![forbid(unsafe_code)]

//! Audio codecs for JustRDP.
//!
//! Provides decoders for audio formats used in RDP audio channels (MS-RDPEA):
//! PCM passthrough, MS-ADPCM, and IMA-ADPCM.
//!
//! AAC and Opus are parsed (header/frame extraction) but actual decoding
//! is delegated to external libraries via the backend trait.

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
mod pcm;
mod ms_adpcm;
mod ima_adpcm;
pub mod aac;
pub mod opus;

pub use error::{AudioError, AudioResult};
pub use pcm::PcmDecoder;
pub use ms_adpcm::MsAdpcmDecoder;
pub use ima_adpcm::ImaAdpcmDecoder;
pub use aac::{parse_heaac_info, adts_frame_length, AacPayloadType, HeaacWaveInfo};
pub use opus::{parse_opus_head, OpusHead};

/// Unified audio decoder trait.
///
/// Implementations decode compressed audio data to interleaved i16 PCM samples.
/// For block-based codecs (MS-ADPCM, IMA-ADPCM), `input` should be a single
/// complete block. For stream-based codecs (PCM), `input` is arbitrary.
pub trait AudioDecoder: Send + core::fmt::Debug {
    /// Decode audio data to i16 PCM samples.
    ///
    /// Returns the number of samples written to `output`.
    /// Output is interleaved for multi-channel (L, R, L, R, ...).
    fn decode(&mut self, input: &[u8], output: &mut [i16]) -> AudioResult<usize>;

    /// Sample rate in Hz.
    fn sample_rate(&self) -> u32;

    /// Number of output channels.
    fn channels(&self) -> u16;
}

impl AudioDecoder for PcmDecoder {
    fn decode(&mut self, input: &[u8], output: &mut [i16]) -> AudioResult<usize> {
        // PcmDecoder::decode takes &self, delegate directly.
        PcmDecoder::decode(self, input, output)
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate()
    }

    fn channels(&self) -> u16 {
        self.channels()
    }
}

impl AudioDecoder for MsAdpcmDecoder {
    fn decode(&mut self, input: &[u8], output: &mut [i16]) -> AudioResult<usize> {
        self.decode_block(input, output)
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate()
    }

    fn channels(&self) -> u16 {
        self.channels()
    }
}

impl AudioDecoder for ImaAdpcmDecoder {
    fn decode(&mut self, input: &[u8], output: &mut [i16]) -> AudioResult<usize> {
        self.decode_block(input, output)
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate()
    }

    fn channels(&self) -> u16 {
        self.channels()
    }
}
