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
