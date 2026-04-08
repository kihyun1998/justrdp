//! Platform audio output trait.

use crate::error::NativeAudioResult;

/// Platform-specific audio output device.
///
/// Implementations write interleaved i16 PCM samples to the OS audio subsystem.
pub trait NativeAudioOutput: Send {
    /// Open the audio output device with the given format parameters.
    fn open(sample_rate: u32, channels: u16, bits_per_sample: u16) -> NativeAudioResult<Self>
    where
        Self: Sized;

    /// Write interleaved i16 PCM samples to the audio device.
    ///
    /// Blocks until all samples are consumed or an error occurs.
    fn write_samples(&mut self, samples: &[i16]) -> NativeAudioResult<()>;

    /// Set the playback volume.
    ///
    /// `left` and `right` are in the range `0..=0xFFFF` (0 = mute, 0xFFFF = max).
    fn set_volume(&mut self, left: u16, right: u16);

    /// Close the audio device and release resources.
    fn close(&mut self);
}
