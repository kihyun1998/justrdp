//! Native audio capture backends for justrdp-rdpeai (MS-RDPEAI).
//!
//! Provides [`AudioCaptureBackend`] trait and platform implementations that
//! capture audio from the OS microphone and produce PCM bytes suitable for
//! [`AudioInputClient::build_audio_messages()`].
//!
//! # Platform Support
//!
//! - **Windows**: waveIn API (always available)
//! - **Linux**: PulseAudio/PipeWire (feature `pulseaudio`)
//! - **macOS**: CoreAudio AudioQueue (feature `coreaudio`)
//!
//! # Example
//!
//! ```ignore
//! use justrdp_rdpeai_native::{AudioCaptureBackend, AudioCaptureConfig, NativeCapture};
//!
//! let config = AudioCaptureConfig {
//!     sample_rate: 44100,
//!     channels: 2,
//!     bits_per_sample: 16,
//!     frames_per_packet: 1024,
//! };
//! let mut capture = NativeCapture::open(&config).expect("capture open");
//! let mut buf = vec![0u8; config.packet_byte_size()];
//! let n = capture.read(&mut buf).expect("capture read");
//! ```

#[cfg(target_os = "windows")]
mod wavein;

#[cfg(all(target_os = "linux", feature = "pulseaudio"))]
mod pulse;

#[cfg(all(target_os = "macos", feature = "coreaudio"))]
mod coreaudio;

use std::fmt;

/// Audio capture configuration derived from protocol negotiation.
#[derive(Debug, Clone)]
pub struct AudioCaptureConfig {
    /// Sample rate in Hz (e.g., 44100, 22050).
    pub sample_rate: u32,
    /// Number of channels (1 = mono, 2 = stereo).
    pub channels: u16,
    /// Bits per sample (typically 16).
    pub bits_per_sample: u16,
    /// Frames per packet requested by the server.
    pub frames_per_packet: u32,
}

impl AudioCaptureConfig {
    /// Byte size of one complete audio packet.
    ///
    /// `frames_per_packet * channels * (bits_per_sample / 8)`
    pub fn packet_byte_size(&self) -> usize {
        self.frames_per_packet as usize
            * self.channels as usize
            * (self.bits_per_sample as usize / 8)
    }
}

/// Error from the audio capture backend.
#[derive(Debug)]
pub enum AudioCaptureError {
    /// Capture device not available or failed to open.
    DeviceError(String),
    /// Requested audio format not supported.
    FormatNotSupported,
    /// Read from capture device failed.
    ReadError(String),
}

impl fmt::Display for AudioCaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceError(msg) => write!(f, "capture device error: {msg}"),
            Self::FormatNotSupported => f.write_str("capture format not supported"),
            Self::ReadError(msg) => write!(f, "capture read error: {msg}"),
        }
    }
}

impl std::error::Error for AudioCaptureError {}

/// Platform-specific audio capture backend.
///
/// Implementations capture audio from the OS microphone/input device
/// and produce interleaved PCM bytes (little-endian, signed 16-bit).
pub trait AudioCaptureBackend: Send {
    /// Open the capture device with the given configuration.
    fn open(config: &AudioCaptureConfig) -> Result<Self, AudioCaptureError>
    where
        Self: Sized;

    /// Read captured audio data into `buf`.
    ///
    /// Blocks until enough data is available to fill `buf` (or as much as
    /// the device provides in one read cycle). Returns the number of bytes read.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, AudioCaptureError>;

    /// Close the capture device and release resources.
    fn close(&mut self);
}

// ── Platform type aliases ──────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub type NativeCapture = wavein::WaveInCapture;

#[cfg(all(target_os = "linux", feature = "pulseaudio"))]
pub type NativeCapture = pulse::PulseAudioCapture;

#[cfg(all(target_os = "macos", feature = "coreaudio"))]
pub type NativeCapture = coreaudio::CoreAudioCapture;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_byte_size_stereo_16bit() {
        let config = AudioCaptureConfig {
            sample_rate: 44100,
            channels: 2,
            bits_per_sample: 16,
            frames_per_packet: 1024,
        };
        // 1024 frames * 2 channels * 2 bytes = 4096
        assert_eq!(config.packet_byte_size(), 4096);
    }

    #[test]
    fn packet_byte_size_mono_16bit() {
        let config = AudioCaptureConfig {
            sample_rate: 22050,
            channels: 1,
            bits_per_sample: 16,
            frames_per_packet: 512,
        };
        // 512 * 1 * 2 = 1024
        assert_eq!(config.packet_byte_size(), 1024);
    }
}
