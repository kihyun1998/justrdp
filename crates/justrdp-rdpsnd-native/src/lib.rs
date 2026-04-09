//! Native audio output backends for JustRDP RDPSND (MS-RDPEA).
//!
//! Provides [`NativeAudioBackend`] which implements [`RdpsndBackend`] by
//! decoding audio via `justrdp-audio` and playing it through the OS audio
//! subsystem.
//!
//! # Platform Support
//!
//! - **Windows**: waveOut API (enabled automatically on `cfg(windows)`)
//! - **Linux**: PulseAudio/PipeWire (requires feature `pulseaudio`)
//! - **macOS**: CoreAudio (requires feature `coreaudio`)
//!
//! On unsupported platforms, the `PlatformAudioBackend` type alias is not defined.
//!
//! # Example
//!
//! ```ignore
//! use justrdp_rdpsnd::RdpsndClient;
//! use justrdp_rdpsnd_native::NativeAudioBackend;
//!
//! let backend = NativeAudioBackend::new();
//! let rdpsnd = RdpsndClient::new(Box::new(backend));
//! ```

mod backend;
mod error;
mod output;

#[cfg(windows)]
mod wasapi;

#[cfg(all(target_os = "linux", feature = "pulseaudio"))]
mod pulseaudio;

#[cfg(all(target_os = "macos", feature = "coreaudio"))]
mod coreaudio;

pub use backend::NativeAudioBackend;
pub use error::{NativeAudioError, NativeAudioResult};
pub use output::NativeAudioOutput;

// Platform-specific type aliases for convenient use.

#[cfg(windows)]
pub type PlatformAudioBackend = NativeAudioBackend<wasapi::WaveOutOutput>;

#[cfg(all(target_os = "linux", feature = "pulseaudio"))]
pub type PlatformAudioBackend = NativeAudioBackend<pulseaudio::PulseAudioOutput>;

#[cfg(all(target_os = "macos", feature = "coreaudio"))]
pub type PlatformAudioBackend = NativeAudioBackend<coreaudio::CoreAudioOutput>;
