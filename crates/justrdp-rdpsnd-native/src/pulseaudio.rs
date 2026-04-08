//! PulseAudio audio output backend for Linux.

use libpulse_binding::sample::{Format, Spec};
use libpulse_binding::stream::Direction;
use libpulse_simple_binding::Simple;

use crate::error::{NativeAudioError, NativeAudioResult};
use crate::output::NativeAudioOutput;

/// PulseAudio output using the Simple (blocking) API.
pub struct PulseAudioOutput {
    simple: Simple,
}

impl NativeAudioOutput for PulseAudioOutput {
    fn open(sample_rate: u32, channels: u16, bits_per_sample: u16) -> NativeAudioResult<Self> {
        if bits_per_sample != 16 {
            return Err(NativeAudioError::FormatNotSupported);
        }

        let spec = Spec {
            format: Format::S16le,
            channels: channels as u8,
            rate: sample_rate,
        };

        if !spec.is_valid() {
            return Err(NativeAudioError::FormatNotSupported);
        }

        let simple = Simple::new(
            None,                  // default server
            "justrdp",             // application name
            Direction::Playback,
            None,                  // default device
            "RDP Audio Output",    // stream description
            &spec,
            None,                  // default channel map
            None,                  // default buffering
        )
        .map_err(|e| NativeAudioError::DeviceError(e.to_string().unwrap_or_default()))?;

        Ok(Self { simple })
    }

    fn write_samples(&mut self, samples: &[i16]) -> NativeAudioResult<()> {
        // SAFETY: Reinterprets `&[i16]` as `&[u8]` with exactly `samples.len() * 2` bytes.
        // The pointer is valid for the entire slice, and `i16` has no invalid bit patterns.
        // PulseAudio expects raw PCM bytes in the format specified at open time (S16LE).
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(samples.as_ptr() as *const u8, samples.len() * 2)
        };

        self.simple
            .write(bytes)
            .map_err(|e| NativeAudioError::WriteError(e.to_string().unwrap_or_default()))?;

        Ok(())
    }

    fn set_volume(&mut self, _left: u16, _right: u16) {
        // PulseAudio Simple API doesn't support per-stream volume control.
        // Volume is managed at the system level via pavucontrol/pactl.
    }

    fn close(&mut self) {
        let _ = self.simple.drain();
    }
}
