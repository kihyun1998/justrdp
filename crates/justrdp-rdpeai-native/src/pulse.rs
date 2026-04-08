//! Linux PulseAudio audio capture backend.

use libpulse_binding::sample::{Format, Spec};
use libpulse_binding::stream::Direction;
use libpulse_simple_binding::Simple;

use crate::{AudioCaptureBackend, AudioCaptureConfig, AudioCaptureError};

/// PulseAudio capture using the Simple (blocking) API.
///
/// Works transparently with PipeWire via its PulseAudio compatibility layer.
pub struct PulseAudioCapture {
    simple: Option<Simple>,
}

// SAFETY: PulseAudio Simple API wraps a C `pa_simple*` pointer. The Simple
// API is safe to use from any thread with exclusive access, which is enforced
// by the `&mut self` requirement on all methods.
unsafe impl Send for PulseAudioCapture {}

impl AudioCaptureBackend for PulseAudioCapture {
    fn open(config: &AudioCaptureConfig) -> Result<Self, AudioCaptureError> {
        if config.bits_per_sample != 16 {
            return Err(AudioCaptureError::FormatNotSupported);
        }

        let channels = u8::try_from(config.channels)
            .map_err(|_| AudioCaptureError::FormatNotSupported)?;

        let spec = Spec {
            format: Format::S16le,
            channels,
            rate: config.sample_rate,
        };

        if !spec.is_valid() {
            return Err(AudioCaptureError::FormatNotSupported);
        }

        let simple = Simple::new(
            None,                // default server
            "justrdp",           // app name
            Direction::Record,   // capture
            None,                // default device
            "RDP Audio Input",   // stream description
            &spec,
            None,                // default channel map
            None,                // default buffering
        )
        .map_err(|e| AudioCaptureError::DeviceError(e.to_string().unwrap_or_default()))?;

        Ok(Self {
            simple: Some(simple),
        })
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, AudioCaptureError> {
        let simple = self
            .simple
            .as_mut()
            .ok_or(AudioCaptureError::ReadError("device closed".into()))?;

        simple
            .read(buf)
            .map_err(|e| AudioCaptureError::ReadError(e.to_string().unwrap_or_default()))?;

        Ok(buf.len())
    }

    fn close(&mut self) {
        // Drop the Simple handle to release the PulseAudio connection.
        // Simple implements Drop which calls pa_simple_free().
        self.simple.take();
    }
}
