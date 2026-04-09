//! Windows waveIn audio capture backend.

use std::ptr;
use std::sync::atomic::{self, Ordering};

use windows_sys::Win32::Media::Audio::{
    waveInAddBuffer, waveInClose, waveInOpen, waveInPrepareHeader, waveInReset, waveInStart,
    waveInStop, waveInUnprepareHeader, CALLBACK_NULL, HWAVEIN, WAVEHDR, WAVEFORMATEX,
    WAVE_FORMAT_PCM, WAVE_MAPPER, WHDR_DONE,
};
use windows_sys::Win32::Media::MMSYSERR_NOERROR;

use crate::{AudioCaptureBackend, AudioCaptureConfig, AudioCaptureError};

/// Polling interval for waiting on WHDR_DONE.
const WAVEIN_POLL_INTERVAL_MS: u64 = 1;
/// Maximum iterations before timeout (5 seconds = 5000 × 1 ms).
const WAVEIN_TIMEOUT_ITERS: u32 = 5_000;

/// Windows waveIn audio capture backend.
///
/// Wraps the Win32 waveIn API to capture PCM audio from the default
/// recording device. `waveInStart` is deferred to the first `read()` call
/// so that buffers are submitted before recording begins (MSDN requirement).
pub struct WaveInCapture {
    handle: HWAVEIN,
    started: bool,
}

impl AudioCaptureBackend for WaveInCapture {
    fn open(config: &AudioCaptureConfig) -> Result<Self, AudioCaptureError> {
        config.validate()?;

        if config.bits_per_sample != 16 {
            return Err(AudioCaptureError::FormatNotSupported);
        }

        // bits_per_sample is guaranteed byte-aligned and non-zero by validate().
        let block_align = config
            .channels
            .checked_mul(config.bits_per_sample / 8)
            .ok_or(AudioCaptureError::FormatNotSupported)?;

        let avg_bytes = (config.sample_rate as u64)
            .checked_mul(block_align as u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(AudioCaptureError::FormatNotSupported)?;

        let format = WAVEFORMATEX {
            wFormatTag: WAVE_FORMAT_PCM as u16,
            nChannels: config.channels,
            nSamplesPerSec: config.sample_rate,
            nAvgBytesPerSec: avg_bytes,
            nBlockAlign: block_align,
            wBitsPerSample: config.bits_per_sample,
            cbSize: 0,
        };

        let mut handle: HWAVEIN = ptr::null_mut();

        // SAFETY: valid out-pointer and properly initialised WAVEFORMATEX.
        let result = unsafe {
            waveInOpen(&mut handle, WAVE_MAPPER, &format, 0, 0, CALLBACK_NULL)
        };

        if result != MMSYSERR_NOERROR {
            return Err(AudioCaptureError::DeviceError(format!(
                "waveInOpen failed: {result}"
            )));
        }

        Ok(Self {
            handle,
            started: false,
        })
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, AudioCaptureError> {
        let buf_len = u32::try_from(buf.len())
            .map_err(|_| AudioCaptureError::ReadError("buffer too large".into()))?;

        let header_size = u32::try_from(std::mem::size_of::<WAVEHDR>())
            .map_err(|_| AudioCaptureError::ReadError("WAVEHDR size overflow".into()))?;

        let mut header = WAVEHDR {
            lpData: buf.as_mut_ptr(),
            dwBufferLength: buf_len,
            dwBytesRecorded: 0,
            dwUser: 0,
            dwFlags: 0,
            dwLoops: 0,
            lpNext: ptr::null_mut(),
            reserved: 0,
        };

        unsafe {
            // SAFETY: handle is valid, header points to valid buffer.
            let res = waveInPrepareHeader(self.handle, &mut header, header_size);
            if res != MMSYSERR_NOERROR {
                return Err(AudioCaptureError::ReadError(format!(
                    "waveInPrepareHeader failed: {res}"
                )));
            }

            // SAFETY: header was successfully prepared.
            let res = waveInAddBuffer(self.handle, &mut header, header_size);
            if res != MMSYSERR_NOERROR {
                // If recording was active, stop the device to avoid silent data
                // loss from a running device with no buffers queued.
                if self.started {
                    waveInStop(self.handle);
                    self.started = false;
                }
                waveInUnprepareHeader(self.handle, &mut header, header_size);
                return Err(AudioCaptureError::ReadError(format!(
                    "waveInAddBuffer failed: {res}"
                )));
            }

            // Start recording on first read (buffer is already submitted).
            if !self.started {
                let res = waveInStart(self.handle);
                if res != MMSYSERR_NOERROR {
                    // SAFETY: waveInReset returns all pending buffers to the app
                    // (marks them WHDR_DONE) so we can safely unprepare.
                    waveInReset(self.handle);
                    waveInUnprepareHeader(self.handle, &mut header, header_size);
                    return Err(AudioCaptureError::DeviceError(format!(
                        "waveInStart failed: {res}"
                    )));
                }
                self.started = true;
            }

            // Poll for WHDR_DONE with 5-second timeout.
            // SAFETY: The waveIn driver writes `dwFlags` from outside the Rust
            // memory model. We use `addr_of!` + `read_volatile` to avoid
            // forming a `&` reference to a field under concurrent OS mutation
            // (Stacked Borrows aliasing rules). `read_volatile` forces a
            // re-read each iteration — without it, the compiler may hoist the
            // load out of the loop in release builds. The acquire fence
            // provides additional ordering for dependent data (dwBytesRecorded).
            let flags_ptr = ptr::addr_of!(header.dwFlags);
            let mut timed_out = false;
            let mut iters = 0u32;
            loop {
                atomic::fence(Ordering::Acquire);
                if ptr::read_volatile(flags_ptr) & WHDR_DONE != 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(WAVEIN_POLL_INTERVAL_MS));
                iters += 1;
                if iters >= WAVEIN_TIMEOUT_ITERS {
                    // SAFETY: waveInReset marks all pending buffers as done (MSDN).
                    // After reset, recording is stopped; waveInStart must be
                    // called again before the next buffer can be filled.
                    waveInReset(self.handle);
                    self.started = false;
                    timed_out = true;
                    break;
                }
            }

            let recorded_ptr = ptr::addr_of!(header.dwBytesRecorded);
            let bytes_recorded = (ptr::read_volatile(recorded_ptr) as usize).min(buf.len());

            // SAFETY: unprepare the header to release driver resources.
            waveInUnprepareHeader(self.handle, &mut header, header_size);

            if timed_out {
                return Err(AudioCaptureError::ReadError(
                    "waveIn capture timed out after 5 seconds".into(),
                ));
            }

            Ok(bytes_recorded)
        }
    }

    fn close(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: handle is valid. Stop, reset (returns pending buffers), close.
            unsafe {
                waveInStop(self.handle);
                waveInReset(self.handle);
                waveInClose(self.handle);
            }
            self.handle = ptr::null_mut();
            self.started = false;
        }
    }
}

impl Drop for WaveInCapture {
    fn drop(&mut self) {
        self.close();
    }
}

// SAFETY: HWAVEIN is a raw handle. waveIn API is safe from any thread
// with exclusive access, enforced by &mut self on all methods.
unsafe impl Send for WaveInCapture {}

#[cfg(test)]
mod tests {
    use crate::{AudioCaptureBackend, AudioCaptureConfig};
    use super::*;

    #[test]
    fn open_rejects_non_16bit() {
        let config = AudioCaptureConfig {
            sample_rate: 44100,
            channels: 2,
            bits_per_sample: 8,
            frames_per_packet: 1024,
        };
        let result = WaveInCapture::open(&config);
        assert!(result.is_err());
    }

    #[test]
    fn open_rejects_32bit() {
        let config = AudioCaptureConfig {
            sample_rate: 44100,
            channels: 1,
            bits_per_sample: 32,
            frames_per_packet: 512,
        };
        let result = WaveInCapture::open(&config);
        assert!(result.is_err());
    }

    #[test]
    fn open_rejects_zero_channels() {
        let config = AudioCaptureConfig {
            sample_rate: 44100,
            channels: 0,
            bits_per_sample: 16,
            frames_per_packet: 1024,
        };
        let result = WaveInCapture::open(&config);
        assert!(result.is_err());
    }

    #[test]
    fn open_and_close_succeeds() {
        let config = AudioCaptureConfig {
            sample_rate: 44100,
            channels: 2,
            bits_per_sample: 16,
            frames_per_packet: 1024,
        };
        match WaveInCapture::open(&config) {
            Ok(mut capture) => {
                capture.close();
                // Double close should be safe (no-op).
                capture.close();
            }
            Err(_) => {
                // CI environments may not have an audio input device — skip.
            }
        }
    }
}
