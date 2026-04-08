//! Windows waveIn audio capture backend.

use std::ptr;

use windows_sys::Win32::Media::Audio::{
    waveInAddBuffer, waveInClose, waveInOpen, waveInPrepareHeader, waveInReset, waveInStart,
    waveInStop, waveInUnprepareHeader, CALLBACK_NULL, HWAVEIN, WAVEHDR, WAVEFORMATEX,
    WAVE_FORMAT_PCM, WAVE_MAPPER, WHDR_DONE,
};
use windows_sys::Win32::Media::MMSYSERR_NOERROR;

use crate::{AudioCaptureBackend, AudioCaptureConfig, AudioCaptureError};

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
        if config.bits_per_sample == 0 || config.bits_per_sample % 8 != 0 {
            return Err(AudioCaptureError::FormatNotSupported);
        }

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

        let header_size = std::mem::size_of::<WAVEHDR>() as u32;

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
                waveInUnprepareHeader(self.handle, &mut header, header_size);
                return Err(AudioCaptureError::ReadError(format!(
                    "waveInAddBuffer failed: {res}"
                )));
            }

            // Start recording on first read (buffer is already submitted).
            if !self.started {
                let res = waveInStart(self.handle);
                if res != MMSYSERR_NOERROR {
                    waveInUnprepareHeader(self.handle, &mut header, header_size);
                    return Err(AudioCaptureError::DeviceError(format!(
                        "waveInStart failed: {res}"
                    )));
                }
                self.started = true;
            }

            // Poll for WHDR_DONE with 5-second timeout.
            // Use addr_of! + read_unaligned for safe field access via raw pointer.
            let flags_ptr = ptr::addr_of!(header.dwFlags);
            let mut timed_out = false;
            let mut iters = 0u32;
            while ptr::read_unaligned(flags_ptr) & WHDR_DONE == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
                iters += 1;
                if iters >= 5_000 {
                    // SAFETY: waveInReset marks all pending buffers as done (MSDN).
                    waveInReset(self.handle);
                    timed_out = true;
                    break;
                }
            }

            let recorded_ptr = ptr::addr_of!(header.dwBytesRecorded);
            let bytes_recorded = ptr::read_unaligned(recorded_ptr) as usize;

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
