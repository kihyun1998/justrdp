//! Windows waveOut audio output backend.
//!
//! Uses the Win32 `waveOut*` API family from `winmm.dll` for PCM audio playback.
//! This is simpler than full WASAPI COM and works well for RDP audio output.

use std::ptr;

use windows_sys::Win32::Media::Audio::{
    waveOutClose, waveOutOpen, waveOutPrepareHeader, waveOutReset, waveOutSetVolume,
    waveOutUnprepareHeader, waveOutWrite, CALLBACK_NULL, HWAVEOUT, WAVEHDR, WAVEFORMATEX,
    WAVE_FORMAT_PCM, WAVE_MAPPER, WHDR_DONE,
};
use windows_sys::Win32::Media::MMSYSERR_NOERROR;

use crate::error::{NativeAudioError, NativeAudioResult};
use crate::output::NativeAudioOutput;

/// Windows waveOut audio output device.
pub struct WasapiOutput {
    handle: HWAVEOUT,
    _sample_rate: u32,
    _channels: u16,
}

// SAFETY: HWAVEOUT is a raw handle to a waveOut device. The Win32 waveOut API
// is thread-safe for the operations we use (write, set volume, close), and we
// ensure exclusive access through `&mut self` on all methods.
unsafe impl Send for WasapiOutput {}

impl NativeAudioOutput for WasapiOutput {
    fn open(sample_rate: u32, channels: u16, bits_per_sample: u16) -> NativeAudioResult<Self> {
        let block_align = channels
            .checked_mul(bits_per_sample / 8)
            .ok_or(NativeAudioError::FormatNotSupported)?;
        let avg_bytes_per_sec = (sample_rate as u64)
            .checked_mul(block_align as u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(NativeAudioError::FormatNotSupported)?;

        let format = WAVEFORMATEX {
            wFormatTag: WAVE_FORMAT_PCM as u16,
            nChannels: channels,
            nSamplesPerSec: sample_rate,
            nAvgBytesPerSec: avg_bytes_per_sec,
            nBlockAlign: block_align,
            wBitsPerSample: bits_per_sample,
            cbSize: 0,
        };

        let mut handle: HWAVEOUT = ptr::null_mut();

        // SAFETY: Calling Win32 API with valid format struct and handle pointer.
        // WAVE_MAPPER selects the default audio output device.
        let result = unsafe {
            waveOutOpen(
                &mut handle,
                WAVE_MAPPER,
                &format,
                0,
                0,
                CALLBACK_NULL,
            )
        };

        if result != MMSYSERR_NOERROR {
            return Err(NativeAudioError::DeviceError(format!(
                "waveOutOpen failed with error code {result}"
            )));
        }

        Ok(Self {
            handle,
            _sample_rate: sample_rate,
            _channels: channels,
        })
    }

    fn write_samples(&mut self, samples: &[i16]) -> NativeAudioResult<()> {
        if samples.is_empty() {
            return Ok(());
        }

        // Convert i16 samples to little-endian bytes.
        let bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();

        let mut header = WAVEHDR {
            lpData: bytes.as_ptr() as *mut u8,
            dwBufferLength: bytes.len() as u32,
            dwBytesRecorded: 0,
            dwUser: 0,
            dwFlags: 0,
            dwLoops: 0,
            lpNext: ptr::null_mut(),
            reserved: 0,
        };

        let header_size = std::mem::size_of::<WAVEHDR>() as u32;

        // SAFETY: header points to valid data that outlives the playback; we busy-wait
        // for completion before returning, ensuring the buffer is not freed prematurely.
        unsafe {
            let res = waveOutPrepareHeader(self.handle, &mut header, header_size);
            if res != MMSYSERR_NOERROR {
                return Err(NativeAudioError::WriteError(format!(
                    "waveOutPrepareHeader failed with error code {res}"
                )));
            }

            let res = waveOutWrite(self.handle, &mut header, header_size);
            if res != MMSYSERR_NOERROR {
                // SAFETY: header was prepared, so we must unprepare it before returning.
                waveOutUnprepareHeader(self.handle, &mut header, header_size);
                return Err(NativeAudioError::WriteError(format!(
                    "waveOutWrite failed with error code {res}"
                )));
            }

            // Wait for the buffer to finish playing (WHDR_DONE flag is set by the driver).
            // Use raw pointer + read_unaligned since WAVEHDR is packed.
            // Timeout after MAX_WRITE_WAIT_ITERS iterations to prevent infinite hang.
            let flags_ptr = ptr::addr_of!(header.dwFlags);
            let mut wait_iters = 0u32;
            while ptr::read_unaligned(flags_ptr) & WHDR_DONE == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
                wait_iters += 1;
                if wait_iters >= crate::backend::MAX_WRITE_WAIT_ITERS {
                    waveOutReset(self.handle);
                    break;
                }
            }

            // SAFETY: playback is complete (WHDR_DONE set), safe to unprepare.
            waveOutUnprepareHeader(self.handle, &mut header, header_size);
        }

        Ok(())
    }

    fn set_volume(&mut self, left: u16, right: u16) {
        // waveOutSetVolume packs left channel in the low word and right channel
        // in the high word of a DWORD.
        let volume = (left as u32) | ((right as u32) << 16);

        // SAFETY: handle is valid; waveOutSetVolume is safe to call at any time.
        unsafe {
            waveOutSetVolume(self.handle, volume);
        }
    }

    fn close(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: handle is valid. waveOutReset stops all pending playback,
            // then waveOutClose releases the device.
            unsafe {
                waveOutReset(self.handle);
                waveOutClose(self.handle);
            }
            self.handle = ptr::null_mut();
        }
    }
}

impl Drop for WasapiOutput {
    fn drop(&mut self) {
        self.close();
    }
}
