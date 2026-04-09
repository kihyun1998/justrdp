//! Windows waveOut audio output backend.
//!
//! Uses the Win32 `waveOut*` API family from `winmm.dll` for PCM audio playback.
//! This is simpler than full WASAPI COM and works well for RDP audio output.

#![deny(unsafe_op_in_unsafe_fn)]

use std::mem::ManuallyDrop;
use std::ptr;

use windows_sys::Win32::Media::Audio::{
    waveOutClose, waveOutOpen, waveOutPrepareHeader, waveOutReset, waveOutSetVolume,
    waveOutUnprepareHeader, waveOutWrite, CALLBACK_NULL, HWAVEOUT, WAVEHDR, WAVEFORMATEX,
    WAVE_FORMAT_PCM, WAVE_MAPPER, WHDR_DONE,
};
use windows_sys::Win32::Media::MMSYSERR_NOERROR;

use crate::error::{NativeAudioError, NativeAudioResult};
use crate::output::NativeAudioOutput;

/// Maximum iterations for waveOut busy-wait (5 seconds at 1ms sleep).
const MAX_WRITE_WAIT_ITERS: u32 = 5_000;

/// Windows waveOut audio output device.
pub struct WaveOutOutput {
    handle: HWAVEOUT,
}

// SAFETY: HWAVEOUT is a raw handle to a waveOut device. The Win32 waveOut API
// is thread-safe for the operations we use (write, set volume, close), and we
// ensure exclusive access through `&mut self` on all methods.
// NOTE: `Sync` is intentionally NOT implemented — concurrent calls via `&self`
// are not safe because waveOut operations are not re-entrant.
unsafe impl Send for WaveOutOutput {}

impl NativeAudioOutput for WaveOutOutput {
    fn open(sample_rate: u32, channels: u16, bits_per_sample: u16) -> NativeAudioResult<Self> {
        if sample_rate == 0 || channels == 0 || bits_per_sample == 0 || bits_per_sample % 8 != 0 {
            return Err(NativeAudioError::FormatNotSupported);
        }

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

        Ok(Self { handle })
    }

    fn write_samples(&mut self, samples: &[i16]) -> NativeAudioResult<()> {
        if samples.is_empty() {
            return Ok(());
        }

        // Convert i16 samples to little-endian bytes.
        let raw_bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();

        let buffer_len = u32::try_from(raw_bytes.len()).map_err(|_| {
            NativeAudioError::WriteError("audio buffer too large for waveOut".into())
        })?;

        // Use ManuallyDrop to prevent the Vec from being dropped while waveOut
        // is still reading from it during asynchronous playback.
        let bytes = ManuallyDrop::new(raw_bytes);

        let mut header = WAVEHDR {
            lpData: bytes.as_ptr() as *mut u8,
            dwBufferLength: buffer_len,
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
        // ManuallyDrop ensures `bytes` is not dropped even if we panic during playback.
        unsafe {
            let res = waveOutPrepareHeader(self.handle, &mut header, header_size);
            if res != MMSYSERR_NOERROR {
                ManuallyDrop::into_inner(bytes);
                return Err(NativeAudioError::WriteError(format!(
                    "waveOutPrepareHeader failed with error code {res}"
                )));
            }

            let res = waveOutWrite(self.handle, &mut header, header_size);
            if res != MMSYSERR_NOERROR {
                // SAFETY: header was prepared, so we must unprepare it before returning.
                waveOutUnprepareHeader(self.handle, &mut header, header_size);
                ManuallyDrop::into_inner(bytes);
                return Err(NativeAudioError::WriteError(format!(
                    "waveOutWrite failed with error code {res}"
                )));
            }

            // Wait for the buffer to finish playing (WHDR_DONE flag is set by the driver).
            // Timeout after MAX_WRITE_WAIT_ITERS iterations to prevent infinite hang.
            let flags_ptr = ptr::addr_of!(header.dwFlags);
            let mut timed_out = false;
            let mut wait_iters = 0u32;
            while ptr::read(flags_ptr) & WHDR_DONE == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
                wait_iters += 1;
                if wait_iters >= MAX_WRITE_WAIT_ITERS {
                    waveOutReset(self.handle);
                    timed_out = true;
                    break;
                }
            }

            // SAFETY: playback is complete (WHDR_DONE set or reset called),
            // safe to unprepare and free.
            waveOutUnprepareHeader(self.handle, &mut header, header_size);
            ManuallyDrop::into_inner(bytes);

            if timed_out {
                return Err(NativeAudioError::WriteError(
                    "waveOut timeout: buffer did not complete within 5 seconds".into(),
                ));
            }
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

impl Drop for WaveOutOutput {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify WAVEFORMATEX field computation for standard formats.
    #[test]
    fn waveformatex_field_computation() {
        // 44100 Hz, stereo, 16-bit
        let block_align = 2u16.checked_mul(16 / 8).unwrap();
        assert_eq!(block_align, 4); // 2 channels * 2 bytes
        let avg = (44100u64).checked_mul(block_align as u64).unwrap();
        assert_eq!(avg, 176400); // 44100 * 4

        // 8000 Hz, mono, 16-bit
        let block_align = 1u16.checked_mul(16 / 8).unwrap();
        assert_eq!(block_align, 2); // 1 channel * 2 bytes
        let avg = (8000u64).checked_mul(block_align as u64).unwrap();
        assert_eq!(avg, 16000); // 8000 * 2

        // 48000 Hz, stereo, 16-bit
        let block_align = 2u16.checked_mul(16 / 8).unwrap();
        assert_eq!(block_align, 4);
        let avg = (48000u64).checked_mul(block_align as u64).unwrap();
        assert_eq!(avg, 192000);
    }

    /// Verify that invalid format parameters are rejected.
    #[test]
    fn open_rejects_invalid_formats() {
        // Zero sample rate
        assert!(WaveOutOutput::open(0, 2, 16).is_err());
        // Zero channels
        assert!(WaveOutOutput::open(44100, 0, 16).is_err());
        // Zero bits per sample
        assert!(WaveOutOutput::open(44100, 2, 0).is_err());
        // Non-byte-aligned bits per sample
        assert!(WaveOutOutput::open(44100, 2, 12).is_err());
    }

    /// Verify volume packing: left in low word, right in high word.
    #[test]
    fn volume_packing() {
        let left: u16 = 0x1234;
        let right: u16 = 0x5678;
        let packed = (left as u32) | ((right as u32) << 16);
        assert_eq!(packed & 0xFFFF, 0x1234);
        assert_eq!(packed >> 16, 0x5678);

        // Boundary: max volume both channels
        let packed = (0xFFFFu32) | (0xFFFFu32 << 16);
        assert_eq!(packed, 0xFFFF_FFFF);

        // Boundary: mute
        let packed = 0u32 | (0u32 << 16);
        assert_eq!(packed, 0);
    }
}
