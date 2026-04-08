//! CoreAudio audio output backend for macOS.

use std::ptr;

use coreaudio_sys::{
    AudioQueueAllocateBuffer, AudioQueueBufferRef, AudioQueueDispose, AudioQueueEnqueueBuffer,
    AudioQueueNewOutput, AudioQueueRef, AudioQueueSetParameter, AudioQueueStart, AudioQueueStop,
    AudioStreamBasicDescription, AudioQueueFreeBuffer,
};

use crate::error::{NativeAudioError, NativeAudioResult};
use crate::output::NativeAudioOutput;

// Audio format constants from CoreAudio headers.
// `kAudioFormatLinearPCM` = 'lpcm' = 0x6C70636D
const K_AUDIO_FORMAT_LINEAR_PCM: u32 = 0x6C70_636D;

// Linear PCM format flags.
const K_LINEAR_PCM_FORMAT_FLAG_IS_SIGNED_INTEGER: u32 = 1 << 2; // kAudioFormatFlagIsSignedInteger
const K_LINEAR_PCM_FORMAT_FLAG_IS_PACKED: u32 = 1 << 3; // kAudioFormatFlagIsPacked

// AudioQueue parameter IDs.
const K_AUDIO_QUEUE_PARAM_VOLUME: u32 = 1; // kAudioQueueParam_Volume

/// CoreAudio output using the AudioQueue (blocking enqueue) API.
pub struct CoreAudioOutput {
    queue: AudioQueueRef,
    sample_rate: u32,
    channels: u16,
}

// SAFETY: `AudioQueueRef` is a pointer to an OS-managed opaque type.
// CoreAudio audio queues can be used from any thread once created;
// the AudioQueue API is documented as thread-safe for enqueue operations.
unsafe impl Send for CoreAudioOutput {}

impl NativeAudioOutput for CoreAudioOutput {
    fn open(sample_rate: u32, channels: u16, bits_per_sample: u16) -> NativeAudioResult<Self> {
        if bits_per_sample != 16 {
            return Err(NativeAudioError::FormatNotSupported);
        }

        let bytes_per_frame = (channels as u32) * (bits_per_sample as u32 / 8);

        let format = AudioStreamBasicDescription {
            mSampleRate: sample_rate as f64,
            mFormatID: K_AUDIO_FORMAT_LINEAR_PCM,
            mFormatFlags: K_LINEAR_PCM_FORMAT_FLAG_IS_SIGNED_INTEGER
                | K_LINEAR_PCM_FORMAT_FLAG_IS_PACKED,
            mBytesPerPacket: bytes_per_frame,
            mFramesPerPacket: 1,
            mBytesPerFrame: bytes_per_frame,
            mChannelsPerFrame: channels as u32,
            mBitsPerChannel: bits_per_sample as u32,
            mReserved: 0,
        };

        let mut queue: AudioQueueRef = ptr::null_mut();

        // SAFETY: `AudioQueueNewOutput` is called with a valid format description
        // and a valid output pointer. We pass no callback (synchronous enqueue mode),
        // NULL run loop (uses internal thread), and no flags.
        let status = unsafe {
            AudioQueueNewOutput(
                &format,
                None,             // no callback — we use synchronous enqueue
                ptr::null_mut(),  // callback user data
                ptr::null_mut(),  // run loop (NULL = internal)
                ptr::null(),      // run loop mode
                0,                // flags (reserved, must be 0)
                &mut queue,
            )
        };

        if status != 0 {
            return Err(NativeAudioError::DeviceError(format!(
                "AudioQueueNewOutput failed with status {status}"
            )));
        }

        // SAFETY: `queue` is valid after successful `AudioQueueNewOutput`.
        // Passing NULL for the start time means "start immediately".
        let status = unsafe { AudioQueueStart(queue, ptr::null()) };

        if status != 0 {
            // SAFETY: Disposing a valid queue. `1` = immediate (don't drain).
            unsafe {
                AudioQueueDispose(queue, 1);
            }
            return Err(NativeAudioError::DeviceError(format!(
                "AudioQueueStart failed with status {status}"
            )));
        }

        Ok(Self {
            queue,
            sample_rate,
            channels,
        })
    }

    fn write_samples(&mut self, samples: &[i16]) -> NativeAudioResult<()> {
        if samples.is_empty() {
            return Ok(());
        }

        let byte_size = samples.len() * 2;

        let mut buffer: AudioQueueBufferRef = ptr::null_mut();

        // SAFETY: Allocating a buffer from a valid audio queue.
        // `byte_size` is the capacity in bytes.
        let status = unsafe {
            AudioQueueAllocateBuffer(self.queue, byte_size as u32, &mut buffer)
        };

        if status != 0 {
            return Err(NativeAudioError::WriteError(format!(
                "AudioQueueAllocateBuffer failed with status {status}"
            )));
        }

        // SAFETY: `buffer` is valid after successful allocation and has at least
        // `byte_size` bytes of capacity. We copy the i16 PCM data as raw bytes.
        unsafe {
            let buf_data = (*buffer).mAudioData as *mut u8;
            ptr::copy_nonoverlapping(samples.as_ptr() as *const u8, buf_data, byte_size);
            (*buffer).mAudioDataByteSize = byte_size as u32;
        }

        // SAFETY: Enqueuing a properly filled buffer into a valid queue.
        // The buffer will be freed by the queue after playback.
        let status = unsafe {
            AudioQueueEnqueueBuffer(self.queue, buffer, 0, ptr::null())
        };

        if status != 0 {
            // SAFETY: Freeing the buffer we allocated since enqueue failed.
            unsafe {
                AudioQueueFreeBuffer(self.queue, buffer);
            }
            return Err(NativeAudioError::WriteError(format!(
                "AudioQueueEnqueueBuffer failed with status {status}"
            )));
        }

        Ok(())
    }

    fn set_volume(&mut self, left: u16, right: u16) {
        // AudioQueue only supports a single scalar volume, so we average left and right.
        // Both channels are in the range 0..=0xFFFF; map to 0.0..=1.0.
        let avg = ((left as f32) + (right as f32)) / (2.0 * 65535.0);

        // SAFETY: `self.queue` is valid. `AudioQueueSetParameter` sets the
        // volume parameter (range 0.0 to 1.0).
        unsafe {
            AudioQueueSetParameter(self.queue, K_AUDIO_QUEUE_PARAM_VOLUME, avg);
        }
    }

    fn close(&mut self) {
        if !self.queue.is_null() {
            // SAFETY: Stopping and disposing a valid audio queue.
            // `AudioQueueStop` with `0` (false) means asynchronous stop — it
            // drains any remaining buffers before stopping.
            // `AudioQueueDispose` with `0` (false) also drains before disposing.
            unsafe {
                AudioQueueStop(self.queue, 0);
                AudioQueueDispose(self.queue, 0);
            }
            self.queue = ptr::null_mut();
        }
    }
}

impl Drop for CoreAudioOutput {
    fn drop(&mut self) {
        self.close();
    }
}
