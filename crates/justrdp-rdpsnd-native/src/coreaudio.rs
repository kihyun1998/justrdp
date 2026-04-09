//! CoreAudio audio output backend for macOS.

#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::VecDeque;
use std::ptr;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use coreaudio_sys::{
    AudioQueueAllocateBuffer, AudioQueueBufferRef, AudioQueueDispose, AudioQueueEnqueueBuffer,
    AudioQueueNewOutput, AudioQueueRef, AudioQueueSetParameter, AudioQueueStart, AudioQueueStop,
    AudioStreamBasicDescription,
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

/// Number of pre-allocated AudioQueue buffers in the pool.
///
/// A small pool (3 buffers) allows double-buffering with one spare.
/// Buffers are returned to the pool by the output callback after playback.
const NUM_BUFFERS: usize = 3;

/// Buffer size in bytes for each pre-allocated AudioQueue buffer.
/// 16384 bytes ≈ 4096 stereo 16-bit samples ≈ ~93ms at 44.1 kHz.
const BUFFER_SIZE: u32 = 16384;

/// Timeout for waiting on a buffer from the pool.
/// If CoreAudio stops returning buffers (device disconnect, audio route change),
/// we return an error instead of blocking indefinitely.
const BUFFER_WAIT_TIMEOUT: Duration = Duration::from_secs(2);

/// Shared buffer pool between the AudioQueue callback and `write_samples()`.
struct BufferPool {
    available: Mutex<VecDeque<AudioQueueBufferRef>>,
    condvar: Condvar,
}

/// AudioQueue output callback invoked by CoreAudio after a buffer finishes playback.
///
/// Returns the buffer to the shared pool so `write_samples()` can reuse it.
///
/// # Safety
///
/// This function is called by CoreAudio with valid queue and buffer pointers.
/// `user_data` must point to a valid `BufferPool` that outlives the audio queue.
unsafe extern "C" fn output_callback(
    user_data: *mut std::ffi::c_void,
    _queue: AudioQueueRef,
    buffer: AudioQueueBufferRef,
) {
    // SAFETY: `user_data` is a `&BufferPool` pointer created in `open()` and
    // remains valid for the lifetime of the audio queue.
    let pool = unsafe { &*(user_data as *const BufferPool) };

    if let Ok(mut available) = pool.available.lock() {
        available.push_back(buffer);
        pool.condvar.notify_one();
    }
    // If lock fails (poisoned), silently drop — the buffer stays in the queue's
    // ownership and will be freed by `AudioQueueDispose`.
}

/// CoreAudio output using the AudioQueue API with a pre-allocated buffer pool.
///
/// Buffers are allocated once in `open()` and cycled through the pool:
/// `write_samples()` takes a buffer → fills it → enqueues it → callback returns it.
/// `AudioQueueDispose` frees all buffers when the queue is torn down.
pub struct CoreAudioOutput {
    queue: AudioQueueRef,
    /// Buffer pool shared with the output callback. Boxed for stable address.
    pool: Box<BufferPool>,
}

// SAFETY: `AudioQueueRef` is a pointer to an OS-managed opaque type.
// CoreAudio audio queues can be used from any thread once created;
// the AudioQueue API is documented as thread-safe for enqueue operations.
// `pool` is behind a Mutex and Condvar, which are Send+Sync.
// NOTE: `Sync` is intentionally NOT implemented — concurrent calls via `&self`
// are not safe because AudioQueue operations on the same queue are not re-entrant.
unsafe impl Send for CoreAudioOutput {}

impl NativeAudioOutput for CoreAudioOutput {
    fn open(sample_rate: u32, channels: u16, bits_per_sample: u16) -> NativeAudioResult<Self> {
        if bits_per_sample != 16 || channels == 0 || sample_rate == 0 {
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

        let pool = Box::new(BufferPool {
            available: Mutex::new(VecDeque::with_capacity(NUM_BUFFERS)),
            condvar: Condvar::new(),
        });

        let pool_ptr: *const BufferPool = &*pool;
        let mut queue: AudioQueueRef = ptr::null_mut();

        // SAFETY: `AudioQueueNewOutput` is called with a valid format description,
        // a valid callback function, and a valid user-data pointer (`pool_ptr`).
        // The pool is Box-pinned so the pointer remains stable. We pass NULL
        // for the run loop (uses internal thread) and no flags.
        let status = unsafe {
            AudioQueueNewOutput(
                &format,
                Some(output_callback),
                pool_ptr as *mut std::ffi::c_void,
                ptr::null_mut(), // run loop (NULL = internal)
                ptr::null(),     // run loop mode
                0,               // flags (reserved, must be 0)
                &mut queue,
            )
        };

        if status != 0 {
            return Err(NativeAudioError::DeviceError(format!(
                "AudioQueueNewOutput failed with status {status}"
            )));
        }

        // Pre-allocate buffers and add them to the available pool.
        {
            let mut available = pool.available.lock().unwrap();
            for _ in 0..NUM_BUFFERS {
                let mut buffer: AudioQueueBufferRef = ptr::null_mut();

                // SAFETY: Allocating a buffer from a valid audio queue.
                let alloc_status = unsafe {
                    AudioQueueAllocateBuffer(queue, BUFFER_SIZE, &mut buffer)
                };

                if alloc_status != 0 {
                    // SAFETY: Disposing a valid queue. `1` = immediate (don't drain).
                    // AudioQueueDispose frees all allocated buffers.
                    unsafe {
                        AudioQueueDispose(queue, 1);
                    }
                    return Err(NativeAudioError::DeviceError(format!(
                        "AudioQueueAllocateBuffer failed with status {alloc_status}"
                    )));
                }

                available.push_back(buffer);
            }
        }

        // SAFETY: `queue` is valid after successful `AudioQueueNewOutput`.
        // Buffers are pre-allocated and available in the pool.
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

        Ok(Self { queue, pool })
    }

    fn write_samples(&mut self, samples: &[i16]) -> NativeAudioResult<()> {
        if samples.is_empty() {
            return Ok(());
        }

        let byte_size = samples.len().checked_mul(std::mem::size_of::<i16>()).ok_or_else(|| {
            NativeAudioError::WriteError("sample buffer size overflow".into())
        })?;

        let byte_size_u32 = u32::try_from(byte_size).map_err(|_| {
            NativeAudioError::WriteError(format!(
                "sample buffer too large for AudioQueue: {byte_size} bytes exceeds u32::MAX"
            ))
        })?;

        if byte_size_u32 > BUFFER_SIZE {
            // Split into chunks that fit in a single pool buffer.
            let chunk_samples = (BUFFER_SIZE as usize) / std::mem::size_of::<i16>();
            for chunk in samples.chunks(chunk_samples) {
                self.write_samples_single(chunk)?;
            }
            return Ok(());
        }

        self.write_samples_single(samples)
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
            // `AudioQueueStop` with `1` (true) means synchronous/immediate stop —
            // all pending callbacks complete before it returns, so we can safely
            // dispose the queue knowing no callback will fire afterward.
            // `AudioQueueDispose` with `1` (true) disposes immediately and frees
            // all allocated buffers.
            unsafe {
                AudioQueueStop(self.queue, 1);
                AudioQueueDispose(self.queue, 1);
            }
            self.queue = ptr::null_mut();
        }
    }
}

impl CoreAudioOutput {
    /// Write a single chunk of samples using a buffer from the pool.
    ///
    /// The chunk must fit within `BUFFER_SIZE` bytes.
    fn write_samples_single(&mut self, samples: &[i16]) -> NativeAudioResult<()> {
        let byte_size = samples.len().checked_mul(std::mem::size_of::<i16>()).ok_or_else(|| {
            NativeAudioError::WriteError("chunk size overflow".into())
        })?;
        debug_assert!(byte_size <= BUFFER_SIZE as usize, "chunk too large for buffer pool");

        // Wait for an available buffer from the pool, with timeout.
        let buffer = {
            let mut available = self
                .pool
                .available
                .lock()
                .map_err(|_| NativeAudioError::WriteError("buffer pool poisoned".into()))?;

            while available.is_empty() {
                let (guard, wait_result) = self
                    .pool
                    .condvar
                    .wait_timeout(available, BUFFER_WAIT_TIMEOUT)
                    .map_err(|_| NativeAudioError::WriteError("buffer pool poisoned".into()))?;

                available = guard;

                if wait_result.timed_out() && available.is_empty() {
                    return Err(NativeAudioError::WriteError(
                        "buffer pool timeout: audio device may be disconnected".into(),
                    ));
                }
            }

            available.pop_front().unwrap()
        };

        // SAFETY: `buffer` is a valid AudioQueueBuffer from our pool with at least
        // `BUFFER_SIZE` bytes of capacity. `byte_size <= BUFFER_SIZE` is guaranteed
        // by the caller (`write_samples` splits larger inputs into chunks).
        unsafe {
            debug_assert!(
                byte_size <= (*buffer).mAudioDataBytesCapacity as usize,
                "byte_size ({byte_size}) exceeds buffer capacity ({})",
                (*buffer).mAudioDataBytesCapacity
            );
            let buf_data = (*buffer).mAudioData as *mut u8;
            ptr::copy_nonoverlapping(samples.as_ptr() as *const u8, buf_data, byte_size);
            (*buffer).mAudioDataByteSize = u32::try_from(byte_size).expect("byte_size exceeds u32 — contract violated");
        }

        // SAFETY: Enqueuing a properly filled buffer into a valid queue.
        // After playback, the output callback returns this buffer to the pool.
        let status = unsafe {
            AudioQueueEnqueueBuffer(self.queue, buffer, 0, ptr::null())
        };

        if status != 0 {
            // Return the buffer to the pool since enqueue failed.
            if let Ok(mut available) = self.pool.available.lock() {
                available.push_back(buffer);
            }
            return Err(NativeAudioError::WriteError(format!(
                "AudioQueueEnqueueBuffer failed with status {status}"
            )));
        }

        Ok(())
    }
}

impl Drop for CoreAudioOutput {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify volume averaging formula: (left + right) / (2 * 65535) → 0.0..=1.0.
    #[test]
    fn volume_average_boundaries() {
        // Both mute → 0.0
        let avg = ((0u16 as f32) + (0u16 as f32)) / (2.0 * 65535.0);
        assert_eq!(avg, 0.0);

        // Both max → 1.0
        let avg = ((0xFFFFu16 as f32) + (0xFFFFu16 as f32)) / (2.0 * 65535.0);
        assert!((avg - 1.0).abs() < f32::EPSILON);

        // Left max, right mute → 0.5
        let avg = ((0xFFFFu16 as f32) + (0u16 as f32)) / (2.0 * 65535.0);
        assert!((avg - 0.5).abs() < 0.001);

        // Mid-point both channels → 0.5
        let avg = ((0x7FFFu16 as f32) + (0x8000u16 as f32)) / (2.0 * 65535.0);
        assert!((avg - 0.5).abs() < 0.001);
    }

    /// Verify open() rejects invalid formats.
    #[test]
    fn open_rejects_invalid_formats() {
        // Non-16-bit
        assert!(CoreAudioOutput::open(44100, 2, 8).is_err());
        // Zero channels
        assert!(CoreAudioOutput::open(44100, 0, 16).is_err());
        // Zero sample rate
        assert!(CoreAudioOutput::open(0, 2, 16).is_err());
    }

    /// Verify chunk splitting boundary: samples exactly at BUFFER_SIZE should not split.
    #[test]
    fn chunk_split_boundary() {
        let chunk_samples = (BUFFER_SIZE as usize) / std::mem::size_of::<i16>();
        // Exactly BUFFER_SIZE bytes → should NOT trigger splitting
        assert_eq!(chunk_samples * std::mem::size_of::<i16>(), BUFFER_SIZE as usize);

        // One more sample → should trigger splitting into 2 chunks
        let samples = chunk_samples + 1;
        let byte_size = samples * std::mem::size_of::<i16>();
        assert!(byte_size > BUFFER_SIZE as usize);

        // Verify chunks iterator produces correct count
        let data = vec![0i16; samples];
        let chunks: Vec<_> = data.chunks(chunk_samples).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), chunk_samples);
        assert_eq!(chunks[1].len(), 1);
    }
}
