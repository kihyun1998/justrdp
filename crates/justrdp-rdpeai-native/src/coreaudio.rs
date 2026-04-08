//! CoreAudio audio capture backend for macOS.

use std::collections::VecDeque;
use std::ptr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use coreaudio_sys::{
    AudioQueueAllocateBuffer, AudioQueueBufferRef, AudioQueueDispose, AudioQueueEnqueueBuffer,
    AudioQueueNewInput, AudioQueueRef, AudioQueueStart, AudioQueueStop,
    AudioStreamBasicDescription, AudioStreamPacketDescription, AudioTimeStamp,
};

use crate::{AudioCaptureBackend, AudioCaptureConfig, AudioCaptureError};

// Audio format constants from CoreAudio headers.
// `kAudioFormatLinearPCM` = 'lpcm' = 0x6C70636D
// Reference: CoreAudio/CoreAudioTypes.h — kAudioFormatLinearPCM
const K_AUDIO_FORMAT_LINEAR_PCM: u32 = 0x6C70_636D;

// Linear PCM format flags.
// Reference: CoreAudio/CoreAudioTypes.h — kAudioFormatFlagIsSignedInteger, kAudioFormatFlagIsPacked
const K_LINEAR_PCM_FORMAT_FLAG_IS_SIGNED_INTEGER: u32 = 1 << 2;
const K_LINEAR_PCM_FORMAT_FLAG_IS_PACKED: u32 = 1 << 3;

/// Number of AudioQueue buffers for continuous recording.
const NUM_AUDIO_QUEUE_BUFFERS: usize = 3;

/// Maximum ring buffer size: 4x the packet size. Data beyond this is dropped.
const RING_BUFFER_MAX_PACKETS: usize = 4;

/// Timeout for `read()` condvar wait.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Shared ring buffer between the AudioQueue callback and the `read()` caller.
struct SharedBuffer {
    data: Mutex<VecDeque<u8>>,
    condvar: Condvar,
    /// Maximum ring buffer capacity in bytes (set once in `open()`).
    ring_cap: usize,
}

/// CoreAudio capture using the AudioQueue input API.
pub struct CoreAudioCapture {
    queue: AudioQueueRef,
    shared: Arc<SharedBuffer>,
    /// Raw pointer given to CoreAudio as `user_data`; reclaimed in `close()`.
    shared_raw: *const SharedBuffer,
}

// SAFETY: `AudioQueueRef` is a pointer to an OS-managed opaque type.
// CoreAudio audio queues can be used from any thread once created;
// the AudioQueue API is documented as thread-safe for enqueue operations.
// `shared_raw` is only dereferenced by the CoreAudio callback thread and
// reclaimed in `close()` after the queue is disposed.
unsafe impl Send for CoreAudioCapture {}

/// AudioQueue input callback invoked by CoreAudio when a buffer is filled.
///
/// Copies recorded audio data into the shared ring buffer and re-enqueues
/// the buffer for continuous recording.
///
/// # Safety
///
/// This function is called by CoreAudio with valid buffer pointers. `user_data`
/// must point to a valid `SharedBuffer` that outlives the audio queue.
unsafe extern "C" fn input_callback(
    user_data: *mut std::ffi::c_void,
    queue: AudioQueueRef,
    buffer: AudioQueueBufferRef,
    _start_time: *const AudioTimeStamp,
    _num_packets: u32,
    _packet_desc: *const AudioStreamPacketDescription,
) {
    // SAFETY: `user_data` is an `Arc<SharedBuffer>` raw pointer created in `open()`
    // and remains valid for the lifetime of the audio queue.
    let shared = &*(user_data as *const SharedBuffer);

    // SAFETY: `buffer` is a valid AudioQueueBuffer filled by CoreAudio.
    // `mAudioData` points to `mAudioDataByteSize` bytes of captured PCM data.
    let data_ptr = (*buffer).mAudioData as *const u8;
    let data_len = (*buffer).mAudioDataByteSize as usize;
    let slice = std::slice::from_raw_parts(data_ptr, data_len);

    // Use unwrap_or_else to avoid panicking across the FFI boundary if
    // the mutex is poisoned (e.g., if the consumer thread panicked).
    if let Ok(mut ring) = shared.data.lock() {
        // Enforce ring buffer capacity: drop oldest data if full.
        let available = shared.ring_cap.saturating_sub(ring.len());
        if slice.len() <= available {
            ring.extend(slice);
        } else {
            // Drop oldest bytes to make room.
            let need = slice.len().saturating_sub(available);
            ring.drain(..need);
            ring.extend(slice);
        }
        shared.condvar.notify_one();
    }
    // If lock fails (poisoned), silently drop the audio data rather than panicking.

    // SAFETY: Re-enqueuing the same buffer back into the valid audio queue
    // so CoreAudio can fill it again for continuous recording.
    AudioQueueEnqueueBuffer(queue, buffer, 0, ptr::null());
}

impl AudioCaptureBackend for CoreAudioCapture {
    fn open(config: &AudioCaptureConfig) -> Result<Self, AudioCaptureError> {
        config.validate()?;

        if config.bits_per_sample != 16 {
            return Err(AudioCaptureError::FormatNotSupported);
        }

        let bytes_per_sample = (config.bits_per_sample / 8) as u32;
        let bytes_per_frame = (config.channels as u32)
            .checked_mul(bytes_per_sample)
            .ok_or(AudioCaptureError::FormatNotSupported)?;

        let format = AudioStreamBasicDescription {
            mSampleRate: config.sample_rate as f64,
            mFormatID: K_AUDIO_FORMAT_LINEAR_PCM,
            mFormatFlags: K_LINEAR_PCM_FORMAT_FLAG_IS_SIGNED_INTEGER
                | K_LINEAR_PCM_FORMAT_FLAG_IS_PACKED,
            mBytesPerPacket: bytes_per_frame,
            mFramesPerPacket: 1,
            mBytesPerFrame: bytes_per_frame,
            mChannelsPerFrame: config.channels as u32,
            mBitsPerChannel: config.bits_per_sample as u32,
            mReserved: 0,
        };

        let packet_size = config.packet_byte_size();
        let ring_cap = packet_size
            .checked_mul(RING_BUFFER_MAX_PACKETS)
            .ok_or(AudioCaptureError::FormatNotSupported)?;

        let shared = Arc::new(SharedBuffer {
            data: Mutex::new(VecDeque::new()),
            condvar: Condvar::new(),
            ring_cap,
        });

        let mut queue: AudioQueueRef = ptr::null_mut();

        // We clone the Arc and convert to a raw pointer for the callback's user data.
        // This reference is reclaimed in `close()` or on error paths below.
        let shared_ptr = Arc::into_raw(Arc::clone(&shared));

        // SAFETY: `AudioQueueNewInput` is called with a valid format description,
        // a valid callback function, and a valid user-data pointer. We pass NULL
        // for the run loop (uses internal thread) and no flags.
        let status = unsafe {
            AudioQueueNewInput(
                &format,
                Some(input_callback),
                shared_ptr as *mut std::ffi::c_void,
                ptr::null_mut(), // run loop (NULL = internal)
                ptr::null(),     // run loop mode
                0,               // flags (reserved, must be 0)
                &mut queue,
            )
        };

        if status != 0 {
            // SAFETY: Reclaiming the Arc we leaked via `into_raw` since the queue
            // was never created and won't use this pointer.
            unsafe {
                Arc::from_raw(shared_ptr);
            }
            return Err(AudioCaptureError::DeviceError(format!(
                "AudioQueueNewInput failed with status {status}"
            )));
        }

        // Allocate and enqueue buffers for continuous recording.
        let buf_size = u32::try_from(packet_size)
            .map_err(|_| AudioCaptureError::FormatNotSupported)?;

        for _ in 0..NUM_AUDIO_QUEUE_BUFFERS {
            let mut buffer: AudioQueueBufferRef = ptr::null_mut();

            // SAFETY: Allocating a buffer from a valid audio queue.
            let alloc_status = unsafe {
                AudioQueueAllocateBuffer(queue, buf_size, &mut buffer)
            };

            if alloc_status != 0 {
                unsafe {
                    AudioQueueDispose(queue, 1);
                    Arc::from_raw(shared_ptr);
                }
                return Err(AudioCaptureError::DeviceError(format!(
                    "AudioQueueAllocateBuffer failed with status {alloc_status}"
                )));
            }

            // SAFETY: Enqueuing a freshly allocated buffer into the valid queue.
            let enqueue_status = unsafe {
                AudioQueueEnqueueBuffer(queue, buffer, 0, ptr::null())
            };

            if enqueue_status != 0 {
                unsafe {
                    AudioQueueDispose(queue, 1);
                    Arc::from_raw(shared_ptr);
                }
                return Err(AudioCaptureError::DeviceError(format!(
                    "AudioQueueEnqueueBuffer failed with status {enqueue_status}"
                )));
            }
        }

        // SAFETY: `queue` is valid after successful `AudioQueueNewInput`.
        // Passing NULL for the start time means "start immediately".
        let status = unsafe { AudioQueueStart(queue, ptr::null()) };

        if status != 0 {
            // SAFETY: Disposing a valid queue (`1` = immediate, don't drain)
            // and reclaiming the Arc raw pointer.
            unsafe {
                AudioQueueDispose(queue, 1);
                Arc::from_raw(shared_ptr);
            }
            return Err(AudioCaptureError::DeviceError(format!(
                "AudioQueueStart failed with status {status}"
            )));
        }

        Ok(Self {
            queue,
            shared,
            shared_raw: shared_ptr,
        })
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, AudioCaptureError> {
        if self.queue.is_null() {
            return Err(AudioCaptureError::ReadError("device closed".into()));
        }

        let mut ring = self
            .shared
            .data
            .lock()
            .map_err(|_| AudioCaptureError::ReadError("shared buffer poisoned".into()))?;

        // Block until the ring buffer has enough data to fill `buf`, with timeout.
        while ring.len() < buf.len() {
            let (guard, wait_result) = self
                .shared
                .condvar
                .wait_timeout(ring, READ_TIMEOUT)
                .map_err(|_| AudioCaptureError::ReadError("shared buffer poisoned".into()))?;

            ring = guard;

            if wait_result.timed_out() && ring.len() < buf.len() {
                return Err(AudioCaptureError::ReadError(
                    "CoreAudio capture timed out after 5 seconds".into(),
                ));
            }
        }

        // Copy data out of the ring buffer.
        for (dst, src) in buf.iter_mut().zip(ring.drain(..buf.len())) {
            *dst = src;
        }

        Ok(buf.len())
    }

    fn close(&mut self) {
        if !self.queue.is_null() {
            // SAFETY: Stopping and disposing a valid audio queue.
            // `AudioQueueStop` with `1` (true) means immediate stop.
            // `AudioQueueDispose` with `1` (true) disposes immediately.
            // After `AudioQueueDispose` returns, the callback is guaranteed
            // not to fire again, so it is safe to reclaim `shared_raw`.
            unsafe {
                AudioQueueStop(self.queue, 1);
                AudioQueueDispose(self.queue, 1);
            }
            self.queue = ptr::null_mut();

            // SAFETY: Reclaiming the Arc raw pointer that was leaked in `open()`
            // via `Arc::into_raw`. The callback can no longer access it after
            // `AudioQueueDispose` has returned.
            if !self.shared_raw.is_null() {
                unsafe {
                    Arc::from_raw(self.shared_raw);
                }
                self.shared_raw = ptr::null();
            }
        }
    }
}

impl Drop for CoreAudioCapture {
    fn drop(&mut self) {
        self.close();
    }
}
