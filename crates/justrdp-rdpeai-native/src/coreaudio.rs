//! CoreAudio audio capture backend for macOS.

use std::collections::VecDeque;
use std::ptr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use coreaudio_sys::{
    AudioQueueAllocateBuffer, AudioQueueBufferRef, AudioQueueDispose, AudioQueueEnqueueBuffer,
    AudioQueueNewInput, AudioQueueRef, AudioQueueStart, AudioQueueStop,
    AudioStreamBasicDescription, AudioStreamPacketDescription, AudioTimeStamp,
};

use crate::{AudioCaptureBackend, AudioCaptureConfig, AudioCaptureError};

// Audio format constants from CoreAudio headers.
// `kAudioFormatLinearPCM` = 'lpcm' = 0x6C70636D
// Reference: CoreAudio/CoreAudioTypes.h — kAudioFormatLinearPCM
const AUDIO_FORMAT_LINEAR_PCM: u32 = 0x6C70_636D;

// Linear PCM format flags.
// Reference: CoreAudio/CoreAudioTypes.h — kAudioFormatFlagIsSignedInteger, kAudioFormatFlagIsPacked
// kAudioFormatFlagIsBigEndian (1 << 1) is intentionally absent → little-endian output,
// matching MS-RDPEAI's expected PCM byte order.
// kAudioFormatFlagIsFloat (1 << 0) is also absent → signed integer, not floating-point.
const LINEAR_PCM_FORMAT_FLAG_IS_SIGNED_INTEGER: u32 = 1 << 2;
const LINEAR_PCM_FORMAT_FLAG_IS_PACKED: u32 = 1 << 3;

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
    let shared = unsafe { &*(user_data as *const SharedBuffer) };

    // SAFETY: `buffer` is a valid AudioQueueBuffer filled by CoreAudio.
    // `mAudioData` points to `mAudioDataByteSize` bytes of captured PCM data.
    // Clamp to `mAudioDataCapacityInBytes` to guard against a buggy driver
    // reporting more bytes than the buffer can hold (prevents OOB read).
    let (data_ptr, data_len) = unsafe {
        let cap = (*buffer).mAudioDataCapacityInBytes as usize;
        (
            (*buffer).mAudioData as *const u8,
            ((*buffer).mAudioDataByteSize as usize).min(cap),
        )
    };
    let slice = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };

    // Use unwrap_or_else to avoid panicking across the FFI boundary if
    // the mutex is poisoned (e.g., if the consumer thread panicked).
    if let Ok(mut ring) = shared.data.lock() {
        // Enforce ring buffer capacity: drop oldest data if full.
        if slice.len() >= shared.ring_cap {
            // Single callback delivers more data than the entire ring — keep newest.
            ring.clear();
            ring.extend(&slice[slice.len() - shared.ring_cap..]);
        } else {
            let available = shared.ring_cap.saturating_sub(ring.len());
            if slice.len() <= available {
                ring.extend(slice);
            } else {
                // Drop oldest bytes to make room.
                let need = slice.len().saturating_sub(available);
                ring.drain(..need);
                ring.extend(slice);
            }
        }
        shared.condvar.notify_one();

        // SAFETY: Re-enqueuing the same buffer back into the valid audio queue
        // so CoreAudio can fill it again for continuous recording.
        // Only re-enqueue when the lock succeeded; on poisoned mutex we let
        // the buffer stay un-enqueued so recording stalls rather than risking
        // a use-after-free race with close().
        unsafe {
            AudioQueueEnqueueBuffer(queue, buffer, 0, ptr::null());
        }
    }
    // If lock fails (poisoned), silently drop the audio data and do not
    // re-enqueue. Recording will stall, and read() will return a timeout error.
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
            mFormatID: AUDIO_FORMAT_LINEAR_PCM,
            mFormatFlags: LINEAR_PCM_FORMAT_FLAG_IS_SIGNED_INTEGER
                | LINEAR_PCM_FORMAT_FLAG_IS_PACKED,
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

        // Validate buf_size fits u32 before creating any OS resources,
        // so we don't need mid-open() cleanup if this fails.
        let buf_size = u32::try_from(packet_size)
            .map_err(|_| AudioCaptureError::FormatNotSupported)?;

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
        // (`buf_size` was validated above, before any OS resources were created.)
        //
        // Scope guard: on any error path below, dispose the queue and reclaim
        // the Arc raw pointer. This eliminates duplicated teardown code.
        let mut queue_armed = true;

        let result = (|| -> Result<(), AudioCaptureError> {
            for _ in 0..NUM_AUDIO_QUEUE_BUFFERS {
                let mut buffer: AudioQueueBufferRef = ptr::null_mut();

                // SAFETY: Allocating a buffer from a valid audio queue.
                let alloc_status = unsafe {
                    AudioQueueAllocateBuffer(queue, buf_size, &mut buffer)
                };

                if alloc_status != 0 {
                    return Err(AudioCaptureError::DeviceError(format!(
                        "AudioQueueAllocateBuffer failed with status {alloc_status}"
                    )));
                }

                // SAFETY: Enqueuing a freshly allocated buffer into the valid queue.
                let enqueue_status = unsafe {
                    AudioQueueEnqueueBuffer(queue, buffer, 0, ptr::null())
                };

                if enqueue_status != 0 {
                    return Err(AudioCaptureError::DeviceError(format!(
                        "AudioQueueEnqueueBuffer failed with status {enqueue_status}"
                    )));
                }
            }

            // SAFETY: `queue` is valid after successful `AudioQueueNewInput`.
            // Passing NULL for the start time means "start immediately".
            let status = unsafe { AudioQueueStart(queue, ptr::null()) };

            if status != 0 {
                return Err(AudioCaptureError::DeviceError(format!(
                    "AudioQueueStart failed with status {status}"
                )));
            }

            Ok(())
        })();

        match result {
            Ok(()) => {
                let _ = queue_armed; // disarm — success, no cleanup needed
                Ok(Self {
                    queue,
                    shared,
                    shared_raw: shared_ptr,
                })
            }
            Err(e) => {
                // SAFETY: Disposing the queue frees all its allocated buffers.
                // Then reclaim the Arc raw pointer leaked via `into_raw`.
                // (Reaching this arm means the closure returned Err, so the
                // queue is always live and needs cleanup.)
                unsafe {
                    AudioQueueDispose(queue, 1);
                    Arc::from_raw(shared_ptr);
                }
                Err(e)
            }
        }
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
        // Track cumulative elapsed time to prevent spurious wakeups from
        // extending the total wait beyond READ_TIMEOUT.
        let deadline = Instant::now() + READ_TIMEOUT;
        while ring.len() < buf.len() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(AudioCaptureError::ReadError(
                    "CoreAudio capture timed out after 5 seconds".into(),
                ));
            }

            let (guard, _) = self
                .shared
                .condvar
                .wait_timeout(ring, remaining)
                .map_err(|_| AudioCaptureError::ReadError("shared buffer poisoned".into()))?;

            ring = guard;
            // On timeout or spurious wakeup, the `remaining.is_zero()` check
            // at the top of the next iteration handles the deadline.
        }

        // Copy data out of the ring buffer using bulk memcpy.
        let n = buf.len();
        let (front, back) = ring.as_slices();
        let front_n = front.len().min(n);
        buf[..front_n].copy_from_slice(&front[..front_n]);
        if front_n < n {
            buf[front_n..n].copy_from_slice(&back[..n - front_n]);
        }
        ring.drain(..n);

        Ok(n)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AudioCaptureBackend, AudioCaptureConfig};

    fn valid_config() -> AudioCaptureConfig {
        AudioCaptureConfig {
            sample_rate: 44100,
            channels: 2,
            bits_per_sample: 16,
            frames_per_packet: 1024,
        }
    }

    #[test]
    fn open_rejects_non_16bit() {
        let config = AudioCaptureConfig {
            sample_rate: 44100,
            channels: 2,
            bits_per_sample: 8,
            frames_per_packet: 1024,
        };
        let result = CoreAudioCapture::open(&config);
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
        let result = CoreAudioCapture::open(&config);
        assert!(result.is_err());
    }

    #[test]
    fn open_and_close_succeeds() {
        // CoreAudio AudioQueue can be created even without a physical microphone
        // (uses default input device or fails gracefully).
        let config = valid_config();
        match CoreAudioCapture::open(&config) {
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

    #[test]
    fn read_after_close_returns_error() {
        let config = valid_config();
        match CoreAudioCapture::open(&config) {
            Ok(mut capture) => {
                capture.close();
                let mut buf = vec![0u8; 1024];
                let result = capture.read(&mut buf);
                assert!(result.is_err());
            }
            Err(_) => {
                // No audio device — skip.
            }
        }
    }

    #[test]
    fn shared_buffer_ring_cap_enforced() {
        // Test the ring buffer capacity enforcement logic directly.
        let shared = SharedBuffer {
            data: Mutex::new(VecDeque::new()),
            condvar: Condvar::new(),
            ring_cap: 100,
        };

        let mut ring = shared.data.lock().unwrap();

        // Fill to capacity
        ring.extend(std::iter::repeat(0xAA).take(100));
        assert_eq!(ring.len(), 100);

        // Simulate callback behavior: insert 20 bytes, oldest 20 should be dropped
        let new_data = vec![0xBB; 20];
        let available = shared.ring_cap.saturating_sub(ring.len());
        assert_eq!(available, 0);

        let need = new_data.len().saturating_sub(available);
        ring.drain(..need);
        ring.extend(&new_data);

        assert_eq!(ring.len(), 100);
        // First byte should now be 0xAA (original data shifted), last 20 should be 0xBB
        assert_eq!(*ring.back().unwrap(), 0xBB);
        assert_eq!(ring.iter().filter(|&&b| b == 0xBB).count(), 20);
    }

    #[test]
    fn shared_buffer_oversized_slice() {
        // When a single callback delivers more data than ring_cap,
        // only the newest ring_cap bytes should be retained.
        let shared = SharedBuffer {
            data: Mutex::new(VecDeque::new()),
            condvar: Condvar::new(),
            ring_cap: 50,
        };

        let mut ring = shared.data.lock().unwrap();
        ring.extend(std::iter::repeat(0xAA).take(30));

        // Simulate oversized callback data (100 bytes > ring_cap 50).
        let slice: Vec<u8> = (0..100).collect();
        if slice.len() >= shared.ring_cap {
            ring.clear();
            ring.extend(&slice[slice.len() - shared.ring_cap..]);
        }
        assert_eq!(ring.len(), 50);
        // Should contain the last 50 bytes of slice (50..100).
        assert_eq!(ring[0], 50);
        assert_eq!(*ring.back().unwrap(), 99);
    }

    #[test]
    fn shared_buffer_empty_insert() {
        let shared = SharedBuffer {
            data: Mutex::new(VecDeque::new()),
            condvar: Condvar::new(),
            ring_cap: 1000,
        };

        let mut ring = shared.data.lock().unwrap();
        let data = vec![0x42; 500];
        let available = shared.ring_cap.saturating_sub(ring.len());
        assert!(data.len() <= available);
        ring.extend(&data);
        assert_eq!(ring.len(), 500);
    }

    #[test]
    fn constants_match_coreaudio_headers() {
        // Verify our constants match CoreAudio header values.
        assert_eq!(AUDIO_FORMAT_LINEAR_PCM, 0x6C70_636D); // 'lpcm'
        assert_eq!(LINEAR_PCM_FORMAT_FLAG_IS_SIGNED_INTEGER, 4);
        assert_eq!(LINEAR_PCM_FORMAT_FLAG_IS_PACKED, 8);
        assert_eq!(NUM_AUDIO_QUEUE_BUFFERS, 3);
        assert_eq!(RING_BUFFER_MAX_PACKETS, 4);
        assert_eq!(READ_TIMEOUT, Duration::from_secs(5));
    }
}
