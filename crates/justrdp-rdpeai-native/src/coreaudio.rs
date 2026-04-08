//! CoreAudio audio capture backend for macOS.

use std::collections::VecDeque;
use std::ptr;
use std::sync::{Arc, Condvar, Mutex};

use coreaudio_sys::{
    AudioQueueAllocateBuffer, AudioQueueBufferRef, AudioQueueDispose, AudioQueueEnqueueBuffer,
    AudioQueueNewInput, AudioQueueRef, AudioQueueStart, AudioQueueStop,
    AudioStreamBasicDescription, AudioStreamPacketDescription, AudioTimeStamp,
};

use crate::{AudioCaptureBackend, AudioCaptureConfig, AudioCaptureError};

// Audio format constants from CoreAudio headers.
// `kAudioFormatLinearPCM` = 'lpcm' = 0x6C70636D
const K_AUDIO_FORMAT_LINEAR_PCM: u32 = 0x6C70_636D;

// Linear PCM format flags.
const K_LINEAR_PCM_FORMAT_FLAG_IS_SIGNED_INTEGER: u32 = 1 << 2; // kAudioFormatFlagIsSignedInteger
const K_LINEAR_PCM_FORMAT_FLAG_IS_PACKED: u32 = 1 << 3; // kAudioFormatFlagIsPacked

/// Shared ring buffer between the AudioQueue callback and the `read()` caller.
struct SharedBuffer {
    data: Mutex<VecDeque<u8>>,
    condvar: Condvar,
}

/// CoreAudio capture using the AudioQueue input API.
pub struct CoreAudioCapture {
    queue: AudioQueueRef,
    shared: Arc<SharedBuffer>,
}

// SAFETY: `AudioQueueRef` is a pointer to an OS-managed opaque type.
// CoreAudio audio queues can be used from any thread once created;
// the AudioQueue API is documented as thread-safe for enqueue operations.
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

    let mut ring = shared.data.lock().unwrap();
    ring.extend(slice);
    shared.condvar.notify_one();

    // SAFETY: Re-enqueuing the same buffer back into the valid audio queue
    // so CoreAudio can fill it again for continuous recording.
    AudioQueueEnqueueBuffer(queue, buffer, 0, ptr::null());
}

impl AudioCaptureBackend for CoreAudioCapture {
    fn open(config: &AudioCaptureConfig) -> Result<Self, AudioCaptureError> {
        if config.bits_per_sample != 16 {
            return Err(AudioCaptureError::FormatNotSupported);
        }

        let bytes_per_frame = (config.channels as u32) * 2;

        let format = AudioStreamBasicDescription {
            mSampleRate: config.sample_rate as f64,
            mFormatID: K_AUDIO_FORMAT_LINEAR_PCM,
            mFormatFlags: K_LINEAR_PCM_FORMAT_FLAG_IS_SIGNED_INTEGER
                | K_LINEAR_PCM_FORMAT_FLAG_IS_PACKED,
            mBytesPerPacket: bytes_per_frame,
            mFramesPerPacket: 1,
            mBytesPerFrame: bytes_per_frame,
            mChannelsPerFrame: config.channels as u32,
            mBitsPerChannel: 16,
            mReserved: 0,
        };

        let shared = Arc::new(SharedBuffer {
            data: Mutex::new(VecDeque::new()),
            condvar: Condvar::new(),
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

        // Allocate and enqueue 3 buffers for continuous recording.
        let buf_size = config.packet_byte_size() as u32;

        for _ in 0..3 {
            let mut buffer: AudioQueueBufferRef = ptr::null_mut();

            // SAFETY: Allocating a buffer from a valid audio queue. `buf_size` is
            // the capacity in bytes, and `buffer` receives the allocated pointer.
            unsafe {
                AudioQueueAllocateBuffer(queue, buf_size, &mut buffer);
            }

            // SAFETY: Enqueuing a freshly allocated buffer into the valid queue.
            // CoreAudio will fill it with captured audio data and invoke the callback.
            unsafe {
                AudioQueueEnqueueBuffer(queue, buffer, 0, ptr::null());
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

        Ok(Self { queue, shared })
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, AudioCaptureError> {
        let mut ring = self.shared.data.lock().unwrap();

        // Block until the ring buffer has enough data to fill `buf`.
        while ring.len() < buf.len() {
            ring = self.shared.condvar.wait(ring).unwrap();
        }

        // Copy data out of the ring buffer.
        for byte in buf.iter_mut() {
            *byte = ring.pop_front().unwrap();
        }

        Ok(buf.len())
    }

    fn close(&mut self) {
        if !self.queue.is_null() {
            // SAFETY: Stopping and disposing a valid audio queue.
            // `AudioQueueStop` with `1` (true) means immediate stop.
            // `AudioQueueDispose` with `1` (true) disposes immediately.
            unsafe {
                AudioQueueStop(self.queue, 1);
                AudioQueueDispose(self.queue, 1);
            }
            self.queue = ptr::null_mut();
        }
    }
}

impl Drop for CoreAudioCapture {
    fn drop(&mut self) {
        self.close();
    }
}
