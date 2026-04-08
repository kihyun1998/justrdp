//! `NativeAudioBackend` — implements `RdpsndBackend` using a platform audio output.

use std::collections::HashMap;

use justrdp_audio::AudioDecoder;
use justrdp_rdpsnd::pdu::{AudioFormat, VolumePdu, WaveFormatTag};
use justrdp_rdpsnd::{make_decoder, RdpsndBackend};

use crate::error::NativeAudioError;
use crate::output::NativeAudioOutput;

/// Maximum supported sample rate (Hz).
const MAX_SAMPLE_RATE_HZ: usize = 48_000;
/// Maximum supported channel count.
const MAX_CHANNELS: usize = 2;
/// Decode buffer duration (seconds).
const DECODE_BUFFER_SECS: usize = 2;
/// Maximum decoded PCM buffer size in samples.
const MAX_DECODE_SAMPLES: usize = MAX_SAMPLE_RATE_HZ * MAX_CHANNELS * DECODE_BUFFER_SECS;

/// Maximum iterations for waveOut busy-wait (5 seconds at 1ms sleep).
pub(crate) const MAX_WRITE_WAIT_ITERS: u32 = 5_000;

/// Codec tags we can decode (PCM, MS-ADPCM, IMA-ADPCM).
fn is_decodable(format: &AudioFormat) -> bool {
    matches!(
        format.format_tag,
        WaveFormatTag::PCM | WaveFormatTag::ADPCM | WaveFormatTag::DVI_ADPCM
    )
}

/// Native audio backend that decodes RDP audio and plays it through
/// the platform audio output device.
///
/// Generic over `O: NativeAudioOutput` so each platform provides its own
/// implementation (WASAPI, PulseAudio, CoreAudio).
pub struct NativeAudioBackend<O: NativeAudioOutput> {
    /// Audio formats keyed by server format index.
    /// Sparse map: only decodable formats are stored.
    format_map: HashMap<u16, AudioFormat>,
    /// Decoder cache keyed by server format index.
    decoders: HashMap<u16, Box<dyn AudioDecoder>>,
    /// Platform audio output device (lazily opened on first audio data).
    output: Option<O>,
    /// Reusable decode buffer.
    decode_buf: Vec<i16>,
}

impl<O: NativeAudioOutput> Default for NativeAudioBackend<O> {
    fn default() -> Self {
        Self::new()
    }
}

impl<O: NativeAudioOutput> NativeAudioBackend<O> {
    /// Create a new native audio backend.
    pub fn new() -> Self {
        Self {
            format_map: HashMap::new(),
            decoders: HashMap::new(),
            output: None,
            decode_buf: vec![0i16; MAX_DECODE_SAMPLES],
        }
    }

    /// Ensure a decoder exists for the given server format index.
    fn ensure_decoder(&mut self, format_no: u16) -> Result<(), NativeAudioError> {
        if self.decoders.contains_key(&format_no) {
            return Ok(());
        }
        let format = self
            .format_map
            .get(&format_no)
            .ok_or(NativeAudioError::FormatNotSupported)?;
        let decoder = make_decoder(format)
            .map_err(|e| NativeAudioError::DecodeError(format!("{e}")))?;
        self.decoders.insert(format_no, decoder);
        Ok(())
    }
}

impl<O: NativeAudioOutput> std::fmt::Debug for NativeAudioBackend<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeAudioBackend")
            .field("formats", &self.format_map.len())
            .field("output_open", &self.output.is_some())
            .finish()
    }
}

impl<O: NativeAudioOutput + 'static> RdpsndBackend for NativeAudioBackend<O> {
    fn on_server_formats(&mut self, server_formats: &[AudioFormat]) -> Vec<usize> {
        self.format_map.clear();
        self.decoders.clear();

        let mut supported_indices = Vec::new();
        for (i, format) in server_formats.iter().enumerate() {
            if is_decodable(format) {
                supported_indices.push(i);
                // Store with the server's original index as key
                self.format_map.insert(i as u16, format.clone());
            }
        }

        supported_indices
    }

    fn on_wave_data(&mut self, format_no: u16, data: &[u8], _audio_timestamp: Option<u32>) {
        // Ensure decoder exists for this server format index
        if self.ensure_decoder(format_no).is_err() {
            return;
        }

        // Split borrows: access decoder and decode_buf separately
        let decoder = match self.decoders.get_mut(&format_no) {
            Some(d) => d,
            None => return,
        };

        let sample_rate = decoder.sample_rate();
        let channels = decoder.channels();

        let n_samples = match decoder.decode(data, &mut self.decode_buf) {
            Ok(n) => n,
            Err(_) => return,
        };

        if n_samples == 0 {
            return;
        }

        // Clamp to buffer size to prevent out-of-bounds
        let n_samples = n_samples.min(self.decode_buf.len());

        // Ensure output is open
        if self.output.is_none() {
            match O::open(sample_rate, channels, 16) {
                Ok(output) => self.output = Some(output),
                Err(_) => return,
            }
        }

        // Write samples; on failure close device so it can be re-opened next time
        if let Some(output) = self.output.as_mut() {
            if output.write_samples(&self.decode_buf[..n_samples]).is_err() {
                output.close();
                self.output = None;
            }
        }
    }

    fn on_volume(&mut self, volume: &VolumePdu) {
        if let Some(output) = self.output.as_mut() {
            output.set_volume(volume.left(), volume.right());
        }
    }

    fn on_close(&mut self) {
        if let Some(output) = self.output.as_mut() {
            output.close();
        }
        self.output = None;
        self.decoders.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Mock audio output for testing.
    #[derive(Debug)]
    struct MockOutput {
        samples: Arc<Mutex<Vec<i16>>>,
        closed: bool,
    }

    impl NativeAudioOutput for MockOutput {
        fn open(_sample_rate: u32, _channels: u16, _bits: u16) -> Result<Self, NativeAudioError> {
            Ok(Self {
                samples: Arc::new(Mutex::new(Vec::new())),
                closed: false,
            })
        }

        fn write_samples(&mut self, samples: &[i16]) -> Result<(), NativeAudioError> {
            self.samples.lock().unwrap().extend_from_slice(samples);
            Ok(())
        }

        fn set_volume(&mut self, _left: u16, _right: u16) {}

        fn close(&mut self) {
            self.closed = true;
        }
    }

    #[test]
    fn on_server_formats_filters_decodable() {
        let mut backend = NativeAudioBackend::<MockOutput>::new();
        let formats = vec![
            AudioFormat::pcm(2, 44100, 16),
            AudioFormat {
                format_tag: WaveFormatTag::OPUS,
                n_channels: 2,
                n_samples_per_sec: 48000,
                n_avg_bytes_per_sec: 0,
                n_block_align: 0,
                bits_per_sample: 0,
                extra_data: vec![],
            },
            AudioFormat::pcm(1, 22050, 16),
        ];

        let indices = backend.on_server_formats(&formats);
        // Should accept PCM formats (index 0, 2) but not Opus (index 1)
        assert_eq!(indices, vec![0, 2]);
        assert_eq!(backend.format_map.len(), 2);
    }

    #[test]
    fn format_index_mapping_correct() {
        let mut backend = NativeAudioBackend::<MockOutput>::new();
        let formats = vec![
            AudioFormat {
                format_tag: WaveFormatTag::OPUS,
                n_channels: 2,
                n_samples_per_sec: 48000,
                n_avg_bytes_per_sec: 0,
                n_block_align: 0,
                bits_per_sample: 0,
                extra_data: vec![],
            },
            AudioFormat::pcm(2, 44100, 16),  // server index 1
            AudioFormat::pcm(1, 22050, 16),  // server index 2
        ];

        let indices = backend.on_server_formats(&formats);
        assert_eq!(indices, vec![1, 2]);

        // Server sends format_no=1, should find the 44100 Hz format
        assert!(backend.format_map.contains_key(&1));
        assert_eq!(backend.format_map[&1].n_samples_per_sec, 44100);

        // Server sends format_no=2, should find the 22050 Hz format
        assert!(backend.format_map.contains_key(&2));
        assert_eq!(backend.format_map[&2].n_samples_per_sec, 22050);

        // format_no=0 (Opus) should NOT be in the map
        assert!(!backend.format_map.contains_key(&0));
    }

    #[test]
    fn on_wave_data_decodes_pcm() {
        let mut backend = NativeAudioBackend::<MockOutput>::new();

        let formats = vec![AudioFormat::pcm(1, 44100, 16)];
        backend.on_server_formats(&formats);

        // Send 16-bit LE PCM: [0x0100] = 256
        let pcm_data = [0x00, 0x01, 0xFF, 0x7F]; // 256, 32767
        backend.on_wave_data(0, &pcm_data, None);

        assert!(backend.output.is_some());
    }

    #[test]
    fn on_close_clears_state() {
        let mut backend = NativeAudioBackend::<MockOutput>::new();
        let formats = vec![AudioFormat::pcm(1, 44100, 16)];
        backend.on_server_formats(&formats);

        // Trigger output open
        let pcm_data = [0x00, 0x01];
        backend.on_wave_data(0, &pcm_data, None);
        assert!(backend.output.is_some());

        backend.on_close();
        assert!(backend.output.is_none());
        assert!(backend.decoders.is_empty());
    }

    #[test]
    fn on_server_formats_no_decodable() {
        let mut backend = NativeAudioBackend::<MockOutput>::new();
        let formats = vec![AudioFormat {
            format_tag: WaveFormatTag::OPUS,
            n_channels: 2,
            n_samples_per_sec: 48000,
            n_avg_bytes_per_sec: 0,
            n_block_align: 0,
            bits_per_sample: 0,
            extra_data: vec![],
        }];

        let indices = backend.on_server_formats(&formats);
        assert!(indices.is_empty());
    }

    #[test]
    fn write_failure_closes_output() {
        /// Mock that fails on write.
        #[derive(Debug)]
        struct FailOutput;

        impl NativeAudioOutput for FailOutput {
            fn open(_: u32, _: u16, _: u16) -> Result<Self, NativeAudioError> {
                Ok(Self)
            }
            fn write_samples(&mut self, _: &[i16]) -> Result<(), NativeAudioError> {
                Err(NativeAudioError::WriteError("device gone".into()))
            }
            fn set_volume(&mut self, _: u16, _: u16) {}
            fn close(&mut self) {}
        }

        let mut backend = NativeAudioBackend::<FailOutput>::new();
        let formats = vec![AudioFormat::pcm(1, 44100, 16)];
        backend.on_server_formats(&formats);

        backend.on_wave_data(0, &[0x00, 0x01], None);
        // Output should be closed after write failure
        assert!(backend.output.is_none());
    }
}
