#![forbid(unsafe_code)]

//! Audio output channel routing on top of `justrdp-rdpsnd` (MS-RDPEA).
//!
//! [`AudioChannel`] hosts an [`RdpsndClient`] inside a
//! [`StaticChannelSet`] with a shared [`AudioState`] backend. Wave data
//! the server pushes lands in `pending_frames` for the embedder to
//! drain via `take_frame`; the demo page funnels each frame into a
//! Web Audio `AudioContext`.
//!
//! Format negotiation: the bundled backend accepts **PCM** (16-bit
//! little-endian, mono or stereo, any sample rate), **MS-ADPCM**
//! (`WaveFormatTag::ADPCM`, 0x0002), and **IMA / DVI ADPCM**
//! (`WaveFormatTag::DVI_ADPCM`, 0x0011). The backend keeps a per-format
//! decoder cache (`justrdp_audio::AudioDecoder`) and converts every
//! incoming wave PDU to interleaved PCM16-LE before pushing an
//! [`AudioFrame`], so embedders see a single uniform on-the-wire shape
//! regardless of the negotiated codec.
//!
//! Compressed codecs that need a browser-side decoder (Opus, AAC,
//! G.711) are still rejected here — they will be wired up in a
//! separate sub-step (S6b2 in the roadmap) via an embedder-injected
//! decoder trait.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use std::sync::{Arc, Mutex};

use justrdp_audio::AudioDecoder;
use justrdp_connector::ConnectionResult;
use justrdp_rdpsnd::pdu::{AudioFormat, VolumePdu, WaveFormatTag};
use justrdp_rdpsnd::{make_decoder, RdpsndBackend, RdpsndClient};
use justrdp_svc::StaticChannelSet;

/// Maximum sample rate the bundled decode buffer is sized for.
const MAX_SAMPLE_RATE_HZ: usize = 48_000;
/// Maximum channel count we accept.
const MAX_CHANNELS: usize = 2;
/// Decode buffer span — one wave PDU practically never exceeds a
/// couple of seconds of audio, even for ADPCM blocks.
const DECODE_BUFFER_SECS: usize = 2;
/// Sample capacity of the reusable decode buffer.
const MAX_DECODE_SAMPLES: usize = MAX_SAMPLE_RATE_HZ * MAX_CHANNELS * DECODE_BUFFER_SECS;

/// One decoded audio chunk pulled off the wire.
#[derive(Debug, Clone)]
pub struct AudioFrame {
    /// Index into the negotiated format list (`accepted_formats`).
    pub format_no: u16,
    /// Sample rate in Hz (e.g. 44100).
    pub sample_rate: u32,
    /// Channel count (1 = mono, 2 = stereo).
    pub channels: u16,
    /// Sample width in bits — always `16` post-decode. Every supported
    /// codec (PCM16, MS-ADPCM, IMA-ADPCM) lands as interleaved
    /// little-endian PCM16 in [`Self::data`].
    pub bits_per_sample: u16,
    /// Raw little-endian PCM bytes. Length = `channels * bytes_per_sample
    /// * num_frames`. Embedders convert to floats and feed an
    /// `AudioContext` via `decodeAudioData` / `AudioBuffer`.
    pub data: Vec<u8>,
}

/// Embedder-visible audio state.
#[derive(Default)]
pub struct AudioState {
    /// PCM formats the bundled backend accepted from the server, in
    /// the order they were advertised. `format_no` in [`AudioFrame`]
    /// indexes this Vec.
    accepted_formats: Vec<AudioFormat>,
    /// Wave data buffer — FIFO so the embedder can drain in order.
    pending_frames: VecDeque<AudioFrame>,
    /// Last volume the server requested. The `u32` packs left+right
    /// channels (low 16 bits = left, high 16 bits = right; MS-RDPEA
    /// 2.2.3.7). `None` until the server sends a Volume PDU.
    volume: Option<u32>,
    /// `true` once the server has sent a Close PDU. The channel will
    /// stop pushing new wave data; the embedder typically tears down
    /// its `AudioContext`.
    closed: bool,
}

impl AudioState {
    pub fn accepted_formats(&self) -> &[AudioFormat] {
        &self.accepted_formats
    }

    pub fn volume(&self) -> Option<u32> {
        self.volume
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn pending_frame_count(&self) -> usize {
        self.pending_frames.len()
    }
}

struct SharedBackend {
    state: Arc<Mutex<AudioState>>,
    /// Per-format decoder cache, keyed by the dense index in the
    /// negotiated format list (the `format_no` the server sends in
    /// Wave / Wave2 PDUs). Built up in `on_server_formats` so we don't
    /// re-instantiate decoders per wave PDU.
    decoders: BTreeMap<u16, Box<dyn AudioDecoder>>,
    /// Reusable interleaved-i16 decode buffer. Shared across formats
    /// because only one decode is ever in flight per `on_wave_data` call.
    decode_buf: Vec<i16>,
}

impl SharedBackend {
    fn new(state: Arc<Mutex<AudioState>>) -> Self {
        Self {
            state,
            decoders: BTreeMap::new(),
            decode_buf: alloc::vec![0i16; MAX_DECODE_SAMPLES],
        }
    }

    /// First-pass acceptance check — quickly reject formats whose
    /// codec we don't have a decoder for, or whose dimensions exceed
    /// the bundled buffer sizing. The follow-up
    /// [`make_decoder`] call is the authoritative gate (it validates
    /// the codec-specific `extra_data` blob, e.g. MS-ADPCM coefficient
    /// table); this filter just avoids round-tripping obviously bad
    /// formats through the decoder factory.
    fn accept(format: &AudioFormat) -> bool {
        if !(format.n_channels == 1 || format.n_channels == 2) {
            return false;
        }
        if format.n_samples_per_sec == 0
            || format.n_samples_per_sec as usize > MAX_SAMPLE_RATE_HZ
        {
            return false;
        }
        match format.format_tag {
            WaveFormatTag::PCM => format.bits_per_sample == 16,
            // Block-based ADPCM variants — `make_decoder` validates the
            // extra_data layout, so all we check here is non-zero
            // block alignment.
            WaveFormatTag::ADPCM | WaveFormatTag::DVI_ADPCM => format.n_block_align > 0,
            // Opus / AAC / G.711 — need a browser-side or
            // embedder-injected decoder; tracked in roadmap §11.3 S6b2.
            _ => false,
        }
    }
}

impl RdpsndBackend for SharedBackend {
    fn on_server_formats(&mut self, server_formats: &[AudioFormat]) -> Vec<usize> {
        // A new format list invalidates every cached decoder.
        self.decoders.clear();

        let mut accepted_idx = Vec::new();
        let mut accepted_formats = Vec::new();
        for (i, fmt) in server_formats.iter().enumerate() {
            if !Self::accept(fmt) {
                continue;
            }
            // make_decoder is the authoritative codec validator — if it
            // rejects the format (e.g. malformed MS-ADPCM extra_data),
            // skip the format entirely instead of advertising a codec
            // we can't actually drive.
            let decoder = match make_decoder(fmt) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let dense_idx = accepted_formats.len() as u16;
            accepted_idx.push(i);
            accepted_formats.push(fmt.clone());
            self.decoders.insert(dense_idx, decoder);
        }
        if let Ok(mut g) = self.state.lock() {
            g.accepted_formats = accepted_formats;
        }
        accepted_idx
    }

    fn on_wave_data(&mut self, format_no: u16, data: &[u8], _audio_timestamp: Option<u32>) {
        let Some(decoder) = self.decoders.get_mut(&format_no) else {
            // Stale or out-of-range format_no — drop rather than push
            // unknown bytes downstream.
            return;
        };

        let sample_rate = decoder.sample_rate();
        let channels = decoder.channels();
        let n_samples = match decoder.decode(data, &mut self.decode_buf) {
            Ok(n) => n.min(self.decode_buf.len()),
            Err(_) => return,
        };
        if n_samples == 0 {
            return;
        }

        // Re-pack the i16 samples as little-endian PCM16 bytes — the
        // demo's Web Audio bridge consumes that layout directly via
        // `DataView::getInt16(_, /*littleEndian*/ true)`.
        let mut bytes = Vec::with_capacity(n_samples * 2);
        for &s in &self.decode_buf[..n_samples] {
            bytes.extend_from_slice(&s.to_le_bytes());
        }

        if let Ok(mut g) = self.state.lock() {
            g.pending_frames.push_back(AudioFrame {
                format_no,
                sample_rate,
                channels,
                // Always 16 post-decode — every supported codec lands
                // as PCM16 after `AudioDecoder::decode`.
                bits_per_sample: 16,
                data: bytes,
            });
        }
    }

    fn on_volume(&mut self, volume: &VolumePdu) {
        if let Ok(mut g) = self.state.lock() {
            g.volume = Some(volume.volume);
        }
    }

    fn on_close(&mut self) {
        if let Ok(mut g) = self.state.lock() {
            g.closed = true;
        }
    }
}

/// Audio channel routing helper.
pub struct AudioChannel {
    channels: StaticChannelSet,
    user_channel_id: u16,
    rdpsnd_channel_id: u16,
    state: Arc<Mutex<AudioState>>,
}

impl core::fmt::Debug for AudioChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AudioChannel")
            .field("user_channel_id", &self.user_channel_id)
            .field("rdpsnd_channel_id", &self.rdpsnd_channel_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum AudioChannelError {
    /// The negotiated channel set didn't include `rdpsnd`.
    ChannelNotNegotiated,
    /// The wrapped channel set rejected the operation.
    Svc(justrdp_svc::SvcError),
}

impl core::fmt::Display for AudioChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ChannelNotNegotiated => f.write_str("RDPSND channel not negotiated by server"),
            Self::Svc(e) => write!(f, "svc: {e:?}"),
        }
    }
}

impl From<justrdp_svc::SvcError> for AudioChannelError {
    fn from(e: justrdp_svc::SvcError) -> Self {
        Self::Svc(e)
    }
}

impl AudioChannel {
    /// Construct from a [`ConnectionResult`]. Looks up `rdpsnd` in the
    /// negotiated channel list and instantiates the inner
    /// [`RdpsndClient`] with the bundled PCM/ADPCM backend.
    pub fn from_connection(result: &ConnectionResult) -> Result<Self, AudioChannelError> {
        let rdpsnd_channel_id = result
            .channel_ids
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("rdpsnd"))
            .map(|(_, id)| *id)
            .ok_or(AudioChannelError::ChannelNotNegotiated)?;

        let state: Arc<Mutex<AudioState>> = Arc::new(Mutex::new(AudioState::default()));
        let backend = Box::new(SharedBackend::new(Arc::clone(&state)));
        let rdpsnd = Box::new(RdpsndClient::new(backend));

        let mut channels = StaticChannelSet::new();
        channels.insert(rdpsnd).map_err(AudioChannelError::Svc)?;
        channels.assign_ids(&[(String::from("rdpsnd"), rdpsnd_channel_id)]);

        Ok(Self {
            channels,
            user_channel_id: result.user_channel_id,
            rdpsnd_channel_id,
            state,
        })
    }

    pub fn channel_id(&self) -> u16 {
        self.rdpsnd_channel_id
    }

    pub fn state(&self) -> Arc<Mutex<AudioState>> {
        Arc::clone(&self.state)
    }

    /// Process raw `ChannelData.data` bytes from a
    /// [`SessionEvent::Channel`] event. If the channel id doesn't
    /// match RDPSND, returns an empty Vec so the embedder can route
    /// every channel event without filtering.
    ///
    /// Returned wire frames are TPKT-framed and ready to send via
    /// `transport.send`.
    ///
    /// [`SessionEvent::Channel`]: crate::SessionEvent::Channel
    pub fn process_channel_data(
        &mut self,
        channel_id: u16,
        data: &[u8],
    ) -> Result<Vec<Vec<u8>>, AudioChannelError> {
        if channel_id != self.rdpsnd_channel_id {
            return Ok(Vec::new());
        }
        Ok(self
            .channels
            .process_incoming(channel_id, data, self.user_channel_id)?)
    }

    /// Drain the next queued audio frame, removing it from the
    /// FIFO. Returns `None` when the queue is empty.
    pub fn take_frame(&mut self) -> Option<AudioFrame> {
        self.state.lock().ok()?.pending_frames.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use justrdp_pdu::x224::SecurityProtocol;

    fn make_result(rdpsnd_id: u16) -> ConnectionResult {
        ConnectionResult {
            io_channel_id: 1003,
            user_channel_id: 1001,
            share_id: 0x0001_03ea,
            server_capabilities: Vec::new(),
            channel_ids: vec![(String::from("rdpsnd"), rdpsnd_id)],
            selected_protocol: SecurityProtocol::RDP,
            session_id: 0,
            server_monitor_layout: None,
            server_arc_cookie: None,
            server_redirection: None,
        }
    }

    #[test]
    fn from_connection_finds_rdpsnd_channel_id() {
        let result = make_result(1005);
        let ch = AudioChannel::from_connection(&result).unwrap();
        assert_eq!(ch.channel_id(), 1005);
    }

    #[test]
    fn from_connection_errors_when_rdpsnd_missing() {
        let mut result = make_result(0);
        result.channel_ids.clear();
        let err = AudioChannel::from_connection(&result).unwrap_err();
        assert!(matches!(err, AudioChannelError::ChannelNotNegotiated));
    }

    #[test]
    fn process_channel_data_ignores_unrelated_channel_ids() {
        let result = make_result(1005);
        let mut ch = AudioChannel::from_connection(&result).unwrap();
        let frames = ch.process_channel_data(2000, &[0u8; 16]).unwrap();
        assert!(frames.is_empty());
    }

    /// Build a minimal MS-ADPCM `AudioFormat` (mono, 22050 Hz) using the
    /// reference coefficient table from MS-RDPEA samples.
    fn make_msadpcm_format() -> AudioFormat {
        let coefs: [(i16, i16); 7] = [
            (256, 0),
            (512, -256),
            (0, 0),
            (192, 64),
            (240, 0),
            (460, -208),
            (392, -232),
        ];
        let mut extra = vec![0u8; 32];
        // wSamplesPerBlock = 4 — keeps the block small for tests.
        extra[0..2].copy_from_slice(&4u16.to_le_bytes());
        // wNumCoef = 7
        extra[2..4].copy_from_slice(&7u16.to_le_bytes());
        for (i, (c1, c2)) in coefs.iter().enumerate() {
            let off = 4 + i * 4;
            extra[off..off + 2].copy_from_slice(&c1.to_le_bytes());
            extra[off + 2..off + 4].copy_from_slice(&c2.to_le_bytes());
        }
        AudioFormat {
            format_tag: WaveFormatTag::ADPCM,
            n_channels: 1,
            n_samples_per_sec: 22_050,
            n_avg_bytes_per_sec: 22_311,
            n_block_align: 256,
            bits_per_sample: 4,
            extra_data: extra,
        }
    }

    /// Minimal valid MS-ADPCM block for `make_msadpcm_format()`: mono
    /// with `samples_per_block = 4`, so we need a 7-byte header plus
    /// exactly one byte of nibble data (2 nibbles → 2 trailing samples).
    fn make_msadpcm_block() -> Vec<u8> {
        let mut block = Vec::with_capacity(8);
        block.push(0); // bPredictor index 0
        block.extend_from_slice(&16i16.to_le_bytes()); // iDelta
        block.extend_from_slice(&0i16.to_le_bytes()); // iSamp1
        block.extend_from_slice(&0i16.to_le_bytes()); // iSamp2
        block.push(0x00); // 2 nibbles, both 0 — predictable decode
        block
    }

    fn make_dvi_format() -> AudioFormat {
        AudioFormat {
            format_tag: WaveFormatTag::DVI_ADPCM,
            n_channels: 2,
            n_samples_per_sec: 22_050,
            n_avg_bytes_per_sec: 22_201,
            n_block_align: 1024,
            bits_per_sample: 4,
            // wSamplesPerBlock = 1017 (per MS-ADPCM IMA layout for
            // block_align=1024, stereo).
            extra_data: vec![0xF9, 0x03],
        }
    }

    #[test]
    fn shared_backend_accepts_pcm_adpcm_dvi_rejects_opus() {
        let state: Arc<Mutex<AudioState>> = Arc::new(Mutex::new(AudioState::default()));
        let mut backend = SharedBackend::new(Arc::clone(&state));
        let server = vec![
            AudioFormat::pcm(2, 44_100, 16),
            make_msadpcm_format(),
            make_dvi_format(),
            AudioFormat {
                format_tag: WaveFormatTag::OPUS,
                n_channels: 2,
                n_samples_per_sec: 48_000,
                n_avg_bytes_per_sec: 0,
                n_block_align: 0,
                bits_per_sample: 0,
                extra_data: vec![],
            },
        ];
        let accepted = backend.on_server_formats(&server);
        // PCM, MS-ADPCM, DVI-ADPCM — Opus rejected.
        assert_eq!(accepted, vec![0, 1, 2]);
        let g = state.lock().unwrap();
        assert_eq!(g.accepted_formats.len(), 3);
    }

    #[test]
    fn shared_backend_pcm_passthrough_via_decoder() {
        let state: Arc<Mutex<AudioState>> = Arc::new(Mutex::new(AudioState::default()));
        let mut backend = SharedBackend::new(Arc::clone(&state));
        backend.on_server_formats(&[AudioFormat::pcm(1, 44_100, 16)]);

        // Two PCM16 LE samples: 0x0100, 0x0200.
        let input = [0x00, 0x01, 0x00, 0x02];
        backend.on_wave_data(0, &input, None);

        let mut g = state.lock().unwrap();
        let frame = g.pending_frames.pop_front().expect("frame queued");
        assert_eq!(frame.format_no, 0);
        assert_eq!(frame.channels, 1);
        assert_eq!(frame.sample_rate, 44_100);
        assert_eq!(frame.bits_per_sample, 16);
        // PCM passthrough — output bytes match the input verbatim.
        assert_eq!(frame.data, input.to_vec());
    }

    #[test]
    fn shared_backend_msadpcm_decodes_to_pcm16() {
        let state: Arc<Mutex<AudioState>> = Arc::new(Mutex::new(AudioState::default()));
        let mut backend = SharedBackend::new(Arc::clone(&state));
        backend.on_server_formats(&[make_msadpcm_format()]);

        backend.on_wave_data(0, &make_msadpcm_block(), None);

        let mut g = state.lock().unwrap();
        let frame = g.pending_frames.pop_front().expect("frame queued");
        // Post-decode shape — every supported codec lands as PCM16 mono
        // / stereo at the original sample rate.
        assert_eq!(frame.bits_per_sample, 16);
        assert_eq!(frame.channels, 1);
        assert_eq!(frame.sample_rate, 22_050);
        // samples_per_block = 4 mono → 4 i16 samples → 8 bytes.
        assert_eq!(frame.data.len(), 8);
    }

    #[test]
    fn shared_backend_drops_wave_for_unknown_format_no() {
        let state: Arc<Mutex<AudioState>> = Arc::new(Mutex::new(AudioState::default()));
        let mut backend = SharedBackend::new(Arc::clone(&state));
        backend.on_server_formats(&[AudioFormat::pcm(1, 44_100, 16)]);

        // format_no=5 was never negotiated — decoder cache miss must
        // be silent and must NOT push a malformed frame.
        backend.on_wave_data(5, &[0u8; 16], None);

        assert_eq!(state.lock().unwrap().pending_frame_count(), 0);
    }

    #[test]
    fn take_frame_drains_fifo_in_order() {
        let result = make_result(1005);
        let mut ch = AudioChannel::from_connection(&result).unwrap();
        // Drive the backend directly to enqueue two frames without a
        // full RDPSND state-machine setup.
        {
            let state = ch.state();
            let mut g = state.lock().unwrap();
            g.accepted_formats = vec![AudioFormat::pcm(2, 44_100, 16)];
            g.pending_frames.push_back(AudioFrame {
                format_no: 0,
                sample_rate: 44_100,
                channels: 2,
                bits_per_sample: 16,
                data: vec![0x10, 0x20],
            });
            g.pending_frames.push_back(AudioFrame {
                format_no: 0,
                sample_rate: 44_100,
                channels: 2,
                bits_per_sample: 16,
                data: vec![0x30, 0x40],
            });
        }
        let f1 = ch.take_frame().unwrap();
        assert_eq!(f1.data, vec![0x10, 0x20]);
        let f2 = ch.take_frame().unwrap();
        assert_eq!(f2.data, vec![0x30, 0x40]);
        assert!(ch.take_frame().is_none());
    }
}
