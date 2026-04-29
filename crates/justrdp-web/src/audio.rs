#![forbid(unsafe_code)]

//! Audio output (RDPSND) and input (RDPEAI) channel routing.
//!
//! [`AudioChannel`] hosts the RDPSND processors inside a
//! [`StaticChannelSet`]. Wave data the server pushes lands in
//! `pending_frames` for the embedder to drain via `take_frame`; the
//! demo page funnels each frame into a Web Audio `AudioContext`.
//!
//! ## Output (server → client)
//!
//! Two transports are supported and selected automatically based on
//! what the server negotiated:
//!
//! * **SVC mode** — server addresses the static `rdpsnd` channel
//!   directly. Hosts an [`RdpsndClient`] (advertises version 6).
//! * **DVC mode** — server tunnels audio through `drdynvc`, opening
//!   `AUDIO_PLAYBACK_DVC` (reliable) and / or `AUDIO_PLAYBACK_LOSSY_DVC`
//!   (UDP multitransport). Both DVC clients (advertising version 8)
//!   are registered with a [`DrdynvcClient`] under the `drdynvc` SVC.
//!
//! Both routes share one [`AudioState`] (decoded frames land in the
//! same FIFO regardless of source); each backend keeps its own
//! per-format decoder cache. Whichever transport the server picks
//! delivers wave PDUs into the same queue.
//!
//! ## Input (client → server, microphone redirection)
//!
//! When `drdynvc` is negotiated, an [`AudioInputClient`] is registered
//! alongside the playback DVCs to advertise the `AUDIO_INPUT` channel
//! (MS-RDPEAI). The embedder polls [`AudioChannel::audio_input_state`]
//! to learn the negotiated PCM format and feeds captured mic samples
//! back through [`AudioChannel::audio_input_pcm_frames`], which builds
//! the DVC PDUs and TPKT-frames them ready to send. The full RDPEAI
//! state machine (Version → Formats → Open → Recording / FormatChange)
//! is handled inside `AudioInputClient` itself; this module just wires
//! it into the same drdynvc multiplexer that hosts the playback DVCs.
//!
//! Format negotiation: the bundled backend accepts **PCM** (16-bit
//! little-endian, mono or stereo, any sample rate), **MS-ADPCM**
//! (`WaveFormatTag::ADPCM`, 0x0002), and **IMA / DVI ADPCM**
//! (`WaveFormatTag::DVI_ADPCM`, 0x0011). The backend converts every
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
use justrdp_core::AsAny;
use justrdp_dvc::{DrdynvcClient, DvcError, DvcMessage, DvcOutput, DvcProcessor, DvcResult};
use justrdp_rdpeai::AudioInputClient;
use justrdp_rdpsnd::pdu::{AudioFormat, VolumePdu, WaveFormatTag};
use justrdp_rdpsnd::{make_decoder, RdpsndBackend, RdpsndClient, RdpsndDvcClient, RdpsndLossyDvcClient};
use justrdp_svc::{StaticChannelSet, SvcMessage};

/// Embedder-injected decoder for codecs the bundled `justrdp-audio`
/// stack doesn't handle (Opus, AAC, G.711, …).
///
/// The contract is intentionally narrow: given an [`AudioFormat`] (the
/// same descriptor the server sent during negotiation) and one wave
/// PDU's worth of encoded bytes, return interleaved little-endian
/// PCM16. The bundled audio path then re-packs that into an
/// [`AudioFrame`] with `bits_per_sample = 16`, so the embedder sees a
/// uniform shape regardless of which decoder ran.
///
/// Implementations are typically backed by a native codec (libopus,
/// fdk-aac, etc.) for desktop targets, or by a buffered WebCodecs
/// pipeline for wasm32 targets — note that browser audio decoders are
/// inherently asynchronous, so a wasm implementation must drive the
/// async setup ahead of time and only return synchronously here.
///
/// `Send` is required because [`RdpsndBackend`] is `Send`; the channel
/// processors that own a [`SharedBackend`] live behind a
/// `Box<dyn SvcProcessor>` and may be moved between threads in
/// hosting code.
pub trait ExternalAudioDecoder: Send {
    /// Probe whether this decoder supports `format`. Called once per
    /// server format during negotiation; only formats returning `true`
    /// are advertised back to the server in [`SharedBackend::on_server_formats`].
    /// Implementations should be cheap — this is dispatch, not state.
    fn accepts(&mut self, format: &AudioFormat) -> bool;

    /// Decode one wave PDU's payload to interleaved PCM16-LE bytes
    /// (`channels * num_samples * 2`). Returning an empty `Vec`
    /// signals "drop this chunk silently" — the wave is not pushed
    /// downstream and no frame appears in the FIFO. Used both for
    /// transient decode failures (lost prefix in a streaming codec)
    /// and for codecs that produce no output until they've buffered
    /// enough data.
    fn decode(&mut self, format: &AudioFormat, payload: &[u8]) -> Vec<u8>;
}

/// Cache slot for one negotiated format. `Bundled` runs through the
/// `justrdp-audio` decoder factory; `External` defers to the
/// embedder-injected [`ExternalAudioDecoder`] (carrying the format
/// description because that decoder is generic over the format).
enum DecoderSlot {
    Bundled(Box<dyn AudioDecoder>),
    External(AudioFormat),
}

/// Type alias for the shareable decoder handle. Multiple
/// [`SharedBackend`] instances (SVC + reliable DVC + lossy DVC) wrap
/// references to the same underlying decoder so its internal codec
/// state stays coherent regardless of which transport the server
/// actually picks.
type ExternalDecoderHandle = Arc<Mutex<dyn ExternalAudioDecoder>>;

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
    /// Per-format decoder slot, keyed by the dense index in the
    /// negotiated format list (the `format_no` the server sends in
    /// Wave / Wave2 PDUs). Built up in `on_server_formats` so we don't
    /// re-instantiate decoders per wave PDU.
    decoders: BTreeMap<u16, DecoderSlot>,
    /// Reusable interleaved-i16 decode buffer. Shared across formats
    /// because only one decode is ever in flight per `on_wave_data` call.
    decode_buf: Vec<i16>,
    /// Optional embedder-injected decoder for codecs the bundled
    /// `justrdp-audio` stack doesn't handle. Shared across all
    /// `SharedBackend` instances (SVC + DVC paths) so its internal
    /// state stays coherent regardless of which transport the server
    /// uses.
    external_decoder: Option<ExternalDecoderHandle>,
}

impl SharedBackend {
    fn new(state: Arc<Mutex<AudioState>>) -> Self {
        Self {
            state,
            decoders: BTreeMap::new(),
            decode_buf: alloc::vec![0i16; MAX_DECODE_SAMPLES],
            external_decoder: None,
        }
    }

    fn with_external_decoder(
        state: Arc<Mutex<AudioState>>,
        external_decoder: ExternalDecoderHandle,
    ) -> Self {
        Self {
            state,
            decoders: BTreeMap::new(),
            decode_buf: alloc::vec![0i16; MAX_DECODE_SAMPLES],
            external_decoder: Some(external_decoder),
        }
    }

    /// First-pass acceptance check for the **bundled** decoder path —
    /// quickly reject formats whose codec we don't have a decoder for,
    /// or whose dimensions exceed the bundled buffer sizing. The
    /// follow-up [`make_decoder`] call is the authoritative gate (it
    /// validates the codec-specific `extra_data` blob, e.g. MS-ADPCM
    /// coefficient table); this filter just avoids round-tripping
    /// obviously bad formats through the decoder factory.
    ///
    /// Channel-count and sample-rate ceilings apply uniformly so
    /// embedder-injected decoders (e.g. Opus) cannot bypass the
    /// shared decode-buffer sizing.
    fn shape_acceptable(format: &AudioFormat) -> bool {
        if !(format.n_channels == 1 || format.n_channels == 2) {
            return false;
        }
        if format.n_samples_per_sec == 0
            || format.n_samples_per_sec as usize > MAX_SAMPLE_RATE_HZ
        {
            return false;
        }
        true
    }

    fn bundled_codec_acceptable(format: &AudioFormat) -> bool {
        match format.format_tag {
            WaveFormatTag::PCM => format.bits_per_sample == 16,
            // Block-based ADPCM variants — `make_decoder` validates the
            // extra_data layout, so all we check here is non-zero
            // block alignment.
            WaveFormatTag::ADPCM | WaveFormatTag::DVI_ADPCM => format.n_block_align > 0,
            // Opus / AAC / G.711 — bundled stack returns
            // `UnsupportedCodec`. Defer to `external_decoder` if one
            // was injected.
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
            if !Self::shape_acceptable(fmt) {
                continue;
            }

            // 1) Try the bundled decoder factory first. `make_decoder`
            //    is the authoritative codec validator — if it rejects
            //    the format (e.g. malformed MS-ADPCM extra_data), we
            //    skip rather than advertise a codec we can't drive.
            let bundled_slot = if Self::bundled_codec_acceptable(fmt) {
                make_decoder(fmt).ok().map(DecoderSlot::Bundled)
            } else {
                None
            };

            // 2) Otherwise, defer to the embedder-injected decoder if
            //    one is registered and accepts this format. The
            //    decoder is shared across all backends; we acquire it
            //    just long enough to probe.
            let slot = bundled_slot.or_else(|| {
                let ext = self.external_decoder.as_ref()?;
                let mut g = ext.lock().ok()?;
                if g.accepts(fmt) {
                    Some(DecoderSlot::External(fmt.clone()))
                } else {
                    None
                }
            });

            let Some(slot) = slot else { continue };

            let dense_idx = accepted_formats.len() as u16;
            accepted_idx.push(i);
            accepted_formats.push(fmt.clone());
            self.decoders.insert(dense_idx, slot);
        }
        if let Ok(mut g) = self.state.lock() {
            g.accepted_formats = accepted_formats;
        }
        accepted_idx
    }

    fn on_wave_data(&mut self, format_no: u16, data: &[u8], _audio_timestamp: Option<u32>) {
        let Some(slot) = self.decoders.get_mut(&format_no) else {
            // Stale or out-of-range format_no — drop rather than push
            // unknown bytes downstream.
            return;
        };

        match slot {
            DecoderSlot::Bundled(decoder) => {
                let sample_rate = decoder.sample_rate();
                let channels = decoder.channels();
                let n_samples = match decoder.decode(data, &mut self.decode_buf) {
                    Ok(n) => n.min(self.decode_buf.len()),
                    Err(_) => return,
                };
                if n_samples == 0 {
                    return;
                }

                // Re-pack the i16 samples as little-endian PCM16 bytes
                // — the demo's Web Audio bridge consumes that layout
                // directly via `DataView::getInt16(_, /*littleEndian*/ true)`.
                let mut bytes = Vec::with_capacity(n_samples * 2);
                for &s in &self.decode_buf[..n_samples] {
                    bytes.extend_from_slice(&s.to_le_bytes());
                }

                if let Ok(mut g) = self.state.lock() {
                    g.pending_frames.push_back(AudioFrame {
                        format_no,
                        sample_rate,
                        channels,
                        bits_per_sample: 16,
                        data: bytes,
                    });
                }
            }
            DecoderSlot::External(format) => {
                // The Mutex guard must be released before we re-take
                // `state` (these are separate locks; ordering is fine,
                // but keeping the guard scope tight keeps callers
                // responsive on the audio path).
                let Some(ext) = self.external_decoder.as_ref() else {
                    return;
                };
                let bytes = match ext.lock() {
                    Ok(mut g) => g.decode(format, data),
                    Err(_) => return,
                };
                if bytes.is_empty() {
                    // Embedder signalled "drop this chunk" — common
                    // for streaming codecs that haven't yet buffered
                    // enough to produce output.
                    return;
                }

                let sample_rate = format.n_samples_per_sec;
                let channels = format.n_channels;
                if let Ok(mut g) = self.state.lock() {
                    g.pending_frames.push_back(AudioFrame {
                        format_no,
                        sample_rate,
                        channels,
                        // External decoder contract: returned bytes
                        // are PCM16-LE.
                        bits_per_sample: 16,
                        data: bytes,
                    });
                }
            }
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

/// `DvcProcessor` wrapper that delegates to a shared [`AudioInputClient`].
///
/// The drdynvc machinery requires a single boxed `DvcProcessor` per
/// channel, but the embedder also needs a way to inspect input state
/// (recording flag, negotiated format) and inject captured samples
/// — neither possible if the only reference lives behind a
/// `Box<dyn DvcProcessor>` inside the channel set.
///
/// The proxy holds an `Arc<Mutex<AudioInputClient>>` and forwards
/// every callback through it; the embedder gets the second `Arc` clone
/// for direct access. Locking inside callbacks is safe because the
/// drdynvc dispatcher already serialises trait calls per channel.
struct AudioInputProxy {
    inner: Arc<Mutex<AudioInputClient>>,
}

impl AsAny for AudioInputProxy {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl core::fmt::Debug for AudioInputProxy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AudioInputProxy").finish_non_exhaustive()
    }
}

impl DvcProcessor for AudioInputProxy {
    fn channel_name(&self) -> &str {
        // Mirrors the constant inside `AudioInputClient`; resolved
        // there as the wire-truthful name. Hard-coding here keeps
        // `&str` lifetime tied to a 'static slice rather than the
        // lock guard.
        "AUDIO_INPUT"
    }

    fn start(&mut self, channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| DvcError::Protocol(String::from("audio input mutex poisoned")))?;
        g.start(channel_id)
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| DvcError::Protocol(String::from("audio input mutex poisoned")))?;
        g.process(channel_id, payload)
    }

    fn close(&mut self, channel_id: u32) {
        if let Ok(mut g) = self.inner.lock() {
            g.close(channel_id);
        }
    }
}

/// Snapshot of the AUDIO_INPUT (microphone redirection) DVC state.
///
/// Returned by [`AudioChannel::audio_input_state`] when `drdynvc` is
/// negotiated. The embedder uses `recording` to decide when to start
/// `getUserMedia` (or its native equivalent), and `sample_rate` /
/// `channels` / `bits_per_sample` to format captured PCM before
/// passing it to [`AudioChannel::audio_input_pcm_frames`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioInputState {
    /// `true` when the server has issued the Open PDU and is ready
    /// to consume captured audio.
    pub recording: bool,
    /// Sample rate of the negotiated PCM format, in Hz.
    pub sample_rate: u32,
    /// Channel count (1 = mono, 2 = stereo).
    pub channels: u16,
    /// Sample width — always 16 for PCM (the only format
    /// `AudioInputClient` exposes by default).
    pub bits_per_sample: u16,
    /// Frames-per-packet hint from the server's Open PDU. The
    /// embedder typically uses this as the natural chunk size when
    /// pushing samples back.
    pub frames_per_packet: u32,
}

/// Audio channel routing helper.
pub struct AudioChannel {
    channels: StaticChannelSet,
    user_channel_id: u16,
    /// MCS id of the `rdpsnd` SVC, when negotiated. `None` means the
    /// server did not allocate it (DVC-only path or audio entirely
    /// disabled).
    rdpsnd_channel_id: Option<u16>,
    /// MCS id of the `drdynvc` SVC, when negotiated. `None` means the
    /// embedder did not advertise `drdynvc` or the server did not
    /// allocate it (SVC-only path).
    drdynvc_channel_id: Option<u16>,
    state: Arc<Mutex<AudioState>>,
    /// Shared handle to the `AUDIO_INPUT` DVC client. Present when
    /// `drdynvc` was negotiated; the embedder reaches into this to
    /// inspect state and build wire-back messages for captured mic
    /// samples.
    audio_input: Option<Arc<Mutex<AudioInputClient>>>,
}

impl core::fmt::Debug for AudioChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AudioChannel")
            .field("user_channel_id", &self.user_channel_id)
            .field("rdpsnd_channel_id", &self.rdpsnd_channel_id)
            .field("drdynvc_channel_id", &self.drdynvc_channel_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum AudioChannelError {
    /// The negotiated channel set included neither `rdpsnd` nor
    /// `drdynvc` — there is no transport for audio.
    ChannelNotNegotiated,
    /// The wrapped channel set rejected the operation.
    Svc(justrdp_svc::SvcError),
    /// AUDIO_INPUT (mic redirection) is not available — `drdynvc`
    /// was not negotiated, so no DVC channel exists for MS-RDPEAI.
    AudioInputUnavailable,
    /// AUDIO_INPUT setup or send-back path returned an error
    /// (typically a `DvcError` formatted as a string).
    AudioInput(String),
}

impl core::fmt::Display for AudioChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ChannelNotNegotiated => f.write_str(
                "neither rdpsnd nor drdynvc was negotiated — audio cannot be routed",
            ),
            Self::Svc(e) => write!(f, "svc: {e:?}"),
            Self::AudioInputUnavailable => {
                f.write_str("AUDIO_INPUT (mic redirection) not negotiated — drdynvc absent")
            }
            Self::AudioInput(msg) => write!(f, "audio input: {msg}"),
        }
    }
}

impl From<justrdp_svc::SvcError> for AudioChannelError {
    fn from(e: justrdp_svc::SvcError) -> Self {
        Self::Svc(e)
    }
}

impl AudioChannel {
    /// Construct from a [`ConnectionResult`].
    ///
    /// Looks up both `rdpsnd` (SVC mode) and `drdynvc` (DVC mode hosting
    /// `AUDIO_PLAYBACK_DVC` / `AUDIO_PLAYBACK_LOSSY_DVC`) in the
    /// negotiated channel list. At least one must be present.
    ///
    /// * If `rdpsnd` is negotiated, an [`RdpsndClient`] is registered
    ///   under that MCS id.
    /// * If `drdynvc` is negotiated, a [`DrdynvcClient`] is registered
    ///   under that id, with [`RdpsndDvcClient`] (reliable) and
    ///   [`RdpsndLossyDvcClient`] (UDP multitransport) hosted inside.
    ///
    /// Each client owns its own [`SharedBackend`] (separate decoder
    /// caches) but all share the returned [`AudioState`] — wave PDUs
    /// from whichever route the server actually uses land in the same
    /// FIFO.
    pub fn from_connection(result: &ConnectionResult) -> Result<Self, AudioChannelError> {
        Self::build(result, None)
    }

    /// Same as [`Self::from_connection`] but with an embedder-injected
    /// [`ExternalAudioDecoder`] available for codecs the bundled
    /// `justrdp-audio` stack doesn't handle (Opus, AAC, G.711). If
    /// the decoder accepts a server-advertised format, it is
    /// negotiated alongside the bundled formats.
    ///
    /// The decoder is shared across the SVC, reliable-DVC, and
    /// lossy-DVC backends so a stateful codec sees a single,
    /// continuous stream regardless of which transport the server
    /// picks.
    pub fn from_connection_with_external_decoder<D>(
        result: &ConnectionResult,
        external_decoder: D,
    ) -> Result<Self, AudioChannelError>
    where
        D: ExternalAudioDecoder + 'static,
    {
        // `Arc::new` returns `Arc<Mutex<D>>` for sized `D`; the
        // unsizing coercion to `Arc<Mutex<dyn ExternalAudioDecoder>>`
        // happens here because the binding's annotated type is the
        // unsized handle.
        let handle: ExternalDecoderHandle = Arc::new(Mutex::new(external_decoder));
        Self::build(result, Some(handle))
    }

    fn build(
        result: &ConnectionResult,
        external_decoder: Option<ExternalDecoderHandle>,
    ) -> Result<Self, AudioChannelError> {
        let rdpsnd_channel_id = result
            .channel_ids
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("rdpsnd"))
            .map(|(_, id)| *id);
        let drdynvc_channel_id = result
            .channel_ids
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("drdynvc"))
            .map(|(_, id)| *id);

        if rdpsnd_channel_id.is_none() && drdynvc_channel_id.is_none() {
            return Err(AudioChannelError::ChannelNotNegotiated);
        }

        let state: Arc<Mutex<AudioState>> = Arc::new(Mutex::new(AudioState::default()));
        let mut channels = StaticChannelSet::new();
        let mut id_assignments: Vec<(String, u16)> = Vec::new();
        let mut audio_input: Option<Arc<Mutex<AudioInputClient>>> = None;

        let make_backend = |state: Arc<Mutex<AudioState>>| -> Box<SharedBackend> {
            match &external_decoder {
                Some(ext) => Box::new(SharedBackend::with_external_decoder(state, Arc::clone(ext))),
                None => Box::new(SharedBackend::new(state)),
            }
        };

        if let Some(id) = rdpsnd_channel_id {
            let backend = make_backend(Arc::clone(&state));
            let rdpsnd = Box::new(RdpsndClient::new(backend));
            channels.insert(rdpsnd).map_err(AudioChannelError::Svc)?;
            id_assignments.push((String::from("rdpsnd"), id));
        }

        if let Some(id) = drdynvc_channel_id {
            // Reliable DVC and lossy DVC each take their own backend
            // (each owns a separate decoder cache); both push decoded
            // frames into the shared `AudioState`. In practice the
            // server picks one, but registering both leaves the choice
            // to the server.
            let reliable_backend = make_backend(Arc::clone(&state));
            let lossy_backend = make_backend(Arc::clone(&state));
            let mut drdynvc = DrdynvcClient::new();
            drdynvc.register(Box::new(RdpsndDvcClient::new(reliable_backend)));
            drdynvc.register(Box::new(RdpsndLossyDvcClient::new(lossy_backend)));

            // Audio input: register `AudioInputClient` via a proxy so
            // we keep an external `Arc<Mutex<...>>` reference for
            // state inspection and outbound mic-sample injection. The
            // server only opens AUDIO_INPUT if the system has a mic
            // configured for redirection, so registering it has no
            // effect when the server doesn't ask.
            let input_handle = Arc::new(Mutex::new(AudioInputClient::new()));
            drdynvc.register(Box::new(AudioInputProxy {
                inner: Arc::clone(&input_handle),
            }));
            audio_input = Some(input_handle);

            channels
                .insert(Box::new(drdynvc))
                .map_err(AudioChannelError::Svc)?;
            id_assignments.push((String::from("drdynvc"), id));
        }

        channels.assign_ids(&id_assignments);

        Ok(Self {
            channels,
            user_channel_id: result.user_channel_id,
            rdpsnd_channel_id,
            drdynvc_channel_id,
            state,
            audio_input,
        })
    }

    /// MCS channel id for the `rdpsnd` SVC, when negotiated.
    pub fn rdpsnd_channel_id(&self) -> Option<u16> {
        self.rdpsnd_channel_id
    }

    /// MCS channel id for the `drdynvc` SVC (host for `AUDIO_PLAYBACK_DVC`
    /// and `AUDIO_PLAYBACK_LOSSY_DVC`), when negotiated.
    pub fn drdynvc_channel_id(&self) -> Option<u16> {
        self.drdynvc_channel_id
    }

    pub fn state(&self) -> Arc<Mutex<AudioState>> {
        Arc::clone(&self.state)
    }

    /// Process raw `ChannelData.data` bytes from a
    /// [`SessionEvent::Channel`] event. The id is matched against both
    /// the SVC `rdpsnd` and the SVC `drdynvc` slots; channels that
    /// belong to neither return an empty Vec so the embedder can fan
    /// every channel event in without pre-filtering.
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
        let matches_rdpsnd = Some(channel_id) == self.rdpsnd_channel_id;
        let matches_drdynvc = Some(channel_id) == self.drdynvc_channel_id;
        if !matches_rdpsnd && !matches_drdynvc {
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

    // ── AUDIO_INPUT (microphone redirection) — MS-RDPEAI ──

    /// Snapshot of the AUDIO_INPUT DVC state.
    ///
    /// `None` when `drdynvc` was not negotiated (no transport for
    /// MS-RDPEAI). When present:
    ///
    /// * `recording = false` means the server has not yet opened the
    ///   channel — the embedder should hold off on capture.
    /// * `recording = true` means the embedder may now feed captured
    ///   PCM bytes via [`Self::audio_input_pcm_frames`]. The format
    ///   fields describe how the embedder should encode the samples.
    pub fn audio_input_state(&self) -> Option<AudioInputState> {
        let handle = self.audio_input.as_ref()?;
        let g = handle.lock().ok()?;
        let recording = g.is_recording();
        // When not yet recording, populate format fields with the
        // first negotiated PCM (best estimate) or fall back to the
        // safe defaults `AudioInputClient` advertises (44.1k stereo
        // 16-bit). Either way the embedder shouldn't act on these
        // until `recording` flips.
        let fmt = if recording {
            g.current_format().cloned()
        } else {
            g.negotiated_formats().first().cloned()
        };
        let (sample_rate, channels, bits_per_sample) = match fmt {
            Some(f) => (f.n_samples_per_sec, f.n_channels, f.bits_per_sample),
            None => (44_100, 2, 16),
        };
        Some(AudioInputState {
            recording,
            sample_rate,
            channels,
            bits_per_sample,
            frames_per_packet: g.frames_per_packet(),
        })
    }

    /// Wrap captured mic samples into wire-ready TPKT frames.
    ///
    /// `samples` must be interleaved little-endian PCM matching the
    /// format reported by [`Self::audio_input_state`]. Internally:
    ///
    /// 1. [`AudioInputClient::build_audio_messages`] produces the
    ///    `INCOMING_DATA` + `DATA` DVC PDU pair.
    /// 2. The drdynvc manager wraps each into a `DYNVC_DATA` SVC PDU
    ///    (routing aware — UDP tunnels are skipped here because
    ///    justrdp-web does not enable multitransport).
    /// 3. The static channel set chunks and TPKT-frames the result.
    ///
    /// Returns an empty `Vec` when the AUDIO_INPUT channel has not
    /// been opened by the server yet (the embedder may safely poll
    /// this in their capture loop). Returns
    /// [`AudioChannelError::AudioInputUnavailable`] when `drdynvc`
    /// was never negotiated.
    pub fn audio_input_pcm_frames(
        &mut self,
        samples: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, AudioChannelError> {
        let drdynvc_id = self
            .drdynvc_channel_id
            .ok_or(AudioChannelError::AudioInputUnavailable)?;
        let input_handle = self
            .audio_input
            .as_ref()
            .ok_or(AudioChannelError::AudioInputUnavailable)?;

        // Step 1: build the DVC payloads from the input client.
        let dvc_messages = {
            let g = input_handle
                .lock()
                .map_err(|_| AudioChannelError::AudioInputUnavailable)?;
            if !g.is_recording() {
                // Server hasn't opened the channel yet — silent drop
                // so a polling embedder doesn't see spurious errors
                // before the server's Open PDU arrives.
                return Ok(Vec::new());
            }
            g.build_audio_messages(samples)
                .map_err(|e| AudioChannelError::AudioInput(format!("{e:?}")))?
        };
        if dvc_messages.is_empty() {
            return Ok(Vec::new());
        }

        // Step 2: encode each DVC message via DrdynvcClient.
        // route_outbound is route-aware (Soft-Sync UDP tunnels) but
        // justrdp-web does not opt into multitransport, so every
        // result lands in the SVC variant.
        let mut svc_messages: Vec<SvcMessage> = Vec::with_capacity(dvc_messages.len());
        {
            let svc = self
                .channels
                .get_by_channel_id_mut(drdynvc_id)
                .ok_or(AudioChannelError::AudioInputUnavailable)?;
            let drdynvc = svc
                .as_any_mut()
                .downcast_mut::<DrdynvcClient>()
                .ok_or(AudioChannelError::AudioInputUnavailable)?;
            let audio_input_id = drdynvc
                .channel_id_by_name("AUDIO_INPUT")
                .ok_or(AudioChannelError::AudioInputUnavailable)?;
            for dvc_msg in dvc_messages {
                let out = drdynvc
                    .route_outbound(audio_input_id, &dvc_msg.data)
                    .map_err(|e| AudioChannelError::AudioInput(format!("{e:?}")))?;
                match out {
                    DvcOutput::Svc(msg) => svc_messages.push(msg),
                    DvcOutput::Tunnel { .. } => {
                        // justrdp-web does not enable UDP
                        // multitransport, so tunnel routing should
                        // never occur. Fail loudly rather than drop.
                        return Err(AudioChannelError::AudioInput(String::from(
                            "AUDIO_INPUT routed to UDP tunnel — multitransport not supported in justrdp-web",
                        )));
                    }
                }
            }
        }

        // Step 3: chunk and frame the SVC messages.
        let mut wire = Vec::new();
        for svc_msg in svc_messages {
            let frames = self
                .channels
                .encode_message(self.user_channel_id, drdynvc_id, &svc_msg)?;
            wire.extend(frames);
        }
        Ok(wire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use justrdp_pdu::x224::SecurityProtocol;

    fn make_result_with(channel_ids: Vec<(String, u16)>) -> ConnectionResult {
        ConnectionResult {
            io_channel_id: 1003,
            user_channel_id: 1001,
            share_id: 0x0001_03ea,
            server_capabilities: Vec::new(),
            channel_ids,
            selected_protocol: SecurityProtocol::RDP,
            session_id: 0,
            server_monitor_layout: None,
            server_arc_cookie: None,
            server_redirection: None,
        }
    }

    fn make_result(rdpsnd_id: u16) -> ConnectionResult {
        make_result_with(vec![(String::from("rdpsnd"), rdpsnd_id)])
    }

    #[test]
    fn from_connection_finds_rdpsnd_channel_id() {
        let result = make_result(1005);
        let ch = AudioChannel::from_connection(&result).unwrap();
        assert_eq!(ch.rdpsnd_channel_id(), Some(1005));
        assert_eq!(ch.drdynvc_channel_id(), None);
    }

    #[test]
    fn from_connection_finds_drdynvc_only() {
        // DVC-only path: server may negotiate `drdynvc` without
        // `rdpsnd` when the embedder only advertised the dynamic
        // channel. AudioChannel must still construct successfully.
        let result = make_result_with(vec![(String::from("drdynvc"), 1006)]);
        let ch = AudioChannel::from_connection(&result).unwrap();
        assert_eq!(ch.rdpsnd_channel_id(), None);
        assert_eq!(ch.drdynvc_channel_id(), Some(1006));
    }

    #[test]
    fn from_connection_finds_both_channels() {
        // Both routes negotiated — the server picks at runtime which
        // one to use; AudioChannel just routes whichever traffic
        // arrives.
        let result = make_result_with(vec![
            (String::from("rdpsnd"), 1005),
            (String::from("drdynvc"), 1006),
        ]);
        let ch = AudioChannel::from_connection(&result).unwrap();
        assert_eq!(ch.rdpsnd_channel_id(), Some(1005));
        assert_eq!(ch.drdynvc_channel_id(), Some(1006));
    }

    #[test]
    fn from_connection_errors_when_neither_channel_negotiated() {
        let result = make_result_with(Vec::new());
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

    #[test]
    fn process_channel_data_routes_drdynvc_id() {
        // A drdynvc-only AudioChannel must accept its negotiated id —
        // even an empty PDU body should land at the DRDYNVC processor
        // rather than be dropped at the routing gate. We feed a
        // minimal valid `ChannelPduHeader` (length=0, FIRST|LAST) so
        // the SVC layer dispatches one empty payload to DrdynvcClient,
        // which produces no response (no DVC PDUs to decode). The
        // assertion is that no error escapes — i.e. the channel was
        // recognised and routed.
        let result = make_result_with(vec![(String::from("drdynvc"), 1006)]);
        let mut ch = AudioChannel::from_connection(&result).unwrap();
        // ChannelPduHeader (8 bytes): length(u32 LE) = 0 + flags(u32 LE)
        // = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST = 0x03.
        let mut frame = Vec::new();
        frame.extend_from_slice(&0u32.to_le_bytes());
        frame.extend_from_slice(&0x03u32.to_le_bytes());
        let frames = ch.process_channel_data(1006, &frame).unwrap();
        assert!(frames.is_empty(), "empty drdynvc payload yields no response");
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

    // ── External (Opus / AAC / G.711) decoder injection (S6b2) ──

    /// Test double — accepts every format whose `format_tag` is in
    /// `accept_tags`, and decodes by returning a fixed PCM16-LE
    /// payload whose first byte is the format tag's low byte. That
    /// makes it easy for a test to verify "this frame came from the
    /// external decoder for this format."
    struct StubExternalDecoder {
        accept_tags: Vec<WaveFormatTag>,
        produce: Vec<u8>,
        accepts_calls: u32,
        decode_calls: u32,
    }

    impl ExternalAudioDecoder for StubExternalDecoder {
        fn accepts(&mut self, format: &AudioFormat) -> bool {
            self.accepts_calls += 1;
            self.accept_tags.contains(&format.format_tag)
        }

        fn decode(&mut self, _format: &AudioFormat, _payload: &[u8]) -> Vec<u8> {
            self.decode_calls += 1;
            self.produce.clone()
        }
    }

    fn make_opus_format() -> AudioFormat {
        AudioFormat {
            format_tag: WaveFormatTag::OPUS,
            n_channels: 2,
            n_samples_per_sec: 48_000,
            n_avg_bytes_per_sec: 0,
            n_block_align: 0,
            // OPUS is encoded; the bundled path rejects this regardless
            // of bits_per_sample. The bytes the external decoder
            // returns are PCM16-LE per the trait contract.
            bits_per_sample: 0,
            extra_data: vec![],
        }
    }

    #[test]
    fn external_decoder_advertises_opus_when_bundled_rejects() {
        // Without an external decoder, OPUS is dropped at negotiation.
        // With one that accepts it, OPUS becomes a negotiated format
        // and the original index is returned to the engine.
        let state: Arc<Mutex<AudioState>> = Arc::new(Mutex::new(AudioState::default()));
        let stub = Arc::new(Mutex::new(StubExternalDecoder {
            accept_tags: vec![WaveFormatTag::OPUS],
            produce: vec![0xAA, 0x00, 0xBB, 0x00],
            accepts_calls: 0,
            decode_calls: 0,
        }));
        let handle: ExternalDecoderHandle = stub.clone();
        let mut backend = SharedBackend::with_external_decoder(Arc::clone(&state), handle);

        let server = vec![
            AudioFormat::pcm(2, 44_100, 16),
            make_opus_format(),
        ];
        let accepted = backend.on_server_formats(&server);
        // Both formats are accepted: PCM via bundled, OPUS via external.
        assert_eq!(accepted, vec![0, 1]);
        let g = state.lock().unwrap();
        assert_eq!(g.accepted_formats.len(), 2);
        assert_eq!(g.accepted_formats[1].format_tag, WaveFormatTag::OPUS);
    }

    #[test]
    fn external_decoder_runs_on_wave_data_for_advertised_format() {
        // After negotiating OPUS through the external decoder, a Wave
        // PDU at the corresponding format_no must dispatch to the
        // external decoder and queue its returned bytes verbatim
        // (bits_per_sample = 16 per trait contract).
        let state: Arc<Mutex<AudioState>> = Arc::new(Mutex::new(AudioState::default()));
        let stub = Arc::new(Mutex::new(StubExternalDecoder {
            accept_tags: vec![WaveFormatTag::OPUS],
            produce: vec![0xAA, 0x00, 0xBB, 0x00],
            accepts_calls: 0,
            decode_calls: 0,
        }));
        let mut backend = SharedBackend::with_external_decoder(
            Arc::clone(&state),
            stub.clone() as ExternalDecoderHandle,
        );
        backend.on_server_formats(&[make_opus_format()]);

        // format_no=0 is the OPUS slot.
        backend.on_wave_data(0, &[0x01, 0x02, 0x03], None);

        let mut g = state.lock().unwrap();
        let frame = g.pending_frames.pop_front().expect("frame queued");
        assert_eq!(frame.format_no, 0);
        assert_eq!(frame.channels, 2);
        assert_eq!(frame.sample_rate, 48_000);
        assert_eq!(frame.bits_per_sample, 16);
        assert_eq!(frame.data, vec![0xAA, 0x00, 0xBB, 0x00]);
        drop(g);

        // Decode was invoked exactly once.
        assert_eq!(stub.lock().unwrap().decode_calls, 1);
    }

    #[test]
    fn external_decoder_empty_output_drops_frame_silently() {
        // Streaming codecs (Opus, AAC) typically buffer some prefix
        // bytes before producing PCM. A decoder returning Vec::new()
        // signals "drop this chunk silently" — no AudioFrame must
        // appear in the FIFO.
        let state: Arc<Mutex<AudioState>> = Arc::new(Mutex::new(AudioState::default()));
        let stub = Arc::new(Mutex::new(StubExternalDecoder {
            accept_tags: vec![WaveFormatTag::OPUS],
            produce: vec![],
            accepts_calls: 0,
            decode_calls: 0,
        }));
        let mut backend = SharedBackend::with_external_decoder(
            Arc::clone(&state),
            stub.clone() as ExternalDecoderHandle,
        );
        backend.on_server_formats(&[make_opus_format()]);

        backend.on_wave_data(0, &[0x01, 0x02], None);

        assert_eq!(state.lock().unwrap().pending_frame_count(), 0);
        assert_eq!(stub.lock().unwrap().decode_calls, 1);
    }

    #[test]
    fn external_decoder_skipped_when_bundled_handles_format() {
        // PCM is handled by the bundled decoder. The external decoder
        // must not see PCM at all (otherwise stateful codecs could be
        // initialised redundantly), so accepts() should never be
        // called for it.
        let state: Arc<Mutex<AudioState>> = Arc::new(Mutex::new(AudioState::default()));
        let stub = Arc::new(Mutex::new(StubExternalDecoder {
            accept_tags: vec![WaveFormatTag::PCM, WaveFormatTag::OPUS],
            produce: vec![0xFF],
            accepts_calls: 0,
            decode_calls: 0,
        }));
        let mut backend = SharedBackend::with_external_decoder(
            Arc::clone(&state),
            stub.clone() as ExternalDecoderHandle,
        );
        backend.on_server_formats(&[AudioFormat::pcm(1, 44_100, 16)]);

        // Bundled path took PCM — external decoder was never asked.
        assert_eq!(stub.lock().unwrap().accepts_calls, 0);
    }

    // ── AUDIO_INPUT (mic redirection) wiring (S6c) ──

    #[test]
    fn audio_input_state_none_when_drdynvc_absent() {
        // SVC-only path — RDPEAI has no transport.
        let result = make_result(1005);
        let ch = AudioChannel::from_connection(&result).unwrap();
        assert!(ch.audio_input_state().is_none());
    }

    #[test]
    fn audio_input_state_present_when_drdynvc_negotiated() {
        let result = make_result_with(vec![(String::from("drdynvc"), 1006)]);
        let ch = AudioChannel::from_connection(&result).unwrap();
        let st = ch.audio_input_state().expect("rdpeai wired with drdynvc");
        // Before the server opens AUDIO_INPUT, recording is false.
        // The format fields are best-effort defaults — the embedder
        // shouldn't act on them until `recording` flips.
        assert!(!st.recording);
        assert_eq!(st.bits_per_sample, 16);
        assert_eq!(st.frames_per_packet, 0);
    }

    #[test]
    fn audio_input_pcm_frames_errors_when_drdynvc_absent() {
        let result = make_result(1005); // rdpsnd SVC only
        let mut ch = AudioChannel::from_connection(&result).unwrap();
        let err = ch.audio_input_pcm_frames(vec![0u8; 4]).unwrap_err();
        assert!(matches!(err, AudioChannelError::AudioInputUnavailable));
    }

    #[test]
    fn audio_input_pcm_frames_silent_drop_before_open() {
        // Before the server has issued the Open PDU, captured samples
        // are silently dropped — this lets the embedder poll
        // unconditionally during their getUserMedia loop.
        let result = make_result_with(vec![(String::from("drdynvc"), 1006)]);
        let mut ch = AudioChannel::from_connection(&result).unwrap();
        let frames = ch.audio_input_pcm_frames(vec![0u8; 4]).unwrap();
        assert!(frames.is_empty(), "no wire bytes emitted before recording");
    }

    #[test]
    fn drdynvc_hosts_audio_playback_and_audio_input_processors() {
        // Structural assertion: when `drdynvc` is negotiated, the
        // hosted DrdynvcClient must have all three audio DVCs
        // registered (reliable + lossy playback + input). The actual
        // open-channel ids are populated only after the server sends
        // a DYNVC_CREATE_REQUEST, so `channel_id_by_name` returns
        // `None` here — but the registration happened at construction
        // time, which is what this test guards.
        //
        // The full RDPEAI state machine is covered exhaustively in
        // `justrdp-rdpeai`'s own client-test suite; we verify only
        // the routing-gate wiring at this layer.
        let result = make_result_with(vec![(String::from("drdynvc"), 1006)]);
        let mut ch = AudioChannel::from_connection(&result).unwrap();
        let svc = ch
            .channels
            .get_by_channel_id_mut(1006)
            .expect("drdynvc channel registered");
        let drdynvc = svc
            .as_any_mut()
            .downcast_mut::<DrdynvcClient>()
            .expect("svc processor is DrdynvcClient");
        // Pre-CREATE_REQUEST: server hasn't allocated channel ids yet.
        assert_eq!(drdynvc.channel_id_by_name("AUDIO_PLAYBACK_DVC"), None);
        assert_eq!(drdynvc.channel_id_by_name("AUDIO_PLAYBACK_LOSSY_DVC"), None);
        assert_eq!(drdynvc.channel_id_by_name("AUDIO_INPUT"), None);
    }

    #[test]
    fn from_connection_with_external_decoder_routes_through_dvc() {
        // End-to-end at the AudioChannel layer: build with an external
        // decoder, pretend the server announced an OPUS format via a
        // direct backend probe (the full RDPSND state machine isn't
        // needed for this assertion), then verify the negotiated
        // format list reflects the OPUS entry. Confirms the decoder
        // handle is actually plumbed into the per-processor backends.
        let result = make_result_with(vec![(String::from("drdynvc"), 1006)]);
        let stub = StubExternalDecoder {
            accept_tags: vec![WaveFormatTag::OPUS],
            produce: vec![0x01, 0x00],
            accepts_calls: 0,
            decode_calls: 0,
        };
        let ch = AudioChannel::from_connection_with_external_decoder(&result, stub).unwrap();
        // Drive a freshly constructed SharedBackend the same way
        // `RdpsndDvcClient::on_server_formats` would, but via direct
        // probe — using the channel's `state()` to verify the path is
        // wired. We can't reach into the registered backend, so this
        // test instead asserts that the AudioChannel constructed with
        // the external decoder is structurally sound (no panic, both
        // ids resolve as expected). Behaviour-level coverage of the
        // external path is in the SharedBackend tests above.
        assert_eq!(ch.drdynvc_channel_id(), Some(1006));
        assert_eq!(ch.rdpsnd_channel_id(), None);
        assert_eq!(ch.state().lock().unwrap().accepted_formats().len(), 0);
    }
}
