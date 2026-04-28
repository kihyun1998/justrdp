#![forbid(unsafe_code)]

//! Audio output channel routing on top of `justrdp-rdpsnd` (MS-RDPEA).
//!
//! [`AudioChannel`] hosts an [`RdpsndClient`] inside a
//! [`StaticChannelSet`] with a shared [`AudioState`] backend. Wave data
//! the server pushes lands in `pending_frames` for the embedder to
//! drain via `take_frame`; the demo page funnels each frame into a
//! Web Audio `AudioContext`.
//!
//! Format negotiation: the bundled backend accepts only **PCM** (16-bit
//! little-endian, mono or stereo, any sample rate). Other codecs
//! (ADPCM / Opus / AAC) need a browser-side decoder or a server-side
//! fall-back; the trait surface is the right place for those follow-ups
//! (see S6b in the roadmap).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use std::sync::{Arc, Mutex};

use justrdp_connector::ConnectionResult;
use justrdp_rdpsnd::pdu::{AudioFormat, VolumePdu, WaveFormatTag};
use justrdp_rdpsnd::{RdpsndBackend, RdpsndClient};
use justrdp_svc::StaticChannelSet;

/// One decoded audio chunk pulled off the wire.
#[derive(Debug, Clone)]
pub struct AudioFrame {
    /// Index into the negotiated format list (`accepted_formats`).
    pub format_no: u16,
    /// Sample rate in Hz (e.g. 44100).
    pub sample_rate: u32,
    /// Channel count (1 = mono, 2 = stereo).
    pub channels: u16,
    /// Sample width in bits (currently always 16 — only PCM 16 is wired).
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
}

impl SharedBackend {
    /// PCM 16-bit only — single-channel and stereo at any sample rate.
    /// Other codecs would need a browser-side decoder or transcoder.
    fn accept(format: &AudioFormat) -> bool {
        format.format_tag == WaveFormatTag::PCM
            && format.bits_per_sample == 16
            && (format.n_channels == 1 || format.n_channels == 2)
    }
}

impl RdpsndBackend for SharedBackend {
    fn on_server_formats(&mut self, server_formats: &[AudioFormat]) -> Vec<usize> {
        let mut accepted_idx = Vec::new();
        let mut accepted_formats = Vec::new();
        for (i, fmt) in server_formats.iter().enumerate() {
            if Self::accept(fmt) {
                accepted_idx.push(i);
                accepted_formats.push(fmt.clone());
            }
        }
        if let Ok(mut g) = self.state.lock() {
            g.accepted_formats = accepted_formats;
        }
        accepted_idx
    }

    fn on_wave_data(&mut self, format_no: u16, data: &[u8], _audio_timestamp: Option<u32>) {
        if let Ok(mut g) = self.state.lock() {
            // The format_no indexes our *accepted* list; pull dimensions
            // out of it so the embedder doesn't have to re-derive them.
            let Some(fmt) = g.accepted_formats.get(format_no as usize).cloned() else {
                // Stale or out-of-range format_no — drop the chunk
                // rather than dispatching unknown bytes.
                return;
            };
            g.pending_frames.push_back(AudioFrame {
                format_no,
                sample_rate: fmt.n_samples_per_sec,
                channels: fmt.n_channels,
                bits_per_sample: fmt.bits_per_sample,
                data: data.to_vec(),
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
    /// [`RdpsndClient`] with the bundled PCM-only backend.
    pub fn from_connection(result: &ConnectionResult) -> Result<Self, AudioChannelError> {
        let rdpsnd_channel_id = result
            .channel_ids
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("rdpsnd"))
            .map(|(_, id)| *id)
            .ok_or(AudioChannelError::ChannelNotNegotiated)?;

        let state: Arc<Mutex<AudioState>> = Arc::new(Mutex::new(AudioState::default()));
        let backend = Box::new(SharedBackend {
            state: Arc::clone(&state),
        });
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
