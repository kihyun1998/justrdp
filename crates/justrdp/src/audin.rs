//! The audio input channel (MS-RDPEAI) as a sans-IO helper the host drives over the dynamic
//! channel `AUDIO_INPUT` (ADR-0018). The host feeds each message on the channel to
//! [`AudioInput::process`] and sends every [`AudioInputEvent::Send`] back on it. When the server
//! asks to record, the host opens its device and answers through [`AudioInput::open_reply`];
//! from then on it hands captured samples to [`AudioInput::push`], which returns the messages
//! that carry them.
//!
//! The host chooses the formats it can record in, in preference order, by `wFormatTag`; the
//! helper answers the server's list with every server format of those tags that the core
//! encodes, copied as the server sent it, so the client list is always a subset of the server's
//! (3.2.5.1.5). Malformed, unknown and out-of-sequence messages are ignored, as 3.1.5 requires.

use justrdp_codecs::{g711, pcm};
use justrdp_pdu::audin::{self as pdu, AudioFormat, ServerPdu};
use justrdp_pdu::rdpsnd::{WAVE_FORMAT_ALAW, WAVE_FORMAT_PCM};

/// The `HRESULT` severity bit, set on an error code (`[MS-ERREF]` 2.1).
const HRESULT_SEVERITY_ERROR: u32 = 0x8000_0000;

/// The protocol version this helper advertises (2.2.2.1).
pub const CLIENT_VERSION: u32 = 0x0000_0002;

/// The `wFormatTag`s the core encodes.
pub const ENCODABLE_FORMAT_TAGS: &[u16] = &[WAVE_FORMAT_PCM, WAVE_FORMAT_ALAW];

/// How samples of one client format encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoder {
    /// Linear PCM at this many bits.
    Pcm(u16),
    /// G.711 A-law.
    Alaw,
}

impl Encoder {
    /// The encoder for `format`, or `None` when the core does not encode it. PCM at 8 or 16 bits
    /// and A-law at 8 need at least one channel and a block of exactly one frame.
    fn for_format(format: &AudioFormat) -> Option<Self> {
        let one_frame = format.channels > 0
            && u32::from(format.block_align)
                == u32::from(format.channels) * u32::from(format.bits_per_sample / 8);
        match (format.format_tag, format.bits_per_sample) {
            (WAVE_FORMAT_PCM, bits @ (8 | 16)) if one_frame => Some(Encoder::Pcm(bits)),
            (WAVE_FORMAT_ALAW, 8) if one_frame => Some(Encoder::Alaw),
            _ => None,
        }
    }

    /// `samples` in this format.
    fn encode(self, samples: &[i16]) -> Vec<u8> {
        match self {
            Encoder::Pcm(bits) => {
                pcm::encode(bits, samples).expect("the depth was checked at negotiation")
            }
            Encoder::Alaw => g711::encode_alaw(samples),
        }
    }
}

/// What the host offers the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioInputConfig {
    /// The `wFormatTag`s the host records in, most preferred first, each once.
    pub format_tags: Vec<u16>,
}

impl Default for AudioInputConfig {
    /// PCM.
    fn default() -> Self {
        Self {
            format_tags: vec![WAVE_FORMAT_PCM],
        }
    }
}

/// Why an [`AudioInputConfig`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioInputConfigError {
    /// The core cannot encode this format tag.
    UnencodableFormat {
        /// The tag.
        format_tag: u16,
    },
    /// This format tag is listed more than once, which would list its formats more than once.
    RepeatedFormatTag {
        /// The tag.
        format_tag: u16,
    },
}

impl core::fmt::Display for AudioInputConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AudioInputConfigError::UnencodableFormat { format_tag } => {
                write!(
                    f,
                    "audio format tag {format_tag:#06x} is not one the core encodes"
                )
            }
            AudioInputConfigError::RepeatedFormatTag { format_tag } => {
                write!(f, "audio format tag {format_tag:#06x} is listed twice")
            }
        }
    }
}

impl core::error::Error for AudioInputConfigError {}

/// What processing one audio input message produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioInputEvent {
    /// A message to send on the audio input channel.
    Send(Vec<u8>),
    /// The formats this side answered the server's list with, in order. An empty list means the
    /// server offers no format of the host's tags that the core encodes, and it will not ask to
    /// record.
    Negotiated(Vec<AudioFormat>),
    /// The server asks to start recording. The host opens its device and answers with
    /// [`AudioInput::open_reply`].
    Open {
        /// The format the samples are sent in: the host pushes interleaved samples of
        /// `format.channels` channels at `format.samples_per_sec` frames a second.
        format: AudioFormat,
        /// The format the server suggests capturing from the device in (2.2.2.3).
        capture_format: AudioFormat,
        /// The Open PDU's `FramesPerPacket`, counted in `capture_format`: each Data PDU lasts
        /// that many of its frames.
        frames_per_packet: u32,
    },
    /// The server switched to another format from the client's list. Samples the helper held
    /// for the old format are dropped, and the host pushes in this one from now on.
    FormatChanged(AudioFormat),
}

/// Where the protocol stands (3.1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Waiting for the server's Version PDU.
    Version,
    /// Waiting for the server's Sound Formats PDU.
    Formats,
    /// Formats agreed; waiting for an Open PDU.
    Negotiated,
    /// An Open PDU is waiting for the host's answer.
    Opening(Recording),
    /// The device is open and samples are sent.
    Recording(Recording),
}

/// The format samples are sent in, and how many frames a packet holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Recording {
    /// Its index in the client's format list.
    format_no: usize,
    /// The Open PDU's `FramesPerPacket`.
    frames_per_packet: u32,
    /// The `nSamplesPerSec` of the Open PDU's capture format.
    capture_rate: u32,
    /// The samples one Data PDU carries: as many frames as last `FramesPerPacket` frames of the
    /// capture format, of the format's channels.
    packet_samples: usize,
}

/// The audio input protocol state.
#[derive(Debug, Clone)]
pub struct AudioInput {
    config: AudioInputConfig,
    /// The formats this side sent, indexed as the server's `initialFormat` and `NewFormat` are,
    /// each with its encoder.
    client_formats: Vec<(AudioFormat, Encoder)>,
    stage: Stage,
    /// Samples pushed and not yet sent: less than one packet.
    pending: Vec<i16>,
}

impl AudioInput {
    /// An audio input waiting for the server's Version PDU. A format tag the core does not
    /// encode, or one listed twice, is refused.
    pub fn new(config: AudioInputConfig) -> Result<Self, AudioInputConfigError> {
        for (at, &format_tag) in config.format_tags.iter().enumerate() {
            if !ENCODABLE_FORMAT_TAGS.contains(&format_tag) {
                return Err(AudioInputConfigError::UnencodableFormat { format_tag });
            }
            if config.format_tags[..at].contains(&format_tag) {
                return Err(AudioInputConfigError::RepeatedFormatTag { format_tag });
            }
        }
        Ok(Self {
            config,
            client_formats: Vec::new(),
            stage: Stage::Version,
            pending: Vec::new(),
        })
    }

    /// Consume one whole message from the audio input channel.
    pub fn process(&mut self, message: &[u8]) -> Vec<AudioInputEvent> {
        let pdu = match ServerPdu::decode(message) {
            Ok(pdu) => pdu,
            Err(error) => {
                tracing::warn!(target: "rdp_audin", %error, "malformed audio input PDU ignored");
                return Vec::new();
            }
        };
        match (pdu, self.stage) {
            (ServerPdu::Version(server_version), Stage::Version) => {
                tracing::debug!(target: "rdp_audin", server_version, "audio input version");
                self.stage = Stage::Formats;
                vec![AudioInputEvent::Send(pdu::encode_version(CLIENT_VERSION))]
            }
            (ServerPdu::Formats(formats), Stage::Formats) => {
                self.stage = Stage::Negotiated;
                self.negotiate(&formats)
            }
            (ServerPdu::Open(open), Stage::Negotiated) => self.open(open),
            (ServerPdu::FormatChange(new_format), Stage::Recording(current)) => {
                self.format_change(current, new_format)
            }
            (ServerPdu::Unknown { message_id }, _) => {
                tracing::debug!(target: "rdp_audin", message_id, "unknown audio input PDU ignored");
                Vec::new()
            }
            (pdu, stage) => {
                tracing::debug!(
                    target: "rdp_audin",
                    ?pdu,
                    ?stage,
                    "out-of-sequence audio input PDU ignored"
                );
                Vec::new()
            }
        }
    }

    /// Answer the server's format list: every server format the core encodes whose tag the host
    /// records in, in the host's order of tags and the server's within a tag.
    fn negotiate(&mut self, server_formats: &[AudioFormat]) -> Vec<AudioInputEvent> {
        self.client_formats = self
            .config
            .format_tags
            .iter()
            .flat_map(|tag| server_formats.iter().filter(move |f| f.format_tag == *tag))
            .filter_map(|f| Encoder::for_format(f).map(|encoder| (f.clone(), encoder)))
            .collect();
        let formats: Vec<AudioFormat> =
            self.client_formats.iter().map(|(f, _)| f.clone()).collect();
        tracing::debug!(
            target: "rdp_audin",
            server_formats = server_formats.len(),
            client_formats = formats.len(),
            "audio input formats negotiated"
        );
        vec![
            AudioInputEvent::Send(pdu::encode_incoming_data()),
            AudioInputEvent::Send(pdu::encode_formats(&formats)),
            AudioInputEvent::Negotiated(formats),
        ]
    }

    /// The recording that `format_no`, `frames_per_packet` and `capture_rate` name, or `None`
    /// when the index is past the client's list, `frames_per_packet` is zero, or a packet would
    /// hold more than one second of the format. A packet lasts `frames_per_packet` frames at
    /// `capture_rate`, and at least one frame; with no `capture_rate` it holds
    /// `frames_per_packet` frames.
    fn recording(
        &self,
        format_no: u32,
        frames_per_packet: u32,
        capture_rate: u32,
    ) -> Option<Recording> {
        let format_no = usize::try_from(format_no).ok()?;
        let (format, _) = self.client_formats.get(format_no)?;
        if frames_per_packet == 0 {
            return None;
        }
        let packet_frames = match capture_rate {
            0 => u64::from(frames_per_packet),
            rate => (u64::from(frames_per_packet) * u64::from(format.samples_per_sec)
                / u64::from(rate))
            .max(1),
        };
        if packet_frames > u64::from(format.samples_per_sec) {
            return None;
        }
        let packet_samples = usize::try_from(packet_frames)
            .ok()?
            .checked_mul(usize::from(format.channels))?;
        (packet_samples > 0).then_some(Recording {
            format_no,
            frames_per_packet,
            capture_rate,
            packet_samples,
        })
    }

    /// Confirm an Open PDU's initial format and hand the request to the host.
    fn open(&mut self, open: pdu::Open) -> Vec<AudioInputEvent> {
        let Some(recording) = self.recording(
            open.initial_format,
            open.frames_per_packet,
            open.capture_format.samples_per_sec,
        ) else {
            tracing::warn!(
                target: "rdp_audin",
                initial_format = open.initial_format,
                frames_per_packet = open.frames_per_packet,
                "Open PDU ignored: it names no format in the client's list, or no frames, or \
                 more than a second of them"
            );
            return Vec::new();
        };
        self.stage = Stage::Opening(recording);
        vec![
            AudioInputEvent::Send(pdu::encode_format_change(open.initial_format)),
            AudioInputEvent::Open {
                format: self.client_formats[recording.format_no].0.clone(),
                capture_format: open.capture_format,
                frames_per_packet: open.frames_per_packet,
            },
        ]
    }

    /// Confirm a Format Change PDU, dropping the partial packet held for the old format.
    fn format_change(&mut self, current: Recording, new_format: u32) -> Vec<AudioInputEvent> {
        let Some(recording) =
            self.recording(new_format, current.frames_per_packet, current.capture_rate)
        else {
            tracing::warn!(
                target: "rdp_audin",
                new_format,
                "Format Change PDU ignored: it names no format in the client's list, or one \
                 a packet holds more than a second of"
            );
            return Vec::new();
        };
        self.stage = Stage::Recording(recording);
        self.pending.clear();
        vec![
            AudioInputEvent::Send(pdu::encode_format_change(new_format)),
            AudioInputEvent::FormatChanged(self.client_formats[recording.format_no].0.clone()),
        ]
    }

    /// Answer the Open PDU with the `HRESULT` of opening the host's device: the Open Reply PDU
    /// to send. A success code starts recording; an error code does not, and the server may
    /// send another Open PDU (3.3.5.1.8). `None` when no Open PDU is waiting for an answer.
    pub fn open_reply(&mut self, result: u32) -> Option<Vec<u8>> {
        let Stage::Opening(recording) = self.stage else {
            return None;
        };
        self.stage = if result & HRESULT_SEVERITY_ERROR == 0 {
            Stage::Recording(recording)
        } else {
            Stage::Negotiated
        };
        Some(pdu::encode_open_reply(result))
    }

    /// Take captured samples, interleaved, in the format of the last [`AudioInputEvent::Open`]
    /// or [`AudioInputEvent::FormatChanged`], in pieces of any length. Returns the messages to
    /// send: an Incoming Data PDU and a Data PDU for every packet now held (3.2.5.2), a packet
    /// lasting `FramesPerPacket` frames of the Open's capture format. Samples pushed while not
    /// recording are dropped.
    pub fn push(&mut self, samples: &[i16]) -> Vec<Vec<u8>> {
        let Stage::Recording(recording) = self.stage else {
            return Vec::new();
        };
        let encoder = self.client_formats[recording.format_no].1;
        self.pending.extend_from_slice(samples);
        let mut out = Vec::new();
        let mut packets = self.pending.chunks_exact(recording.packet_samples);
        for packet in &mut packets {
            out.push(pdu::encode_incoming_data());
            out.push(pdu::encode_data(&encoder.encode(packet)));
        }
        let held = packets.remainder().len();
        let sent = self.pending.len() - held;
        self.pending.drain(..sent);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::audin::{
        MSG_SNDIN_DATA, MSG_SNDIN_DATA_INCOMING, MSG_SNDIN_FORMATCHANGE, MSG_SNDIN_FORMATS,
        MSG_SNDIN_OPEN, MSG_SNDIN_VERSION, encode_format_change, encode_formats,
    };
    use justrdp_pdu::rdpsnd::WAVE_FORMAT_ADPCM;

    const E_FAIL: u32 = 0x8000_4005;

    /// `WAVE_FORMAT_GSM610`, which the core does not encode.
    const WAVE_FORMAT_GSM610: u16 = 0x0031;

    fn format(format_tag: u16, channels: u16, rate: u32, bits: u16) -> AudioFormat {
        let block_align = channels * bits / 8;
        AudioFormat {
            format_tag,
            channels,
            samples_per_sec: rate,
            avg_bytes_per_sec: rate * u32::from(block_align),
            block_align,
            bits_per_sample: bits,
            extra: Vec::new(),
        }
    }

    fn pcm(channels: u16, rate: u32, bits: u16) -> AudioFormat {
        format(WAVE_FORMAT_PCM, channels, rate, bits)
    }

    fn server_version(version: u32) -> Vec<u8> {
        let mut out = vec![MSG_SNDIN_VERSION];
        out.extend_from_slice(&version.to_le_bytes());
        out
    }

    /// A server Sound Formats PDU; its `cbSizeFormatsPacket` is arbitrary on the wire, so the
    /// client encoding stands in.
    fn server_formats(formats: &[AudioFormat]) -> Vec<u8> {
        encode_formats(formats)
    }

    fn server_open(frames_per_packet: u32, initial_format: u32, capture: &AudioFormat) -> Vec<u8> {
        let mut out = vec![MSG_SNDIN_OPEN];
        out.extend_from_slice(&frames_per_packet.to_le_bytes());
        out.extend_from_slice(&initial_format.to_le_bytes());
        let one = encode_formats(std::slice::from_ref(capture));
        out.extend_from_slice(&one[9..]);
        out
    }

    /// An audio input that has agreed `formats` with the server.
    fn negotiated(tags: &[u16], formats: &[AudioFormat]) -> AudioInput {
        let mut input = AudioInput::new(AudioInputConfig {
            format_tags: tags.to_vec(),
        })
        .unwrap();
        input.process(&server_version(1));
        input.process(&server_formats(formats));
        input
    }

    /// An audio input recording in client format 0 with `frames_per_packet`.
    fn recording(format: AudioFormat, frames_per_packet: u32) -> AudioInput {
        let mut input = negotiated(&[WAVE_FORMAT_PCM], std::slice::from_ref(&format));
        input.process(&server_open(frames_per_packet, 0, &format));
        input.open_reply(0).unwrap();
        input
    }

    #[test]
    fn a_format_tag_the_core_cannot_encode_or_listed_twice_is_refused() {
        assert_eq!(
            AudioInput::new(AudioInputConfig {
                format_tags: vec![WAVE_FORMAT_GSM610]
            })
            .err(),
            Some(AudioInputConfigError::UnencodableFormat {
                format_tag: WAVE_FORMAT_GSM610
            })
        );
        assert_eq!(
            AudioInput::new(AudioInputConfig {
                format_tags: vec![WAVE_FORMAT_PCM, WAVE_FORMAT_PCM]
            })
            .err(),
            Some(AudioInputConfigError::RepeatedFormatTag {
                format_tag: WAVE_FORMAT_PCM
            })
        );
    }

    /// The client acknowledges the server's Version PDU with its own (3.2.5.1.2), whatever the
    /// server's version.
    #[test]
    fn the_version_pdu_is_answered_with_the_clients() {
        for version in [1, 2, 3] {
            let mut input = AudioInput::new(AudioInputConfig::default()).unwrap();
            assert_eq!(
                input.process(&server_version(version)),
                [AudioInputEvent::Send(pdu::encode_version(CLIENT_VERSION))]
            );
        }
    }

    /// The client answers with the server's formats of the host's tags that the core encodes,
    /// in the host's order of tags and the server's within a tag, after an Incoming Data PDU
    /// (3.2.5.1.4, 3.2.5.1.5).
    #[test]
    fn the_answer_is_the_encodable_server_formats_after_an_incoming_data_pdu() {
        let server = [
            format(WAVE_FORMAT_ADPCM, 2, 44100, 4),
            pcm(2, 44100, 16),
            pcm(1, 22050, 24),
            pcm(1, 22050, 8),
            format(WAVE_FORMAT_ALAW, 1, 8000, 8),
        ];
        let mut input = AudioInput::new(AudioInputConfig::default()).unwrap();
        input.process(&server_version(1));
        let events = input.process(&server_formats(&server));
        let expected = vec![server[1].clone(), server[3].clone()];
        assert_eq!(
            events,
            [
                AudioInputEvent::Send(pdu::encode_incoming_data()),
                AudioInputEvent::Send(encode_formats(&expected)),
                AudioInputEvent::Negotiated(expected),
            ]
        );
    }

    /// A PCM format whose block is not exactly one frame is not encoded, so it is not offered.
    #[test]
    fn a_pcm_format_whose_block_is_not_one_frame_is_not_offered() {
        let mut odd = pcm(2, 44100, 16);
        odd.block_align = 2;
        let mut silent = pcm(1, 44100, 16);
        silent.channels = 0;
        let mut input = AudioInput::new(AudioInputConfig::default()).unwrap();
        input.process(&server_version(1));
        let events = input.process(&server_formats(&[odd, silent]));
        assert_eq!(
            events.last(),
            Some(&AudioInputEvent::Negotiated(Vec::new()))
        );
    }

    /// An Open PDU is confirmed with a Format Change PDU naming its initial format before the
    /// host answers (3.2.5.1.7), and the host learns the format to push in.
    #[test]
    fn an_open_pdu_is_confirmed_by_a_format_change_then_reaches_the_host() {
        let formats = [pcm(2, 44100, 16), pcm(1, 22050, 16)];
        let mut input = negotiated(&[WAVE_FORMAT_PCM], &formats);
        let capture = pcm(2, 48000, 16);
        assert_eq!(
            input.process(&server_open(441, 1, &capture)),
            [
                AudioInputEvent::Send(encode_format_change(1)),
                AudioInputEvent::Open {
                    format: formats[1].clone(),
                    capture_format: capture,
                    frames_per_packet: 441,
                },
            ]
        );
        assert_eq!(input.open_reply(0), Some(pdu::encode_open_reply(0)));
    }

    #[test]
    fn an_open_reply_needs_an_open_pdu_waiting() {
        let mut input = negotiated(&[WAVE_FORMAT_PCM], &[pcm(1, 8000, 16)]);
        assert_eq!(input.open_reply(0), None);
        input.process(&server_open(10, 0, &pcm(1, 8000, 16)));
        assert!(input.open_reply(0).is_some());
        assert_eq!(input.open_reply(0), None);
    }

    /// Each `FramesPerPacket` frames pushed leave as an Incoming Data PDU and a Data PDU
    /// (3.2.5.2.1, 3.2.5.2.2), however the host splits its pushes.
    #[test]
    fn samples_leave_in_packets_of_frames_per_packet_frames_whatever_the_push_sizes() {
        let mut input = recording(pcm(2, 44100, 16), 3);
        let samples: Vec<i16> = (1..=14).collect();
        let mut out = Vec::new();
        for piece in [
            &samples[..1],
            &samples[1..5],
            &samples[5..13],
            &samples[13..],
        ] {
            out.extend(input.push(piece));
        }
        let data = |s: &[i16]| pdu::encode_data(&pcm::encode(16, s).unwrap());
        assert_eq!(
            out,
            [
                pdu::encode_incoming_data(),
                data(&samples[..6]),
                pdu::encode_incoming_data(),
                data(&samples[6..12]),
            ]
        );
        // Two samples, one frame, are held for the next packet.
        assert_eq!(input.push(&[15, 16, 17, 18]).len(), 2);
    }

    /// A host listing A-law answers with the server's 8-bit A-law formats of one-frame blocks,
    /// such as the Windows 11 server's one, 22.05 kHz stereo (#404), and pushes A-law bytes.
    #[test]
    fn a_host_listing_alaw_negotiates_and_encodes_it() {
        let alaw = format(WAVE_FORMAT_ALAW, 2, 22050, 8);
        let alaw_16 = format(WAVE_FORMAT_ALAW, 2, 22050, 16);
        let mut alaw_wide_block = alaw.clone();
        alaw_wide_block.block_align = 4;
        let mut input = negotiated(
            &[WAVE_FORMAT_ALAW],
            &[pcm(2, 44100, 16), alaw_16, alaw_wide_block, alaw.clone()],
        );
        assert_eq!(
            input.process(&server_open(4, 0, &pcm(2, 44100, 16)))[1],
            AudioInputEvent::Open {
                format: alaw,
                capture_format: pcm(2, 44100, 16),
                frames_per_packet: 4,
            }
        );
        input.open_reply(0).unwrap();
        let samples = [0, -1, 32767, -32768];
        assert_eq!(
            input.push(&samples),
            [
                pdu::encode_incoming_data(),
                pdu::encode_data(&g711::encode_alaw(&samples)),
            ]
        );
    }

    /// A packet lasts as long as `FramesPerPacket` frames of the Open's capture format: the
    /// Windows 11 server asks for 441 frames with a 44.1 kHz capture format, and records A-law at
    /// 22.05 kHz only in packets of about 10 ms (#402), so 220 frames make one.
    #[test]
    fn a_packet_lasts_frames_per_packet_frames_of_the_capture_format() {
        let alaw = format(WAVE_FORMAT_ALAW, 2, 22050, 8);
        let mut input = negotiated(&[WAVE_FORMAT_ALAW], std::slice::from_ref(&alaw));
        input.process(&server_open(441, 0, &pcm(2, 44100, 16)));
        input.open_reply(0).unwrap();
        let samples: Vec<i16> = (0..880).collect();
        assert!(input.push(&samples[..438]).is_empty());
        assert_eq!(
            input.push(&samples[438..]),
            [
                pdu::encode_incoming_data(),
                pdu::encode_data(&g711::encode_alaw(&samples[..440])),
                pdu::encode_incoming_data(),
                pdu::encode_data(&g711::encode_alaw(&samples[440..])),
            ]
        );
    }

    /// A capture format of no rate gives no time to measure a packet in, so it holds
    /// `FramesPerPacket` frames; one too short for a whole frame holds one.
    #[test]
    fn a_packet_holds_frames_per_packet_frames_without_a_capture_rate_and_at_least_one() {
        let mut no_rate = pcm(1, 8000, 16);
        no_rate.samples_per_sec = 0;
        let mut input = negotiated(&[WAVE_FORMAT_PCM], &[pcm(1, 8000, 16)]);
        input.process(&server_open(3, 0, &no_rate));
        input.open_reply(0).unwrap();
        assert!(input.push(&[1, 2]).is_empty());
        assert_eq!(input.push(&[3]).len(), 2);

        let mut input = negotiated(&[WAVE_FORMAT_PCM], &[pcm(1, 8000, 16)]);
        input.process(&server_open(1, 0, &pcm(1, 44100, 16)));
        input.open_reply(0).unwrap();
        assert_eq!(input.push(&[1]).len(), 2);
    }

    /// 8-bit PCM packets hold one byte per sample.
    #[test]
    fn eight_bit_packets_hold_one_byte_a_sample() {
        let mut input = recording(pcm(1, 8000, 8), 4);
        let out = input.push(&[0, 256, -256, 32767]);
        assert_eq!(out[1], [MSG_SNDIN_DATA, 0x80, 0x81, 0x7F, 0xFF]);
    }

    #[test]
    fn samples_pushed_while_not_recording_are_dropped() {
        let mut input = negotiated(&[WAVE_FORMAT_PCM], &[pcm(1, 8000, 16)]);
        assert!(input.push(&[1, 2, 3]).is_empty());
        input.process(&server_open(2, 0, &pcm(1, 8000, 16)));
        assert!(input.push(&[1, 2, 3]).is_empty());
        input.open_reply(0).unwrap();
        // Nothing pushed before the device opened is sent.
        assert_eq!(
            input.push(&[4, 5]),
            [
                pdu::encode_incoming_data(),
                pdu::encode_data(&pcm::encode(16, &[4, 5]).unwrap())
            ]
        );
    }

    /// An error code does not start recording, and the server may send another Open PDU
    /// (3.3.5.1.8).
    #[test]
    fn a_failed_open_does_not_record_and_another_open_is_answered() {
        let format = pcm(1, 8000, 16);
        let mut input = negotiated(&[WAVE_FORMAT_PCM], std::slice::from_ref(&format));
        input.process(&server_open(1, 0, &format));
        assert_eq!(
            input.open_reply(E_FAIL),
            Some(pdu::encode_open_reply(E_FAIL))
        );
        assert!(input.push(&[1]).is_empty());
        assert_eq!(input.process(&server_open(1, 0, &format)).len(), 2);
        input.open_reply(0).unwrap();
        assert_eq!(input.push(&[1]).len(), 2);
    }

    /// A Format Change PDU is confirmed with the same index (3.2.5.3.2); the partial packet held
    /// for the old format is dropped, and the host learns the new format.
    #[test]
    fn a_format_change_is_confirmed_and_drops_the_partial_packet() {
        let formats = [pcm(1, 8000, 16), pcm(2, 16000, 16)];
        let mut input = negotiated(&[WAVE_FORMAT_PCM], &formats);
        input.process(&server_open(2, 0, &formats[0]));
        input.open_reply(0).unwrap();
        assert!(input.push(&[1]).is_empty());
        assert_eq!(
            input.process(&encode_format_change(1)),
            [
                AudioInputEvent::Send(encode_format_change(1)),
                AudioInputEvent::FormatChanged(formats[1].clone()),
            ]
        );
        // A packet still lasts two 8 kHz frames, now four frames of two channels, and the held
        // sample is gone.
        let samples: Vec<i16> = (2..10).collect();
        assert!(input.push(&samples[..7]).is_empty());
        assert_eq!(
            input.push(&samples[7..])[1],
            pdu::encode_data(&pcm::encode(16, &samples).unwrap())
        );
    }

    /// Malformed, unknown and out-of-sequence PDUs are ignored (3.1.5).
    #[test]
    fn malformed_unknown_and_out_of_sequence_pdus_are_ignored() {
        let format = pcm(1, 8000, 16);
        let mut input = AudioInput::new(AudioInputConfig::default()).unwrap();
        // Before the Version PDU, formats, an open and a format change are out of sequence.
        assert!(
            input
                .process(&server_formats(std::slice::from_ref(&format)))
                .is_empty()
        );
        assert!(input.process(&server_open(1, 0, &format)).is_empty());
        assert!(input.process(&encode_format_change(0)).is_empty());
        assert!(input.process(&[MSG_SNDIN_DATA_INCOMING]).is_empty());
        assert!(input.process(&[MSG_SNDIN_VERSION, 1]).is_empty());
        assert!(input.process(&[]).is_empty());
        assert_eq!(input.process(&server_version(1)).len(), 1);
        // A second Version PDU is out of sequence.
        assert!(input.process(&server_version(1)).is_empty());
        assert!(input.process(&[MSG_SNDIN_FORMATS, 9, 0, 0, 0]).is_empty());
        assert_eq!(
            input
                .process(&server_formats(std::slice::from_ref(&format)))
                .len(),
            3
        );
        assert!(input.process(&encode_format_change(0)).is_empty());
        assert!(input.process(&[MSG_SNDIN_FORMATCHANGE]).is_empty());
        assert_eq!(input.process(&server_open(1, 0, &format)).len(), 2);
        // While an Open waits for the host, another Open is out of sequence.
        assert!(input.process(&server_open(1, 0, &format)).is_empty());
    }

    /// An `initialFormat` or `NewFormat` past the client's list names nothing, and a
    /// `FramesPerPacket` of zero asks for empty packets; such PDUs are ignored.
    #[test]
    fn an_index_past_the_list_or_zero_frames_per_packet_is_ignored() {
        let format = pcm(1, 8000, 16);
        let mut input = negotiated(&[WAVE_FORMAT_PCM], std::slice::from_ref(&format));
        assert!(input.process(&server_open(1, 1, &format)).is_empty());
        assert!(input.process(&server_open(0, 0, &format)).is_empty());
        assert_eq!(input.process(&server_open(1, 0, &format)).len(), 2);
        input.open_reply(0).unwrap();
        assert!(input.process(&encode_format_change(1)).is_empty());
        assert!(input.process(&encode_format_change(u32::MAX)).is_empty());
        assert_eq!(input.push(&[7]).len(), 2);
    }

    /// A packet longer than one second would hold pushed samples for that long before sending
    /// any; an Open asking for one is ignored, so a server cannot make the helper hold samples
    /// without bound. A Format Change keeps the packet's length in time.
    #[test]
    fn a_packet_longer_than_a_second_is_ignored() {
        let format = pcm(1, 8000, 16);
        let mut input = negotiated(&[WAVE_FORMAT_PCM], std::slice::from_ref(&format));
        assert!(input.process(&server_open(8001, 0, &format)).is_empty());
        assert!(input.process(&server_open(u32::MAX, 0, &format)).is_empty());
        // 8000 frames of a 4 kHz capture format are two seconds.
        assert!(
            input
                .process(&server_open(8000, 0, &pcm(1, 4000, 16)))
                .is_empty()
        );
        let mut no_rate = format.clone();
        no_rate.samples_per_sec = 0;
        assert!(input.process(&server_open(8001, 0, &no_rate)).is_empty());
        assert_eq!(input.process(&server_open(8000, 0, &format)).len(), 2);
        input.open_reply(0).unwrap();
        assert_eq!(input.push(&[0; 8000]).len(), 2);
    }

    /// Figure 4 (3.1.5) leaves the Opened state only by a Format Change or by closing the
    /// channel: an Open while recording, and a Format Change while an Open waits for the host,
    /// are out of sequence and ignored, and recording goes on as it was.
    #[test]
    fn an_open_while_recording_and_a_format_change_while_opening_are_ignored() {
        let formats = [pcm(1, 8000, 16), pcm(2, 8000, 16)];
        let mut input = negotiated(&[WAVE_FORMAT_PCM], &formats);
        input.process(&server_open(2, 0, &formats[0]));
        assert!(input.process(&encode_format_change(1)).is_empty());
        input.open_reply(0).unwrap();
        assert!(input.push(&[1]).is_empty());
        assert!(input.process(&server_open(1, 1, &formats[1])).is_empty());
        assert_eq!(input.open_reply(0), None);
        assert_eq!(
            input.push(&[2]),
            [
                pdu::encode_incoming_data(),
                pdu::encode_data(&pcm::encode(16, &[1, 2]).unwrap())
            ]
        );
    }

    proptest::proptest! {
        /// However the host splits its pushes, the Data PDUs carry the samples in order, each
        /// exactly `FramesPerPacket` frames, and each after an Incoming Data PDU.
        #[test]
        fn packets_are_exact_whatever_the_push_sizes(
            channels in 1u16..=2,
            frames_per_packet in 1u32..=8,
            cuts in proptest::collection::vec(0usize..=20, 0..12),
        ) {
            let mut input = recording(pcm(channels, 8000, 16), frames_per_packet);
            let total: usize = cuts.iter().sum();
            let samples: Vec<i16> = (0..total).map(|n| n as i16).collect();
            let mut out = Vec::new();
            let mut at = 0;
            for cut in cuts {
                out.extend(input.push(&samples[at..at + cut]));
                at += cut;
            }
            let packet = frames_per_packet as usize * usize::from(channels);
            let expected: Vec<Vec<u8>> = samples
                .chunks_exact(packet)
                .flat_map(|p| {
                    [
                        pdu::encode_incoming_data(),
                        pdu::encode_data(&pcm::encode(16, p).unwrap()),
                    ]
                })
                .collect();
            proptest::prop_assert_eq!(out, expected);
        }
    }
}
