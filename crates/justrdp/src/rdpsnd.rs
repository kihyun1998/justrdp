//! The audio output channel (MS-RDPEA) as a sans-IO helper the host drives, over either
//! transport: the static channel `rdpsnd` or the dynamic channel `AUDIO_PLAYBACK_DVC` (ADR-0018),
//! whose messages are the same. The host feeds each message on its channel to
//! [`AudioOutput::process`] and sends every [`AudioOutputEvent::Send`] back on that channel. A
//! decoded sample reaches the host as an [`AudioBlock`], and a sample the helper refuses as
//! [`AudioOutputEvent::Dropped`]; once the host has played or dropped either,
//! [`AudioOutput::confirm`] gives the Wave Confirm PDU, carrying the milliseconds that took.
//!
//! The host chooses the formats it takes, in preference order, by `wFormatTag`; the helper
//! answers the server's list with every server format of those tags that the core decodes,
//! copied as the server sent it, so the client list is always a subset of the server's
//! (2.2.2.2).

use justrdp_codecs::{g711, pcm};
use justrdp_pdu::DecodeError;
use justrdp_pdu::rdpsnd::{
    self as pdu, AudioFormat, ClientFormats, ServerPdu, TSSNDCAPS_ALIVE, TSSNDCAPS_VOLUME,
    WAVE_FORMAT_ALAW, WAVE_FORMAT_PCM,
};

/// The `wVersion` this helper implements and so advertises: Windows 8 and later's, which brings
/// Wave2 (3.3.5.2.1.8).
pub const CLIENT_VERSION: u16 = 0x0008;

/// The lowest version at which both sides exchange a Quality Mode PDU (2.2.2.3).
const QUALITY_MODE_FROM: u16 = 0x0006;

/// The `wFormatTag`s the core decodes.
pub const DECODABLE_FORMAT_TAGS: &[u16] = &[WAVE_FORMAT_PCM, WAVE_FORMAT_ALAW];

/// Whether the core decodes samples in `format`: PCM at 8 or 16 bits or A-law at 8, with at
/// least one channel and a block that is exactly one frame of them.
fn decodable(format: &AudioFormat) -> bool {
    let depth = match format.format_tag {
        WAVE_FORMAT_PCM => matches!(format.bits_per_sample, 8 | 16),
        WAVE_FORMAT_ALAW => format.bits_per_sample == 8,
        _ => false,
    };
    depth
        && format.channels > 0
        && u32::from(format.block_align)
            == u32::from(format.channels) * u32::from(format.bits_per_sample / 8)
}

/// The Quality Mode PDU's `wQualityMode` (2.2.2.3). What each means is the server's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QualityMode {
    /// `DYNAMIC_QUALITY`: the server adapts to the bandwidth.
    Dynamic,
    /// `MEDIUM_QUALITY`.
    Medium,
    /// `HIGH_QUALITY`.
    #[default]
    High,
}

impl QualityMode {
    fn wire(self) -> u16 {
        match self {
            QualityMode::Dynamic => pdu::DYNAMIC_QUALITY,
            QualityMode::Medium => pdu::MEDIUM_QUALITY,
            QualityMode::High => pdu::HIGH_QUALITY,
        }
    }
}

/// What the host offers the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioOutputConfig {
    /// The `wFormatTag`s the host takes, most preferred first, each once.
    pub format_tags: Vec<u16>,
    /// The Quality Mode the host asks for.
    pub quality_mode: QualityMode,
    /// `Some` advertises `TSSNDCAPS_VOLUME` with this initial `dwVolume` (left channel in the
    /// low word, right in the high word, `0xFFFF` each at full volume); Volume PDUs then reach
    /// the host as [`AudioOutputEvent::Volume`]. `None` advertises no volume control.
    pub volume: Option<u32>,
}

impl Default for AudioOutputConfig {
    /// PCM at high quality, with no volume control.
    fn default() -> Self {
        Self {
            format_tags: vec![WAVE_FORMAT_PCM],
            quality_mode: QualityMode::High,
            volume: None,
        }
    }
}

/// Why an [`AudioOutputConfig`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioOutputConfigError {
    /// The core cannot decode this format tag.
    UndecodableFormat {
        /// The tag.
        format_tag: u16,
    },
    /// This format tag is listed more than once, which would list its formats more than once.
    RepeatedFormatTag {
        /// The tag.
        format_tag: u16,
    },
}

impl core::fmt::Display for AudioOutputConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AudioOutputConfigError::UndecodableFormat { format_tag } => {
                write!(
                    f,
                    "audio format tag {format_tag:#06x} is not one the core decodes"
                )
            }
            AudioOutputConfigError::RepeatedFormatTag { format_tag } => {
                write!(f, "audio format tag {format_tag:#06x} is listed twice")
            }
        }
    }
}

impl core::error::Error for AudioOutputConfigError {}

/// What the host returns to [`AudioOutput::confirm`] for one sample: its `wTimeStamp` and
/// `cBlockNo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaveConfirm {
    timestamp: u16,
    block_no: u8,
}

/// One decoded audio sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioBlock {
    /// The server format it was sent in.
    pub format: AudioFormat,
    /// Interleaved signed 16-bit samples, `format.channels` to a frame, at
    /// `format.samples_per_sec` frames a second.
    pub samples: Vec<i16>,
    /// The token to hand to [`AudioOutput::confirm`] once the sample is played or dropped.
    pub confirm: WaveConfirm,
}

/// What processing one audio output message produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioOutputEvent {
    /// A message to send on the audio output channel.
    Send(Vec<u8>),
    /// The formats this side answered the server's list with, in order. An empty list means
    /// the server offers no format of the host's tags that the core decodes, and no audio will
    /// follow.
    Negotiated(Vec<AudioFormat>),
    /// A decoded sample.
    Block(AudioBlock),
    /// A sample whose header was read but which was refused: its `wFormatNo` names no client
    /// format, its data is not whole frames of that format, or its Wave PDU does not match its
    /// WaveInfo PDU. The host confirms it as it confirms a block it dropped.
    Dropped {
        /// The token to hand to [`AudioOutput::confirm`].
        confirm: WaveConfirm,
        /// Why it was refused.
        reason: &'static str,
    },
    /// The server set the volume: the left channel in the low word, the right in the high word.
    Volume(u32),
    /// The server ended the audio stream (2.2.3.9). It may start another with a new format list.
    Closed,
}

/// The audio output protocol state.
#[derive(Debug, Clone)]
pub struct AudioOutput {
    config: AudioOutputConfig,
    /// The formats this side sent, indexed by `wFormatNo`.
    client_formats: Vec<AudioFormat>,
    /// The WaveInfo PDU whose Wave PDU is the next message.
    pending_wave: Option<pdu::WaveInfo>,
}

impl AudioOutput {
    /// An audio output waiting for the server's format list. A format tag the core does not
    /// decode, or one listed twice, is refused.
    pub fn new(config: AudioOutputConfig) -> Result<Self, AudioOutputConfigError> {
        for (at, &format_tag) in config.format_tags.iter().enumerate() {
            if !DECODABLE_FORMAT_TAGS.contains(&format_tag) {
                return Err(AudioOutputConfigError::UndecodableFormat { format_tag });
            }
            if config.format_tags[..at].contains(&format_tag) {
                return Err(AudioOutputConfigError::RepeatedFormatTag { format_tag });
            }
        }
        Ok(Self {
            config,
            client_formats: Vec::new(),
            pending_wave: None,
        })
    }

    /// The Wave Confirm PDU (2.2.3.8) for a sample the host played or dropped `elapsed_ms`
    /// milliseconds after it arrived: its `wTimeStamp` plus `elapsed_ms`, wrapping at 16 bits.
    pub fn confirm(&self, confirm: WaveConfirm, elapsed_ms: u32) -> Vec<u8> {
        pdu::encode_wave_confirm(
            confirm.timestamp.wrapping_add(elapsed_ms as u16),
            confirm.block_no,
        )
    }

    /// Consume one whole message from the audio output channel. A malformed PDU is an error;
    /// a sample refused after its header was read is [`AudioOutputEvent::Dropped`].
    pub fn process(&mut self, message: &[u8]) -> Result<Vec<AudioOutputEvent>, DecodeError> {
        if let Some(info) = self.pending_wave.take() {
            let confirm = WaveConfirm {
                timestamp: info.timestamp,
                block_no: info.block_no,
            };
            return Ok(vec![match pdu::decode_wave(&info, message) {
                Ok(sample) => self.block(info.format_no, confirm, &sample),
                Err(_) => dropped(confirm, "the Wave PDU does not match its WaveInfo PDU"),
            }]);
        }
        note_slack(message);
        match ServerPdu::decode(message)? {
            ServerPdu::Formats {
                version, formats, ..
            } => Ok(self.negotiate(version, &formats)),
            ServerPdu::Training {
                timestamp,
                pack_size,
            } => Ok(vec![AudioOutputEvent::Send(pdu::encode_training_confirm(
                timestamp, pack_size,
            ))]),
            ServerPdu::WaveInfo(info) => {
                self.pending_wave = Some(info);
                Ok(Vec::new())
            }
            ServerPdu::Wave2 {
                timestamp,
                format_no,
                block_no,
                data,
                ..
            } => {
                let confirm = WaveConfirm {
                    timestamp,
                    block_no,
                };
                Ok(vec![self.block(format_no, confirm, &data)])
            }
            ServerPdu::Close => Ok(vec![AudioOutputEvent::Closed]),
            ServerPdu::Volume(volume) if self.config.volume.is_some() => {
                Ok(vec![AudioOutputEvent::Volume(volume)])
            }
            ServerPdu::Volume(volume) => {
                tracing::debug!(
                    target: "rdp_rdpsnd",
                    volume,
                    "Volume PDU skipped: volume control was not advertised"
                );
                Ok(Vec::new())
            }
            ServerPdu::Pitch(_) => Ok(Vec::new()),
            ServerPdu::Unknown { msg_type } => {
                tracing::debug!(target: "rdp_rdpsnd", msg_type, "unknown audio output PDU skipped");
                Ok(Vec::new())
            }
        }
    }

    /// Answer the server's format list: every server format the core decodes whose tag the host
    /// takes, in the host's order of tags and the server's within a tag, then the Quality Mode
    /// when both sides are at least version 6.
    fn negotiate(
        &mut self,
        server_version: u16,
        server_formats: &[AudioFormat],
    ) -> Vec<AudioOutputEvent> {
        self.client_formats = self
            .config
            .format_tags
            .iter()
            .flat_map(|tag| {
                server_formats
                    .iter()
                    .filter(move |f| f.format_tag == *tag && decodable(f))
            })
            .cloned()
            .collect();
        tracing::debug!(
            target: "rdp_rdpsnd",
            server_version,
            server_formats = server_formats.len(),
            client_formats = self.client_formats.len(),
            "audio output formats negotiated"
        );
        let flags = TSSNDCAPS_ALIVE
            | if self.config.volume.is_some() {
                TSSNDCAPS_VOLUME
            } else {
                0
            };
        let mut events = vec![AudioOutputEvent::Send(pdu::encode_client_formats(
            &ClientFormats {
                flags,
                volume: self.config.volume.unwrap_or(0),
                pitch: 0,
                version: CLIENT_VERSION,
                formats: self.client_formats.clone(),
            },
        ))];
        if server_version >= QUALITY_MODE_FROM {
            events.push(AudioOutputEvent::Send(pdu::encode_quality_mode(
                self.config.quality_mode.wire(),
            )));
        }
        events.push(AudioOutputEvent::Negotiated(self.client_formats.clone()));
        events
    }

    /// Decode one sample sent in client format `format_no`, or drop it. Every client format is
    /// [`decodable`], so its `block_align` is not zero.
    fn block(&self, format_no: u16, confirm: WaveConfirm, data: &[u8]) -> AudioOutputEvent {
        let Some(format) = self.client_formats.get(usize::from(format_no)) else {
            return dropped(confirm, "wFormatNo names no format in the client's list");
        };
        if !data.len().is_multiple_of(usize::from(format.block_align)) {
            return dropped(confirm, "the sample is not a whole number of frames");
        }
        let samples = match format.format_tag {
            WAVE_FORMAT_ALAW => Ok(g711::decode_alaw(data)),
            _ => pcm::decode(format.bits_per_sample, data),
        };
        match samples {
            Ok(samples) => AudioOutputEvent::Block(AudioBlock {
                format: format.clone(),
                samples,
                confirm,
            }),
            Err(_) => dropped(confirm, "the sample is not audio the core decodes"),
        }
    }
}

/// A refused sample, recorded (ADR-0009 §3(b)).
fn dropped(confirm: WaveConfirm, reason: &'static str) -> AudioOutputEvent {
    tracing::warn!(
        target: "rdp_rdpsnd",
        block_no = confirm.block_no,
        reason,
        "audio sample dropped"
    );
    AudioOutputEvent::Dropped { confirm, reason }
}

/// Record bytes past a PDU's `BodySize`, which decoding ignores (ADR-0009 §3(b)). A WaveInfo's
/// `BodySize` counts the next message, so it is not checked.
fn note_slack(message: &[u8]) {
    if let [msg_type, _, lo, hi, ..] = *message
        && msg_type != pdu::SNDC_WAVE
    {
        let declared = 4 + usize::from(u16::from_le_bytes([lo, hi]));
        if message.len() > declared {
            tracing::debug!(
                target: "rdp_rdpsnd",
                msg_type,
                slack = message.len() - declared,
                "bytes past an audio output PDU's BodySize ignored"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::rdpsnd::{
        SNDC_FORMATS, SNDC_SETPITCH, SNDC_SETVOLUME, SNDC_TRAINING, SNDC_WAVE, SNDC_WAVE2,
        WAVE_FORMAT_ALAW,
    };

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

    fn message(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![msg_type, 0];
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    fn server_formats(version: u16, formats: &[AudioFormat]) -> Vec<u8> {
        // The server PDU has the client PDU's layout; its own fixed fields are ignored.
        let mut encoded = pdu::encode_client_formats(&ClientFormats {
            flags: 0,
            volume: 0,
            pitch: 0,
            version,
            formats: formats.to_vec(),
        });
        encoded[1] = 0x2b;
        encoded
    }

    fn wave_info(timestamp: u16, format_no: u16, block_no: u8, sample: &[u8]) -> Vec<u8> {
        let mut body = timestamp.to_le_bytes().to_vec();
        body.extend_from_slice(&format_no.to_le_bytes());
        body.extend_from_slice(&[block_no, 0, 0, 0]);
        body.extend_from_slice(&sample[..4]);
        let mut out = vec![SNDC_WAVE, 0];
        out.extend_from_slice(&((sample.len() + 8) as u16).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn wave(sample: &[u8]) -> Vec<u8> {
        [&[0u8; 4][..], &sample[4..]].concat()
    }

    fn wave2(timestamp: u16, format_no: u16, block_no: u8, sample: &[u8]) -> Vec<u8> {
        let mut body = timestamp.to_le_bytes().to_vec();
        body.extend_from_slice(&format_no.to_le_bytes());
        body.extend_from_slice(&[block_no, 0, 0, 0]);
        body.extend_from_slice(&0x0DAC_B8C2u32.to_le_bytes());
        body.extend_from_slice(sample);
        message(SNDC_WAVE2, &body)
    }

    fn sends(events: &[AudioOutputEvent]) -> Vec<Vec<u8>> {
        events
            .iter()
            .filter_map(|e| match e {
                AudioOutputEvent::Send(m) => Some(m.clone()),
                _ => None,
            })
            .collect()
    }

    fn negotiated(output: &mut AudioOutput, version: u16, formats: &[AudioFormat]) {
        output.process(&server_formats(version, formats)).unwrap();
    }

    /// The client list is every server format of the host's tags, in the host's tag order and
    /// the server's within a tag, sent as the server sent it, with ALIVE and version 8, then a
    /// Quality Mode.
    #[test]
    fn the_server_list_is_answered_with_the_hosts_formats_in_its_order() {
        let pcm_44 = format(WAVE_FORMAT_PCM, 2, 44100, 16);
        let pcm_22 = format(WAVE_FORMAT_PCM, 2, 22050, 16);
        let mut adpcm = format(pdu::WAVE_FORMAT_ADPCM, 2, 22050, 4);
        adpcm.extra = vec![0xf4, 0x03, 0x07, 0x00];
        let alaw = format(WAVE_FORMAT_ALAW, 1, 8000, 8);
        let mut output = AudioOutput::new(AudioOutputConfig::default()).unwrap();
        let events = output
            .process(&server_formats(
                8,
                &[alaw, pcm_44.clone(), adpcm, pcm_22.clone()],
            ))
            .unwrap();
        let expected_formats = vec![pcm_44, pcm_22];
        assert_eq!(
            sends(&events),
            vec![
                pdu::encode_client_formats(&ClientFormats {
                    flags: TSSNDCAPS_ALIVE,
                    volume: 0,
                    pitch: 0,
                    version: 8,
                    formats: expected_formats.clone(),
                }),
                pdu::encode_quality_mode(pdu::HIGH_QUALITY),
            ]
        );
        assert_eq!(
            events.last(),
            Some(&AudioOutputEvent::Negotiated(expected_formats))
        );
    }

    /// Below version 6 the server takes no Quality Mode PDU; volume control is advertised only
    /// when the host asks for it.
    #[test]
    fn quality_mode_needs_version_6_and_volume_is_the_hosts() {
        let pcm = format(WAVE_FORMAT_PCM, 2, 22050, 16);
        let mut output = AudioOutput::new(AudioOutputConfig {
            volume: Some(0xFFFF_FFFF),
            ..AudioOutputConfig::default()
        })
        .unwrap();
        let events = output
            .process(&server_formats(5, std::slice::from_ref(&pcm)))
            .unwrap();
        assert_eq!(
            sends(&events),
            vec![pdu::encode_client_formats(&ClientFormats {
                flags: TSSNDCAPS_ALIVE | TSSNDCAPS_VOLUME,
                volume: 0xFFFF_FFFF,
                pitch: 0,
                version: 8,
                formats: vec![pcm],
            })]
        );
        assert_eq!(
            output.process(&message(SNDC_SETVOLUME, &0x8000_4000u32.to_le_bytes())),
            Ok(vec![AudioOutputEvent::Volume(0x8000_4000)])
        );
    }

    /// Version 6 is the first that takes a Quality Mode PDU (2.2.2.3).
    #[test]
    fn a_version_6_server_gets_the_quality_mode() {
        let pcm = format(WAVE_FORMAT_PCM, 2, 22050, 16);
        let mut output = AudioOutput::new(AudioOutputConfig {
            quality_mode: QualityMode::Dynamic,
            ..AudioOutputConfig::default()
        })
        .unwrap();
        let events = output.process(&server_formats(6, &[pcm])).unwrap();
        assert_eq!(
            sends(&events).last(),
            Some(&pdu::encode_quality_mode(pdu::DYNAMIC_QUALITY))
        );
    }

    /// A Volume PDU without volume control advertised, and every Pitch PDU, reach no one.
    #[test]
    fn volume_unadvertised_and_pitch_are_ignored() {
        let mut output = AudioOutput::new(AudioOutputConfig::default()).unwrap();
        assert_eq!(
            output.process(&message(SNDC_SETVOLUME, &[0xFF; 4])),
            Ok(Vec::new())
        );
        assert_eq!(
            output.process(&message(SNDC_SETPITCH, &[0, 0, 1, 0])),
            Ok(Vec::new())
        );
        assert_eq!(output.process(&message(0x0A, &[])), Ok(Vec::new()));
    }

    #[test]
    fn training_is_confirmed_with_its_own_fields() {
        let mut output = AudioOutput::new(AudioOutputConfig::default()).unwrap();
        let mut body = vec![0xda, 0x89, 0x00, 0x04];
        body.resize(0x3fc, 0);
        assert_eq!(
            output.process(&message(SNDC_TRAINING, &body)),
            Ok(vec![AudioOutputEvent::Send(pdu::encode_training_confirm(
                0x89da, 0x0400
            ))])
        );
    }

    /// A WaveInfo and its Wave PDU make one block: the WaveInfo's four bytes lead the sample,
    /// and the samples are the PCM converted to i16.
    #[test]
    fn a_wave_info_and_its_wave_make_one_block() {
        let pcm = format(WAVE_FORMAT_PCM, 2, 22050, 16);
        let mut output = AudioOutput::new(AudioOutputConfig::default()).unwrap();
        negotiated(&mut output, 8, std::slice::from_ref(&pcm));
        let sample = [0x01, 0x00, 0xFF, 0x7F, 0x00, 0x80, 0x34, 0x12];
        assert_eq!(
            output.process(&wave_info(0xadd7, 0, 8, &sample)),
            Ok(Vec::new())
        );
        let events = output.process(&wave(&sample)).unwrap();
        let [AudioOutputEvent::Block(block)] = events.as_slice() else {
            panic!("{events:?}");
        };
        assert_eq!(block.format, pcm);
        assert_eq!(block.samples, [1, 32767, -32768, 0x1234]);
        assert_eq!(
            output.confirm(block.confirm, 0),
            pdu::encode_wave_confirm(0xadd7, 8)
        );
    }

    /// A Wave2 is a block by itself, in the format its `wFormatNo` names in the client's list.
    #[test]
    fn a_wave2_is_one_block_in_the_client_format_it_names() {
        let pcm_16 = format(WAVE_FORMAT_PCM, 2, 44100, 16);
        let pcm_8 = format(WAVE_FORMAT_PCM, 1, 22050, 8);
        let mut output = AudioOutput::new(AudioOutputConfig::default()).unwrap();
        negotiated(&mut output, 8, &[pcm_16, pcm_8.clone()]);
        let events = output
            .process(&wave2(0xa116, 1, 2, &[0x80, 0x00, 0xFF]))
            .unwrap();
        let [AudioOutputEvent::Block(block)] = events.as_slice() else {
            panic!("{events:?}");
        };
        assert_eq!(block.format, pcm_8);
        assert_eq!(block.samples, [0, -32768, 32512]);
        assert_eq!(
            output.confirm(block.confirm, 0),
            pdu::encode_wave_confirm(0xa116, 2)
        );
    }

    /// The Wave Confirm adds the host's elapsed milliseconds to the timestamp, wrapping at 16
    /// bits (65_536, not FreeRDP's 65_535).
    #[test]
    fn the_confirm_adds_the_elapsed_time_and_wraps_at_16_bits() {
        let output = AudioOutput::new(AudioOutputConfig::default()).unwrap();
        let token = WaveConfirm {
            timestamp: 0xFFF0,
            block_no: 7,
        };
        assert_eq!(
            output.confirm(token, 0x20),
            pdu::encode_wave_confirm(0x0010, 7)
        );
        assert_eq!(
            output.confirm(token, 15),
            pdu::encode_wave_confirm(0xFFFF, 7)
        );
    }

    /// The confirm token of a sample that was refused.
    fn dropped(events: &[AudioOutputEvent]) -> Option<WaveConfirm> {
        match events {
            [AudioOutputEvent::Dropped { confirm, .. }] => Some(*confirm),
            _ => None,
        }
    }

    /// A sample in a format the client never listed, or that is not whole frames, is dropped,
    /// and the host still gets the token that confirms it.
    #[test]
    fn a_refused_sample_is_dropped_with_its_confirm() {
        let pcm = format(WAVE_FORMAT_PCM, 2, 22050, 16);
        let mut output = AudioOutput::new(AudioOutputConfig::default()).unwrap();
        let before = output.process(&wave2(0x1111, 0, 1, &[0; 8])).unwrap();
        assert_eq!(
            dropped(&before).map(|c| output.confirm(c, 0)),
            Some(pdu::encode_wave_confirm(0x1111, 1)),
            "before negotiation"
        );
        negotiated(&mut output, 8, &[pcm]);
        let unknown = output.process(&wave2(0x2222, 1, 2, &[0; 8])).unwrap();
        assert_eq!(
            dropped(&unknown).map(|c| output.confirm(c, 5)),
            Some(pdu::encode_wave_confirm(0x2227, 2))
        );
        let partial = output.process(&wave2(0x3333, 0, 3, &[0; 6])).unwrap();
        assert_eq!(
            dropped(&partial).map(|c| output.confirm(c, 0)),
            Some(pdu::encode_wave_confirm(0x3333, 3))
        );
        assert!(matches!(
            output.process(&wave2(0, 0, 4, &[0; 8])).unwrap().as_slice(),
            [AudioOutputEvent::Block(_)]
        ));
    }

    /// A WaveInfo announcing four bytes or fewer still takes the next message as its Wave, which
    /// is dropped; the message after that is read as a PDU again.
    #[test]
    fn a_short_wave_info_keeps_the_framing_and_drops_its_wave() {
        let mut output = AudioOutput::new(AudioOutputConfig::default()).unwrap();
        negotiated(&mut output, 8, &[format(WAVE_FORMAT_PCM, 2, 22050, 16)]);
        let mut info = vec![SNDC_WAVE, 0, 12, 0, 0x44, 0x44, 0, 0, 9, 0, 0, 0];
        info.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(output.process(&info), Ok(Vec::new()));
        let events = output.process(&[0, 0, 0, 0]).unwrap();
        assert_eq!(
            dropped(&events).map(|c| output.confirm(c, 0)),
            Some(pdu::encode_wave_confirm(0x4444, 9))
        );
        assert_eq!(
            output.process(&message(pdu::SNDC_CLOSE, &[])),
            Ok(vec![AudioOutputEvent::Closed])
        );
    }

    /// Only the variants the core decodes are offered: PCM at 8 or 16 bits whose block size is
    /// one frame of its channels.
    #[test]
    fn undecodable_variants_of_a_taken_tag_are_not_offered() {
        let good = format(WAVE_FORMAT_PCM, 2, 44100, 16);
        let pcm_24 = format(WAVE_FORMAT_PCM, 2, 44100, 24);
        // No channels and no block: only the channel check refuses it.
        let no_channels = AudioFormat {
            channels: 0,
            block_align: 0,
            avg_bytes_per_sec: 0,
            ..good.clone()
        };
        let half_frame = AudioFormat {
            block_align: 2,
            ..good.clone()
        };
        let mut output = AudioOutput::new(AudioOutputConfig::default()).unwrap();
        let events = output
            .process(&server_formats(
                8,
                &[pcm_24, no_channels, half_frame, good.clone()],
            ))
            .unwrap();
        assert_eq!(
            events.last(),
            Some(&AudioOutputEvent::Negotiated(vec![good]))
        );
    }

    /// A tag listed twice would list its formats twice.
    #[test]
    fn a_repeated_format_tag_is_refused() {
        assert_eq!(
            AudioOutput::new(AudioOutputConfig {
                format_tags: vec![WAVE_FORMAT_PCM, WAVE_FORMAT_PCM],
                ..AudioOutputConfig::default()
            })
            .err(),
            Some(AudioOutputConfigError::RepeatedFormatTag {
                format_tag: WAVE_FORMAT_PCM
            })
        );
    }

    /// Close reaches the host, and a new format list restarts the stream with a new client list.
    #[test]
    fn close_reaches_the_host_and_a_new_list_renegotiates() {
        let pcm_44 = format(WAVE_FORMAT_PCM, 2, 44100, 16);
        let pcm_8 = format(WAVE_FORMAT_PCM, 1, 8000, 8);
        let mut output = AudioOutput::new(AudioOutputConfig::default()).unwrap();
        negotiated(&mut output, 8, &[pcm_44]);
        assert_eq!(
            output.process(&message(pdu::SNDC_CLOSE, &[])),
            Ok(vec![AudioOutputEvent::Closed])
        );
        negotiated(&mut output, 8, std::slice::from_ref(&pcm_8));
        let events = output.process(&wave2(0, 0, 1, &[0x80])).unwrap();
        let [AudioOutputEvent::Block(block)] = events.as_slice() else {
            panic!("{events:?}");
        };
        assert_eq!(block.format, pcm_8);
    }

    /// A host listing A-law gets the server's 8-bit A-law formats in its tag order, and their
    /// samples decoded to i16 (#388). A-law at another depth is not offered.
    #[test]
    fn a_host_listing_alaw_negotiates_and_decodes_it() {
        let pcm = format(WAVE_FORMAT_PCM, 2, 44100, 16);
        let alaw = format(WAVE_FORMAT_ALAW, 2, 22050, 8);
        let alaw_16 = format(WAVE_FORMAT_ALAW, 2, 22050, 16);
        let mut output = AudioOutput::new(AudioOutputConfig {
            format_tags: vec![WAVE_FORMAT_ALAW, WAVE_FORMAT_PCM],
            ..AudioOutputConfig::default()
        })
        .unwrap();
        let events = output
            .process(&server_formats(8, &[pcm.clone(), alaw_16, alaw.clone()]))
            .unwrap();
        assert_eq!(
            events.last(),
            Some(&AudioOutputEvent::Negotiated(vec![alaw.clone(), pcm]))
        );
        let events = output
            .process(&wave2(0x0101, 0, 5, &[0xD5, 0x55, 0xAA, 0x2A]))
            .unwrap();
        let [AudioOutputEvent::Block(block)] = events.as_slice() else {
            panic!("{events:?}");
        };
        assert_eq!(block.format, alaw);
        assert_eq!(block.samples, [8, -8, 32256, -32256]);
    }

    /// The host may list only formats the core decodes.
    #[test]
    fn an_undecodable_format_tag_is_refused() {
        assert_eq!(
            AudioOutput::new(AudioOutputConfig {
                format_tags: vec![WAVE_FORMAT_PCM, pdu::WAVE_FORMAT_MULAW],
                ..AudioOutputConfig::default()
            })
            .err(),
            Some(AudioOutputConfigError::UndecodableFormat {
                format_tag: pdu::WAVE_FORMAT_MULAW
            })
        );
    }

    /// With no server format of the host's tags the answer is an empty list, and the host
    /// learns it.
    #[test]
    fn no_common_format_is_an_empty_answer() {
        let mut output = AudioOutput::new(AudioOutputConfig::default()).unwrap();
        let events = output
            .process(&server_formats(8, &[format(WAVE_FORMAT_ALAW, 1, 8000, 8)]))
            .unwrap();
        assert_eq!(
            events.last(),
            Some(&AudioOutputEvent::Negotiated(Vec::new()))
        );
        assert_eq!(&sends(&events)[0][..2], &[SNDC_FORMATS, 0]);
    }
}
