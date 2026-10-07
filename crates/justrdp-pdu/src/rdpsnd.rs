//! Audio output virtual channel PDUs (MS-RDPEA), carried over the static channel
//! [`CHANNEL_NAME`] or the dynamic channel [`DVC_CHANNEL_NAME`] with the same bytes. Every PDU
//! but the Wave PDU opens with a 4-byte `SNDPROLOG` (2.2.1); the Wave PDU (2.2.3.4) has none,
//! so it is decoded with [`decode_wave`] against the WaveInfo PDU that announced it.

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// The static channel name (2.1).
pub const CHANNEL_NAME: &str = "rdpsnd";
/// The reliable dynamic channel name (2.1).
pub const DVC_CHANNEL_NAME: &str = "AUDIO_PLAYBACK_DVC";

/// `SNDC_CLOSE` (2.2.3.9).
pub const SNDC_CLOSE: u8 = 0x01;
/// `SNDC_WAVE`, the WaveInfo PDU (2.2.3.3).
pub const SNDC_WAVE: u8 = 0x02;
/// `SNDC_SETVOLUME` (2.2.4.1).
pub const SNDC_SETVOLUME: u8 = 0x03;
/// `SNDC_SETPITCH` (2.2.4.2).
pub const SNDC_SETPITCH: u8 = 0x04;
/// `SNDC_WAVECONFIRM` (2.2.3.8).
pub const SNDC_WAVECONFIRM: u8 = 0x05;
/// `SNDC_TRAINING`, the Training and Training Confirm PDUs (2.2.3.1, 2.2.3.2).
pub const SNDC_TRAINING: u8 = 0x06;
/// `SNDC_FORMATS`, the server and client Audio Formats and Version PDUs (2.2.2.1, 2.2.2.2).
pub const SNDC_FORMATS: u8 = 0x07;
/// `SNDC_QUALITYMODE` (2.2.2.3).
pub const SNDC_QUALITYMODE: u8 = 0x0C;
/// `SNDC_WAVE2` (2.2.3.10).
pub const SNDC_WAVE2: u8 = 0x0D;

/// `TSSNDCAPS_ALIVE`: the client consumes audio. Audio flows only when it is set.
pub const TSSNDCAPS_ALIVE: u32 = 0x0000_0001;
/// `TSSNDCAPS_VOLUME`: the client applies Volume PDUs.
pub const TSSNDCAPS_VOLUME: u32 = 0x0000_0002;
/// `TSSNDCAPS_PITCH`: the client applies Pitch PDUs.
pub const TSSNDCAPS_PITCH: u32 = 0x0000_0004;

/// `DYNAMIC_QUALITY` (2.2.2.3).
pub const DYNAMIC_QUALITY: u16 = 0x0000;
/// `MEDIUM_QUALITY` (2.2.2.3).
pub const MEDIUM_QUALITY: u16 = 0x0001;
/// `HIGH_QUALITY` (2.2.2.3).
pub const HIGH_QUALITY: u16 = 0x0002;

/// `WAVE_FORMAT_PCM`.
pub const WAVE_FORMAT_PCM: u16 = 0x0001;
/// `WAVE_FORMAT_ADPCM` (Microsoft ADPCM).
pub const WAVE_FORMAT_ADPCM: u16 = 0x0002;
/// `WAVE_FORMAT_ALAW`.
pub const WAVE_FORMAT_ALAW: u16 = 0x0006;
/// `WAVE_FORMAT_MULAW`.
pub const WAVE_FORMAT_MULAW: u16 = 0x0007;
/// `WAVE_FORMAT_DVI_ADPCM` (IMA ADPCM).
pub const WAVE_FORMAT_DVI_ADPCM: u16 = 0x0011;

/// The size of the fixed part of an Audio Formats and Version PDU body.
const FORMATS_FIXED_SIZE: usize = 20;
/// The size of an `AUDIO_FORMAT` before its `cbSize` bytes.
const AUDIO_FORMAT_FIXED_SIZE: usize = 18;
/// The bytes of a WaveInfo body before the four bytes it carries (2.2.3.3).
const WAVE_INFO_FIXED_SIZE: usize = 8;

/// An `AUDIO_FORMAT` (2.2.2.1.1), the wire `WAVEFORMATEX`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFormat {
    /// `wFormatTag`.
    pub format_tag: u16,
    /// `nChannels`.
    pub channels: u16,
    /// `nSamplesPerSec`.
    pub samples_per_sec: u32,
    /// `nAvgBytesPerSec`.
    pub avg_bytes_per_sec: u32,
    /// `nBlockAlign`.
    pub block_align: u16,
    /// `wBitsPerSample`.
    pub bits_per_sample: u16,
    /// The `cbSize` bytes that follow.
    pub extra: Vec<u8>,
}

impl AudioFormat {
    pub(crate) fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let format_tag = cur.read_u16_le()?;
        let channels = cur.read_u16_le()?;
        let samples_per_sec = cur.read_u32_le()?;
        let avg_bytes_per_sec = cur.read_u32_le()?;
        let block_align = cur.read_u16_le()?;
        let bits_per_sample = cur.read_u16_le()?;
        let cb_size = cur.read_u16_le()?;
        let extra = cur.read_slice(usize::from(cb_size))?.to_vec();
        Ok(Self {
            format_tag,
            channels,
            samples_per_sec,
            avg_bytes_per_sec,
            block_align,
            bits_per_sample,
            extra,
        })
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.format_tag.to_le_bytes());
        out.extend_from_slice(&self.channels.to_le_bytes());
        out.extend_from_slice(&self.samples_per_sec.to_le_bytes());
        out.extend_from_slice(&self.avg_bytes_per_sec.to_le_bytes());
        out.extend_from_slice(&self.block_align.to_le_bytes());
        out.extend_from_slice(&self.bits_per_sample.to_le_bytes());
        out.extend_from_slice(&(self.extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.extra);
    }

    /// The bytes this format takes on the wire.
    pub(crate) fn encoded_len(&self) -> usize {
        AUDIO_FORMAT_FIXED_SIZE + self.extra.len()
    }
}

/// The fields a WaveInfo PDU (2.2.3.3) carries for the Wave PDU that follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaveInfo {
    /// `wTimeStamp`.
    pub timestamp: u16,
    /// `wFormatNo`: an index into the client's format list.
    pub format_no: u16,
    /// `cBlockNo`.
    pub block_no: u8,
    /// The first four bytes of the audio sample.
    pub head: [u8; 4],
    /// The audio sample's length: `BodySize` less 8.
    pub sample_len: usize,
}

/// A server-to-client PDU, decoded from one whole channel message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerPdu {
    /// Server Audio Formats and Version (2.2.2.1).
    Formats {
        /// `cLastBlockConfirmed`: the block number before the first one the server sends.
        last_block_confirmed: u8,
        /// `wVersion`.
        version: u16,
        /// `sndFormats`.
        formats: Vec<AudioFormat>,
    },
    /// Training (2.2.3.1).
    Training {
        /// `wTimeStamp`.
        timestamp: u16,
        /// `wPackSize`.
        pack_size: u16,
    },
    /// WaveInfo (2.2.3.3): the next message is the Wave PDU it describes.
    WaveInfo(WaveInfo),
    /// Wave2 (2.2.3.10).
    Wave2 {
        /// `wTimeStamp`.
        timestamp: u16,
        /// `wFormatNo`: an index into the client's format list.
        format_no: u16,
        /// `cBlockNo`.
        block_no: u8,
        /// `dwAudioTimeStamp`.
        audio_timestamp: u32,
        /// The audio sample.
        data: Vec<u8>,
    },
    /// Close (2.2.3.9).
    Close,
    /// Volume (2.2.4.1): the left channel in the low word, the right in the high word.
    Volume(u32),
    /// Pitch (2.2.4.2), which the client MUST ignore.
    Pitch(u32),
    /// A `msgType` this module does not decode.
    Unknown {
        /// The `msgType`.
        msg_type: u8,
    },
}

impl ServerPdu {
    /// Decode one channel message that is not a Wave PDU.
    pub fn decode(message: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(message, "SNDPROLOG");
        let msg_type = cur.read_u8()?;
        let _pad = cur.read_u8()?;
        let body_size = usize::from(cur.read_u16_le()?);
        if msg_type == SNDC_WAVE {
            return Self::decode_wave_info(&mut cur, body_size);
        }
        let body = cur
            .read_slice(body_size)
            .map_err(|_| DecodeError::InvalidField {
                field: "SNDPROLOG.BodySize",
                reason: "runs past the message",
            })?;
        let mut cur = ReadCursor::new(body, "RDPSND body");
        match msg_type {
            SNDC_FORMATS => {
                let _flags = cur.read_u32_le()?;
                let _volume = cur.read_u32_le()?;
                let _pitch = cur.read_u32_le()?;
                let _dgram_port = cur.read_u16_be()?;
                let count = cur.read_u16_le()?;
                let last_block_confirmed = cur.read_u8()?;
                let version = cur.read_u16_le()?;
                let _pad = cur.read_u8()?;
                let formats = (0..count)
                    .map(|_| AudioFormat::decode(&mut cur))
                    .collect::<Result<_, _>>()?;
                Ok(Self::Formats {
                    last_block_confirmed,
                    version,
                    formats,
                })
            }
            SNDC_TRAINING => Ok(Self::Training {
                timestamp: cur.read_u16_le()?,
                pack_size: cur.read_u16_le()?,
            }),
            SNDC_WAVE2 => {
                let timestamp = cur.read_u16_le()?;
                let format_no = cur.read_u16_le()?;
                let block_no = cur.read_u8()?;
                let _pad = cur.read_slice(3)?;
                let audio_timestamp = cur.read_u32_le()?;
                let data = cur.read_slice(cur.remaining())?.to_vec();
                Ok(Self::Wave2 {
                    timestamp,
                    format_no,
                    block_no,
                    audio_timestamp,
                    data,
                })
            }
            SNDC_CLOSE => Ok(Self::Close),
            SNDC_SETVOLUME => Ok(Self::Volume(cur.read_u32_le()?)),
            SNDC_SETPITCH => Ok(Self::Pitch(cur.read_u32_le()?)),
            msg_type => Ok(Self::Unknown { msg_type }),
        }
    }

    /// The WaveInfo body. Its `BodySize` counts the Wave PDU's data too, so it bounds nothing
    /// in this message. A sample length the spec forbids is refused by [`decode_wave`], so that
    /// the Wave PDU still takes its place.
    fn decode_wave_info(cur: &mut ReadCursor<'_>, body_size: usize) -> Result<Self, DecodeError> {
        let timestamp = cur.read_u16_le()?;
        let format_no = cur.read_u16_le()?;
        let block_no = cur.read_u8()?;
        let _pad = cur.read_slice(3)?;
        let head = cur.read_slice(4)?;
        let sample_len = body_size.saturating_sub(WAVE_INFO_FIXED_SIZE);
        Ok(Self::WaveInfo(WaveInfo {
            timestamp,
            format_no,
            block_no,
            head: [head[0], head[1], head[2], head[3]],
            sample_len,
        }))
    }
}

/// The audio sample a Wave PDU (2.2.3.4) carries: its four pad bytes replaced by the four bytes
/// `info` carried. The sample must be longer than four bytes (2.2.3.3), and the message exactly
/// as long as `info` announced.
pub fn decode_wave(info: &WaveInfo, message: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if info.sample_len <= 4 {
        return Err(DecodeError::InvalidField {
            field: "SNDPROLOG.BodySize",
            reason: "a WaveInfo PDU announced an audio sample of four bytes or fewer",
        });
    }
    if message.len() != info.sample_len {
        return Err(DecodeError::InvalidField {
            field: "SNDWAVE",
            reason: "the Wave PDU is not as long as its WaveInfo PDU announced",
        });
    }
    let mut sample = message.to_vec();
    sample[..4].copy_from_slice(&info.head);
    Ok(sample)
}

/// A message with its `SNDPROLOG`.
fn with_header(msg_type: u8, body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    out.push(0);
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// The fields a client sends in its Audio Formats and Version PDU (2.2.2.2). `wDGramPort` is
/// always 0, which keeps audio on the virtual channel (3.2.5.1.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFormats {
    /// `dwFlags`: `TSSNDCAPS_*`.
    pub flags: u32,
    /// `dwVolume`, meaningful with [`TSSNDCAPS_VOLUME`].
    pub volume: u32,
    /// `dwPitch`, meaningful with [`TSSNDCAPS_PITCH`].
    pub pitch: u32,
    /// `wVersion`.
    pub version: u16,
    /// `sndFormats`, each one from the server's list.
    pub formats: Vec<AudioFormat>,
}

/// Encode a Client Audio Formats and Version PDU.
pub fn encode_client_formats(client: &ClientFormats) -> Vec<u8> {
    let formats_len: usize = client.formats.iter().map(AudioFormat::encoded_len).sum();
    let mut body = Vec::with_capacity(FORMATS_FIXED_SIZE + formats_len);
    body.extend_from_slice(&client.flags.to_le_bytes());
    body.extend_from_slice(&client.volume.to_le_bytes());
    body.extend_from_slice(&client.pitch.to_le_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&(client.formats.len() as u16).to_le_bytes());
    body.push(0); // cLastBlockConfirmed: unused from the client
    body.extend_from_slice(&client.version.to_le_bytes());
    body.push(0);
    for format in &client.formats {
        format.encode(&mut body);
    }
    with_header(SNDC_FORMATS, body)
}

/// Encode a Quality Mode PDU (2.2.2.3).
pub fn encode_quality_mode(quality_mode: u16) -> Vec<u8> {
    let mut body = quality_mode.to_le_bytes().to_vec();
    body.extend_from_slice(&0u16.to_le_bytes());
    with_header(SNDC_QUALITYMODE, body)
}

/// Encode a Training Confirm PDU (2.2.3.2), echoing the Training PDU's fields.
pub fn encode_training_confirm(timestamp: u16, pack_size: u16) -> Vec<u8> {
    let mut body = timestamp.to_le_bytes().to_vec();
    body.extend_from_slice(&pack_size.to_le_bytes());
    with_header(SNDC_TRAINING, body)
}

/// Encode a Wave Confirm PDU (2.2.3.8).
pub fn encode_wave_confirm(timestamp: u16, block_no: u8) -> Vec<u8> {
    let mut body = timestamp.to_le_bytes().to_vec();
    body.push(block_no);
    body.push(0);
    with_header(SNDC_WAVECONFIRM, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `[MS-RDPEA]` 4.1.1, byte for byte.
    const SERVER_FORMATS: &str = "072b900008fb8b00e0f1090070271f7700000500ff050000010002002256000088580100040010000000060002002256000044ac0000020008000000070002002256000044ac0000020008000000020002002256000027570000000404002000f403070000010000000200ff00000000c0004000f0000000cc0130ff880118ff1100020022560000b9560000000404000200f903";

    /// `[MS-RDPEA]` 4.1.2, byte for byte.
    const CLIENT_FORMATS: &str = "0700900003000000ffffffff00f7f900000005002805007c010002002256000088580100040010000000060002002256000044ac0000020008000000070002002256000044ac0000020008000000020002002256000027570000000404002000f403070000010000000200ff00000000c0004000f0000000cc0130ff880118ff1100020022560000b9560000000404000200f903";

    fn pcm_22050_stereo_16() -> AudioFormat {
        AudioFormat {
            format_tag: WAVE_FORMAT_PCM,
            channels: 2,
            samples_per_sec: 22050,
            avg_bytes_per_sec: 88200,
            block_align: 4,
            bits_per_sample: 16,
            extra: Vec::new(),
        }
    }

    #[test]
    fn the_specs_server_formats_decode() {
        let ServerPdu::Formats {
            last_block_confirmed,
            version,
            formats,
        } = ServerPdu::decode(&hex(SERVER_FORMATS)).unwrap()
        else {
            panic!("not Formats");
        };
        assert_eq!((last_block_confirmed, version), (255, 5));
        let tags: Vec<u16> = formats.iter().map(|f| f.format_tag).collect();
        assert_eq!(tags, [1, 6, 7, 2, 0x11]);
        assert_eq!(formats[0], pcm_22050_stereo_16());
        // MS ADPCM carries 32 bytes of extra data: samples per block and its coefficients.
        assert_eq!(formats[3].extra.len(), 32);
        assert_eq!(&formats[3].extra[..4], &[0xf4, 0x03, 0x07, 0x00]);
        assert_eq!(formats[4].extra, [0xf9, 0x03]);
    }

    /// The client PDU of 4.1.2 re-encodes from the server's formats; its `dwPitch`,
    /// `cLastBlockConfirmed` and `bPad` are arbitrary there and zero here.
    #[test]
    fn the_specs_client_formats_encode() {
        let ServerPdu::Formats { formats, .. } = ServerPdu::decode(&hex(SERVER_FORMATS)).unwrap()
        else {
            panic!("not Formats");
        };
        let mut expected = hex(CLIENT_FORMATS);
        expected[12..16].copy_from_slice(&[0; 4]); // dwPitch
        expected[20] = 0; // cLastBlockConfirmed
        expected[23] = 0; // bPad
        let encoded = encode_client_formats(&ClientFormats {
            flags: TSSNDCAPS_ALIVE | TSSNDCAPS_VOLUME,
            volume: 0xFFFF_FFFF,
            pitch: 0,
            version: 5,
            formats,
        });
        assert_eq!(encoded, expected);
    }

    /// 4.1.4 (its `bPad` is arbitrary there and zero here) and 4.2.3 (likewise).
    #[test]
    fn the_specs_confirms_encode() {
        assert_eq!(
            encode_training_confirm(0x89da, 0x0400),
            hex("06000400da890004")
        );
        assert_eq!(encode_wave_confirm(0x5ab7, 8), hex("05000400b75a0800"));
    }

    #[test]
    fn quality_mode_encodes() {
        assert_eq!(encode_quality_mode(HIGH_QUALITY), hex("0c00040002000000"));
    }

    /// 4.1.3's header and fields; the spec elides the 1,020 data bytes, so zeros stand in.
    #[test]
    fn the_specs_training_decodes() {
        let mut message = hex("0623fc03da890004");
        message.resize(4 + 0x3fc, 0);
        assert_eq!(
            ServerPdu::decode(&message),
            Ok(ServerPdu::Training {
                timestamp: 0x89da,
                pack_size: 0x0400,
            })
        );
    }

    /// 4.2.1: `BodySize` 593 announces a 585-byte sample, the Wave PDU's length.
    #[test]
    fn the_specs_wave_info_decodes_and_the_wave_takes_its_head() {
        let info = WaveInfo {
            timestamp: 0xadd7,
            format_no: 15,
            block_no: 8,
            head: [0x20, 0x48, 0x17, 0xd6],
            sample_len: 585,
        };
        assert_eq!(
            ServerPdu::decode(&hex("027e5102d7ad0f0008000000204817d6")),
            Ok(ServerPdu::WaveInfo(info))
        );
        let mut wave = vec![0u8; 585];
        wave[4..9].copy_from_slice(&hex("8402802449"));
        let sample = decode_wave(&info, &wave).unwrap();
        assert_eq!(&sample[..9], &hex("204817d68402802449"));
        assert!(decode_wave(&info, &wave[..584]).is_err());
        assert!(decode_wave(&info, &[wave.clone(), vec![0]].concat()).is_err());
    }

    /// 4.2.4's header and fields; the spec elides most of the 248 data bytes.
    #[test]
    fn the_specs_wave2_decodes() {
        let mut message = hex("0d00040116a1030002000000c2b8ac0d");
        message.resize(4 + 0x104, 0xAB);
        let ServerPdu::Wave2 {
            timestamp,
            format_no,
            block_no,
            audio_timestamp,
            data,
        } = ServerPdu::decode(&message).unwrap()
        else {
            panic!("not Wave2");
        };
        assert_eq!(
            (timestamp, format_no, block_no, audio_timestamp),
            (0xa116, 3, 2, 229_423_298)
        );
        assert_eq!(data.len(), 0x104 - 12);
    }

    #[test]
    fn close_volume_pitch_and_unknown_decode() {
        assert_eq!(ServerPdu::decode(&hex("01000000")), Ok(ServerPdu::Close));
        assert_eq!(
            ServerPdu::decode(&hex("030004000000ffff")),
            Ok(ServerPdu::Volume(0xFFFF_0000))
        );
        assert_eq!(
            ServerPdu::decode(&hex("0400040000000100")),
            Ok(ServerPdu::Pitch(0x0001_0000))
        );
        assert_eq!(
            ServerPdu::decode(&hex("0a000000")),
            Ok(ServerPdu::Unknown { msg_type: 0x0a })
        );
    }

    #[test]
    fn malformed_messages_are_typed_errors() {
        // BodySize past the message.
        assert!(ServerPdu::decode(&hex("07000800000000")).is_err());
        // A format list that claims one more format than it holds.
        let mut formats = hex(SERVER_FORMATS);
        formats[18] = 6;
        assert!(ServerPdu::decode(&formats).is_err());
        // A WaveInfo announcing a sample of four bytes still decodes, so the Wave PDU after it
        // keeps its place; the Wave is what is refused (2.2.3.3: the sample MUST be greater
        // than four bytes).
        let Ok(ServerPdu::WaveInfo(short)) =
            ServerPdu::decode(&hex("02000c00d7ad0f0008000000204817d6"))
        else {
            panic!("a short WaveInfo still decodes");
        };
        assert_eq!(short.sample_len, 4);
        assert!(decode_wave(&short, &[0; 4]).is_err());
        // Truncated headers.
        assert!(ServerPdu::decode(&hex("07")).is_err());
        assert!(ServerPdu::decode(&hex("020051")).is_err());
    }

    proptest! {
        /// Untrusted messages never panic, whatever the `msgType`.
        #[test]
        fn decode_never_panics(
            msg_type in prop_oneof![1u8..=13, any::<u8>()],
            body_size in prop_oneof![0u16..64, any::<u16>()],
            body in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            let mut message = vec![msg_type, 0];
            message.extend_from_slice(&body_size.to_le_bytes());
            message.extend_from_slice(&body);
            if let Ok(ServerPdu::WaveInfo(info)) = ServerPdu::decode(&message) {
                let _ = decode_wave(&info, &body);
            }
        }

        /// A format list round-trips through the client encoder and the server decoder, which
        /// share the layout.
        #[test]
        fn formats_round_trip(
            formats in proptest::collection::vec(
                (any::<u16>(), any::<u16>(), any::<u32>(), any::<u32>(), any::<u16>(), any::<u16>(),
                 proptest::collection::vec(any::<u8>(), 0..8)),
                0..4,
            ),
            version in any::<u16>(),
        ) {
            let formats: Vec<AudioFormat> = formats
                .into_iter()
                .map(|(format_tag, channels, samples_per_sec, avg_bytes_per_sec, block_align, bits_per_sample, extra)| AudioFormat {
                    format_tag, channels, samples_per_sec, avg_bytes_per_sec, block_align, bits_per_sample, extra,
                })
                .collect();
            let message = encode_client_formats(&ClientFormats {
                flags: TSSNDCAPS_ALIVE,
                volume: 0,
                pitch: 0,
                version,
                formats: formats.clone(),
            });
            prop_assert_eq!(
                ServerPdu::decode(&message),
                Ok(ServerPdu::Formats { last_block_confirmed: 0, version, formats })
            );
        }
    }
}
