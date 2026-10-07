//! Audio input virtual channel PDUs (MS-RDPEAI), carried over the dynamic channel
//! [`CHANNEL_NAME`]. Every PDU opens with a one-byte `MessageId` (2.2.1); multi-byte fields are
//! little-endian. An audio format is `[MS-RDPEA]`'s `AUDIO_FORMAT`, the same as the audio output
//! channel's [`AudioFormat`].

use crate::cursor::ReadCursor;
use crate::error::DecodeError;
pub use crate::rdpsnd::AudioFormat;

/// The dynamic channel name (2.1).
pub const CHANNEL_NAME: &str = "AUDIO_INPUT";

/// `MSG_SNDIN_VERSION`, the Version PDU (2.2.2.1).
pub const MSG_SNDIN_VERSION: u8 = 0x01;
/// `MSG_SNDIN_FORMATS`, the Sound Formats PDU (2.2.2.2).
pub const MSG_SNDIN_FORMATS: u8 = 0x02;
/// `MSG_SNDIN_OPEN`, the Open PDU (2.2.2.3).
pub const MSG_SNDIN_OPEN: u8 = 0x03;
/// `MSG_SNDIN_OPEN_REPLY`, the Open Reply PDU (2.2.2.4).
pub const MSG_SNDIN_OPEN_REPLY: u8 = 0x04;
/// `MSG_SNDIN_DATA_INCOMING`, the Incoming Data PDU (2.2.3.1).
pub const MSG_SNDIN_DATA_INCOMING: u8 = 0x05;
/// `MSG_SNDIN_DATA`, the Data PDU (2.2.3.2).
pub const MSG_SNDIN_DATA: u8 = 0x06;
/// `MSG_SNDIN_FORMATCHANGE`, the Format Change PDU (2.2.4.1).
pub const MSG_SNDIN_FORMATCHANGE: u8 = 0x07;

/// The Sound Formats PDU's bytes before its formats: `MessageId`, `NumFormats` and
/// `cbSizeFormatsPacket`.
const FORMATS_FIXED_SIZE: usize = 9;

/// The Open PDU's request to start recording (2.2.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    /// `FramesPerPacket`: the audio frames each Data PDU carries.
    pub frames_per_packet: u32,
    /// `initialFormat`: the index, in the client's format list, of the format to encode in.
    pub initial_format: u32,
    /// The format the server suggests capturing from the device in, its `cbSize` bytes
    /// included (a `WAVEFORMAT_EXTENSIBLE` when the tag is `0xFFFE`).
    pub capture_format: AudioFormat,
}

/// A message the server sends on the audio input channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerPdu {
    /// The server's protocol version (2.2.2.1).
    Version(u32),
    /// The audio formats the server supports (2.2.2.2).
    Formats(Vec<AudioFormat>),
    /// The server asks the client to start recording (2.2.2.3).
    Open(Open),
    /// The server asks for another format from the client's list, by index (2.2.4.1).
    FormatChange(u32),
    /// A `MessageId` the server does not send.
    Unknown {
        /// The `MessageId`.
        message_id: u8,
    },
}

impl ServerPdu {
    /// Decode one channel message. Bytes past the fields are ignored, including a Sound Formats
    /// PDU's `ExtraData` (2.2.2.2).
    pub fn decode(message: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(message, "SNDIN_PDU");
        Ok(match cur.read_u8()? {
            MSG_SNDIN_VERSION => ServerPdu::Version(cur.read_u32_le()?),
            MSG_SNDIN_FORMATS => {
                let num_formats = cur.read_u32_le()?;
                let _cb_size_formats_packet = cur.read_u32_le()?;
                let mut formats = Vec::new();
                for _ in 0..num_formats {
                    formats.push(AudioFormat::decode(&mut cur)?);
                }
                ServerPdu::Formats(formats)
            }
            MSG_SNDIN_OPEN => ServerPdu::Open(Open {
                frames_per_packet: cur.read_u32_le()?,
                initial_format: cur.read_u32_le()?,
                capture_format: AudioFormat::decode(&mut cur)?,
            }),
            MSG_SNDIN_FORMATCHANGE => ServerPdu::FormatChange(cur.read_u32_le()?),
            message_id => ServerPdu::Unknown { message_id },
        })
    }
}

/// A PDU of one `MessageId` and one 32-bit field.
fn encode_u32(message_id: u8, value: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(message_id);
    out.extend_from_slice(&value.to_le_bytes());
    out
}

/// The client's Version PDU (2.2.2.1).
pub fn encode_version(version: u32) -> Vec<u8> {
    encode_u32(MSG_SNDIN_VERSION, version)
}

/// The client's Sound Formats PDU (2.2.2.2), with no `ExtraData`, so `cbSizeFormatsPacket` is the
/// whole PDU's length.
pub fn encode_formats(formats: &[AudioFormat]) -> Vec<u8> {
    let len = FORMATS_FIXED_SIZE + formats.iter().map(AudioFormat::encoded_len).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.push(MSG_SNDIN_FORMATS);
    out.extend_from_slice(&(formats.len() as u32).to_le_bytes());
    out.extend_from_slice(&(len as u32).to_le_bytes());
    for format in formats {
        format.encode(&mut out);
    }
    out
}

/// The Open Reply PDU (2.2.2.4) with this `HRESULT`.
pub fn encode_open_reply(result: u32) -> Vec<u8> {
    encode_u32(MSG_SNDIN_OPEN_REPLY, result)
}

/// The Incoming Data PDU (2.2.3.1).
pub fn encode_incoming_data() -> Vec<u8> {
    vec![MSG_SNDIN_DATA_INCOMING]
}

/// The Data PDU (2.2.3.2) carrying `data`.
pub fn encode_data(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + data.len());
    out.push(MSG_SNDIN_DATA);
    out.extend_from_slice(data);
    out
}

/// The client's Format Change PDU (2.2.4.1).
pub fn encode_format_change(new_format: u32) -> Vec<u8> {
    encode_u32(MSG_SNDIN_FORMATCHANGE, new_format)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdpsnd::{WAVE_FORMAT_ADPCM, WAVE_FORMAT_DVI_ADPCM, WAVE_FORMAT_PCM};
    use proptest::prelude::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `[MS-RDPEAI]` 4.1.1 and 4.1.2: the server's and the client's Version PDUs are the same
    /// bytes.
    const VERSION_1: &str = "0101000000";
    /// `[MS-RDPEAI]` 4.1.7, 4.3.1 and 4.3.2: every Format Change PDU in the examples.
    const FORMAT_CHANGE_11: &str = "070b000000";
    /// `[MS-RDPEAI]` 4.1.8.
    const OPEN_REPLY_S_OK: &str = "0400000000";

    /// `[MS-RDPEAI]` 4.1.3, byte for byte (667 bytes).
    const SERVER_FORMATS: &str = concat!(
        "0215000000000000800100020044ac000010b102000400100000000200020044ac000047ad00000008040020",
        "00f407070000010000000200ff00000000c0004000f0000000cc0130ff880118ff1100020044ac0000dbac00",
        "00000804000200f907020002002256000027570000000404002000f403070000010000000200ff00000000c0",
        "004000f0000000cc0130ff880118ff1100020022560000b9560000000404000200f9030200010044ac0000a3",
        "560000000404002000f407070000010000000200ff00000000c0004000f0000000cc0130ff880118ff110001",
        "0044ac00006d560000000404000200f90702000200112b0000192c0000000204002000f40107000001000000",
        "0200ff00000000c0004000f0000000cc0130ff880118ff11000200112b0000a92b0000000204000200f90102",
        "00010022560000932b0000000204002000f403070000010000000200ff00000000c0004000f0000000cc0130",
        "ff880118ff11000100225600005c2b0000000204000200f9033100010044ac0000fd22000041000000020040",
        "0102000200401f000000200000000204002000f401070000010000000200ff00000000c0004000f0000000cc",
        "0130ff880118ff11000200401f0000ae1f0000000204000200f90102000100112b00000c1600000001040020",
        "00f401070000010000000200ff00000000c0004000f0000000cc0130ff880118ff11000100112b0000d41500",
        "00000104000200f90131000100225600007e110000410000000200400102000100401f000000100000000104",
        "002000f401070000010000000200ff00000000c0004000f0000000cc0130ff880118ff11000100401f0000d7",
        "0f0000000104000200f90131000100112b0000bf080000410000000200400131000100401f00005906000041",
        "00000002004001",
    );

    /// `[MS-RDPEAI]` 4.1.5, byte for byte (704 bytes).
    const CLIENT_FORMATS: &str = concat!(
        "02150000009b0200000100020044ac000010b102000400100000000200020044ac000047ad00000008040020",
        "00f407070000010000000200ff00000000c0004000f0000000cc0130ff880118ff1100020044ac0000dbac00",
        "00000804000200f907020002002256000027570000000404002000f403070000010000000200ff00000000c0",
        "004000f0000000cc0130ff880118ff1100020022560000b9560000000404000200f9030200010044ac0000a3",
        "560000000404002000f407070000010000000200ff00000000c0004000f0000000cc0130ff880118ff110001",
        "0044ac00006d560000000404000200f90702000200112b0000192c0000000204002000f40107000001000000",
        "0200ff00000000c0004000f0000000cc0130ff880118ff11000200112b0000a92b0000000204000200f90102",
        "00010022560000932b0000000204002000f403070000010000000200ff00000000c0004000f0000000cc0130",
        "ff880118ff11000100225600005c2b0000000204000200f9033100010044ac0000fd22000041000000020040",
        "0102000200401f000000200000000204002000f401070000010000000200ff00000000c0004000f0000000cc",
        "0130ff880118ff11000200401f0000ae1f0000000204000200f90102000100112b00000c1600000001040020",
        "00f401070000010000000200ff00000000c0004000f0000000cc0130ff880118ff11000100112b0000d41500",
        "00000104000200f90131000100225600007e110000410000000200400102000100401f000000100000000104",
        "002000f401070000010000000200ff00000000c0004000f0000000cc0130ff880118ff11000100401f0000d7",
        "0f0000000104000200f90131000100112b0000bf080000410000000200400131000100401f00005906000041",
        "0000000200400100000000000000000000000000000000000000000000000000000000000000000000000000",
    );

    /// `[MS-RDPEAI]` 4.1.6, byte for byte (49 bytes).
    const OPEN: &str = concat!(
        "039d0800000b000000feff020044ac000010b102000400100016001000030000000100000000001000800000",
        "aa00389b71",
    );

    /// `[MS-RDPEAI]` 4.2.2, byte for byte (391 bytes).
    const DATA: &str = concat!(
        "06d638995905ac56932405d4df135ac67cb66e7b0bbb2dd9e95c042efc64d9891d5989711d2db1b2b1e51cb9",
        "4c78c1f76d133bb67726edb6bdebb6d960df4e2d59a797099311d3769a4db9605bc6ca3b2d2b75d9a3c41899",
        "3649d3442ef6c93411485695912428f5c08f7624176e51c2ac00001004741625499224a161da4444499224d3",
        "07d7cda2bd95e448ae06074b7dfb3852e2a8242d0912404962c36c00122449f26c8eee405ece8620492245cf",
        "8f499224c93776356178dcb68d2b9c380c499224d308d7d514654c10800400f2db7bdbc653e1bc2399647392",
        "2449553922c97d7dbb8033194c52eefefbb4db963fc68a9664db96e58851521bb78d785cfeffffffff51e816",
        "11635fac22cd9265510f981f499224c9cc962449920c3c6df6dc489294778d919d51d06fc99124899567b173",
        "46db4c99a9c025772e61923d426ddffe5ddf93f8d69553a3d1ff6fdbb6bd66b2edd9b66d5b777cdbb66d6067",
        "cf14274992246ba1b01931576799eb25ddeae29a71e1254992be9c63926507c5c9c2c79223b44d",
    );

    fn formats(pdu: ServerPdu) -> Vec<AudioFormat> {
        match pdu {
            ServerPdu::Formats(formats) => formats,
            other => panic!("not Formats: {other:?}"),
        }
    }

    #[test]
    fn the_specs_version_pdus_decode_and_encode() {
        assert_eq!(
            ServerPdu::decode(&hex(VERSION_1)),
            Ok(ServerPdu::Version(1))
        );
        assert_eq!(encode_version(1), hex(VERSION_1));
    }

    #[test]
    fn the_specs_server_formats_decode() {
        let formats = formats(ServerPdu::decode(&hex(SERVER_FORMATS)).unwrap());
        assert_eq!(formats.len(), 21);
        assert_eq!(
            formats[0],
            AudioFormat {
                format_tag: WAVE_FORMAT_PCM,
                channels: 2,
                samples_per_sec: 44100,
                avg_bytes_per_sec: 176_400,
                block_align: 4,
                bits_per_sample: 16,
                extra: Vec::new(),
            }
        );
        assert_eq!(formats[1].format_tag, WAVE_FORMAT_ADPCM);
        assert_eq!(formats[1].extra.len(), 32);
        assert_eq!(formats[2].format_tag, WAVE_FORMAT_DVI_ADPCM);
        assert_eq!(formats[2].extra, [0xf9, 0x07]);
        // GSM 6.10, the last format, with its two-byte samples-per-block extra.
        assert_eq!(formats[20].format_tag, 0x0031);
        assert_eq!(formats[20].extra, [0x40, 0x01]);
    }

    /// The client's list in 4.1.5 holds the server's 21 formats and 37 bytes of `ExtraData`;
    /// `cbSizeFormatsPacket` counts everything but those. Encoding the formats with no
    /// `ExtraData` gives exactly the counted bytes.
    #[test]
    fn the_specs_client_formats_are_the_server_formats_re_encoded() {
        let server = formats(ServerPdu::decode(&hex(SERVER_FORMATS)).unwrap());
        let client = hex(CLIENT_FORMATS);
        assert_eq!(encode_formats(&server), client[..667]);
        assert_eq!(formats(ServerPdu::decode(&client).unwrap()), server);
    }

    #[test]
    fn the_specs_open_pdu_decodes() {
        let ServerPdu::Open(open) = ServerPdu::decode(&hex(OPEN)).unwrap() else {
            panic!("not Open");
        };
        assert_eq!((open.frames_per_packet, open.initial_format), (2205, 11));
        let capture = open.capture_format;
        assert_eq!(capture.format_tag, 0xFFFE);
        assert_eq!(
            (
                capture.channels,
                capture.samples_per_sec,
                capture.bits_per_sample
            ),
            (2, 44100, 16)
        );
        assert_eq!(capture.extra.len(), 22);
        // wValidBitsPerSample 16, dwChannelMask front left | front right.
        assert_eq!(&capture.extra[..6], &[0x10, 0x00, 0x03, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn the_specs_format_change_decodes_and_encodes() {
        assert_eq!(
            ServerPdu::decode(&hex(FORMAT_CHANGE_11)),
            Ok(ServerPdu::FormatChange(11))
        );
        assert_eq!(encode_format_change(11), hex(FORMAT_CHANGE_11));
    }

    #[test]
    fn the_specs_client_pdus_encode() {
        assert_eq!(encode_open_reply(0), hex(OPEN_REPLY_S_OK));
        assert_eq!(encode_incoming_data(), [MSG_SNDIN_DATA_INCOMING]);
        let data = hex(DATA);
        assert_eq!(encode_data(&data[1..]), data);
    }

    #[test]
    fn a_message_id_the_server_does_not_send_is_unknown() {
        for message_id in [0x00, MSG_SNDIN_OPEN_REPLY, MSG_SNDIN_DATA, 0x08, 0xFF] {
            assert_eq!(
                ServerPdu::decode(&[message_id, 1, 2, 3]),
                Ok(ServerPdu::Unknown { message_id })
            );
        }
    }

    #[test]
    fn truncated_pdus_are_errors() {
        let open = hex(OPEN);
        for message in [
            &[][..],
            &hex(VERSION_1)[..4],
            &hex(FORMAT_CHANGE_11)[..3],
            &open[..open.len() - 1],
            &hex(SERVER_FORMATS)[..100],
        ] {
            assert!(
                matches!(
                    ServerPdu::decode(message),
                    Err(DecodeError::NotEnoughBytes { .. })
                ),
                "{message:02x?}"
            );
        }
    }

    /// A `NumFormats` far beyond the message fails on the bytes, not on an allocation.
    #[test]
    fn a_huge_format_count_is_a_short_read() {
        let mut message = vec![MSG_SNDIN_FORMATS];
        message.extend_from_slice(&u32::MAX.to_le_bytes());
        message.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            ServerPdu::decode(&message),
            Err(DecodeError::NotEnoughBytes { .. })
        ));
    }

    proptest! {
        /// Untrusted server messages never panic.
        #[test]
        fn decode_never_panics(message in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = ServerPdu::decode(&message);
        }

        /// The Version and Format Change PDUs the client sends have the server's layout, so they
        /// decode back to the same value.
        #[test]
        fn client_version_and_format_change_round_trip(value in any::<u32>()) {
            prop_assert_eq!(ServerPdu::decode(&encode_version(value)), Ok(ServerPdu::Version(value)));
            prop_assert_eq!(
                ServerPdu::decode(&encode_format_change(value)),
                Ok(ServerPdu::FormatChange(value))
            );
        }
    }
}
