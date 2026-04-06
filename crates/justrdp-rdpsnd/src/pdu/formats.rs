#![forbid(unsafe_code)]

//! Server/Client Audio Formats and Version PDU -- MS-RDPEA 2.2.2.1, 2.2.2.2

use alloc::vec::Vec;

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{Decode, DecodeResult, Encode, EncodeResult};

use super::audio_format::AudioFormat;
use super::header::{SndHeader, SndMsgType, SND_HEADER_SIZE};

/// Fixed body size for formats PDU (before the format array).
const FORMATS_BODY_FIXED_SIZE: usize = 20;

/// Maximum number of audio formats in a single PDU.
/// Real servers advertise fewer than 100; cap to prevent DoS.
const MAX_AUDIO_FORMATS: u16 = 256;

/// Client sound capability flags -- MS-RDPEA 2.2.2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientSndFlags(u32);

impl ClientSndFlags {
    /// Client can consume audio.
    pub const ALIVE: Self = Self(0x0000_0001);
    /// Client supports volume control.
    pub const VOLUME: Self = Self(0x0000_0002);
    /// Client supports pitch control.
    pub const PITCH: Self = Self(0x0000_0004);

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Get raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check if a flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Server Audio Formats and Version PDU -- MS-RDPEA 2.2.2.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAudioFormatsPdu {
    /// Initial block number counter.
    pub last_block_confirmed: u8,
    /// Server protocol version.
    pub version: u16,
    /// Supported audio formats.
    pub formats: Vec<AudioFormat>,
}

impl ServerAudioFormatsPdu {
    /// Decode from cursor after the header has been read.
    pub fn decode_body(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let _dw_flags = src.read_u32_le("ServerFormats::dwFlags")?;
        let _dw_volume = src.read_u32_le("ServerFormats::dwVolume")?;
        let _dw_pitch = src.read_u32_le("ServerFormats::dwPitch")?;
        let _w_dgram_port = src.read_u16_le("ServerFormats::wDGramPort")?;
        let num_formats = src.read_u16_le("ServerFormats::wNumberOfFormats")?;
        if num_formats > MAX_AUDIO_FORMATS {
            return Err(justrdp_core::DecodeError::invalid_value(
                "ServerFormats",
                "wNumberOfFormats exceeds limit",
            ));
        }
        let last_block_confirmed = src.read_u8("ServerFormats::cLastBlockConfirmed")?;
        let version = src.read_u16_le("ServerFormats::wVersion")?;
        let _pad = src.read_u8("ServerFormats::bPad")?;

        let mut formats = Vec::with_capacity(num_formats as usize);
        for _ in 0..num_formats {
            formats.push(AudioFormat::decode(src)?);
        }

        Ok(Self {
            last_block_confirmed,
            version,
            formats,
        })
    }
}

/// Client Audio Formats and Version PDU -- MS-RDPEA 2.2.2.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAudioFormatsPdu {
    /// Capability flags.
    pub flags: ClientSndFlags,
    /// Initial volume (left in low word, right in high word).
    pub volume: u32,
    /// Pitch multiplier (fixed-point).
    pub pitch: u32,
    /// Client protocol version.
    pub version: u16,
    /// Supported audio formats (intersection of server's list).
    pub formats: Vec<AudioFormat>,
}

impl ClientAudioFormatsPdu {
    fn body_size(&self) -> usize {
        FORMATS_BODY_FIXED_SIZE + self.formats.iter().map(|f| f.size()).sum::<usize>()
    }
}

impl Encode for ClientAudioFormatsPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let body_size = u16::try_from(self.body_size())
            .map_err(|_| justrdp_core::EncodeError::invalid_value("ClientFormats", "body too large"))?;
        let num_formats = u16::try_from(self.formats.len())
            .map_err(|_| justrdp_core::EncodeError::invalid_value("ClientFormats", "too many formats"))?;
        let header = SndHeader::new(SndMsgType::Formats, body_size);
        header.encode(dst)?;
        dst.write_u32_le(self.flags.bits(), "ClientFormats::dwFlags")?;
        dst.write_u32_le(self.volume, "ClientFormats::dwVolume")?;
        dst.write_u32_le(self.pitch, "ClientFormats::dwPitch")?;
        // MS-RDPEA 2.2.2.2: wDGramPort, 0 = no UDP
        dst.write_u16_le(0, "ClientFormats::wDGramPort")?;
        dst.write_u16_le(num_formats, "ClientFormats::wNumberOfFormats")?;
        dst.write_u8(0, "ClientFormats::cLastBlockConfirmed")?;
        dst.write_u16_le(self.version, "ClientFormats::wVersion")?;
        dst.write_u8(0, "ClientFormats::bPad")?;
        for fmt in &self.formats {
            fmt.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ClientAudioFormatsPdu"
    }

    fn size(&self) -> usize {
        SND_HEADER_SIZE + self.body_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::audio_format::WaveFormatTag;

    #[test]
    fn server_formats_spec_test_vector() {
        // MS-RDPEA annotated dump (partial: header + first format)
        #[rustfmt::skip]
        let bytes: alloc::vec::Vec<u8> = alloc::vec![
            // Header
            0x07, 0x2b, 0x90, 0x00,
            // Body fixed fields
            0x08, 0xfb, 0x8b, 0x00, // dwFlags
            0xe0, 0xf1, 0x09, 0x00, // dwVolume
            0x70, 0x27, 0x1f, 0x77, // dwPitch
            0x00, 0x00,             // wDGramPort
            0x05, 0x00,             // wNumberOfFormats = 5
            0xff,                   // cLastBlockConfirmed = 255
            0x05, 0x00,             // wVersion = 5
            0x00,                   // bPad
            // Format 0: PCM (18 bytes)
            0x01, 0x00, 0x02, 0x00, 0x22, 0x56, 0x00, 0x00,
            0x88, 0x58, 0x01, 0x00, 0x04, 0x00, 0x10, 0x00,
            0x00, 0x00,
            // Format 1: PCM (18 bytes)
            0x01, 0x00, 0x02, 0x00, 0x11, 0x2b, 0x00, 0x00,
            0x44, 0xac, 0x00, 0x00, 0x04, 0x00, 0x10, 0x00,
            0x00, 0x00,
            // Format 2: PCM (18 bytes)
            0x01, 0x00, 0x02, 0x00, 0x44, 0xac, 0x00, 0x00,
            0x10, 0xb1, 0x02, 0x00, 0x04, 0x00, 0x10, 0x00,
            0x00, 0x00,
            // Format 3: ADPCM (50 bytes)
            0x02, 0x00, 0x02, 0x00, 0x22, 0x56, 0x00, 0x00,
            0x27, 0x57, 0x00, 0x00, 0x00, 0x04, 0x04, 0x00,
            0x20, 0x00,
            0xf4, 0x03, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x02, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xc0, 0x00, 0x40, 0x00, 0xf0, 0x00, 0x00, 0x00,
            0xcc, 0x01, 0x30, 0xff, 0x88, 0x01, 0x18, 0xff,
            // Format 4: IMA-ADPCM (20 bytes)
            0x11, 0x00, 0x02, 0x00, 0x22, 0x56, 0x00, 0x00,
            0xb9, 0x56, 0x00, 0x00, 0x00, 0x04, 0x04, 0x00,
            0x02, 0x00, 0xf9, 0x03,
        ];

        assert_eq!(bytes.len(), 148); // 4 header + 144 body

        let mut cursor = ReadCursor::new(&bytes);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::Formats);
        assert_eq!(header.body_size, 144);

        let pdu = ServerAudioFormatsPdu::decode_body(&mut cursor).unwrap();
        assert_eq!(pdu.last_block_confirmed, 255);
        assert_eq!(pdu.version, 5);
        assert_eq!(pdu.formats.len(), 5);

        // Format 0: PCM stereo 22050 Hz 16-bit
        assert_eq!(pdu.formats[0].format_tag, WaveFormatTag::PCM);
        assert_eq!(pdu.formats[0].n_channels, 2);
        assert_eq!(pdu.formats[0].n_samples_per_sec, 22050);
        assert_eq!(pdu.formats[0].n_avg_bytes_per_sec, 88200);
        assert_eq!(pdu.formats[0].n_block_align, 4);
        assert_eq!(pdu.formats[0].bits_per_sample, 16);

        // Format 3: ADPCM with 32 bytes extra
        assert_eq!(pdu.formats[3].format_tag, WaveFormatTag::ADPCM);
        assert_eq!(pdu.formats[3].extra_data.len(), 32);

        // Format 4: IMA-ADPCM with 2 bytes extra
        assert_eq!(pdu.formats[4].format_tag, WaveFormatTag::DVI_ADPCM);
        assert_eq!(pdu.formats[4].extra_data.len(), 2);

        // Verify body size sum
        let computed_body: usize = 20 + pdu.formats.iter().map(|f| f.size()).sum::<usize>();
        assert_eq!(computed_body, 144);
    }

    #[test]
    fn server_formats_rejects_too_many_formats() {
        // wNumberOfFormats = 257 (> MAX_AUDIO_FORMATS=256)
        let body = [
            0x00, 0x00, 0x00, 0x00, // dwFlags
            0x00, 0x00, 0x00, 0x00, // dwVolume
            0x00, 0x00, 0x00, 0x00, // dwPitch
            0x00, 0x00,             // wDGramPort
            0x01, 0x01,             // wNumberOfFormats = 257
            0x00,                   // cLastBlockConfirmed
            0x06, 0x00,             // wVersion = 6
            0x00,                   // bPad
        ];
        let mut cursor = ReadCursor::new(&body);
        assert!(ServerAudioFormatsPdu::decode_body(&mut cursor).is_err());
    }

    #[test]
    fn client_formats_roundtrip() {
        let pdu = ClientAudioFormatsPdu {
            flags: ClientSndFlags::ALIVE.union(ClientSndFlags::VOLUME),
            volume: 0xFFFF_FFFF,
            pitch: 0x0001_0000,
            version: 6,
            formats: alloc::vec![AudioFormat::pcm(2, 44100, 16)],
        };

        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        // Verify header
        let mut cursor = ReadCursor::new(&buf);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::Formats);

        // Verify flags
        let flags = cursor.read_u32_le("flags").unwrap();
        assert_eq!(flags, 0x03); // ALIVE | VOLUME
    }
}
