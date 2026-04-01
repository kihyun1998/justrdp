#![forbid(unsafe_code)]

//! AUDIO_FORMAT structure -- MS-RDPEA 2.2.1.1

use alloc::vec::Vec;

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{Decode, DecodeResult, Encode, EncodeResult};

/// Minimum AUDIO_FORMAT size (fixed fields, no extra data).
const AUDIO_FORMAT_FIXED_SIZE: usize = 18;

/// Well-known audio format tags -- MS-RDPEA 2.2.1.1 / RFC 2361
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaveFormatTag(pub u16);

impl WaveFormatTag {
    /// PCM (uncompressed).
    pub const PCM: Self = Self(0x0001);
    /// Microsoft ADPCM.
    pub const ADPCM: Self = Self(0x0002);
    /// G.711 a-law.
    pub const ALAW: Self = Self(0x0006);
    /// G.711 mu-law.
    pub const MULAW: Self = Self(0x0007);
    /// IMA/DVI ADPCM.
    pub const DVI_ADPCM: Self = Self(0x0011);
    /// AAC (MPEG-4).
    pub const AAC: Self = Self(0x00FF);
    /// Opus codec.
    pub const OPUS: Self = Self(0x704F);
}

/// AUDIO_FORMAT -- MS-RDPEA 2.2.1.1
///
/// Describes an audio format with compression tag, channels,
/// sample rate, and optional codec-specific extra data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFormat {
    /// Compression format tag.
    pub format_tag: WaveFormatTag,
    /// Number of audio channels.
    pub n_channels: u16,
    /// Samples per second.
    pub n_samples_per_sec: u32,
    /// Average bytes per second.
    pub n_avg_bytes_per_sec: u32,
    /// Minimum atomic unit size in bytes.
    pub n_block_align: u16,
    /// Bits per sample.
    pub bits_per_sample: u16,
    /// Codec-specific extra data.
    pub extra_data: Vec<u8>,
}

impl AudioFormat {
    /// Create a PCM audio format.
    pub fn pcm(n_channels: u16, n_samples_per_sec: u32, bits_per_sample: u16) -> Self {
        let block_align = n_channels * (bits_per_sample / 8);
        Self {
            format_tag: WaveFormatTag::PCM,
            n_channels,
            n_samples_per_sec,
            n_avg_bytes_per_sec: n_samples_per_sec * block_align as u32,
            n_block_align: block_align,
            bits_per_sample,
            extra_data: Vec::new(),
        }
    }
}

impl Encode for AudioFormat {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.format_tag.0, "AudioFormat::wFormatTag")?;
        dst.write_u16_le(self.n_channels, "AudioFormat::nChannels")?;
        dst.write_u32_le(self.n_samples_per_sec, "AudioFormat::nSamplesPerSec")?;
        dst.write_u32_le(self.n_avg_bytes_per_sec, "AudioFormat::nAvgBytesPerSec")?;
        dst.write_u16_le(self.n_block_align, "AudioFormat::nBlockAlign")?;
        dst.write_u16_le(self.bits_per_sample, "AudioFormat::wBitsPerSample")?;
        dst.write_u16_le(self.extra_data.len() as u16, "AudioFormat::cbSize")?;
        if !self.extra_data.is_empty() {
            dst.write_slice(&self.extra_data, "AudioFormat::data")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "AudioFormat"
    }

    fn size(&self) -> usize {
        AUDIO_FORMAT_FIXED_SIZE + self.extra_data.len()
    }
}

impl<'de> Decode<'de> for AudioFormat {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let format_tag = WaveFormatTag(src.read_u16_le("AudioFormat::wFormatTag")?);
        let n_channels = src.read_u16_le("AudioFormat::nChannels")?;
        let n_samples_per_sec = src.read_u32_le("AudioFormat::nSamplesPerSec")?;
        let n_avg_bytes_per_sec = src.read_u32_le("AudioFormat::nAvgBytesPerSec")?;
        let n_block_align = src.read_u16_le("AudioFormat::nBlockAlign")?;
        let bits_per_sample = src.read_u16_le("AudioFormat::wBitsPerSample")?;
        let cb_size = src.read_u16_le("AudioFormat::cbSize")?;
        let extra_data = if cb_size > 0 {
            src.read_slice(cb_size as usize, "AudioFormat::data")?.to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            format_tag,
            n_channels,
            n_samples_per_sec,
            n_avg_bytes_per_sec,
            n_block_align,
            bits_per_sample,
            extra_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcm_format_roundtrip() {
        let fmt = AudioFormat::pcm(2, 22050, 16);
        assert_eq!(fmt.size(), 18);
        let mut buf = alloc::vec![0u8; fmt.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        fmt.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = AudioFormat::decode(&mut cursor).unwrap();
        assert_eq!(fmt, decoded);
    }

    #[test]
    fn pcm_format_spec_bytes() {
        // From MS-RDPEA test vector: Format 0 (PCM)
        let bytes: [u8; 18] = [
            0x01, 0x00, // wFormatTag = PCM (1)
            0x02, 0x00, // nChannels = 2
            0x22, 0x56, 0x00, 0x00, // nSamplesPerSec = 22050
            0x88, 0x58, 0x01, 0x00, // nAvgBytesPerSec = 88200
            0x04, 0x00, // nBlockAlign = 4
            0x10, 0x00, // wBitsPerSample = 16
            0x00, 0x00, // cbSize = 0
        ];
        let mut cursor = ReadCursor::new(&bytes);
        let fmt = AudioFormat::decode(&mut cursor).unwrap();
        assert_eq!(fmt.format_tag, WaveFormatTag::PCM);
        assert_eq!(fmt.n_channels, 2);
        assert_eq!(fmt.n_samples_per_sec, 22050);
        assert_eq!(fmt.n_avg_bytes_per_sec, 88200);
        assert_eq!(fmt.n_block_align, 4);
        assert_eq!(fmt.bits_per_sample, 16);
        assert!(fmt.extra_data.is_empty());
        assert_eq!(fmt.size(), 18);
    }

    #[test]
    fn adpcm_format_with_extra_data() {
        // From MS-RDPEA test vector: Format 3 (ADPCM, cbSize=32)
        let bytes: [u8; 50] = [
            0x02, 0x00, // wFormatTag = ADPCM (2)
            0x02, 0x00, // nChannels = 2
            0x22, 0x56, 0x00, 0x00, // nSamplesPerSec = 22050
            0x27, 0x57, 0x00, 0x00, // nAvgBytesPerSec = 22311
            0x00, 0x04, // nBlockAlign = 1024
            0x04, 0x00, // wBitsPerSample = 4
            0x20, 0x00, // cbSize = 32
            // 32 bytes extra data
            0xf4, 0x03, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x02, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xc0, 0x00, 0x40, 0x00, 0xf0, 0x00, 0x00, 0x00,
            0xcc, 0x01, 0x30, 0xff, 0x88, 0x01, 0x18, 0xff,
        ];
        let mut cursor = ReadCursor::new(&bytes);
        let fmt = AudioFormat::decode(&mut cursor).unwrap();
        assert_eq!(fmt.format_tag, WaveFormatTag::ADPCM);
        assert_eq!(fmt.extra_data.len(), 32);
        assert_eq!(fmt.size(), 50);

        // Roundtrip
        let mut out = alloc::vec![0u8; fmt.size()];
        let mut cursor = WriteCursor::new(&mut out);
        fmt.encode(&mut cursor).unwrap();
        assert_eq!(out, bytes);
    }

    #[test]
    fn ima_adpcm_format() {
        // From MS-RDPEA test vector: Format 4 (IMA-ADPCM, cbSize=2)
        let bytes: [u8; 20] = [
            0x11, 0x00, // wFormatTag = DVI_ADPCM (17)
            0x02, 0x00, // nChannels = 2
            0x22, 0x56, 0x00, 0x00, // nSamplesPerSec = 22050
            0xb9, 0x56, 0x00, 0x00, // nAvgBytesPerSec = 22201
            0x00, 0x04, // nBlockAlign = 1024
            0x04, 0x00, // wBitsPerSample = 4
            0x02, 0x00, // cbSize = 2
            0xf9, 0x03, // extra data
        ];
        let mut cursor = ReadCursor::new(&bytes);
        let fmt = AudioFormat::decode(&mut cursor).unwrap();
        assert_eq!(fmt.format_tag, WaveFormatTag::DVI_ADPCM);
        assert_eq!(fmt.extra_data.len(), 2);
        assert_eq!(fmt.size(), 20);
    }
}
