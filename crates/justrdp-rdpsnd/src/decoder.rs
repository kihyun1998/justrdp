#![forbid(unsafe_code)]

//! Audio decoder factory -- creates decoders from AudioFormat.

use alloc::boxed::Box;

use justrdp_audio::{
    AudioDecoder, AudioError, AudioResult, ImaAdpcmDecoder, MsAdpcmDecoder, PcmDecoder,
};

use crate::pdu::{AudioFormat, WaveFormatTag};

/// Create an audio decoder from an `AudioFormat` descriptor.
///
/// Returns a boxed `AudioDecoder` appropriate for the format tag.
/// Returns `AudioError::UnsupportedCodec` for unknown or unimplemented codecs
/// (AAC, Opus, G.711 — these require external decoder backends).
pub fn make_decoder(format: &AudioFormat) -> AudioResult<Box<dyn AudioDecoder>> {
    match format.format_tag {
        WaveFormatTag::PCM => {
            let dec = PcmDecoder::new(
                format.bits_per_sample,
                format.n_channels,
                format.n_samples_per_sec,
            )?;
            Ok(Box::new(dec))
        }

        WaveFormatTag::ADPCM => {
            let dec = MsAdpcmDecoder::new(
                format.n_channels,
                format.n_samples_per_sec,
                format.n_block_align,
                &format.extra_data,
            )?;
            Ok(Box::new(dec))
        }

        WaveFormatTag::DVI_ADPCM => {
            let dec = ImaAdpcmDecoder::new(
                format.n_channels,
                format.n_samples_per_sec,
                format.n_block_align,
                &format.extra_data,
            )?;
            Ok(Box::new(dec))
        }

        // AAC, Opus, G.711 etc. require external decoder backends.
        _ => Err(AudioError::UnsupportedCodec),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_pcm_decoder() {
        let format = AudioFormat::pcm(2, 44100, 16);
        let dec = make_decoder(&format).unwrap();
        assert_eq!(dec.sample_rate(), 44100);
        assert_eq!(dec.channels(), 2);
    }

    #[test]
    fn make_adpcm_decoder() {
        // Build extra data for MS-ADPCM: wSamplesPerBlock=4, wNumCoef=7, 7 coef pairs
        let coefs: [(i16, i16); 7] = [
            (256, 0), (512, -256), (0, 0), (192, 64),
            (240, 0), (460, -208), (392, -232),
        ];
        let mut extra = alloc::vec![0u8; 32];
        extra[0..2].copy_from_slice(&4u16.to_le_bytes());
        extra[2..4].copy_from_slice(&7u16.to_le_bytes());
        for (i, (c1, c2)) in coefs.iter().enumerate() {
            let off = 4 + i * 4;
            extra[off..off + 2].copy_from_slice(&c1.to_le_bytes());
            extra[off + 2..off + 4].copy_from_slice(&c2.to_le_bytes());
        }

        let format = AudioFormat {
            format_tag: WaveFormatTag::ADPCM,
            n_channels: 1,
            n_samples_per_sec: 22050,
            n_avg_bytes_per_sec: 22311,
            n_block_align: 1024,
            bits_per_sample: 4,
            extra_data: extra,
        };

        let dec = make_decoder(&format).unwrap();
        assert_eq!(dec.sample_rate(), 22050);
        assert_eq!(dec.channels(), 1);
    }

    #[test]
    fn make_ima_adpcm_decoder() {
        let format = AudioFormat {
            format_tag: WaveFormatTag::DVI_ADPCM,
            n_channels: 2,
            n_samples_per_sec: 22050,
            n_avg_bytes_per_sec: 22201,
            n_block_align: 1024,
            bits_per_sample: 4,
            extra_data: alloc::vec![0xF9, 0x03], // wSamplesPerBlock = 1017
        };

        let dec = make_decoder(&format).unwrap();
        assert_eq!(dec.sample_rate(), 22050);
        assert_eq!(dec.channels(), 2);
    }

    #[test]
    fn make_unsupported_codec() {
        let format = AudioFormat {
            format_tag: WaveFormatTag::OPUS,
            n_channels: 2,
            n_samples_per_sec: 48000,
            n_avg_bytes_per_sec: 0,
            n_block_align: 0,
            bits_per_sample: 0,
            extra_data: alloc::vec![],
        };

        let err = make_decoder(&format).unwrap_err();
        assert_eq!(err, AudioError::UnsupportedCodec);
    }

    #[test]
    fn decode_through_trait_object() {
        let format = AudioFormat::pcm(1, 44100, 16);
        let mut dec = make_decoder(&format).unwrap();
        // 16-bit LE: 0x00FF = 255
        let input = [0xFF, 0x00];
        let mut output = [0i16; 1];
        let n = dec.decode(&input, &mut output).unwrap();
        assert_eq!(n, 1);
        assert_eq!(output[0], 255);
    }

    #[test]
    fn make_adpcm_bad_extra_data() {
        let format = AudioFormat {
            format_tag: WaveFormatTag::ADPCM,
            n_channels: 1,
            n_samples_per_sec: 22050,
            n_avg_bytes_per_sec: 0,
            n_block_align: 256,
            bits_per_sample: 4,
            extra_data: alloc::vec![], // too short
        };
        let err = make_decoder(&format).unwrap_err();
        assert_eq!(
            err,
            AudioError::InvalidFormat("MS-ADPCM extra data too short")
        );
    }

    #[test]
    fn make_ima_adpcm_bad_extra_data() {
        let format = AudioFormat {
            format_tag: WaveFormatTag::DVI_ADPCM,
            n_channels: 1,
            n_samples_per_sec: 22050,
            n_avg_bytes_per_sec: 0,
            n_block_align: 256,
            bits_per_sample: 4,
            extra_data: alloc::vec![], // too short
        };
        let err = make_decoder(&format).unwrap_err();
        assert_eq!(
            err,
            AudioError::InvalidFormat("IMA-ADPCM extra data too short")
        );
    }
}
