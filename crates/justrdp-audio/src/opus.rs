#![forbid(unsafe_code)]

//! Opus header parsing (RFC 7845).
//!
//! Parses OpusHead identification header from AUDIO_FORMAT extra data.
//! Actual Opus decoding is external.

use crate::error::{AudioError, AudioResult};

/// OpusHead magic bytes.
const OPUS_HEAD_MAGIC: &[u8; 8] = b"OpusHead";

/// Minimum OpusHead size (through channel_mapping_family).
const OPUS_HEAD_MIN_SIZE: usize = 19;

/// Parsed OpusHead identification header -- RFC 7845 Section 5.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpusHead {
    /// Version (must have major = 0).
    pub version: u8,
    /// Number of output channels.
    pub output_channel_count: u8,
    /// Pre-skip in samples at 48 kHz.
    pub pre_skip: u16,
    /// Original input sample rate (informational, 0 = unspecified).
    pub input_sample_rate: u32,
    /// Output gain in Q7.8 fixed-point dB.
    pub output_gain: i16,
    /// Channel mapping family.
    pub channel_mapping_family: u8,
}

impl OpusHead {
    /// Opus always decodes at 48 kHz.
    pub fn decode_sample_rate(&self) -> u32 {
        48000
    }

    /// Number of output channels.
    pub fn channels(&self) -> u8 {
        self.output_channel_count
    }
}

/// Parse an OpusHead identification header from raw bytes.
pub fn parse_opus_head(data: &[u8]) -> AudioResult<OpusHead> {
    if data.len() < OPUS_HEAD_MIN_SIZE {
        return Err(AudioError::InvalidFormat("OpusHead too short"));
    }

    // Verify magic.
    if &data[0..8] != OPUS_HEAD_MAGIC {
        return Err(AudioError::InvalidFormat("OpusHead magic mismatch"));
    }

    let version = data[8];
    // Major version must be 0.
    if version & 0xF0 != 0x00 {
        return Err(AudioError::InvalidFormat("OpusHead unsupported version"));
    }

    let output_channel_count = data[9];
    if output_channel_count == 0 {
        return Err(AudioError::InvalidFormat(
            "OpusHead output_channel_count is 0",
        ));
    }

    let pre_skip = u16::from_le_bytes([data[10], data[11]]);
    let input_sample_rate = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let output_gain = i16::from_le_bytes([data[16], data[17]]);
    let channel_mapping_family = data[18];

    // Validate channel_mapping_family constraints.
    if channel_mapping_family == 0 && output_channel_count > 2 {
        return Err(AudioError::InvalidFormat(
            "OpusHead family 0 requires 1 or 2 channels",
        ));
    }

    Ok(OpusHead {
        version,
        output_channel_count,
        pre_skip,
        input_sample_rate,
        output_gain,
        channel_mapping_family,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_opus_head_stereo() {
        #[rustfmt::skip]
        let data: [u8; 19] = [
            b'O', b'p', b'u', b's', b'H', b'e', b'a', b'd', // magic
            0x01,       // version = 1
            0x02,       // output_channel_count = 2
            0x38, 0x01, // pre_skip = 312
            0x80, 0xBB, 0x00, 0x00, // input_sample_rate = 48000
            0x00, 0x00, // output_gain = 0
            0x00,       // channel_mapping_family = 0
        ];

        let head = parse_opus_head(&data).unwrap();
        assert_eq!(head.version, 1);
        assert_eq!(head.output_channel_count, 2);
        assert_eq!(head.pre_skip, 312);
        assert_eq!(head.input_sample_rate, 48000);
        assert_eq!(head.output_gain, 0);
        assert_eq!(head.channel_mapping_family, 0);
        assert_eq!(head.decode_sample_rate(), 48000);
        assert_eq!(head.channels(), 2);
    }

    #[test]
    fn parse_opus_head_mono() {
        let mut data = [0u8; 19];
        data[0..8].copy_from_slice(b"OpusHead");
        data[8] = 0x01;  // version
        data[9] = 0x01;  // mono
        data[18] = 0x00; // family 0

        let head = parse_opus_head(&data).unwrap();
        assert_eq!(head.channels(), 1);
    }

    #[test]
    fn opus_head_magic_mismatch() {
        let mut data = [0u8; 19];
        data[0..8].copy_from_slice(b"NotOpus!");
        data[9] = 1;

        let err = parse_opus_head(&data).unwrap_err();
        assert_eq!(err, AudioError::InvalidFormat("OpusHead magic mismatch"));
    }

    #[test]
    fn opus_head_zero_channels() {
        let mut data = [0u8; 19];
        data[0..8].copy_from_slice(b"OpusHead");
        data[8] = 0x01;
        data[9] = 0; // 0 channels → error

        let err = parse_opus_head(&data).unwrap_err();
        assert_eq!(
            err,
            AudioError::InvalidFormat("OpusHead output_channel_count is 0")
        );
    }

    #[test]
    fn opus_head_family0_too_many_channels() {
        let mut data = [0u8; 19];
        data[0..8].copy_from_slice(b"OpusHead");
        data[8] = 0x01;
        data[9] = 3;     // 3 channels
        data[18] = 0x00; // family 0 → only 1 or 2 allowed

        let err = parse_opus_head(&data).unwrap_err();
        assert_eq!(
            err,
            AudioError::InvalidFormat("OpusHead family 0 requires 1 or 2 channels")
        );
    }

    #[test]
    fn opus_head_too_short() {
        let err = parse_opus_head(&[0u8; 10]).unwrap_err();
        assert_eq!(err, AudioError::InvalidFormat("OpusHead too short"));
    }

    #[test]
    fn opus_head_bad_version() {
        let mut data = [0u8; 19];
        data[0..8].copy_from_slice(b"OpusHead");
        data[8] = 0x10; // major version = 1 → unsupported
        data[9] = 1;

        let err = parse_opus_head(&data).unwrap_err();
        assert_eq!(
            err,
            AudioError::InvalidFormat("OpusHead unsupported version")
        );
    }
}
