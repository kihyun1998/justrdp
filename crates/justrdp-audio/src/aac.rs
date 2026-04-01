#![forbid(unsafe_code)]

//! AAC header parsing and ADTS frame extraction.
//!
//! Parses HEAACWAVEINFO from AUDIO_FORMAT extra data and extracts
//! ADTS frame boundaries. Actual AAC decoding is external.

use crate::error::{AudioError, AudioResult};

/// AAC payload type -- HEAACWAVEINFO.wPayloadType
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AacPayloadType {
    /// Raw AAC data blocks.
    Raw = 0x0000,
    /// ADTS framed data.
    Adts = 0x0001,
    /// ADIF format.
    Adif = 0x0002,
    /// LOAS/LATM transport.
    Latm = 0x0003,
}

impl AacPayloadType {
    /// Convert from u16.
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0 => Some(Self::Raw),
            1 => Some(Self::Adts),
            2 => Some(Self::Adif),
            3 => Some(Self::Latm),
            _ => None,
        }
    }
}

/// Parsed HEAACWAVEINFO from AUDIO_FORMAT extra data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaacWaveInfo {
    /// Payload type.
    pub payload_type: AacPayloadType,
    /// Audio profile and level indication.
    pub profile_level: u16,
    /// Structure type (0 = AudioSpecificConfig follows).
    pub struct_type: u16,
}

/// Minimum HEAACWAVEINFO extra data size.
const HEAAC_MIN_SIZE: usize = 12;

/// Parse HEAACWAVEINFO from AUDIO_FORMAT extra data.
pub fn parse_heaac_info(extra_data: &[u8]) -> AudioResult<HeaacWaveInfo> {
    if extra_data.len() < HEAAC_MIN_SIZE {
        return Err(AudioError::InvalidFormat("HEAACWAVEINFO too short"));
    }

    let payload_type_raw = u16::from_le_bytes([extra_data[0], extra_data[1]]);
    let payload_type = AacPayloadType::from_u16(payload_type_raw)
        .ok_or(AudioError::InvalidFormat("unknown AAC payload type"))?;
    let profile_level = u16::from_le_bytes([extra_data[2], extra_data[3]]);
    let struct_type = u16::from_le_bytes([extra_data[4], extra_data[5]]);
    // reserved1 (u16) at offset 6, reserved2 (u32) at offset 8 — skip

    Ok(HeaacWaveInfo {
        payload_type,
        profile_level,
        struct_type,
    })
}

/// Extract the length of an ADTS frame from its header.
///
/// Returns the total frame length (including header) if the data
/// starts with a valid ADTS syncword, or `None` if invalid.
pub fn adts_frame_length(data: &[u8]) -> Option<usize> {
    if data.len() < 7 {
        return None;
    }

    // Check syncword: 0xFFF (12 bits).
    if data[0] != 0xFF || (data[1] & 0xF0) != 0xF0 {
        return None;
    }

    // frame_length is 13 bits at bytes 3-5.
    let frame_length = (((data[3] & 0x03) as usize) << 11)
        | ((data[4] as usize) << 3)
        | (((data[5] >> 5) & 0x07) as usize);

    if frame_length < 7 || frame_length > 8191 {
        return None;
    }

    Some(frame_length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_heaac_info_basic() {
        let mut data = [0u8; 12];
        // wPayloadType = ADTS (1)
        data[0] = 0x01;
        data[1] = 0x00;
        // wAudioProfileLevelIndication = 0x29
        data[2] = 0x29;
        data[3] = 0x00;
        // wStructType = 0
        data[4] = 0x00;
        data[5] = 0x00;

        let info = parse_heaac_info(&data).unwrap();
        assert_eq!(info.payload_type, AacPayloadType::Adts);
        assert_eq!(info.profile_level, 0x29);
        assert_eq!(info.struct_type, 0);
    }

    #[test]
    fn parse_heaac_too_short() {
        let err = parse_heaac_info(&[0u8; 4]).unwrap_err();
        assert_eq!(err, AudioError::InvalidFormat("HEAACWAVEINFO too short"));
    }

    #[test]
    fn adts_syncword_detection() {
        // Valid ADTS header with frame_length = 100
        let mut header = [0u8; 7];
        header[0] = 0xFF;
        header[1] = 0xF1; // syncword + MPEG-4 + layer=0 + protection_absent=1
        header[2] = 0x50; // profile, sampling freq, etc.
        // frame_length = 100 → 13 bits: 0_0000_0110_0100
        // data[3] bits 1-0 = 0b00
        // data[4] = 0b00001100 = 0x0C
        // data[5] bits 7-5 = 0b100
        header[3] = (header[3] & 0xFC) | 0x00;
        header[4] = 0x0C;
        header[5] = (0x04 << 5) | (header[5] & 0x1F);

        let len = adts_frame_length(&header).unwrap();
        assert_eq!(len, 100);
    }

    #[test]
    fn adts_no_syncword() {
        let data = [0x00u8; 7];
        assert!(adts_frame_length(&data).is_none());
    }

    #[test]
    fn adts_too_short() {
        assert!(adts_frame_length(&[0xFF, 0xF1]).is_none());
    }

    #[test]
    fn parse_heaac_unknown_payload_type() {
        let mut data = [0u8; 12];
        data[0] = 0xFF; // unknown payload type
        data[1] = 0x00;
        let err = parse_heaac_info(&data).unwrap_err();
        assert_eq!(err, AudioError::InvalidFormat("unknown AAC payload type"));
    }
}
