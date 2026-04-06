#![forbid(unsafe_code)]

//! WaveInfo / Wave2 PDU -- MS-RDPEA 2.2.3.3, 2.2.3.9

use alloc::vec::Vec;

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{DecodeResult, Encode, EncodeResult};

use super::header::{SndHeader, SndMsgType, SND_HEADER_SIZE};

/// WaveInfo PDU (Server → Client) -- MS-RDPEA 2.2.3.3
///
/// Contains the first 4 bytes of audio data. The remaining data
/// follows in a Wave PDU (no header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaveInfoPdu {
    /// Timestamp when PDU was built.
    pub timestamp: u16,
    /// Zero-based index into negotiated format list.
    pub format_no: u16,
    /// Block ID (echoed in WaveConfirm).
    pub block_no: u8,
    /// First 4 bytes of audio data.
    pub initial_data: [u8; 4],
    /// Total audio data size (initial_data + remaining wave data).
    /// Used to calculate BodySize in header.
    pub total_audio_size: usize,
}

impl WaveInfoPdu {
    /// Decode from cursor after the header has been read.
    ///
    /// MS-RDPEA 2.2.3.3: BodySize = 4 + total_audio_data_size,
    /// where total_audio_data_size includes the 4 initial bytes in Data[].
    /// Equivalently: remaining_wave_bytes = BodySize - 8, matching FreeRDP.
    pub fn decode_body(src: &mut ReadCursor<'_>, body_size: u16) -> DecodeResult<Self> {
        // MS-RDPEA 2.2.3.3: BodySize = 4 + total_audio_size.
        // Minimum valid BodySize is 8 (total_audio_size = 4 = initial_data only).
        // Values 4..7 would give total_audio_size 0..3, which is less than the
        // 4-byte initial_data and would cause data length inconsistency.
        if body_size < 8 {
            return Err(justrdp_core::DecodeError::invalid_value(
                "WaveInfoPdu",
                "body_size too small",
            ));
        }
        let timestamp = src.read_u16_le("WaveInfoPdu::wTimeStamp")?;
        let format_no = src.read_u16_le("WaveInfoPdu::wFormatNo")?;
        let block_no = src.read_u8("WaveInfoPdu::cBlockNo")?;
        src.skip(3, "WaveInfoPdu::bPad")?;
        let initial_bytes = src.read_slice(4, "WaveInfoPdu::Data")?;
        let mut initial_data = [0u8; 4];
        initial_data.copy_from_slice(initial_bytes);

        // MS-RDPEA 2.2.3.3: BodySize = 4 + total_audio_size
        // Body has 8 non-audio bytes + 4 initial audio bytes = 12 bytes on wire,
        // but BodySize is overloaded to encode total audio size.
        let total_audio_size = (body_size - 4) as usize;

        Ok(Self {
            timestamp,
            format_no,
            block_no,
            initial_data,
            total_audio_size,
        })
    }

    /// Size of the remaining Wave PDU data (after this WaveInfo PDU).
    /// decode_body guarantees total_audio_size >= 4; saturating_sub guards
    /// against direct construction with smaller values.
    pub fn remaining_wave_size(&self) -> usize {
        debug_assert!(
            self.total_audio_size >= 4,
            "invariant: total_audio_size >= 4 (from decode_body)"
        );
        self.total_audio_size.saturating_sub(4)
    }
}

/// Decode the Wave PDU that follows a WaveInfo PDU.
///
/// The Wave PDU has no RDPSND header. It starts with 4 bytes padding
/// followed by the remaining audio data.
///
/// Returns the complete audio data (initial_data + remaining).
pub fn decode_wave_data(
    src: &mut ReadCursor<'_>,
    wave_info: &WaveInfoPdu,
) -> DecodeResult<Vec<u8>> {
    // Skip 4-byte padding
    src.skip(4, "WavePdu::bPad")?;
    let remaining_size = wave_info.remaining_wave_size();
    let remaining = if remaining_size > 0 {
        src.read_slice(remaining_size, "WavePdu::data")?
    } else {
        &[]
    };

    // Reassemble: initial_data + remaining
    let mut audio = Vec::with_capacity(wave_info.total_audio_size);
    audio.extend_from_slice(&wave_info.initial_data);
    audio.extend_from_slice(remaining);
    Ok(audio)
}

/// Wave2 PDU (Server → Client) -- MS-RDPEA 2.2.3.9
///
/// Modern alternative to WaveInfo+Wave pair. Contains all audio
/// data in a single PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wave2Pdu {
    /// Timestamp when PDU was built.
    pub timestamp: u16,
    /// Zero-based index into negotiated format list.
    pub format_no: u16,
    /// Block ID (echoed in WaveConfirm).
    pub block_no: u8,
    /// Milliseconds since system start when audio was captured.
    pub audio_timestamp: u32,
    /// Audio data in the negotiated format.
    pub data: Vec<u8>,
}

/// Wave2 fixed body size (before variable data).
const WAVE2_FIXED_BODY_SIZE: usize = 12;

impl Wave2Pdu {
    /// Decode from cursor after the header has been read.
    pub fn decode_body(src: &mut ReadCursor<'_>, body_size: u16) -> DecodeResult<Self> {
        if (body_size as usize) < WAVE2_FIXED_BODY_SIZE {
            return Err(justrdp_core::DecodeError::invalid_value(
                "Wave2Pdu",
                "body_size too small",
            ));
        }
        let timestamp = src.read_u16_le("Wave2Pdu::wTimeStamp")?;
        let format_no = src.read_u16_le("Wave2Pdu::wFormatNo")?;
        let block_no = src.read_u8("Wave2Pdu::cBlockNo")?;
        src.skip(3, "Wave2Pdu::bPad")?;
        let audio_timestamp = src.read_u32_le("Wave2Pdu::dwAudioTimeStamp")?;

        let data_len = (body_size as usize) - WAVE2_FIXED_BODY_SIZE;
        let data = if data_len > 0 {
            src.read_slice(data_len, "Wave2Pdu::Data")?.to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            timestamp,
            format_no,
            block_no,
            audio_timestamp,
            data,
        })
    }
}

impl Encode for Wave2Pdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let body_size = WAVE2_FIXED_BODY_SIZE + self.data.len();
        let body_size_u16 = u16::try_from(body_size)
            .map_err(|_| justrdp_core::EncodeError::invalid_value("Wave2Pdu", "body too large"))?;
        let header = SndHeader::new(SndMsgType::Wave2, body_size_u16);
        header.encode(dst)?;
        dst.write_u16_le(self.timestamp, "Wave2Pdu::wTimeStamp")?;
        dst.write_u16_le(self.format_no, "Wave2Pdu::wFormatNo")?;
        dst.write_u8(self.block_no, "Wave2Pdu::cBlockNo")?;
        dst.write_slice(&[0u8; 3], "Wave2Pdu::bPad")?;
        dst.write_u32_le(self.audio_timestamp, "Wave2Pdu::dwAudioTimeStamp")?;
        if !self.data.is_empty() {
            dst.write_slice(&self.data, "Wave2Pdu::Data")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "Wave2Pdu"
    }

    fn size(&self) -> usize {
        SND_HEADER_SIZE + WAVE2_FIXED_BODY_SIZE + self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_core::Decode;

    #[test]
    fn wave_info_decode() {
        // WaveInfo body: timestamp=100, formatNo=0, blockNo=1, pad=0, initial_data=[1,2,3,4]
        // BodySize = 4 + total_audio_size. If total_audio=8, BodySize=12.
        let body = [
            0x64, 0x00, // timestamp = 100
            0x00, 0x00, // formatNo = 0
            0x01,       // blockNo = 1
            0x00, 0x00, 0x00, // pad
            0x01, 0x02, 0x03, 0x04, // initial 4 bytes
        ];
        let mut cursor = ReadCursor::new(&body);
        let pdu = WaveInfoPdu::decode_body(&mut cursor, 12).unwrap();
        assert_eq!(pdu.timestamp, 100);
        assert_eq!(pdu.format_no, 0);
        assert_eq!(pdu.block_no, 1);
        assert_eq!(pdu.initial_data, [1, 2, 3, 4]);
        assert_eq!(pdu.total_audio_size, 8);
        assert_eq!(pdu.remaining_wave_size(), 4);
    }

    #[test]
    fn wave_info_body_size_too_small() {
        let body = [0x00; 12];
        let mut cursor = ReadCursor::new(&body);
        // body_size=7 → total_audio_size would be 3 < 4 (initial_data), rejected
        assert!(WaveInfoPdu::decode_body(&mut cursor, 7).is_err());
    }

    #[test]
    fn wave_info_minimum_body_size() {
        // body_size=8 → total_audio_size=4 (initial_data only, no remaining)
        let body = [
            0x00, 0x00, // timestamp
            0x00, 0x00, // formatNo
            0x00,       // blockNo
            0x00, 0x00, 0x00, // pad
            0x01, 0x02, 0x03, 0x04, // initial data
        ];
        let mut cursor = ReadCursor::new(&body);
        let pdu = WaveInfoPdu::decode_body(&mut cursor, 8).unwrap();
        assert_eq!(pdu.total_audio_size, 4);
        assert_eq!(pdu.remaining_wave_size(), 0);
    }

    #[test]
    fn wave2_body_size_too_small() {
        let body = [0x00; 12];
        let mut cursor = ReadCursor::new(&body);
        assert!(Wave2Pdu::decode_body(&mut cursor, 11).is_err());
    }

    #[test]
    fn wave2_minimum_body_size() {
        // body_size=12 → zero audio data (minimum valid)
        let body = [
            0x00, 0x00, // timestamp
            0x00, 0x00, // formatNo
            0x00,       // blockNo
            0x00, 0x00, 0x00, // pad
            0x00, 0x00, 0x00, 0x00, // audioTimestamp
        ];
        let mut cursor = ReadCursor::new(&body);
        let pdu = Wave2Pdu::decode_body(&mut cursor, 12).unwrap();
        assert!(pdu.data.is_empty());
    }

    #[test]
    fn wave_data_reassembly() {
        let wave_info = WaveInfoPdu {
            timestamp: 0,
            format_no: 0,
            block_no: 0,
            initial_data: [0xAA, 0xBB, 0xCC, 0xDD],
            total_audio_size: 8,
        };
        // Wave PDU: 4 bytes pad + 4 bytes remaining data
        let wave_pdu = [0x00, 0x00, 0x00, 0x00, 0xEE, 0xFF, 0x11, 0x22];
        let mut cursor = ReadCursor::new(&wave_pdu);
        let audio = decode_wave_data(&mut cursor, &wave_info).unwrap();
        assert_eq!(audio, alloc::vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);
    }

    #[test]
    fn wave2_roundtrip() {
        let pdu = Wave2Pdu {
            timestamp: 500,
            format_no: 1,
            block_no: 3,
            audio_timestamp: 12345,
            data: alloc::vec![0x10, 0x20, 0x30, 0x40],
        };

        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::Wave2);
        assert_eq!(header.body_size as usize, 12 + 4);

        let decoded = Wave2Pdu::decode_body(&mut cursor, header.body_size).unwrap();
        assert_eq!(decoded, pdu);
    }
}
