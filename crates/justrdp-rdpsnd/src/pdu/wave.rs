#![forbid(unsafe_code)]

//! WaveInfo / Wave2 PDU -- MS-RDPEA 2.2.3.3, 2.2.3.10

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

/// Fixed body size seen on the wire for a WaveInfo PDU (before the
/// `BodySize` overloading that also encodes total audio size). Covers
/// `wTimeStamp` (2) + `wFormatNo` (2) + `cBlockNo` (1) + `bPad` (3) +
/// `Data[4]` (4) = 12 bytes.
const WAVE_INFO_WIRE_BODY_SIZE: usize = 12;

impl WaveInfoPdu {
    /// Build a WaveInfo PDU from an audio chunk. The first 4 bytes of
    /// `audio` populate `Data[]` (`initial_data`); the remaining bytes
    /// are emitted by the caller as a Wave PDU via
    /// [`encode_wave_pdu_body`].
    ///
    /// Returns `None` if `audio.len() < 4` -- the WaveInfo PDU requires
    /// at least 4 bytes to fill the `Data[4]` field (MS-RDPEA 2.2.3.3).
    pub fn from_chunk(
        timestamp: u16,
        format_no: u16,
        block_no: u8,
        audio: &[u8],
    ) -> Option<Self> {
        if audio.len() < 4 {
            return None;
        }
        let mut initial_data = [0u8; 4];
        initial_data.copy_from_slice(&audio[..4]);
        Some(Self {
            timestamp,
            format_no,
            block_no,
            initial_data,
            total_audio_size: audio.len(),
        })
    }

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

impl Encode for WaveInfoPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // MS-RDPEA 2.2.3.3: BodySize = 4 + total_audio_size, NOT the
        // 12 wire bytes. The spec overloads this field so the client
        // learns how many total audio bytes (across WaveInfo+Wave) are
        // en route. `total_audio_size` MUST be >= 4 (the 4 bytes in
        // `Data[]`); anything smaller is a struct-construction bug.
        if self.total_audio_size < 4 {
            return Err(justrdp_core::EncodeError::invalid_value(
                "WaveInfoPdu",
                "total_audio_size < 4",
            ));
        }
        let body_size = u16::try_from(self.total_audio_size.saturating_add(4))
            .map_err(|_| justrdp_core::EncodeError::invalid_value("WaveInfoPdu", "total_audio_size too large"))?;
        let header = SndHeader::new(SndMsgType::Wave, body_size);
        header.encode(dst)?;
        dst.write_u16_le(self.timestamp, "WaveInfoPdu::wTimeStamp")?;
        dst.write_u16_le(self.format_no, "WaveInfoPdu::wFormatNo")?;
        dst.write_u8(self.block_no, "WaveInfoPdu::cBlockNo")?;
        dst.write_slice(&[0u8; 3], "WaveInfoPdu::bPad")?;
        dst.write_slice(&self.initial_data, "WaveInfoPdu::Data")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "WaveInfoPdu"
    }

    fn size(&self) -> usize {
        SND_HEADER_SIZE + WAVE_INFO_WIRE_BODY_SIZE
    }
}

/// Encode the raw Wave PDU that follows a WaveInfo PDU on the wire.
///
/// The Wave PDU has no `SNDPROLOG` header; it is 4 zero bytes of
/// padding followed by the audio bytes that did not fit in the
/// preceding WaveInfo's `Data[4]` field (MS-RDPEA 2.2.3.4). Callers
/// typically pair this with [`WaveInfoPdu::from_chunk`] via:
///
/// ```text
/// let info = WaveInfoPdu::from_chunk(ts, fmt, blk, &audio)?;
/// let info_bytes = encode_to_vec(&info)?;
/// let wave_bytes = encode_wave_pdu_body(&audio[4..]);
/// // send info_bytes then wave_bytes on the SVC channel
/// ```
pub fn encode_wave_pdu_body(remaining_audio: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + remaining_audio.len());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(remaining_audio);
    out
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

/// Wave2 PDU (Server → Client) -- MS-RDPEA 2.2.3.10
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
    fn wave_info_from_chunk_rejects_short_audio() {
        // MS-RDPEA 2.2.3.3: Data[4] requires 4 bytes.
        assert!(WaveInfoPdu::from_chunk(0, 0, 0, &[]).is_none());
        assert!(WaveInfoPdu::from_chunk(0, 0, 0, &[1, 2, 3]).is_none());
        assert!(WaveInfoPdu::from_chunk(0, 0, 0, &[1, 2, 3, 4]).is_some());
    }

    #[test]
    fn wave_info_encode_minimum_audio_size() {
        // 4-byte audio -> total_audio_size=4, remaining=0, body_size=8.
        let pdu = WaveInfoPdu::from_chunk(100, 0, 1, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::Wave);
        assert_eq!(header.body_size, 8);

        let decoded = WaveInfoPdu::decode_body(&mut cursor, header.body_size).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn wave_info_encode_with_remaining_data() {
        // 12-byte audio -> total_audio_size=12, body_size=16, remaining=8.
        let audio: alloc::vec::Vec<u8> = (0..12u8).collect();
        let pdu = WaveInfoPdu::from_chunk(100, 0, 1, &audio).unwrap();
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.body_size, 16);
        let decoded = WaveInfoPdu::decode_body(&mut cursor, header.body_size).unwrap();
        assert_eq!(decoded.initial_data, [0, 1, 2, 3]);
        assert_eq!(decoded.total_audio_size, 12);
        assert_eq!(decoded.remaining_wave_size(), 8);
    }

    #[test]
    fn encode_wave_pdu_body_prepends_four_zero_pad() {
        // 0 remaining bytes -> just 4 zeros.
        let bytes = encode_wave_pdu_body(&[]);
        assert_eq!(bytes, alloc::vec![0, 0, 0, 0]);

        // 8 remaining bytes -> 4 zeros + those bytes.
        let bytes = encode_wave_pdu_body(&[0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(
            bytes,
            alloc::vec![0, 0, 0, 0, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        );
    }

    #[test]
    fn wave_info_plus_wave_roundtrip_full_audio() {
        // End-to-end: encode a 12-byte chunk, then decode WaveInfo and
        // Wave back, reassemble, verify identity.
        let audio: alloc::vec::Vec<u8> = (0x10..0x1Cu8).collect();
        let info = WaveInfoPdu::from_chunk(42, 2, 7, &audio).unwrap();

        let mut info_buf = alloc::vec![0u8; info.size()];
        let mut c = WriteCursor::new(&mut info_buf);
        info.encode(&mut c).unwrap();

        let wave_buf = encode_wave_pdu_body(&audio[4..]);

        // Decode WaveInfo.
        let mut c = ReadCursor::new(&info_buf);
        let header = SndHeader::decode(&mut c).unwrap();
        let decoded_info = WaveInfoPdu::decode_body(&mut c, header.body_size).unwrap();

        // Decode Wave (no header) and reassemble.
        let mut c = ReadCursor::new(&wave_buf);
        let full = decode_wave_data(&mut c, &decoded_info).unwrap();
        assert_eq!(full, audio);
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
