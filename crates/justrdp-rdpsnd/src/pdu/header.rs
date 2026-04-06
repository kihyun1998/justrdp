#![forbid(unsafe_code)]

//! SNDPROLOG -- MS-RDPEA 2.2.1
//!
//! 4-byte header present in all RDPSND PDUs (except Wave PDU).

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeResult};

/// RDPSND PDU header size in bytes.
pub const SND_HEADER_SIZE: usize = 4;

/// RDPSND message types -- MS-RDPEA 2.2.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SndMsgType {
    /// Close PDU.
    Close = 0x01,
    /// WaveInfo PDU.
    Wave = 0x02,
    /// Volume PDU.
    SetVolume = 0x03,
    /// Pitch PDU.
    SetPitch = 0x04,
    /// Wave Confirm PDU.
    WaveConfirm = 0x05,
    /// Training / Training Confirm PDU.
    Training = 0x06,
    /// Server/Client Audio Formats and Version PDU.
    Formats = 0x07,
    /// Crypt Key PDU.
    CryptKey = 0x08,
    /// Wave Encrypt PDU (UDP only).
    WaveEncrypt = 0x09,
    /// UDP Wave PDU.
    UdpWave = 0x0A,
    /// UDP Wave Last PDU.
    UdpWaveLast = 0x0B,
    /// Quality Mode PDU.
    QualityMode = 0x0C,
    /// Wave2 PDU.
    Wave2 = 0x0D,
}

impl SndMsgType {
    /// Check if a byte value is a known RDPSND message type.
    pub fn is_valid(value: u8) -> bool {
        Self::from_u8(value).is_some()
    }

    /// Try to convert a u8 to a SndMsgType.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Close),
            0x02 => Some(Self::Wave),
            0x03 => Some(Self::SetVolume),
            0x04 => Some(Self::SetPitch),
            0x05 => Some(Self::WaveConfirm),
            0x06 => Some(Self::Training),
            0x07 => Some(Self::Formats),
            0x08 => Some(Self::CryptKey),
            0x09 => Some(Self::WaveEncrypt),
            0x0A => Some(Self::UdpWave),
            0x0B => Some(Self::UdpWaveLast),
            0x0C => Some(Self::QualityMode),
            0x0D => Some(Self::Wave2),
            _ => None,
        }
    }
}

/// SNDPROLOG -- MS-RDPEA 2.2.1
///
/// ```text
/// ┌──────────┬──────┬────────────┐
/// │ msgType  │ bPad │ BodySize   │
/// │ (1 byte) │ (1)  │ (2 bytes)  │
/// └──────────┴──────┴────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SndHeader {
    /// PDU type identifier.
    pub msg_type: SndMsgType,
    /// Size of data following this header.
    pub body_size: u16,
}

impl SndHeader {
    /// Create a new RDPSND header.
    pub fn new(msg_type: SndMsgType, body_size: u16) -> Self {
        Self {
            msg_type,
            body_size,
        }
    }
}

impl Encode for SndHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(self.msg_type as u8, "SndHeader::msgType")?;
        dst.write_u8(0, "SndHeader::bPad")?;
        dst.write_u16_le(self.body_size, "SndHeader::BodySize")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SndHeader"
    }

    fn size(&self) -> usize {
        SND_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for SndHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let raw_type = src.read_u8("SndHeader::msgType")?;
        let msg_type = SndMsgType::from_u8(raw_type)
            .ok_or_else(|| DecodeError::invalid_value("SndHeader", "msgType"))?;
        let _pad = src.read_u8("SndHeader::bPad")?;
        let body_size = src.read_u16_le("SndHeader::BodySize")?;
        Ok(Self {
            msg_type,
            body_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = SndHeader::new(SndMsgType::Formats, 144);
        let mut buf = [0u8; SND_HEADER_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        header.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded.msg_type, SndMsgType::Formats);
        assert_eq!(decoded.body_size, 144);
    }

    #[test]
    fn header_spec_bytes() {
        // From MS-RDPEA test vector: 07 2b 90 00
        let bytes = [0x07, 0x2b, 0x90, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::Formats);
        assert_eq!(header.body_size, 0x0090); // 144
    }
}
