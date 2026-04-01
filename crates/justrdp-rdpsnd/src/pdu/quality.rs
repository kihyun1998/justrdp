#![forbid(unsafe_code)]

//! Quality Mode PDU -- MS-RDPEA 2.2.2.3

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{DecodeResult, Encode, EncodeResult};

use super::header::{SndHeader, SndMsgType, SND_HEADER_SIZE};

/// Quality mode values -- MS-RDPEA 2.2.2.3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum QualityMode {
    /// Server auto-adjusts format based on bandwidth/latency.
    Dynamic = 0x0000,
    /// Moderate quality, moderate bandwidth.
    Medium = 0x0001,
    /// Best quality, ignores bandwidth.
    High = 0x0002,
}

impl QualityMode {
    /// Create from raw u16 value.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Self::Dynamic),
            0x0001 => Some(Self::Medium),
            0x0002 => Some(Self::High),
            _ => None,
        }
    }
}

/// Quality Mode PDU -- MS-RDPEA 2.2.2.3
///
/// 8 bytes total: 4-byte header + 2-byte quality mode + 2-byte reserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityModePdu {
    /// Selected quality mode.
    pub quality_mode: QualityMode,
}

impl QualityModePdu {
    /// Create a new quality mode PDU.
    pub fn new(quality_mode: QualityMode) -> Self {
        Self { quality_mode }
    }

    /// Decode from cursor after the header has been read.
    pub fn decode_body(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let raw = src.read_u16_le("QualityModePdu::wQualityMode")?;
        let _reserved = src.read_u16_le("QualityModePdu::Reserved")?;
        let quality_mode = QualityMode::from_u16(raw).unwrap_or(QualityMode::Dynamic);
        Ok(Self { quality_mode })
    }
}

impl Encode for QualityModePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SndHeader::new(SndMsgType::QualityMode, 4);
        header.encode(dst)?;
        dst.write_u16_le(self.quality_mode as u16, "QualityModePdu::wQualityMode")?;
        dst.write_u16_le(0, "QualityModePdu::Reserved")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "QualityModePdu"
    }

    fn size(&self) -> usize {
        SND_HEADER_SIZE + 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_core::Decode as _;

    #[test]
    fn quality_mode_roundtrip() {
        let pdu = QualityModePdu::new(QualityMode::High);
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::QualityMode);
        assert_eq!(header.body_size, 4);

        let decoded = QualityModePdu::decode_body(&mut cursor).unwrap();
        assert_eq!(decoded.quality_mode, QualityMode::High);
    }
}
