#![forbid(unsafe_code)]

//! Wave Confirm PDU -- MS-RDPEA 2.2.3.8

use justrdp_core::{DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use super::header::{SndHeader, SndMsgType, SND_HEADER_SIZE};

/// Wave Confirm PDU (Client → Server) -- MS-RDPEA 2.2.3.8
///
/// 8 bytes total: 4-byte header + 4-byte body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaveConfirmPdu {
    /// Timestamp.
    pub timestamp: u16,
    /// Block number from the corresponding WaveInfo/Wave2 PDU.
    pub confirmed_block_no: u8,
}

impl WaveConfirmPdu {
    /// Create a new wave confirm PDU.
    pub fn new(timestamp: u16, confirmed_block_no: u8) -> Self {
        Self {
            timestamp,
            confirmed_block_no,
        }
    }

    /// Decode from cursor after the header has been read.
    ///
    /// Used by server-side processors (client emits this PDU) to
    /// correlate Wave / Wave2 PDUs with their completion timestamps.
    pub fn decode_body(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let timestamp = src.read_u16_le("WaveConfirmPdu::wTimeStamp")?;
        let confirmed_block_no = src.read_u8("WaveConfirmPdu::cConfirmedBlockNo")?;
        let _pad = src.read_u8("WaveConfirmPdu::bPad")?;
        Ok(Self {
            timestamp,
            confirmed_block_no,
        })
    }
}

impl Encode for WaveConfirmPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SndHeader::new(SndMsgType::WaveConfirm, 4);
        header.encode(dst)?;
        dst.write_u16_le(self.timestamp, "WaveConfirmPdu::wTimeStamp")?;
        dst.write_u8(self.confirmed_block_no, "WaveConfirmPdu::cConfirmedBlockNo")?;
        dst.write_u8(0, "WaveConfirmPdu::bPad")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "WaveConfirmPdu"
    }

    fn size(&self) -> usize {
        SND_HEADER_SIZE + 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_core::Decode;

    #[test]
    fn wave_confirm_roundtrip() {
        let pdu = WaveConfirmPdu::new(1234, 5);
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::WaveConfirm);
        assert_eq!(header.body_size, 4);

        let decoded = WaveConfirmPdu::decode_body(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }
}
