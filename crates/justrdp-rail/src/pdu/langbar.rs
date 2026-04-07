#![forbid(unsafe_code)]

//! Language Bar Info PDU -- MS-RDPERP 2.2.2.9.1

use justrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use super::header::{RailHeader, RailOrderType, RAIL_HEADER_SIZE};

// ── Language bar status flags -- MS-RDPERP 2.2.2.9.1 ──

pub const TF_SFT_SHOWNORMAL: u32 = 0x0000_0001;
pub const TF_SFT_DOCK: u32 = 0x0000_0002;
pub const TF_SFT_MINIMIZED: u32 = 0x0000_0004;
pub const TF_SFT_HIDDEN: u32 = 0x0000_0008;
pub const TF_SFT_NOTRANSPARENCY: u32 = 0x0000_0010;
pub const TF_SFT_LOWTRANSPARENCY: u32 = 0x0000_0020;
pub const TF_SFT_HIGHTRANSPARENCY: u32 = 0x0000_0040;
pub const TF_SFT_LABELS: u32 = 0x0000_0080;
pub const TF_SFT_NOLABELS: u32 = 0x0000_0100;
pub const TF_SFT_EXTRAICONSONMINIMIZED: u32 = 0x0000_0200;
pub const TF_SFT_NOEXTRAICONSONMINIMIZED: u32 = 0x0000_0400;
pub const TF_SFT_DESKBAND: u32 = 0x0000_0800;

/// Language Bar Info PDU -- MS-RDPERP 2.2.2.9.1
///
/// Bidirectional: both client and server may send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LangBarInfoPdu {
    pub language_bar_status: u32,
}

impl LangBarInfoPdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4;

    pub fn new(status: u32) -> Self {
        Self {
            language_bar_status: status,
        }
    }
}

impl Encode for LangBarInfoPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::LangBarInfo, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.language_bar_status, "LangBarInfo::LanguageBarStatus")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "LangBarInfoPdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for LangBarInfoPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let language_bar_status = src.read_u32_le("LangBarInfo::LanguageBarStatus")?;
        Ok(Self {
            language_bar_status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn langbar_roundtrip() {
        let pdu = LangBarInfoPdu::new(TF_SFT_DOCK | TF_SFT_LABELS);
        let mut buf = [0u8; LangBarInfoPdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = RailHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.order_type, RailOrderType::LangBarInfo);
        let decoded = LangBarInfoPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }
}
