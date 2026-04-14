//! `OD_FILTER_STATE_UPDATED` (MS-RDPEMC §2.2.3.1).

use justrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor,
};

use super::header::OrderHeader;
use crate::constants::odtype;

/// Total wire size of [`OdFilterStateUpdated`] in bytes.
pub const FILTER_STATE_UPDATED_SIZE: u16 = 5;

/// `OD_FILTER_STATE_UPDATED` (MS-RDPEMC §2.2.3.1). Direction: SM → P.
///
/// Signals that the sharing filter has been enabled or disabled. On any
/// state change the receiver SHOULD flush cached application and window
/// lists because the sharing manager is about to re-send them
/// (MS-RDPEMC Appendix A <13>).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OdFilterStateUpdated {
    /// `Flags` byte. Bit 0 is [`crate::constants::flags::FILTER_ENABLED`];
    /// other bits are reserved.
    pub flags: u8,
}

const CTX: &str = "OD_FILTER_STATE_UPDATED";

impl OdFilterStateUpdated {
    pub fn size(&self) -> usize {
        FILTER_STATE_UPDATED_SIZE as usize
    }
}

impl Encode for OdFilterStateUpdated {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        OrderHeader::new(odtype::FILTER_STATE_UPDATED, FILTER_STATE_UPDATED_SIZE).encode(dst)?;
        dst.write_u8(self.flags, CTX)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        CTX
    }

    fn size(&self) -> usize {
        FILTER_STATE_UPDATED_SIZE as usize
    }
}

impl<'de> Decode<'de> for OdFilterStateUpdated {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        hdr.expect(odtype::FILTER_STATE_UPDATED, FILTER_STATE_UPDATED_SIZE)?;
        let flags = src.read_u8(CTX)?;
        Ok(Self { flags })
    }
}
