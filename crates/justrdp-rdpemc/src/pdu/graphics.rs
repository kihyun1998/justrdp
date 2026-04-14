//! `OD_GRAPHICS_STREAM_PAUSED` (§2.2.5.1) and
//! `OD_GRAPHICS_STREAM_RESUMED` (§2.2.5.2). Both are header-only
//! (4-byte total wire size) and travel SM → P.

use justrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use super::header::OrderHeader;
use crate::constants::{odtype, ORDER_HDR_SIZE};

const HEADER_ONLY_LEN: u16 = ORDER_HDR_SIZE as u16;

// ── OD_GRAPHICS_STREAM_PAUSED (§2.2.5.1) ──────────────────────────────

/// `OD_GRAPHICS_STREAM_PAUSED` (MS-RDPEMC §2.2.5.1). Direction: SM → P.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OdGraphicsStreamPaused;

const PAUSED_CTX: &str = "OD_GRAPHICS_STREAM_PAUSED";

impl OdGraphicsStreamPaused {
    pub fn size(&self) -> usize {
        ORDER_HDR_SIZE
    }
}

impl Encode for OdGraphicsStreamPaused {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        OrderHeader::new(odtype::GRAPHICS_STREAM_PAUSED, HEADER_ONLY_LEN).encode(dst)
    }

    fn name(&self) -> &'static str {
        PAUSED_CTX
    }

    fn size(&self) -> usize {
        ORDER_HDR_SIZE
    }
}

impl<'de> Decode<'de> for OdGraphicsStreamPaused {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        hdr.expect(odtype::GRAPHICS_STREAM_PAUSED, HEADER_ONLY_LEN)?;
        Ok(Self)
    }
}

// ── OD_GRAPHICS_STREAM_RESUMED (§2.2.5.2) ─────────────────────────────

/// `OD_GRAPHICS_STREAM_RESUMED` (MS-RDPEMC §2.2.5.2). Direction: SM → P.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OdGraphicsStreamResumed;

const RESUMED_CTX: &str = "OD_GRAPHICS_STREAM_RESUMED";

impl OdGraphicsStreamResumed {
    pub fn size(&self) -> usize {
        ORDER_HDR_SIZE
    }
}

impl Encode for OdGraphicsStreamResumed {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        OrderHeader::new(odtype::GRAPHICS_STREAM_RESUMED, HEADER_ONLY_LEN).encode(dst)
    }

    fn name(&self) -> &'static str {
        RESUMED_CTX
    }

    fn size(&self) -> usize {
        ORDER_HDR_SIZE
    }
}

impl<'de> Decode<'de> for OdGraphicsStreamResumed {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        hdr.expect(odtype::GRAPHICS_STREAM_RESUMED, HEADER_ONLY_LEN)?;
        Ok(Self)
    }
}
