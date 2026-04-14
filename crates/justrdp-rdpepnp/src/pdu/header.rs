//! `PNP_INFO_HEADER` — the 8-byte header prefixing every PNPDR PDU
//! (MS-RDPEPNP §2.2.1.1).

use justrdp_core::{DecodeError, DecodeResult, EncodeResult, ReadCursor, WriteCursor};

use crate::constants::PNP_INFO_HEADER_SIZE;

/// `PNP_INFO_HEADER` — `Size` includes the 8-byte header; `PacketId`
/// disambiguates the message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PnpInfoHeader {
    /// Total PDU size in bytes, including this header.
    pub size: u32,
    /// Message type (see [`crate::constants::packet_id`]).
    pub packet_id: u32,
}

const HDR_CTX: &str = "PnpInfoHeader";

impl PnpInfoHeader {
    pub fn new(size: u32, packet_id: u32) -> Self {
        Self { size, packet_id }
    }

    pub(crate) fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.size, HDR_CTX)?;
        dst.write_u32_le(self.packet_id, HDR_CTX)?;
        Ok(())
    }

    pub(crate) fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let size = src.read_u32_le(HDR_CTX)?;
        let packet_id = src.read_u32_le(HDR_CTX)?;
        if (size as usize) < PNP_INFO_HEADER_SIZE {
            return Err(DecodeError::invalid_value(HDR_CTX, "Size < 8"));
        }
        Ok(Self { size, packet_id })
    }

    /// Verify that a decoded header matches a PDU's expected `PacketId`
    /// and total `Size`. Fixed-size PDUs call this once after decoding
    /// the header.
    pub(crate) fn expect(
        &self,
        expected_packet_id: u32,
        expected_size: u32,
        ctx: &'static str,
    ) -> DecodeResult<()> {
        if self.packet_id != expected_packet_id {
            return Err(DecodeError::invalid_value(ctx, "PacketId"));
        }
        if self.size != expected_size {
            return Err(DecodeError::invalid_value(ctx, "Size"));
        }
        Ok(())
    }
}
