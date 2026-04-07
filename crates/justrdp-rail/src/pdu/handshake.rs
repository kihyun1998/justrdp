#![forbid(unsafe_code)]

//! Handshake / HandshakeEx PDUs -- MS-RDPERP 2.2.2.2.1, 2.2.2.2.3

use justrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use super::header::{RailHeader, RailOrderType, RAIL_HEADER_SIZE};

// ── HandshakeEx flags -- MS-RDPERP 2.2.2.2.3 ──

/// Enhanced RemoteApp (HiDef) supported.
pub const TS_RAIL_ORDER_HANDSHAKEEX_FLAGS_HIDEF: u32 = 0x0000_0001;
/// Extended SPI supported.
pub const TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_EXTENDED_SPI_SUPPORTED: u32 = 0x0000_0002;
/// Snap arrange supported.
pub const TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_SNAP_ARRANGE_SUPPORTED: u32 = 0x0000_0004;
/// Text scale info supported.
pub const TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_TEXT_SCALE_SUPPORTED: u32 = 0x0000_0008;
/// Caret blink info supported.
pub const TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_CARET_BLINK_SUPPORTED: u32 = 0x0000_0010;
/// Extended SPI 2 supported.
pub const TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_EXTENDED_SPI_2_SUPPORTED: u32 = 0x0000_0020;
/// Extended SPI 3 supported.
pub const TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_EXTENDED_SPI_3_SUPPORTED: u32 = 0x0000_0040;

/// Handshake PDU -- MS-RDPERP 2.2.2.2.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakePdu {
    pub build_number: u32,
}

impl HandshakePdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4;

    pub fn new(build_number: u32) -> Self {
        Self { build_number }
    }
}

impl Encode for HandshakePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::Handshake, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.build_number, "Handshake::buildNumber")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "HandshakePdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for HandshakePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let build_number = src.read_u32_le("Handshake::buildNumber")?;
        Ok(Self { build_number })
    }
}

/// HandshakeEx PDU -- MS-RDPERP 2.2.2.2.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeExPdu {
    pub build_number: u32,
    pub rail_handshake_flags: u32,
}

impl HandshakeExPdu {
    pub const FIXED_SIZE: usize = RAIL_HEADER_SIZE + 4 + 4;

    pub fn new(build_number: u32, flags: u32) -> Self {
        Self {
            build_number,
            rail_handshake_flags: flags,
        }
    }
}

impl Encode for HandshakeExPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(RailOrderType::HandshakeEx, Self::FIXED_SIZE as u16);
        header.encode(dst)?;
        dst.write_u32_le(self.build_number, "HandshakeEx::buildNumber")?;
        dst.write_u32_le(self.rail_handshake_flags, "HandshakeEx::railHandshakeFlags")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "HandshakeExPdu"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE
    }
}

impl<'de> Decode<'de> for HandshakeExPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let build_number = src.read_u32_le("HandshakeEx::buildNumber")?;
        let rail_handshake_flags = src.read_u32_le("HandshakeEx::railHandshakeFlags")?;
        Ok(Self {
            build_number,
            rail_handshake_flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_roundtrip() {
        let pdu = HandshakePdu::new(0x00001DB1);
        let mut buf = [0u8; HandshakePdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = RailHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.order_type, RailOrderType::Handshake);
        assert_eq!(header.order_length, 8);
        let decoded = HandshakePdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn handshake_ex_roundtrip() {
        let pdu = HandshakeExPdu::new(
            0x00001DB1,
            TS_RAIL_ORDER_HANDSHAKEEX_FLAGS_HIDEF
                | TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_SNAP_ARRANGE_SUPPORTED,
        );
        let mut buf = [0u8; HandshakeExPdu::FIXED_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = RailHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.order_type, RailOrderType::HandshakeEx);
        assert_eq!(header.order_length, 12);
        let decoded = HandshakeExPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }
}
