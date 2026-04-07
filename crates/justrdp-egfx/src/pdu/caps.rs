extern crate alloc;

use alloc::vec::Vec;
use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor};

use super::{
    RdpgfxHeader, RDPGFX_CMDID_CAPSADVERTISE, RDPGFX_CMDID_CAPSCONFIRM,
    RDPGFX_CAPVERSION_101,
};

// ── RDPGFX_CAPSET (MS-RDPEGFX 2.2.1.6) ──

/// A single capability set.
///
/// ```text
/// Offset  Size  Field
/// 0       4     version (u32 LE)
/// 4       4     capsDataLength (u32 LE)
/// 8       var   capsData (capsDataLength bytes)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GfxCapSet {
    pub version: u32,
    pub flags: u32,
}

impl GfxCapSet {
    /// Wire size: 8 (version + capsDataLength) + capsData.
    /// VERSION101 has 16 bytes capsData; all others have 4 bytes.
    pub fn caps_data_length(&self) -> u32 {
        if self.version == RDPGFX_CAPVERSION_101 {
            16
        } else {
            4
        }
    }
}

impl Encode for GfxCapSet {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.version, "GfxCapSet::version")?;
        let cdl = self.caps_data_length();
        dst.write_u32_le(cdl, "GfxCapSet::capsDataLength")?;
        if self.version == RDPGFX_CAPVERSION_101 {
            // VERSION101: 16 bytes capsData — first 4 bytes are flags, rest reserved
            // (MS-RDPEGFX 2.2.3.4)
            dst.write_u32_le(self.flags, "GfxCapSet::flags")?;
            dst.write_slice(&[0u8; 12], "GfxCapSet::reserved")?;
        } else {
            dst.write_u32_le(self.flags, "GfxCapSet::flags")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "GfxCapSet"
    }

    fn size(&self) -> usize {
        8 + self.caps_data_length() as usize
    }
}

impl<'de> Decode<'de> for GfxCapSet {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let version = src.read_u32_le("GfxCapSet::version")?;
        let caps_data_length = src.read_u32_le("GfxCapSet::capsDataLength")?;

        if version == RDPGFX_CAPVERSION_101 {
            if caps_data_length != 16 {
                return Err(DecodeError::invalid_value("GfxCapSet", "capsDataLength"));
            }
            let flags = src.read_u32_le("GfxCapSet::flags")?;
            let _reserved = src.read_slice(12, "GfxCapSet::reserved")?;
            Ok(Self { version, flags })
        } else {
            if caps_data_length != 4 {
                return Err(DecodeError::invalid_value("GfxCapSet", "capsDataLength"));
            }
            let flags = src.read_u32_le("GfxCapSet::flags")?;
            Ok(Self { version, flags })
        }
    }
}

// ── RDPGFX_CAPS_ADVERTISE_PDU (MS-RDPEGFX 2.2.2.18) — Client → Server ──

/// Capability advertisement sent by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsAdvertisePdu {
    pub cap_sets: Vec<GfxCapSet>,
}

impl CapsAdvertisePdu {
    /// Minimum wire size: header(8) + capsSetCount(2) = 10.
    pub const MIN_WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + 2;
}

impl Encode for CapsAdvertisePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let pdu_length = self.size() as u32;
        let header = RdpgfxHeader {
            cmd_id: RDPGFX_CMDID_CAPSADVERTISE,
            flags: 0,
            pdu_length,
        };
        header.encode(dst)?;

        let count = u16::try_from(self.cap_sets.len())
            .map_err(|_| EncodeError::other("CapsAdvertisePdu", "capsSetCount overflows u16"))?;
        dst.write_u16_le(count, "CapsAdvertise::capsSetCount")?;

        for cs in &self.cap_sets {
            cs.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CapsAdvertisePdu"
    }

    fn size(&self) -> usize {
        Self::MIN_WIRE_SIZE + self.cap_sets.iter().map(|cs| cs.size()).sum::<usize>()
    }
}

impl<'de> Decode<'de> for CapsAdvertisePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = RdpgfxHeader::decode(src)?;
        if header.cmd_id != RDPGFX_CMDID_CAPSADVERTISE {
            return Err(DecodeError::invalid_value("CapsAdvertisePdu", "cmdId"));
        }

        let count = src.read_u16_le("CapsAdvertise::capsSetCount")?;
        let mut cap_sets = Vec::with_capacity(count as usize);
        for _ in 0..count {
            cap_sets.push(GfxCapSet::decode(src)?);
        }

        Ok(Self { cap_sets })
    }
}

// ── RDPGFX_CAPS_CONFIRM_PDU (MS-RDPEGFX 2.2.2.19) — Server → Client ──

/// Capability confirmation sent by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsConfirmPdu {
    pub cap_set: GfxCapSet,
}

impl Encode for CapsConfirmPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let pdu_length = self.size() as u32;
        let header = RdpgfxHeader {
            cmd_id: RDPGFX_CMDID_CAPSCONFIRM,
            flags: 0,
            pdu_length,
        };
        header.encode(dst)?;
        self.cap_set.encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CapsConfirmPdu"
    }

    fn size(&self) -> usize {
        RdpgfxHeader::WIRE_SIZE + self.cap_set.size()
    }
}

impl<'de> Decode<'de> for CapsConfirmPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = RdpgfxHeader::decode(src)?;
        if header.cmd_id != RDPGFX_CMDID_CAPSCONFIRM {
            return Err(DecodeError::invalid_value("CapsConfirmPdu", "cmdId"));
        }

        let cap_set = GfxCapSet::decode(src)?;
        Ok(Self { cap_set })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn capset_version10_roundtrip() {
        let cs = GfxCapSet {
            version: 0x000A_0002,
            flags: 0,
        };
        let mut buf = vec![0u8; cs.size()];
        let mut dst = WriteCursor::new(&mut buf);
        cs.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(GfxCapSet::decode(&mut src).unwrap(), cs);
    }

    #[test]
    fn capset_version101_roundtrip() {
        let cs = GfxCapSet {
            version: RDPGFX_CAPVERSION_101,
            flags: 0,
        };
        assert_eq!(cs.size(), 24); // 8 + 16
        let mut buf = vec![0u8; cs.size()];
        let mut dst = WriteCursor::new(&mut buf);
        cs.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        let decoded = GfxCapSet::decode(&mut src).unwrap();
        assert_eq!(decoded.version, RDPGFX_CAPVERSION_101);
        assert_eq!(decoded.flags, 0);
    }

    #[test]
    fn caps_advertise_roundtrip() {
        let pdu = CapsAdvertisePdu {
            cap_sets: vec![
                GfxCapSet {
                    version: 0x000A_0002,
                    flags: 0,
                },
                GfxCapSet {
                    version: 0x0008_0004,
                    flags: 0x0000_0002,
                },
            ],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(CapsAdvertisePdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn caps_advertise_spec_vector() {
        // Minimal CapsAdvertise with one VERSION10 capset (flags=0)
        // Header: cmdId=0x0012, flags=0x0000, pduLength=22
        // capsSetCount=1
        // capset: version=0x000A0002, capsDataLength=4, flags=0
        let pdu = CapsAdvertisePdu {
            cap_sets: vec![GfxCapSet {
                version: 0x000A_0002,
                flags: 0,
            }],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();

        assert_eq!(pdu.size(), 22);
        // Header bytes
        assert_eq!(&buf[0..2], &[0x12, 0x00]); // cmdId
        assert_eq!(&buf[2..4], &[0x00, 0x00]); // flags
        assert_eq!(&buf[4..8], &[22, 0, 0, 0]); // pduLength
        // capsSetCount
        assert_eq!(&buf[8..10], &[0x01, 0x00]);
        // capset version
        assert_eq!(&buf[10..14], &[0x02, 0x00, 0x0A, 0x00]);
        // capsDataLength
        assert_eq!(&buf[14..18], &[0x04, 0x00, 0x00, 0x00]);
        // flags
        assert_eq!(&buf[18..22], &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn caps_confirm_roundtrip() {
        let pdu = CapsConfirmPdu {
            cap_set: GfxCapSet {
                version: 0x000A_0002,
                flags: 0x0000_0020, // AVC_DISABLED
            },
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(CapsConfirmPdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn capset_reject_invalid_caps_data_length() {
        // version = VERSION8, capsDataLength = 8 (should be 4)
        let data = [
            0x04, 0x00, 0x08, 0x00, // version
            0x08, 0x00, 0x00, 0x00, // capsDataLength = 8 (wrong)
            0x00, 0x00, 0x00, 0x00, // data
        ];
        let mut src = ReadCursor::new(&data);
        assert!(GfxCapSet::decode(&mut src).is_err());
    }
}
