#![forbid(unsafe_code)]

//! Clipboard Capabilities PDU -- MS-RDPECLIP 2.2.2.1

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeError, EncodeResult};
use justrdp_core::{Decode, Encode};

use super::header::{ClipboardHeader, ClipboardMsgFlags, ClipboardMsgType, CLIPBOARD_HEADER_SIZE};

/// General capability set version 1 -- MS-RDPECLIP 2.2.2.1.1.1
pub const CB_CAPS_VERSION_1: u32 = 0x0000_0001;
/// General capability set version 2 -- MS-RDPECLIP 2.2.2.1.1.1
pub const CB_CAPS_VERSION_2: u32 = 0x0000_0002;

/// Capability set type: General -- MS-RDPECLIP 2.2.2.1.1
const CB_CAPSTYPE_GENERAL: u16 = 0x0001;

/// Size of the general capability set (type + length + version + flags) -- MS-RDPECLIP 2.2.2.1.1.1
const GENERAL_CAPABILITY_SET_SIZE: usize = 12;

/// General capability flags -- MS-RDPECLIP 2.2.2.1.1.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneralCapabilityFlags(u32);

impl GeneralCapabilityFlags {
    /// No flags.
    pub const NONE: Self = Self(0x0000_0000);
    /// Long format names supported.
    pub const USE_LONG_FORMAT_NAMES: Self = Self(0x0000_0002);
    /// File stream copy/paste supported.
    pub const STREAM_FILECLIP_ENABLED: Self = Self(0x0000_0004);
    /// Source file paths must not be included.
    pub const FILECLIP_NO_FILE_PATHS: Self = Self(0x0000_0008);
    /// Lock/Unlock PDUs supported.
    pub const CAN_LOCK_CLIPDATA: Self = Self(0x0000_0010);
    /// Files > 4 GiB supported.
    pub const HUGE_FILE_SUPPORT_ENABLED: Self = Self(0x0000_0020);

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Get raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check if a flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// General capability set -- MS-RDPECLIP 2.2.2.1.1.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralCapabilitySet {
    /// Informational version (MUST NOT be used for capability decisions).
    pub version: u32,
    /// Capability flags bitmask.
    pub general_flags: GeneralCapabilityFlags,
}

impl GeneralCapabilitySet {
    /// Create a new general capability set.
    pub fn new(version: u32, general_flags: GeneralCapabilityFlags) -> Self {
        Self {
            version,
            general_flags,
        }
    }
}

impl Encode for GeneralCapabilitySet {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // CLIPRDR_CAPS_SET header -- MS-RDPECLIP 2.2.2.1.1
        dst.write_u16_le(CB_CAPSTYPE_GENERAL, "GeneralCapabilitySet::capabilitySetType")?;
        dst.write_u16_le(
            GENERAL_CAPABILITY_SET_SIZE as u16,
            "GeneralCapabilitySet::lengthCapability",
        )?;
        // General capability data -- MS-RDPECLIP 2.2.2.1.1.1
        dst.write_u32_le(self.version, "GeneralCapabilitySet::version")?;
        dst.write_u32_le(self.general_flags.bits(), "GeneralCapabilitySet::generalFlags")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "GeneralCapabilitySet"
    }

    fn size(&self) -> usize {
        GENERAL_CAPABILITY_SET_SIZE
    }
}

impl<'de> Decode<'de> for GeneralCapabilitySet {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cap_type = src.read_u16_le("GeneralCapabilitySet::capabilitySetType")?;
        if cap_type != CB_CAPSTYPE_GENERAL {
            return Err(DecodeError::invalid_value(
                "GeneralCapabilitySet",
                "capabilitySetType",
            ));
        }
        let length = src.read_u16_le("GeneralCapabilitySet::lengthCapability")?;
        if length < GENERAL_CAPABILITY_SET_SIZE as u16 {
            return Err(DecodeError::invalid_value(
                "GeneralCapabilitySet",
                "lengthCapability",
            ));
        }
        let version = src.read_u32_le("GeneralCapabilitySet::version")?;
        let general_flags =
            GeneralCapabilityFlags::from_bits(src.read_u32_le("GeneralCapabilitySet::generalFlags")?);

        // Skip any extra bytes beyond the known fields.
        let extra = (length as usize).saturating_sub(GENERAL_CAPABILITY_SET_SIZE);
        if extra > 0 {
            src.skip(extra, "GeneralCapabilitySet::extra")?;
        }

        Ok(Self {
            version,
            general_flags,
        })
    }
}

/// Clipboard Capabilities PDU -- MS-RDPECLIP 2.2.2.1
///
/// Contains the header and one or more capability sets. In practice,
/// only the General Capability Set is defined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardCapsPdu {
    /// Capability sets (currently only General is defined).
    pub general: GeneralCapabilitySet,
}

impl ClipboardCapsPdu {
    /// Create a new capabilities PDU.
    pub fn new(general: GeneralCapabilitySet) -> Self {
        Self { general }
    }

    /// Payload length (after the 8-byte clipboard header):
    /// 2 (cCapabilitiesSets) + 2 (pad1) + capability set data.
    fn payload_len(&self) -> usize {
        4 + self.general.size()
    }
}

impl Encode for ClipboardCapsPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // Clipboard header
        let data_len = u32::try_from(self.payload_len())
            .map_err(|_| EncodeError::invalid_value("ClipboardCapsPdu", "dataLen too large"))?;
        let header = ClipboardHeader::new(
            ClipboardMsgType::ClipCaps,
            ClipboardMsgFlags::NONE,
            data_len,
        );
        header.encode(dst)?;

        // cCapabilitiesSets -- MS-RDPECLIP 2.2.2.1
        dst.write_u16_le(1, "ClipboardCapsPdu::cCapabilitiesSets")?;
        // pad1
        dst.write_u16_le(0, "ClipboardCapsPdu::pad1")?;
        // capability set
        self.general.encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ClipboardCapsPdu"
    }

    fn size(&self) -> usize {
        CLIPBOARD_HEADER_SIZE + self.payload_len()
    }
}

impl<'de> Decode<'de> for ClipboardCapsPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let count = src.read_u16_le("ClipboardCapsPdu::cCapabilitiesSets")?;
        src.skip(2, "ClipboardCapsPdu::pad1")?;

        if count == 0 {
            return Err(DecodeError::invalid_value(
                "ClipboardCapsPdu",
                "cCapabilitiesSets",
            ));
        }

        // Decode the first (and only defined) capability set.
        let general = GeneralCapabilitySet::decode(src)?;

        Ok(Self { general })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn caps_pdu_roundtrip() {
        let pdu = ClipboardCapsPdu::new(GeneralCapabilitySet::new(
            CB_CAPS_VERSION_2,
            GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
                .union(GeneralCapabilityFlags::STREAM_FILECLIP_ENABLED)
                .union(GeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS),
        ));
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        // Skip the 8-byte header for Decode (which expects post-header data).
        let mut cursor = ReadCursor::new(&buf[CLIPBOARD_HEADER_SIZE..]);
        let decoded = ClipboardCapsPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn caps_pdu_spec_test_vector() {
        // MS-RDPECLIP 4.1.1 -- Server Clipboard Capabilities PDU
        let bytes: Vec<u8> = alloc::vec![
            0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // header
            0x01, 0x00, 0x00, 0x00, // cCapabilitiesSets=1, pad1=0
            0x01, 0x00, 0x0C, 0x00, // type=GENERAL, length=12
            0x02, 0x00, 0x00, 0x00, // version=2
            0x0E, 0x00, 0x00, 0x00, // flags=0x0E
        ];

        // Decode header
        let mut cursor = ReadCursor::new(&bytes);
        let header = ClipboardHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, ClipboardMsgType::ClipCaps);
        assert_eq!(header.data_len, 0x10);

        // Decode caps
        let decoded = ClipboardCapsPdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded.general.version, CB_CAPS_VERSION_2);
        assert!(decoded
            .general
            .general_flags
            .contains(GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES));
        assert!(decoded
            .general
            .general_flags
            .contains(GeneralCapabilityFlags::STREAM_FILECLIP_ENABLED));
        assert!(decoded
            .general
            .general_flags
            .contains(GeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS));

        // Roundtrip: re-encode and compare
        let pdu = ClipboardCapsPdu::new(decoded.general.clone());
        let mut out = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut out);
        pdu.encode(&mut cursor).unwrap();
        assert_eq!(out, bytes);
    }
}
