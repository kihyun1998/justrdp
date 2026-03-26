#![forbid(unsafe_code)]

//! Pre-Connection Blob (PCB) -- MS-RDPBCGR 2.2.1.0
//!
//! Sent by the client **before** the X.224 Connection Request to provide
//! correlation info for load balancers and connection brokers.
//!
//! Wire format (little-endian):
//! ```text
//! ┌──────────┬───────┬─────────┬────────┬──────────────────────┐
//! │ cbSize   │ flags │ version │ id     │ [v2: target name]    │
//! │  4B LE   │ 4B LE │  2B LE  │ 16B    │ UTF-16LE + null (v2) │
//! └──────────┴───────┴─────────┴────────┴──────────────────────┘
//! ```

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

/// PCB version 1 (Correlation ID only).
pub const PCB_VERSION_1: u16 = 1;

/// PCB version 2 (Correlation ID + Target name).
pub const PCB_VERSION_2: u16 = 2;

/// PCB flags (currently always 0).
pub const PCB_FLAGS: u32 = 0;

/// Size of the correlation ID field.
pub const CORRELATION_ID_SIZE: usize = 16;

/// Fixed size of PCB v1: cbSize(4) + flags(4) + version(2) + id(2) + correlationId(16) = 28
/// Note: the `id` field is actually 2 bytes (unused, set to 0).
pub const PCB_V1_FIXED_SIZE: usize = 4 + 4 + 2 + 2 + CORRELATION_ID_SIZE;

/// Pre-Connection Blob.
///
/// Contains correlation info used by load balancers to route connections
/// to the correct session host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreConnectionBlob {
    /// 16-byte correlation ID.
    pub correlation_id: [u8; CORRELATION_ID_SIZE],
    /// Optional target name (v2 only). UTF-16LE encoded on wire.
    #[cfg(feature = "alloc")]
    pub target: Option<alloc::string::String>,
}

impl PreConnectionBlob {
    /// Create a PCB v1 (correlation ID only).
    pub fn v1(correlation_id: [u8; CORRELATION_ID_SIZE]) -> Self {
        Self {
            correlation_id,
            #[cfg(feature = "alloc")]
            target: None,
        }
    }

    /// Create a PCB v2 (correlation ID + target name).
    #[cfg(feature = "alloc")]
    pub fn v2(correlation_id: [u8; CORRELATION_ID_SIZE], target: alloc::string::String) -> Self {
        Self {
            correlation_id,
            target: Some(target),
        }
    }

    /// Returns the PCB version.
    pub fn version(&self) -> u16 {
        #[cfg(feature = "alloc")]
        if self.target.is_some() {
            return PCB_VERSION_2;
        }
        PCB_VERSION_1
    }

    /// Compute the size of the target name field on wire (UTF-16LE + null terminator).
    #[cfg(feature = "alloc")]
    fn target_wire_size(&self) -> usize {
        match &self.target {
            Some(t) => {
                // UTF-16LE: each char is 2 bytes + 2 bytes null terminator
                (t.encode_utf16().count() + 1) * 2
            }
            None => 0,
        }
    }
}

impl Encode for PreConnectionBlob {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let cb_size = self.size() as u32;
        dst.write_u32_le(cb_size, "PCB::cbSize")?;
        dst.write_u32_le(PCB_FLAGS, "PCB::flags")?;
        dst.write_u16_le(self.version(), "PCB::version")?;
        // cbTargetName: byte length of targetName field (0 for v1, target wire size for v2)
        let cb_target_name = self.target_wire_size() as u16;
        dst.write_u16_le(cb_target_name, "PCB::cbTargetName")?;
        dst.write_slice(&self.correlation_id, "PCB::correlationId")?;

        #[cfg(feature = "alloc")]
        if let Some(ref target) = self.target {
            // Write UTF-16LE encoded target name
            for code_unit in target.encode_utf16() {
                dst.write_u16_le(code_unit, "PCB::target")?;
            }
            // Null terminator
            dst.write_u16_le(0, "PCB::target_null")?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "PreConnectionBlob"
    }

    fn size(&self) -> usize {
        let mut size = PCB_V1_FIXED_SIZE;
        #[cfg(feature = "alloc")]
        {
            size += self.target_wire_size();
        }
        size
    }
}

#[cfg(feature = "alloc")]
impl<'de> Decode<'de> for PreConnectionBlob {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cb_size = src.read_u32_le("PCB::cbSize")? as usize;
        let _flags = src.read_u32_le("PCB::flags")?;
        let version = src.read_u16_le("PCB::version")?;
        let cb_target_name = src.read_u16_le("PCB::cbTargetName")? as usize;

        if version != PCB_VERSION_1 && version != PCB_VERSION_2 {
            return Err(DecodeError::unexpected_value(
                "PreConnectionBlob",
                "version",
                "expected 1 or 2",
            ));
        }

        let id_bytes = src.read_slice(CORRELATION_ID_SIZE, "PCB::correlationId")?;
        let mut correlation_id = [0u8; CORRELATION_ID_SIZE];
        correlation_id.copy_from_slice(id_bytes);

        let target = if version == PCB_VERSION_2 {
            // Use cbTargetName for target size, fallback to cbSize-based calculation
            let target_size = if cb_target_name > 0 {
                cb_target_name
            } else {
                cb_size.saturating_sub(PCB_V1_FIXED_SIZE)
            };
            if target_size < 2 {
                return Err(DecodeError::invalid_value("PreConnectionBlob", "cbTargetName"));
            }

            let target_bytes = src.read_slice(target_size, "PCB::target")?;
            // Decode UTF-16LE, strip null terminator
            let u16_units: alloc::vec::Vec<u16> = target_bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .take_while(|&c| c != 0)
                .collect();
            Some(alloc::string::String::from_utf16_lossy(&u16_units))
        } else {
            None
        };

        Ok(Self {
            correlation_id,
            target,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcb_v1_roundtrip() {
        let id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let pcb = PreConnectionBlob::v1(id);

        assert_eq!(pcb.version(), PCB_VERSION_1);
        assert_eq!(pcb.size(), PCB_V1_FIXED_SIZE);

        let mut buf = alloc::vec![0u8; pcb.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pcb.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = PreConnectionBlob::decode(&mut cursor).unwrap();
        assert_eq!(decoded.correlation_id, id);
        assert_eq!(decoded.target, None);
    }

    #[test]
    fn pcb_v2_roundtrip() {
        let id = [0xAA; CORRELATION_ID_SIZE];
        let pcb = PreConnectionBlob::v2(id, "SESSIONHOST01".into());

        assert_eq!(pcb.version(), PCB_VERSION_2);

        let mut buf = alloc::vec![0u8; pcb.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pcb.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = PreConnectionBlob::decode(&mut cursor).unwrap();
        assert_eq!(decoded.correlation_id, id);
        assert_eq!(decoded.target.as_deref(), Some("SESSIONHOST01"));
    }

    #[test]
    fn pcb_invalid_version() {
        let mut buf = [0u8; PCB_V1_FIXED_SIZE];
        // cbSize = 28
        buf[0..4].copy_from_slice(&28u32.to_le_bytes());
        // flags = 0
        // version = 99 (invalid)
        buf[8..10].copy_from_slice(&99u16.to_le_bytes());

        let mut cursor = ReadCursor::new(&buf);
        assert!(PreConnectionBlob::decode(&mut cursor).is_err());
    }

    #[test]
    fn pcb_v2_empty_target() {
        let id = [0x55; CORRELATION_ID_SIZE];
        let pcb = PreConnectionBlob::v2(id, "".into());

        let mut buf = alloc::vec![0u8; pcb.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pcb.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = PreConnectionBlob::decode(&mut cursor).unwrap();
        assert_eq!(decoded.correlation_id, id);
        assert_eq!(decoded.target.as_deref(), Some(""));
    }
}
