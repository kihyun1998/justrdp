//! `OD_APP_CREATED` (§2.2.3.2) and `OD_APP_REMOVED` (§2.2.3.3).

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use super::header::{OrderHeader, UnicodeString};
use crate::constants::odtype;

/// Total wire size of [`OdAppRemoved`] in bytes.
pub const APP_REMOVED_SIZE: u16 = 8;

/// Wire size of the fixed portion of [`OdAppCreated`] (before the
/// trailing [`UnicodeString`]).
pub const APP_CREATED_FIXED_SIZE: u16 = 10;

// ── OD_APP_CREATED (§2.2.3.2) ─────────────────────────────────────────

/// `OD_APP_CREATED` (MS-RDPEMC §2.2.3.2). Direction: SM → P.
///
/// Announces an application (identified by [`app_id`]; Windows uses the
/// process PID per Appendix A <1>) that is available for sharing.
/// On receive, upsert into the application list keyed by `app_id`.
///
/// [`app_id`]: Self::app_id
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OdAppCreated {
    /// `Flags` (u16). Bit 0 is
    /// [`crate::constants::flags::APPLICATION_SHARED`].
    pub flags: u16,
    /// Unique application identifier (Windows: PID).
    pub app_id: u32,
    /// Application display name. May be empty (`cchString == 0`);
    /// Windows may omit the name entirely (Appendix A <10>).
    pub name: UnicodeString,
}

const CREATED_CTX: &str = "OD_APP_CREATED";

impl OdAppCreated {
    pub fn size(&self) -> usize {
        APP_CREATED_FIXED_SIZE as usize + self.name.size()
    }

    fn total_length(&self) -> EncodeResult<u16> {
        let total = self.size();
        if total > u16::MAX as usize {
            return Err(EncodeError::invalid_value(CREATED_CTX, "length overflow"));
        }
        Ok(total as u16)
    }
}

impl Encode for OdAppCreated {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let length = self.total_length()?;
        OrderHeader::new(odtype::APP_CREATED, length).encode(dst)?;
        dst.write_u16_le(self.flags, CREATED_CTX)?;
        dst.write_u32_le(self.app_id, CREATED_CTX)?;
        self.name.encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        CREATED_CTX
    }

    fn size(&self) -> usize {
        OdAppCreated::size(self)
    }
}

impl<'de> Decode<'de> for OdAppCreated {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        if hdr.type_ != odtype::APP_CREATED {
            return Err(DecodeError::invalid_value(CREATED_CTX, "type"));
        }
        if hdr.length < APP_CREATED_FIXED_SIZE {
            return Err(DecodeError::invalid_value(CREATED_CTX, "length"));
        }
        let flags = src.read_u16_le(CREATED_CTX)?;
        let app_id = src.read_u32_le(CREATED_CTX)?;
        let name = UnicodeString::decode(src)?;
        let expected = APP_CREATED_FIXED_SIZE as usize + name.size();
        if expected != hdr.length as usize {
            return Err(DecodeError::invalid_value(CREATED_CTX, "length mismatch"));
        }
        Ok(Self {
            flags,
            app_id,
            name,
        })
    }
}

// ── OD_APP_REMOVED (§2.2.3.3) ─────────────────────────────────────────

/// `OD_APP_REMOVED` (MS-RDPEMC §2.2.3.3). Direction: SM → P.
///
/// Unknown `app_id` values MUST be silently discarded by the receiver
/// (§3.1.5.3). Removing an application also implicitly removes all
/// windows that referenced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OdAppRemoved {
    pub app_id: u32,
}

const REMOVED_CTX: &str = "OD_APP_REMOVED";

impl OdAppRemoved {
    pub fn size(&self) -> usize {
        APP_REMOVED_SIZE as usize
    }
}

impl Encode for OdAppRemoved {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        OrderHeader::new(odtype::APP_REMOVED, APP_REMOVED_SIZE).encode(dst)?;
        dst.write_u32_le(self.app_id, REMOVED_CTX)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        REMOVED_CTX
    }

    fn size(&self) -> usize {
        APP_REMOVED_SIZE as usize
    }
}

impl<'de> Decode<'de> for OdAppRemoved {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        hdr.expect(odtype::APP_REMOVED, APP_REMOVED_SIZE)?;
        let app_id = src.read_u32_le(REMOVED_CTX)?;
        Ok(Self { app_id })
    }
}
