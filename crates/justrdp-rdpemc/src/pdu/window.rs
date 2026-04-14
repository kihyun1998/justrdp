//! Window-related PDUs: `OD_WND_CREATED` (§2.2.3.4),
//! `OD_WND_REMOVED` (§2.2.3.5), `OD_WND_SHOW` (§2.2.3.6),
//! `OD_WND_REGION_UPDATE` (§2.2.3.7).

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use super::header::{OrderHeader, UnicodeString};
use crate::constants::odtype;

/// Fixed portion of [`OdWndCreated`] in bytes.
pub const WND_CREATED_FIXED_SIZE: u16 = 14;
/// Total wire size of [`OdWndRemoved`] in bytes.
pub const WND_REMOVED_SIZE: u16 = 8;
/// Total wire size of [`OdWndShow`] in bytes.
pub const WND_SHOW_SIZE: u16 = 8;
/// Total wire size of [`OdWndRegionUpdate`] in bytes.
pub const WND_REGION_UPDATE_SIZE: u16 = 20;

// ── OD_WND_CREATED (§2.2.3.4) ─────────────────────────────────────────

/// `OD_WND_CREATED` (MS-RDPEMC §2.2.3.4). Direction: SM → P.
///
/// Announces a window (Windows: HWND) owned by a previously-announced
/// application. Duplicate `wnd_id` values replace the existing record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OdWndCreated {
    /// `Flags` (u16). Bit 0 is
    /// [`crate::constants::flags::WINDOW_SHARED`].
    pub flags: u16,
    /// Identifier of the owning application (from a prior
    /// [`super::OdAppCreated`]).
    pub app_id: u32,
    /// Unique window identifier (Windows: HWND, Appendix A <3>).
    pub wnd_id: u32,
    /// Window title. May be empty.
    pub name: UnicodeString,
}

const CREATED_CTX: &str = "OD_WND_CREATED";

impl OdWndCreated {
    pub fn size(&self) -> usize {
        WND_CREATED_FIXED_SIZE as usize + self.name.size()
    }

    fn total_length(&self) -> EncodeResult<u16> {
        let total = self.size();
        if total > u16::MAX as usize {
            return Err(EncodeError::invalid_value(CREATED_CTX, "length overflow"));
        }
        Ok(total as u16)
    }
}

impl Encode for OdWndCreated {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let length = self.total_length()?;
        OrderHeader::new(odtype::WND_CREATED, length).encode(dst)?;
        dst.write_u16_le(self.flags, CREATED_CTX)?;
        dst.write_u32_le(self.app_id, CREATED_CTX)?;
        dst.write_u32_le(self.wnd_id, CREATED_CTX)?;
        self.name.encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        CREATED_CTX
    }

    fn size(&self) -> usize {
        OdWndCreated::size(self)
    }
}

impl<'de> Decode<'de> for OdWndCreated {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        if hdr.type_ != odtype::WND_CREATED {
            return Err(DecodeError::invalid_value(CREATED_CTX, "type"));
        }
        if hdr.length < WND_CREATED_FIXED_SIZE {
            return Err(DecodeError::invalid_value(CREATED_CTX, "length"));
        }
        let flags = src.read_u16_le(CREATED_CTX)?;
        let app_id = src.read_u32_le(CREATED_CTX)?;
        let wnd_id = src.read_u32_le(CREATED_CTX)?;
        let name = UnicodeString::decode(src)?;
        let expected = WND_CREATED_FIXED_SIZE as usize + name.size();
        if expected != hdr.length as usize {
            return Err(DecodeError::invalid_value(CREATED_CTX, "length mismatch"));
        }
        Ok(Self {
            flags,
            app_id,
            wnd_id,
            name,
        })
    }
}

// ── OD_WND_REMOVED (§2.2.3.5) ─────────────────────────────────────────

/// `OD_WND_REMOVED` (MS-RDPEMC §2.2.3.5). Direction: SM → P.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OdWndRemoved {
    pub wnd_id: u32,
}

const REMOVED_CTX: &str = "OD_WND_REMOVED";

impl OdWndRemoved {
    pub fn size(&self) -> usize {
        WND_REMOVED_SIZE as usize
    }
}

impl Encode for OdWndRemoved {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        OrderHeader::new(odtype::WND_REMOVED, WND_REMOVED_SIZE).encode(dst)?;
        dst.write_u32_le(self.wnd_id, REMOVED_CTX)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        REMOVED_CTX
    }

    fn size(&self) -> usize {
        WND_REMOVED_SIZE as usize
    }
}

impl<'de> Decode<'de> for OdWndRemoved {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        hdr.expect(odtype::WND_REMOVED, WND_REMOVED_SIZE)?;
        let wnd_id = src.read_u32_le(REMOVED_CTX)?;
        Ok(Self { wnd_id })
    }
}

// ── OD_WND_SHOW (§2.2.3.6) ────────────────────────────────────────────

/// `OD_WND_SHOW` (MS-RDPEMC §2.2.3.6). Direction: P → SM.
///
/// Participant requests that the sharing manager un-minimize/foreground
/// the named window. Only acted on if the participant has
/// `MAY_INTERACT` permission (Appendix A <27>).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OdWndShow {
    pub wnd_id: u32,
}

const SHOW_CTX: &str = "OD_WND_SHOW";

impl OdWndShow {
    pub fn size(&self) -> usize {
        WND_SHOW_SIZE as usize
    }
}

impl Encode for OdWndShow {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        OrderHeader::new(odtype::WND_SHOW, WND_SHOW_SIZE).encode(dst)?;
        dst.write_u32_le(self.wnd_id, SHOW_CTX)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        SHOW_CTX
    }

    fn size(&self) -> usize {
        WND_SHOW_SIZE as usize
    }
}

impl<'de> Decode<'de> for OdWndShow {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        hdr.expect(odtype::WND_SHOW, WND_SHOW_SIZE)?;
        let wnd_id = src.read_u32_le(SHOW_CTX)?;
        Ok(Self { wnd_id })
    }
}

// ── OD_WND_REGION_UPDATE (§2.2.3.7) ───────────────────────────────────

/// `OD_WND_REGION_UPDATE` (MS-RDPEMC §2.2.3.7). Direction: SM → P.
///
/// Bounding rectangle advisory. Windows sharing managers never send
/// this PDU (Appendix A <5>), but the receiver MUST parse it if
/// encountered. NOTE: the wire form has no `wnd_id` field, so the
/// rectangle is not bound to a specific window — this is a spec gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OdWndRegionUpdate {
    pub left: u32,
    pub top: u32,
    pub right: u32,
    pub bottom: u32,
}

const RGN_CTX: &str = "OD_WND_REGION_UPDATE";

impl OdWndRegionUpdate {
    pub fn size(&self) -> usize {
        WND_REGION_UPDATE_SIZE as usize
    }
}

impl Encode for OdWndRegionUpdate {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        OrderHeader::new(odtype::WND_RGN_UPDATE, WND_REGION_UPDATE_SIZE).encode(dst)?;
        dst.write_u32_le(self.left, RGN_CTX)?;
        dst.write_u32_le(self.top, RGN_CTX)?;
        dst.write_u32_le(self.right, RGN_CTX)?;
        dst.write_u32_le(self.bottom, RGN_CTX)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        RGN_CTX
    }

    fn size(&self) -> usize {
        WND_REGION_UPDATE_SIZE as usize
    }
}

impl<'de> Decode<'de> for OdWndRegionUpdate {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        hdr.expect(odtype::WND_RGN_UPDATE, WND_REGION_UPDATE_SIZE)?;
        let left = src.read_u32_le(RGN_CTX)?;
        let top = src.read_u32_le(RGN_CTX)?;
        let right = src.read_u32_le(RGN_CTX)?;
        let bottom = src.read_u32_le(RGN_CTX)?;
        Ok(Self {
            left,
            top,
            right,
            bottom,
        })
    }
}
