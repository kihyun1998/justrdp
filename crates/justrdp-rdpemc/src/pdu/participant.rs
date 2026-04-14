//! Participant-related PDUs: `OD_PARTICIPANT_CREATED` (§2.2.4.1),
//! `OD_PARTICIPANT_REMOVED` (§2.2.4.2), `OD_PARTICIPANT_CTRL_CHANGE`
//! (§2.2.4.3), `OD_PARTICIPANT_CTRL_CHANGE_RESPONSE` (§2.2.4.4).

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use super::header::{OrderHeader, UnicodeString};
use crate::constants::odtype;

/// Fixed portion of [`OdParticipantCreated`] in bytes (header, IDs,
/// flags — everything before the trailing [`UnicodeString`]).
pub const PARTICIPANT_CREATED_FIXED_SIZE: u16 = 14;
/// Total wire size of [`OdParticipantRemoved`] in bytes.
pub const PARTICIPANT_REMOVED_SIZE: u16 = 16;
/// Total wire size of [`OdParticipantCtrlChange`] in bytes.
pub const PARTICIPANT_CTRL_CHANGE_SIZE: u16 = 10;
/// Total wire size of [`OdParticipantCtrlChangeResponse`] in bytes.
pub const PARTICIPANT_CTRL_CHANGE_RESPONSE_SIZE: u16 = 14;

// ── OD_PARTICIPANT_CREATED (§2.2.4.1) ─────────────────────────────────

/// `OD_PARTICIPANT_CREATED` (MS-RDPEMC §2.2.4.1). Direction: SM → P
/// (Windows participants never send this PDU, Appendix A <28>).
///
/// Dual purpose: announces a new participant, AND — when sent with an
/// existing `participant_id` — reflects an updated permission bitmask
/// after a successful control-level change (§3.2.5.2.1). When
/// [`IS_PARTICIPANT`] is set in `flags`, the PDU is unicast to the
/// described participant so they learn their own identity.
///
/// [`IS_PARTICIPANT`]: crate::constants::flags::IS_PARTICIPANT
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OdParticipantCreated {
    /// Unique identifier assigned to this participant by the sharing
    /// manager.
    pub participant_id: u32,
    /// `GroupId` — group membership. Windows always sets this to 0
    /// (Appendix A <6>).
    pub group_id: u32,
    /// Permission bitmask. See [`crate::constants::flags`]
    /// (`MAY_VIEW`, `MAY_INTERACT`, `IS_PARTICIPANT`).
    pub flags: u16,
    /// Display name of the participant.
    pub friendly_name: UnicodeString,
}

const CREATED_CTX: &str = "OD_PARTICIPANT_CREATED";

impl OdParticipantCreated {
    pub fn size(&self) -> usize {
        PARTICIPANT_CREATED_FIXED_SIZE as usize + self.friendly_name.size()
    }

    fn total_length(&self) -> EncodeResult<u16> {
        let total = self.size();
        if total > u16::MAX as usize {
            return Err(EncodeError::invalid_value(CREATED_CTX, "length overflow"));
        }
        Ok(total as u16)
    }
}

impl Encode for OdParticipantCreated {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let length = self.total_length()?;
        OrderHeader::new(odtype::PARTICIPANT_CREATED, length).encode(dst)?;
        dst.write_u32_le(self.participant_id, CREATED_CTX)?;
        dst.write_u32_le(self.group_id, CREATED_CTX)?;
        dst.write_u16_le(self.flags, CREATED_CTX)?;
        self.friendly_name.encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        CREATED_CTX
    }

    fn size(&self) -> usize {
        OdParticipantCreated::size(self)
    }
}

impl<'de> Decode<'de> for OdParticipantCreated {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        if hdr.type_ != odtype::PARTICIPANT_CREATED {
            return Err(DecodeError::invalid_value(CREATED_CTX, "type"));
        }
        if hdr.length < PARTICIPANT_CREATED_FIXED_SIZE {
            return Err(DecodeError::invalid_value(CREATED_CTX, "length"));
        }
        let participant_id = src.read_u32_le(CREATED_CTX)?;
        let group_id = src.read_u32_le(CREATED_CTX)?;
        let flags = src.read_u16_le(CREATED_CTX)?;
        let friendly_name = UnicodeString::decode(src)?;
        let expected = PARTICIPANT_CREATED_FIXED_SIZE as usize + friendly_name.size();
        if expected != hdr.length as usize {
            return Err(DecodeError::invalid_value(CREATED_CTX, "length mismatch"));
        }
        Ok(Self {
            participant_id,
            group_id,
            flags,
            friendly_name,
        })
    }
}

// ── OD_PARTICIPANT_REMOVED (§2.2.4.2) ─────────────────────────────────

/// `OD_PARTICIPANT_REMOVED` (MS-RDPEMC §2.2.4.2). Direction: SM → P.
///
/// Windows receivers do not parse `disc_type` or `disc_code`
/// (Appendix A <21>); the fields are exposed verbatim as informational.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OdParticipantRemoved {
    pub participant_id: u32,
    /// `DiscType` (§2.2.4.2). See
    /// [`crate::constants::participant_disconnect_reason`].
    pub disc_type: u32,
    /// `DiscCode` — HRESULT/Win32 error code.
    pub disc_code: u32,
}

const REMOVED_CTX: &str = "OD_PARTICIPANT_REMOVED";

impl OdParticipantRemoved {
    pub fn size(&self) -> usize {
        PARTICIPANT_REMOVED_SIZE as usize
    }
}

impl Encode for OdParticipantRemoved {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        OrderHeader::new(odtype::PARTICIPANT_REMOVED, PARTICIPANT_REMOVED_SIZE).encode(dst)?;
        dst.write_u32_le(self.participant_id, REMOVED_CTX)?;
        dst.write_u32_le(self.disc_type, REMOVED_CTX)?;
        dst.write_u32_le(self.disc_code, REMOVED_CTX)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        REMOVED_CTX
    }

    fn size(&self) -> usize {
        PARTICIPANT_REMOVED_SIZE as usize
    }
}

impl<'de> Decode<'de> for OdParticipantRemoved {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        hdr.expect(odtype::PARTICIPANT_REMOVED, PARTICIPANT_REMOVED_SIZE)?;
        let participant_id = src.read_u32_le(REMOVED_CTX)?;
        let disc_type = src.read_u32_le(REMOVED_CTX)?;
        let disc_code = src.read_u32_le(REMOVED_CTX)?;
        Ok(Self {
            participant_id,
            disc_type,
            disc_code,
        })
    }
}

// ── OD_PARTICIPANT_CTRL_CHANGE (§2.2.4.3) ─────────────────────────────

/// `OD_PARTICIPANT_CTRL_CHANGE` (MS-RDPEMC §2.2.4.3). Direction: P → SM.
///
/// Wire layout: `Flags` (u16) comes BEFORE `ParticipantId` (u32), per
/// spec §2.2.4.3. Note that the spec's `ALLOW_CONTROL_REQUESTS` flag is
/// never sent or interpreted by Windows (Appendix A <30>) — it is
/// defined here only for round-trip fidelity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OdParticipantCtrlChange {
    /// Requested permission bitmask. See [`crate::constants::flags`]
    /// (`REQUEST_VIEW`, `REQUEST_INTERACT`, `ALLOW_CONTROL_REQUESTS`).
    pub flags: u16,
    pub participant_id: u32,
}

const CHG_CTX: &str = "OD_PARTICIPANT_CTRL_CHANGE";

impl OdParticipantCtrlChange {
    pub fn size(&self) -> usize {
        PARTICIPANT_CTRL_CHANGE_SIZE as usize
    }
}

impl Encode for OdParticipantCtrlChange {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        OrderHeader::new(odtype::PARTICIPANT_CTRL_CHANGED, PARTICIPANT_CTRL_CHANGE_SIZE)
            .encode(dst)?;
        dst.write_u16_le(self.flags, CHG_CTX)?;
        dst.write_u32_le(self.participant_id, CHG_CTX)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        CHG_CTX
    }

    fn size(&self) -> usize {
        PARTICIPANT_CTRL_CHANGE_SIZE as usize
    }
}

impl<'de> Decode<'de> for OdParticipantCtrlChange {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        hdr.expect(odtype::PARTICIPANT_CTRL_CHANGED, PARTICIPANT_CTRL_CHANGE_SIZE)?;
        let flags = src.read_u16_le(CHG_CTX)?;
        let participant_id = src.read_u32_le(CHG_CTX)?;
        Ok(Self {
            flags,
            participant_id,
        })
    }
}

// ── OD_PARTICIPANT_CTRL_CHANGE_RESPONSE (§2.2.4.4) ────────────────────

/// `OD_PARTICIPANT_CTRL_CHANGE_RESPONSE` (MS-RDPEMC §2.2.4.4).
/// Direction: SM → P.
///
/// The spec defines `reason_code` as a u32 but does NOT enumerate its
/// valid values (§2.2.4.4). Convention: `0` = accepted (`S_OK`),
/// non-zero = rejected with an opaque reason. On acceptance the sharing
/// manager MUST also broadcast an updated [`OdParticipantCreated`] to
/// all participants (§3.3.5.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OdParticipantCtrlChangeResponse {
    /// Echoes the `flags` from the original request.
    pub flags: u16,
    pub participant_id: u32,
    pub reason_code: u32,
}

const RESP_CTX: &str = "OD_PARTICIPANT_CTRL_CHANGE_RESPONSE";

impl OdParticipantCtrlChangeResponse {
    pub fn size(&self) -> usize {
        PARTICIPANT_CTRL_CHANGE_RESPONSE_SIZE as usize
    }
}

impl Encode for OdParticipantCtrlChangeResponse {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        OrderHeader::new(
            odtype::PARTICIPANT_CTRL_CHANGE_RESPONSE,
            PARTICIPANT_CTRL_CHANGE_RESPONSE_SIZE,
        )
        .encode(dst)?;
        dst.write_u16_le(self.flags, RESP_CTX)?;
        dst.write_u32_le(self.participant_id, RESP_CTX)?;
        dst.write_u32_le(self.reason_code, RESP_CTX)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        RESP_CTX
    }

    fn size(&self) -> usize {
        PARTICIPANT_CTRL_CHANGE_RESPONSE_SIZE as usize
    }
}

impl<'de> Decode<'de> for OdParticipantCtrlChangeResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let hdr = OrderHeader::decode(src)?;
        hdr.expect(
            odtype::PARTICIPANT_CTRL_CHANGE_RESPONSE,
            PARTICIPANT_CTRL_CHANGE_RESPONSE_SIZE,
        )?;
        let flags = src.read_u16_le(RESP_CTX)?;
        let participant_id = src.read_u32_le(RESP_CTX)?;
        let reason_code = src.read_u32_le(RESP_CTX)?;
        Ok(Self {
            flags,
            participant_id,
            reason_code,
        })
    }
}
