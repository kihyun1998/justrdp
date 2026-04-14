//! Wire-format PDU structs for MS-RDPEDC §2.2.
//!
//! All 7 PDUs are **fixed size** and all travel server → client. Every
//! PDU starts with the 4-byte [`CommonHeader`]:
//!
//! ```text
//!   1B  header    = 0x32
//!   1B  operation = op code
//!   2B  size  LE  = total PDU size − 4
//! ```

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{operation as op, ALT_SEC_HEADER_BYTE, CACHE_ID_DESTROY_BIT};

/// Wire size of the common 4-byte header that prefixes every MS-RDPEDC PDU.
pub const COMMON_HEADER_SIZE: usize = 4;

// ── Common header helpers ────────────────────────────────────────────

fn write_common_header(
    dst: &mut WriteCursor<'_>,
    op_code: u8,
    body_size: u16,
    ctx: &'static str,
) -> EncodeResult<()> {
    dst.write_u8(ALT_SEC_HEADER_BYTE, ctx)?;
    dst.write_u8(op_code, ctx)?;
    dst.write_u16_le(body_size, ctx)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommonHeader {
    operation: u8,
    body_size: u16,
}

fn read_common_header(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<CommonHeader> {
    let header = src.read_u8(ctx)?;
    if header != ALT_SEC_HEADER_BYTE {
        return Err(DecodeError::invalid_value(ctx, "header byte"));
    }
    let operation = src.read_u8(ctx)?;
    let body_size = src.read_u16_le(ctx)?;
    Ok(CommonHeader {
        operation,
        body_size,
    })
}

fn expect_body_size(
    got: u16,
    expected: u16,
    ctx: &'static str,
) -> DecodeResult<()> {
    if got != expected {
        return Err(DecodeError::invalid_value(ctx, "size"));
    }
    Ok(())
}

/// Reject any `cache_id` with bit 31 set. Centralised because three
/// PDUs (`SurfObj`, `SwitchSurfObj`, `FlushComposeOnce`) share the
/// same invariant.
fn check_cache_id_no_bit31(cache_id: u32, ctx: &'static str) -> EncodeResult<()> {
    if cache_id & CACHE_ID_DESTROY_BIT != 0 {
        return Err(EncodeError::invalid_value(ctx, "cache_id bit 31"));
    }
    Ok(())
}

// ── TS_COMPDESK_TOGGLE (§2.2.1.1) ────────────────────────────────────

/// `TS_COMPDESK_TOGGLE.eventType` values, spec §2.2.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    CompositionOff = 0x00,
    Reserved00 = 0x01,
    Reserved01 = 0x02,
    CompositionOn = 0x03,
    DwmDeskEnter = 0x04,
    DwmDeskLeave = 0x05,
}

impl EventType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x00 => Self::CompositionOff,
            0x01 => Self::Reserved00,
            0x02 => Self::Reserved01,
            0x03 => Self::CompositionOn,
            0x04 => Self::DwmDeskEnter,
            0x05 => Self::DwmDeskLeave,
            _ => return None,
        })
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// `TS_COMPDESK_TOGGLE` — 5-byte PDU; signals desktop composition
/// mode changes (MS-RDPEDC §2.2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompDeskToggle {
    pub event_type: EventType,
}

impl CompDeskToggle {
    pub const BODY_SIZE: u16 = 1;
    pub const WIRE_SIZE: usize = COMMON_HEADER_SIZE + Self::BODY_SIZE as usize;
}

impl Encode for CompDeskToggle {
    fn name(&self) -> &'static str {
        "MS-RDPEDC::CompDeskToggle"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_common_header(dst, op::COMPDESKTOGGLE, Self::BODY_SIZE, self.name())?;
        dst.write_u8(self.event_type.as_u8(), self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for CompDeskToggle {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEDC::CompDeskToggle";
        let hdr = read_common_header(src, CTX)?;
        if hdr.operation != op::COMPDESKTOGGLE {
            return Err(DecodeError::invalid_value(CTX, "operation"));
        }
        expect_body_size(hdr.body_size, Self::BODY_SIZE, CTX)?;
        let event_type_raw = src.read_u8(CTX)?;
        let event_type = EventType::from_u8(event_type_raw)
            .ok_or_else(|| DecodeError::invalid_value(CTX, "eventType"))?;
        Ok(Self { event_type })
    }
}

// ── TS_COMPDESK_LSURFACE (§2.2.2.1) ──────────────────────────────────

/// Validated `flags` field for `TS_COMPDESK_LSURFACE`; only the two
/// defined bits are exposed (`TS_COMPDESK_HLSURF_COMPOSEONCE = 0x01`,
/// `TS_COMPDESK_HLSURF_REDIRECTION = 0x04`). Undefined bits are
/// masked off on decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LSurfaceFlags(pub u8);

impl LSurfaceFlags {
    pub const COMPOSEONCE: Self = Self(crate::constants::lsurface_flags::TS_COMPDESK_HLSURF_COMPOSEONCE);
    pub const REDIRECTION: Self = Self(crate::constants::lsurface_flags::TS_COMPDESK_HLSURF_REDIRECTION);

    pub fn is_compose_once(self) -> bool {
        self.0 & crate::constants::lsurface_flags::TS_COMPDESK_HLSURF_COMPOSEONCE != 0
    }

    pub fn is_redirection(self) -> bool {
        self.0 & crate::constants::lsurface_flags::TS_COMPDESK_HLSURF_REDIRECTION != 0
    }
}

/// `TS_COMPDESK_LSURFACE` — 38-byte PDU; create or destroy a logical
/// surface (MS-RDPEDC §2.2.2.1).
///
/// Per spec, `width`, `height`, and `luid` MUST all be zero and MUST
/// be ignored on decode, so we don't expose them on the struct. We
/// still write zeros for them on encode so the bytes on the wire match
/// the spec exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LSurfaceCreateDestroy {
    /// `true` = create, `false` = destroy.
    pub create: bool,
    /// Only meaningful when `create == true`; ignored by the spec when
    /// destroying. Decode masks off undefined bits.
    pub flags: LSurfaceFlags,
    pub h_lsurface: u64,
    pub hwnd: u64,
}

impl LSurfaceCreateDestroy {
    pub const BODY_SIZE: u16 = 34;
    pub const WIRE_SIZE: usize = COMMON_HEADER_SIZE + Self::BODY_SIZE as usize;
}

impl Encode for LSurfaceCreateDestroy {
    fn name(&self) -> &'static str {
        "MS-RDPEDC::LSurfaceCreateDestroy"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_common_header(dst, op::LSURFACE_CREATE_DESTROY, Self::BODY_SIZE, self.name())?;
        dst.write_u8(if self.create { 0x01 } else { 0x00 }, self.name())?;
        // `flags` is only meaningful when `create`; when destroying we
        // still emit 0 (spec says the field is ignored in that case).
        let flags_on_wire = if self.create { self.flags.0 } else { 0 };
        dst.write_u8(flags_on_wire, self.name())?;
        dst.write_u64_le(self.h_lsurface, self.name())?;
        dst.write_u32_le(0, self.name())?; // width  MUST be 0
        dst.write_u32_le(0, self.name())?; // height MUST be 0
        dst.write_u64_le(self.hwnd, self.name())?;
        dst.write_u64_le(0, self.name())?; // luid   MUST be 0
        Ok(())
    }
}

impl<'de> Decode<'de> for LSurfaceCreateDestroy {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEDC::LSurfaceCreateDestroy";
        let hdr = read_common_header(src, CTX)?;
        if hdr.operation != op::LSURFACE_CREATE_DESTROY {
            return Err(DecodeError::invalid_value(CTX, "operation"));
        }
        expect_body_size(hdr.body_size, Self::BODY_SIZE, CTX)?;
        let f_create = src.read_u8(CTX)?;
        let create = match f_create {
            0x00 => false,
            0x01 => true,
            _ => return Err(DecodeError::invalid_value(CTX, "fCreate")),
        };
        let raw_flags = src.read_u8(CTX)?;
        // Mask to known bits; undefined bits are SHOULD-be-zero per spec.
        let flags = if create {
            LSurfaceFlags(raw_flags & crate::constants::lsurface_flags::DEFINED_MASK)
        } else {
            // Field is explicitly ignored on destroy.
            LSurfaceFlags(0)
        };
        let h_lsurface = src.read_u64_le(CTX)?;
        let _width = src.read_u32_le(CTX)?; // ignored
        let _height = src.read_u32_le(CTX)?; // ignored
        let hwnd = src.read_u64_le(CTX)?;
        let _luid = src.read_u64_le(CTX)?; // ignored
        Ok(Self {
            create,
            flags,
            h_lsurface,
            hwnd,
        })
    }
}

// ── TS_COMPDESK_SURFOBJ (§2.2.2.2) ───────────────────────────────────

/// `TS_COMPDESK_SURFOBJ` — 26-byte PDU; create or destroy a
/// redirection surface (MS-RDPEDC §2.2.2.2).
///
/// The create/destroy discriminator is bit 31 of `cache_id` on the
/// wire; we expose it as a separate `create` bool and keep the id in
/// the lower 31 bits to prevent accidental collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfObjCreateDestroy {
    /// `true` = create, `false` = destroy.
    pub create: bool,
    /// 31-bit surface identifier (upper bit of the wire field is the
    /// discriminator and is NOT included here).
    pub cache_id: u32,
    pub surface_bpp: u8,
    pub h_surf: u64,
    pub cx: u32,
    pub cy: u32,
}

impl SurfObjCreateDestroy {
    pub const BODY_SIZE: u16 = 22;
    pub const WIRE_SIZE: usize = COMMON_HEADER_SIZE + Self::BODY_SIZE as usize;
    pub const MAX_CACHE_ID: u32 = crate::constants::CACHE_ID_ID_MASK;
}

impl Encode for SurfObjCreateDestroy {
    fn name(&self) -> &'static str {
        "MS-RDPEDC::SurfObjCreateDestroy"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        check_cache_id_no_bit31(self.cache_id, self.name())?;
        write_common_header(dst, op::SURFOBJ_CREATE_DESTROY, Self::BODY_SIZE, self.name())?;
        let wire_id = if self.create {
            self.cache_id
        } else {
            self.cache_id | CACHE_ID_DESTROY_BIT
        };
        dst.write_u32_le(wire_id, self.name())?;
        dst.write_u8(self.surface_bpp, self.name())?;
        dst.write_u8(0, self.name())?; // flags  MUST be 0
        dst.write_u64_le(self.h_surf, self.name())?;
        dst.write_u32_le(self.cx, self.name())?;
        dst.write_u32_le(self.cy, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for SurfObjCreateDestroy {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEDC::SurfObjCreateDestroy";
        let hdr = read_common_header(src, CTX)?;
        if hdr.operation != op::SURFOBJ_CREATE_DESTROY {
            return Err(DecodeError::invalid_value(CTX, "operation"));
        }
        expect_body_size(hdr.body_size, Self::BODY_SIZE, CTX)?;
        let wire_id = src.read_u32_le(CTX)?;
        let create = (wire_id & crate::constants::CACHE_ID_DESTROY_BIT) == 0;
        let cache_id = wire_id & crate::constants::CACHE_ID_ID_MASK;
        let surface_bpp = src.read_u8(CTX)?;
        let _flags = src.read_u8(CTX)?; // MUST be ignored
        let h_surf = src.read_u64_le(CTX)?;
        let cx = src.read_u32_le(CTX)?;
        let cy = src.read_u32_le(CTX)?;
        Ok(Self {
            create,
            cache_id,
            surface_bpp,
            h_surf,
            cx,
            cy,
        })
    }
}

// ── TS_COMPDESK_REDIRSURF_ASSOC_LSURFACE (§2.2.2.3) ──────────────────

/// `TS_COMPDESK_REDIRSURF_ASSOC_LSURFACE` — 21-byte PDU; associate or
/// disassociate a redirection surface with a logical surface
/// (MS-RDPEDC §2.2.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirSurfAssocLSurface {
    /// `true` = associate, `false` = disassociate.
    pub associate: bool,
    pub h_lsurface: u64,
    pub h_surf: u64,
}

impl RedirSurfAssocLSurface {
    pub const BODY_SIZE: u16 = 17;
    pub const WIRE_SIZE: usize = COMMON_HEADER_SIZE + Self::BODY_SIZE as usize;
}

impl Encode for RedirSurfAssocLSurface {
    fn name(&self) -> &'static str {
        "MS-RDPEDC::RedirSurfAssocLSurface"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_common_header(
            dst,
            op::REDIRSURF_ASSOC_DEASSOC_LSURFACE,
            Self::BODY_SIZE,
            self.name(),
        )?;
        dst.write_u8(if self.associate { 0x01 } else { 0x00 }, self.name())?;
        dst.write_u64_le(self.h_lsurface, self.name())?;
        dst.write_u64_le(self.h_surf, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for RedirSurfAssocLSurface {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEDC::RedirSurfAssocLSurface";
        let hdr = read_common_header(src, CTX)?;
        if hdr.operation != op::REDIRSURF_ASSOC_DEASSOC_LSURFACE {
            return Err(DecodeError::invalid_value(CTX, "operation"));
        }
        expect_body_size(hdr.body_size, Self::BODY_SIZE, CTX)?;
        let f_associate = src.read_u8(CTX)?;
        let associate = match f_associate {
            0x00 => false,
            0x01 => true,
            _ => return Err(DecodeError::invalid_value(CTX, "fAssociate")),
        };
        let h_lsurface = src.read_u64_le(CTX)?;
        let h_surf = src.read_u64_le(CTX)?;
        Ok(Self {
            associate,
            h_lsurface,
            h_surf,
        })
    }
}

// ── TS_COMPDESK_LSURFACE_COMPREF_PENDING (§2.2.2.4) ──────────────────

/// `TS_COMPDESK_LSURFACE_COMPREF_PENDING` — 12-byte PDU; compositor
/// has a pending reference to a logical surface (MS-RDPEDC §2.2.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LSurfaceCompRefPending {
    pub h_lsurface: u64,
}

impl LSurfaceCompRefPending {
    pub const BODY_SIZE: u16 = 8;
    pub const WIRE_SIZE: usize = COMMON_HEADER_SIZE + Self::BODY_SIZE as usize;
}

impl Encode for LSurfaceCompRefPending {
    fn name(&self) -> &'static str {
        "MS-RDPEDC::LSurfaceCompRefPending"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_common_header(dst, op::LSURFACE_COMPREF_PENDING, Self::BODY_SIZE, self.name())?;
        dst.write_u64_le(self.h_lsurface, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for LSurfaceCompRefPending {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEDC::LSurfaceCompRefPending";
        let hdr = read_common_header(src, CTX)?;
        if hdr.operation != op::LSURFACE_COMPREF_PENDING {
            return Err(DecodeError::invalid_value(CTX, "operation"));
        }
        expect_body_size(hdr.body_size, Self::BODY_SIZE, CTX)?;
        let h_lsurface = src.read_u64_le(CTX)?;
        Ok(Self { h_lsurface })
    }
}

// ── TS_COMPDESK_SWITCH_SURFOBJ (§2.2.3.1) ────────────────────────────

/// `TS_COMPDESK_SWITCH_SURFOBJ` — 8-byte PDU; retargets subsequent
/// drawing operations at a specific redirection surface
/// (MS-RDPEDC §2.2.3.1).
///
/// Per spec, bit 31 of the `cacheId` field MUST be `0`; we enforce
/// this on both encode and decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchSurfObj {
    pub cache_id: u32,
}

impl SwitchSurfObj {
    pub const BODY_SIZE: u16 = 4;
    pub const WIRE_SIZE: usize = COMMON_HEADER_SIZE + Self::BODY_SIZE as usize;
}

impl Encode for SwitchSurfObj {
    fn name(&self) -> &'static str {
        "MS-RDPEDC::SwitchSurfObj"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        check_cache_id_no_bit31(self.cache_id, self.name())?;
        write_common_header(dst, op::SURFOBJSWITCH, Self::BODY_SIZE, self.name())?;
        dst.write_u32_le(self.cache_id, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for SwitchSurfObj {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEDC::SwitchSurfObj";
        let hdr = read_common_header(src, CTX)?;
        if hdr.operation != op::SURFOBJSWITCH {
            return Err(DecodeError::invalid_value(CTX, "operation"));
        }
        expect_body_size(hdr.body_size, Self::BODY_SIZE, CTX)?;
        let cache_id = src.read_u32_le(CTX)?;
        if cache_id & crate::constants::CACHE_ID_DESTROY_BIT != 0 {
            return Err(DecodeError::invalid_value(CTX, "cacheId bit 31"));
        }
        Ok(Self { cache_id })
    }
}

// ── TS_COMPDESK_FLUSH_COMPOSEONCE (§2.2.3.2) ─────────────────────────

/// `TS_COMPDESK_FLUSH_COMPOSEONCE` — 16-byte PDU; signals completion
/// of a drawing pass on a compose-once surface (MS-RDPEDC §2.2.3.2).
///
/// Per spec, bit 31 of the `cacheId` field MUST be ignored on receive;
/// we strip it on decode so callers always see the 31-bit id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushComposeOnce {
    pub cache_id: u32,
    pub h_lsurface: u64,
}

impl FlushComposeOnce {
    pub const BODY_SIZE: u16 = 12;
    pub const WIRE_SIZE: usize = COMMON_HEADER_SIZE + Self::BODY_SIZE as usize;
}

impl Encode for FlushComposeOnce {
    fn name(&self) -> &'static str {
        "MS-RDPEDC::FlushComposeOnce"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        check_cache_id_no_bit31(self.cache_id, self.name())?;
        write_common_header(dst, op::FLUSHCOMPOSEONCE, Self::BODY_SIZE, self.name())?;
        dst.write_u32_le(self.cache_id, self.name())?;
        dst.write_u64_le(self.h_lsurface, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for FlushComposeOnce {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEDC::FlushComposeOnce";
        let hdr = read_common_header(src, CTX)?;
        if hdr.operation != op::FLUSHCOMPOSEONCE {
            return Err(DecodeError::invalid_value(CTX, "operation"));
        }
        expect_body_size(hdr.body_size, Self::BODY_SIZE, CTX)?;
        // Spec: bit 31 MUST be ignored, so we mask instead of erroring.
        let cache_id = src.read_u32_le(CTX)? & crate::constants::CACHE_ID_ID_MASK;
        let h_lsurface = src.read_u64_le(CTX)?;
        Ok(Self {
            cache_id,
            h_lsurface,
        })
    }
}

// ── Tagged dispatch helper ───────────────────────────────────────────

/// Tagged union over all 7 MS-RDPEDC PDUs; used by the processor (Step 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompDeskPdu {
    Toggle(CompDeskToggle),
    LSurface(LSurfaceCreateDestroy),
    SurfObj(SurfObjCreateDestroy),
    RedirSurfAssoc(RedirSurfAssocLSurface),
    CompRefPending(LSurfaceCompRefPending),
    Switch(SwitchSurfObj),
    Flush(FlushComposeOnce),
}

/// Peek the 2-byte `header + operation` prefix of an MS-RDPEDC order
/// and dispatch to the matching PDU decoder. On success, advances
/// `src` by exactly the wire size of the decoded PDU.
///
/// Returns `Err` if the header byte is wrong or the operation code
/// is unknown. Forward-compatibility with future op codes is NOT
/// handled here — [`crate::client::RdpedcClient::process_order`] is
/// responsible for skipping unknown orders using `size + 4` bytes.
pub fn decode_any<'de>(src: &mut ReadCursor<'de>) -> DecodeResult<CompDeskPdu> {
    const CTX: &str = "MS-RDPEDC::decode_any";
    // Peek the operation byte without consuming. We know we need at
    // least 4 header bytes to decide anything useful.
    let rest = src.peek_remaining();
    if rest.len() < COMMON_HEADER_SIZE {
        return Err(DecodeError::not_enough_bytes(
            CTX,
            COMMON_HEADER_SIZE,
            rest.len(),
        ));
    }
    if rest[0] != ALT_SEC_HEADER_BYTE {
        return Err(DecodeError::invalid_value(CTX, "header byte"));
    }
    let operation = rest[1];
    Ok(match operation {
        op::COMPDESKTOGGLE => CompDeskPdu::Toggle(CompDeskToggle::decode(src)?),
        op::LSURFACE_CREATE_DESTROY => CompDeskPdu::LSurface(LSurfaceCreateDestroy::decode(src)?),
        op::SURFOBJ_CREATE_DESTROY => CompDeskPdu::SurfObj(SurfObjCreateDestroy::decode(src)?),
        op::REDIRSURF_ASSOC_DEASSOC_LSURFACE => {
            CompDeskPdu::RedirSurfAssoc(RedirSurfAssocLSurface::decode(src)?)
        }
        op::LSURFACE_COMPREF_PENDING => {
            CompDeskPdu::CompRefPending(LSurfaceCompRefPending::decode(src)?)
        }
        op::SURFOBJSWITCH => CompDeskPdu::Switch(SwitchSurfObj::decode(src)?),
        op::FLUSHCOMPOSEONCE => CompDeskPdu::Flush(FlushComposeOnce::decode(src)?),
        _ => return Err(DecodeError::invalid_value(CTX, "unknown operation")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn encode_to_vec<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        assert_eq!(cur.pos(), pdu.size(), "size() mismatch for {}", pdu.name());
        buf
    }

    // ── TS_COMPDESK_TOGGLE ───────────────────────────────────────────

    #[test]
    fn toggle_roundtrip_all_event_types() {
        for &ev in &[
            EventType::CompositionOff,
            EventType::Reserved00,
            EventType::Reserved01,
            EventType::CompositionOn,
            EventType::DwmDeskEnter,
            EventType::DwmDeskLeave,
        ] {
            let pdu = CompDeskToggle { event_type: ev };
            let bytes = encode_to_vec(&pdu);
            assert_eq!(bytes.len(), 5);
            assert_eq!(
                &bytes[..4],
                &[0x32, 0x01, 0x01, 0x00],
                "header prefix for eventType={:?}",
                ev
            );
            assert_eq!(bytes[4], ev.as_u8());
            let mut r = ReadCursor::new(&bytes);
            let back = CompDeskToggle::decode(&mut r).unwrap();
            assert_eq!(back, pdu);
            assert_eq!(r.remaining(), 0);
        }
    }

    #[test]
    fn toggle_decode_rejects_bad_header_byte() {
        let bytes = [0x30, 0x01, 0x01, 0x00, 0x03];
        let mut r = ReadCursor::new(&bytes);
        assert!(CompDeskToggle::decode(&mut r).is_err());
    }

    #[test]
    fn toggle_decode_rejects_bad_operation() {
        let bytes = [0x32, 0x99, 0x01, 0x00, 0x03];
        let mut r = ReadCursor::new(&bytes);
        assert!(CompDeskToggle::decode(&mut r).is_err());
    }

    #[test]
    fn toggle_decode_rejects_unknown_event_type() {
        let bytes = [0x32, 0x01, 0x01, 0x00, 0xFF];
        let mut r = ReadCursor::new(&bytes);
        assert!(CompDeskToggle::decode(&mut r).is_err());
    }

    #[test]
    fn toggle_decode_rejects_wrong_body_size() {
        let bytes = [0x32, 0x01, 0x02, 0x00, 0x03, 0x00];
        let mut r = ReadCursor::new(&bytes);
        assert!(CompDeskToggle::decode(&mut r).is_err());
    }

    // ── TS_COMPDESK_LSURFACE ─────────────────────────────────────────

    #[test]
    fn lsurface_create_roundtrip() {
        let pdu = LSurfaceCreateDestroy {
            create: true,
            flags: LSurfaceFlags::COMPOSEONCE,
            h_lsurface: 0x1122_3344_5566_7788,
            hwnd: 0xDEAD_BEEF_0000_0001,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 38);
        assert_eq!(&bytes[..4], &[0x32, 0x02, 0x22, 0x00]);
        assert_eq!(bytes[4], 0x01); // fCreate
        assert_eq!(bytes[5], 0x01); // flags COMPOSEONCE
        assert_eq!(&bytes[6..14], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(&bytes[14..18], &[0, 0, 0, 0]); // width = 0
        assert_eq!(&bytes[18..22], &[0, 0, 0, 0]); // height = 0
        assert_eq!(&bytes[22..30], &0xDEAD_BEEF_0000_0001u64.to_le_bytes());
        assert_eq!(&bytes[30..38], &[0, 0, 0, 0, 0, 0, 0, 0]); // luid = 0
        let mut r = ReadCursor::new(&bytes);
        let back = LSurfaceCreateDestroy::decode(&mut r).unwrap();
        assert_eq!(back, pdu);
    }

    #[test]
    fn lsurface_destroy_clears_flags_field() {
        // On destroy, `flags` MUST be ignored; we should get a zero
        // `flags` back even if the on-wire bits were set.
        let original = LSurfaceCreateDestroy {
            create: false,
            flags: LSurfaceFlags::REDIRECTION,
            h_lsurface: 7,
            hwnd: 0,
        };
        let bytes = encode_to_vec(&original);
        // On encode we emit 0 for flags when destroying; verify:
        assert_eq!(bytes[5], 0x00);
        let mut r = ReadCursor::new(&bytes);
        let back = LSurfaceCreateDestroy::decode(&mut r).unwrap();
        assert_eq!(back.create, false);
        assert_eq!(back.flags, LSurfaceFlags::default());
    }

    #[test]
    fn lsurface_decode_masks_undefined_flag_bits() {
        let mut bytes = [0u8; 38];
        bytes[..4].copy_from_slice(&[0x32, 0x02, 0x22, 0x00]);
        bytes[4] = 0x01; // fCreate = true
        bytes[5] = 0xFF; // all flag bits set (only 0x01 and 0x04 defined)
        let mut r = ReadCursor::new(&bytes);
        let back = LSurfaceCreateDestroy::decode(&mut r).unwrap();
        assert_eq!(
            back.flags.0,
            0x05,
            "undefined bits should be masked off"
        );
        assert!(back.flags.is_compose_once());
        assert!(back.flags.is_redirection());
    }

    #[test]
    fn lsurface_decode_rejects_bad_fcreate() {
        let mut bytes = [0u8; 38];
        bytes[..4].copy_from_slice(&[0x32, 0x02, 0x22, 0x00]);
        bytes[4] = 0x02; // illegal
        let mut r = ReadCursor::new(&bytes);
        assert!(LSurfaceCreateDestroy::decode(&mut r).is_err());
    }

    // ── TS_COMPDESK_SURFOBJ (spec §4.3.2 hex vector) ─────────────────

    #[test]
    fn surfobj_spec_hex_vector_432() {
        // Spec §4.3.2 Redirection Surfaces Creation Order hex dump.
        let spec_bytes: [u8; 26] = [
            0x32, 0x03, 0x16, 0x00, 0x09, 0x00, 0x00, 0x00, 0x20, 0x00, 0x84, 0x01, 0x05, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        ];
        let mut r = ReadCursor::new(&spec_bytes);
        let pdu = SurfObjCreateDestroy::decode(&mut r).unwrap();
        assert_eq!(pdu.create, true);
        assert_eq!(pdu.cache_id, 9);
        assert_eq!(pdu.surface_bpp, 32);
        assert_eq!(pdu.h_surf, 0x0000_0000_0705_0184);
        assert_eq!(pdu.cx, 64);
        assert_eq!(pdu.cy, 64);
        let round = encode_to_vec(&pdu);
        assert_eq!(round, spec_bytes);
    }

    #[test]
    fn surfobj_destroy_uses_bit31() {
        let pdu = SurfObjCreateDestroy {
            create: false,
            cache_id: 9,
            surface_bpp: 32,
            h_surf: 0,
            cx: 0,
            cy: 0,
        };
        let bytes = encode_to_vec(&pdu);
        let wire_id = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(wire_id, 0x8000_0009);
        let mut r = ReadCursor::new(&bytes);
        let back = SurfObjCreateDestroy::decode(&mut r).unwrap();
        assert_eq!(back, pdu);
    }

    #[test]
    fn surfobj_encode_rejects_cache_id_with_bit31_set() {
        let pdu = SurfObjCreateDestroy {
            create: true,
            cache_id: 0x8000_0000,
            surface_bpp: 32,
            h_surf: 0,
            cx: 0,
            cy: 0,
        };
        let mut buf = [0u8; 26];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(pdu.encode(&mut cur).is_err());
    }

    #[test]
    fn surfobj_decode_ignores_flags_byte() {
        let mut bytes: [u8; 26] = [
            0x32, 0x03, 0x16, 0x00, 0x09, 0x00, 0x00, 0x00, 0x20, 0x00, 0x84, 0x01, 0x05, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        ];
        bytes[9] = 0xFF; // `flags` field — spec says "MUST be ignored"
        let mut r = ReadCursor::new(&bytes);
        assert!(SurfObjCreateDestroy::decode(&mut r).is_ok());
    }

    // ── TS_COMPDESK_REDIRSURF_ASSOC_LSURFACE ─────────────────────────

    #[test]
    fn redirsurf_assoc_associate_roundtrip() {
        let pdu = RedirSurfAssocLSurface {
            associate: true,
            h_lsurface: 0xAAAA_BBBB_CCCC_DDDD,
            h_surf: 0x1111_2222_3333_4444,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 21);
        assert_eq!(&bytes[..4], &[0x32, 0x04, 0x11, 0x00]);
        assert_eq!(bytes[4], 0x01);
        let mut r = ReadCursor::new(&bytes);
        let back = RedirSurfAssocLSurface::decode(&mut r).unwrap();
        assert_eq!(back, pdu);
    }

    #[test]
    fn redirsurf_assoc_disassociate_roundtrip() {
        let pdu = RedirSurfAssocLSurface {
            associate: false,
            h_lsurface: 1,
            h_surf: 2,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes[4], 0x00);
        let mut r = ReadCursor::new(&bytes);
        let back = RedirSurfAssocLSurface::decode(&mut r).unwrap();
        assert_eq!(back, pdu);
    }

    // ── TS_COMPDESK_LSURFACE_COMPREF_PENDING ─────────────────────────

    #[test]
    fn compref_pending_roundtrip() {
        let pdu = LSurfaceCompRefPending {
            h_lsurface: 0xFEED_FACE_CAFE_BABE,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[..4], &[0x32, 0x05, 0x08, 0x00]);
        assert_eq!(&bytes[4..12], &0xFEED_FACE_CAFE_BABEu64.to_le_bytes());
        let mut r = ReadCursor::new(&bytes);
        let back = LSurfaceCompRefPending::decode(&mut r).unwrap();
        assert_eq!(back, pdu);
    }

    // ── TS_COMPDESK_SWITCH_SURFOBJ (spec §4.2.1 hex vector) ──────────

    #[test]
    fn switch_surfobj_spec_hex_vector_421() {
        // Spec §4.2.1 Retargeting Drawing Order hex dump.
        let spec_bytes: [u8; 8] = [0x32, 0x06, 0x04, 0x00, 0x8F, 0x00, 0x00, 0x00];
        let mut r = ReadCursor::new(&spec_bytes);
        let pdu = SwitchSurfObj::decode(&mut r).unwrap();
        assert_eq!(pdu.cache_id, 0x8F);
        let round = encode_to_vec(&pdu);
        assert_eq!(round, spec_bytes);
    }

    #[test]
    fn switch_surfobj_decode_rejects_bit31_set() {
        let bytes: [u8; 8] = [0x32, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x80];
        let mut r = ReadCursor::new(&bytes);
        assert!(SwitchSurfObj::decode(&mut r).is_err());
    }

    #[test]
    fn switch_surfobj_encode_rejects_bit31_set() {
        let pdu = SwitchSurfObj {
            cache_id: 0x8000_0001,
        };
        let mut buf = [0u8; 8];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(pdu.encode(&mut cur).is_err());
    }

    // ── TS_COMPDESK_FLUSH_COMPOSEONCE ────────────────────────────────

    #[test]
    fn flush_compose_once_roundtrip() {
        let pdu = FlushComposeOnce {
            cache_id: 0x1234_5678,
            h_lsurface: 0xAAAA_BBBB_CCCC_DDDD,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 16);
        assert_eq!(&bytes[..4], &[0x32, 0x07, 0x0C, 0x00]);
        assert_eq!(&bytes[4..8], &0x1234_5678u32.to_le_bytes());
        assert_eq!(&bytes[8..16], &0xAAAA_BBBB_CCCC_DDDDu64.to_le_bytes());
        let mut r = ReadCursor::new(&bytes);
        let back = FlushComposeOnce::decode(&mut r).unwrap();
        assert_eq!(back, pdu);
    }

    #[test]
    fn flush_compose_once_decode_ignores_bit31() {
        // Per spec §2.2.3.2, bit 31 of cacheId MUST be ignored on decode.
        let bytes: [u8; 16] = [
            0x32, 0x07, 0x0C, 0x00, 0x78, 0x56, 0x34, 0x92, // cache_id with bit31 set
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut r = ReadCursor::new(&bytes);
        let pdu = FlushComposeOnce::decode(&mut r).unwrap();
        assert_eq!(pdu.cache_id, 0x1234_5678); // bit31 stripped
    }

    // ── decode_any tagged dispatch ───────────────────────────────────

    #[test]
    fn decode_any_recognises_all_7_operations() {
        let cases: [(u8, [u8; 4]); 7] = [
            (0x01, [0x32, 0x01, 0x01, 0x00]),
            (0x02, [0x32, 0x02, 0x22, 0x00]),
            (0x03, [0x32, 0x03, 0x16, 0x00]),
            (0x04, [0x32, 0x04, 0x11, 0x00]),
            (0x05, [0x32, 0x05, 0x08, 0x00]),
            (0x06, [0x32, 0x06, 0x04, 0x00]),
            (0x07, [0x32, 0x07, 0x0C, 0x00]),
        ];
        for (op_code, header) in cases {
            // Build a zero-filled body of the right size so the inner
            // decoder is happy.
            let body_size = header[2] as usize;
            let mut bytes: Vec<u8> = Vec::new();
            bytes.extend_from_slice(&header);
            bytes.resize(4 + body_size, 0);
            // Patch fCreate for LSURFACE (op 0x02) — 0x00 is legal (destroy).
            // Patch fAssociate for op 0x04 — 0x00 is legal (disassociate).
            // Toggle (op 0x01): eventType 0x00 = CompositionOff, legal.
            let mut r = ReadCursor::new(&bytes);
            let pdu = decode_any(&mut r)
                .unwrap_or_else(|e| panic!("op 0x{:02x}: {:?}", op_code, e));
            // Spot-check the variant tag matches the op code.
            let matches = match (op_code, pdu) {
                (0x01, CompDeskPdu::Toggle(_))
                | (0x02, CompDeskPdu::LSurface(_))
                | (0x03, CompDeskPdu::SurfObj(_))
                | (0x04, CompDeskPdu::RedirSurfAssoc(_))
                | (0x05, CompDeskPdu::CompRefPending(_))
                | (0x06, CompDeskPdu::Switch(_))
                | (0x07, CompDeskPdu::Flush(_)) => true,
                _ => false,
            };
            assert!(matches, "variant mismatch for op 0x{:02x}", op_code);
        }
    }

    #[test]
    fn decode_any_rejects_unknown_operation() {
        let bytes = [0x32, 0x42, 0x00, 0x00];
        let mut r = ReadCursor::new(&bytes);
        assert!(decode_any(&mut r).is_err());
    }

    #[test]
    fn decode_any_rejects_bad_header_byte() {
        let bytes = [0x00, 0x01, 0x01, 0x00, 0x03];
        let mut r = ReadCursor::new(&bytes);
        assert!(decode_any(&mut r).is_err());
    }

    #[test]
    fn decode_any_rejects_short_input() {
        let bytes = [0x32, 0x01];
        let mut r = ReadCursor::new(&bytes);
        assert!(decode_any(&mut r).is_err());
    }
}
