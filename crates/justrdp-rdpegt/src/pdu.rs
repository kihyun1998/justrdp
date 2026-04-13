//! MS-RDPEGT §2.2 Message Syntax — wire-format PDUs.
//!
//! The Geometry Tracking extension defines a single packet,
//! `MAPPED_GEOMETRY_PACKET`, which the server sends to the client on the
//! `Microsoft::Windows::RDS::Geometry::v08.01` dynamic virtual channel.
//!
//! Two update kinds share the 24-byte fixed header:
//!   - `GEOMETRY_UPDATE (1)` -- add or replace a mapping.
//!   - `GEOMETRY_CLEAR  (2)` -- remove a mapping.

use alloc::vec::Vec;

use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

// ── DVC channel name (MS-RDPEGT §2.1) ──

/// Name of the dynamic virtual channel carrying Geometry Tracking PDUs.
pub const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Geometry::v08.01";

// ── Protocol constants (MS-RDPEGT §2.2.1) ──

/// Only supported value of the `Version` field.
pub const MAPPED_GEOMETRY_VERSION: u32 = 0x0000_0001;

/// `UpdateType` for GEOMETRY_UPDATE (add or replace a mapping).
pub const GEOMETRY_UPDATE: u32 = 0x0000_0001;

/// `UpdateType` for GEOMETRY_CLEAR (remove a mapping).
pub const GEOMETRY_CLEAR: u32 = 0x0000_0002;

/// Only `GeometryType` value observed in the published spec.
///
/// The geometry buffer is an `RGNDATA` structure (see [`RGNDATAHEADER_SIZE`]).
pub const GEOMETRY_TYPE_REGION: u32 = 0x0000_0002;

/// `iType` for RGNDATAHEADER — always `RDH_RECTANGLES`.
pub const RDH_RECTANGLES: u32 = 0x0000_0001;

/// Fixed size of the `RGNDATAHEADER` that precedes each RECT array.
pub const RGNDATAHEADER_SIZE: u32 = 32;

/// Size of the common header (24) plus UPDATE-specific fixed fields (48).
const UPDATE_FIXED_SIZE: u32 = 72;

/// Size on the wire of a CLEAR packet (header fields only).
const CLEAR_PACKET_SIZE: u32 = 24;

// ── DoS caps (defensive; spec is silent) ──

/// Maximum RECTs we are willing to decode from a single geometry packet.
///
/// 4096 RECTs × 16 bytes = 64 KiB of rect data, which is more than any
/// realistic video window compositing region would ever require.
pub const MAX_RECTS_PER_GEOMETRY: u32 = 4096;

/// Maximum number of active geometry mappings the client will track.
pub const MAX_ACTIVE_MAPPINGS: usize = 1024;

/// Maximum `cbGeometryBuffer` accepted. Bounds allocation at decode time.
pub const MAX_CBGEOMETRYBUFFER: u32 = 65_536;

/// Maximum `cbGeometryData` accepted (header + buffer).
pub const MAX_CBGEOMETRYDATA: u32 = 72 + MAX_CBGEOMETRYBUFFER;

// ── IRect ──

/// Axis-aligned rectangle in server desktop coordinates.
///
/// `right` and `bottom` are exclusive (Windows GDI convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl IRect {
    /// Wire size of a single `RECT`.
    pub const WIRE_SIZE: usize = 16;

    pub fn new(left: i32, top: i32, right: i32, bottom: i32) -> Self {
        Self { left, top, right, bottom }
    }

    fn encode(&self, dst: &mut WriteCursor<'_>, ctx: &'static str) -> EncodeResult<()> {
        dst.write_i32_le(self.left, ctx)?;
        dst.write_i32_le(self.top, ctx)?;
        dst.write_i32_le(self.right, ctx)?;
        dst.write_i32_le(self.bottom, ctx)?;
        Ok(())
    }

    fn decode(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<Self> {
        Ok(Self {
            left: src.read_i32_le(ctx)?,
            top: src.read_i32_le(ctx)?,
            right: src.read_i32_le(ctx)?,
            bottom: src.read_i32_le(ctx)?,
        })
    }
}

// ── GeometryUpdate ──

/// `MAPPED_GEOMETRY_PACKET` with `UpdateType == GEOMETRY_UPDATE`.
///
/// Adds a new mapping or replaces an existing one with the same `mapping_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeometryUpdate {
    /// Server-assigned opaque handle.
    pub mapping_id: u64,
    /// Reserved / server-defined flag bits. Stored but not interpreted.
    pub flags: u32,
    /// Handle of the top-level parent window.
    pub top_level_id: u64,
    /// Video window rectangle (relative to server desktop).
    pub window_rect: IRect,
    /// Top-level window rectangle (relative to server desktop).
    pub top_level_rect: IRect,
    /// Region bounding rect from the `RGNDATAHEADER`.
    pub region_bound: IRect,
    /// Clip rectangles making up the visible region of the video window.
    pub rects: Vec<IRect>,
    /// Value of the `nRgnSize` header field. Microsoft docs call it
    /// reserved; Windows does not reliably populate it. Stored verbatim so
    /// that an encode→decode roundtrip is byte-exact.
    pub rgn_size: u32,
}

impl GeometryUpdate {
    /// Constructor for a minimal GEOMETRY_UPDATE with a single clip rect.
    pub fn new_single(mapping_id: u64, top_level_id: u64, window: IRect) -> Self {
        let width = window.right.saturating_sub(window.left);
        let height = window.bottom.saturating_sub(window.top);
        Self {
            mapping_id,
            flags: 0,
            top_level_id,
            window_rect: window,
            top_level_rect: window,
            region_bound: IRect::new(0, 0, width, height),
            rects: alloc::vec![IRect::new(0, 0, width, height)],
            rgn_size: 0,
        }
    }

    /// `cbGeometryBuffer` value that will be written on the wire.
    ///
    /// Returns `None` if `rects.len()` cannot fit in a `u32`, in which case
    /// the caller should not encode this PDU.
    fn cb_geometry_buffer(&self) -> Option<u32> {
        let count = u32::try_from(self.rects.len()).ok()?;
        let bytes = count.checked_mul(IRect::WIRE_SIZE as u32)?;
        RGNDATAHEADER_SIZE.checked_add(bytes)
    }

    /// `cbGeometryData` value for the full UPDATE packet.
    fn cb_geometry_data(&self) -> Option<u32> {
        UPDATE_FIXED_SIZE.checked_add(self.cb_geometry_buffer()?)
    }
}

// ── GeometryClear ──

/// `MAPPED_GEOMETRY_PACKET` with `UpdateType == GEOMETRY_CLEAR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeometryClear {
    pub mapping_id: u64,
    pub flags: u32,
}

impl GeometryClear {
    pub fn new(mapping_id: u64) -> Self {
        Self { mapping_id, flags: 0 }
    }
}

// ── MappedGeometryPacket ──

/// A decoded geometry packet. Either an `Update` or a `Clear`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedGeometryPacket {
    Update(GeometryUpdate),
    Clear(GeometryClear),
}

impl MappedGeometryPacket {
    /// Returns the `mapping_id` this packet addresses.
    pub fn mapping_id(&self) -> u64 {
        match self {
            Self::Update(u) => u.mapping_id,
            Self::Clear(c) => c.mapping_id,
        }
    }
}

impl Encode for MappedGeometryPacket {
    fn name(&self) -> &'static str {
        "MAPPED_GEOMETRY_PACKET"
    }

    fn size(&self) -> usize {
        match self {
            Self::Update(u) => u
                .cb_geometry_data()
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(usize::MAX),
            Self::Clear(_) => CLEAR_PACKET_SIZE as usize,
        }
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const CTX: &str = "MAPPED_GEOMETRY_PACKET";
        match self {
            Self::Update(u) => {
                let cb_buffer = u
                    .cb_geometry_buffer()
                    .ok_or_else(|| justrdp_core::EncodeError::invalid_value(CTX, "rects.len()"))?;
                let cb_data = u
                    .cb_geometry_data()
                    .ok_or_else(|| justrdp_core::EncodeError::invalid_value(CTX, "cbGeometryData"))?;
                if cb_data > MAX_CBGEOMETRYDATA {
                    return Err(justrdp_core::EncodeError::invalid_value(CTX, "MAX_CBGEOMETRYDATA"));
                }
                dst.write_u32_le(cb_data, CTX)?;
                dst.write_u32_le(MAPPED_GEOMETRY_VERSION, CTX)?;
                dst.write_u64_le(u.mapping_id, CTX)?;
                dst.write_u32_le(GEOMETRY_UPDATE, CTX)?;
                dst.write_u32_le(u.flags, CTX)?;
                dst.write_u64_le(u.top_level_id, CTX)?;
                u.window_rect.encode(dst, CTX)?;
                u.top_level_rect.encode(dst, CTX)?;
                dst.write_u32_le(GEOMETRY_TYPE_REGION, CTX)?;
                dst.write_u32_le(cb_buffer, CTX)?;
                // RGNDATAHEADER
                dst.write_u32_le(RGNDATAHEADER_SIZE, CTX)?;
                dst.write_u32_le(RDH_RECTANGLES, CTX)?;
                dst.write_u32_le(u.rects.len() as u32, CTX)?;
                dst.write_u32_le(u.rgn_size, CTX)?;
                u.region_bound.encode(dst, CTX)?;
                for r in &u.rects {
                    r.encode(dst, CTX)?;
                }
            }
            Self::Clear(c) => {
                dst.write_u32_le(24, CTX)?;
                dst.write_u32_le(MAPPED_GEOMETRY_VERSION, CTX)?;
                dst.write_u64_le(c.mapping_id, CTX)?;
                dst.write_u32_le(GEOMETRY_CLEAR, CTX)?;
                dst.write_u32_le(c.flags, CTX)?;
            }
        }
        Ok(())
    }
}

impl<'de> Decode<'de> for MappedGeometryPacket {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MAPPED_GEOMETRY_PACKET";

        // Fixed header (24 bytes).
        let cb_geometry_data = src.read_u32_le(CTX)?;
        if cb_geometry_data < 24 {
            return Err(DecodeError::invalid_value(CTX, "cbGeometryData"));
        }
        if cb_geometry_data > MAX_CBGEOMETRYDATA {
            return Err(DecodeError::invalid_value(CTX, "cbGeometryData (cap)"));
        }

        let version = src.read_u32_le(CTX)?;
        if version != MAPPED_GEOMETRY_VERSION {
            return Err(DecodeError::invalid_value(CTX, "Version"));
        }

        let mapping_id = src.read_u64_le(CTX)?;
        let update_type = src.read_u32_le(CTX)?;
        let flags = src.read_u32_le(CTX)?;

        match update_type {
            GEOMETRY_CLEAR => {
                if cb_geometry_data != 24 {
                    return Err(DecodeError::invalid_value(CTX, "cbGeometryData for CLEAR"));
                }
                Ok(Self::Clear(GeometryClear { mapping_id, flags }))
            }
            GEOMETRY_UPDATE => {
                // 72 (fixed + UPDATE fields) + 32 (RGNDATAHEADER minimum).
                if cb_geometry_data < 72 + RGNDATAHEADER_SIZE {
                    return Err(DecodeError::invalid_value(CTX, "cbGeometryData for UPDATE"));
                }
                let top_level_id = src.read_u64_le(CTX)?;
                let window_rect = IRect::decode(src, CTX)?;
                let top_level_rect = IRect::decode(src, CTX)?;

                let geometry_type = src.read_u32_le(CTX)?;
                if geometry_type != GEOMETRY_TYPE_REGION {
                    return Err(DecodeError::invalid_value(CTX, "GeometryType"));
                }

                let cb_geometry_buffer = src.read_u32_le(CTX)?;
                if cb_geometry_buffer > MAX_CBGEOMETRYBUFFER {
                    return Err(DecodeError::invalid_value(CTX, "cbGeometryBuffer (cap)"));
                }
                if cb_geometry_data != 72u32.saturating_add(cb_geometry_buffer) {
                    return Err(DecodeError::invalid_value(
                        CTX,
                        "cbGeometryData / cbGeometryBuffer mismatch",
                    ));
                }
                if cb_geometry_buffer < RGNDATAHEADER_SIZE {
                    return Err(DecodeError::invalid_value(
                        CTX,
                        "cbGeometryBuffer < RGNDATAHEADER",
                    ));
                }

                // RGNDATAHEADER
                let dw_size = src.read_u32_le(CTX)?;
                if dw_size != RGNDATAHEADER_SIZE {
                    return Err(DecodeError::invalid_value(CTX, "RGNDATAHEADER.dwSize"));
                }
                let i_type = src.read_u32_le(CTX)?;
                if i_type != RDH_RECTANGLES {
                    return Err(DecodeError::invalid_value(CTX, "RGNDATAHEADER.iType"));
                }
                let n_count = src.read_u32_le(CTX)?;
                if n_count > MAX_RECTS_PER_GEOMETRY {
                    return Err(DecodeError::invalid_value(CTX, "RGNDATAHEADER.nCount (cap)"));
                }
                let rects_bytes = n_count
                    .checked_mul(IRect::WIRE_SIZE as u32)
                    .ok_or_else(|| DecodeError::invalid_value(CTX, "nCount overflow"))?;
                if RGNDATAHEADER_SIZE + rects_bytes != cb_geometry_buffer {
                    return Err(DecodeError::invalid_value(
                        CTX,
                        "cbGeometryBuffer != 32 + nCount*16",
                    ));
                }
                let rgn_size = src.read_u32_le(CTX)?;
                let region_bound = IRect::decode(src, CTX)?;

                let mut rects = Vec::with_capacity(n_count as usize);
                for _ in 0..n_count {
                    rects.push(IRect::decode(src, CTX)?);
                }

                Ok(Self::Update(GeometryUpdate {
                    mapping_id,
                    flags,
                    top_level_id,
                    window_rect,
                    top_level_rect,
                    region_bound,
                    rects,
                    rgn_size,
                }))
            }
            _ => Err(DecodeError::invalid_value(CTX, "UpdateType")),
        }
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_4_1_bytes() -> Vec<u8> {
        // MS-RDPEGT §4.1 GEOMETRY_UPDATE sample (120 bytes).
        let mut v = Vec::new();
        v.extend_from_slice(&0x78u32.to_le_bytes()); // cbGeometryData
        v.extend_from_slice(&1u32.to_le_bytes()); // Version
        v.extend_from_slice(&0x80007ABA_00040222u64.to_le_bytes()); // MappingId
        v.extend_from_slice(&GEOMETRY_UPDATE.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // Flags
        v.extend_from_slice(&0x0000_0000_0003_01E2u64.to_le_bytes()); // TopLevelId
        v.extend_from_slice(&16i32.to_le_bytes());
        v.extend_from_slice(&138i32.to_le_bytes());
        v.extend_from_slice(&496i32.to_le_bytes());
        v.extend_from_slice(&382i32.to_le_bytes());
        v.extend_from_slice(&291i32.to_le_bytes());
        v.extend_from_slice(&113i32.to_le_bytes());
        v.extend_from_slice(&1144i32.to_le_bytes());
        v.extend_from_slice(&714i32.to_le_bytes());
        v.extend_from_slice(&GEOMETRY_TYPE_REGION.to_le_bytes());
        v.extend_from_slice(&48u32.to_le_bytes()); // cbGeometryBuffer
        // RGNDATAHEADER
        v.extend_from_slice(&32u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes()); // iType
        v.extend_from_slice(&1u32.to_le_bytes()); // nCount
        v.extend_from_slice(&0u32.to_le_bytes()); // nRgnSize
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&480i32.to_le_bytes());
        v.extend_from_slice(&244i32.to_le_bytes());
        // RECT[0]
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&480i32.to_le_bytes());
        v.extend_from_slice(&244i32.to_le_bytes());
        assert_eq!(v.len(), 120);
        v
    }

    fn encode_pdu(pdu: &MappedGeometryPacket) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        assert_eq!(cur.pos(), pdu.size());
        buf
    }

    #[test]
    fn decode_spec_4_1_update() {
        let bytes = spec_4_1_bytes();
        let mut cur = ReadCursor::new(&bytes);
        let pdu = MappedGeometryPacket::decode(&mut cur).unwrap();
        match pdu {
            MappedGeometryPacket::Update(u) => {
                assert_eq!(u.mapping_id, 0x80007ABA_00040222);
                assert_eq!(u.flags, 0);
                assert_eq!(u.top_level_id, 0x0000_0000_0003_01E2);
                assert_eq!(u.window_rect, IRect::new(16, 138, 496, 382));
                assert_eq!(u.top_level_rect, IRect::new(291, 113, 1144, 714));
                assert_eq!(u.region_bound, IRect::new(0, 0, 480, 244));
                assert_eq!(u.rects.len(), 1);
                assert_eq!(u.rects[0], IRect::new(0, 0, 480, 244));
                assert_eq!(u.rgn_size, 0);
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn roundtrip_spec_4_1_update() {
        let bytes = spec_4_1_bytes();
        let mut cur = ReadCursor::new(&bytes);
        let pdu = MappedGeometryPacket::decode(&mut cur).unwrap();
        let re = encode_pdu(&pdu);
        assert_eq!(re, bytes);
    }

    #[test]
    fn roundtrip_clear() {
        let pdu = MappedGeometryPacket::Clear(GeometryClear::new(0xDEAD_BEEF_CAFE_BABE));
        let bytes = encode_pdu(&pdu);
        assert_eq!(bytes.len(), 24);
        assert_eq!(&bytes[0..4], &24u32.to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        let decoded = MappedGeometryPacket::decode(&mut cur).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn roundtrip_empty_region_update() {
        let u = GeometryUpdate {
            mapping_id: 42,
            flags: 0,
            top_level_id: 1,
            window_rect: IRect::new(0, 0, 10, 10),
            top_level_rect: IRect::new(0, 0, 20, 20),
            region_bound: IRect::new(0, 0, 0, 0),
            rects: Vec::new(),
            rgn_size: 0,
        };
        let pdu = MappedGeometryPacket::Update(u);
        let bytes = encode_pdu(&pdu);
        assert_eq!(bytes.len(), 72 + 32);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = MappedGeometryPacket::decode(&mut cur).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn reject_bad_version() {
        let mut bytes = spec_4_1_bytes();
        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        assert!(MappedGeometryPacket::decode(&mut cur).is_err());
    }

    #[test]
    fn reject_bad_update_type() {
        let mut bytes = spec_4_1_bytes();
        bytes[16..20].copy_from_slice(&99u32.to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        assert!(MappedGeometryPacket::decode(&mut cur).is_err());
    }

    #[test]
    fn reject_bad_geometry_type() {
        let mut bytes = spec_4_1_bytes();
        // GeometryType offset = 24 + 8 + 32 = 64
        bytes[64..68].copy_from_slice(&5u32.to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        assert!(MappedGeometryPacket::decode(&mut cur).is_err());
    }

    #[test]
    fn reject_bad_dw_size() {
        let mut bytes = spec_4_1_bytes();
        // dwSize offset = 72
        bytes[72..76].copy_from_slice(&16u32.to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        assert!(MappedGeometryPacket::decode(&mut cur).is_err());
    }

    #[test]
    fn reject_bad_i_type() {
        let mut bytes = spec_4_1_bytes();
        // iType offset = 76
        bytes[76..80].copy_from_slice(&7u32.to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        assert!(MappedGeometryPacket::decode(&mut cur).is_err());
    }

    #[test]
    fn reject_cb_data_too_small() {
        let mut bytes = spec_4_1_bytes();
        bytes[0..4].copy_from_slice(&20u32.to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        assert!(MappedGeometryPacket::decode(&mut cur).is_err());
    }

    #[test]
    fn reject_n_count_overflow_guard() {
        let mut bytes = spec_4_1_bytes();
        // nCount offset = 80
        bytes[80..84].copy_from_slice(&(MAX_RECTS_PER_GEOMETRY + 1).to_le_bytes());
        let mut cur = ReadCursor::new(&bytes);
        assert!(MappedGeometryPacket::decode(&mut cur).is_err());
    }

    #[test]
    fn reject_clear_with_trailing_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&32u32.to_le_bytes()); // cbGeometryData = 32 (wrong)
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&GEOMETRY_CLEAR.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8]);
        let mut cur = ReadCursor::new(&bytes);
        assert!(MappedGeometryPacket::decode(&mut cur).is_err());
    }

    #[test]
    fn new_single_helper_roundtrip() {
        let u = GeometryUpdate::new_single(100, 200, IRect::new(50, 50, 150, 150));
        let pdu = MappedGeometryPacket::Update(u);
        let bytes = encode_pdu(&pdu);
        let mut cur = ReadCursor::new(&bytes);
        let decoded = MappedGeometryPacket::decode(&mut cur).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(decoded.mapping_id(), 100);
    }
}
