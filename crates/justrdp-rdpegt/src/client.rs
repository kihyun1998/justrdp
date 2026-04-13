//! MS-RDPEGT §3 — DVC processor and geometry map state.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, ReadCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::pdu::{
    GeometryUpdate, IRect, MappedGeometryPacket, CHANNEL_NAME, MAX_ACTIVE_MAPPINGS,
};

// ── GeometryEntry ──

/// A single active geometry mapping as stored inside [`RdpegtClient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeometryEntry {
    pub top_level_id: u64,
    pub window_rect: IRect,
    pub top_level_rect: IRect,
    pub region_bound: IRect,
    pub rects: Vec<IRect>,
}

impl GeometryEntry {
    fn from_update(u: &GeometryUpdate) -> Self {
        Self {
            top_level_id: u.top_level_id,
            window_rect: u.window_rect,
            top_level_rect: u.top_level_rect,
            region_bound: u.region_bound,
            rects: u.rects.clone(),
        }
    }
}

// ── GeometryLookup trait ──

/// Read-only lookup port over the geometry state.
///
/// [`RdpegtClient`] implements this directly; consumers such as
/// `justrdp-rdpevor` (MS-RDPEVOR §9.8) use it to resolve a
/// `MappingId` reference inside a presentation request into the
/// concrete rectangle where the decoded video frame should be drawn.
pub trait GeometryLookup {
    /// Returns the geometry entry for `mapping_id`, if one is active.
    fn lookup(&self, mapping_id: u64) -> Option<&GeometryEntry>;

    /// Returns the number of active mappings.
    fn active_mappings(&self) -> usize;
}

// ── RdpegtClient ──

/// Client-side processor for the `Microsoft::Windows::RDS::Geometry::v08.01` DVC.
///
/// The Geometry Tracking channel is strictly server-to-client: the client
/// opens the DVC and receives `MAPPED_GEOMETRY_PACKET`s; it never sends
/// any messages back.
#[derive(Debug, Default)]
pub struct RdpegtClient {
    geometries: BTreeMap<u64, GeometryEntry>,
    channel_id: u32,
    open: bool,
}

impl RdpegtClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether the DVC has been opened by the DRDYNVC layer.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Consumes the state, returning the current geometry map.
    pub fn into_entries(self) -> BTreeMap<u64, GeometryEntry> {
        self.geometries
    }

    fn apply(&mut self, pdu: MappedGeometryPacket) -> DvcResult<()> {
        match pdu {
            MappedGeometryPacket::Update(u) => {
                // Enforce cap, but only when inserting a *new* mapping so
                // that replacing an existing id cannot reject a legitimate
                // update once the map is at capacity.
                if !self.geometries.contains_key(&u.mapping_id)
                    && self.geometries.len() >= MAX_ACTIVE_MAPPINGS
                {
                    return Err(DvcError::Protocol(String::from(
                        "RDPEGT: MAX_ACTIVE_MAPPINGS exceeded",
                    )));
                }
                self.geometries
                    .insert(u.mapping_id, GeometryEntry::from_update(&u));
            }
            MappedGeometryPacket::Clear(c) => {
                // Unknown mapping id → silent ignore per §3.
                self.geometries.remove(&c.mapping_id);
            }
        }
        Ok(())
    }
}

impl GeometryLookup for RdpegtClient {
    fn lookup(&self, mapping_id: u64) -> Option<&GeometryEntry> {
        self.geometries.get(&mapping_id)
    }

    fn active_mappings(&self) -> usize {
        self.geometries.len()
    }
}

impl AsAny for RdpegtClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl DvcProcessor for RdpegtClient {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        self.channel_id = channel_id;
        self.open = true;
        Ok(Vec::new())
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if !self.open {
            return Err(DvcError::Protocol(String::from(
                "RDPEGT process() called before start()",
            )));
        }
        debug_assert_eq!(
            channel_id, self.channel_id,
            "RdpegtClient: channel_id mismatch in process()"
        );
        let mut cur = ReadCursor::new(payload);
        let pdu = MappedGeometryPacket::decode(&mut cur).map_err(DvcError::Decode)?;
        if cur.remaining() != 0 {
            return Err(DvcError::Protocol(String::from(
                "RDPEGT trailing bytes after MAPPED_GEOMETRY_PACKET",
            )));
        }
        self.apply(pdu)?;
        Ok(Vec::new())
    }

    fn close(&mut self, _channel_id: u32) {
        self.geometries.clear();
        self.open = false;
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{GeometryClear, GeometryUpdate};
    use alloc::vec;
    use justrdp_core::{Encode, WriteCursor};

    fn encode_pdu(pdu: &MappedGeometryPacket) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        buf
    }

    #[test]
    fn start_marks_open() {
        let mut c = RdpegtClient::new();
        assert!(!c.is_open());
        let out = c.start(7).unwrap();
        assert!(out.is_empty());
        assert!(c.is_open());
    }

    #[test]
    fn update_then_lookup() {
        let mut c = RdpegtClient::new();
        c.start(1).unwrap();
        let u = GeometryUpdate::new_single(0xAA, 0xBB, IRect::new(10, 20, 110, 220));
        let bytes = encode_pdu(&MappedGeometryPacket::Update(u));
        let out = c.process(1, &bytes).unwrap();
        assert!(out.is_empty());
        let entry = c.lookup(0xAA).unwrap();
        assert_eq!(entry.window_rect, IRect::new(10, 20, 110, 220));
        assert_eq!(c.active_mappings(), 1);
    }

    #[test]
    fn update_replaces_existing_mapping() {
        let mut c = RdpegtClient::new();
        c.start(1).unwrap();
        let u1 = GeometryUpdate::new_single(0xAA, 0xBB, IRect::new(0, 0, 100, 100));
        c.process(1, &encode_pdu(&MappedGeometryPacket::Update(u1)))
            .unwrap();
        let u2 = GeometryUpdate::new_single(0xAA, 0xCC, IRect::new(0, 0, 200, 200));
        c.process(1, &encode_pdu(&MappedGeometryPacket::Update(u2)))
            .unwrap();
        let entry = c.lookup(0xAA).unwrap();
        assert_eq!(entry.top_level_id, 0xCC);
        assert_eq!(entry.window_rect.right, 200);
        assert_eq!(c.active_mappings(), 1);
    }

    #[test]
    fn clear_removes_mapping() {
        let mut c = RdpegtClient::new();
        c.start(1).unwrap();
        let u = GeometryUpdate::new_single(42, 1, IRect::new(0, 0, 10, 10));
        c.process(1, &encode_pdu(&MappedGeometryPacket::Update(u)))
            .unwrap();
        assert_eq!(c.active_mappings(), 1);

        let clear = MappedGeometryPacket::Clear(GeometryClear::new(42));
        c.process(1, &encode_pdu(&clear)).unwrap();
        assert_eq!(c.active_mappings(), 0);
        assert!(c.lookup(42).is_none());
    }

    #[test]
    fn clear_unknown_mapping_is_silent() {
        let mut c = RdpegtClient::new();
        c.start(1).unwrap();
        let clear = MappedGeometryPacket::Clear(GeometryClear::new(9999));
        let out = c.process(1, &encode_pdu(&clear)).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn close_clears_state() {
        let mut c = RdpegtClient::new();
        c.start(1).unwrap();
        let u = GeometryUpdate::new_single(1, 2, IRect::new(0, 0, 10, 10));
        c.process(1, &encode_pdu(&MappedGeometryPacket::Update(u)))
            .unwrap();
        c.close(1);
        assert_eq!(c.active_mappings(), 0);
        assert!(!c.is_open());
    }

    #[test]
    fn max_active_mappings_boundary() {
        let mut c = RdpegtClient::new();
        c.start(1).unwrap();
        // Fill to exactly MAX_ACTIVE_MAPPINGS.
        for id in 0..MAX_ACTIVE_MAPPINGS as u64 {
            let u = GeometryUpdate::new_single(id, 0, IRect::new(0, 0, 10, 10));
            c.process(1, &encode_pdu(&MappedGeometryPacket::Update(u)))
                .unwrap();
        }
        assert_eq!(c.active_mappings(), MAX_ACTIVE_MAPPINGS);

        // A new id at capacity must be rejected.
        let u = GeometryUpdate::new_single(
            MAX_ACTIVE_MAPPINGS as u64,
            0,
            IRect::new(0, 0, 10, 10),
        );
        let err = c.process(1, &encode_pdu(&MappedGeometryPacket::Update(u)));
        assert!(err.is_err());
        assert_eq!(c.active_mappings(), MAX_ACTIVE_MAPPINGS);

        // Replacing an existing id at capacity must still succeed.
        let u = GeometryUpdate::new_single(0, 42, IRect::new(0, 0, 99, 99));
        c.process(1, &encode_pdu(&MappedGeometryPacket::Update(u)))
            .unwrap();
        assert_eq!(c.lookup(0).unwrap().top_level_id, 42);
    }

    #[test]
    fn process_before_start_is_error() {
        let mut c = RdpegtClient::new();
        let u = GeometryUpdate::new_single(1, 2, IRect::new(0, 0, 10, 10));
        let err = c.process(1, &encode_pdu(&MappedGeometryPacket::Update(u)));
        assert!(err.is_err());
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut c = RdpegtClient::new();
        c.start(1).unwrap();
        let u = GeometryUpdate::new_single(1, 2, IRect::new(0, 0, 10, 10));
        let mut bytes = encode_pdu(&MappedGeometryPacket::Update(u));
        bytes.push(0xAB);
        let err = c.process(1, &bytes);
        assert!(err.is_err());
    }

    #[test]
    fn malformed_payload_returns_error() {
        let mut c = RdpegtClient::new();
        c.start(1).unwrap();
        // 8 bytes is far too short for the 24-byte fixed header.
        let err = c.process(1, &[0u8; 8]);
        assert!(err.is_err());
    }
}
