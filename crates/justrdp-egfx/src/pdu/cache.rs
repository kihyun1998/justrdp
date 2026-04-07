extern crate alloc;

use alloc::vec::Vec;
use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor};

use super::{GfxPoint16, GfxRect16, RdpgfxHeader, RDPGFX_CMDID_CACHEIMPORTOFFER};

// ── SurfaceToCache (MS-RDPEGFX 2.2.2.6) — Server → Client ──

/// Cache a surface region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceToCachePdu {
    pub surface_id: u16,
    pub cache_key: u64,
    pub cache_slot: u16,
    pub rect_src: GfxRect16,
}

impl SurfaceToCachePdu {
    /// Body: surfaceId(2) + cacheKey(8) + cacheSlot(2) + rectSrc(8) = 20.
    pub const BODY_SIZE: usize = 20;
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + Self::BODY_SIZE;
}

impl<'de> Decode<'de> for SurfaceToCachePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            surface_id: src.read_u16_le("SurfaceToCache::surfaceId")?,
            cache_key: src.read_u64_le("SurfaceToCache::cacheKey")?,
            cache_slot: src.read_u16_le("SurfaceToCache::cacheSlot")?,
            rect_src: GfxRect16::decode(src)?,
        })
    }
}

impl Encode for SurfaceToCachePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.surface_id, "SurfaceToCache::surfaceId")?;
        dst.write_u64_le(self.cache_key, "SurfaceToCache::cacheKey")?;
        dst.write_u16_le(self.cache_slot, "SurfaceToCache::cacheSlot")?;
        self.rect_src.encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SurfaceToCachePdu"
    }

    fn size(&self) -> usize {
        Self::BODY_SIZE
    }
}

// ── CacheToSurface (MS-RDPEGFX 2.2.2.7) — Server → Client ──

/// Copy cached bitmap to a surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheToSurfacePdu {
    pub cache_slot: u16,
    pub surface_id: u16,
    pub dest_pts: Vec<GfxPoint16>,
}

impl CacheToSurfacePdu {
    /// Minimum body: cacheSlot(2) + surfaceId(2) + destPtsCount(2) = 6.
    pub const MIN_BODY_SIZE: usize = 6;
}

impl<'de> Decode<'de> for CacheToSurfacePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cache_slot = src.read_u16_le("CacheToSurface::cacheSlot")?;
        let surface_id = src.read_u16_le("CacheToSurface::surfaceId")?;
        let count = src.read_u16_le("CacheToSurface::destPtsCount")?;
        let mut dest_pts = Vec::with_capacity(count as usize);
        for _ in 0..count {
            dest_pts.push(GfxPoint16::decode(src)?);
        }
        Ok(Self {
            cache_slot,
            surface_id,
            dest_pts,
        })
    }
}

impl Encode for CacheToSurfacePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.cache_slot, "CacheToSurface::cacheSlot")?;
        dst.write_u16_le(self.surface_id, "CacheToSurface::surfaceId")?;
        dst.write_u16_le(self.dest_pts.len() as u16, "CacheToSurface::destPtsCount")?;
        for pt in &self.dest_pts {
            pt.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CacheToSurfacePdu"
    }

    fn size(&self) -> usize {
        Self::MIN_BODY_SIZE + self.dest_pts.len() * GfxPoint16::WIRE_SIZE
    }
}

// ── EvictCacheEntry (MS-RDPEGFX 2.2.2.8) — Server → Client ──

/// Evict a bitmap cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvictCacheEntryPdu {
    pub cache_slot: u16,
}

impl EvictCacheEntryPdu {
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + 2;
}

impl<'de> Decode<'de> for EvictCacheEntryPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            cache_slot: src.read_u16_le("EvictCacheEntry::cacheSlot")?,
        })
    }
}

impl Encode for EvictCacheEntryPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.cache_slot, "EvictCacheEntry::cacheSlot")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "EvictCacheEntryPdu"
    }

    fn size(&self) -> usize {
        2
    }
}

// ── CacheEntryMetadata (MS-RDPEGFX 2.2.2.16.1) ──

/// Metadata for a single cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheEntryMetadata {
    pub cache_key: u64,
    pub bitmap_length: u32,
}

impl CacheEntryMetadata {
    pub const WIRE_SIZE: usize = 12;
}

impl Encode for CacheEntryMetadata {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u64_le(self.cache_key, "CacheEntryMetadata::cacheKey")?;
        dst.write_u32_le(self.bitmap_length, "CacheEntryMetadata::bitmapLength")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CacheEntryMetadata"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for CacheEntryMetadata {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            cache_key: src.read_u64_le("CacheEntryMetadata::cacheKey")?,
            bitmap_length: src.read_u32_le("CacheEntryMetadata::bitmapLength")?,
        })
    }
}

// ── CacheImportOffer (MS-RDPEGFX 2.2.2.16) — Client → Server ──

/// Maximum cache entries count: MUST be < 5462 (MS-RDPEGFX 2.2.2.16).
pub const MAX_CACHE_ENTRIES: u16 = 5461;

/// Offer persistent cache entries to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheImportOfferPdu {
    pub cache_entries: Vec<CacheEntryMetadata>,
}

impl CacheImportOfferPdu {
    /// Minimum body: header(8) + count(2) = 10.
    pub const MIN_WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + 2;
}

impl Encode for CacheImportOfferPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.cache_entries.len() > MAX_CACHE_ENTRIES as usize {
            return Err(EncodeError::other("CacheImportOfferPdu", "cacheEntriesCount exceeds limit"));
        }
        let pdu_length = self.size() as u32;
        let header = RdpgfxHeader {
            cmd_id: RDPGFX_CMDID_CACHEIMPORTOFFER,
            flags: 0,
            pdu_length,
        };
        header.encode(dst)?;
        dst.write_u16_le(self.cache_entries.len() as u16, "CacheImportOffer::count")?;
        for entry in &self.cache_entries {
            entry.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CacheImportOfferPdu"
    }

    fn size(&self) -> usize {
        Self::MIN_WIRE_SIZE + self.cache_entries.len() * CacheEntryMetadata::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for CacheImportOfferPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = RdpgfxHeader::decode(src)?;
        if header.cmd_id != RDPGFX_CMDID_CACHEIMPORTOFFER {
            return Err(DecodeError::invalid_value("CacheImportOfferPdu", "cmdId"));
        }

        let count = src.read_u16_le("CacheImportOffer::count")?;
        if count > MAX_CACHE_ENTRIES {
            return Err(DecodeError::invalid_value("CacheImportOfferPdu", "cacheEntriesCount"));
        }

        let mut cache_entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            cache_entries.push(CacheEntryMetadata::decode(src)?);
        }
        Ok(Self { cache_entries })
    }
}

// ── CacheImportReply (MS-RDPEGFX 2.2.2.17) — Server → Client ──

/// Server's response indicating which cache entries were accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheImportReplyPdu {
    pub cache_slots: Vec<u16>,
}

impl CacheImportReplyPdu {
    /// Minimum body: count(2) = 2 (excluding header).
    pub const MIN_BODY_SIZE: usize = 2;
}

impl<'de> Decode<'de> for CacheImportReplyPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let count = src.read_u16_le("CacheImportReply::importedEntriesCount")?;
        let mut cache_slots = Vec::with_capacity(count as usize);
        for _ in 0..count {
            cache_slots.push(src.read_u16_le("CacheImportReply::cacheSlot")?);
        }
        Ok(Self { cache_slots })
    }
}

impl Encode for CacheImportReplyPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.cache_slots.len() as u16, "CacheImportReply::count")?;
        for &slot in &self.cache_slots {
            dst.write_u16_le(slot, "CacheImportReply::cacheSlot")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CacheImportReplyPdu"
    }

    fn size(&self) -> usize {
        Self::MIN_BODY_SIZE + self.cache_slots.len() * 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn surface_to_cache_roundtrip() {
        let pdu = SurfaceToCachePdu {
            surface_id: 1,
            cache_key: 0xDEAD_BEEF_CAFE_BABE,
            cache_slot: 42,
            rect_src: GfxRect16 {
                left: 10,
                top: 20,
                right: 110,
                bottom: 120,
            },
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(SurfaceToCachePdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn cache_to_surface_roundtrip() {
        let pdu = CacheToSurfacePdu {
            cache_slot: 7,
            surface_id: 3,
            dest_pts: vec![
                GfxPoint16 { x: 0, y: 0 },
                GfxPoint16 { x: 100, y: 100 },
            ],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(CacheToSurfacePdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn evict_cache_entry_roundtrip() {
        let pdu = EvictCacheEntryPdu { cache_slot: 99 };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(EvictCacheEntryPdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn cache_import_offer_roundtrip() {
        let pdu = CacheImportOfferPdu {
            cache_entries: vec![
                CacheEntryMetadata {
                    cache_key: 0x1234,
                    bitmap_length: 4096,
                },
                CacheEntryMetadata {
                    cache_key: 0x5678,
                    bitmap_length: 8192,
                },
            ],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(CacheImportOfferPdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn cache_import_reply_roundtrip() {
        let pdu = CacheImportReplyPdu {
            cache_slots: vec![0, 1, 5, 10],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(CacheImportReplyPdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn cache_import_offer_reject_too_many() {
        // Build raw bytes with count = 5462 (> MAX_CACHE_ENTRIES = 5461)
        let mut data = vec![0u8; 10]; // header(8) + count(2)
        // header: cmdId=0x0010, flags=0, pduLength=10
        data[0..2].copy_from_slice(&0x0010u16.to_le_bytes());
        data[2..4].copy_from_slice(&0u16.to_le_bytes());
        data[4..8].copy_from_slice(&10u32.to_le_bytes());
        data[8..10].copy_from_slice(&5462u16.to_le_bytes());
        let mut src = ReadCursor::new(&data);
        assert!(CacheImportOfferPdu::decode(&mut src).is_err());
    }

    #[test]
    fn cache_import_offer_max_valid() {
        // count = 5461 should be accepted (but will fail reading data since we don't provide it)
        let mut data = vec![0u8; 10 + 5461 * 12];
        data[0..2].copy_from_slice(&0x0010u16.to_le_bytes());
        data[2..4].copy_from_slice(&0u16.to_le_bytes());
        let pdu_len = (10 + 5461 * 12) as u32;
        data[4..8].copy_from_slice(&pdu_len.to_le_bytes());
        data[8..10].copy_from_slice(&5461u16.to_le_bytes());
        let mut src = ReadCursor::new(&data);
        let result = CacheImportOfferPdu::decode(&mut src);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().cache_entries.len(), 5461);
    }
}
