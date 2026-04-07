extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use super::{GfxPixelFormat, RdpgfxHeader};

// ── CreateSurface (MS-RDPEGFX 2.2.2.9) — Server → Client ──

/// Create a new graphics surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateSurfacePdu {
    pub surface_id: u16,
    pub width: u16,
    pub height: u16,
    pub pixel_format: GfxPixelFormat,
}

impl CreateSurfacePdu {
    /// Total wire size: header(8) + 2+2+2+1 = 15.
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + 7;
}

impl<'de> Decode<'de> for CreateSurfacePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            surface_id: src.read_u16_le("CreateSurface::surfaceId")?,
            width: src.read_u16_le("CreateSurface::width")?,
            height: src.read_u16_le("CreateSurface::height")?,
            pixel_format: GfxPixelFormat::decode(src)?,
        })
    }
}

impl Encode for CreateSurfacePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.surface_id, "CreateSurface::surfaceId")?;
        dst.write_u16_le(self.width, "CreateSurface::width")?;
        dst.write_u16_le(self.height, "CreateSurface::height")?;
        self.pixel_format.encode(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CreateSurfacePdu"
    }

    fn size(&self) -> usize {
        7 // body only (header written separately)
    }
}

// ── DeleteSurface (MS-RDPEGFX 2.2.2.10) — Server → Client ──

/// Delete a surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteSurfacePdu {
    pub surface_id: u16,
}

impl DeleteSurfacePdu {
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + 2;
}

impl<'de> Decode<'de> for DeleteSurfacePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            surface_id: src.read_u16_le("DeleteSurface::surfaceId")?,
        })
    }
}

impl Encode for DeleteSurfacePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.surface_id, "DeleteSurface::surfaceId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DeleteSurfacePdu"
    }

    fn size(&self) -> usize {
        2
    }
}

// ── Monitor definition for ResetGraphics (MS-RDPBCGR 2.2.1.3.6.1) ──

/// TS_MONITOR_DEF: 20 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GfxMonitorDef {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub flags: u32,
}

impl GfxMonitorDef {
    pub const WIRE_SIZE: usize = 20;
}

impl Encode for GfxMonitorDef {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_i32_le(self.left, "GfxMonitorDef::left")?;
        dst.write_i32_le(self.top, "GfxMonitorDef::top")?;
        dst.write_i32_le(self.right, "GfxMonitorDef::right")?;
        dst.write_i32_le(self.bottom, "GfxMonitorDef::bottom")?;
        dst.write_u32_le(self.flags, "GfxMonitorDef::flags")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "GfxMonitorDef"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for GfxMonitorDef {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            left: src.read_i32_le("GfxMonitorDef::left")?,
            top: src.read_i32_le("GfxMonitorDef::top")?,
            right: src.read_i32_le("GfxMonitorDef::right")?,
            bottom: src.read_i32_le("GfxMonitorDef::bottom")?,
            flags: src.read_u32_le("GfxMonitorDef::flags")?,
        })
    }
}

// ── ResetGraphics (MS-RDPEGFX 2.2.2.14) — Server → Client ──

/// Reset graphics state. Total PDU MUST be exactly 340 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetGraphicsPdu {
    pub width: u32,
    pub height: u32,
    pub monitors: Vec<GfxMonitorDef>,
}

impl ResetGraphicsPdu {
    /// The total PDU size is always 340 bytes (MS-RDPEGFX 2.2.2.14).
    pub const FIXED_PDU_LENGTH: u32 = 340;
    /// Max monitors (MS-RDPEGFX 2.2.2.14).
    pub const MAX_MONITOR_COUNT: u32 = 16;
    /// Body = width(4) + height(4) + monitorCount(4) + monitors + pad = 332.
    const BODY_SIZE: usize = Self::FIXED_PDU_LENGTH as usize - RdpgfxHeader::WIRE_SIZE;
}

impl<'de> Decode<'de> for ResetGraphicsPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let width = src.read_u32_le("ResetGraphics::width")?;
        let height = src.read_u32_le("ResetGraphics::height")?;
        let monitor_count = src.read_u32_le("ResetGraphics::monitorCount")?;

        if monitor_count > Self::MAX_MONITOR_COUNT {
            return Err(DecodeError::invalid_value("ResetGraphics", "monitorCount"));
        }

        let mut monitors = Vec::with_capacity(monitor_count as usize);
        for _ in 0..monitor_count {
            monitors.push(GfxMonitorDef::decode(src)?);
        }

        // Skip pad bytes: 332 - 12 - monitorCount*20
        let pad_len = Self::BODY_SIZE - 12 - (monitor_count as usize * GfxMonitorDef::WIRE_SIZE);
        let _pad = src.read_slice(pad_len, "ResetGraphics::pad")?;

        Ok(Self {
            width,
            height,
            monitors,
        })
    }
}

impl Encode for ResetGraphicsPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.width, "ResetGraphics::width")?;
        dst.write_u32_le(self.height, "ResetGraphics::height")?;
        dst.write_u32_le(self.monitors.len() as u32, "ResetGraphics::monitorCount")?;

        for m in &self.monitors {
            m.encode(dst)?;
        }

        // Pad to fill 332 bytes total body
        let pad_len = Self::BODY_SIZE - 12 - (self.monitors.len() * GfxMonitorDef::WIRE_SIZE);
        let zeros = vec![0u8; pad_len];
        dst.write_slice(&zeros, "ResetGraphics::pad")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ResetGraphicsPdu"
    }

    fn size(&self) -> usize {
        Self::BODY_SIZE
    }
}

// ── MapSurfaceToOutput (MS-RDPEGFX 2.2.2.15) — Server → Client ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapSurfaceToOutputPdu {
    pub surface_id: u16,
    pub output_origin_x: u32,
    pub output_origin_y: u32,
}

impl MapSurfaceToOutputPdu {
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + 12;
}

impl<'de> Decode<'de> for MapSurfaceToOutputPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let surface_id = src.read_u16_le("MapSurfaceToOutput::surfaceId")?;
        let _reserved = src.read_u16_le("MapSurfaceToOutput::reserved")?;
        let output_origin_x = src.read_u32_le("MapSurfaceToOutput::outputOriginX")?;
        let output_origin_y = src.read_u32_le("MapSurfaceToOutput::outputOriginY")?;
        Ok(Self {
            surface_id,
            output_origin_x,
            output_origin_y,
        })
    }
}

impl Encode for MapSurfaceToOutputPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.surface_id, "MapSurfaceToOutput::surfaceId")?;
        dst.write_u16_le(0, "MapSurfaceToOutput::reserved")?;
        dst.write_u32_le(self.output_origin_x, "MapSurfaceToOutput::outputOriginX")?;
        dst.write_u32_le(self.output_origin_y, "MapSurfaceToOutput::outputOriginY")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "MapSurfaceToOutputPdu"
    }

    fn size(&self) -> usize {
        12
    }
}

// ── MapSurfaceToWindow (MS-RDPEGFX 2.2.2.20) — Server → Client ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapSurfaceToWindowPdu {
    pub surface_id: u16,
    pub window_id: u64,
    pub mapped_width: u32,
    pub mapped_height: u32,
}

impl MapSurfaceToWindowPdu {
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + 18;
}

impl<'de> Decode<'de> for MapSurfaceToWindowPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            surface_id: src.read_u16_le("MapSurfaceToWindow::surfaceId")?,
            window_id: src.read_u64_le("MapSurfaceToWindow::windowId")?,
            mapped_width: src.read_u32_le("MapSurfaceToWindow::mappedWidth")?,
            mapped_height: src.read_u32_le("MapSurfaceToWindow::mappedHeight")?,
        })
    }
}

impl Encode for MapSurfaceToWindowPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.surface_id, "MapSurfaceToWindow::surfaceId")?;
        dst.write_u64_le(self.window_id, "MapSurfaceToWindow::windowId")?;
        dst.write_u32_le(self.mapped_width, "MapSurfaceToWindow::mappedWidth")?;
        dst.write_u32_le(self.mapped_height, "MapSurfaceToWindow::mappedHeight")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "MapSurfaceToWindowPdu"
    }

    fn size(&self) -> usize {
        18
    }
}

// ── MapSurfaceToScaledOutput (MS-RDPEGFX 2.2.2.22) — Server → Client ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapSurfaceToScaledOutputPdu {
    pub surface_id: u16,
    pub output_origin_x: u32,
    pub output_origin_y: u32,
    pub target_width: u32,
    pub target_height: u32,
}

impl MapSurfaceToScaledOutputPdu {
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + 20;
}

impl<'de> Decode<'de> for MapSurfaceToScaledOutputPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let surface_id = src.read_u16_le("MapSurfaceToScaledOutput::surfaceId")?;
        let _reserved = src.read_u16_le("MapSurfaceToScaledOutput::reserved")?;
        let output_origin_x = src.read_u32_le("MapSurfaceToScaledOutput::outputOriginX")?;
        let output_origin_y = src.read_u32_le("MapSurfaceToScaledOutput::outputOriginY")?;
        let target_width = src.read_u32_le("MapSurfaceToScaledOutput::targetWidth")?;
        let target_height = src.read_u32_le("MapSurfaceToScaledOutput::targetHeight")?;
        Ok(Self {
            surface_id,
            output_origin_x,
            output_origin_y,
            target_width,
            target_height,
        })
    }
}

impl Encode for MapSurfaceToScaledOutputPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.surface_id, "MapSurfaceToScaledOutput::surfaceId")?;
        dst.write_u16_le(0, "MapSurfaceToScaledOutput::reserved")?;
        dst.write_u32_le(self.output_origin_x, "MapSurfaceToScaledOutput::outputOriginX")?;
        dst.write_u32_le(self.output_origin_y, "MapSurfaceToScaledOutput::outputOriginY")?;
        dst.write_u32_le(self.target_width, "MapSurfaceToScaledOutput::targetWidth")?;
        dst.write_u32_le(self.target_height, "MapSurfaceToScaledOutput::targetHeight")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "MapSurfaceToScaledOutputPdu"
    }

    fn size(&self) -> usize {
        20
    }
}

// ── MapSurfaceToScaledWindow (MS-RDPEGFX 2.2.2.23) — Server → Client ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapSurfaceToScaledWindowPdu {
    pub surface_id: u16,
    pub window_id: u64,
    pub mapped_width: u32,
    pub mapped_height: u32,
    pub target_width: u32,
    pub target_height: u32,
}

impl MapSurfaceToScaledWindowPdu {
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + 26;
}

impl<'de> Decode<'de> for MapSurfaceToScaledWindowPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            surface_id: src.read_u16_le("MapSurfaceToScaledWindow::surfaceId")?,
            window_id: src.read_u64_le("MapSurfaceToScaledWindow::windowId")?,
            mapped_width: src.read_u32_le("MapSurfaceToScaledWindow::mappedWidth")?,
            mapped_height: src.read_u32_le("MapSurfaceToScaledWindow::mappedHeight")?,
            target_width: src.read_u32_le("MapSurfaceToScaledWindow::targetWidth")?,
            target_height: src.read_u32_le("MapSurfaceToScaledWindow::targetHeight")?,
        })
    }
}

impl Encode for MapSurfaceToScaledWindowPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.surface_id, "MapSurfaceToScaledWindow::surfaceId")?;
        dst.write_u64_le(self.window_id, "MapSurfaceToScaledWindow::windowId")?;
        dst.write_u32_le(self.mapped_width, "MapSurfaceToScaledWindow::mappedWidth")?;
        dst.write_u32_le(self.mapped_height, "MapSurfaceToScaledWindow::mappedHeight")?;
        dst.write_u32_le(self.target_width, "MapSurfaceToScaledWindow::targetWidth")?;
        dst.write_u32_le(self.target_height, "MapSurfaceToScaledWindow::targetHeight")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "MapSurfaceToScaledWindowPdu"
    }

    fn size(&self) -> usize {
        26
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_surface_roundtrip() {
        let pdu = CreateSurfacePdu {
            surface_id: 42,
            width: 1920,
            height: 1080,
            pixel_format: GfxPixelFormat::XRGB_8888,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(CreateSurfacePdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn delete_surface_roundtrip() {
        let pdu = DeleteSurfacePdu { surface_id: 7 };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(DeleteSurfacePdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn reset_graphics_roundtrip() {
        let pdu = ResetGraphicsPdu {
            width: 1920,
            height: 1080,
            monitors: vec![GfxMonitorDef {
                left: 0,
                top: 0,
                right: 1919,
                bottom: 1079,
                flags: 1,
            }],
        };
        assert_eq!(pdu.size(), 332); // body = 340 - 8
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        let decoded = ResetGraphicsPdu::decode(&mut src).unwrap();
        assert_eq!(decoded.width, 1920);
        assert_eq!(decoded.height, 1080);
        assert_eq!(decoded.monitors.len(), 1);
        assert_eq!(decoded.monitors[0].flags, 1);
    }

    #[test]
    fn reset_graphics_zero_monitors() {
        let pdu = ResetGraphicsPdu {
            width: 800,
            height: 600,
            monitors: vec![],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        let decoded = ResetGraphicsPdu::decode(&mut src).unwrap();
        assert_eq!(decoded.monitors.len(), 0);
    }

    #[test]
    fn map_surface_to_output_roundtrip() {
        let pdu = MapSurfaceToOutputPdu {
            surface_id: 1,
            output_origin_x: 100,
            output_origin_y: 200,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(MapSurfaceToOutputPdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn map_surface_to_window_roundtrip() {
        let pdu = MapSurfaceToWindowPdu {
            surface_id: 3,
            window_id: 0x1234_5678_9ABC_DEF0,
            mapped_width: 800,
            mapped_height: 600,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(MapSurfaceToWindowPdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn map_surface_to_scaled_output_roundtrip() {
        let pdu = MapSurfaceToScaledOutputPdu {
            surface_id: 2,
            output_origin_x: 0,
            output_origin_y: 0,
            target_width: 1920,
            target_height: 1080,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(MapSurfaceToScaledOutputPdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn map_surface_to_scaled_window_roundtrip() {
        let pdu = MapSurfaceToScaledWindowPdu {
            surface_id: 5,
            window_id: 42,
            mapped_width: 1024,
            mapped_height: 768,
            target_width: 2048,
            target_height: 1536,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(MapSurfaceToScaledWindowPdu::decode(&mut src).unwrap(), pdu);
    }
}
