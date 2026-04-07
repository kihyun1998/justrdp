extern crate alloc;

use alloc::vec::Vec;
use justrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use super::{GfxColor32, GfxPoint16, GfxRect16};

// ── SolidFill (MS-RDPEGFX 2.2.2.4) — Server → Client ──

/// Fill rectangles with a solid color.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolidFillPdu {
    pub surface_id: u16,
    pub fill_pixel: GfxColor32,
    pub fill_rects: Vec<GfxRect16>,
}

impl SolidFillPdu {
    /// Minimum body size: surfaceId(2) + fillPixel(4) + fillRectCount(2) = 8.
    pub const MIN_BODY_SIZE: usize = 8;
}

impl<'de> Decode<'de> for SolidFillPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let surface_id = src.read_u16_le("SolidFill::surfaceId")?;
        let fill_pixel = GfxColor32::decode(src)?;
        let count = src.read_u16_le("SolidFill::fillRectCount")?;
        let mut fill_rects = Vec::with_capacity(count as usize);
        for _ in 0..count {
            fill_rects.push(GfxRect16::decode(src)?);
        }
        Ok(Self {
            surface_id,
            fill_pixel,
            fill_rects,
        })
    }
}

impl Encode for SolidFillPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.surface_id, "SolidFill::surfaceId")?;
        self.fill_pixel.encode(dst)?;
        dst.write_u16_le(self.fill_rects.len() as u16, "SolidFill::fillRectCount")?;
        for r in &self.fill_rects {
            r.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SolidFillPdu"
    }

    fn size(&self) -> usize {
        Self::MIN_BODY_SIZE + self.fill_rects.len() * GfxRect16::WIRE_SIZE
    }
}

// ── SurfaceToSurface (MS-RDPEGFX 2.2.2.5) — Server → Client ──

/// Copy a region from one surface to another (or same surface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceToSurfacePdu {
    pub surface_id_src: u16,
    pub surface_id_dest: u16,
    pub rect_src: GfxRect16,
    pub dest_pts: Vec<GfxPoint16>,
}

impl SurfaceToSurfacePdu {
    /// Minimum body size: srcId(2) + dstId(2) + rect(8) + count(2) = 14.
    pub const MIN_BODY_SIZE: usize = 14;
}

impl<'de> Decode<'de> for SurfaceToSurfacePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let surface_id_src = src.read_u16_le("SurfaceToSurface::surfaceIdSrc")?;
        let surface_id_dest = src.read_u16_le("SurfaceToSurface::surfaceIdDest")?;
        let rect_src = GfxRect16::decode(src)?;
        let count = src.read_u16_le("SurfaceToSurface::destPtsCount")?;
        let mut dest_pts = Vec::with_capacity(count as usize);
        for _ in 0..count {
            dest_pts.push(GfxPoint16::decode(src)?);
        }
        Ok(Self {
            surface_id_src,
            surface_id_dest,
            rect_src,
            dest_pts,
        })
    }
}

impl Encode for SurfaceToSurfacePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.surface_id_src, "SurfaceToSurface::surfaceIdSrc")?;
        dst.write_u16_le(self.surface_id_dest, "SurfaceToSurface::surfaceIdDest")?;
        self.rect_src.encode(dst)?;
        dst.write_u16_le(self.dest_pts.len() as u16, "SurfaceToSurface::destPtsCount")?;
        for pt in &self.dest_pts {
            pt.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SurfaceToSurfacePdu"
    }

    fn size(&self) -> usize {
        Self::MIN_BODY_SIZE + self.dest_pts.len() * GfxPoint16::WIRE_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn solid_fill_roundtrip() {
        let pdu = SolidFillPdu {
            surface_id: 1,
            fill_pixel: GfxColor32 {
                b: 0xFF,
                g: 0x00,
                r: 0x00,
                xa: 0xFF,
            },
            fill_rects: vec![
                GfxRect16 {
                    left: 0,
                    top: 0,
                    right: 100,
                    bottom: 100,
                },
                GfxRect16 {
                    left: 200,
                    top: 200,
                    right: 300,
                    bottom: 300,
                },
            ],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(SolidFillPdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn solid_fill_zero_rects() {
        let pdu = SolidFillPdu {
            surface_id: 0,
            fill_pixel: GfxColor32 {
                b: 0,
                g: 0,
                r: 0,
                xa: 0,
            },
            fill_rects: vec![],
        };
        assert_eq!(pdu.size(), SolidFillPdu::MIN_BODY_SIZE);
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(SolidFillPdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn surface_to_surface_roundtrip() {
        let pdu = SurfaceToSurfacePdu {
            surface_id_src: 1,
            surface_id_dest: 2,
            rect_src: GfxRect16 {
                left: 10,
                top: 20,
                right: 110,
                bottom: 120,
            },
            dest_pts: vec![
                GfxPoint16 { x: 0, y: 0 },
                GfxPoint16 { x: 50, y: 50 },
            ],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(SurfaceToSurfacePdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn surface_to_surface_same_surface() {
        let pdu = SurfaceToSurfacePdu {
            surface_id_src: 5,
            surface_id_dest: 5,
            rect_src: GfxRect16 {
                left: 0,
                top: 0,
                right: 50,
                bottom: 50,
            },
            dest_pts: vec![GfxPoint16 { x: 100, y: 100 }],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(SurfaceToSurfacePdu::decode(&mut src).unwrap(), pdu);
    }
}
