extern crate alloc;

use alloc::vec::Vec;
use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use super::{GfxPixelFormat, GfxRect16, RdpgfxHeader};

/// Maximum bitmap data size (32 MB) to prevent memory exhaustion from untrusted input.
const MAX_BITMAP_DATA_SIZE: u32 = 32 * 1024 * 1024;

// ── WireToSurface1 (MS-RDPEGFX 2.2.2.1) — Server → Client ──

/// Codec-based bitmap transfer.
///
/// ```text
/// Offset  Size  Field
/// 8       2     surfaceId
/// 10      2     codecId
/// 12      1     pixelFormat
/// 13      8     destRect
/// 21      4     bitmapDataLength
/// 25      var   bitmapData
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireToSurface1Pdu {
    pub surface_id: u16,
    pub codec_id: u16,
    pub pixel_format: GfxPixelFormat,
    pub dest_rect: GfxRect16,
    pub bitmap_data: Vec<u8>,
}

impl WireToSurface1Pdu {
    /// Minimum body size: 2+2+1+8+4 = 17 (excluding header).
    pub const MIN_BODY_SIZE: usize = 17;
}

impl<'de> Decode<'de> for WireToSurface1Pdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let surface_id = src.read_u16_le("WireToSurface1::surfaceId")?;
        let codec_id = src.read_u16_le("WireToSurface1::codecId")?;
        let pixel_format = GfxPixelFormat::decode(src)?;
        let dest_rect = GfxRect16::decode(src)?;
        let bitmap_data_length = src.read_u32_le("WireToSurface1::bitmapDataLength")?;
        if bitmap_data_length > MAX_BITMAP_DATA_SIZE {
            return Err(DecodeError::invalid_value("WireToSurface1Pdu", "bitmapDataLength"));
        }
        let data = src.read_slice(bitmap_data_length as usize, "WireToSurface1::bitmapData")?;
        Ok(Self {
            surface_id,
            codec_id,
            pixel_format,
            dest_rect,
            bitmap_data: data.to_vec(),
        })
    }
}

impl Encode for WireToSurface1Pdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.surface_id, "WireToSurface1::surfaceId")?;
        dst.write_u16_le(self.codec_id, "WireToSurface1::codecId")?;
        self.pixel_format.encode(dst)?;
        self.dest_rect.encode(dst)?;
        dst.write_u32_le(self.bitmap_data.len() as u32, "WireToSurface1::bitmapDataLength")?;
        dst.write_slice(&self.bitmap_data, "WireToSurface1::bitmapData")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "WireToSurface1Pdu"
    }

    fn size(&self) -> usize {
        Self::MIN_BODY_SIZE + self.bitmap_data.len()
    }
}

// ── WireToSurface2 (MS-RDPEGFX 2.2.2.2) — Server → Client ──

/// Context-based bitmap transfer (Progressive RFX only).
///
/// ```text
/// Offset  Size  Field
/// 8       2     surfaceId
/// 10      2     codecId (MUST = 0x0009)
/// 12      4     codecContextId
/// 16      1     pixelFormat
/// 17      4     bitmapDataLength
/// 21      var   bitmapData
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireToSurface2Pdu {
    pub surface_id: u16,
    pub codec_id: u16,
    pub codec_context_id: u32,
    pub pixel_format: GfxPixelFormat,
    pub bitmap_data: Vec<u8>,
}

impl WireToSurface2Pdu {
    /// Minimum body size: 2+2+4+1+4 = 13 (excluding header).
    pub const MIN_BODY_SIZE: usize = 13;
}

impl<'de> Decode<'de> for WireToSurface2Pdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let surface_id = src.read_u16_le("WireToSurface2::surfaceId")?;
        let codec_id = src.read_u16_le("WireToSurface2::codecId")?;
        let codec_context_id = src.read_u32_le("WireToSurface2::codecContextId")?;
        let pixel_format = GfxPixelFormat::decode(src)?;
        let bitmap_data_length = src.read_u32_le("WireToSurface2::bitmapDataLength")?;
        if bitmap_data_length > MAX_BITMAP_DATA_SIZE {
            return Err(DecodeError::invalid_value("WireToSurface2Pdu", "bitmapDataLength"));
        }
        let data = src.read_slice(bitmap_data_length as usize, "WireToSurface2::bitmapData")?;
        Ok(Self {
            surface_id,
            codec_id,
            codec_context_id,
            pixel_format,
            bitmap_data: data.to_vec(),
        })
    }
}

impl Encode for WireToSurface2Pdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.surface_id, "WireToSurface2::surfaceId")?;
        dst.write_u16_le(self.codec_id, "WireToSurface2::codecId")?;
        dst.write_u32_le(self.codec_context_id, "WireToSurface2::codecContextId")?;
        self.pixel_format.encode(dst)?;
        dst.write_u32_le(self.bitmap_data.len() as u32, "WireToSurface2::bitmapDataLength")?;
        dst.write_slice(&self.bitmap_data, "WireToSurface2::bitmapData")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "WireToSurface2Pdu"
    }

    fn size(&self) -> usize {
        Self::MIN_BODY_SIZE + self.bitmap_data.len()
    }
}

// ── DeleteEncodingContext (MS-RDPEGFX 2.2.2.3) — Server → Client ──

/// Delete a persistent encoding context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteEncodingContextPdu {
    pub surface_id: u16,
    pub codec_context_id: u32,
}

impl DeleteEncodingContextPdu {
    pub const WIRE_SIZE: usize = RdpgfxHeader::WIRE_SIZE + 6;
}

impl<'de> Decode<'de> for DeleteEncodingContextPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            surface_id: src.read_u16_le("DeleteEncodingContext::surfaceId")?,
            codec_context_id: src.read_u32_le("DeleteEncodingContext::codecContextId")?,
        })
    }
}

impl Encode for DeleteEncodingContextPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.surface_id, "DeleteEncodingContext::surfaceId")?;
        dst.write_u32_le(self.codec_context_id, "DeleteEncodingContext::codecContextId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DeleteEncodingContextPdu"
    }

    fn size(&self) -> usize {
        6
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn wire_to_surface1_roundtrip() {
        let pdu = WireToSurface1Pdu {
            surface_id: 1,
            codec_id: 0x000A, // Planar
            pixel_format: GfxPixelFormat::XRGB_8888,
            dest_rect: GfxRect16 {
                left: 0,
                top: 0,
                right: 64,
                bottom: 64,
            },
            bitmap_data: vec![0xAA; 128],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(WireToSurface1Pdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn wire_to_surface1_empty_bitmap() {
        let pdu = WireToSurface1Pdu {
            surface_id: 0,
            codec_id: 0x0000,
            pixel_format: GfxPixelFormat::XRGB_8888,
            dest_rect: GfxRect16 {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
            bitmap_data: vec![],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(WireToSurface1Pdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn wire_to_surface2_roundtrip() {
        let pdu = WireToSurface2Pdu {
            surface_id: 2,
            codec_id: 0x0009, // CAPROGRESSIVE
            codec_context_id: 100,
            pixel_format: GfxPixelFormat::XRGB_8888,
            bitmap_data: vec![0xBB; 256],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(WireToSurface2Pdu::decode(&mut src).unwrap(), pdu);
    }

    #[test]
    fn delete_encoding_context_roundtrip() {
        let pdu = DeleteEncodingContextPdu {
            surface_id: 5,
            codec_context_id: 42,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(DeleteEncodingContextPdu::decode(&mut src).unwrap(), pdu);
    }
}
