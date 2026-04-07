extern crate alloc;

use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

mod caps;
mod surface;
mod bitmap;
mod draw;
mod cache;
mod frame;
pub mod avc;

pub use caps::*;
pub use surface::*;
pub use bitmap::*;
pub use draw::*;
pub use cache::*;
pub use frame::*;
pub use avc::*;

// ── Command IDs (MS-RDPEGFX 2.2.1.5) ──

/// WireToSurface1 -- codec-based bitmap transfer.
pub const RDPGFX_CMDID_WIRETOSURFACE_1: u16 = 0x0001;
/// WireToSurface2 -- context-based bitmap transfer (Progressive RFX).
pub const RDPGFX_CMDID_WIRETOSURFACE_2: u16 = 0x0002;
/// DeleteEncodingContext.
pub const RDPGFX_CMDID_DELETEENCODINGCONTEXT: u16 = 0x0003;
/// SolidFill.
pub const RDPGFX_CMDID_SOLIDFILL: u16 = 0x0004;
/// SurfaceToSurface.
pub const RDPGFX_CMDID_SURFACETOSURFACE: u16 = 0x0005;
/// SurfaceToCache.
pub const RDPGFX_CMDID_SURFACETOCACHE: u16 = 0x0006;
/// CacheToSurface.
pub const RDPGFX_CMDID_CACHETOSURFACE: u16 = 0x0007;
/// EvictCacheEntry.
pub const RDPGFX_CMDID_EVICTCACHEENTRY: u16 = 0x0008;
/// CreateSurface.
pub const RDPGFX_CMDID_CREATESURFACE: u16 = 0x0009;
/// DeleteSurface.
pub const RDPGFX_CMDID_DELETESURFACE: u16 = 0x000A;
/// StartFrame.
pub const RDPGFX_CMDID_STARTFRAME: u16 = 0x000B;
/// EndFrame.
pub const RDPGFX_CMDID_ENDFRAME: u16 = 0x000C;
/// FrameAcknowledge.
pub const RDPGFX_CMDID_FRAMEACKNOWLEDGE: u16 = 0x000D;
/// ResetGraphics.
pub const RDPGFX_CMDID_RESETGRAPHICS: u16 = 0x000E;
/// MapSurfaceToOutput.
pub const RDPGFX_CMDID_MAPSURFACETOOUTPUT: u16 = 0x000F;
/// CacheImportOffer.
pub const RDPGFX_CMDID_CACHEIMPORTOFFER: u16 = 0x0010;
/// CacheImportReply.
pub const RDPGFX_CMDID_CACHEIMPORTREPLY: u16 = 0x0011;
/// CapsAdvertise.
pub const RDPGFX_CMDID_CAPSADVERTISE: u16 = 0x0012;
/// CapsConfirm.
pub const RDPGFX_CMDID_CAPSCONFIRM: u16 = 0x0013;
// Note: 0x0014 is absent from the spec.
/// MapSurfaceToWindow.
pub const RDPGFX_CMDID_MAPSURFACETOWINDOW: u16 = 0x0015;
/// QoE FrameAcknowledge.
pub const RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE: u16 = 0x0016;
/// MapSurfaceToScaledOutput.
pub const RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT: u16 = 0x0017;
/// MapSurfaceToScaledWindow.
pub const RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW: u16 = 0x0018;

// ── Codec IDs (MS-RDPEGFX 2.2.2.1) ──

/// Raw uncompressed pixels.
pub const RDPGFX_CODECID_UNCOMPRESSED: u16 = 0x0000;
/// RemoteFX Codec (MS-RDPRFX).
pub const RDPGFX_CODECID_CAVIDEO: u16 = 0x0003;
/// ClearCodec (MS-RDPEGFX 2.2.4.1).
pub const RDPGFX_CODECID_CLEARCODEC: u16 = 0x0008;
/// RemoteFX Progressive Codec (WireToSurface2 only).
pub const RDPGFX_CODECID_CAPROGRESSIVE: u16 = 0x0009;
/// Planar Codec (MS-RDPEGDI 2.2.2.5.1).
pub const RDPGFX_CODECID_PLANAR: u16 = 0x000A;
/// MPEG-4 AVC/H.264 YUV420p.
pub const RDPGFX_CODECID_AVC420: u16 = 0x000B;
/// Alpha Codec (MS-RDPEGFX 2.2.4.3).
pub const RDPGFX_CODECID_ALPHA: u16 = 0x000C;
/// MPEG-4 AVC/H.264 YUV444.
pub const RDPGFX_CODECID_AVC444: u16 = 0x000E;
/// MPEG-4 AVC/H.264 YUV444v2.
pub const RDPGFX_CODECID_AVC444V2: u16 = 0x000F;

// ── Pixel Formats (MS-RDPEGFX 2.2.1.4) ──

/// 32bpp XRGB, no valid alpha.
pub const PIXEL_FORMAT_XRGB_8888: u8 = 0x20;
/// 32bpp ARGB, valid alpha.
pub const PIXEL_FORMAT_ARGB_8888: u8 = 0x21;

// ── Capability Versions (MS-RDPEGFX 2.2.1.6) ──

/// Version 8.0.
pub const RDPGFX_CAPVERSION_8: u32 = 0x0008_0004;
/// Version 8.1.
pub const RDPGFX_CAPVERSION_81: u32 = 0x0008_0105;
/// Version 10.0.
pub const RDPGFX_CAPVERSION_10: u32 = 0x000A_0002;
/// Version 10.1.
pub const RDPGFX_CAPVERSION_101: u32 = 0x000A_0100;
/// Version 10.2.
pub const RDPGFX_CAPVERSION_102: u32 = 0x000A_0200;
/// Version 10.3.
pub const RDPGFX_CAPVERSION_103: u32 = 0x000A_0301;
/// Version 10.4.
pub const RDPGFX_CAPVERSION_104: u32 = 0x000A_0400;
/// Version 10.5.
pub const RDPGFX_CAPVERSION_105: u32 = 0x000A_0502;
/// Version 10.6.
pub const RDPGFX_CAPVERSION_106: u32 = 0x000A_0600;
/// Version 10.7.
pub const RDPGFX_CAPVERSION_107: u32 = 0x000A_0701;

// ── Capability Flags (MS-RDPEGFX 2.2.3) ──

/// Bitmap cache constrained to 16 MB; use RemoteFX instead of Progressive.
pub const RDPGFX_CAPS_FLAG_THINCLIENT: u32 = 0x0000_0001;
/// Bitmap cache constrained to 16 MB.
pub const RDPGFX_CAPS_FLAG_SMALL_CACHE: u32 = 0x0000_0002;
/// AVC/H.264 YUV420p supported (VERSION81 only).
pub const RDPGFX_CAPS_FLAG_AVC420_ENABLED: u32 = 0x0000_0010;
/// AVC/H.264 NOT supported.
pub const RDPGFX_CAPS_FLAG_AVC_DISABLED: u32 = 0x0000_0020;
/// Prefer AVC/H.264 YUV444; MUST NOT coexist with AVC_DISABLED.
pub const RDPGFX_CAPS_FLAG_AVC_THINCLIENT: u32 = 0x0000_0040;
/// MapSurfaceToScaledOutput/Window not supported (VERSION107 only).
pub const RDPGFX_CAPS_FLAG_SCALEDMAP_DISABLE: u32 = 0x0000_0080;

// ── Frame Acknowledge Sentinels (MS-RDPEGFX 2.2.2.13) ──

/// No queue depth info available.
pub const QUEUE_DEPTH_UNAVAILABLE: u32 = 0x0000_0000;
/// Client suspends frame acknowledgement.
pub const SUSPEND_FRAME_ACKNOWLEDGEMENT: u32 = 0xFFFF_FFFF;

// ── RDPGFX_HEADER (MS-RDPEGFX 2.2.1.5) ──

/// RDPGFX command header: 8 bytes.
///
/// ```text
/// Offset  Size  Field
/// 0       2     cmdId (u16 LE)
/// 2       2     flags (u16 LE) — MUST be 0x0000
/// 4       4     pduLength (u32 LE) — includes header
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdpgfxHeader {
    pub cmd_id: u16,
    pub flags: u16,
    pub pdu_length: u32,
}

impl RdpgfxHeader {
    /// Wire size of the header.
    pub const WIRE_SIZE: usize = 8;
}

impl Encode for RdpgfxHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.cmd_id, "RdpgfxHeader::cmdId")?;
        dst.write_u16_le(self.flags, "RdpgfxHeader::flags")?;
        dst.write_u32_le(self.pdu_length, "RdpgfxHeader::pduLength")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RdpgfxHeader"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for RdpgfxHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let cmd_id = src.read_u16_le("RdpgfxHeader::cmdId")?;
        let flags = src.read_u16_le("RdpgfxHeader::flags")?;
        let pdu_length = src.read_u32_le("RdpgfxHeader::pduLength")?;

        if pdu_length < Self::WIRE_SIZE as u32 {
            return Err(DecodeError::invalid_value("RdpgfxHeader", "pduLength"));
        }

        Ok(Self {
            cmd_id,
            flags,
            pdu_length,
        })
    }
}

// ── RDPGFX_POINT16 (MS-RDPEGFX 2.2.1.1) ──

/// 16-bit point with signed coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GfxPoint16 {
    pub x: i16,
    pub y: i16,
}

impl GfxPoint16 {
    pub const WIRE_SIZE: usize = 4;
}

impl Encode for GfxPoint16 {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_i16_le(self.x, "GfxPoint16::x")?;
        dst.write_i16_le(self.y, "GfxPoint16::y")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "GfxPoint16"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for GfxPoint16 {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            x: src.read_i16_le("GfxPoint16::x")?,
            y: src.read_i16_le("GfxPoint16::y")?,
        })
    }
}

// ── RDPGFX_RECT16 (MS-RDPEGFX 2.2.1.2) ──

/// 16-bit rectangle with exclusive right/bottom bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GfxRect16 {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

impl GfxRect16 {
    pub const WIRE_SIZE: usize = 8;
}

impl Encode for GfxRect16 {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.left, "GfxRect16::left")?;
        dst.write_u16_le(self.top, "GfxRect16::top")?;
        dst.write_u16_le(self.right, "GfxRect16::right")?;
        dst.write_u16_le(self.bottom, "GfxRect16::bottom")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "GfxRect16"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for GfxRect16 {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            left: src.read_u16_le("GfxRect16::left")?,
            top: src.read_u16_le("GfxRect16::top")?,
            right: src.read_u16_le("GfxRect16::right")?,
            bottom: src.read_u16_le("GfxRect16::bottom")?,
        })
    }
}

// ── RDPGFX_COLOR32 (MS-RDPEGFX 2.2.1.3) ──

/// 32-bit color in B, G, R, XA wire order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GfxColor32 {
    pub b: u8,
    pub g: u8,
    pub r: u8,
    pub xa: u8,
}

impl GfxColor32 {
    pub const WIRE_SIZE: usize = 4;
}

impl Encode for GfxColor32 {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(self.b, "GfxColor32::B")?;
        dst.write_u8(self.g, "GfxColor32::G")?;
        dst.write_u8(self.r, "GfxColor32::R")?;
        dst.write_u8(self.xa, "GfxColor32::XA")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "GfxColor32"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for GfxColor32 {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            b: src.read_u8("GfxColor32::B")?,
            g: src.read_u8("GfxColor32::G")?,
            r: src.read_u8("GfxColor32::R")?,
            xa: src.read_u8("GfxColor32::XA")?,
        })
    }
}

// ── RDPGFX_PIXELFORMAT (MS-RDPEGFX 2.2.1.4) ──

/// Pixel format (1 byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GfxPixelFormat(pub u8);

impl GfxPixelFormat {
    pub const XRGB_8888: Self = Self(PIXEL_FORMAT_XRGB_8888);
    pub const ARGB_8888: Self = Self(PIXEL_FORMAT_ARGB_8888);
    pub const WIRE_SIZE: usize = 1;

    pub fn is_valid(self) -> bool {
        matches!(self.0, PIXEL_FORMAT_XRGB_8888 | PIXEL_FORMAT_ARGB_8888)
    }
}

impl Encode for GfxPixelFormat {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(self.0, "GfxPixelFormat")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "GfxPixelFormat"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for GfxPixelFormat {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let val = src.read_u8("GfxPixelFormat")?;
        let fmt = Self(val);
        if !fmt.is_valid() {
            return Err(DecodeError::invalid_value("GfxPixelFormat", "format"));
        }
        Ok(fmt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn header_roundtrip() {
        let hdr = RdpgfxHeader {
            cmd_id: RDPGFX_CMDID_STARTFRAME,
            flags: 0,
            pdu_length: 16,
        };
        let mut buf = vec![0u8; hdr.size()];
        let mut dst = WriteCursor::new(&mut buf);
        hdr.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        let decoded = RdpgfxHeader::decode(&mut src).unwrap();
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn header_reject_short_pdu_length() {
        // pduLength = 4 < 8 minimum
        let data = [0x0B, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00];
        let mut src = ReadCursor::new(&data);
        assert!(RdpgfxHeader::decode(&mut src).is_err());
    }

    #[test]
    fn point16_roundtrip() {
        let pt = GfxPoint16 { x: -100, y: 200 };
        let mut buf = vec![0u8; pt.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pt.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(GfxPoint16::decode(&mut src).unwrap(), pt);
    }

    #[test]
    fn rect16_roundtrip() {
        let rect = GfxRect16 {
            left: 10,
            top: 20,
            right: 100,
            bottom: 200,
        };
        let mut buf = vec![0u8; rect.size()];
        let mut dst = WriteCursor::new(&mut buf);
        rect.encode(&mut dst).unwrap();
        let mut src = ReadCursor::new(&buf);
        assert_eq!(GfxRect16::decode(&mut src).unwrap(), rect);
    }

    #[test]
    fn color32_wire_order_bgr() {
        let color = GfxColor32 {
            b: 0xFF,
            g: 0x80,
            r: 0x00,
            xa: 0xAA,
        };
        let mut buf = vec![0u8; color.size()];
        let mut dst = WriteCursor::new(&mut buf);
        color.encode(&mut dst).unwrap();
        assert_eq!(buf, [0xFF, 0x80, 0x00, 0xAA]);
    }

    #[test]
    fn pixel_format_valid() {
        assert!(GfxPixelFormat::XRGB_8888.is_valid());
        assert!(GfxPixelFormat::ARGB_8888.is_valid());
        assert!(!GfxPixelFormat(0x00).is_valid());
    }

    #[test]
    fn pixel_format_reject_invalid() {
        let data = [0x00];
        let mut src = ReadCursor::new(&data);
        assert!(GfxPixelFormat::decode(&mut src).is_err());
    }

    #[test]
    fn command_id_constants() {
        assert_eq!(RDPGFX_CMDID_WIRETOSURFACE_1, 0x0001);
        assert_eq!(RDPGFX_CMDID_WIRETOSURFACE_2, 0x0002);
        assert_eq!(RDPGFX_CMDID_CAPSADVERTISE, 0x0012);
        assert_eq!(RDPGFX_CMDID_CAPSCONFIRM, 0x0013);
        assert_eq!(RDPGFX_CMDID_MAPSURFACETOWINDOW, 0x0015); // 0x0014 absent
        assert_eq!(RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW, 0x0018);
    }

    #[test]
    fn codec_id_constants() {
        assert_eq!(RDPGFX_CODECID_UNCOMPRESSED, 0x0000);
        assert_eq!(RDPGFX_CODECID_CAVIDEO, 0x0003);
        assert_eq!(RDPGFX_CODECID_CLEARCODEC, 0x0008);
        assert_eq!(RDPGFX_CODECID_CAPROGRESSIVE, 0x0009);
        assert_eq!(RDPGFX_CODECID_AVC444V2, 0x000F);
    }

    #[test]
    fn capability_version_constants() {
        assert_eq!(RDPGFX_CAPVERSION_8, 0x0008_0004);
        assert_eq!(RDPGFX_CAPVERSION_107, 0x000A_0701);
    }
}
