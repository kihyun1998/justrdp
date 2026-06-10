//! Graphics Pipeline Extension PDUs (MS-RDPEGFX) — the EGFX dynamic channel's payload
//! format, carried over the `Microsoft::Windows::RDS::Graphics` DVC. **Server→client** bytes
//! are wrapped in RDP_SEGMENTED_DATA + RDP8 bulk encoding (zgfx, MS-RDPEGFX 3.1.9.1) — the
//! *decompression* is a codec concern (`justrdp-codecs`); **client→server** PDUs go raw
//! (segment-wrapping them gets the connection reset — real-VM-proven, slice-9). This module
//! owns the pure PDU layer plus the uncompressed segment encoder test harnesses use to build
//! server-side messages.
//!
//! One decompressed blob can carry several PDUs back to back; [`decode_all`] walks the
//! `RDPGFX_HEADER` chain. The client speaks first on this channel: a Caps Advertise right
//! after the DVC opens; the server answers with Caps Confirm and then drives the surface
//! model (create/map/draw/cache ops bracketed by Start/End Frame).

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// The dynamic channel name the server uses in its drdynvc Create Request.
pub const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Graphics";

/// `RDPGFX_CMDID_WIRETOSURFACE_1` — bitmap data for a surface, codec per `codecId`.
pub const CMDID_WIRE_TO_SURFACE_1: u16 = 0x0001;
/// `RDPGFX_CMDID_WIRETOSURFACE_2` — progressive bitmap data (context-keyed).
pub const CMDID_WIRE_TO_SURFACE_2: u16 = 0x0002;
/// `RDPGFX_CMDID_DELETEENCODINGCONTEXT`.
pub const CMDID_DELETE_ENCODING_CONTEXT: u16 = 0x0003;
/// `RDPGFX_CMDID_SOLIDFILL`.
pub const CMDID_SOLID_FILL: u16 = 0x0004;
/// `RDPGFX_CMDID_SURFACETOSURFACE`.
pub const CMDID_SURFACE_TO_SURFACE: u16 = 0x0005;
/// `RDPGFX_CMDID_SURFACETOCACHE`.
pub const CMDID_SURFACE_TO_CACHE: u16 = 0x0006;
/// `RDPGFX_CMDID_CACHETOSURFACE`.
pub const CMDID_CACHE_TO_SURFACE: u16 = 0x0007;
/// `RDPGFX_CMDID_EVICTCACHEENTRY`.
pub const CMDID_EVICT_CACHE_ENTRY: u16 = 0x0008;
/// `RDPGFX_CMDID_CREATESURFACE`.
pub const CMDID_CREATE_SURFACE: u16 = 0x0009;
/// `RDPGFX_CMDID_DELETESURFACE`.
pub const CMDID_DELETE_SURFACE: u16 = 0x000A;
/// `RDPGFX_CMDID_STARTFRAME`.
pub const CMDID_START_FRAME: u16 = 0x000B;
/// `RDPGFX_CMDID_ENDFRAME`.
pub const CMDID_END_FRAME: u16 = 0x000C;
/// `RDPGFX_CMDID_FRAMEACKNOWLEDGE` (client→server).
pub const CMDID_FRAME_ACKNOWLEDGE: u16 = 0x000D;
/// `RDPGFX_CMDID_RESETGRAPHICS`.
pub const CMDID_RESET_GRAPHICS: u16 = 0x000E;
/// `RDPGFX_CMDID_MAPSURFACETOOUTPUT`.
pub const CMDID_MAP_SURFACE_TO_OUTPUT: u16 = 0x000F;
/// `RDPGFX_CMDID_CAPSADVERTISE` (client→server).
pub const CMDID_CAPS_ADVERTISE: u16 = 0x0012;
/// `RDPGFX_CMDID_CAPSCONFIRM`.
pub const CMDID_CAPS_CONFIRM: u16 = 0x0013;

/// `RDPGFX_CAPVERSION_8` — the RemoteFX / Progressive / ClearCodec / Planar era baseline.
pub const CAPVERSION_8: u32 = 0x0008_0004;
/// `RDPGFX_CAPVERSION_81` — adds optional AVC420 (gated by [`CAPS_FLAG_AVC420_ENABLED`],
/// which justrdp does not set — no H.264 decoder).
pub const CAPVERSION_8_1: u32 = 0x0008_0105;
/// `RDPGFX_CAPVERSION_10` — the modern baseline; AVC is on by default and disabled via
/// [`CAPS_FLAG_AVC_DISABLED`].
pub const CAPVERSION_10: u32 = 0x000A_0002;

/// `RDPGFX_CAPS_FLAG_AVC420_ENABLED` (8.1): the client can decode AVC420. justrdp does not
/// set it.
pub const CAPS_FLAG_AVC420_ENABLED: u32 = 0x0000_0010;
/// `RDPGFX_CAPS_FLAG_AVC_DISABLED` (10+): the server MUST NOT use AVC — set by justrdp on
/// every 10.x capset until an H.264 decoder exists.
pub const CAPS_FLAG_AVC_DISABLED: u32 = 0x0000_0020;

/// `RDPGFX_CODECID_UNCOMPRESSED` (WireToSurface1).
pub const CODECID_UNCOMPRESSED: u16 = 0x0000;
/// `RDPGFX_CODECID_CAVIDEO` — RemoteFX, non-progressive (WireToSurface1).
pub const CODECID_CAVIDEO: u16 = 0x0003;
/// `RDPGFX_CODECID_CLEARCODEC` (WireToSurface1).
pub const CODECID_CLEARCODEC: u16 = 0x0008;
/// `RDPGFX_CODECID_CAPROGRESSIVE` — RemoteFX Progressive (WireToSurface2).
pub const CODECID_CAPROGRESSIVE: u16 = 0x0009;
/// `RDPGFX_CODECID_PLANAR` — RDP6 planar (WireToSurface1).
pub const CODECID_PLANAR: u16 = 0x000A;
/// `RDPGFX_CODECID_ALPHA` (WireToSurface1).
pub const CODECID_ALPHA: u16 = 0x000C;

/// `PIXEL_FORMAT_XRGB_8888` — 32bpp, BGRX byte order in memory, alpha ignored.
pub const PIXEL_FORMAT_XRGB_8888: u8 = 0x20;
/// `PIXEL_FORMAT_ARGB_8888` — 32bpp, BGRA byte order in memory.
pub const PIXEL_FORMAT_ARGB_8888: u8 = 0x21;

/// `QUEUE_DEPTH_UNAVAILABLE` in the Frame Acknowledge PDU.
pub const QUEUE_DEPTH_UNAVAILABLE: u32 = 0x0000_0000;

/// An inclusive-left, **exclusive**-right/bottom rectangle (`RDPGFX_RECT16`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect16 {
    /// Left edge (inclusive).
    pub left: u16,
    /// Top edge (inclusive).
    pub top: u16,
    /// Right edge (exclusive).
    pub right: u16,
    /// Bottom edge (exclusive).
    pub bottom: u16,
}

impl Rect16 {
    fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            left: cur.read_u16_le()?,
            top: cur.read_u16_le()?,
            right: cur.read_u16_le()?,
            bottom: cur.read_u16_le()?,
        })
    }

    /// Width in pixels (0 if degenerate).
    pub fn width(&self) -> u16 {
        self.right.saturating_sub(self.left)
    }

    /// Height in pixels (0 if degenerate).
    pub fn height(&self) -> u16 {
        self.bottom.saturating_sub(self.top)
    }
}

/// A signed point (`RDPGFX_POINT16`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point16 {
    /// X coordinate.
    pub x: i16,
    /// Y coordinate.
    pub y: i16,
}

impl Point16 {
    fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            x: cur.read_u16_le()? as i16,
            y: cur.read_u16_le()? as i16,
        })
    }
}

/// One server→client EGFX PDU (plus [`EgfxPdu::Unknown`] for everything justrdp does not
/// consume — well-formed-but-unknown is skipped upstream, never fatal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgfxPdu<'a> {
    /// The server's answer to the Caps Advertise: the one version it chose.
    CapsConfirm {
        /// The confirmed capability version (e.g. [`CAPVERSION_8`]).
        version: u32,
        /// The confirmed capability flags.
        flags: u32,
    },
    /// Reset the graphics output: new output size (surfaces survive, mappings reset).
    ResetGraphics {
        /// New output width in pixels.
        width: u32,
        /// New output height in pixels.
        height: u32,
    },
    /// Create an off-screen surface.
    CreateSurface {
        /// The new surface's ID.
        surface_id: u16,
        /// Surface width in pixels.
        width: u16,
        /// Surface height in pixels.
        height: u16,
        /// [`PIXEL_FORMAT_XRGB_8888`] or [`PIXEL_FORMAT_ARGB_8888`].
        pixel_format: u8,
    },
    /// Delete a surface.
    DeleteSurface {
        /// The surface to delete.
        surface_id: u16,
    },
    /// Map a surface's origin to a position in the output (screen) space.
    MapSurfaceToOutput {
        /// The surface being mapped.
        surface_id: u16,
        /// Output-space X of the surface's (0,0).
        origin_x: u32,
        /// Output-space Y of the surface's (0,0).
        origin_y: u32,
    },
    /// A logical frame begins; draw operations until the matching End Frame belong to it.
    StartFrame {
        /// The frame ID to acknowledge later.
        frame_id: u32,
    },
    /// The logical frame is complete; the client acknowledges it.
    EndFrame {
        /// The frame ID from the matching Start Frame.
        frame_id: u32,
    },
    /// Codec-compressed bitmap data targeting a surface rectangle.
    WireToSurface1 {
        /// The destination surface.
        surface_id: u16,
        /// `CODECID_*` (uncompressed / CAVIDEO / ClearCodec / planar / alpha).
        codec_id: u16,
        /// The payload's pixel format.
        pixel_format: u8,
        /// The destination rectangle in surface space.
        dest_rect: Rect16,
        /// The codec bitstream.
        data: &'a [u8],
    },
    /// Progressive bitmap data targeting a surface (tile grid is surface-absolute).
    WireToSurface2 {
        /// The destination surface.
        surface_id: u16,
        /// `CODECID_CAPROGRESSIVE`.
        codec_id: u16,
        /// The progressive codec context (per-context tile state).
        codec_context_id: u32,
        /// The payload's pixel format.
        pixel_format: u8,
        /// The progressive block stream.
        data: &'a [u8],
    },
    /// Free a progressive codec context.
    DeleteEncodingContext {
        /// The surface the context belonged to.
        surface_id: u16,
        /// The context to free.
        codec_context_id: u32,
    },
    /// Fill rectangles of a surface with one color.
    SolidFill {
        /// The destination surface.
        surface_id: u16,
        /// Fill color, wire order B, G, R, XA.
        color_bgrx: [u8; 4],
        /// The rectangles to fill (surface space).
        rects: Vec<Rect16>,
    },
    /// Copy a surface rectangle onto (possibly several) destinations.
    SurfaceToSurface {
        /// Source surface.
        src_surface_id: u16,
        /// Destination surface (may equal the source).
        dest_surface_id: u16,
        /// Source rectangle.
        src_rect: Rect16,
        /// Destination top-left corners, one copy each.
        dest_points: Vec<Point16>,
    },
    /// Store a surface rectangle in a bitmap-cache slot.
    SurfaceToCache {
        /// Source surface.
        surface_id: u16,
        /// Opaque cache key (persistent-cache concerns; stored verbatim).
        cache_key: u64,
        /// The destination cache slot.
        cache_slot: u16,
        /// Source rectangle.
        src_rect: Rect16,
    },
    /// Paste a cache slot onto (possibly several) surface positions.
    CacheToSurface {
        /// The source cache slot.
        cache_slot: u16,
        /// Destination surface.
        surface_id: u16,
        /// Destination top-left corners, one paste each.
        dest_points: Vec<Point16>,
    },
    /// Free a cache slot.
    EvictCacheEntry {
        /// The slot to free.
        cache_slot: u16,
    },
    /// A command justrdp does not consume (caps-gated AVC, window mapping, QoE, …).
    Unknown {
        /// The header's `cmdId`.
        cmd_id: u16,
    },
}

/// Decode every PDU in one decompressed EGFX blob (the `RDPGFX_HEADER` chain).
pub fn decode_all(blob: &[u8]) -> Result<Vec<EgfxPdu<'_>>, DecodeError> {
    let mut pdus = Vec::new();
    let mut rest = blob;
    while !rest.is_empty() {
        let mut cur = ReadCursor::new(rest, "RDPGFX_HEADER");
        let cmd_id = cur.read_u16_le()?;
        let _flags = cur.read_u16_le()?;
        let pdu_length = cur.read_u32_le()? as usize;
        if pdu_length < 8 || pdu_length > rest.len() {
            return Err(DecodeError::InvalidField {
                field: "RDPGFX_HEADER.pduLength",
                reason: "length does not cover the header or exceeds the blob",
            });
        }
        let body = &rest[8..pdu_length];
        pdus.push(decode_body(cmd_id, body)?);
        rest = &rest[pdu_length..];
    }
    Ok(pdus)
}

fn decode_body(cmd_id: u16, body: &[u8]) -> Result<EgfxPdu<'_>, DecodeError> {
    let mut cur = ReadCursor::new(body, "RDPGFX pdu body");
    Ok(match cmd_id {
        CMDID_CAPS_CONFIRM => {
            let version = cur.read_u32_le()?;
            let caps_data_length = cur.read_u32_le()?;
            let flags = if caps_data_length >= 4 {
                cur.read_u32_le()?
            } else {
                0
            };
            EgfxPdu::CapsConfirm { version, flags }
        }
        CMDID_RESET_GRAPHICS => {
            let width = cur.read_u32_le()?;
            let height = cur.read_u32_le()?;
            // monitorCount + monitorDefArray + padding to 340 bytes: not consumed.
            EgfxPdu::ResetGraphics { width, height }
        }
        CMDID_CREATE_SURFACE => EgfxPdu::CreateSurface {
            surface_id: cur.read_u16_le()?,
            width: cur.read_u16_le()?,
            height: cur.read_u16_le()?,
            pixel_format: cur.read_u8()?,
        },
        CMDID_DELETE_SURFACE => EgfxPdu::DeleteSurface {
            surface_id: cur.read_u16_le()?,
        },
        CMDID_MAP_SURFACE_TO_OUTPUT => {
            let surface_id = cur.read_u16_le()?;
            cur.read_u16_le()?; // reserved
            EgfxPdu::MapSurfaceToOutput {
                surface_id,
                origin_x: cur.read_u32_le()?,
                origin_y: cur.read_u32_le()?,
            }
        }
        CMDID_START_FRAME => {
            cur.read_u32_le()?; // timestamp
            EgfxPdu::StartFrame {
                frame_id: cur.read_u32_le()?,
            }
        }
        CMDID_END_FRAME => EgfxPdu::EndFrame {
            frame_id: cur.read_u32_le()?,
        },
        CMDID_WIRE_TO_SURFACE_1 => {
            let surface_id = cur.read_u16_le()?;
            let codec_id = cur.read_u16_le()?;
            let pixel_format = cur.read_u8()?;
            let dest_rect = Rect16::decode(&mut cur)?;
            let data_length = cur.read_u32_le()? as usize;
            let data = cur.read_slice(data_length)?;
            EgfxPdu::WireToSurface1 {
                surface_id,
                codec_id,
                pixel_format,
                dest_rect,
                data,
            }
        }
        CMDID_WIRE_TO_SURFACE_2 => {
            let surface_id = cur.read_u16_le()?;
            let codec_id = cur.read_u16_le()?;
            let codec_context_id = cur.read_u32_le()?;
            let pixel_format = cur.read_u8()?;
            let data = cur.read_slice(cur.remaining())?;
            EgfxPdu::WireToSurface2 {
                surface_id,
                codec_id,
                codec_context_id,
                pixel_format,
                data,
            }
        }
        CMDID_DELETE_ENCODING_CONTEXT => EgfxPdu::DeleteEncodingContext {
            surface_id: cur.read_u16_le()?,
            codec_context_id: cur.read_u32_le()?,
        },
        CMDID_SOLID_FILL => {
            let surface_id = cur.read_u16_le()?;
            let mut color_bgrx = [0u8; 4];
            color_bgrx.copy_from_slice(cur.read_slice(4)?);
            let count = usize::from(cur.read_u16_le()?);
            let mut rects = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                rects.push(Rect16::decode(&mut cur)?);
            }
            EgfxPdu::SolidFill {
                surface_id,
                color_bgrx,
                rects,
            }
        }
        CMDID_SURFACE_TO_SURFACE => {
            let src_surface_id = cur.read_u16_le()?;
            let dest_surface_id = cur.read_u16_le()?;
            let src_rect = Rect16::decode(&mut cur)?;
            let count = usize::from(cur.read_u16_le()?);
            let mut dest_points = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                dest_points.push(Point16::decode(&mut cur)?);
            }
            EgfxPdu::SurfaceToSurface {
                src_surface_id,
                dest_surface_id,
                src_rect,
                dest_points,
            }
        }
        CMDID_SURFACE_TO_CACHE => {
            let surface_id = cur.read_u16_le()?;
            let cache_key = u64::from(cur.read_u32_le()?)
                | (u64::from(cur.read_u32_le()?) << 32);
            let cache_slot = cur.read_u16_le()?;
            let src_rect = Rect16::decode(&mut cur)?;
            EgfxPdu::SurfaceToCache {
                surface_id,
                cache_key,
                cache_slot,
                src_rect,
            }
        }
        CMDID_CACHE_TO_SURFACE => {
            let cache_slot = cur.read_u16_le()?;
            let surface_id = cur.read_u16_le()?;
            let count = usize::from(cur.read_u16_le()?);
            let mut dest_points = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                dest_points.push(Point16::decode(&mut cur)?);
            }
            EgfxPdu::CacheToSurface {
                cache_slot,
                surface_id,
                dest_points,
            }
        }
        CMDID_EVICT_CACHE_ENTRY => EgfxPdu::EvictCacheEntry {
            cache_slot: cur.read_u16_le()?,
        },
        cmd_id => EgfxPdu::Unknown { cmd_id },
    })
}

fn header(cmd_id: u16, body_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body_len);
    out.extend_from_slice(&cmd_id.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&((8 + body_len) as u32).to_le_bytes());
    out
}

/// Encode the client's Caps Advertise (MS-RDPEGFX 2.2.2.16): one capset per
/// `(version, flags)` pair, in preference order.
pub fn encode_caps_advertise(capsets: &[(u32, u32)]) -> Vec<u8> {
    let body_len = 2 + capsets.len() * 12;
    let mut out = header(CMDID_CAPS_ADVERTISE, body_len);
    out.extend_from_slice(&(capsets.len() as u16).to_le_bytes());
    for (version, flags) in capsets {
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&4u32.to_le_bytes()); // capsDataLength
        out.extend_from_slice(&flags.to_le_bytes());
    }
    out
}

/// Encode the client's Frame Acknowledge (2.2.2.13).
pub fn encode_frame_acknowledge(frame_id: u32, total_frames_decoded: u32) -> Vec<u8> {
    let mut out = header(CMDID_FRAME_ACKNOWLEDGE, 12);
    out.extend_from_slice(&QUEUE_DEPTH_UNAVAILABLE.to_le_bytes());
    out.extend_from_slice(&frame_id.to_le_bytes());
    out.extend_from_slice(&total_frames_decoded.to_le_bytes());
    out
}

/// Wrap an EGFX blob as RDP_SEGMENTED_DATA carrying **uncompressed** RDP8 bulk segments
/// (MS-RDPEGFX 2.2.5; descriptor `0xE0` single / `0xE1` multipart, bulk header `0x04` = RDP8
/// type with the COMPRESSED flag clear).
///
/// Segmentation is **asymmetric**: only server→client EGFX traffic is segmented; the client
/// sends its PDUs (Caps Advertise, Frame Acknowledge) raw — a segment-wrapped client PDU
/// gets the connection reset (real-VM-proven, slice-9). This encoder therefore serves test
/// harnesses building server→client messages, not the client send path.
pub fn wrap_uncompressed(blob: &[u8]) -> Vec<u8> {
    const SEGMENT_MAX: usize = 65535;
    if blob.len() <= SEGMENT_MAX {
        let mut out = Vec::with_capacity(2 + blob.len());
        out.push(0xE0);
        out.push(0x04);
        out.extend_from_slice(blob);
        return out;
    }
    let segments: Vec<&[u8]> = blob.chunks(SEGMENT_MAX).collect();
    let mut out = Vec::with_capacity(7 + blob.len() + segments.len() * 5);
    out.push(0xE1);
    out.extend_from_slice(&(segments.len() as u16).to_le_bytes());
    out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    for segment in segments {
        out.extend_from_slice(&((segment.len() + 1) as u32).to_le_bytes());
        out.push(0x04);
        out.extend_from_slice(segment);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pdu(cmd_id: u16, body: &[u8]) -> Vec<u8> {
        let mut out = header(cmd_id, body.len());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn decode_all_walks_the_header_chain() {
        let mut blob = pdu(CMDID_START_FRAME, &[0, 0, 0, 0, 7, 0, 0, 0]);
        blob.extend_from_slice(&pdu(CMDID_END_FRAME, &[7, 0, 0, 0]));
        let pdus = decode_all(&blob).unwrap();
        assert_eq!(
            pdus,
            vec![
                EgfxPdu::StartFrame { frame_id: 7 },
                EgfxPdu::EndFrame { frame_id: 7 },
            ]
        );
    }

    #[test]
    fn bad_pdu_length_is_a_typed_error() {
        let mut blob = pdu(CMDID_END_FRAME, &[7, 0, 0, 0]);
        blob[4] = 200; // pduLength beyond the blob
        assert!(decode_all(&blob).is_err());
        let mut blob = pdu(CMDID_END_FRAME, &[7, 0, 0, 0]);
        blob[4] = 4; // pduLength under the 8-byte header
        assert!(decode_all(&blob).is_err());
    }

    #[test]
    fn create_map_and_reset_decode() {
        let mut body = Vec::new();
        body.extend_from_slice(&3u16.to_le_bytes());
        body.extend_from_slice(&1280u16.to_le_bytes());
        body.extend_from_slice(&1024u16.to_le_bytes());
        body.push(PIXEL_FORMAT_XRGB_8888);
        let blob = pdu(CMDID_CREATE_SURFACE, &body);
        let pdus = decode_all(&blob).unwrap();
        assert_eq!(
            pdus[0],
            EgfxPdu::CreateSurface {
                surface_id: 3,
                width: 1280,
                height: 1024,
                pixel_format: PIXEL_FORMAT_XRGB_8888,
            }
        );

        let mut body = Vec::new();
        body.extend_from_slice(&3u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&100u32.to_le_bytes());
        body.extend_from_slice(&50u32.to_le_bytes());
        let blob = pdu(CMDID_MAP_SURFACE_TO_OUTPUT, &body);
        let pdus = decode_all(&blob).unwrap();
        assert_eq!(
            pdus[0],
            EgfxPdu::MapSurfaceToOutput {
                surface_id: 3,
                origin_x: 100,
                origin_y: 50,
            }
        );

        // ResetGraphics carries monitor defs + padding to 340 bytes; only w/h are consumed.
        let mut body = vec![0u8; 332];
        body[0..4].copy_from_slice(&1024u32.to_le_bytes());
        body[4..8].copy_from_slice(&768u32.to_le_bytes());
        body[8..12].copy_from_slice(&1u32.to_le_bytes());
        let blob = pdu(CMDID_RESET_GRAPHICS, &body);
        let pdus = decode_all(&blob).unwrap();
        assert_eq!(
            pdus[0],
            EgfxPdu::ResetGraphics {
                width: 1024,
                height: 768,
            }
        );
    }

    #[test]
    fn wire_to_surface_1_and_2_decode() {
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_le_bytes());
        body.extend_from_slice(&CODECID_UNCOMPRESSED.to_le_bytes());
        body.push(PIXEL_FORMAT_XRGB_8888);
        for v in [0u16, 0, 2, 1] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(&8u32.to_le_bytes());
        body.extend_from_slice(&[1, 2, 3, 255, 4, 5, 6, 255]);
        let blob = pdu(CMDID_WIRE_TO_SURFACE_1, &body);
        let pdus = decode_all(&blob).unwrap();
        let EgfxPdu::WireToSurface1 {
            surface_id: 5,
            codec_id: CODECID_UNCOMPRESSED,
            dest_rect,
            data,
            ..
        } = pdus[0]
        else {
            panic!("expected WTS1, got {pdus:?}");
        };
        assert_eq!((dest_rect.width(), dest_rect.height()), (2, 1));
        assert_eq!(data.len(), 8);

        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_le_bytes());
        body.extend_from_slice(&CODECID_CAPROGRESSIVE.to_le_bytes());
        body.extend_from_slice(&9u32.to_le_bytes());
        body.push(PIXEL_FORMAT_XRGB_8888);
        body.extend_from_slice(&[0xAA; 16]);
        let blob = pdu(CMDID_WIRE_TO_SURFACE_2, &body);
        let pdus = decode_all(&blob).unwrap();
        assert!(matches!(
            pdus[0],
            EgfxPdu::WireToSurface2 {
                surface_id: 5,
                codec_id: CODECID_CAPROGRESSIVE,
                codec_context_id: 9,
                data: &[0xAA, ..],
                ..
            }
        ));
    }

    #[test]
    fn blit_and_cache_ops_decode() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&[10, 20, 30, 0]);
        body.extend_from_slice(&2u16.to_le_bytes());
        for r in [[0u16, 0, 4, 4], [8, 8, 16, 12]] {
            for v in r {
                body.extend_from_slice(&v.to_le_bytes());
            }
        }
        let blob = pdu(CMDID_SOLID_FILL, &body);
        let pdus = decode_all(&blob).unwrap();
        let EgfxPdu::SolidFill {
            surface_id: 1,
            color_bgrx: [10, 20, 30, 0],
            ref rects,
        } = pdus[0]
        else {
            panic!("expected SolidFill");
        };
        assert_eq!(rects.len(), 2);

        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&0xDEAD_BEEF_CAFE_F00Du64.to_le_bytes());
        body.extend_from_slice(&3u16.to_le_bytes());
        for v in [0u16, 0, 8, 8] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        let blob = pdu(CMDID_SURFACE_TO_CACHE, &body);
        let pdus = decode_all(&blob).unwrap();
        assert!(matches!(
            pdus[0],
            EgfxPdu::SurfaceToCache {
                surface_id: 1,
                cache_key: 0xDEAD_BEEF_CAFE_F00D,
                cache_slot: 3,
                ..
            }
        ));

        let mut body = Vec::new();
        body.extend_from_slice(&3u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [32i16, -4] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        let blob = pdu(CMDID_CACHE_TO_SURFACE, &body);
        let pdus = decode_all(&blob).unwrap();
        let EgfxPdu::CacheToSurface {
            cache_slot: 3,
            surface_id: 1,
            ref dest_points,
        } = pdus[0]
        else {
            panic!("expected CacheToSurface");
        };
        assert_eq!(dest_points[0], Point16 { x: 32, y: -4 });
    }

    #[test]
    fn unknown_commands_are_surfaced_not_fatal() {
        let blob = pdu(0x0016, &[0; 8]); // QoE frame ack
        let pdus = decode_all(&blob).unwrap();
        assert_eq!(pdus[0], EgfxPdu::Unknown { cmd_id: 0x0016 });
    }

    #[test]
    fn caps_advertise_and_frame_ack_wire_shape() {
        let adv = encode_caps_advertise(&[(CAPVERSION_8, 0)]);
        assert_eq!(adv.len(), 8 + 2 + 12);
        assert_eq!(&adv[0..2], &CMDID_CAPS_ADVERTISE.to_le_bytes());
        assert_eq!(&adv[4..8], &(adv.len() as u32).to_le_bytes());
        assert_eq!(&adv[8..10], &1u16.to_le_bytes());
        assert_eq!(&adv[10..14], &CAPVERSION_8.to_le_bytes());
        assert_eq!(&adv[14..18], &4u32.to_le_bytes());

        let ack = encode_frame_acknowledge(7, 42);
        assert_eq!(ack.len(), 20);
        assert_eq!(&ack[8..12], &QUEUE_DEPTH_UNAVAILABLE.to_le_bytes());
        assert_eq!(&ack[12..16], &7u32.to_le_bytes());
        assert_eq!(&ack[16..20], &42u32.to_le_bytes());
    }

    #[test]
    fn wrap_uncompressed_single_and_multipart() {
        let single = wrap_uncompressed(&[1, 2, 3]);
        assert_eq!(single, vec![0xE0, 0x04, 1, 2, 3]);

        let big = vec![7u8; 70000];
        let multi = wrap_uncompressed(&big);
        assert_eq!(multi[0], 0xE1);
        assert_eq!(u16::from_le_bytes([multi[1], multi[2]]), 2);
        assert_eq!(
            u32::from_le_bytes([multi[3], multi[4], multi[5], multi[6]]),
            70000
        );
        // First segment: size covers the bulk-header byte + 65535 data bytes.
        assert_eq!(
            u32::from_le_bytes([multi[7], multi[8], multi[9], multi[10]]),
            65536
        );
        assert_eq!(multi[11], 0x04);
    }

    #[test]
    fn caps_confirm_decodes() {
        let mut body = Vec::new();
        body.extend_from_slice(&CAPVERSION_8.to_le_bytes());
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let blob = pdu(CMDID_CAPS_CONFIRM, &body);
        let pdus = decode_all(&blob).unwrap();
        assert_eq!(
            pdus[0],
            EgfxPdu::CapsConfirm {
                version: CAPVERSION_8,
                flags: 0,
            }
        );
    }
}
