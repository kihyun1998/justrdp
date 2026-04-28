#![forbid(unsafe_code)]

//! Rendering: [`FrameSink`] trait + bitmap fast-path dispatcher.
//!
//! Supported bitmap inputs:
//! * Uncompressed 32 bpp BGRA (S3b).
//! * Uncompressed and **Interleaved RLE** compressed 24 bpp (BGR), 16 bpp
//!   (RGB565), and 15 bpp (RGB555) — added in S3c via
//!   [`justrdp_graphics::RleDecompressor`]. After decompression each bpp
//!   variant is converted to top-down RGBA in a single pass.
//! * 8 bpp (palette-indexed) and Planar/RemoteFX/NSCodec/AVC are still
//!   surfaced as typed errors and left for later steps.
//!
//! # Wire → sink conversions, in one pass
//!
//! RDP fast-path bitmap rectangles are **bottom-up DIBs** — the first
//! `width * (bpp/8)` bytes of the wire data describe the *bottom* row of
//! the destination rectangle. The wire byte order is **BGRA**, while the
//! `ImageData` API used by `<canvas>` expects **RGBA**.
//! [`decode_bitmap_update_fast_path`] does both — row flip and B/R swap —
//! in a single pass so [`FrameSink`] implementors get top-down RGBA
//! pixels ready to hand to a Canvas/WebGL/wgpu surface without an extra
//! conversion stage.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{Decode, ReadCursor};
use justrdp_graphics::rfx::rlgr::RlgrMode;
use justrdp_graphics::rfx::wire::{
    RfxChannels, RfxCodecVersions, RfxContext, RfxFrameBegin, RfxFrameEnd, RfxRegion, RfxSync,
    RfxTileSet, WBT_CHANNELS, WBT_CODEC_VERSIONS, WBT_CONTEXT, WBT_EXTENSION, WBT_FRAME_BEGIN,
    WBT_FRAME_END, WBT_REGION, WBT_SYNC,
};
use justrdp_graphics::rfx::{RfxDecoder, RfxError, TILE_COEFFICIENTS, TILE_SIZE};
use alloc::boxed::Box;

use justrdp_graphics::avc::{
    combine_avc444_planes, combine_avc444v2_planes, yuv420_to_bgra, yuv444_to_bgra, AvcDecoder,
    AvcError, Yuv420Frame,
};
use justrdp_graphics::clearcodec::{ClearCodecDecoder, ClearCodecError};
use justrdp_graphics::nscodec::{NsCodecDecompressor, NsCodecError};
use justrdp_graphics::{BitsPerPixel, RleDecompressor, RleError};
use justrdp_pdu::rdp::bitmap::{
    TsBitmapData, TsUpdateBitmapData, BITMAP_COMPRESSION,
};
use justrdp_pdu::rdp::drawing_orders::{
    decode_dstblt, decode_lineto, decode_memblt, decode_opaque_rect, decode_patblt,
    decode_polygon_cb, decode_polygon_sc, decode_polyline, decode_scrblt, DstBltOrder,
    LineToOrder, MemBltOrder, OpaqueRectOrder, PatBltOrder, PolygonCbOrder, PolygonScOrder,
    PolylineOrder, PrimaryOrderHistory, PrimaryOrderType, SecondaryOrderType,
    ALT_SECONDARY_ORDER_HEADER_SIZE, ORDER_TYPE_CHANGE, TS_BOUNDS, TS_DELTA_COORDINATES,
    TS_SECONDARY, TS_STANDARD, TS_ZERO_BOUNDS_DELTAS, TS_ZERO_FIELD_BYTE_BIT0,
    TS_ZERO_FIELD_BYTE_BIT1,
};
use justrdp_pdu::rdp::fast_path::FastPathUpdateType;
use justrdp_pdu::rdp::surface_commands::{BitmapDataEx, SurfaceCommand, SURFACECMD_FRAMEACTION_END};

use crate::session::SessionEvent;

/// Render-side failure modes.
#[derive(Debug)]
pub enum RenderError {
    /// The wire payload could not be decoded.
    Decode(justrdp_core::DecodeError),
    /// The fast-path update type isn't handled yet.
    Unsupported { update_code: FastPathUpdateType },
    /// The bitmap announced a color depth this crate does not convert.
    UnsupportedBpp { bits_per_pixel: u16 },
    /// `width * height * bpp` does not match `bitmap_data.len()` for the
    /// uncompressed path, or a Palette PDU was malformed.
    SizeMismatch(String),
    /// RLE decompression failed.
    Rle(RleError),
    /// An 8 bpp Bitmap arrived before a Palette update — the renderer
    /// has no table to convert the indices with.
    PaletteMissing,
    /// A Surface Command referenced a codec that isn't wired yet
    /// (NSCodec / ClearCodec / AVC444 are S3d-5).
    UnsupportedCodec { codec_id: u8 },
    /// RemoteFX decoding failed (RLGR / DWT / size).
    Rfx(RfxError),
    /// RemoteFX TileSet referenced a quant index outside the table the
    /// same TileSet declared.
    RfxQuantIndexOutOfRange { quant_idx: u8, num_quants: u8 },
    /// A Drawing Order's `controlFlags` did not match any known class
    /// (Primary / Secondary / Alternate Secondary).
    UnknownOrderClass { control_flags: u8 },
    /// A Primary order referenced a type the renderer can't advance the
    /// cursor for. The order stream is unrecoverable from this point —
    /// the caller should drop the rest of the batch.
    UnsupportedPrimaryOrder { order_type: PrimaryOrderType },
    /// NSCodec (MS-RDPNSC) decompression failed.
    NsCodec(NsCodecError),
    /// ClearCodec (MS-RDPEGFX 2.2.4) decode failed.
    ClearCodec(ClearCodecError),
    /// AVC (H.264) decode or YUV→BGRA conversion failed. Emitted by the
    /// injected [`AvcDecoder`] or by [`yuv420_to_bgra`] downstream.
    Avc(AvcError),
    /// `set_avc420_codec_id` (or 444 sibling) was registered but no
    /// `AvcDecoder` was injected. The justrdp-web crate has no built-in
    /// H.264 decoder — the embedder MUST provide one
    /// (browser MediaSource on wasm32, openh264 / FFmpeg on native).
    AvcDecoderMissing,
    /// AVC frame returned no output (P-frame with no visible delta, or
    /// the decoder is buffering for B-frames). The blit is a no-op but
    /// surfaces here so the embedder can keep frame ids in sync.
    AvcFrameUnavailable,
    /// AVC444 wire stream advertised an `LC` code that requires a
    /// previous-frame luma cache the renderer doesn't keep yet
    /// (`LC = 1`, chroma-only refresh). Frames following an `LC = 0`
    /// or `LC = 2` are decoded normally.
    AvcLumaCacheRequired,
}

impl core::fmt::Display for RenderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "render decode: {e}"),
            Self::Unsupported { update_code } => {
                write!(f, "unsupported fast-path update type: {update_code:?}")
            }
            Self::UnsupportedBpp { bits_per_pixel } => {
                write!(f, "unsupported bits_per_pixel: {bits_per_pixel}")
            }
            Self::SizeMismatch(msg) => write!(f, "size mismatch: {msg}"),
            Self::Rle(e) => write!(f, "RLE decompress: {e}"),
            Self::PaletteMissing => f.write_str("8 bpp bitmap arrived before any Palette update"),
            Self::UnsupportedCodec { codec_id } => {
                write!(f, "Surface Command codec 0x{codec_id:02X} not yet supported")
            }
            Self::Rfx(e) => write!(f, "RFX: {e}"),
            Self::RfxQuantIndexOutOfRange {
                quant_idx,
                num_quants,
            } => write!(
                f,
                "RFX tile quant_idx {quant_idx} ≥ TileSet num_quants {num_quants}"
            ),
            Self::UnknownOrderClass { control_flags } => write!(
                f,
                "drawing order controlFlags 0x{control_flags:02X} matches no known class"
            ),
            Self::UnsupportedPrimaryOrder { order_type } => write!(
                f,
                "primary drawing order {order_type:?} not yet supported by the order walker"
            ),
            Self::NsCodec(e) => write!(f, "NSCodec: {e}"),
            Self::ClearCodec(e) => write!(f, "ClearCodec: {e}"),
            Self::Avc(e) => write!(f, "AVC: {e}"),
            Self::AvcDecoderMissing => f.write_str(
                "AVC codec_id registered but no AvcDecoder was injected (set_avc_decoder)",
            ),
            Self::AvcFrameUnavailable => f.write_str("AVC decoder returned no frame this call"),
            Self::AvcLumaCacheRequired => f.write_str(
                "AVC444 frame uses LC=1 (chroma-only refresh) which needs a cached luma frame; \
                 unsupported in justrdp-web — wait for the next LC=0 / LC=2 keyframe",
            ),
        }
    }
}

impl From<NsCodecError> for RenderError {
    fn from(e: NsCodecError) -> Self {
        Self::NsCodec(e)
    }
}

impl From<ClearCodecError> for RenderError {
    fn from(e: ClearCodecError) -> Self {
        Self::ClearCodec(e)
    }
}

impl From<AvcError> for RenderError {
    fn from(e: AvcError) -> Self {
        Self::Avc(e)
    }
}

impl From<RfxError> for RenderError {
    fn from(e: RfxError) -> Self {
        Self::Rfx(e)
    }
}

impl core::error::Error for RenderError {}

impl From<justrdp_core::DecodeError> for RenderError {
    fn from(e: justrdp_core::DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<RleError> for RenderError {
    fn from(e: RleError) -> Self {
        Self::Rle(e)
    }
}

/// One decoded rectangle, ready to hand to a [`FrameSink`].
///
/// `pixels_rgba` is top-down packed RGBA, length = `width * height * 4`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRect {
    pub dest_left: u16,
    pub dest_top: u16,
    pub width: u16,
    pub height: u16,
    pub pixels_rgba: Vec<u8>,
}

/// Render target.
///
/// `blit_rgba` receives top-down packed RGBA, the same byte order
/// `<canvas>` `ImageData` and most GPU APIs (WebGL `RGBA`/`UNSIGNED_BYTE`,
/// wgpu `Rgba8Unorm`, vulkan `R8G8B8A8_UNORM`) expect. `(dest_left,
/// dest_top)` is the inclusive top-left corner in desktop coordinates;
/// the blit covers `(dest_left .. dest_left + width)` ×
/// `(dest_top .. dest_top + height)`.
///
/// All methods default-impl as no-ops *except* `blit_rgba`, so a sink
/// that only cares about pixels can elide the rest.
pub trait FrameSink {
    /// Optional: server announced new desktop dimensions.
    fn resize(&mut self, _width: u16, _height: u16) {}

    /// Blit a top-down RGBA rectangle into the surface.
    fn blit_rgba(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        pixels_rgba: &[u8],
    );

    /// Optional read-back: copy a rectangle of currently-displayed RGBA
    /// pixels into `out`. Default returns `false` — sinks that don't
    /// keep a shadow buffer simply opt out, and primary orders that
    /// require destination read-back (DstBlt DSTINVERT, MemBlt
    /// non-SRCCOPY ROPs, future PatBlt pattern with merge ROPs) will
    /// silently drop their blits instead of corrupting the display.
    ///
    /// Implementors that *do* hold a shadow buffer (`CanvasFrameSink`
    /// reading via `getImageData`, native compositors, …) override
    /// this to fill `out` with `width * height * 4` RGBA bytes and
    /// return `true`.
    fn peek_rgba(
        &mut self,
        _dest_left: u16,
        _dest_top: u16,
        _width: u16,
        _height: u16,
        _out: &mut Vec<u8>,
    ) -> bool {
        false
    }

    /// Optional: end of an update batch — useful for sinks that buffer
    /// blits to amortize draw calls.
    fn flush(&mut self) {}
}

/// Number of palette entries in a TS_UPDATE_PALETTE PDU (always 256 per
/// MS-RDPBCGR 2.2.9.1.1.3.1.1.1).
const PALETTE_ENTRY_COUNT: usize = 256;

/// Stateful renderer.
///
/// Holds protocol state that survives across update batches — the 8 bpp
/// palette table, the latest Frame Marker id, the RFX entropy mode (when
/// the codec is registered), and the ClearCodec glyph/VBar caches. Use
/// one instance per session; reusing across sessions risks decoding new
/// traffic against stale palette/codec state.
///
/// Not `Clone` (ClearCodecDecoder is not Clone) and not derived `Debug`
/// (same reason); a manual Debug impl below prints just the loose
/// metadata and elides the codec internals.
pub struct BitmapRenderer {
    palette: Option<[(u8, u8, u8); PALETTE_ENTRY_COUNT]>,
    /// Most recent Frame Marker id seen (BEGIN or END). Embedders that
    /// want true v-sync can poll this between draws to coalesce updates.
    last_frame_id: Option<u32>,
    /// codec_id assigned to RemoteFX in the current session. Servers
    /// pick this dynamically during capability negotiation, so the
    /// embedder must register it via [`Self::set_rfx_codec_id`] before
    /// any Surface Command carrying RFX data arrives. Default `None`
    /// makes any non-zero codec_id surface as
    /// [`RenderError::UnsupportedCodec`].
    rfx_codec_id: Option<u8>,
    /// RFX entropy mode last seen on a TS_RFX_CONTEXT block. Defaults
    /// to RLGR1; tests and unsigned-frame streams can override.
    rfx_entropy: RlgrMode,
    /// Per-type Primary Drawing Order field history (delta encoding,
    /// type-change suppression, zero-field byte optimization). MUST
    /// persist across orders within a session to correctly reconstruct
    /// fields that the server elides.
    primary_history: PrimaryOrderHistory,
    /// Last Primary order type seen — used when a controlFlags byte
    /// does NOT carry the TS_TYPE_CHANGE bit (the server is reusing
    /// the previous order type to save a byte). Initial value matches
    /// MS-RDPEGDI 3.2.1.1 (PatBlt).
    last_primary_type: PrimaryOrderType,
    /// codec_id assigned to NSCodec (MS-RDPNSC). Same registration
    /// dance as `rfx_codec_id` — the server picks dynamically.
    nscodec_codec_id: Option<u8>,
    /// codec_id assigned to ClearCodec (MS-RDPEGFX §2.2.4).
    clearcodec_codec_id: Option<u8>,
    /// ClearCodec carries glyph + VBar caches across calls; constructed
    /// lazily on first use to avoid the allocation when the codec
    /// isn't registered.
    clearcodec_decoder: Option<ClearCodecDecoder>,
    /// codec_id assigned to AVC420 (single-stream H.264).
    avc420_codec_id: Option<u8>,
    /// codec_id assigned to AVC444 (dual-stream luma + chroma aux,
    /// MS-RDPEGFX 2.2.4.4.2 layout).
    avc444_codec_id: Option<u8>,
    /// codec_id assigned to AVC444v2 (MS-RDPEGFX 2.2.4.4.3 layout).
    avc444v2_codec_id: Option<u8>,
    /// Embedder-supplied H.264 decoder. `Box<dyn AvcDecoder>` because
    /// justrdp-web does NOT bundle an H.264 implementation — wasm32
    /// callers usually wrap the browser's MediaSource / VideoDecoder
    /// API; native callers wrap openh264 / FFmpeg / hardware backends.
    avc_decoder: Option<Box<dyn AvcDecoder>>,
    /// Bitmap cache populated by `CacheBitmapV2Uncompressed` Secondary
    /// drawing orders (MS-RDPEGDI 2.2.2.2.1.2.3). Keyed by
    /// `(cache_id, cache_index)`; `MemBlt` Primary orders look up
    /// against this and blit the cached bitmap (or a sub-region).
    bitmap_cache: BTreeMap<(u8, u16), CachedBitmap>,
    /// Brush cache populated by `CacheBrush` Secondary drawing orders
    /// (MS-RDPEGDI 2.2.2.2.1.2.7). 8×8 monochrome brushes only at the
    /// moment — the byte array is `[u8; 8]` rows, MSB-first within
    /// each row. PatBlt orders with `BS_PATTERN` and a cached
    /// `brush_hatch` index look up here.
    brush_cache: BTreeMap<u8, [u8; 8]>,
    /// Glyph cache populated by `CacheGlyph` Secondary orders
    /// (MS-RDPEGDI 2.2.2.2.1.2.5 / 2.2.2.2.1.2.6). Keyed by
    /// `(cache_id, glyph_index)`; each entry stores cx/cy and a
    /// 1 bpp mask. GlyphIndex orders composite the mask onto the
    /// destination using the foreground color.
    glyph_cache: BTreeMap<(u8, u16), CachedGlyph>,
}

/// One entry in [`BitmapRenderer::glyph_cache`].
///
/// MS-RDPEGDI 2.2.2.2.1.2.5: glyph data is 1 bpp, padded so each row
/// is a multiple of 4 bytes (`stride = ((cx + 31) & !31) / 8`). The
/// row order matches the wire (top-down). We store the bytes
/// verbatim and walk them per-pixel during composition.
#[derive(Debug, Clone)]
struct CachedGlyph {
    cx: u16,
    cy: u16,
    stride: u16,
    mask: Vec<u8>,
}

/// One entry in [`BitmapRenderer::bitmap_cache`].
///
/// `pixels_rgba` is top-down 32-bpp RGBA, ready to feed straight to a
/// `FrameSink::blit_rgba`. We convert at cache insert so MemBlt
/// look-ups stay O(1) per byte (no per-blit channel swap).
#[derive(Debug, Clone)]
struct CachedBitmap {
    width: u16,
    height: u16,
    pixels_rgba: Vec<u8>,
}

impl Default for BitmapRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for BitmapRenderer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BitmapRenderer")
            .field("has_palette", &self.palette.is_some())
            .field("last_frame_id", &self.last_frame_id)
            .field("rfx_codec_id", &self.rfx_codec_id)
            .field("rfx_entropy", &self.rfx_entropy)
            .field("last_primary_type", &self.last_primary_type)
            .field("nscodec_codec_id", &self.nscodec_codec_id)
            .field("clearcodec_codec_id", &self.clearcodec_codec_id)
            .field("avc420_codec_id", &self.avc420_codec_id)
            .field("avc444_codec_id", &self.avc444_codec_id)
            .field("avc444v2_codec_id", &self.avc444v2_codec_id)
            .field("has_avc_decoder", &self.avc_decoder.is_some())
            .field("bitmap_cache_entries", &self.bitmap_cache.len())
            .finish_non_exhaustive()
    }
}

impl BitmapRenderer {
    pub fn new() -> Self {
        Self {
            palette: None,
            last_frame_id: None,
            rfx_codec_id: None,
            rfx_entropy: RlgrMode::Rlgr1,
            primary_history: PrimaryOrderHistory::new(),
            last_primary_type: PrimaryOrderType::PatBlt,
            nscodec_codec_id: None,
            clearcodec_codec_id: None,
            clearcodec_decoder: None,
            avc420_codec_id: None,
            avc444_codec_id: None,
            avc444v2_codec_id: None,
            avc_decoder: None,
            bitmap_cache: BTreeMap::new(),
            brush_cache: BTreeMap::new(),
            glyph_cache: BTreeMap::new(),
        }
    }

    pub fn glyph_cache_len(&self) -> usize {
        self.glyph_cache.len()
    }

    /// Number of cached bitmaps currently held (test / instrumentation).
    pub fn bitmap_cache_len(&self) -> usize {
        self.bitmap_cache.len()
    }

    /// Number of cached brushes currently held.
    pub fn brush_cache_len(&self) -> usize {
        self.brush_cache.len()
    }

    /// Inject an embedder-supplied H.264 decoder. Required before any
    /// AVC420 / AVC444 codec_id can render frames. Replaces any
    /// previously-installed decoder (the old one is dropped).
    pub fn set_avc_decoder(&mut self, decoder: Box<dyn AvcDecoder>) {
        self.avc_decoder = Some(decoder);
    }

    /// Drop the injected AVC decoder. Subsequent AVC420 / AVC444
    /// frames will surface as [`RenderError::AvcDecoderMissing`].
    pub fn clear_avc_decoder(&mut self) {
        self.avc_decoder = None;
    }

    pub fn has_avc_decoder(&self) -> bool {
        self.avc_decoder.is_some()
    }

    /// Register the AVC420 server-assigned codec_id. The matching
    /// Surface Bits cmd's `bitmap_data` is treated as a single H.264
    /// Annex B access unit and fed to the injected decoder.
    pub fn set_avc420_codec_id(&mut self, codec_id: u8) {
        self.avc420_codec_id = Some(codec_id);
    }

    pub fn avc420_codec_id(&self) -> Option<u8> {
        self.avc420_codec_id
    }

    /// Register the AVC444 (v1 layout) server-assigned codec_id.
    /// Wire format: MS-RDPEGFX 2.2.4.4.2.
    pub fn set_avc444_codec_id(&mut self, codec_id: u8) {
        self.avc444_codec_id = Some(codec_id);
    }

    pub fn avc444_codec_id(&self) -> Option<u8> {
        self.avc444_codec_id
    }

    /// Register the AVC444v2 server-assigned codec_id (modern Windows
    /// default for high-color session graphics). Wire format:
    /// MS-RDPEGFX 2.2.4.4.3 — same `LC` code as v1 but a different
    /// chroma-aux layout consumed by [`combine_avc444v2_planes`].
    pub fn set_avc444v2_codec_id(&mut self, codec_id: u8) {
        self.avc444v2_codec_id = Some(codec_id);
    }

    pub fn avc444v2_codec_id(&self) -> Option<u8> {
        self.avc444v2_codec_id
    }

    /// Register the NSCodec server-assigned codec_id. Subsequent
    /// Surface Bits commands with that id route through
    /// [`NsCodecDecompressor`].
    pub fn set_nscodec_codec_id(&mut self, codec_id: u8) {
        self.nscodec_codec_id = Some(codec_id);
    }

    pub fn nscodec_codec_id(&self) -> Option<u8> {
        self.nscodec_codec_id
    }

    /// Register the ClearCodec server-assigned codec_id. Allocates the
    /// [`ClearCodecDecoder`] on first call so the per-session glyph /
    /// VBar caches persist for the rest of the session.
    pub fn set_clearcodec_codec_id(&mut self, codec_id: u8) {
        self.clearcodec_codec_id = Some(codec_id);
        if self.clearcodec_decoder.is_none() {
            self.clearcodec_decoder = Some(ClearCodecDecoder::new());
        }
    }

    pub fn clearcodec_codec_id(&self) -> Option<u8> {
        self.clearcodec_codec_id
    }

    /// Tell the renderer which codec_id to interpret as RemoteFX. Must
    /// be called before any Surface Command carrying RFX data — the
    /// codec_id is server-assigned during capability negotiation, so
    /// the embedder reads it out of [`ConnectionResult::server_capabilities`]
    /// and forwards it here.
    ///
    /// [`ConnectionResult::server_capabilities`]: justrdp_connector::ConnectionResult
    pub fn set_rfx_codec_id(&mut self, codec_id: u8) {
        self.rfx_codec_id = Some(codec_id);
    }

    pub fn rfx_codec_id(&self) -> Option<u8> {
        self.rfx_codec_id
    }

    /// Whether the server has sent a Palette update yet. 8 bpp bitmaps
    /// before the first palette will fail with [`RenderError::PaletteMissing`].
    pub fn has_palette(&self) -> bool {
        self.palette.is_some()
    }

    /// The most recent Frame Marker id observed (BEGIN or END), or
    /// `None` if the server has not sent one this session.
    pub fn last_frame_id(&self) -> Option<u32> {
        self.last_frame_id
    }

    /// Apply one [`SessionEvent`] to a [`FrameSink`], updating internal
    /// state as needed. Returns `Ok(true)` if any pixels were drawn,
    /// `Ok(false)` for plumbing-only events (palette/synchronize/etc.).
    pub fn render<S: FrameSink>(
        &mut self,
        event: &SessionEvent,
        sink: &mut S,
    ) -> Result<bool, RenderError> {
        let SessionEvent::Graphics { update_code, data } = event else {
            return Ok(false);
        };

        match update_code {
            FastPathUpdateType::Palette => {
                self.update_palette(data)?;
                Ok(false)
            }
            FastPathUpdateType::Bitmap => {
                let rects = self.decode_bitmap_rects(data)?;
                let any = !rects.is_empty();
                for r in rects {
                    sink.blit_rgba(
                        r.dest_left,
                        r.dest_top,
                        r.width,
                        r.height,
                        &r.pixels_rgba,
                    );
                }
                if any {
                    sink.flush();
                }
                Ok(any)
            }
            FastPathUpdateType::SurfaceCommands => self.process_surface_commands(data, sink),
            FastPathUpdateType::Orders => self.process_orders(data, sink),
            // Synchronize is plumbing — accept silently.
            FastPathUpdateType::Synchronize => Ok(false),
            other => Err(RenderError::Unsupported {
                update_code: *other,
            }),
        }
    }

    /// Walk a `FASTPATH_UPDATETYPE_ORDERS` payload (MS-RDPEGDI 2.2.2.2):
    /// `numberOrders (u16 LE) + N drawing orders`.
    ///
    /// S3d-4 renders Primary OpaqueRect orders to the sink (single-color
    /// filled rectangles — the most common GDI primitive). All other
    /// Primary types and every Secondary / Alternate Secondary order
    /// are decoded only enough to advance the cursor; the renderer
    /// returns an `Unsupported*` error if it can't safely skip past one,
    /// since silently dropping mid-stream desynchronises the
    /// `PrimaryOrderHistory` for everything that follows.
    fn process_orders<S: FrameSink>(
        &mut self,
        payload: &[u8],
        sink: &mut S,
    ) -> Result<bool, RenderError> {
        let mut cursor = ReadCursor::new(payload);
        let number_orders = cursor.read_u16_le("Orders::numberOrders")? as usize;
        let mut any_blits = false;
        for _ in 0..number_orders {
            if cursor.remaining() == 0 {
                break;
            }
            let control_flags = cursor.read_u8("DrawingOrder::controlFlags")?;
            if control_flags & TS_STANDARD == 0 {
                // TS_STANDARD clear → Alternate Secondary order. Length
                // prefix follows (u16 LE, total = controlFlags + length
                // + body), so we can always skip safely without parsing
                // the body.
                let order_length =
                    cursor.read_u16_le("AltSecondaryOrder::orderLength")? as usize;
                let body_size = order_length
                    .checked_sub(ALT_SECONDARY_ORDER_HEADER_SIZE - 1)
                    .ok_or_else(|| {
                        RenderError::SizeMismatch(format!(
                            "alt-secondary orderLength too small: {order_length}"
                        ))
                    })?;
                cursor.read_slice(body_size, "AltSecondaryOrder::body")?;
                continue;
            }
            if control_flags & TS_SECONDARY != 0 {
                // Secondary: orderLength + extraFlags + orderType + body.
                let order_length =
                    cursor.read_u16_le("SecondaryOrder::orderLength")? as i32;
                let extra_flags = cursor.read_u16_le("SecondaryOrder::extraFlags")?;
                let order_type_raw = cursor.read_u8("SecondaryOrder::orderType")?;
                // Per MS-RDPEGDI: body length = orderLength + 7 - 3 = orderLength + 4
                let body_len = (order_length + 4) as usize;
                let body = cursor.read_slice(body_len, "SecondaryOrder::body")?;
                // Dispatch the subset we know how to render. Unknown /
                // unsupported types fall through silently — the
                // embedder loses caching for those but the stream
                // stays in sync because we already advanced the cursor.
                if let Ok(sec_type) = SecondaryOrderType::from_u8(order_type_raw) {
                    match sec_type {
                        SecondaryOrderType::CacheBitmapV1Uncompressed => {
                            let _ = self.cache_bitmap_v1(extra_flags, body, false);
                        }
                        SecondaryOrderType::CacheBitmapV1Compressed => {
                            let _ = self.cache_bitmap_v1(extra_flags, body, true);
                        }
                        SecondaryOrderType::CacheBitmapV2Uncompressed => {
                            let _ = self.cache_bitmap_v2(extra_flags, body, false);
                        }
                        SecondaryOrderType::CacheBitmapV2Compressed => {
                            let _ = self.cache_bitmap_v2(extra_flags, body, true);
                        }
                        SecondaryOrderType::CacheBitmapV3 => {
                            let _ = self.cache_bitmap_v3(extra_flags, body);
                        }
                        SecondaryOrderType::CacheBrush => {
                            let _ = self.cache_brush(body);
                        }
                        SecondaryOrderType::CacheGlyph => {
                            let _ = self.cache_glyph(extra_flags, body);
                        }
                        // CacheColorTable: decoded only enough to keep
                        // the order stream in sync.
                        _ => {}
                    }
                }
                continue;
            }
            // Primary order.
            if self.process_primary_order(control_flags, &mut cursor, sink)? {
                any_blits = true;
            }
        }
        Ok(any_blits)
    }

    /// Decode and (where renderable) blit one Primary drawing order.
    ///
    /// `control_flags` is the byte already read from the stream. The
    /// cursor is positioned at `orderType` (when TS_TYPE_CHANGE is set)
    /// or `fieldFlags` (otherwise).
    fn process_primary_order<S: FrameSink>(
        &mut self,
        control_flags: u8,
        cursor: &mut ReadCursor<'_>,
        sink: &mut S,
    ) -> Result<bool, RenderError> {
        let order_type = if control_flags & ORDER_TYPE_CHANGE != 0 {
            let raw = cursor.read_u8("PrimaryOrder::orderType")?;
            let t = PrimaryOrderType::from_u8(raw)?;
            self.last_primary_type = t;
            t
        } else {
            self.last_primary_type
        };

        // Field flags: starts at the per-type max byte count, but each
        // TS_ZERO_FIELD_BYTE bit drops a trailing-zero byte from the
        // wire (MS-RDPEGDI 2.2.2.2.1.1.2).
        let max_ff_bytes = primary_field_flags_byte_count(order_type);
        let zero_count = ((control_flags & TS_ZERO_FIELD_BYTE_BIT0) != 0) as usize
            + ((control_flags & TS_ZERO_FIELD_BYTE_BIT1) != 0) as usize;
        let ff_bytes = max_ff_bytes.saturating_sub(zero_count);
        let mut field_flags: u32 = 0;
        for i in 0..ff_bytes {
            let b = cursor.read_u8("PrimaryOrder::fieldFlags")?;
            field_flags |= (b as u32) << (i * 8);
        }

        // Optional bounds: skipped for rendering (the server is just
        // narrowing the clip rect — we treat the whole desktop as the
        // clip for now). We still consume the wire bytes so the cursor
        // stays in sync.
        if control_flags & TS_BOUNDS != 0 && control_flags & TS_ZERO_BOUNDS_DELTAS == 0 {
            // Bounds are encoded as a 1-byte present-flags bitmap +
            // 0..4 fields, each i16 (or i8 delta). Decode via the
            // typed BoundsRect decoder so the format stays canonical.
            let _ = justrdp_pdu::rdp::drawing_orders::BoundsRect::decode(cursor)?;
        }

        let delta = control_flags & TS_DELTA_COORDINATES != 0;

        // Each typed decoder advances the cursor by exactly the right
        // amount, so unsupported types still stay in sync.
        match order_type {
            PrimaryOrderType::OpaqueRect => {
                let r = decode_opaque_rect(cursor, field_flags, delta, &mut self.primary_history)?;
                blit_opaque_rect(&r, sink);
                Ok(true)
            }
            PrimaryOrderType::DstBlt => {
                let order =
                    decode_dstblt(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(try_render_dstblt(&order, sink))
            }
            PrimaryOrderType::PatBlt => {
                let order =
                    decode_patblt(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(try_render_patblt(&order, &self.brush_cache, sink))
            }
            PrimaryOrderType::GlyphIndex => self.try_render_glyph_index(cursor, field_flags, sink),
            PrimaryOrderType::PolygonSc => {
                let order =
                    decode_polygon_sc(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(try_render_polygon_sc(&order, sink))
            }
            PrimaryOrderType::PolygonCb => {
                let order =
                    decode_polygon_cb(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(try_render_polygon_cb(&order, &self.brush_cache, sink))
            }
            PrimaryOrderType::ScrBlt => {
                let _ = decode_scrblt(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(false)
            }
            PrimaryOrderType::MemBlt => {
                let order =
                    decode_memblt(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(self.try_render_memblt(&order, sink))
            }
            PrimaryOrderType::LineTo => {
                let order =
                    decode_lineto(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(try_render_lineto(&order, sink))
            }
            PrimaryOrderType::Polyline => {
                let order =
                    decode_polyline(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(try_render_polyline(&order, sink))
            }
            other => Err(RenderError::UnsupportedPrimaryOrder { order_type: other }),
        }
    }

    /// `GlyphIndex` body decoder + 1 bpp mask compositor (MS-RDPEGDI
    /// 2.2.2.2.1.1.2.13). Each command in the trailing variable-length
    /// `data` is one of:
    ///   * 0x00..=0xFD — single glyph index byte (cache id is in the
    ///     header). Renders the cached glyph mask at the running pen
    ///     position with the foreground color where bits = 1.
    ///   * 0xFE — cache_id switch (1 byte) — followed by index.
    ///   * 0xFF — terminator (we honor it but the order's cbData should
    ///     already bound the iteration).
    ///   * 0x80..=0xFD with high bit set in some flAccel modes — used
    ///     as relative offset (skipped for now; rare on modern wire).
    ///
    /// `flAccel` flags (`order.fl_accel`) we honor:
    ///   SO_VERTICAL / SO_HORIZONTAL — fixed cell layout.
    ///   SO_REVERSED — render right-to-left (deferred).
    ///
    /// Glyphs that miss the cache silently skip (the embedder loses
    /// that one character). Background-rect drawing (BkLeft..BkBottom
    /// + BackColor) is not currently rendered — fonts on top of an
    /// already-painted background look right; isolated text spans
    /// would need the bk rect too (S3d-6d3 follow-up).
    fn try_render_glyph_index<S: FrameSink>(
        &mut self,
        cursor: &mut ReadCursor<'_>,
        field_flags: u32,
        sink: &mut S,
    ) -> Result<bool, RenderError> {
        // Decode the 22 fixed fields per their flag bits.
        let mut cache_id = 0u8;
        let mut _fl_accel = 0u8;
        let mut _ul_char_inc = 0u8;
        let mut _f_op_redundant = 0u8;
        let mut back_color = [0u8; 3];
        let mut fore_color = [0u8; 3];
        let mut bk_left = 0i16;
        let mut bk_top = 0i16;
        let mut bk_right = 0i16;
        let mut bk_bottom = 0i16;
        let mut _op_left = 0i16;
        let mut _op_top = 0i16;
        let mut _op_right = 0i16;
        let mut _op_bottom = 0i16;
        let mut _brush_org_x = 0u8;
        let mut _brush_org_y = 0u8;
        let mut _brush_style = 0u8;
        let mut _brush_hatch = 0u8;
        let mut _brush_extra = [0u8; 7];
        let mut x = 0i16;
        let mut y = 0i16;

        if field_flags & (1 << 0) != 0 {
            cache_id = cursor.read_u8("GlyphIndex::cacheId")?;
        }
        if field_flags & (1 << 1) != 0 {
            _fl_accel = cursor.read_u8("GlyphIndex::flAccel")?;
        }
        if field_flags & (1 << 2) != 0 {
            _ul_char_inc = cursor.read_u8("GlyphIndex::ulCharInc")?;
        }
        if field_flags & (1 << 3) != 0 {
            _f_op_redundant = cursor.read_u8("GlyphIndex::fOpRedundant")?;
        }
        if field_flags & (1 << 4) != 0 {
            back_color[0] = cursor.read_u8("GlyphIndex::back[0]")?;
            back_color[1] = cursor.read_u8("GlyphIndex::back[1]")?;
            back_color[2] = cursor.read_u8("GlyphIndex::back[2]")?;
        }
        if field_flags & (1 << 5) != 0 {
            fore_color[0] = cursor.read_u8("GlyphIndex::fore[0]")?;
            fore_color[1] = cursor.read_u8("GlyphIndex::fore[1]")?;
            fore_color[2] = cursor.read_u8("GlyphIndex::fore[2]")?;
        }
        for (i, dst) in [
            &mut bk_left,
            &mut bk_top,
            &mut bk_right,
            &mut bk_bottom,
            &mut _op_left,
            &mut _op_top,
            &mut _op_right,
            &mut _op_bottom,
        ]
        .iter_mut()
        .enumerate()
        {
            if field_flags & (1 << (6 + i)) != 0 {
                **dst = cursor.read_u16_le("GlyphIndex::rect")? as i16;
            }
        }
        if field_flags & (1 << 14) != 0 {
            _brush_org_x = cursor.read_u8("GlyphIndex::brushOrgX")?;
        }
        if field_flags & (1 << 15) != 0 {
            _brush_org_y = cursor.read_u8("GlyphIndex::brushOrgY")?;
        }
        if field_flags & (1 << 16) != 0 {
            _brush_style = cursor.read_u8("GlyphIndex::brushStyle")?;
        }
        if field_flags & (1 << 17) != 0 {
            _brush_hatch = cursor.read_u8("GlyphIndex::brushHatch")?;
        }
        if field_flags & (1 << 18) != 0 {
            for i in 0..7 {
                _brush_extra[i] = cursor.read_u8("GlyphIndex::brushExtra")?;
            }
        }
        if field_flags & (1 << 19) != 0 {
            x = cursor.read_u16_le("GlyphIndex::x")? as i16;
        }
        if field_flags & (1 << 20) != 0 {
            y = cursor.read_u16_le("GlyphIndex::y")? as i16;
        }
        let mut cb = 0usize;
        let mut data: Vec<u8> = Vec::new();
        if field_flags & (1 << 21) != 0 {
            cb = cursor.read_u8("GlyphIndex::cbData")? as usize;
            let bytes = cursor.read_slice(cb, "GlyphIndex::data")?;
            data = bytes.to_vec();
        }
        let _ = (back_color, bk_left, bk_top, bk_right, bk_bottom, cb);

        let fore_rgba = [fore_color[0], fore_color[1], fore_color[2], 0xFF];
        let mut pen_x = x as i32;
        let pen_y = y as i32;
        let mut current_cache_id = cache_id;
        let mut any_blits = false;
        let mut i = 0;
        while i < data.len() {
            let b = data[i];
            i += 1;
            match b {
                0xFE => {
                    // Cache id switch: next byte is the new cache_id.
                    if i < data.len() {
                        current_cache_id = data[i];
                        i += 1;
                    }
                    continue;
                }
                0xFF => break, // explicit terminator
                idx => {
                    let glyph_key = (current_cache_id, idx as u16);
                    if let Some(g) = self.glyph_cache.get(&glyph_key).cloned() {
                        if composite_glyph_mask(&g, pen_x, pen_y, &fore_rgba, sink) {
                            any_blits = true;
                        }
                        // Advance pen by glyph width. Real flAccel-driven
                        // schemes can shift differently (vertical text,
                        // proportional spacing) — this minimum ships the
                        // common left-to-right horizontal layout.
                        pen_x += g.cx as i32;
                    }
                }
            }
        }
        Ok(any_blits)
    }


    /// Walk a `FASTPATH_UPDATETYPE_SURFCMDS` payload, dispatching each
    /// command (MS-RDPBCGR 2.2.9.1.2.1.10):
    ///
    /// * `SET_SURFACE_BITS` / `STREAM_SURFACE_BITS` with `codec_id == 0`
    ///   → raw 32 bpp BGRA pixels (top-down per spec) → RGBA blit.
    /// * Any non-zero `codec_id` → [`RenderError::UnsupportedCodec`]
    ///   (RFX / NSCodec / ClearCodec / AVC land in S3d-3+).
    /// * `FRAME_MARKER` → cache `frame_id`; on `END`, call
    ///   [`FrameSink::flush`] so embedders that buffer per-frame can
    ///   commit at the spec-defined boundary.
    fn process_surface_commands<S: FrameSink>(
        &mut self,
        payload: &[u8],
        sink: &mut S,
    ) -> Result<bool, RenderError> {
        let mut cursor = ReadCursor::new(payload);
        let mut any_blits = false;
        while cursor.remaining() > 0 {
            let cmd = SurfaceCommand::decode(&mut cursor)?;
            match cmd {
                SurfaceCommand::SetSurfaceBits(c) => {
                    if self.dispatch_surface_bits(c.dest_left, c.dest_top, &c.bitmap_data, sink)? {
                        any_blits = true;
                    }
                }
                SurfaceCommand::StreamSurfaceBits(c) => {
                    if self.dispatch_surface_bits(c.dest_left, c.dest_top, &c.bitmap_data, sink)? {
                        any_blits = true;
                    }
                }
                SurfaceCommand::FrameMarker(m) => {
                    self.last_frame_id = Some(m.frame_id);
                    if m.frame_action == SURFACECMD_FRAMEACTION_END {
                        sink.flush();
                    }
                }
            }
        }
        Ok(any_blits)
    }

    /// `CacheBitmapV1` parser (MS-RDPEGDI 2.2.2.2.1.2.2).
    ///
    /// `extraFlags` holds:
    ///   bits 0–8  : cacheId (3 bits, low nibble) — only low 3 used
    ///   high bits : reserved
    ///
    /// Body layout (fixed):
    ///   cacheId         (u8)  — duplicate of the extraFlags field
    ///   pad1            (u8)
    ///   bitmapWidth     (u8)  — pixel width
    ///   bitmapHeight    (u8)  — pixel height
    ///   bitmapBpp       (u8)  — bits per pixel
    ///   bitmapLength    (u16 LE)
    ///   cacheIndex      (u16 LE)
    ///   bitmapDataStream (bitmapLength bytes)
    ///
    /// V1 entries are bottom-up (DIB convention) — different from V2
    /// which is top-down. We flip during cache insert so MemBlt
    /// look-ups always see top-down RGBA. Only 16 bpp (uncompressed
    /// or RLE) and 24 bpp (uncompressed) are wired; 8 bpp would need
    /// the palette and 32 bpp is a V3 feature.
    fn cache_bitmap_v1(
        &mut self,
        _extra_flags: u16,
        body: &[u8],
        compressed: bool,
    ) -> Result<(), RenderError> {
        if body.len() < 9 {
            return Err(RenderError::SizeMismatch(
                "CacheBitmapV1: header truncated".into(),
            ));
        }
        let cache_id = body[0];
        // body[1] reserved
        let width = body[2] as u16;
        let height = body[3] as u16;
        let bpp = body[4];
        let bitmap_length = u16::from_le_bytes([body[5], body[6]]) as usize;
        let cache_index = u16::from_le_bytes([body[7], body[8]]);
        if body.len() < 9 + bitmap_length {
            return Err(RenderError::SizeMismatch(format!(
                "CacheBitmapV1: bitmapLength {bitmap_length} but only {} bytes left",
                body.len() - 9
            )));
        }
        let payload = &body[9..9 + bitmap_length];

        let pixels_rgba = match (compressed, bpp) {
            (false, 16) => {
                let expected = width as usize * height as usize * 2;
                if payload.len() != expected {
                    return Ok(());
                }
                flip_and_convert_rgb565(payload, width, height)
            }
            (false, 24) => {
                let expected = width as usize * height as usize * 3;
                if payload.len() != expected {
                    return Ok(());
                }
                flip_and_swap_24bpp(payload, width, height)
            }
            (true, 16) => {
                let mut raw = Vec::new();
                RleDecompressor::new()
                    .decompress(payload, width, height, BitsPerPixel::Bpp16, &mut raw)?;
                flip_and_convert_rgb565(&raw, width, height)
            }
            (true, 24) => {
                let mut raw = Vec::new();
                RleDecompressor::new()
                    .decompress(payload, width, height, BitsPerPixel::Bpp24, &mut raw)?;
                flip_and_swap_24bpp(&raw, width, height)
            }
            _ => return Ok(()),
        };
        self.bitmap_cache.insert(
            (cache_id, cache_index),
            CachedBitmap {
                width,
                height,
                pixels_rgba,
            },
        );
        Ok(())
    }

    /// `CacheBitmapV3` parser (MS-RDPEGDI 2.2.2.2.1.2.8).
    ///
    /// `extraFlags` packs:
    ///   bits 0–2  : cacheId (3 bits)
    ///   bits 7–14 : bitmapBpp (8 bits) — **actual** bpp (not a code)
    ///
    /// Body:
    ///   cacheIndex (u16 LE)
    ///   key1, key2 (u32 LE × 2)
    ///   bitmapData (TS_COMPRESSED_BITMAP_HEADER_EX + raw payload)
    ///
    /// `TS_BITMAP_DATA_EX` payload format:
    ///   bpp (u8) flags (u8) reserved (u8) codec_id (u8)
    ///   width (u16 LE) height (u16 LE) bitmapDataLength (u32 LE)
    ///   exHeader (24 bytes, optional)
    ///   bitmapData (length bytes)
    ///
    /// V3 entries are top-down. We accept codec_id = 0 (raw 32 bpp)
    /// and codec_id matching the registered RFX/NSCodec/ClearCodec
    /// codec_ids — but only the raw path is implemented here for the
    /// minimum. Codec-encoded V3 cache entries surface as
    /// `RenderError::UnsupportedCodec` from the next MemBlt that
    /// look-up misses.
    fn cache_bitmap_v3(
        &mut self,
        extra_flags: u16,
        body: &[u8],
    ) -> Result<(), RenderError> {
        if body.len() < 2 + 8 + 12 {
            return Err(RenderError::SizeMismatch(
                "CacheBitmapV3: header truncated".into(),
            ));
        }
        let cache_id = (extra_flags & 0x07) as u8;
        let cache_index = u16::from_le_bytes([body[0], body[1]]);
        // Skip key1+key2 (8 bytes).
        let mut cur = &body[2 + 8..];
        // TS_BITMAP_DATA_EX — same shape as Surface Bits payload.
        if cur.len() < 12 {
            return Err(RenderError::SizeMismatch(
                "CacheBitmapV3: TS_BITMAP_DATA_EX truncated".into(),
            ));
        }
        let bpp = cur[0];
        let flags = cur[1];
        // cur[2] reserved
        let codec_id = cur[3];
        let width = u16::from_le_bytes([cur[4], cur[5]]);
        let height = u16::from_le_bytes([cur[6], cur[7]]);
        let length = u32::from_le_bytes([cur[8], cur[9], cur[10], cur[11]]) as usize;
        cur = &cur[12..];
        if flags & 0x01 != 0 {
            // EX_COMPRESSED_BITMAP_HEADER_PRESENT — skip the 24-byte header.
            if cur.len() < 24 {
                return Err(RenderError::SizeMismatch(
                    "CacheBitmapV3: ex header truncated".into(),
                ));
            }
            cur = &cur[24..];
        }
        if cur.len() < length {
            return Err(RenderError::SizeMismatch(format!(
                "CacheBitmapV3: payload {length} but only {} bytes left",
                cur.len()
            )));
        }
        let payload = &cur[..length];
        let pixels_rgba = match (codec_id, bpp) {
            (0, 32) => {
                let expected = width as usize * height as usize * 4;
                if payload.len() != expected {
                    return Ok(());
                }
                bgra_to_rgba(payload)
            }
            (0, 24) => {
                let expected = width as usize * height as usize * 3;
                if payload.len() != expected {
                    return Ok(());
                }
                bgr_top_down_to_rgba(payload, width, height)
            }
            // Codec-encoded V3 entries (RFX / NSCodec / ClearCodec /
            // AVC) are recognized but not yet decoded into the cache.
            // S3d-6c5b would route through the existing codec dispatch.
            _ => return Ok(()),
        };
        self.bitmap_cache.insert(
            (cache_id, cache_index),
            CachedBitmap {
                width,
                height,
                pixels_rgba,
            },
        );
        Ok(())
    }

    /// `CacheGlyph` parser (MS-RDPEGDI 2.2.2.2.1.2.5 — V1 layout).
    ///
    /// `extraFlags` low 8 bits = cacheId; `body` layout:
    ///   cacheId         (u8)  — duplicated in extraFlags
    ///   cGlyphs         (u8)
    ///   array of cGlyphs entries:
    ///     cacheIndex    (u16 LE)
    ///     x, y          (i16 LE × 2) — origin (we ignore)
    ///     cx, cy        (u16 LE × 2)
    ///     aj            (cy * stride bytes, 1 bpp mask)
    /// where `stride = ((cx + 7) / 8 + 3) & ~3` per spec
    /// (each row aligned to 4 bytes).
    ///
    /// V2 (orderType 0x09) has a slightly different header but the
    /// glyph entries follow the same shape — V2 support deferred.
    fn cache_glyph(&mut self, extra_flags: u16, body: &[u8]) -> Result<(), RenderError> {
        if body.len() < 2 {
            return Err(RenderError::SizeMismatch(
                "CacheGlyph: header truncated".into(),
            ));
        }
        let _cache_id_dup = body[0];
        let cache_id = (extra_flags & 0xFF) as u8;
        let c_glyphs = body[1] as usize;
        let mut off = 2usize;
        for _ in 0..c_glyphs {
            if body.len() < off + 10 {
                return Err(RenderError::SizeMismatch(
                    "CacheGlyph: glyph header truncated".into(),
                ));
            }
            let cache_index = u16::from_le_bytes([body[off], body[off + 1]]);
            // x, y unused (text origin reset by GlyphIndex).
            let cx = u16::from_le_bytes([body[off + 6], body[off + 7]]);
            let cy = u16::from_le_bytes([body[off + 8], body[off + 9]]);
            off += 10;
            let row_bytes = ((cx as usize + 7) / 8 + 3) & !3;
            let mask_len = row_bytes * cy as usize;
            if body.len() < off + mask_len {
                return Err(RenderError::SizeMismatch(format!(
                    "CacheGlyph: glyph mask {mask_len} but {} bytes left",
                    body.len() - off
                )));
            }
            let mask = body[off..off + mask_len].to_vec();
            off += mask_len;
            self.glyph_cache.insert(
                (cache_id, cache_index),
                CachedGlyph {
                    cx,
                    cy,
                    stride: row_bytes as u16,
                    mask,
                },
            );
        }
        Ok(())
    }

    /// `CacheBrush` parser (MS-RDPEGDI 2.2.2.2.1.2.7).
    ///
    /// Body layout:
    ///   cacheEntry      (u8)  — index in [0, BRUSH_CACHE_SIZE)
    ///   iBitmapFormat   (u8)  — 1 = 1 bpp mono, 3 = 8 bpp, etc.
    ///   cx              (u8)  — width (must be 8)
    ///   cy              (u8)  — height (must be 8)
    ///   style           (u8)  — reserved
    ///   iBytes          (u8)  — count of brushData bytes
    ///   brushData       (iBytes)
    ///
    /// We accept only 8×8 1 bpp monochrome (the most common shape used
    /// by Windows for hatched / dithered fills). Higher color depths
    /// silently drop — the next PatBlt that references the missing
    /// entry will skip its blit rather than paint corrupted pixels.
    fn cache_brush(&mut self, body: &[u8]) -> Result<(), RenderError> {
        if body.len() < 6 {
            return Err(RenderError::SizeMismatch(
                "CacheBrush: header truncated".into(),
            ));
        }
        let cache_entry = body[0];
        let i_bitmap_format = body[1];
        let cx = body[2];
        let cy = body[3];
        let _style = body[4];
        let i_bytes = body[5] as usize;
        if cx != 8 || cy != 8 {
            return Ok(()); // non-8×8 brushes silently drop for now
        }
        if body.len() < 6 + i_bytes {
            return Err(RenderError::SizeMismatch(format!(
                "CacheBrush: iBytes={i_bytes} but only {} body bytes left",
                body.len() - 6
            )));
        }
        let brush_data = &body[6..6 + i_bytes];
        if i_bitmap_format != 1 {
            return Ok(()); // non-1bpp brushes deferred (S3d-6b3)
        }
        // 1 bpp 8×8 = 8 bytes, MSB-first row layout. The wire row
        // order on a CacheBrush is *reversed* (bottom-to-top per spec
        // remarks for Brush types — this is the same convention DIB
        // brushes use). Reverse on store so the renderer always sees
        // a top-down 8×8 mask.
        if brush_data.len() < 8 {
            return Ok(());
        }
        let mut rows = [0u8; 8];
        for i in 0..8 {
            rows[i] = brush_data[7 - i];
        }
        self.brush_cache.insert(cache_entry, rows);
        Ok(())
    }

    /// `CacheBitmapV2` parser (MS-RDPEGDI 2.2.2.2.1.2.3) — handles both
    /// the uncompressed (`orderType = 0x04`) and compressed
    /// (`orderType = 0x05`, RLE) variants behind one method.
    ///
    /// `extraFlags` holds the cache id, bpp code, and a flags byte; the
    /// body starts (optionally) with key1/key2 (8 bytes when persistent
    /// bit is set), then variable-length width / height / bitmapLength /
    /// cacheIndex, then the raw bitmap pixels.
    ///
    /// Supported per-bpp entries:
    /// * `bpp_code = 0x06` (32 bpp, BGRA top-down) — uncompressed only;
    ///   the compressed wire never advertises 32 bpp.
    /// * `bpp_code = 0x04` (16 bpp, RGB565) — uncompressed or RLE.
    /// Others silently drop (matching MemBlt look-ups will miss).
    fn cache_bitmap_v2(
        &mut self,
        extra_flags: u16,
        body: &[u8],
        compressed: bool,
    ) -> Result<(), RenderError> {
        const CBR2_PERSISTENT_KEY_PRESENT: u16 = 0x0100;
        const CBR2_HEIGHT_SAME_AS_WIDTH: u16 = 0x0200;
        const PIXEL_BPP_16: u8 = 0x04;
        const PIXEL_BPP_32: u8 = 0x06;

        let cache_id = (extra_flags & 0x07) as u8;
        let bpp_code = ((extra_flags >> 3) & 0x1F) as u8;
        let mut cur = body;
        if extra_flags & CBR2_PERSISTENT_KEY_PRESENT != 0 {
            if cur.len() < 8 {
                return Err(RenderError::SizeMismatch(
                    "CacheBitmapV2: persistent keys truncated".into(),
                ));
            }
            cur = &cur[8..];
        }
        let (width, mut cur) = read_two_byte_unsigned(cur, "bitmapWidth")?;
        let height = if extra_flags & CBR2_HEIGHT_SAME_AS_WIDTH != 0 {
            width
        } else {
            let (h, rest) = read_two_byte_unsigned(cur, "bitmapHeight")?;
            cur = rest;
            h
        };
        let (length, cur) = read_four_byte_unsigned(cur, "bitmapLength")?;
        let (cache_index, cur) = read_two_byte_unsigned(cur, "cacheIndex")?;
        if (length as usize) > cur.len() {
            return Err(RenderError::SizeMismatch(format!(
                "CacheBitmapV2: bitmapLength {length} exceeds remaining {} bytes",
                cur.len()
            )));
        }
        let payload = &cur[..length as usize];

        const PIXEL_BPP_24: u8 = 0x05;
        let pixels_rgba = match (compressed, bpp_code) {
            (false, PIXEL_BPP_32) => {
                let expected = width as usize * height as usize * 4;
                if payload.len() != expected {
                    return Ok(());
                }
                bgra_to_rgba(payload)
            }
            (false, PIXEL_BPP_24) => {
                let expected = width as usize * height as usize * 3;
                if payload.len() != expected {
                    return Ok(());
                }
                bgr_top_down_to_rgba(payload, width, height)
            }
            (false, PIXEL_BPP_16) => {
                let expected = width as usize * height as usize * 2;
                if payload.len() != expected {
                    return Ok(());
                }
                // Cache entries are top-down per MS-RDPEGDI cache
                // convention, the row flip is undesirable here; do the
                // RGB565 expansion without a flip.
                rgb565_top_down_to_rgba(payload, width, height)
            }
            (true, PIXEL_BPP_16) => {
                let mut raw = Vec::new();
                RleDecompressor::new()
                    .decompress(payload, width, height, BitsPerPixel::Bpp16, &mut raw)?;
                rgb565_top_down_to_rgba(&raw, width, height)
            }
            (true, PIXEL_BPP_24) => {
                let mut raw = Vec::new();
                RleDecompressor::new()
                    .decompress(payload, width, height, BitsPerPixel::Bpp24, &mut raw)?;
                bgr_top_down_to_rgba(&raw, width, height)
            }
            // 8 bpp would need a Palette PDU; CacheBitmapV1 / V3 use
            // different layouts. Tracked under S3d-6c5.
            _ => return Ok(()),
        };
        self.bitmap_cache.insert(
            (cache_id, cache_index),
            CachedBitmap {
                width,
                height,
                pixels_rgba,
            },
        );
        Ok(())
    }

    /// MemBlt: blit a sub-region of a cached bitmap into the surface.
    /// SRCCOPY (`0xCC`) is the fast path (no destination read-back).
    /// Other ROPs run through the [`rop3`] evaluator using the cached
    /// bitmap as `S`, the destination read via [`FrameSink::peek_rgba`]
    /// as `D`, and `P = 0xFF` (no pattern for MemBlt). When `peek_rgba`
    /// is unsupported the blit silently drops to avoid corrupting the
    /// display.
    fn try_render_memblt<S: FrameSink>(
        &mut self,
        order: &MemBltOrder,
        sink: &mut S,
    ) -> bool {
        let cache_id = (order.cache_id & 0xFF) as u8;
        let entry = match self.bitmap_cache.get(&(cache_id, order.cache_index)) {
            Some(e) => e.clone(), // brief clone to release self-borrow before sink.blit
            None => return false,
        };
        let w = order.width.max(0) as u16;
        let h = order.height.max(0) as u16;
        if w == 0 || h == 0 {
            return false;
        }
        let src_x = order.src_left.max(0) as u16;
        let src_y = order.src_top.max(0) as u16;
        let copy_w = w.min(entry.width.saturating_sub(src_x));
        let copy_h = h.min(entry.height.saturating_sub(src_y));
        if copy_w == 0 || copy_h == 0 {
            return false;
        }
        let dest_left = order.left.max(0) as u16;
        let dest_top = order.top.max(0) as u16;

        // Source pixels: crop the cached bitmap to (src_x, src_y, copy_w × copy_h).
        let row_stride = entry.width as usize * 4;
        let mut src = Vec::with_capacity(copy_w as usize * copy_h as usize * 4);
        for row in 0..copy_h as usize {
            let off = (src_y as usize + row) * row_stride + src_x as usize * 4;
            src.extend_from_slice(&entry.pixels_rgba[off..off + copy_w as usize * 4]);
        }

        const ROP3_SRCCOPY: u8 = 0xCC;
        if order.rop == ROP3_SRCCOPY {
            sink.blit_rgba(dest_left, dest_top, copy_w, copy_h, &src);
            return true;
        }

        // RMW: pull existing destination, evaluate ROP3 per channel.
        let mut dst = Vec::new();
        if !sink.peek_rgba(dest_left, dest_top, copy_w, copy_h, &mut dst) {
            return false;
        }
        if dst.len() != src.len() {
            return false;
        }
        let mut out = Vec::with_capacity(src.len());
        for (s_px, d_px) in src.chunks_exact(4).zip(dst.chunks_exact(4)) {
            // P=0xFF (no pattern for MemBlt). Apply the ROP per RGB channel;
            // alpha is held at 0xFF (RDP surfaces don't carry a real alpha).
            out.push(rop3(order.rop, 0xFF, s_px[0], d_px[0]));
            out.push(rop3(order.rop, 0xFF, s_px[1], d_px[1]));
            out.push(rop3(order.rop, 0xFF, s_px[2], d_px[2]));
            out.push(0xFF);
        }
        sink.blit_rgba(dest_left, dest_top, copy_w, copy_h, &out);
        true
    }

    /// Per-codec dispatch for one Surface Bits command.
    fn dispatch_surface_bits<S: FrameSink>(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        data: &BitmapDataEx,
        sink: &mut S,
    ) -> Result<bool, RenderError> {
        if data.codec_id == 0 {
            return blit_raw_surface_bits(dest_left, dest_top, data, sink);
        }
        if Some(data.codec_id) == self.rfx_codec_id {
            let blits = decode_rfx_stream(self, dest_left, dest_top, &data.bitmap_data, sink)?;
            return Ok(blits > 0);
        }
        if Some(data.codec_id) == self.nscodec_codec_id {
            return blit_nscodec_surface_bits(dest_left, dest_top, data, sink);
        }
        if Some(data.codec_id) == self.clearcodec_codec_id {
            let decoder = self.clearcodec_decoder.as_mut().expect(
                "set_clearcodec_codec_id allocates the decoder; this Option is always Some here",
            );
            return blit_clearcodec_surface_bits(decoder, dest_left, dest_top, data, sink);
        }
        if Some(data.codec_id) == self.avc420_codec_id {
            return self.blit_avc420_surface_bits(dest_left, dest_top, data, sink);
        }
        if Some(data.codec_id) == self.avc444_codec_id {
            return self.blit_avc444_surface_bits(
                dest_left,
                dest_top,
                data,
                sink,
                Avc444Layout::V1,
            );
        }
        if Some(data.codec_id) == self.avc444v2_codec_id {
            return self.blit_avc444_surface_bits(
                dest_left,
                dest_top,
                data,
                sink,
                Avc444Layout::V2,
            );
        }
        Err(RenderError::UnsupportedCodec {
            codec_id: data.codec_id,
        })
    }

    /// AVC420 single-stream blit. The wire format is
    /// `RDPGFX_AVC420_BITMAP_STREAM` (MS-RDPEGFX 2.2.4.4.1):
    /// numRegionRects + region rects + quantQualityVals + Annex B.
    /// We strip the metablock and feed the trailing Annex B to the
    /// injected `AvcDecoder`.
    fn blit_avc420_surface_bits<S: FrameSink>(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        data: &BitmapDataEx,
        sink: &mut S,
    ) -> Result<bool, RenderError> {
        let decoder = self
            .avc_decoder
            .as_mut()
            .ok_or(RenderError::AvcDecoderMissing)?;
        let annex_b = strip_avc420_metablock(&data.bitmap_data)?;
        let frame_opt = decoder.decode_frame(annex_b)?;
        let frame = frame_opt.ok_or(RenderError::AvcFrameUnavailable)?;
        blit_yuv420_frame(&frame, dest_left, dest_top, data.width, data.height, sink)?;
        Ok(true)
    }

    /// AVC444 (v1 / v2) blit. Wire layout:
    ///   `cbAvc420EncodedBitstream1` (u32 LE, high 4 bits = LC, low 28 = size)
    ///   `avc420EncodedBitstream1` (size bytes, RDPGFX_AVC420_BITMAP_STREAM)
    ///   `avc420EncodedBitstream2` (rest, optional, RDPGFX_AVC420_BITMAP_STREAM)
    ///
    /// LC code (MS-RDPEGFX 3.3.8.3):
    ///   0 → main view only (effectively AVC420; bitstream2 absent)
    ///   1 → chroma-only refresh — requires a cached previous luma; we
    ///       surface this as `RenderError::AvcLumaCacheRequired` rather
    ///       than rendering against a stale frame
    ///   2 → both bitstreams present, combine into YUV 4:4:4
    fn blit_avc444_surface_bits<S: FrameSink>(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        data: &BitmapDataEx,
        sink: &mut S,
        layout: Avc444Layout,
    ) -> Result<bool, RenderError> {
        if self.avc_decoder.is_none() {
            return Err(RenderError::AvcDecoderMissing);
        }
        let (lc, bitstream1, bitstream2) = parse_avc444_envelope(&data.bitmap_data)?;
        match lc {
            0 => {
                // Main view alone — same as AVC420.
                let decoder = self.avc_decoder.as_mut().unwrap();
                let annex_b = strip_avc420_metablock(bitstream1)?;
                let frame = decoder
                    .decode_frame(annex_b)?
                    .ok_or(RenderError::AvcFrameUnavailable)?;
                blit_yuv420_frame(&frame, dest_left, dest_top, data.width, data.height, sink)?;
                Ok(true)
            }
            2 => {
                let decoder = self.avc_decoder.as_mut().unwrap();
                let main_annex = strip_avc420_metablock(bitstream1)?;
                let main = decoder
                    .decode_frame(main_annex)?
                    .ok_or(RenderError::AvcFrameUnavailable)?;
                let aux_bytes =
                    bitstream2.ok_or_else(|| RenderError::SizeMismatch(
                        "AVC444 LC=2 missing bitstream2".into(),
                    ))?;
                let aux_annex = strip_avc420_metablock(aux_bytes)?;
                let aux = decoder
                    .decode_frame(aux_annex)?
                    .ok_or(RenderError::AvcFrameUnavailable)?;
                let yuv444 = match layout {
                    Avc444Layout::V1 => combine_avc444_planes(&main, &aux)?,
                    Avc444Layout::V2 => combine_avc444v2_planes(&main, &aux)?,
                };
                let pixel_count = data.width as usize * data.height as usize;
                let mut bgra = alloc::vec![0u8; pixel_count * 4];
                yuv444_to_bgra(&yuv444, &mut bgra, data.width as u32, data.height as u32)?;
                sink.blit_rgba(
                    dest_left,
                    dest_top,
                    data.width,
                    data.height,
                    &swap_bgra_to_rgba(&bgra),
                );
                Ok(true)
            }
            1 => Err(RenderError::AvcLumaCacheRequired),
            other => Err(RenderError::SizeMismatch(format!(
                "AVC444 envelope: unknown LC code {other}"
            ))),
        }
    }

    fn decode_bitmap_rects(&self, payload: &[u8]) -> Result<Vec<DecodedRect>, RenderError> {
        let mut cursor = ReadCursor::new(payload);
        let update = TsUpdateBitmapData::decode_fast_path(&mut cursor)?;
        let mut out: Vec<DecodedRect> = Vec::with_capacity(update.rectangles.len());
        for rect in &update.rectangles {
            out.push(decode_rect(rect, self.palette.as_ref())?);
        }
        Ok(out)
    }

    /// Decode a fast-path Palette update body and cache the result.
    ///
    /// Wire layout (MS-RDPBCGR 2.2.9.1.2.1.1.1):
    ///   pad2Octets   : u16 (skipped)
    ///   numberColors : u32 LE (must be 256)
    ///   paletteData  : 256 × 3 bytes (R, G, B per entry)
    fn update_palette(&mut self, data: &[u8]) -> Result<(), RenderError> {
        const HEADER_SIZE: usize = 2 + 4;
        if data.len() < HEADER_SIZE {
            return Err(RenderError::SizeMismatch(format!(
                "palette PDU truncated: got {} bytes, need at least {}",
                data.len(),
                HEADER_SIZE
            )));
        }
        let n = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
        if n != PALETTE_ENTRY_COUNT {
            return Err(RenderError::SizeMismatch(format!(
                "palette numberColors = {n}, expected {PALETTE_ENTRY_COUNT}"
            )));
        }
        let body_size = PALETTE_ENTRY_COUNT * 3;
        if data.len() < HEADER_SIZE + body_size {
            return Err(RenderError::SizeMismatch(format!(
                "palette body short: got {} bytes, need {}",
                data.len() - HEADER_SIZE,
                body_size
            )));
        }
        let mut pal = [(0u8, 0u8, 0u8); PALETTE_ENTRY_COUNT];
        for (i, slot) in pal.iter_mut().enumerate() {
            let off = HEADER_SIZE + i * 3;
            *slot = (data[off], data[off + 1], data[off + 2]);
        }
        self.palette = Some(pal);
        Ok(())
    }
}

/// Decode the fast-path Bitmap Update payload (everything *after* the
/// `updateCode` and `size` fields) into a flat list of top-down RGBA
/// rectangles. Stateless — for 8 bpp bitmaps you must use
/// [`BitmapRenderer`] instead so a Palette update can be cached first.
pub fn decode_bitmap_update_fast_path(
    payload: &[u8],
) -> Result<Vec<DecodedRect>, RenderError> {
    let mut cursor = ReadCursor::new(payload);
    let update = TsUpdateBitmapData::decode_fast_path(&mut cursor)?;
    let mut out: Vec<DecodedRect> = Vec::with_capacity(update.rectangles.len());
    for rect in &update.rectangles {
        out.push(decode_rect(rect, None)?);
    }
    Ok(out)
}

fn decode_rect(
    rect: &TsBitmapData,
    palette: Option<&[(u8, u8, u8); PALETTE_ENTRY_COUNT]>,
) -> Result<DecodedRect, RenderError> {
    let compressed = rect.flags & BITMAP_COMPRESSION != 0;

    // Stage 1: get raw bottom-up pixels at the source bpp.
    let raw_pixels: Vec<u8>;
    let raw_slice: &[u8];
    if compressed {
        let bpp = BitsPerPixel::from_raw(rect.bits_per_pixel).ok_or(
            RenderError::UnsupportedBpp {
                bits_per_pixel: rect.bits_per_pixel,
            },
        )?;
        let mut out = Vec::new();
        RleDecompressor::new()
            .decompress(&rect.bitmap_data, rect.width, rect.height, bpp, &mut out)?;
        raw_pixels = out;
        raw_slice = &raw_pixels;
    } else {
        let bpp_bytes = bpp_byte_size(rect.bits_per_pixel)?;
        let stride = rect.width as usize * bpp_bytes;
        let expected = stride * rect.height as usize;
        if rect.bitmap_data.len() != expected {
            return Err(RenderError::SizeMismatch(format!(
                "expected {} bytes for {}x{} @ {}bpp, got {}",
                expected,
                rect.width,
                rect.height,
                rect.bits_per_pixel,
                rect.bitmap_data.len()
            )));
        }
        raw_slice = &rect.bitmap_data;
    }

    // Stage 2: bottom-up source bpp → top-down RGBA, single pass.
    let pixels_rgba = match rect.bits_per_pixel {
        32 => flip_and_swap_32bpp(raw_slice, rect.width, rect.height),
        24 => flip_and_swap_24bpp(raw_slice, rect.width, rect.height),
        16 => flip_and_convert_rgb565(raw_slice, rect.width, rect.height),
        15 => flip_and_convert_rgb555(raw_slice, rect.width, rect.height),
        8 => {
            let pal = palette.ok_or(RenderError::PaletteMissing)?;
            flip_and_apply_palette(raw_slice, rect.width, rect.height, pal)
        }
        other => {
            return Err(RenderError::UnsupportedBpp {
                bits_per_pixel: other,
            });
        }
    };

    Ok(DecodedRect {
        dest_left: rect.dest_left,
        dest_top: rect.dest_top,
        width: rect.width,
        height: rect.height,
        pixels_rgba,
    })
}

/// Source-bpp byte width. Only the bpps we render here are accepted; the
/// rest are surfaced via `UnsupportedBpp` upstream.
fn bpp_byte_size(bpp: u16) -> Result<usize, RenderError> {
    match bpp {
        8 => Ok(1),
        15 | 16 => Ok(2),
        24 => Ok(3),
        32 => Ok(4),
        other => Err(RenderError::UnsupportedBpp {
            bits_per_pixel: other,
        }),
    }
}

/// codec_id == 0 path: raw, top-down 32 bpp BGRA pixels
/// (MS-RDPBCGR 2.2.9.2.1.2.1.1). BGRA → RGBA byte swap, no row flip.
fn blit_raw_surface_bits<S: FrameSink>(
    dest_left: u16,
    dest_top: u16,
    data: &BitmapDataEx,
    sink: &mut S,
) -> Result<bool, RenderError> {
    if data.bpp != 32 {
        return Err(RenderError::UnsupportedBpp {
            bits_per_pixel: data.bpp as u16,
        });
    }
    let expected = data.width as usize * data.height as usize * 4;
    if data.bitmap_data.len() != expected {
        return Err(RenderError::SizeMismatch(format!(
            "Surface raw bitmap: expected {} bytes for {}x{} @ 32bpp, got {}",
            expected,
            data.width,
            data.height,
            data.bitmap_data.len()
        )));
    }
    if expected == 0 {
        return Ok(false);
    }

    let mut rgba = Vec::with_capacity(expected);
    for px in data.bitmap_data.chunks_exact(4) {
        rgba.push(px[2]);
        rgba.push(px[1]);
        rgba.push(px[0]);
        rgba.push(px[3]);
    }
    sink.blit_rgba(dest_left, dest_top, data.width, data.height, &rgba);
    Ok(true)
}

/// AVC444 wire layout selector — picks `combine_avc444_planes` (v1) or
/// `combine_avc444v2_planes` (v2) per the registered codec_id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Avc444Layout {
    V1,
    V2,
}

/// `RDPGFX_AVC420_BITMAP_STREAM` (MS-RDPEGFX 2.2.4.4.1):
///   numRegionRects (u32 LE)
///   regionRects[N]              — 8 bytes each (left/top/right/bottom u16 LE)
///   quantQualityVals[N]         — 3 bytes each (qp + reserved + qualityVal)
///   avc420EncodedBitstream      — Annex B byte stream (rest of the buffer)
///
/// Returns the trailing Annex B slice. We don't interpret the region or
/// quant entries — they describe rectangles inside the destination
/// surface that the H.264 decoder already covers.
fn strip_avc420_metablock(data: &[u8]) -> Result<&[u8], RenderError> {
    if data.len() < 4 {
        return Err(RenderError::SizeMismatch(format!(
            "AVC420 stream truncated: {} bytes, need at least 4",
            data.len()
        )));
    }
    let n = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let after_count = 4usize;
    let after_rects = after_count
        .checked_add(n.checked_mul(8).ok_or_else(|| {
            RenderError::SizeMismatch("AVC420 numRegionRects overflow".into())
        })?)
        .ok_or_else(|| RenderError::SizeMismatch("AVC420 metablock overflow".into()))?;
    let after_quant = after_rects
        .checked_add(n.checked_mul(3).ok_or_else(|| {
            RenderError::SizeMismatch("AVC420 quant table overflow".into())
        })?)
        .ok_or_else(|| RenderError::SizeMismatch("AVC420 metablock overflow".into()))?;
    if data.len() < after_quant {
        return Err(RenderError::SizeMismatch(format!(
            "AVC420 stream short: need {after_quant} bytes for {n} regions, got {}",
            data.len()
        )));
    }
    Ok(&data[after_quant..])
}

/// `RDPGFX_AVC444_BITMAP_STREAM` envelope (MS-RDPEGFX 2.2.4.4.2 / .3):
///   cbAvc420EncodedBitstream1 (u32 LE) — high 4 bits = LC, low 28 = size
///   avc420EncodedBitstream1   (`size` bytes, RDPGFX_AVC420_BITMAP_STREAM)
///   avc420EncodedBitstream2   (rest of the buffer, optional)
fn parse_avc444_envelope(data: &[u8]) -> Result<(u8, &[u8], Option<&[u8]>), RenderError> {
    if data.len() < 4 {
        return Err(RenderError::SizeMismatch(format!(
            "AVC444 envelope truncated: {} bytes, need at least 4",
            data.len()
        )));
    }
    let header = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    // High 4 bits of the u32 → LC code; spec defines values 0–2.
    let lc = ((header >> 28) & 0x0F) as u8;
    let size1 = (header & 0x0FFF_FFFF) as usize;
    let body = &data[4..];
    if body.len() < size1 {
        return Err(RenderError::SizeMismatch(format!(
            "AVC444 envelope: cbAvc420EncodedBitstream1 = {size1} but body has {} bytes",
            body.len()
        )));
    }
    let bitstream1 = &body[..size1];
    let bitstream2 = if body.len() > size1 {
        Some(&body[size1..])
    } else {
        None
    };
    Ok((lc, bitstream1, bitstream2))
}

/// Convert one decoded `Yuv420Frame` to top-down RGBA and blit at
/// `(dest_left, dest_top)` with the *display* `width` / `height`. The
/// coded dimensions of `frame` may exceed the display size (16-aligned
/// macroblocks) — `yuv420_to_bgra` only writes the area that fits.
fn blit_yuv420_frame<S: FrameSink>(
    frame: &Yuv420Frame,
    dest_left: u16,
    dest_top: u16,
    width: u16,
    height: u16,
    sink: &mut S,
) -> Result<(), RenderError> {
    let pixel_count = width as usize * height as usize;
    let mut bgra = alloc::vec![0u8; pixel_count * 4];
    yuv420_to_bgra(frame, &mut bgra, width as u32, height as u32)?;
    sink.blit_rgba(dest_left, dest_top, width, height, &swap_bgra_to_rgba(&bgra));
    Ok(())
}

/// In-place would alias the buffer in test code; allocate a fresh vec
/// so callers can keep the source for further conversion.
fn swap_bgra_to_rgba(bgra: &[u8]) -> Vec<u8> {
    let mut rgba = Vec::with_capacity(bgra.len());
    for px in bgra.chunks_exact(4) {
        rgba.push(px[2]);
        rgba.push(px[1]);
        rgba.push(px[0]);
        rgba.push(px[3]);
    }
    rgba
}

/// NSCodec → BGRA → RGBA top-down blit. NSCodec output is always
/// 32 bpp, so we just do the byte-order swap and call the sink. Surface
/// Commands deliver pixels top-down (no row flip needed).
fn blit_nscodec_surface_bits<S: FrameSink>(
    dest_left: u16,
    dest_top: u16,
    data: &BitmapDataEx,
    sink: &mut S,
) -> Result<bool, RenderError> {
    if data.width == 0 || data.height == 0 {
        return Ok(false);
    }
    let mut bgra = Vec::new();
    NsCodecDecompressor::new()
        .decompress(&data.bitmap_data, data.width, data.height, &mut bgra)?;
    let mut rgba = Vec::with_capacity(bgra.len());
    for px in bgra.chunks_exact(4) {
        rgba.push(px[2]);
        rgba.push(px[1]);
        rgba.push(px[0]);
        rgba.push(px[3]);
    }
    sink.blit_rgba(dest_left, dest_top, data.width, data.height, &rgba);
    Ok(true)
}

/// ClearCodec → BGR (24 bpp) → RGBA (alpha = 0xFF). Pad to 32 bpp
/// during the channel swap so the sink stays uniform.
fn blit_clearcodec_surface_bits<S: FrameSink>(
    decoder: &mut ClearCodecDecoder,
    dest_left: u16,
    dest_top: u16,
    data: &BitmapDataEx,
    sink: &mut S,
) -> Result<bool, RenderError> {
    if data.width == 0 || data.height == 0 {
        return Ok(false);
    }
    let bgr = decoder.decode(&data.bitmap_data, data.width, data.height)?;
    let pixel_count = data.width as usize * data.height as usize;
    if bgr.len() != pixel_count * 3 {
        return Err(RenderError::SizeMismatch(format!(
            "ClearCodec: expected {} BGR bytes for {}x{}, got {}",
            pixel_count * 3,
            data.width,
            data.height,
            bgr.len()
        )));
    }
    let mut rgba = Vec::with_capacity(pixel_count * 4);
    for px in bgr.chunks_exact(3) {
        rgba.push(px[2]);
        rgba.push(px[1]);
        rgba.push(px[0]);
        rgba.push(0xFF);
    }
    sink.blit_rgba(dest_left, dest_top, data.width, data.height, &rgba);
    Ok(true)
}

/// Walk a TS_RFX_* block stream, updating `renderer.rfx_entropy` from
/// the Context block(s) and decoding every TileSet's tiles. Tiles are
/// blitted at `(dest_left + x_idx*64, dest_top + y_idx*64)`.
///
/// Image-mode streams (the common server pattern) carry the four
/// handshake blocks (Sync, CodecVersions, Channels, Context) before
/// every frame, so a single call here is sufficient. Video-mode
/// streams carry them once per session — we accept those too because
/// the loop just no-ops on missing blocks and the entropy field
/// retains its last value.
fn decode_rfx_stream<S: FrameSink>(
    renderer: &mut BitmapRenderer,
    dest_left: u16,
    dest_top: u16,
    payload: &[u8],
    sink: &mut S,
) -> Result<u32, RenderError> {
    let mut cursor = ReadCursor::new(payload);
    let mut blits: u32 = 0;
    while cursor.remaining() > 0 {
        // Peek the 2-byte block_type so each branch can re-read it
        // through the typed decoder (which validates the value).
        if cursor.remaining() < 2 {
            return Err(RenderError::SizeMismatch(format!(
                "RFX block stream truncated: {} bytes left",
                cursor.remaining()
            )));
        }
        let head = cursor.peek_remaining();
        let block_type = u16::from_le_bytes([head[0], head[1]]);
        match block_type {
            WBT_SYNC => {
                RfxSync::decode(&mut cursor)?;
            }
            WBT_CODEC_VERSIONS => {
                RfxCodecVersions::decode(&mut cursor)?;
            }
            WBT_CHANNELS => {
                RfxChannels::decode(&mut cursor)?;
            }
            WBT_CONTEXT => {
                let ctx = RfxContext::decode(&mut cursor)?;
                renderer.rfx_entropy = ctx.properties.entropy;
            }
            WBT_FRAME_BEGIN => {
                RfxFrameBegin::decode(&mut cursor)?;
            }
            WBT_REGION => {
                RfxRegion::decode(&mut cursor)?;
            }
            WBT_EXTENSION => {
                let tileset = RfxTileSet::decode(&mut cursor)?;
                blits = blits.saturating_add(blit_rfx_tileset(
                    &tileset,
                    renderer.rfx_entropy,
                    dest_left,
                    dest_top,
                    sink,
                )?);
            }
            WBT_FRAME_END => {
                RfxFrameEnd::decode(&mut cursor)?;
            }
            other => {
                return Err(RenderError::SizeMismatch(format!(
                    "RFX: unknown block_type 0x{other:04X}"
                )));
            }
        }
    }
    Ok(blits)
}

/// Field-flags byte count per Primary order type (MS-RDPEGDI 2.2.2.2.1.1.2).
/// Mirrors the private helper in `justrdp_pdu::rdp::drawing_orders` —
/// duplicated here because the decoder helpers don't take the byte count
/// as input, they leave it to the caller.
fn primary_field_flags_byte_count(order_type: PrimaryOrderType) -> usize {
    match order_type {
        PrimaryOrderType::DstBlt
        | PrimaryOrderType::ScrBlt
        | PrimaryOrderType::DrawNineGrid
        | PrimaryOrderType::OpaqueRect
        | PrimaryOrderType::SaveBitmap
        | PrimaryOrderType::MultiDstBlt
        | PrimaryOrderType::Polyline
        | PrimaryOrderType::PolygonSc
        | PrimaryOrderType::EllipseSc => 1,
        PrimaryOrderType::PatBlt
        | PrimaryOrderType::LineTo
        | PrimaryOrderType::MemBlt
        | PrimaryOrderType::MultiDrawNineGrid
        | PrimaryOrderType::MultiPatBlt
        | PrimaryOrderType::MultiScrBlt
        | PrimaryOrderType::MultiOpaqueRect
        | PrimaryOrderType::FastIndex
        | PrimaryOrderType::PolygonCb
        | PrimaryOrderType::FastGlyph
        | PrimaryOrderType::EllipseCb => 2,
        PrimaryOrderType::Mem3Blt | PrimaryOrderType::GlyphIndex => 3,
    }
}

/// ROP3 (MS-RDPEGDI 2.2.2.2.1.1.1.7) general truth-table evaluator.
///
/// The `rop` byte's 8 bits define the output for each of 8 input
/// combinations of (P, S, D) ∈ {0,1}³. The lookup index is
/// `(P << 2) | (S << 1) | D`, so:
///
/// ```text
///   bit 0 → output for (P=0, S=0, D=0)
///   bit 7 → output for (P=1, S=1, D=1)
/// ```
///
/// We evaluate per-bit across the 8 bits of each channel byte so the
/// same code handles SRCCOPY (0xCC = `D := S`), SRCAND (0x88 = `D := S
/// & D`), PATPAINT (0xFB = `D := (~S) | P | D`), DSTINVERT (0x55 =
/// `D := ~D`), and the rest of the 256 codes uniformly.
fn rop3(rop: u8, p: u8, s: u8, d: u8) -> u8 {
    let mut out = 0u8;
    for bit in 0..8 {
        let mask = 1u8 << bit;
        let pb = ((p & mask) != 0) as u8;
        let sb = ((s & mask) != 0) as u8;
        let db = ((d & mask) != 0) as u8;
        let idx = (pb << 2) | (sb << 1) | db;
        if rop & (1u8 << idx) != 0 {
            out |= mask;
        }
    }
    out
}

/// Composite a 1 bpp glyph mask onto `sink` at `(pen_x, pen_y)` using
/// `fore_rgba` for set bits and skipping unset bits (transparent).
///
/// The mask is row-major top-down with `g.stride` bytes per row, MSB
/// = leftmost pixel. Issues one tiny `blit_rgba` per filled pixel —
/// not optimal, but correct against any FrameSink. A future
/// optimization could batch contiguous runs.
fn composite_glyph_mask<S: FrameSink>(
    g: &CachedGlyph,
    pen_x: i32,
    pen_y: i32,
    fore_rgba: &[u8; 4],
    sink: &mut S,
) -> bool {
    let mut any = false;
    for row in 0..g.cy as usize {
        let row_start = row * g.stride as usize;
        for col in 0..g.cx as usize {
            let byte = g.mask[row_start + col / 8];
            let bit = 7 - (col & 7);
            if (byte >> bit) & 1 != 0 {
                let x = pen_x + col as i32;
                let y = pen_y + row as i32;
                if x >= 0 && y >= 0 && x <= u16::MAX as i32 && y <= u16::MAX as i32 {
                    sink.blit_rgba(x as u16, y as u16, 1, 1, fore_rgba);
                    any = true;
                }
            }
        }
    }
    any
}

/// Skip-only `GlyphIndex` body parser (MS-RDPEGDI 2.2.2.2.1.1.2.13).
///
/// Retained for callers that need to advance past a GlyphIndex order
/// without bringing the renderer's glyph cache into scope. The
/// real renderer path uses `BitmapRenderer::try_render_glyph_index`.
#[allow(dead_code)]
fn decode_glyph_index_inline(
    cursor: &mut ReadCursor<'_>,
    field_flags: u32,
    _history: &mut PrimaryOrderHistory,
) -> Result<usize, RenderError> {
    // Field 1..4: cacheId, flAccel, ulCharInc, fOpRedundant (u8 each).
    for i in 0..4 {
        if field_flags & (1u32 << i) != 0 {
            cursor.read_u8("GlyphIndex::headerByte")?;
        }
    }
    // Field 5..6: BackColor, ForeColor (3 bytes each).
    for i in 4..6 {
        if field_flags & (1u32 << i) != 0 {
            cursor.read_u8("GlyphIndex::color[0]")?;
            cursor.read_u8("GlyphIndex::color[1]")?;
            cursor.read_u8("GlyphIndex::color[2]")?;
        }
    }
    // Field 7..14: BkLeft/Top/Right/Bottom + OpLeft/Top/Right/Bottom (i16 each).
    for i in 6..14 {
        if field_flags & (1u32 << i) != 0 {
            cursor.read_u16_le("GlyphIndex::rectField")?;
        }
    }
    // Field 15..16: BrushOrgX, BrushOrgY (u8 each).
    for i in 14..16 {
        if field_flags & (1u32 << i) != 0 {
            cursor.read_u8("GlyphIndex::brushOrg")?;
        }
    }
    // Field 17..18: BrushStyle, BrushHatch (u8 each).
    for i in 16..18 {
        if field_flags & (1u32 << i) != 0 {
            cursor.read_u8("GlyphIndex::brushSel")?;
        }
    }
    // Field 19: BrushExtra (7 bytes).
    if field_flags & (1u32 << 18) != 0 {
        for _ in 0..7 {
            cursor.read_u8("GlyphIndex::brushExtra")?;
        }
    }
    // Field 20..21: x, y (u16 each — TS_GLYPH_INDEX uses unsigned).
    for i in 19..21 {
        if field_flags & (1u32 << i) != 0 {
            cursor.read_u16_le("GlyphIndex::pos")?;
        }
    }
    // Field 22: cbData (u8) + that many trailing bytes of glyph commands.
    let mut consumed = 0usize;
    if field_flags & (1u32 << 21) != 0 {
        let cb = cursor.read_u8("GlyphIndex::cbData")? as usize;
        cursor.read_slice(cb, "GlyphIndex::variableData")?;
        consumed = cb;
    }
    Ok(consumed)
}

/// Scan-line polygon fill in `color_rgba`. Standard even-odd / non-
/// zero algorithm: for each scanline that crosses any edge, gather
/// x-intersections, sort, fill between each pair. Issues one tiny
/// `blit_rgba` per filled span.
fn scanline_fill_polygon<S: FrameSink>(
    verts: &[(i32, i32)],
    color_rgba: &[u8; 4],
    sink: &mut S,
) {
    if verts.len() < 3 {
        return;
    }
    let min_y = verts.iter().map(|v| v.1).min().unwrap();
    let max_y = verts.iter().map(|v| v.1).max().unwrap();
    let n = verts.len();
    for y in min_y..=max_y {
        let mut crossings: Vec<i32> = Vec::new();
        for i in 0..n {
            let (x0, y0) = verts[i];
            let (x1, y1) = verts[(i + 1) % n];
            // Half-open interval test: include the lower endpoint, exclude upper.
            let (lo_y, hi_y, lo_x, hi_x) = if y0 < y1 {
                (y0, y1, x0, x1)
            } else if y0 > y1 {
                (y1, y0, x1, x0)
            } else {
                continue; // horizontal edge — skip
            };
            if y < lo_y || y >= hi_y {
                continue;
            }
            // Linear interpolation; integer-only for simplicity.
            let t_num = y - lo_y;
            let t_den = hi_y - lo_y;
            let x = lo_x + (hi_x - lo_x) * t_num / t_den;
            crossings.push(x);
        }
        crossings.sort_unstable();
        for chunk in crossings.chunks(2) {
            if chunk.len() < 2 {
                break;
            }
            let xs = chunk[0].max(0);
            let xe = chunk[1].min(u16::MAX as i32);
            if xs >= xe {
                continue;
            }
            if y < 0 || y > u16::MAX as i32 {
                continue;
            }
            let span = (xe - xs) as u16;
            let pixels: Vec<u8> = core::iter::repeat(*color_rgba)
                .take(span as usize)
                .flatten()
                .collect();
            sink.blit_rgba(xs as u16, y as u16, span, 1, &pixels);
        }
    }
}


/// Bresenham line raster between two points; one tiny `blit_rgba` per
/// pixel so the implementation stays trivially correct against any
/// FrameSink. Shared by [`try_render_lineto`] and the Polyline path.
fn draw_bresenham_segment<S: FrameSink>(
    mut x0: i32,
    mut y0: i32,
    x1: i32,
    y1: i32,
    color_rgba: &[u8; 4],
    sink: &mut S,
) {
    let dx = (x1 - x0).abs();
    let dy = -(y1 - y0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;
    let mut budget = 16_384i32;
    loop {
        if x0 >= 0 && y0 >= 0 && x0 <= u16::MAX as i32 && y0 <= u16::MAX as i32 {
            sink.blit_rgba(x0 as u16, y0 as u16, 1, 1, color_rgba);
        }
        if x0 == x1 && y0 == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x0 += sx;
        }
        if e2 <= dx {
            err += dx;
            y0 += sy;
        }
        budget -= 1;
        if budget <= 0 {
            break;
        }
    }
}

/// BGRA → RGBA byte-order swap (no row flip).
fn bgra_to_rgba(pixels: &[u8]) -> Vec<u8> {
    let mut rgba = Vec::with_capacity(pixels.len());
    for px in pixels.chunks_exact(4) {
        rgba.push(px[2]);
        rgba.push(px[1]);
        rgba.push(px[0]);
        rgba.push(px[3]);
    }
    rgba
}

/// Top-down BGR (24 bpp) → top-down RGBA (alpha = 0xFF). Used by the
/// CacheBitmapV2 24-bpp path (cache convention is top-down).
fn bgr_top_down_to_rgba(src: &[u8], width: u16, height: u16) -> Vec<u8> {
    let stride = width as usize * 3;
    let mut out = Vec::with_capacity(width as usize * height as usize * 4);
    for row in 0..height as usize {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for px in row_bytes.chunks_exact(3) {
            out.push(px[2]);
            out.push(px[1]);
            out.push(px[0]);
            out.push(0xFF);
        }
    }
    out
}

/// Top-down RGB565 (LE u16) → top-down RGBA (alpha = 0xFF). Mirrors
/// [`flip_and_convert_rgb565`] but skips the row flip — used for
/// CacheBitmapV2 entries which are stored top-down by spec.
fn rgb565_top_down_to_rgba(src: &[u8], width: u16, height: u16) -> Vec<u8> {
    let stride = width as usize * 2;
    let mut out = Vec::with_capacity(width as usize * height as usize * 4);
    for row in 0..height as usize {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for px in row_bytes.chunks_exact(2) {
            let v = u16::from_le_bytes([px[0], px[1]]);
            let r5 = ((v >> 11) & 0x1F) as u8;
            let g6 = ((v >> 5) & 0x3F) as u8;
            let b5 = (v & 0x1F) as u8;
            out.push((r5 << 3) | (r5 >> 2));
            out.push((g6 << 2) | (g6 >> 4));
            out.push((b5 << 3) | (b5 >> 2));
            out.push(0xFF);
        }
    }
    out
}

/// `TWO_BYTE_UNSIGNED_ENCODING` (MS-RDPEGDI 2.2.2.2.1.1.1.2):
/// * High bit clear → 7-bit value in single byte.
/// * High bit set   → 15-bit value across 2 bytes (big-endian, MSB byte first).
fn read_two_byte_unsigned<'a>(
    data: &'a [u8],
    field: &'static str,
) -> Result<(u16, &'a [u8]), RenderError> {
    if data.is_empty() {
        return Err(RenderError::SizeMismatch(format!(
            "{field}: TWO_BYTE_UNSIGNED truncated"
        )));
    }
    if data[0] & 0x80 == 0 {
        Ok((data[0] as u16, &data[1..]))
    } else {
        if data.len() < 2 {
            return Err(RenderError::SizeMismatch(format!(
                "{field}: TWO_BYTE_UNSIGNED long form truncated"
            )));
        }
        let value = (((data[0] & 0x7F) as u16) << 8) | data[1] as u16;
        Ok((value, &data[2..]))
    }
}

/// `FOUR_BYTE_UNSIGNED_ENCODING` (MS-RDPEGDI 2.2.2.2.1.1.1.3):
/// First byte's top 2 bits encode the byte count (00→1, 01→2, 10→3, 11→4);
/// the remaining bits across all bytes form a big-endian unsigned integer.
fn read_four_byte_unsigned<'a>(
    data: &'a [u8],
    field: &'static str,
) -> Result<(u32, &'a [u8]), RenderError> {
    if data.is_empty() {
        return Err(RenderError::SizeMismatch(format!(
            "{field}: FOUR_BYTE_UNSIGNED truncated"
        )));
    }
    let n = ((data[0] >> 6) & 0x03) as usize + 1;
    if data.len() < n {
        return Err(RenderError::SizeMismatch(format!(
            "{field}: FOUR_BYTE_UNSIGNED needs {n} bytes, have {}",
            data.len()
        )));
    }
    let mut value: u32 = (data[0] & 0x3F) as u32;
    for &b in &data[1..n] {
        value = (value << 8) | b as u32;
    }
    Ok((value, &data[n..]))
}

/// PatBlt brush styles (MS-RDPEGDI 2.2.2.2.1.1.1.8).
const BS_SOLID: u8 = 0x00;

/// PatBlt raster operation: PATCOPY (MS-RDPEGDI 2.2.2.2.1.1.1.7).
const ROP3_PATCOPY: u8 = 0xF0;

/// DstBlt ROPs we can render without reading the destination back.
const ROP3_BLACKNESS: u8 = 0x00;
const ROP3_WHITENESS: u8 = 0xFF;

/// Render a Polyline order via Bresenham segments in pen color.
fn try_render_polyline<S: FrameSink>(order: &PolylineOrder, sink: &mut S) -> bool {
    let pen_color_rgba = [
        order.pen_color[2],
        order.pen_color[1],
        order.pen_color[0],
        0xFF,
    ];
    let mut x = order.x_start as i32;
    let mut y = order.y_start as i32;
    for d in &order.deltas {
        let nx = x + d.dx as i32;
        let ny = y + d.dy as i32;
        draw_bresenham_segment(x, y, nx, ny, &pen_color_rgba, sink);
        x = nx;
        y = ny;
    }
    true
}

/// PolygonSC: solid-color scan-line fill.
fn try_render_polygon_sc<S: FrameSink>(order: &PolygonScOrder, sink: &mut S) -> bool {
    if order.deltas.is_empty() {
        return false;
    }
    let mut verts: Vec<(i32, i32)> = Vec::with_capacity(order.deltas.len() + 1);
    verts.push((order.x_start as i32, order.y_start as i32));
    let mut x = order.x_start as i32;
    let mut y = order.y_start as i32;
    for d in &order.deltas {
        x += d.dx as i32;
        y += d.dy as i32;
        verts.push((x, y));
    }
    if verts.len() < 3 {
        return false;
    }
    let fill_color_rgba = [
        order.brush_color[2],
        order.brush_color[1],
        order.brush_color[0],
        0xFF,
    ];
    scanline_fill_polygon(&verts, &fill_color_rgba, sink);
    true
}

/// PolygonCB: scan-line fill, currently solid `brush_color` only —
/// the textured-pattern path lands in S3d-6g2-pattern.
fn try_render_polygon_cb<S: FrameSink>(
    order: &PolygonCbOrder,
    _renderer_brush_cache: &BTreeMap<u8, [u8; 8]>,
    sink: &mut S,
) -> bool {
    if order.deltas.is_empty() {
        return false;
    }
    let mut verts: Vec<(i32, i32)> = Vec::with_capacity(order.deltas.len() + 1);
    verts.push((order.x_start as i32, order.y_start as i32));
    let mut x = order.x_start as i32;
    let mut y = order.y_start as i32;
    for d in &order.deltas {
        x += d.dx as i32;
        y += d.dy as i32;
        verts.push((x, y));
    }
    if verts.len() < 3 {
        return false;
    }
    let fill_color_rgba = [
        order.brush_color[2],
        order.brush_color[1],
        order.brush_color[0],
        0xFF,
    ];
    scanline_fill_polygon(&verts, &fill_color_rgba, sink);
    true
}

/// `BS_HATCHED` brush style (predefined 8×8 hatch pattern selected by
/// `brush_hatch`).
const BS_HATCHED: u8 = 0x02;

/// `BS_PATTERN` brush style (8×8 monochrome inline pattern carried in
/// `brush_hatch` + `brush_extra`, OR cache index when the high bit of
/// the brush_style byte is set).
const BS_PATTERN: u8 = 0x03;

/// Hatch index (MS-RDPEGDI 2.2.2.2.1.1.1.8 brushHatch).
const HS_HORIZONTAL: u8 = 0;
const HS_VERTICAL: u8 = 1;
const HS_FDIAGONAL: u8 = 2;
const HS_BDIAGONAL: u8 = 3;
const HS_CROSS: u8 = 4;
const HS_DIAGCROSS: u8 = 5;

/// Six predefined 8×8 hatch patterns (rows 0..7, MSB = leftmost column).
fn hatch_pattern(index: u8) -> Option<[u8; 8]> {
    Some(match index {
        HS_HORIZONTAL => [0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00],
        HS_VERTICAL => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10],
        HS_FDIAGONAL => [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01],
        HS_BDIAGONAL => [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80],
        HS_CROSS => [0x10, 0x10, 0x10, 0xFF, 0x10, 0x10, 0x10, 0x10],
        HS_DIAGCROSS => [0x81, 0x42, 0x24, 0x18, 0x18, 0x24, 0x42, 0x81],
        _ => return None,
    })
}

/// Render PatBlt covering both `BS_SOLID` and `BS_PATTERN` brush styles,
/// for both PATCOPY (no read-back) and the read-modify-write ROPs
/// (PATPAINT, PATINVERT, …) via [`rop3`] + [`FrameSink::peek_rgba`].
///
/// For an 8×8 monochrome `BS_PATTERN`, the pattern data lives inline in
/// the PatBlt order itself (`brush_hatch` is the first byte = top row,
/// `brush_extra` holds the remaining 7 rows). Each pattern bit picks
/// foreground (1) or background (0) for that pixel position before the
/// ROP3 mixes it with the existing destination.
fn try_render_patblt<S: FrameSink>(
    order: &PatBltOrder,
    renderer_brush_cache: &BTreeMap<u8, [u8; 8]>,
    sink: &mut S,
) -> bool {
    let w = order.width.max(0) as u16;
    let h = order.height.max(0) as u16;
    if w == 0 || h == 0 {
        return false;
    }
    let dest_left = order.left.max(0) as u16;
    let dest_top = order.top.max(0) as u16;

    // Resolve the source pattern (`P`). The high bit of brush_style
    // (0x80) marks "cached pattern" — the brush_hatch byte then is a
    // CacheBrush index. Otherwise:
    //   BS_SOLID    → no pattern, fore_color everywhere.
    //   BS_HATCHED  → predefined hatch index in brush_hatch.
    //   BS_PATTERN  → 8×8 inline pattern in brush_hatch + brush_extra.
    let cached_brush_bit = order.brush_style & 0x80 != 0;
    let style_low = order.brush_style & 0x7F;
    let pattern_rows: Option<[u8; 8]> = if cached_brush_bit {
        renderer_brush_lookup(renderer_brush_cache, order.brush_hatch)
    } else {
        match style_low {
            BS_SOLID => None,
            BS_HATCHED => hatch_pattern(order.brush_hatch),
            BS_PATTERN => Some([
                order.brush_hatch,
                order.brush_extra[0],
                order.brush_extra[1],
                order.brush_extra[2],
                order.brush_extra[3],
                order.brush_extra[4],
                order.brush_extra[5],
                order.brush_extra[6],
            ]),
            _ => return false,
        }
    };
    let pattern_pixels: Option<Vec<u8>> = pattern_rows.map(|rows| {
        materialize_pattern(rows, order.brush_org_x, order.brush_org_y, w, h)
    });

    if order.rop == ROP3_PATCOPY {
        // No destination read-back needed.
        let mut out = Vec::with_capacity(w as usize * h as usize * 4);
        for row in 0..h as usize {
            for col in 0..w as usize {
                let bit_set = patblt_bit_set(&pattern_pixels, col, row, w);
                let (r, g, b) = if bit_set || pattern_pixels.is_none() {
                    (order.fore_color[0], order.fore_color[1], order.fore_color[2])
                } else {
                    (order.back_color[0], order.back_color[1], order.back_color[2])
                };
                out.push(r);
                out.push(g);
                out.push(b);
                out.push(0xFF);
            }
        }
        sink.blit_rgba(dest_left, dest_top, w, h, &out);
        return true;
    }

    // RMW path: read destination, evaluate ROP3 per channel with
    // P = (pattern bit ? fore : back), S = 0 (PatBlt has no source).
    let mut dst = Vec::new();
    if !sink.peek_rgba(dest_left, dest_top, w, h, &mut dst) {
        return false;
    }
    let mut out = Vec::with_capacity(dst.len());
    let mut idx = 0;
    for row in 0..h as usize {
        for col in 0..w as usize {
            let bit_set = patblt_bit_set(&pattern_pixels, col, row, w);
            let (pr, pg, pb) = if bit_set || pattern_pixels.is_none() {
                (order.fore_color[0], order.fore_color[1], order.fore_color[2])
            } else {
                (order.back_color[0], order.back_color[1], order.back_color[2])
            };
            let dr = dst[idx];
            let dg = dst[idx + 1];
            let db = dst[idx + 2];
            out.push(rop3(order.rop, pr, 0, dr));
            out.push(rop3(order.rop, pg, 0, dg));
            out.push(rop3(order.rop, pb, 0, db));
            out.push(0xFF);
            idx += 4;
        }
    }
    sink.blit_rgba(dest_left, dest_top, w, h, &out);
    true
}

/// Materialize an 8×8 monochrome pattern (`rows` MSB-first per row,
/// row 0 at top) tiled to fill `(w × h)` with the given brush origin
/// offset, returning one byte per pixel: 0 = background, 1 = foreground.
fn materialize_pattern(rows: [u8; 8], org_x: i8, org_y: i8, w: u16, h: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(w as usize * h as usize);
    let ox = (org_x as i32).rem_euclid(8) as usize;
    let oy = (org_y as i32).rem_euclid(8) as usize;
    for row in 0..h as usize {
        let pat_row = rows[(row + oy) & 7];
        for col in 0..w as usize {
            let bit = 7 - ((col + ox) & 7);
            p.push((pat_row >> bit) & 1);
        }
    }
    p
}

fn patblt_bit_set(pattern: &Option<Vec<u8>>, col: usize, row: usize, w: u16) -> bool {
    match pattern {
        Some(p) => p[row * w as usize + col] != 0,
        None => true,
    }
}

/// Helper that takes a `&BTreeMap<u8, [u8; 8]>` reference even though
/// the renderer's brush_cache is reached through `&self`. We don't
/// thread the renderer down into `try_render_patblt` (which is a free
/// function, not a method) because the call site already has the
/// cache borrow available; this signature keeps the look-up local.
fn renderer_brush_lookup(cache: &BTreeMap<u8, [u8; 8]>, index: u8) -> Option<[u8; 8]> {
    cache.get(&index).copied()
}

/// DstBlt ROP that XORs every channel — needs destination read-back.
const ROP3_DSTINVERT: u8 = 0x55;

/// Render a DstBlt order. Three ROP groups:
///
/// * `BLACKNESS` (0x00) → fill rect with `(0, 0, 0, 0xFF)`.
/// * `WHITENESS` (0xFF) → fill rect with `(0xFF, 0xFF, 0xFF, 0xFF)`.
/// * `DSTINVERT` (0x55) → read existing pixels back, invert R/G/B,
///   re-blit. Requires the sink to implement
///   [`FrameSink::peek_rgba`]; sinks that don't (the trait default)
///   silently drop the blit so the display doesn't decay.
///
/// Other ROPs (BLACKBORDER, etc.) are still skipped pending S3d-6h
/// expansion of the read-modify-write ROP set.
fn try_render_dstblt<S: FrameSink>(order: &DstBltOrder, sink: &mut S) -> bool {
    let w = order.width.max(0) as u16;
    let h = order.height.max(0) as u16;
    if w == 0 || h == 0 {
        return false;
    }
    let dest_left = order.left.max(0) as u16;
    let dest_top = order.top.max(0) as u16;
    if order.rop == ROP3_DSTINVERT {
        let mut buf = Vec::new();
        if !sink.peek_rgba(dest_left, dest_top, w, h, &mut buf) {
            return false;
        }
        // Invert RGB channels in-place; alpha untouched.
        for px in buf.chunks_exact_mut(4) {
            px[0] = !px[0];
            px[1] = !px[1];
            px[2] = !px[2];
        }
        sink.blit_rgba(dest_left, dest_top, w, h, &buf);
        return true;
    }
    let color = match order.rop {
        ROP3_BLACKNESS => [0x00, 0x00, 0x00, 0xFF],
        ROP3_WHITENESS => [0xFF, 0xFF, 0xFF, 0xFF],
        _ => return false,
    };
    let pixels: Vec<u8> = core::iter::repeat(color)
        .take((w as usize) * (h as usize))
        .flatten()
        .collect();
    sink.blit_rgba(dest_left, dest_top, w, h, &pixels);
    true
}

/// Render a LineTo order as a single-pixel-wide Bresenham line in the
/// pen color. `pen_width` and the dashed `pen_style` codes are ignored
/// for now (the embedder loses dotted/dashed lines and ≥2px widths,
/// which is acceptable for the legacy GDI traffic that still emits
/// LineTo). `back_color` and `back_mode` (used for transparent vs
/// opaque dashed lines) are ignored for the same reason.
///
/// Issues one tiny `blit_rgba` per pixel so the implementation stays
/// trivially correct against any FrameSink. A future optimization can
/// batch into a per-segment scratch buffer.
fn try_render_lineto<S: FrameSink>(order: &LineToOrder, sink: &mut S) -> bool {
    let pen_color = [
        order.pen_color[0],
        order.pen_color[1],
        order.pen_color[2],
        0xFF,
    ];
    draw_bresenham_segment(
        order.start_x as i32,
        order.start_y as i32,
        order.end_x as i32,
        order.end_y as i32,
        &pen_color,
        sink,
    );
    true
}

/// Render an OpaqueRect order: a rectangle filled with one solid color.
///
/// `width` / `height` are encoded as the rectangle's pixel dimensions
/// directly per MS-RDPEGDI 2.2.2.2.1.1.2.5; we clamp negatives to zero
/// rather than wrapping (the server never sends negative width but the
/// renderer is defensive).
fn blit_opaque_rect<S: FrameSink>(order: &OpaqueRectOrder, sink: &mut S) {
    let w = order.width.max(0) as u16;
    let h = order.height.max(0) as u16;
    if w == 0 || h == 0 {
        return;
    }
    let pixels: Vec<u8> = core::iter::repeat([order.red, order.green, order.blue, 0xFF])
        .take((w as usize) * (h as usize))
        .flatten()
        .collect();
    sink.blit_rgba(
        order.left.max(0) as u16,
        order.top.max(0) as u16,
        w,
        h,
        &pixels,
    );
}

/// Decode every tile in a TileSet and blit it at its grid position.
fn blit_rfx_tileset<S: FrameSink>(
    tileset: &RfxTileSet,
    entropy: RlgrMode,
    dest_left: u16,
    dest_top: u16,
    sink: &mut S,
) -> Result<u32, RenderError> {
    let decoder = RfxDecoder::new(entropy);
    let mut tile_bgra: Vec<u8> = Vec::with_capacity(TILE_COEFFICIENTS * 4);
    let mut tile_rgba: Vec<u8> = Vec::with_capacity(TILE_COEFFICIENTS * 4);
    let num_quants = tileset.quant_vals.len();
    let mut blits: u32 = 0;

    for tile in &tileset.tiles {
        for (idx, _label) in [
            (tile.quant_idx_y, "Y"),
            (tile.quant_idx_cb, "Cb"),
            (tile.quant_idx_cr, "Cr"),
        ] {
            if (idx as usize) >= num_quants {
                return Err(RenderError::RfxQuantIndexOutOfRange {
                    quant_idx: idx,
                    num_quants: num_quants as u8,
                });
            }
        }
        let q_y = &tileset.quant_vals[tile.quant_idx_y as usize];
        let q_cb = &tileset.quant_vals[tile.quant_idx_cb as usize];
        let q_cr = &tileset.quant_vals[tile.quant_idx_cr as usize];
        decoder.decode_tile(
            &tile.y_data,
            &tile.cb_data,
            &tile.cr_data,
            q_y,
            q_cb,
            q_cr,
            &mut tile_bgra,
        )?;
        // BGRA → RGBA into a separate buffer so subsequent tiles can
        // reuse `tile_bgra` without reallocating.
        tile_rgba.clear();
        tile_rgba.reserve(tile_bgra.len());
        for px in tile_bgra.chunks_exact(4) {
            tile_rgba.push(px[2]);
            tile_rgba.push(px[1]);
            tile_rgba.push(px[0]);
            tile_rgba.push(px[3]);
        }
        let x = dest_left.saturating_add(tile.x_idx.saturating_mul(TILE_SIZE as u16));
        let y = dest_top.saturating_add(tile.y_idx.saturating_mul(TILE_SIZE as u16));
        sink.blit_rgba(x, y, TILE_SIZE as u16, TILE_SIZE as u16, &tile_rgba);
        blits = blits.saturating_add(1);
    }
    Ok(blits)
}

/// Bottom-up 8 bpp indexed → top-down RGBA via the cached palette.
fn flip_and_apply_palette(
    src: &[u8],
    width: u16,
    height: u16,
    palette: &[(u8, u8, u8); PALETTE_ENTRY_COUNT],
) -> Vec<u8> {
    let stride = width as usize;
    let mut out = Vec::with_capacity(width as usize * height as usize * 4);
    for row in (0..height as usize).rev() {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for &idx in row_bytes {
            let (r, g, b) = palette[idx as usize];
            out.push(r);
            out.push(g);
            out.push(b);
            out.push(0xFF);
        }
    }
    out
}

/// Bottom-up BGRA → top-down RGBA.
fn flip_and_swap_32bpp(src: &[u8], width: u16, height: u16) -> Vec<u8> {
    let stride = width as usize * 4;
    let mut out = Vec::with_capacity(stride * height as usize);
    for row in (0..height as usize).rev() {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for px in row_bytes.chunks_exact(4) {
            out.push(px[2]); // R ← wire B
            out.push(px[1]); // G
            out.push(px[0]); // B ← wire R
            out.push(px[3]); // A
        }
    }
    out
}

/// Bottom-up BGR → top-down RGBA (alpha = 0xFF).
fn flip_and_swap_24bpp(src: &[u8], width: u16, height: u16) -> Vec<u8> {
    let stride = width as usize * 3;
    let mut out = Vec::with_capacity(width as usize * height as usize * 4);
    for row in (0..height as usize).rev() {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for px in row_bytes.chunks_exact(3) {
            out.push(px[2]); // R ← wire B
            out.push(px[1]); // G
            out.push(px[0]); // B ← wire R
            out.push(0xFF);
        }
    }
    out
}

/// Bottom-up RGB565 (LE u16) → top-down RGBA (alpha = 0xFF).
///
/// Bit layout per spec: `RRRRR GGGGGG BBBBB` packed into a little-endian
/// 16-bit word. Channel expansion uses bit replication so the brightest
/// 5/6-bit value maps exactly to 0xFF.
fn flip_and_convert_rgb565(src: &[u8], width: u16, height: u16) -> Vec<u8> {
    let stride = width as usize * 2;
    let mut out = Vec::with_capacity(width as usize * height as usize * 4);
    for row in (0..height as usize).rev() {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for px in row_bytes.chunks_exact(2) {
            let v = u16::from_le_bytes([px[0], px[1]]);
            let r5 = ((v >> 11) & 0x1F) as u8;
            let g6 = ((v >> 5) & 0x3F) as u8;
            let b5 = (v & 0x1F) as u8;
            out.push((r5 << 3) | (r5 >> 2));
            out.push((g6 << 2) | (g6 >> 4));
            out.push((b5 << 3) | (b5 >> 2));
            out.push(0xFF);
        }
    }
    out
}

/// Bottom-up RGB555 (LE u16) → top-down RGBA (alpha = 0xFF).
fn flip_and_convert_rgb555(src: &[u8], width: u16, height: u16) -> Vec<u8> {
    let stride = width as usize * 2;
    let mut out = Vec::with_capacity(width as usize * height as usize * 4);
    for row in (0..height as usize).rev() {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for px in row_bytes.chunks_exact(2) {
            let v = u16::from_le_bytes([px[0], px[1]]);
            let r5 = ((v >> 10) & 0x1F) as u8;
            let g5 = ((v >> 5) & 0x1F) as u8;
            let b5 = (v & 0x1F) as u8;
            out.push((r5 << 3) | (r5 >> 2));
            out.push((g5 << 3) | (g5 >> 2));
            out.push((b5 << 3) | (b5 >> 2));
            out.push(0xFF);
        }
    }
    out
}

/// Apply one [`SessionEvent`] to a [`FrameSink`].
///
/// Returns `Ok(true)` if the event produced any output (Bitmap update),
/// `Ok(false)` if the event was non-graphical or has no rectangles. Errors
/// surface as-is so the embedder can decide whether to log+drop or abort.
pub fn render_event<S: FrameSink>(
    event: &SessionEvent,
    sink: &mut S,
) -> Result<bool, RenderError> {
    let SessionEvent::Graphics { update_code, data } = event else {
        return Ok(false);
    };

    match update_code {
        FastPathUpdateType::Bitmap => {
            let rects = decode_bitmap_update_fast_path(data)?;
            let any = !rects.is_empty();
            for r in rects {
                sink.blit_rgba(
                    r.dest_left,
                    r.dest_top,
                    r.width,
                    r.height,
                    &r.pixels_rgba,
                );
            }
            if any {
                sink.flush();
            }
            Ok(any)
        }
        // Synchronize / Surface / Orders / Pointer / etc. — silently
        // accepted as "no pixels to draw"; the embedder doesn't need a
        // separate "ignored" surface yet.
        FastPathUpdateType::Synchronize | FastPathUpdateType::SurfaceCommands => Ok(false),
        other => Err(RenderError::Unsupported {
            update_code: *other,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use justrdp_core::WriteCursor;

    /// Build a fast-path bitmap-update payload with one rectangle.
    fn build_payload(rect: TsBitmapData) -> Vec<u8> {
        let upd = TsUpdateBitmapData {
            rectangles: vec![rect],
        };
        // Worst-case allocation: number_rectangles (u16) + per-rect fixed
        // header (18 bytes) + comp-hdr (8 bytes) + variable bitmap_data.
        let mut buf = vec![0u8; 2 + 32 + upd.rectangles[0].bitmap_data.len() + 16];
        let mut cursor = WriteCursor::new(&mut buf);
        upd.encode_fast_path(&mut cursor).unwrap();
        let written = cursor.pos();
        buf.truncate(written);
        buf
    }

    fn uncompressed_32bpp_rect(width: u16, height: u16, fill: u8) -> TsBitmapData {
        let stride = width as usize * 4;
        let bytes = stride * height as usize;
        let mut data = vec![fill; bytes];
        // Tag the bottom row so we can verify the flip.
        for col in 0..stride.min(8) {
            data[col] = 0xAA;
        }
        TsBitmapData {
            dest_left: 10,
            dest_top: 20,
            dest_right: 10 + width - 1,
            dest_bottom: 20 + height - 1,
            width,
            height,
            bits_per_pixel: 32,
            flags: 0,
            compr_hdr: None,
            bitmap_data: data,
        }
    }

    /// Capture-only [`FrameSink`] used in tests.
    struct Capture {
        resizes: Vec<(u16, u16)>,
        blits: Vec<(u16, u16, u16, u16, Vec<u8>)>,
        flushes: u32,
    }

    impl Capture {
        fn new() -> Self {
            Self {
                resizes: Vec::new(),
                blits: Vec::new(),
                flushes: 0,
            }
        }
    }

    impl FrameSink for Capture {
        fn resize(&mut self, w: u16, h: u16) {
            self.resizes.push((w, h));
        }
        fn blit_rgba(
            &mut self,
            x: u16,
            y: u16,
            w: u16,
            h: u16,
            pixels: &[u8],
        ) {
            self.blits.push((x, y, w, h, pixels.to_vec()));
        }
        fn flush(&mut self) {
            self.flushes += 1;
        }
    }

    #[test]
    fn decodes_uncompressed_32bpp_flips_and_swaps_to_rgba() {
        // Build a 2×3 rect where every wire pixel has a distinct B value
        // so we can spot a missed B/R swap. Wire layout BGRA, all rows
        // pre-filled with [0x11, 0x22, 0x33, 0xFF] = (B,G,R,A).
        let mut rect = uncompressed_32bpp_rect(2, 3, 0x00);
        let pattern = [0x11u8, 0x22, 0x33, 0xFF];
        for px in rect.bitmap_data.chunks_exact_mut(4) {
            px.copy_from_slice(&pattern);
        }
        // Tag the *bottom* wire row (first on the wire) so we can
        // verify the row flip put it at the top-down bottom.
        let stride_bytes = rect.width as usize * 4;
        for col in 0..stride_bytes {
            rect.bitmap_data[col] = 0xAA;
        }

        let payload = build_payload(rect);
        let rects = decode_bitmap_update_fast_path(&payload).unwrap();
        assert_eq!(rects.len(), 1);
        let r = &rects[0];
        assert_eq!((r.dest_left, r.dest_top, r.width, r.height), (10, 20, 2, 3));

        // RGBA byte-order check on a non-tagged row: wire BGRA = (0x11,
        // 0x22, 0x33, 0xFF) must arrive as RGBA = (0x33, 0x22, 0x11, 0xFF).
        // Pick the *first* top-down row (which on the wire was the *last*).
        assert_eq!(&r.pixels_rgba[0..4], &[0x33, 0x22, 0x11, 0xFF]);
        // The last top-down row has the wire-bottom tag (all 0xAA bytes),
        // and 0xAA is symmetric under the B↔R swap.
        let last_row = stride_bytes * (3 - 1);
        for col in 0..stride_bytes {
            assert_eq!(r.pixels_rgba[last_row + col], 0xAA);
        }
    }

    /// The stateless `decode_bitmap_update_fast_path` cannot resolve 8
    /// bpp pixels because it has no palette table. Confirm the typed
    /// error so the embedder can route the caller to BitmapRenderer
    /// instead.
    #[test]
    fn stateless_decode_8bpp_reports_palette_missing() {
        let mut rect = uncompressed_32bpp_rect(1, 1, 0xCC);
        rect.bits_per_pixel = 8;
        rect.bitmap_data = vec![0]; // 1 px @ 8bpp = 1 byte
        let payload = build_payload(rect);
        let err = decode_bitmap_update_fast_path(&payload).unwrap_err();
        assert!(
            matches!(err, RenderError::PaletteMissing),
            "expected PaletteMissing, got {err:?}"
        );
    }

    /// Uncompressed RGB565: a single pixel with all five red bits set,
    /// no green, no blue. Round-trip the bit-replication expansion so a
    /// regression in the bit-shift order would flip the channel.
    #[test]
    fn decodes_uncompressed_rgb565_with_bit_replication() {
        // RGB565 wire word = 0xF800 (LE: 0x00, 0xF8) = R=0x1F, G=0, B=0
        // Bit-replicated 5→8: r5=0x1F → (0x1F<<3) | (0x1F>>2) = 0xFF
        let mut rect = uncompressed_32bpp_rect(1, 1, 0);
        rect.bits_per_pixel = 16;
        rect.bitmap_data = vec![0x00, 0xF8];
        let payload = build_payload(rect);
        let rects = decode_bitmap_update_fast_path(&payload).unwrap();
        assert_eq!(rects.len(), 1);
        assert_eq!(&rects[0].pixels_rgba, &[0xFF, 0x00, 0x00, 0xFF]);
    }

    /// Uncompressed RGB555 + alpha pin to 0xFF.
    #[test]
    fn decodes_uncompressed_rgb555() {
        // RGB555 wire word = 0x7C00 (LE: 0x00, 0x7C) = R=0x1F, G=0, B=0
        let mut rect = uncompressed_32bpp_rect(1, 1, 0);
        rect.bits_per_pixel = 15;
        rect.bitmap_data = vec![0x00, 0x7C];
        let payload = build_payload(rect);
        let rects = decode_bitmap_update_fast_path(&payload).unwrap();
        assert_eq!(rects.len(), 1);
        assert_eq!(&rects[0].pixels_rgba, &[0xFF, 0x00, 0x00, 0xFF]);
    }

    /// Uncompressed 24 bpp BGR — one pixel, channel-distinguishable.
    #[test]
    fn decodes_uncompressed_24bpp_swaps_b_and_r() {
        let mut rect = uncompressed_32bpp_rect(1, 1, 0);
        rect.bits_per_pixel = 24;
        rect.bitmap_data = vec![0x11, 0x22, 0x33]; // wire BGR
        let payload = build_payload(rect);
        let rects = decode_bitmap_update_fast_path(&payload).unwrap();
        assert_eq!(rects.len(), 1);
        assert_eq!(&rects[0].pixels_rgba, &[0x33, 0x22, 0x11, 0xFF]);
    }

    /// Round-trip through `RleDecompressor`: encode a 2×1 16 bpp pattern
    /// as a single FOREGROUND/BACKGROUND run via the SPECIAL_WHITE order
    /// and verify the renderer threads it through the RLE branch and
    /// out the RGB565 converter.
    ///
    /// The simplest RLE program that fills a row is the WHITE single-byte
    /// special order (0xFD) which writes one *white* pixel. Two of them
    /// fill a 2×1 row.
    #[test]
    fn decodes_compressed_rle_16bpp_via_white_special_orders() {
        // RLE program: [WHITE, WHITE]. Each pushes one bpp16 white pixel
        // (= 0xFFFF). bitmap_length is omitted: NO_BITMAP_COMPRESSION_HDR
        // keeps the on-wire shape minimal so the test isn't tied to the
        // 8-byte compression header layout.
        let mut rect = uncompressed_32bpp_rect(2, 1, 0);
        rect.bits_per_pixel = 16;
        rect.flags = BITMAP_COMPRESSION | justrdp_pdu::rdp::bitmap::NO_BITMAP_COMPRESSION_HDR;
        rect.compr_hdr = None;
        rect.bitmap_data = vec![0xFD, 0xFD];
        let payload = build_payload(rect);
        let rects = decode_bitmap_update_fast_path(&payload).unwrap();
        assert_eq!(rects.len(), 1);
        // 0xFFFF in RGB565 → R=0x1F, G=0x3F, B=0x1F → (0xFF, 0xFF, 0xFF) RGBA.
        assert_eq!(
            &rects[0].pixels_rgba,
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    /// Compressed bitmaps with malformed RLE streams must surface as
    /// `RenderError::Rle(...)`, *not* as a panic or generic decode error.
    #[test]
    fn surfaces_rle_decompression_errors() {
        let mut rect = uncompressed_32bpp_rect(2, 1, 0);
        rect.bits_per_pixel = 16;
        rect.flags = BITMAP_COMPRESSION | justrdp_pdu::rdp::bitmap::NO_BITMAP_COMPRESSION_HDR;
        rect.compr_hdr = None;
        // 0xFC is reserved and the decompressor flags it as
        // UnknownOrderCode — perfect canary for the error path.
        rect.bitmap_data = vec![0xFC];
        let payload = build_payload(rect);
        let err = decode_bitmap_update_fast_path(&payload).unwrap_err();
        assert!(
            matches!(err, RenderError::Rle(_)),
            "expected RenderError::Rle, got {err:?}"
        );
    }

    #[test]
    fn render_event_drives_sink_for_bitmap_updates() {
        let rect = uncompressed_32bpp_rect(2, 1, 0x77);
        let payload = build_payload(rect);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Bitmap,
            data: payload,
        };
        let mut sink = Capture::new();
        let any = render_event(&event, &mut sink).unwrap();
        assert!(any);
        assert_eq!(sink.blits.len(), 1);
        assert_eq!(sink.flushes, 1);
        let (x, y, w, h, _) = &sink.blits[0];
        assert_eq!((*x, *y, *w, *h), (10, 20, 2, 1));
    }

    #[test]
    fn render_event_silently_ignores_synchronize() {
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Synchronize,
            data: Vec::new(),
        };
        let mut sink = Capture::new();
        let any = render_event(&event, &mut sink).unwrap();
        assert!(!any, "synchronize is not a draw event");
        assert!(sink.blits.is_empty());
        assert_eq!(sink.flushes, 0);
    }

    #[test]
    fn render_event_returns_false_for_non_graphics_events() {
        let event = SessionEvent::Pointer(crate::PointerEvent::Hidden);
        let mut sink = Capture::new();
        let any = render_event(&event, &mut sink).unwrap();
        assert!(!any);
    }

    #[test]
    fn render_event_surfaces_unsupported_update_type() {
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: Vec::new(),
        };
        let mut sink = Capture::new();
        let err = render_event(&event, &mut sink).unwrap_err();
        assert!(
            matches!(err, RenderError::Unsupported {
                update_code: FastPathUpdateType::Orders
            }),
            "expected Unsupported(Orders), got {err:?}"
        );
    }

    // ── BitmapRenderer / Palette / 8 bpp ────────────────────────────────

    /// Build a fast-path Palette PDU (TS_FP_UPDATE_PALETTE) where every
    /// entry is `(idx, idx, idx)` — a grayscale ramp — so a 8 bpp test
    /// can map back from any chosen index trivially.
    fn build_grayscale_palette_pdu() -> Vec<u8> {
        let mut data = Vec::with_capacity(2 + 4 + PALETTE_ENTRY_COUNT * 3);
        data.extend_from_slice(&[0, 0]); // pad2Octets
        data.extend_from_slice(&(PALETTE_ENTRY_COUNT as u32).to_le_bytes());
        for i in 0..PALETTE_ENTRY_COUNT {
            data.push(i as u8);
            data.push(i as u8);
            data.push(i as u8);
        }
        data
    }

    fn palette_event() -> SessionEvent {
        SessionEvent::Graphics {
            update_code: FastPathUpdateType::Palette,
            data: build_grayscale_palette_pdu(),
        }
    }

    /// 8 bpp uncompressed bitmap with a known per-row index pattern, plus
    /// a separate row 0 (bottom on the wire) tagged with index 0xCC so
    /// the row flip can be observed.
    fn uncompressed_8bpp_rect(width: u16, height: u16) -> TsBitmapData {
        let total = width as usize * height as usize;
        let mut data = Vec::with_capacity(total);
        // Bottom row (wire row 0) tagged with 0xCC; subsequent rows fill
        // with their wire row index for easy assertions.
        for row in 0..height as usize {
            let value = if row == 0 { 0xCC } else { row as u8 };
            for _ in 0..width as usize {
                data.push(value);
            }
        }
        TsBitmapData {
            dest_left: 0,
            dest_top: 0,
            dest_right: width - 1,
            dest_bottom: height - 1,
            width,
            height,
            bits_per_pixel: 8,
            flags: 0,
            compr_hdr: None,
            bitmap_data: data,
        }
    }

    #[test]
    fn renderer_caches_palette_and_decodes_8bpp_uncompressed() {
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();

        // Palette first; no draws.
        assert!(!renderer.has_palette());
        let drew = renderer.render(&palette_event(), &mut sink).unwrap();
        assert!(!drew);
        assert!(renderer.has_palette());
        assert!(sink.blits.is_empty());

        // Now an 8 bpp 2×2 bitmap. Wire row 0 (bottom) = 0xCC, wire row
        // 1 (top) = 0x01. Top-down output: row 0 from index 0x01, row 1
        // from index 0xCC. Grayscale palette → R=G=B=index, A=0xFF.
        let rect = uncompressed_8bpp_rect(2, 2);
        let payload = build_payload(rect);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Bitmap,
            data: payload,
        };
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew);
        assert_eq!(sink.blits.len(), 1);
        let (_, _, _, _, pixels) = &sink.blits[0];
        // First top-down pixel comes from index 0x01.
        assert_eq!(&pixels[0..4], &[0x01, 0x01, 0x01, 0xFF]);
        // Last top-down pixel comes from index 0xCC.
        assert_eq!(&pixels[pixels.len() - 4..], &[0xCC, 0xCC, 0xCC, 0xFF]);
    }

    #[test]
    fn renderer_8bpp_without_palette_errors_with_palette_missing() {
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let rect = uncompressed_8bpp_rect(1, 1);
        let payload = build_payload(rect);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Bitmap,
            data: payload,
        };
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(matches!(err, RenderError::PaletteMissing));
    }

    /// Compressed 8 bpp via the WHITE special order (single-byte 0xFD).
    /// At 8 bpp, "white" is `0xFF`. With the grayscale palette built in
    /// `build_grayscale_palette_pdu`, palette[0xFF] = (0xFF, 0xFF, 0xFF).
    #[test]
    fn renderer_decodes_compressed_8bpp_via_palette() {
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        renderer.render(&palette_event(), &mut sink).unwrap();

        let mut rect = uncompressed_8bpp_rect(2, 1);
        rect.flags = BITMAP_COMPRESSION | justrdp_pdu::rdp::bitmap::NO_BITMAP_COMPRESSION_HDR;
        rect.compr_hdr = None;
        rect.bitmap_data = vec![0xFD, 0xFD]; // two WHITE specials = 0xFF, 0xFF
        let payload = build_payload(rect);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Bitmap,
            data: payload,
        };
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew);
        assert_eq!(sink.blits.len(), 1);
        let pixels = &sink.blits[0].4;
        assert_eq!(
            pixels,
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn renderer_rejects_truncated_palette() {
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let truncated = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Palette,
            data: vec![0, 0, 0, 0], // missing numberColors high bytes + body
        };
        let err = renderer.render(&truncated, &mut sink).unwrap_err();
        assert!(matches!(err, RenderError::SizeMismatch(_)));
        assert!(!renderer.has_palette());
    }

    // ── Surface Commands ────────────────────────────────────────────

    /// Build a fast-path SurfCmds payload carrying one
    /// SetSurfaceBits with a raw (codec_id=0) 1×1 32 bpp BGRA pixel.
    /// `(b, g, r, a)` is the pixel value placed on the wire.
    fn build_surface_set_bits_raw(b: u8, g: u8, r: u8, a: u8) -> Vec<u8> {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::surface_commands::SetSurfaceBitsCmd;
        let cmd = SetSurfaceBitsCmd {
            dest_left: 100,
            dest_top: 50,
            dest_right: 101,
            dest_bottom: 51,
            bitmap_data: BitmapDataEx {
                bpp: 32,
                codec_id: 0,
                width: 1,
                height: 1,
                ex_header: None,
                bitmap_data: vec![b, g, r, a],
            },
        };
        let mut buf = vec![0u8; cmd.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut buf);
            cmd.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        buf.truncate(written);
        buf
    }

    fn build_frame_marker(action: u16, frame_id: u32) -> Vec<u8> {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::surface_commands::FrameMarkerCmd;
        let m = FrameMarkerCmd {
            frame_action: action,
            frame_id,
        };
        let mut buf = vec![0u8; m.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut buf);
            m.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        buf.truncate(written);
        buf
    }

    #[test]
    fn surface_commands_set_surface_bits_raw_32bpp() {
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        // Pixel BGRA = (0x11, 0x22, 0x33, 0xFF) → RGBA (0x33, 0x22, 0x11, 0xFF).
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: build_surface_set_bits_raw(0x11, 0x22, 0x33, 0xFF),
        };
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew);
        assert_eq!(sink.blits.len(), 1);
        let (x, y, w, h, pixels) = &sink.blits[0];
        assert_eq!((*x, *y, *w, *h), (100, 50, 1, 1));
        assert_eq!(pixels, &vec![0x33, 0x22, 0x11, 0xFF]);
    }

    #[test]
    fn surface_commands_frame_marker_end_flushes_sink() {
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        // BEGIN(7), SetSurfaceBits, END(7) — a typical Windows frame.
        let mut payload = build_frame_marker(0x0000, 7);
        payload.extend_from_slice(&build_surface_set_bits_raw(0xFF, 0xFF, 0xFF, 0xFF));
        payload.extend_from_slice(&build_frame_marker(0x0001, 7));
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew);
        assert_eq!(renderer.last_frame_id(), Some(7));
        // One flush from FrameMarker END (BitmapRenderer::process_surface_commands
        // does not flush after each blit; that's the embedder's per-frame hook).
        assert_eq!(sink.flushes, 1);
    }

    // ── RFX (S3d-3) ────────────────────────────────────────────────

    /// Wrap an RFX frame stream in a SetSurfaceBitsCmd payload that uses
    /// the renderer's registered RFX codec_id, then return the full
    /// fast-path SurfCmds payload (one command, no FrameMarker).
    fn build_set_surface_bits_rfx(
        codec_id: u8,
        dest_left: u16,
        dest_top: u16,
        rfx_bytes: Vec<u8>,
    ) -> Vec<u8> {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::surface_commands::SetSurfaceBitsCmd;
        // The Surface Bits header advertises the *post-decode* tile
        // dimensions, but they are spec-marked as informational; the
        // RFX stream itself authoritatively encodes geometry. We pin
        // 64×64 here for the smallest legal one-tile frame.
        let cmd = SetSurfaceBitsCmd {
            dest_left,
            dest_top,
            dest_right: dest_left + 64,
            dest_bottom: dest_top + 64,
            bitmap_data: BitmapDataEx {
                bpp: 32,
                codec_id,
                width: 64,
                height: 64,
                ex_header: None,
                bitmap_data: rfx_bytes,
            },
        };
        let mut buf = vec![0u8; cmd.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut buf);
            cmd.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        buf.truncate(written);
        buf
    }

    /// Encode one RFX frame using the server-side helper, decode it
    /// through `BitmapRenderer`, and check that the round-trip produces
    /// at least one 64×64 RGBA blit at the registered position.
    // ── NSCodec / ClearCodec (S3d-5) ───────────────────────────────

    /// Build a SetSurfaceBitsCmd payload that carries `body` under
    /// `codec_id`. width / height match `body`'s dimensions.
    fn build_set_surface_bits_codec(
        codec_id: u8,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        body: Vec<u8>,
    ) -> Vec<u8> {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::surface_commands::SetSurfaceBitsCmd;
        let cmd = SetSurfaceBitsCmd {
            dest_left,
            dest_top,
            dest_right: dest_left + width,
            dest_bottom: dest_top + height,
            bitmap_data: BitmapDataEx {
                bpp: 32,
                codec_id,
                width,
                height,
                ex_header: None,
                bitmap_data: body,
            },
        };
        let mut buf = vec![0u8; cmd.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut buf);
            cmd.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        buf.truncate(written);
        buf
    }

    /// NSCodec dispatch — when the codec_id is registered, the
    /// renderer must route through `NsCodecDecompressor`. We verify
    /// this with a deliberately-malformed body so the codec returns an
    /// error: it must reach us as `RenderError::NsCodec(...)`, not as
    /// `UnsupportedCodec`. Round-trip wire vectors are tested at the
    /// `justrdp-graphics::nscodec` layer; here we only care that
    /// dispatch + error mapping are correct.
    #[test]
    fn nscodec_dispatch_routes_through_codec() {
        let codec_id = 0x0A;
        // Truncated body: not enough bytes for a NSCodec stream header.
        let payload =
            build_set_surface_bits_codec(codec_id, 0, 0, 1, 1, vec![0u8; 4]);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let mut renderer = BitmapRenderer::new();
        renderer.set_nscodec_codec_id(codec_id);
        let mut sink = Capture::new();
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(
            matches!(err, RenderError::NsCodec(_)),
            "expected NsCodec(_), got {err:?}"
        );
    }

    /// Without registration NSCodec data still surfaces as
    /// UnsupportedCodec — so the embedder doesn't accidentally paint
    /// random bytes when the codec was never negotiated.
    #[test]
    fn nscodec_without_registration_stays_unsupported() {
        let codec_id = 0x0A;
        let payload =
            build_set_surface_bits_codec(codec_id, 0, 0, 1, 1, vec![0u8; 32]);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let mut renderer = BitmapRenderer::new();
        // No set_nscodec_codec_id call.
        let mut sink = Capture::new();
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(matches!(err, RenderError::UnsupportedCodec { codec_id: 0x0A }));
    }

    // ── AVC420 / AVC444 (S3d-5b) ───────────────────────────────────

    /// Fake AvcDecoder for tests — returns a pre-built `Yuv420Frame`
    /// for every call (or `Ok(None)` when configured to drop frames).
    /// Keeps a hit counter so the test can verify dispatch happened.
    struct FakeAvcDecoder {
        frame: Option<justrdp_graphics::avc::Yuv420Frame>,
        calls: u32,
    }

    impl FakeAvcDecoder {
        fn yielding(width: u32, height: u32, fill: u8) -> Self {
            // 16-aligned coded size (H.264 macroblock).
            let coded_w = ((width + 15) / 16) * 16;
            let coded_h = ((height + 15) / 16) * 16;
            Self {
                frame: Some(justrdp_graphics::avc::Yuv420Frame {
                    y: alloc::vec![fill; (coded_w * coded_h) as usize],
                    u: alloc::vec![128; ((coded_w / 2) * (coded_h / 2)) as usize],
                    v: alloc::vec![128; ((coded_w / 2) * (coded_h / 2)) as usize],
                    width: coded_w,
                    height: coded_h,
                }),
                calls: 0,
            }
        }

        fn empty() -> Self {
            Self {
                frame: None,
                calls: 0,
            }
        }
    }

    impl justrdp_graphics::avc::AvcDecoder for FakeAvcDecoder {
        fn decode_frame(
            &mut self,
            _annex_b: &[u8],
        ) -> Result<Option<justrdp_graphics::avc::Yuv420Frame>, justrdp_graphics::avc::AvcError>
        {
            self.calls += 1;
            Ok(self.frame.clone())
        }
    }

    /// Build a RDPGFX_AVC420_BITMAP_STREAM with zero region rects (the
    /// trailing Annex B body is `annex_b`).
    fn build_avc420_stream(annex_b: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + annex_b.len());
        data.extend_from_slice(&0u32.to_le_bytes()); // numRegionRects = 0
        data.extend_from_slice(annex_b);
        data
    }

    /// Build a RDPGFX_AVC444_BITMAP_STREAM with the given LC code,
    /// `bitstream1` (always present), and optional `bitstream2`.
    fn build_avc444_envelope(lc: u8, bitstream1: &[u8], bitstream2: Option<&[u8]>) -> Vec<u8> {
        assert!(lc <= 0x0F);
        let header: u32 = ((lc as u32) << 28) | ((bitstream1.len() as u32) & 0x0FFF_FFFF);
        let mut data = Vec::with_capacity(4 + bitstream1.len() + bitstream2.map_or(0, |b| b.len()));
        data.extend_from_slice(&header.to_le_bytes());
        data.extend_from_slice(bitstream1);
        if let Some(b2) = bitstream2 {
            data.extend_from_slice(b2);
        }
        data
    }

    #[test]
    fn avc420_round_trip_with_injected_decoder() {
        let codec_id = 0x0E;
        let stream = build_avc420_stream(&[0u8; 64]);
        let payload = build_set_surface_bits_codec(codec_id, 4, 8, 16, 16, stream);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let mut renderer = BitmapRenderer::new();
        renderer.set_avc420_codec_id(codec_id);
        // Y=255 (luma white), U=V=128 (no color) → BT.709 reverse maps to
        // R=G=B=255 white. We just check the alpha pin and that a blit
        // happened at the right rect.
        renderer.set_avc_decoder(alloc::boxed::Box::new(FakeAvcDecoder::yielding(
            16, 16, 255,
        )));
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew, "AVC420 should produce one blit");
        assert_eq!(sink.blits.len(), 1);
        let (x, y, w, h, pixels) = &sink.blits[0];
        assert_eq!((*x, *y, *w, *h), (4, 8, 16, 16));
        assert_eq!(pixels.len(), 16 * 16 * 4);
        // Alpha pinned, rough sanity on white luma.
        for px in pixels.chunks_exact(4) {
            assert_eq!(px[3], 0xFF);
        }
    }

    /// AVC420 codec_id registered but no decoder injected → typed
    /// `AvcDecoderMissing` (not `UnsupportedCodec`), so the embedder
    /// gets a clean signal to plumb a decoder.
    #[test]
    fn avc420_without_decoder_surfaces_typed_missing_error() {
        let codec_id = 0x0E;
        let stream = build_avc420_stream(&[0u8; 8]);
        let payload = build_set_surface_bits_codec(codec_id, 0, 0, 16, 16, stream);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let mut renderer = BitmapRenderer::new();
        renderer.set_avc420_codec_id(codec_id);
        // No set_avc_decoder call.
        let mut sink = Capture::new();
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(
            matches!(err, RenderError::AvcDecoderMissing),
            "expected AvcDecoderMissing, got {err:?}"
        );
    }

    /// Decoder buffering (Ok(None)) surfaces as `AvcFrameUnavailable`,
    /// distinct from a hard decode error — embedders may choose to keep
    /// pumping frames in that case.
    #[test]
    fn avc420_decoder_yielding_none_surfaces_frame_unavailable() {
        let codec_id = 0x0E;
        let stream = build_avc420_stream(&[0u8; 8]);
        let payload = build_set_surface_bits_codec(codec_id, 0, 0, 16, 16, stream);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let mut renderer = BitmapRenderer::new();
        renderer.set_avc420_codec_id(codec_id);
        renderer.set_avc_decoder(alloc::boxed::Box::new(FakeAvcDecoder::empty()));
        let mut sink = Capture::new();
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(
            matches!(err, RenderError::AvcFrameUnavailable),
            "expected AvcFrameUnavailable, got {err:?}"
        );
    }

    /// AVC444 LC=0 (main view only) — falls back to the AVC420 path
    /// internally. The renderer must accept it and produce one blit.
    #[test]
    fn avc444_lc0_main_view_only_blits() {
        let codec_id = 0x0F;
        let envelope = build_avc444_envelope(0, &build_avc420_stream(&[0u8; 32]), None);
        let payload = build_set_surface_bits_codec(codec_id, 1, 2, 16, 16, envelope);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let mut renderer = BitmapRenderer::new();
        renderer.set_avc444_codec_id(codec_id);
        renderer.set_avc_decoder(alloc::boxed::Box::new(FakeAvcDecoder::yielding(16, 16, 0x40)));
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew);
        assert_eq!(sink.blits.len(), 1);
        assert_eq!((sink.blits[0].0, sink.blits[0].1), (1, 2));
    }

    /// AVC444 LC=2 (both substreams) — exercises both decode_frame
    /// calls + combine_avc444_planes + yuv444_to_bgra. Two blits would
    /// be wrong; we expect exactly one.
    #[test]
    fn avc444_lc2_combines_both_substreams_v1_layout() {
        let codec_id = 0x0F;
        let envelope = build_avc444_envelope(
            2,
            &build_avc420_stream(&[0u8; 16]), // main
            Some(&build_avc420_stream(&[0u8; 16])), // aux
        );
        let payload = build_set_surface_bits_codec(codec_id, 0, 0, 16, 16, envelope);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let mut renderer = BitmapRenderer::new();
        renderer.set_avc444_codec_id(codec_id);
        renderer.set_avc_decoder(alloc::boxed::Box::new(FakeAvcDecoder::yielding(16, 16, 0x80)));
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew);
        assert_eq!(sink.blits.len(), 1, "AVC444 LC=2 should fold into one blit");
    }

    /// AVC444 LC=1 (chroma-only refresh) requires a previous-frame
    /// luma cache; we explicitly surface that as
    /// `RenderError::AvcLumaCacheRequired` so the embedder can wait
    /// for the next keyframe instead of painting against stale luma.
    #[test]
    fn avc444_lc1_surfaces_luma_cache_required() {
        let codec_id = 0x0F;
        let envelope = build_avc444_envelope(1, &build_avc420_stream(&[0u8; 8]), None);
        let payload = build_set_surface_bits_codec(codec_id, 0, 0, 16, 16, envelope);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let mut renderer = BitmapRenderer::new();
        renderer.set_avc444_codec_id(codec_id);
        renderer.set_avc_decoder(alloc::boxed::Box::new(FakeAvcDecoder::empty()));
        let mut sink = Capture::new();
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(
            matches!(err, RenderError::AvcLumaCacheRequired),
            "expected AvcLumaCacheRequired, got {err:?}"
        );
    }

    /// AVC444v2 codec_id is wired separately — the same envelope works
    /// because the LC code lives in the same place; only the chroma-aux
    /// combination layout differs (v2 vs v1). We just need a smoke
    /// test that the v2 dispatch is reachable.
    #[test]
    fn avc444v2_lc0_is_dispatchable() {
        let codec_id = 0x10;
        let envelope = build_avc444_envelope(0, &build_avc420_stream(&[0u8; 16]), None);
        let payload = build_set_surface_bits_codec(codec_id, 0, 0, 16, 16, envelope);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let mut renderer = BitmapRenderer::new();
        renderer.set_avc444v2_codec_id(codec_id);
        renderer.set_avc_decoder(alloc::boxed::Box::new(FakeAvcDecoder::yielding(16, 16, 0x33)));
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew);
        assert_eq!(sink.blits.len(), 1);
    }

    /// `clear_avc_decoder` must drop the injection so subsequent calls
    /// flip back to `AvcDecoderMissing`.
    #[test]
    fn clear_avc_decoder_disarms_dispatch() {
        let codec_id = 0x0E;
        let stream = build_avc420_stream(&[0u8; 8]);
        let payload = build_set_surface_bits_codec(codec_id, 0, 0, 16, 16, stream);
        let mut renderer = BitmapRenderer::new();
        renderer.set_avc420_codec_id(codec_id);
        renderer.set_avc_decoder(alloc::boxed::Box::new(FakeAvcDecoder::yielding(16, 16, 0)));
        assert!(renderer.has_avc_decoder());
        renderer.clear_avc_decoder();
        assert!(!renderer.has_avc_decoder());
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let mut sink = Capture::new();
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(matches!(err, RenderError::AvcDecoderMissing));
    }

    /// ClearCodec dispatch — same shape as NSCodec. Send a deliberately
    /// truncated body (1 byte) and expect `RenderError::ClearCodec(...)`.
    #[test]
    fn clearcodec_dispatch_routes_through_codec() {
        let codec_id = 0x0B;
        let payload =
            build_set_surface_bits_codec(codec_id, 0, 0, 2, 2, vec![0u8; 1]);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let mut renderer = BitmapRenderer::new();
        renderer.set_clearcodec_codec_id(codec_id);
        let mut sink = Capture::new();
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(
            matches!(err, RenderError::ClearCodec(_)),
            "expected ClearCodec(_), got {err:?}"
        );
    }

    #[test]
    fn clearcodec_without_registration_stays_unsupported() {
        let codec_id = 0x0B;
        let payload =
            build_set_surface_bits_codec(codec_id, 0, 0, 1, 1, vec![0u8; 16]);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: payload,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(matches!(err, RenderError::UnsupportedCodec { codec_id: 0x0B }));
    }

    /// Registering ClearCodec must allocate the decoder lazily and
    /// allow Debug printing without exposing the cache internals.
    #[test]
    fn clearcodec_registration_allocates_decoder_and_debug_redacts_internals() {
        let mut renderer = BitmapRenderer::new();
        assert!(renderer.clearcodec_codec_id().is_none());
        renderer.set_clearcodec_codec_id(0x0B);
        assert_eq!(renderer.clearcodec_codec_id(), Some(0x0B));
        // Debug must compile (manual impl) and not include "cache".
        let s = alloc::format!("{renderer:?}");
        assert!(s.contains("clearcodec_codec_id"));
        assert!(!s.contains("glyph_storage"));
    }

    #[test]
    fn rfx_round_trip_one_tile_image_mode() {
        use justrdp_graphics::rfx::frame_encoder::RfxFrameEncoder;
        use justrdp_graphics::rfx::quant::CodecQuant;
        use justrdp_graphics::rfx::wire::RfxTileWire;

        // Build a single-tile frame. quant index 0 references the
        // default quant table; the tile data can be empty bytes — the
        // RLGR decoder produces all-zero coefficients which color-
        // convert to a uniform mid-gray, which is good enough for a
        // structural integration test.
        let tile = RfxTileWire {
            quant_idx_y: 0,
            quant_idx_cb: 0,
            quant_idx_cr: 0,
            x_idx: 0,
            y_idx: 0,
            // Minimum legal RLGR component: a single zero byte. Decoder
            // emits 4096 zeros, then DWT/dequant/colorconv on zeros
            // → mid-gray BGRA tile.
            y_data: vec![0; 1],
            cb_data: vec![0; 1],
            cr_data: vec![0; 1],
        };
        let mut encoder = RfxFrameEncoder::new(64, 64, RlgrMode::Rlgr1).unwrap();
        // Default Microsoft quant table (MS-RDPRFX §2.2.2.1.5 sample). The
        // exact values do not matter for the structural assertions below;
        // they just need to round-trip the renderer's range checks.
        let quant = CodecQuant::from_bytes(&[0x66, 0x66, 0x77, 0x88, 0x98]);
        let rfx_bytes = encoder
            .encode_frame(&[], vec![quant], vec![tile])
            .unwrap();

        let codec_id = 0x09; // arbitrary server-assigned id
        let surfcmds_payload = build_set_surface_bits_rfx(codec_id, 100, 50, rfx_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: surfcmds_payload,
        };

        let mut renderer = BitmapRenderer::new();
        renderer.set_rfx_codec_id(codec_id);
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew, "RFX frame must produce at least one blit");
        assert_eq!(sink.blits.len(), 1);
        let (x, y, w, h, pixels) = &sink.blits[0];
        assert_eq!(
            (*x, *y, *w, *h),
            (100, 50, 64, 64),
            "single-tile RFX blit must land at (dest_left, dest_top) and be 64×64"
        );
        assert_eq!(pixels.len(), 64 * 64 * 4);
        // Sample alpha: every RGBA pixel from the BGRA→RGBA swap should
        // have alpha = 0xFF since RFX outputs 0xFF in the alpha slot.
        for px in pixels.chunks_exact(4) {
            assert_eq!(px[3], 0xFF);
        }
        // The encoder snapshot should have updated the renderer's
        // entropy field via the embedded TS_RFX_CONTEXT block.
        assert_eq!(renderer.rfx_entropy, RlgrMode::Rlgr1);
    }

    // ── Drawing Orders (S3d-4) ─────────────────────────────────────

    /// Build a fast-path Orders payload carrying one OpaqueRect that
    /// fills `(x, y, w, h)` with `(r, g, b)`. Uses the canonical
    /// `PrimaryOrder::encode` so the wire shape matches what a real
    /// server would emit (TS_STANDARD | ORDER_TYPE_CHANGE controlFlags,
    /// 1-byte fieldFlags=0x7F = all 7 fields present, no bounds).
    fn build_orders_opaquerect(
        x: i16, y: i16, w: i16, h: i16, r: u8, g: u8, b: u8,
    ) -> Vec<u8> {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        // OpaqueRect body: 4 coordinate bytes (1 byte each, default
        // non-delta = i16 LE) + 3 color bytes. With all fields
        // present the encoder writes them in field order: left, top,
        // width, height, red, green, blue.
        let mut body = Vec::with_capacity(4 * 2 + 3);
        body.extend_from_slice(&x.to_le_bytes());
        body.extend_from_slice(&y.to_le_bytes());
        body.extend_from_slice(&w.to_le_bytes());
        body.extend_from_slice(&h.to_le_bytes());
        body.push(r);
        body.push(g);
        body.push(b);
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::OpaqueRect,
            field_flags: 0x7F, // all 7 fields present
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        // numberOrders = 1 (u16 LE)
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        frame
    }

    #[test]
    fn orders_opaque_rect_renders_solid_fill() {
        let payload = build_orders_opaquerect(50, 60, 4, 2, 0xFE, 0xDC, 0xBA);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: payload,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew, "OpaqueRect should produce one blit");
        assert_eq!(sink.blits.len(), 1);
        let (x, y, w, h, pixels) = &sink.blits[0];
        assert_eq!((*x, *y, *w, *h), (50, 60, 4, 2));
        assert_eq!(pixels.len(), 4 * 2 * 4);
        // Every RGBA pixel must equal the OpaqueRect color.
        for px in pixels.chunks_exact(4) {
            assert_eq!(px, &[0xFE, 0xDC, 0xBA, 0xFF]);
        }
    }

    #[test]
    fn orders_zero_count_is_a_noop() {
        // numberOrders=0, no bodies follow.
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: vec![0u8, 0u8],
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(!drew);
        assert!(sink.blits.is_empty());
    }

    /// PatBlt with BS_SOLID brush + PATCOPY ROP renders a solid-color
    /// rectangle from the foreground color — the most common shape
    /// Windows uses for window-frame fills. Build the wire form via
    /// PrimaryOrder::encode so the field-flags byte width matches what
    /// real servers emit.
    #[test]
    fn orders_patblt_solid_patcopy_renders_filled_rect() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        // PatBlt has 12 fields; we set them all (field_flags = 0x0FFF).
        // Body: left/top/width/height (i16 LE × 4) + rop (u8) +
        // back_color (3) + fore_color (3) + brush_org_x (i8) +
        // brush_org_y (i8) + brush_style (u8) + brush_hatch (u8) +
        // brush_extra (7 bytes).
        let mut body = Vec::with_capacity(2 * 4 + 1 + 3 + 3 + 1 + 1 + 1 + 1 + 7);
        body.extend_from_slice(&20i16.to_le_bytes());   // left
        body.extend_from_slice(&30i16.to_le_bytes());   // top
        body.extend_from_slice(&5i16.to_le_bytes());    // width
        body.extend_from_slice(&3i16.to_le_bytes());    // height
        body.push(0xF0);                                 // rop = PATCOPY
        body.extend_from_slice(&[0x00, 0x00, 0x00]);    // back_color (unused with PATCOPY)
        body.extend_from_slice(&[0xAB, 0xCD, 0xEF]);    // fore_color RGB
        body.push(0);                                   // brush_org_x
        body.push(0);                                   // brush_org_y
        body.push(0x00);                                // brush_style = BS_SOLID
        body.push(0);                                   // brush_hatch
        body.extend_from_slice(&[0; 7]);                // brush_extra
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::PatBlt,
            field_flags: 0x0FFF,
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew, "PatBlt BS_SOLID + PATCOPY should produce a blit");
        assert_eq!(sink.blits.len(), 1);
        let (x, y, w, h, pixels) = &sink.blits[0];
        assert_eq!((*x, *y, *w, *h), (20, 30, 5, 3));
        for px in pixels.chunks_exact(4) {
            assert_eq!(px, &[0xAB, 0xCD, 0xEF, 0xFF]);
        }
    }

    #[test]
    fn orders_dstblt_blackness_renders_black_rect() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        // DstBlt has 5 fields: left, top, width, height, rop.
        // field_flags = 0x1F (all five present).
        let mut body = Vec::with_capacity(2 * 4 + 1);
        body.extend_from_slice(&7i16.to_le_bytes());
        body.extend_from_slice(&8i16.to_le_bytes());
        body.extend_from_slice(&3i16.to_le_bytes());
        body.extend_from_slice(&2i16.to_le_bytes());
        body.push(0x00); // ROP3_BLACKNESS
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::DstBlt,
            field_flags: 0x1F,
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew);
        assert_eq!(sink.blits.len(), 1);
        let (x, y, w, h, pixels) = &sink.blits[0];
        assert_eq!((*x, *y, *w, *h), (7, 8, 3, 2));
        for px in pixels.chunks_exact(4) {
            assert_eq!(px, &[0x00, 0x00, 0x00, 0xFF]);
        }
    }

    #[test]
    fn orders_dstblt_dstinvert_silently_skipped() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        let mut body = Vec::with_capacity(2 * 4 + 1);
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&1i16.to_le_bytes());
        body.extend_from_slice(&1i16.to_le_bytes());
        body.push(0x55); // DSTINVERT — needs destination readback, must skip
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::DstBlt,
            field_flags: 0x1F,
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(!drew, "DSTINVERT cannot be rendered without read-back");
        assert!(sink.blits.is_empty());
    }

    /// LineTo: draw a horizontal 5-pixel line. We don't care which
    /// exact pixels Bresenham picks for axis-aligned cases; just
    /// confirm we got the right pen color and the count matches.
    #[test]
    fn orders_lineto_horizontal_emits_one_blit_per_pixel() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        // LineTo has 10 fields. Body order:
        //   back_mode (u16 LE)
        //   start_x, start_y, end_x, end_y (i16 LE × 4)
        //   back_color (3 bytes)
        //   rop2 (u8)
        //   pen_style (u8)
        //   pen_width (u8)
        //   pen_color (3 bytes)
        let mut body = Vec::with_capacity(2 + 2 * 4 + 3 + 1 + 1 + 1 + 3);
        body.extend_from_slice(&1u16.to_le_bytes()); // back_mode = OPAQUE
        body.extend_from_slice(&10i16.to_le_bytes()); // start_x
        body.extend_from_slice(&20i16.to_le_bytes()); // start_y
        body.extend_from_slice(&14i16.to_le_bytes()); // end_x
        body.extend_from_slice(&20i16.to_le_bytes()); // end_y
        body.extend_from_slice(&[0, 0, 0]);            // back_color
        body.push(13);                                 // rop2 = R2_COPYPEN
        body.push(0);                                  // pen_style = solid
        body.push(1);                                  // pen_width
        body.extend_from_slice(&[0xFF, 0x00, 0x00]);   // pen_color = red
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::LineTo,
            field_flags: 0x03FF, // all 10 fields
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew);
        // (10..=14) inclusive on x, fixed y = 5 distinct pixels.
        assert_eq!(sink.blits.len(), 5);
        for blit in &sink.blits {
            assert_eq!((blit.2, blit.3), (1, 1));
            assert_eq!(blit.1, 20);
            assert_eq!(&blit.4, &[0xFF, 0x00, 0x00, 0xFF]);
        }
    }

    /// Build a Secondary CacheBitmapV2Uncompressed order body.
    /// `(width, height)` are encoded via TWO_BYTE_UNSIGNED, length via
    /// FOUR_BYTE_UNSIGNED, cacheIndex via TWO_BYTE_UNSIGNED. Only the
    /// short form is exercised here (values < 0x80).
    fn build_cache_bitmap_v2_body(
        width: u8,
        height: u8,
        cache_index: u8,
        pixels_bgra: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(width);  // TWO_BYTE_UNSIGNED short
        body.push(height); // TWO_BYTE_UNSIGNED short
        // FOUR_BYTE_UNSIGNED short: top-2 bits = 0 → 1 byte, low 6 bits = value.
        let length = pixels_bgra.len();
        assert!(length < 0x40, "test helper covers ≤ 63-byte payloads");
        body.push(length as u8);
        body.push(cache_index);
        body.extend_from_slice(pixels_bgra);
        body
    }

    /// Wrap a Secondary order body as `SecondaryOrder::encode` would —
    /// controlFlags(1) + orderLength(2) + extraFlags(2) + orderType(1) + body.
    fn build_secondary_order_frame(extra_flags: u16, order_type: u8, body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.push(0x03); // TS_STANDARD | TS_SECONDARY
        let order_length = (body.len() as i32 + 2 + 1 - 7) as u16;
        frame.extend_from_slice(&order_length.to_le_bytes());
        frame.extend_from_slice(&extra_flags.to_le_bytes());
        frame.push(order_type);
        frame.extend_from_slice(body);
        frame
    }

    /// Round-trip a CacheBitmapV2Uncompressed Secondary order through
    /// the renderer + verify the cache populated. Then a MemBlt
    /// Primary order looks it up + blits a sub-region.
    #[test]
    fn cache_bitmap_v2_then_memblt_round_trip() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;

        // 4×2 BGRA bitmap. We tag a known-position pixel at (1, 0) so
        // the MemBlt sub-region crop can be verified.
        let mut pixels_bgra = Vec::with_capacity(4 * 2 * 4);
        for row in 0..2 {
            for col in 0..4 {
                pixels_bgra.push(col as u8);             // B
                pixels_bgra.push(row as u8);             // G
                pixels_bgra.push(0xC0 + col as u8);      // R
                pixels_bgra.push(0xFF);                  // A
            }
        }

        // Build the Orders payload with two orders: secondary cache
        // followed by primary MemBlt.
        let extra_flags: u16 = (0x06 << 3) | 0x02; // bpp_code=32 (0x06), cache_id=2
        let cache_body = build_cache_bitmap_v2_body(4, 2, 7, &pixels_bgra);
        let cache_frame = build_secondary_order_frame(extra_flags, 0x04, &cache_body);

        // MemBlt primary: cache_id=2, cache_index=7, blit (src 1,0, 3×2)
        // to dest (10, 20) with SRCCOPY.
        let mut memblt_body = Vec::with_capacity(2 + 4 * 2 + 1 + 2 * 2 + 2);
        memblt_body.extend_from_slice(&2u16.to_le_bytes());   // cacheId
        memblt_body.extend_from_slice(&10i16.to_le_bytes());  // left
        memblt_body.extend_from_slice(&20i16.to_le_bytes());  // top
        memblt_body.extend_from_slice(&3i16.to_le_bytes());   // width
        memblt_body.extend_from_slice(&2i16.to_le_bytes());   // height
        memblt_body.push(0xCC);                                // SRCCOPY
        memblt_body.extend_from_slice(&1i16.to_le_bytes());   // src_left
        memblt_body.extend_from_slice(&0i16.to_le_bytes());   // src_top
        memblt_body.extend_from_slice(&7u16.to_le_bytes());   // cacheIndex
        let memblt = PrimaryOrder {
            order_type: PrimaryOrderType::MemBlt,
            field_flags: 0x01FF, // all 9 fields
            bounds: None,
            data: memblt_body,
        };
        let mut memblt_bytes = vec![0u8; memblt.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut memblt_bytes);
            memblt.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        memblt_bytes.truncate(written);

        let mut frame = Vec::new();
        frame.extend_from_slice(&2u16.to_le_bytes()); // numberOrders = 2
        frame.extend_from_slice(&cache_frame);
        frame.extend_from_slice(&memblt_bytes);

        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        renderer.render(&event, &mut sink).unwrap();
        assert_eq!(renderer.bitmap_cache_len(), 1);
        assert_eq!(sink.blits.len(), 1);
        let (x, y, w, h, pixels) = &sink.blits[0];
        assert_eq!((*x, *y, *w, *h), (10, 20, 3, 2));
        // First top-down pixel of the blit is cache[(1, 0)] in BGRA →
        // RGBA = (0xC0+1, 0, 1, 0xFF).
        assert_eq!(&pixels[0..4], &[0xC1, 0x00, 0x01, 0xFF]);
    }

    /// CacheBitmapV2Compressed (orderType 0x05) at 16 bpp, RLE — feed
    /// a tiny RLE program (two WHITE special bytes = 2 white pixels)
    /// through the secondary handler, confirm the cache populates.
    #[test]
    fn cache_bitmap_v2_compressed_16bpp_rle_decodes() {
        // RLE program: WHITE, WHITE → 2 px @ 16 bpp white = (0xFFFF, 0xFFFF).
        let body_rle = [0xFD, 0xFD];
        // CacheBitmapV2 body (short forms, non-persistent):
        //   bitmapWidth = 2 (TWO_BYTE_UNSIGNED short)
        //   bitmapHeight = 1 (short)
        //   bitmapLength = 2 (FOUR_BYTE_UNSIGNED short — 1 byte with top
        //     bits 00 → 1 byte total, low 6 bits = value)
        //   cacheIndex = 5 (TWO_BYTE_UNSIGNED short)
        let mut body = Vec::new();
        body.push(2);          // width
        body.push(1);          // height
        body.push(2);          // length
        body.push(5);          // cacheIndex
        body.extend_from_slice(&body_rle);
        let extra_flags: u16 = (0x04 << 3) | 0x01; // bpp=16 (0x04), cache_id=1
        let cache_frame =
            build_secondary_order_frame(extra_flags, 0x05 /* CacheBitmapV2Compressed */, &body);
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes()); // numberOrders
        frame.extend_from_slice(&cache_frame);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        renderer.render(&event, &mut sink).unwrap();
        assert_eq!(renderer.bitmap_cache_len(), 1);
    }

    // ── S3d-6g: Polyline ───────────────────────────────────────────

    /// FrameSink that just records blits *and* serves a synthetic
    /// peek_rgba so the read-modify-write tests don't have to wire a
    /// shadow buffer themselves.
    #[derive(Default)]
    struct PeekableCapture {
        blits: Vec<(u16, u16, u16, u16, Vec<u8>)>,
        /// Pixels the sink should pretend are already on screen, RGBA
        /// indexed by `(x, y)` linearized as `y * stride + x`. `stride`
        /// is the width set by `seed`.
        seed_pixels: Vec<u8>,
        seed_width: u16,
        seed_height: u16,
    }

    impl PeekableCapture {
        fn seed(&mut self, w: u16, h: u16, color: [u8; 4]) {
            self.seed_width = w;
            self.seed_height = h;
            self.seed_pixels = core::iter::repeat(color)
                .take(w as usize * h as usize)
                .flatten()
                .collect();
        }
    }

    impl FrameSink for PeekableCapture {
        fn blit_rgba(
            &mut self,
            x: u16,
            y: u16,
            w: u16,
            h: u16,
            pixels: &[u8],
        ) {
            self.blits.push((x, y, w, h, pixels.to_vec()));
        }

        fn peek_rgba(
            &mut self,
            x: u16,
            y: u16,
            w: u16,
            h: u16,
            out: &mut Vec<u8>,
        ) -> bool {
            if x as u32 + w as u32 > self.seed_width as u32
                || y as u32 + h as u32 > self.seed_height as u32
            {
                return false;
            }
            out.clear();
            let stride = self.seed_width as usize * 4;
            for row in 0..h as usize {
                let row_off = (y as usize + row) * stride + x as usize * 4;
                out.extend_from_slice(&self.seed_pixels[row_off..row_off + w as usize * 4]);
            }
            true
        }
    }

    /// Polyline: a 2-segment path with deltas (+5, 0) then (0, +5).
    /// Counts pixels — Bresenham emits one blit per pixel.
    #[test]
    fn orders_polyline_two_segments_emits_pen_color_pixels() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        // Polyline body fields (7):
        //   xStart (i16 LE) = 10
        //   yStart (i16 LE) = 20
        //   bRop2 (u8) = 13
        //   BrushCacheEntry (u16 LE) = 0
        //   PenColor (3 bytes BGR) = (0x00, 0x80, 0xFF)
        //   NumDeltaEntries (u8) = 2
        //   CodedDeltaList: cbData(u16) + 2 deltas, each (dx, dy).
        //     delta1: dx=+5, dy=0 → short form: 0x05, 0x00
        //     delta2: dx=0, dy=+5 → short form: 0x00, 0x05
        let mut delta_list = Vec::new();
        delta_list.push(0x05); delta_list.push(0x00);
        delta_list.push(0x00); delta_list.push(0x05);
        let cb_data = delta_list.len() as u16;

        let mut body = Vec::new();
        body.extend_from_slice(&10i16.to_le_bytes());
        body.extend_from_slice(&20i16.to_le_bytes());
        body.push(13);                                // bRop2 = R2_COPYPEN
        body.extend_from_slice(&0u16.to_le_bytes()); // brushCacheEntry
        body.extend_from_slice(&[0x00, 0x80, 0xFF]); // penColor BGR
        body.push(2);                                 // numDeltaEntries
        body.extend_from_slice(&cb_data.to_le_bytes());
        body.extend_from_slice(&delta_list);

        let order = PrimaryOrder {
            order_type: PrimaryOrderType::Polyline,
            field_flags: 0x7F, // all 7 fields
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        renderer.render(&event, &mut sink).unwrap();
        // Two segments: 5 px horizontal + 5 px vertical = 11 unique
        // points if Bresenham hits each endpoint twice (once at end of
        // segment N, once at start of N+1). Single-pixel-wide
        // segments mean the count is segment_length+1 each minus one
        // overlap = 6 + 5 = 11 pixels in this case (or 5 + 6 with
        // shifted overlap accounting, depending on Bresenham nudges).
        assert!(
            sink.blits.len() >= 10,
            "expected ≥10 line pixels, got {}",
            sink.blits.len()
        );
        // Pen color BGR (0x00, 0x80, 0xFF) → RGBA (0xFF, 0x80, 0x00, 0xFF).
        for blit in &sink.blits {
            assert_eq!(&blit.4, &[0xFF, 0x80, 0x00, 0xFF]);
        }
    }

    // ── S3d-6h: peek_rgba + DstBlt DSTINVERT ───────────────────────

    #[test]
    fn dstblt_dstinvert_inverts_seeded_pixels() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        // DstBlt with DSTINVERT covering (0, 0, 1, 1).
        let mut body = Vec::with_capacity(2 * 4 + 1);
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&1i16.to_le_bytes());
        body.extend_from_slice(&1i16.to_le_bytes());
        body.push(0x55); // ROP3_DSTINVERT
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::DstBlt,
            field_flags: 0x1F,
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = PeekableCapture::default();
        sink.seed(2, 2, [0x12, 0x34, 0x56, 0xFF]);
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew, "DSTINVERT must blit when peek_rgba succeeds");
        assert_eq!(sink.blits.len(), 1);
        assert_eq!(
            sink.blits[0].4,
            vec![!0x12, !0x34, !0x56, 0xFF],
            "RGB inverted, alpha preserved"
        );
    }

    /// Without `peek_rgba`, a DSTINVERT silently drops — protects
    /// against painting against a non-seeded shadow buffer.
    #[test]
    fn dstblt_dstinvert_drops_when_peek_unsupported() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        let mut body = Vec::with_capacity(2 * 4 + 1);
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&1i16.to_le_bytes());
        body.extend_from_slice(&1i16.to_le_bytes());
        body.push(0x55);
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::DstBlt,
            field_flags: 0x1F,
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new(); // default peek_rgba returns false
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(!drew);
        assert!(sink.blits.is_empty());
    }

    /// Triangle (3 vertices) PolygonSC — verify scanline fill issues
    /// at least one row of color blits in the brush color.
    #[test]
    fn polygon_sc_triangle_fills_with_brush_color() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        // Triangle vertices: (10, 0), (0, 10), (20, 10).
        // Encode as (xStart=10, yStart=0) + 2 deltas: (-10, 10), (20, 0).
        let mut delta_list = Vec::new();
        delta_list.push(0x80 | 10); // dx=-10 short
        delta_list.push(0x0A);      // dy=+10 short
        delta_list.push(0x14);      // dx=+20 short
        delta_list.push(0x00);      // dy=0 short
        let cb_data = delta_list.len() as u16;

        let mut body = Vec::new();
        body.extend_from_slice(&10i16.to_le_bytes());
        body.extend_from_slice(&0i16.to_le_bytes());
        body.push(13);
        body.push(1);
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        body.push(2);
        body.extend_from_slice(&cb_data.to_le_bytes());
        body.extend_from_slice(&delta_list);

        let order = PrimaryOrder {
            order_type: PrimaryOrderType::PolygonSc,
            field_flags: 0x7F,
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew, "PolygonSC must produce ≥1 fill blit");
        assert!(!sink.blits.is_empty());
        for blit in &sink.blits {
            for px in blit.4.chunks_exact(4) {
                assert_eq!(px, &[0xCC, 0xBB, 0xAA, 0xFF]);
            }
        }
    }

    #[test]
    fn glyph_index_skeleton_advances_cursor_no_render() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        let mut body = Vec::new();
        body.push(0); // cacheId
        body.push(0); body.push(0); body.push(0);
        body.extend_from_slice(&[0, 0, 0]); // BackColor
        body.extend_from_slice(&[0, 0, 0]); // ForeColor
        for _ in 0..8 {
            body.extend_from_slice(&0u16.to_le_bytes());
        }
        body.push(0); body.push(0); body.push(0); body.push(0);
        body.extend_from_slice(&[0; 7]);
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.push(0); // cbData
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::GlyphIndex,
            field_flags: 0x003F_FFFF,
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(!drew);
        assert!(sink.blits.is_empty());
    }

    #[test]
    fn rop3_evaluator_truth_table() {
        assert_eq!(rop3(0xCC, 0x00, 0xAB, 0x00), 0xAB);
        assert_eq!(rop3(0xCC, 0xFF, 0x12, 0xFF), 0x12);
        assert_eq!(rop3(0x66, 0x00, 0xF0, 0x0F), 0xFF);
        assert_eq!(rop3(0xF0, 0x55, 0xAA, 0x12), 0x55);
        assert_eq!(rop3(0x55, 0x00, 0x00, 0xC3), !0xC3);
        assert_eq!(rop3(0x00, 0xFF, 0xFF, 0xFF), 0x00);
        assert_eq!(rop3(0xFF, 0x00, 0x00, 0x00), 0xFF);
    }

    #[test]
    fn patblt_pattern_patcopy_checkerboard() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        let pattern_rows: [u8; 8] = [0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55];

        let mut body = Vec::new();
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&2i16.to_le_bytes());
        body.extend_from_slice(&2i16.to_le_bytes());
        body.push(0xF0);
        body.extend_from_slice(&[0x11, 0x22, 0x33]);
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        body.push(0); body.push(0);
        body.push(0x03); // BS_PATTERN
        body.push(pattern_rows[0]);
        body.extend_from_slice(&pattern_rows[1..]);

        let order = PrimaryOrder {
            order_type: PrimaryOrderType::PatBlt,
            field_flags: 0x0FFF,
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew);
        assert_eq!(sink.blits.len(), 1);
        let pixels = &sink.blits[0].4;
        // Row 0 (pattern 0xAA): bit7=1, bit6=0 → fore, back.
        // Row 1 (pattern 0x55): bit7=0, bit6=1 → back, fore.
        // Existing PatBlt convention treats fore_color[0..3] as R,G,B
        // directly (matches `orders_patblt_solid_patcopy_renders_filled_rect`).
        assert_eq!(&pixels[0..4],   &[0xAA, 0xBB, 0xCC, 0xFF]);
        assert_eq!(&pixels[4..8],   &[0x11, 0x22, 0x33, 0xFF]);
        assert_eq!(&pixels[8..12],  &[0x11, 0x22, 0x33, 0xFF]);
        assert_eq!(&pixels[12..16], &[0xAA, 0xBB, 0xCC, 0xFF]);
    }

    /// CacheGlyph V1 + GlyphIndex round-trip — cache one 8×8 glyph
    /// (a solid block: every bit set), reference it from a GlyphIndex,
    /// and expect 64 fore-color blits at the pen position.
    #[test]
    fn cache_glyph_then_glyph_index_round_trip() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        // CacheGlyph V1 body: cacheId(1) + cGlyphs(1) + glyph entry.
        // 1 glyph: cacheIndex=5, x=0, y=0, cx=8, cy=4, mask = 4 rows of
        // 4-byte stride (8 bits actually used per row, 0xFF + 3 pad).
        let mut body = Vec::new();
        body.push(2); // cacheId duplicate
        body.push(1); // cGlyphs
        body.extend_from_slice(&5u16.to_le_bytes()); // cacheIndex
        body.extend_from_slice(&0i16.to_le_bytes()); // x
        body.extend_from_slice(&0i16.to_le_bytes()); // y
        body.extend_from_slice(&8u16.to_le_bytes()); // cx
        body.extend_from_slice(&4u16.to_le_bytes()); // cy
        // mask: 4 rows × 4 bytes (stride = ceil(8/8)=1 → +3 pad to 4).
        for _ in 0..4 {
            body.push(0xFF);              // 8 bits = entire row
            body.extend_from_slice(&[0; 3]);
        }
        let extra_flags: u16 = 0x02; // cacheId = 2
        let cache_frame = build_secondary_order_frame(extra_flags, 0x03 /* CacheGlyph */, &body);

        // GlyphIndex order: cacheId=2, foreColor=(0xAA, 0xBB, 0xCC),
        // x=10, y=20, cbData=1, data=[5] → render glyph index 5.
        let mut gi = Vec::new();
        gi.push(2);                                   // cacheId
        gi.push(0); gi.push(0); gi.push(0);           // flAccel/charInc/fOpRedundant
        gi.extend_from_slice(&[0, 0, 0]);             // back
        gi.extend_from_slice(&[0xAA, 0xBB, 0xCC]);    // fore
        for _ in 0..8 { gi.extend_from_slice(&0u16.to_le_bytes()); } // bk/op rects
        gi.push(0); gi.push(0); gi.push(0); gi.push(0);
        gi.extend_from_slice(&[0; 7]);
        gi.extend_from_slice(&10u16.to_le_bytes());   // x
        gi.extend_from_slice(&20u16.to_le_bytes());   // y
        gi.push(1);                                   // cbData
        gi.push(5);                                   // glyph index 5
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::GlyphIndex,
            field_flags: 0x003F_FFFF,
            bounds: None,
            data: gi,
        };
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);

        let mut frame = Vec::new();
        frame.extend_from_slice(&2u16.to_le_bytes());
        frame.extend_from_slice(&cache_frame);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        renderer.render(&event, &mut sink).unwrap();
        assert_eq!(renderer.glyph_cache_len(), 1);
        // 8×4 mask, all bits set → 32 fore-color pixel blits.
        assert_eq!(sink.blits.len(), 32);
        for blit in &sink.blits {
            assert_eq!(&blit.4, &[0xAA, 0xBB, 0xCC, 0xFF]);
        }
    }

    /// CacheBitmapV1 16 bpp uncompressed → cache populates and a
    /// MemBlt look-up against the inserted entry succeeds.
    #[test]
    fn cache_bitmap_v1_uncompressed_16bpp() {
        // V1 body: cacheId(1) + pad(1) + width(1) + height(1) + bpp(1) +
        // bitmapLength(2 LE) + cacheIndex(2 LE) + payload.
        // 1×1 16 bpp white pixel = 0xFFFF.
        let mut body = Vec::new();
        body.push(2); // cacheId
        body.push(0); // pad
        body.push(1); // width
        body.push(1); // height
        body.push(16); // bpp
        body.extend_from_slice(&2u16.to_le_bytes()); // length
        body.extend_from_slice(&9u16.to_le_bytes()); // cacheIndex
        body.extend_from_slice(&[0xFF, 0xFF]);
        let cache_frame = build_secondary_order_frame(0, 0x00 /* V1 uncompressed */, &body);
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        frame.extend_from_slice(&cache_frame);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        renderer.render(&event, &mut sink).unwrap();
        assert_eq!(renderer.bitmap_cache_len(), 1);
    }

    /// CacheBitmapV3 32 bpp uncompressed (codec_id = 0).
    #[test]
    fn cache_bitmap_v3_codec0_32bpp() {
        // V3 body: cacheIndex(2 LE) + key1(4) + key2(4) +
        // TS_BITMAP_DATA_EX (12 byte header + payload).
        let mut body = Vec::new();
        body.extend_from_slice(&7u16.to_le_bytes()); // cacheIndex
        body.extend_from_slice(&0u32.to_le_bytes()); // key1
        body.extend_from_slice(&0u32.to_le_bytes()); // key2
        // TS_BITMAP_DATA_EX header.
        body.push(32); // bpp
        body.push(0);  // flags (no ex header)
        body.push(0);  // reserved
        body.push(0);  // codec_id
        body.extend_from_slice(&1u16.to_le_bytes()); // width
        body.extend_from_slice(&1u16.to_le_bytes()); // height
        body.extend_from_slice(&4u32.to_le_bytes()); // length
        // BGRA white pixel.
        body.extend_from_slice(&[0xCC, 0xBB, 0xAA, 0xFF]);
        // extraFlags: cacheId=2 in low 3 bits, bpp encoded in high bits.
        let extra_flags: u16 = 0x02;
        let cache_frame = build_secondary_order_frame(extra_flags, 0x08 /* V3 */, &body);
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        frame.extend_from_slice(&cache_frame);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        renderer.render(&event, &mut sink).unwrap();
        assert_eq!(renderer.bitmap_cache_len(), 1);
    }

    /// CacheBrush + PatBlt with cached pattern (high-bit-set
    /// brush_style + brush_hatch=cache index) round-trip. Verifies the
    /// brush cache populates and the PatBlt walker resolves through it.
    #[test]
    fn cache_brush_then_patblt_round_trip() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        // CacheBrush body: cacheEntry=3, iBitmapFormat=1 (1bpp), cx=8,
        // cy=8, style=0, iBytes=8, brushData = vertical-stripe pattern
        // (0x55 = 01010101 every row). Wire is bottom-up so we send
        // 8 identical 0x55 bytes and the parser stores them as-is.
        let mut body = Vec::new();
        body.push(3);          // cacheEntry
        body.push(1);          // iBitmapFormat = 1bpp
        body.push(8);          // cx
        body.push(8);          // cy
        body.push(0);          // style
        body.push(8);          // iBytes
        body.extend_from_slice(&[0x55; 8]);
        let cache_frame = build_secondary_order_frame(0, 0x07 /* CacheBrush */, &body);

        // PatBlt with brush_style = BS_PATTERN | 0x80 (cached), brush_hatch=3.
        let mut pat_body = Vec::new();
        pat_body.extend_from_slice(&0i16.to_le_bytes());
        pat_body.extend_from_slice(&0i16.to_le_bytes());
        pat_body.extend_from_slice(&2i16.to_le_bytes()); // 2-wide
        pat_body.extend_from_slice(&1i16.to_le_bytes()); // 1-tall
        pat_body.push(0xF0);                              // PATCOPY
        pat_body.extend_from_slice(&[0x10, 0x20, 0x30]); // back BGR
        pat_body.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // fore BGR
        pat_body.push(0); pat_body.push(0);
        pat_body.push(BS_PATTERN | 0x80);                 // cached pattern
        pat_body.push(3);                                 // brush_hatch = cache index
        pat_body.extend_from_slice(&[0; 7]);              // brush_extra
        let patblt = PrimaryOrder {
            order_type: PrimaryOrderType::PatBlt,
            field_flags: 0x0FFF,
            bounds: None,
            data: pat_body,
        };
        let mut patblt_bytes = vec![0u8; patblt.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut patblt_bytes);
            patblt.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        patblt_bytes.truncate(written);

        let mut frame = Vec::new();
        frame.extend_from_slice(&2u16.to_le_bytes()); // numberOrders = 2
        frame.extend_from_slice(&cache_frame);
        frame.extend_from_slice(&patblt_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        renderer.render(&event, &mut sink).unwrap();
        assert_eq!(renderer.brush_cache_len(), 1);
        // Pattern row reversed (wire bottom-up) → first stored row is
        // 0x55 (column 0=0, column 1=1, …). Top-most bit = leftmost
        // pixel. With pattern row = 0x55 = 01010101 and width=2, top
        // pixel: bit7=0 → back, second pixel: bit6=1 → fore.
        assert_eq!(sink.blits.len(), 1);
        let pixels = &sink.blits[0].4;
        assert_eq!(&pixels[0..4], &[0x10, 0x20, 0x30, 0xFF]); // back
        assert_eq!(&pixels[4..8], &[0xAA, 0xBB, 0xCC, 0xFF]); // fore
    }

    /// BS_HATCHED with HS_HORIZONTAL: row 3 of an 8×8 hatch is all-on
    /// (0xFF), other rows are all-off — render a 1×4 column from y=0..3
    /// and verify only y=3 picks foreground.
    #[test]
    fn patblt_bs_hatched_horizontal() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        let mut body = Vec::new();
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&1i16.to_le_bytes());
        body.extend_from_slice(&4i16.to_le_bytes()); // 1×4
        body.push(0xF0);                              // PATCOPY
        body.extend_from_slice(&[0x10, 0x20, 0x30]); // back
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // fore
        body.push(0); body.push(0);
        body.push(BS_HATCHED);
        body.push(0); // HS_HORIZONTAL
        body.extend_from_slice(&[0; 7]);
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::PatBlt,
            field_flags: 0x0FFF,
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        renderer.render(&event, &mut sink).unwrap();
        let pixels = &sink.blits[0].4;
        // Rows 0, 1, 2 = back; row 3 = fore.
        assert_eq!(&pixels[0..4],   &[0x10, 0x20, 0x30, 0xFF]); // y=0
        assert_eq!(&pixels[4..8],   &[0x10, 0x20, 0x30, 0xFF]); // y=1
        assert_eq!(&pixels[8..12],  &[0x10, 0x20, 0x30, 0xFF]); // y=2
        assert_eq!(&pixels[12..16], &[0xAA, 0xBB, 0xCC, 0xFF]); // y=3
    }

    /// MemBlt against an empty cache must silently skip — same shape
    /// as other "render-only-when-possible" branches in the walker.
    #[test]
    fn memblt_cache_miss_skips_silently() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        let mut body = Vec::with_capacity(2 + 4 * 2 + 1 + 2 * 2 + 2);
        body.extend_from_slice(&0u16.to_le_bytes()); // cacheId 0
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&1i16.to_le_bytes());
        body.extend_from_slice(&1i16.to_le_bytes());
        body.push(0xCC);
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&0i16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // cacheIndex 0
        let memblt = PrimaryOrder {
            order_type: PrimaryOrderType::MemBlt,
            field_flags: 0x01FF,
            bounds: None,
            data: body,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; memblt.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            memblt.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(!drew);
        assert!(sink.blits.is_empty());
    }

    #[test]
    fn orders_unsupported_primary_type_surfaces_typed_error() {
        // PrimaryOrder::encode for a SaveBitmap with no fields → just
        // the header (control_flags + order_type + 1 byte fieldFlags=0).
        // We don't render SaveBitmap, but the cursor advance still
        // works, so this lands as UnsupportedPrimaryOrder.
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::drawing_orders::PrimaryOrder;
        let order = PrimaryOrder {
            order_type: PrimaryOrderType::SaveBitmap,
            field_flags: 0,
            bounds: None,
            data: Vec::new(),
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        let mut order_bytes = vec![0u8; order.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut order_bytes);
            order.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        order_bytes.truncate(written);
        frame.extend_from_slice(&order_bytes);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: frame,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(
            matches!(err, RenderError::UnsupportedPrimaryOrder { order_type: PrimaryOrderType::SaveBitmap }),
            "expected UnsupportedPrimaryOrder(SaveBitmap), got {err:?}"
        );
    }

    /// Without `set_rfx_codec_id`, a Surface Bits cmd carrying RFX data
    /// is still surfaced as `UnsupportedCodec` — protect against an
    /// embedder forgetting to register the codec_id and silently
    /// painting garbage.
    #[test]
    fn rfx_without_registration_surfaces_unsupported_codec() {
        let codec_id = 0x09;
        // Empty RFX payload — never reached because we drop on codec_id.
        let surfcmds_payload = build_set_surface_bits_rfx(codec_id, 0, 0, vec![]);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: surfcmds_payload,
        };
        let mut renderer = BitmapRenderer::new();
        // Note: no set_rfx_codec_id call.
        let mut sink = Capture::new();
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(
            matches!(err, RenderError::UnsupportedCodec { codec_id: 0x09 }),
            "expected UnsupportedCodec(0x09), got {err:?}"
        );
    }

    #[test]
    fn surface_commands_unsupported_codec_surfaces_typed_error() {
        use justrdp_core::Encode;
        use justrdp_pdu::rdp::surface_commands::SetSurfaceBitsCmd;
        let cmd = SetSurfaceBitsCmd {
            dest_left: 0,
            dest_top: 0,
            dest_right: 1,
            dest_bottom: 1,
            bitmap_data: BitmapDataEx {
                bpp: 32,
                codec_id: 0x03, // RemoteFX, not yet wired
                width: 1,
                height: 1,
                ex_header: None,
                bitmap_data: vec![0; 1], // payload doesn't matter — codec_id is rejected first
            },
        };
        let mut buf = vec![0u8; cmd.size()];
        let written = {
            let mut cursor = WriteCursor::new(&mut buf);
            cmd.encode(&mut cursor).unwrap();
            cursor.pos()
        };
        buf.truncate(written);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::SurfaceCommands,
            data: buf,
        };
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(
            matches!(err, RenderError::UnsupportedCodec { codec_id: 0x03 }),
            "expected UnsupportedCodec(0x03), got {err:?}"
        );
    }

    #[test]
    fn renderer_rejects_palette_with_wrong_color_count() {
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let mut data = Vec::with_capacity(2 + 4 + 3);
        data.extend_from_slice(&[0, 0]); // pad
        data.extend_from_slice(&1u32.to_le_bytes()); // wrong count
        data.extend_from_slice(&[0, 0, 0]); // 1 entry
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Palette,
            data,
        };
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(matches!(err, RenderError::SizeMismatch(_)));
    }
}
