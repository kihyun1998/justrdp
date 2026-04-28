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
use justrdp_graphics::{BitsPerPixel, RleDecompressor, RleError};
use justrdp_pdu::rdp::bitmap::{
    TsBitmapData, TsUpdateBitmapData, BITMAP_COMPRESSION,
};
use justrdp_pdu::rdp::drawing_orders::{
    decode_dstblt, decode_lineto, decode_memblt, decode_opaque_rect, decode_patblt, decode_scrblt,
    OpaqueRectOrder, PrimaryOrderHistory, PrimaryOrderType, ALT_SECONDARY_ORDER_HEADER_SIZE,
    ORDER_TYPE_CHANGE, TS_BOUNDS, TS_DELTA_COORDINATES, TS_SECONDARY, TS_STANDARD,
    TS_ZERO_BOUNDS_DELTAS, TS_ZERO_FIELD_BYTE_BIT0, TS_ZERO_FIELD_BYTE_BIT1,
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
        }
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
/// palette table, the latest Frame Marker id, and (when registered) the
/// RFX entropy mode picked up from `TS_RFX_CONTEXT`. Use one instance
/// per session; reusing across sessions risks decoding new traffic
/// against stale palette/codec state.
#[derive(Debug, Clone)]
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
}

impl Default for BitmapRenderer {
    fn default() -> Self {
        Self::new()
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
        }
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
                let _extra_flags = cursor.read_u16_le("SecondaryOrder::extraFlags")?;
                let _order_type = cursor.read_u8("SecondaryOrder::orderType")?;
                // Per MS-RDPEGDI: body length = orderLength + 7 - 3 = orderLength + 4
                let body_len = (order_length + 4) as usize;
                cursor.read_slice(body_len, "SecondaryOrder::body")?;
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
                let _ = decode_dstblt(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(false)
            }
            PrimaryOrderType::PatBlt => {
                let _ = decode_patblt(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(false)
            }
            PrimaryOrderType::ScrBlt => {
                let _ = decode_scrblt(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(false)
            }
            PrimaryOrderType::MemBlt => {
                let _ = decode_memblt(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(false)
            }
            PrimaryOrderType::LineTo => {
                let _ = decode_lineto(cursor, field_flags, delta, &mut self.primary_history)?;
                Ok(false)
            }
            other => Err(RenderError::UnsupportedPrimaryOrder { order_type: other }),
        }
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
        Err(RenderError::UnsupportedCodec {
            codec_id: data.codec_id,
        })
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
