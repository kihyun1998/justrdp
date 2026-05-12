//! `GfxHandler` adapter that bridges decoded RDPEGFX surface commands to
//! a [`FrameSink`]. Maintains its own surface map (Option A from the
//! PRD #20 recon — keeps [`BitmapRenderer`] stateless w.r.t. EGFX
//! surfaces).
//!
//! Embedders construct a [`GfxRenderer`] around their `FrameSink`, wrap
//! it in `GfxClient::with_handler(Box::new(renderer))`, register that on
//! a `DrdynvcClient`, and push the Drdynvc onto the SVC processor list.
//!
//! [`BitmapRenderer`]: crate::BitmapRenderer

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::any::Any;

use justrdp_core::AsAny;
use justrdp_egfx::{GfxColor32, GfxHandler, GfxMonitorDef, GfxPixelFormat, GfxPoint16, GfxRect16};
use justrdp_graphics::avc::AvcDecoder;
use justrdp_graphics::clearcodec::ClearCodecDecoder;

use crate::render::FrameSink;

// `GfxCache` trait is consumed via `self.cache.insert/get/evict`; the
// trait must be in scope wherever those methods are called.
use cache::GfxCache as _;

// `MutexFrameSink` requires `std::sync::Mutex`; behind the alloc + std
// gate so wasm32 / no_std embedders can still depend on the rest of the
// module. Tauri (the primary consumer) is std-only.
extern crate std;
use std::sync::{Arc, Mutex};

/// `FrameSink` wrapper that locks an inner sink behind an `Arc<Mutex<...>>`.
///
/// Useful when two async tasks need to share one sink — for example, the
/// JustRDP Tauri embedder runs the SVC processor pump (which dispatches
/// EGFX surface bits through `GfxRenderer`) on a separate task from
/// `run_session` (which dispatches fast-path Surface Commands through
/// `BitmapRenderer`). Both write to the same canvas; `MutexFrameSink`
/// gives both a `FrameSink` handle to the shared `TauriFrameSink`.
///
/// Locking pattern: each `FrameSink` method takes the mutex, calls
/// through, releases. The mutex is uncontended in the common case
/// (one task at a time during a frame batch).
pub struct MutexFrameSink<S: FrameSink + Send + 'static> {
    inner: Arc<Mutex<S>>,
}

impl<S: FrameSink + Send + 'static> MutexFrameSink<S> {
    /// Wrap a shared sink. Clone the returned `Arc` to hand the same
    /// inner sink to multiple tasks.
    pub fn new(inner: Arc<Mutex<S>>) -> Self {
        Self { inner }
    }

    /// Borrow the underlying `Arc<Mutex<S>>` so the embedder can reach
    /// inner-sink-specific APIs (e.g. `TauriFrameSink::drain_blits`).
    pub fn arc(&self) -> &Arc<Mutex<S>> {
        &self.inner
    }
}

impl<S: FrameSink + Send + 'static> Clone for MutexFrameSink<S> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<S: FrameSink + Send + 'static> FrameSink for MutexFrameSink<S> {
    fn resize(&mut self, width: u16, height: u16) {
        if let Ok(mut s) = self.inner.lock() {
            s.resize(width, height);
        }
    }

    fn blit_rgba(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        pixels_rgba: &[u8],
    ) {
        if let Ok(mut s) = self.inner.lock() {
            s.blit_rgba(dest_left, dest_top, width, height, pixels_rgba);
        }
    }

    fn peek_rgba(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        out: &mut Vec<u8>,
    ) -> bool {
        match self.inner.lock() {
            Ok(mut s) => s.peek_rgba(dest_left, dest_top, width, height, out),
            Err(_) => false,
        }
    }

    fn flush(&mut self) {
        if let Ok(mut s) = self.inner.lock() {
            s.flush();
        }
    }
}

/// Strip the AVC420 envelope and return the inner H.264 Annex B bytes.
///
/// MS-RDPEGFX 2.2.4.4 `RDPGFX_AVC420_BITMAP_STREAM`:
///   numRegionRects (u32 LE)
///   regionRects[numRegionRects] (each 8 bytes: 4 × u16 LE)
///   quantQualityVals[numRegionRects] (each 2 bytes)
///   avc420EncodedBitstream (remaining)
///
/// Returns `None` if the payload is truncated relative to the
/// declared `numRegionRects`.
fn unwrap_avc420_envelope(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < 4 {
        return None;
    }
    let num_rects = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    let rects_len = num_rects.checked_mul(8)?;
    let qq_len = num_rects.checked_mul(2)?;
    let header_len = 4usize.checked_add(rects_len)?.checked_add(qq_len)?;
    if payload.len() < header_len {
        return None;
    }
    Some(&payload[header_len..])
}

/// Strip the AVC444 outer envelope, then the inner AVC420 envelope, and
/// return the Annex B bytes of stream1 (the main view).
///
/// MS-RDPEGFX 2.2.4.5 `RDPGFX_AVC444_BITMAP_STREAM`:
///   cbAvc420EncodedBitstream1 (u32 LE — high 30 bits = byte count of
///     stream1, low 2 bits = LC frame type indicator)
///   avc420EncodedBitstream1 (RDPGFX_AVC420_BITMAP_STREAM, length above)
///   [avc420EncodedBitstream2] (RDPGFX_AVC420_BITMAP_STREAM, only when
///     LC indicates a chroma-and-luma pair)
///
/// This slice handles stream1 only; stream2 (auxiliary view) is a
/// follow-up. Returns `None` on truncation or malformed length.
fn unwrap_avc444_envelope(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < 4 {
        return None;
    }
    let header = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let stream1_len = (header >> 2) as usize;
    let end = 4usize.checked_add(stream1_len)?;
    if payload.len() < end {
        return None;
    }
    unwrap_avc420_envelope(&payload[4..end])
}

/// EGFX bitmap-cache slot store (PRD #35 Module B).
///
/// MS-RDPEGFX 2.2.2.13 (SurfaceToCache), 2.2.2.14 (CacheToSurface), and
/// 2.2.2.16 (EvictCacheEntry) describe a server-driven cache: the
/// server tells us when to insert (with cache_slot + key), when to read
/// (slot → blit at dest points), and when to evict. The client does
/// *not* run its own eviction policy — server is authoritative.
///
/// `GfxCache` is intentionally a small trait so the renderer never
/// touches raw storage. Implementations can be HashMap-backed, slab-
/// backed, or memory-bounded without renderer code knowing.
pub mod cache {
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    /// A bitmap region stored in one cache slot. Pixels are top-down
    /// RGBA, matching the format the rest of `GfxRenderer` keeps in
    /// `SurfaceState::pixels_rgba`.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CachedTile {
        pub width: u16,
        pub height: u16,
        pub pixels_rgba: Vec<u8>,
    }

    /// Server-driven bitmap cache backing.
    pub trait GfxCache {
        /// Store `tile` under `slot`. Replaces any prior entry at the
        /// same slot (the server is responsible for issuing
        /// EvictCacheEntry before reusing a slot when it cares about
        /// the previous tile).
        fn insert(&mut self, slot: u16, tile: CachedTile);
        /// Look up the tile at `slot`, if any.
        fn get(&self, slot: u16) -> Option<&CachedTile>;
        /// Remove the tile at `slot`. No-op if the slot was empty.
        fn evict(&mut self, slot: u16);
    }

    /// Default in-memory `GfxCache` impl — a `BTreeMap<u16, CachedTile>`.
    #[derive(Default, Debug)]
    pub struct InMemoryGfxCache {
        slots: BTreeMap<u16, CachedTile>,
    }

    impl InMemoryGfxCache {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl GfxCache for InMemoryGfxCache {
        fn insert(&mut self, slot: u16, tile: CachedTile) {
            self.slots.insert(slot, tile);
        }

        fn get(&self, slot: u16) -> Option<&CachedTile> {
            self.slots.get(&slot)
        }

        fn evict(&mut self, slot: u16) {
            self.slots.remove(&slot);
        }
    }
}

/// Per-surface state held by [`GfxRenderer`]. Pixels are stored top-down
/// RGBA (the format `FrameSink::blit_rgba` expects), regardless of the
/// surface's wire pixel format — the wire format is normalised at write
/// time inside `on_wire_to_surface_1`.
struct SurfaceState {
    width: u16,
    height: u16,
    /// Output origin in desktop coordinates (`None` until `on_map_surface_to_output`).
    output_origin: Option<(u32, u32)>,
    /// `width * height * 4` RGBA bytes, top-down.
    pixels_rgba: Vec<u8>,
    /// Bounding rect (left, top, right, bottom) of pixels written since
    /// the last `on_end_frame` flush. `None` when nothing was painted
    /// — `on_end_frame` skips the surface so fast-path Bitmap pixels
    /// already on the canvas are not overwritten with a zero-fill EGFX
    /// surface buffer (the bug that #28's full-surface blit caused).
    dirty_rect: Option<(u16, u16, u16, u16)>,
}

impl SurfaceState {
    /// Expand `dirty_rect` to enclose the new `rect`, clamped to the
    /// surface dimensions.
    fn mark_dirty(&mut self, left: u16, top: u16, right: u16, bottom: u16) {
        let r = right.min(self.width);
        let b = bottom.min(self.height);
        if left >= r || top >= b {
            return;
        }
        match self.dirty_rect {
            None => self.dirty_rect = Some((left, top, r, b)),
            Some((l0, t0, r0, b0)) => {
                self.dirty_rect = Some((l0.min(left), t0.min(top), r0.max(r), b0.max(b)));
            }
        }
    }
}

/// `GfxHandler` adapter that decodes EGFX commands into [`FrameSink`]
/// blits at the surface's mapped output origin.
///
/// Generic over the sink so embedders can plug in any `FrameSink` impl
/// (Tauri's `TauriFrameSink`, the WASM `CanvasFrameSink`, a test mock).
pub struct GfxRenderer<S: FrameSink + Send + 'static> {
    sink: S,
    surfaces: BTreeMap<u16, SurfaceState>,
    /// Optional H.264 backend. Required for AVC420 / AVC444 / AVC444V2
    /// payloads to do anything; without it, AVC `on_wire_to_surface_1`
    /// drops silently. The real WebCodecs-backed implementation is
    /// PRD #20 / #26.
    avc_decoder: Option<Box<dyn AvcDecoder>>,
    /// Lazy-initialised ClearCodec decoder. Created on first 0x0008
    /// dispatch so adapters that never see ClearCodec pay no cost.
    /// Stateful (glyph cache + VBar caches per MS-RDPEGFX §2.2.4) —
    /// the `&mut self` carries forward across calls.
    clearcodec_decoder: Option<ClearCodecDecoder>,
    /// Bitmap cache slots backing MS-RDPEGFX 2.2.2.13 (SurfaceToCache),
    /// 2.2.2.14 (CacheToSurface), 2.2.2.16 (EvictCacheEntry).
    /// PRD #35 Module B (renderer cache wire-up).
    cache: cache::InMemoryGfxCache,
}

impl<S: FrameSink + Send + 'static> GfxRenderer<S> {
    /// Create a new adapter wrapping the given sink.
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            surfaces: BTreeMap::new(),
            avc_decoder: None,
            clearcodec_decoder: None,
            cache: cache::InMemoryGfxCache::new(),
        }
    }

    /// Inject an [`AvcDecoder`] backend. After this call, AVC420 /
    /// AVC444 / AVC444V2 payloads route through the decoder; before it
    /// (or with `None`), they drop silently like any unknown codec.
    pub fn set_avc_decoder(&mut self, decoder: Box<dyn AvcDecoder>) {
        self.avc_decoder = Some(decoder);
    }

    /// Borrow the underlying sink (test inspection / diagnostics).
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Consume the adapter and return the underlying sink.
    pub fn into_sink(self) -> S {
        self.sink
    }
}

impl<S: FrameSink + Send + 'static> AsAny for GfxRenderer<S> {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl<S: FrameSink + Send + 'static> GfxHandler for GfxRenderer<S> {
    fn on_create_surface(
        &mut self,
        surface_id: u16,
        width: u16,
        height: u16,
        _pixel_format: GfxPixelFormat,
    ) {
        log::info!(
            "[DIAG-egfx] on_create_surface id={surface_id} {width}x{height}"
        );
        let pixels_rgba = alloc::vec![0u8; usize::from(width) * usize::from(height) * 4];
        self.surfaces.insert(
            surface_id,
            SurfaceState {
                width,
                height,
                output_origin: None,
                pixels_rgba,
                dirty_rect: None,
            },
        );
    }

    fn on_delete_surface(&mut self, surface_id: u16) {
        log::info!("[DIAG-egfx] on_delete_surface id={surface_id}");
        self.surfaces.remove(&surface_id);
    }

    fn on_map_surface_to_output(
        &mut self,
        surface_id: u16,
        output_origin_x: u32,
        output_origin_y: u32,
    ) {
        log::info!(
            "[DIAG-egfx] on_map_surface_to_output id={surface_id} origin=({output_origin_x},{output_origin_y})"
        );
        if let Some(s) = self.surfaces.get_mut(&surface_id) {
            s.output_origin = Some((output_origin_x, output_origin_y));
        }
    }

    fn on_reset_graphics(
        &mut self,
        width: u32,
        height: u32,
        _monitors: &[GfxMonitorDef],
    ) {
        log::info!("[DIAG-egfx] on_reset_graphics {width}x{height}");
        self.surfaces.clear();
    }

    fn on_wire_to_surface_1(
        &mut self,
        surface_id: u16,
        codec_id: u16,
        _pixel_format: GfxPixelFormat,
        dest_rect: GfxRect16,
        bitmap_data: &[u8],
    ) {
        log::info!(
            "[DIAG-egfx] on_wire_to_surface_1 id={surface_id} codec=0x{codec_id:04x} bytes={n} rect=({l},{t},{r},{b})",
            n = bitmap_data.len(),
            l = dest_rect.left,
            t = dest_rect.top,
            r = dest_rect.right,
            b = dest_rect.bottom,
        );
        let Some(surface) = self.surfaces.get_mut(&surface_id) else {
            return; // unknown surface — drop
        };

        match codec_id {
            // RDPGFX_CODECID_UNCOMPRESSED — bitmap_data is wire-format pixels
            // (BGRA byte order per GfxColor32 wire layout). Composite into
            // the surface buffer at dest_rect with BGRA→RGBA swap.
            0x0000 => {
                composite_uncompressed_bgra_to_rgba(surface, dest_rect, bitmap_data);
            }
            // ClearCodec — text + UI chrome codec, MS-RDPEGFX §2.2.4.
            // Decoder returns BGR (3 bytes/pixel); convert to RGBA at
            // composite time. Decoder is stateful (glyph + VBar caches
            // across calls) so we lazy-init on first 0x0008 hit.
            0x0008 => {
                let rect_w = dest_rect.right.saturating_sub(dest_rect.left);
                let rect_h = dest_rect.bottom.saturating_sub(dest_rect.top);
                if rect_w == 0 || rect_h == 0 {
                    return;
                }
                if self.clearcodec_decoder.is_none() {
                    self.clearcodec_decoder = Some(ClearCodecDecoder::new());
                }
                let decoder = self
                    .clearcodec_decoder
                    .as_mut()
                    .expect("just initialized above");
                match decoder.decode(bitmap_data, rect_w, rect_h) {
                    Ok(bgr) => {
                        composite_bgr_to_rgba(surface, dest_rect, &bgr);
                    }
                    Err(_) => {
                        // Decode failure — drop the chunk silently.
                        // Production embedders may want to log here.
                    }
                }
            }
            // AVC420 (RDPGFX_CODECID_AVC420) / AVC444 / AVC444V2 — parse
            // the EGFX envelope, then hand the inner H.264 Annex B
            // bytestream to the registered AvcDecoder. The envelope
            // varies per codec id: AVC420 = RDPGFX_AVC420_BITMAP_STREAM
            // (MS-RDPEGFX 2.2.4.4); AVC444/AVC444V2 = one or two
            // RDPGFX_AVC420_BITMAP_STREAMs preceded by a packed length+LC
            // header (MS-RDPEGFX 2.2.4.5 / 2.2.4.6). PRD #35 Module B.
            // YUV→RGBA composite onto the surface is a follow-up cycle.
            0x000B => {
                if let Some(decoder) = self.avc_decoder.as_mut() {
                    if let Some(annex_b) = unwrap_avc420_envelope(bitmap_data) {
                        let _ = decoder.decode_frame(annex_b);
                    }
                    let _ = surface;
                }
            }
            0x000E | 0x000F => {
                if let Some(decoder) = self.avc_decoder.as_mut() {
                    if let Some(annex_b) = unwrap_avc444_envelope(bitmap_data) {
                        let _ = decoder.decode_frame(annex_b);
                    }
                    let _ = surface;
                }
            }
            // Other codecs (ClearCodec=0x0008, Planar=0x000A) tracked
            // in follow-up cycles. Unknown codecs drop silently.
            _ => {
                // Production embedders should log here; tests assert no
                // blit was emitted.
            }
        }
    }

    fn on_wire_to_surface_2(
        &mut self,
        _surface_id: u16,
        _codec_id: u16,
        _codec_context_id: u32,
        _pixel_format: GfxPixelFormat,
        _bitmap_data: &[u8],
    ) {
        // ProgressiveRFX — out of scope for #28.
    }

    fn on_solid_fill(
        &mut self,
        surface_id: u16,
        fill_color: GfxColor32,
        rectangles: &[GfxRect16],
    ) {
        log::info!(
            "[DIAG-egfx] on_solid_fill id={surface_id} color=#{:02x}{:02x}{:02x} rects={}",
            fill_color.r,
            fill_color.g,
            fill_color.b,
            rectangles.len()
        );
        let Some(surface) = self.surfaces.get_mut(&surface_id) else {
            return;
        };
        let stride = usize::from(surface.width) * 4;
        for rect in rectangles {
            let l = rect.left.min(surface.width);
            let t = rect.top.min(surface.height);
            let r = rect.right.min(surface.width);
            let b = rect.bottom.min(surface.height);
            if l >= r || t >= b {
                continue;
            }
            for row in t..b {
                let row_off = usize::from(row) * stride + usize::from(l) * 4;
                let row_end = row_off + usize::from(r - l) * 4;
                let buf = &mut surface.pixels_rgba[row_off..row_end];
                for px in buf.chunks_exact_mut(4) {
                    px[0] = fill_color.r;
                    px[1] = fill_color.g;
                    px[2] = fill_color.b;
                    px[3] = 0xFF;
                }
            }
            surface.mark_dirty(l, t, r, b);
        }
    }

    fn on_surface_to_surface(
        &mut self,
        src_surface_id: u16,
        dst_surface_id: u16,
        src_rect: GfxRect16,
        dest_points: &[GfxPoint16],
    ) {
        log::info!(
            "[DIAG-egfx] on_surface_to_surface src={src_surface_id} dst={dst_surface_id} src_rect=({},{},{},{}) dst_n={}",
            src_rect.left, src_rect.top, src_rect.right, src_rect.bottom, dest_points.len()
        );
        // Same-surface scroll is the common case (window content shift).
        // Cross-surface is rare; not handled here.
        if src_surface_id != dst_surface_id {
            return;
        }
        let Some(surface) = self.surfaces.get_mut(&src_surface_id) else {
            return;
        };
        let sw = usize::from(surface.width);
        let stride = sw * 4;
        let rect_w = src_rect.right.saturating_sub(src_rect.left);
        let rect_h = src_rect.bottom.saturating_sub(src_rect.top);
        if rect_w == 0 || rect_h == 0 {
            return;
        }
        // Snapshot the source region so overlapping copies don't corrupt
        // (rare but real on scroll-up patterns).
        let mut src_copy = alloc::vec![0u8; usize::from(rect_w) * usize::from(rect_h) * 4];
        for row in 0..rect_h {
            let off = (usize::from(src_rect.top) + usize::from(row)) * stride
                + usize::from(src_rect.left) * 4;
            let dst_off = usize::from(row) * usize::from(rect_w) * 4;
            let bytes = usize::from(rect_w) * 4;
            src_copy[dst_off..dst_off + bytes]
                .copy_from_slice(&surface.pixels_rgba[off..off + bytes]);
        }
        for dp in dest_points {
            // GfxPoint16 fields are i16 — negative dest coords mean
            // (partially) off-screen. Clip to 0; off-surface portions
            // are simply not copied.
            if dp.x < 0 || dp.y < 0 {
                continue;
            }
            let dl = dp.x as u16;
            let dt = dp.y as u16;
            let dr = dl.saturating_add(rect_w).min(surface.width);
            let db = dt.saturating_add(rect_h).min(surface.height);
            if dl >= dr || dt >= db {
                continue;
            }
            for row in 0..(db - dt) {
                let dst_off = (usize::from(dt) + usize::from(row)) * stride
                    + usize::from(dl) * 4;
                let src_off = usize::from(row) * usize::from(rect_w) * 4;
                let bytes = usize::from(dr - dl) * 4;
                surface.pixels_rgba[dst_off..dst_off + bytes]
                    .copy_from_slice(&src_copy[src_off..src_off + bytes]);
            }
            surface.mark_dirty(dl, dt, dr, db);
        }
    }

    fn on_surface_to_cache(
        &mut self,
        surface_id: u16,
        cache_key: u64,
        cache_slot: u16,
        src_rect: GfxRect16,
    ) {
        log::info!(
            "[DIAG-egfx] on_surface_to_cache id={surface_id} slot={cache_slot} key=0x{cache_key:016x} rect=({},{},{},{})",
            src_rect.left, src_rect.top, src_rect.right, src_rect.bottom
        );
        // PRD #35 Module B: extract the src_rect region of the surface's
        // top-down RGBA buffer and stash it as a `CachedTile`. `cache_key`
        // is a server-side hash we don't need to validate — the server
        // owns lookup semantics.
        let Some(surface) = self.surfaces.get(&surface_id) else {
            return;
        };
        let l = src_rect.left.min(surface.width);
        let t = src_rect.top.min(surface.height);
        let r = src_rect.right.min(surface.width);
        let b = src_rect.bottom.min(surface.height);
        if l >= r || t >= b {
            return;
        }
        let w = r - l;
        let h = b - t;
        let src_stride = usize::from(surface.width) * 4;
        let tile_stride = usize::from(w) * 4;
        let mut pixels_rgba = Vec::with_capacity(tile_stride * usize::from(h));
        for row in t..b {
            let row_off = usize::from(row) * src_stride + usize::from(l) * 4;
            pixels_rgba.extend_from_slice(&surface.pixels_rgba[row_off..row_off + tile_stride]);
        }
        let _ = cache_key;
        self.cache.insert(
            cache_slot,
            cache::CachedTile { width: w, height: h, pixels_rgba },
        );
    }

    fn on_cache_to_surface(
        &mut self,
        cache_slot: u16,
        surface_id: u16,
        dest_points: &[GfxPoint16],
    ) {
        log::info!(
            "[DIAG-egfx] on_cache_to_surface slot={cache_slot} dst_id={surface_id} dst_n={}",
            dest_points.len()
        );
        // PRD #35 Module B: look up the slot, then composite the tile
        // onto the destination surface at each dest point (top-left
        // origin). Out-of-bounds dest points are clipped against the
        // surface dimensions — matches `on_solid_fill`'s edge handling.
        let Some(tile) = self.cache.get(cache_slot).cloned() else {
            return; // slot was empty or evicted; server side may retry
        };
        let Some(surface) = self.surfaces.get_mut(&surface_id) else {
            return;
        };
        let dst_stride = usize::from(surface.width) * 4;
        let tile_stride = usize::from(tile.width) * 4;
        for point in dest_points {
            // GfxPoint16 carries signed coords; negative values clip to
            // the surface left/top edge per MS-RDPEGFX 2.2.2.14 dest
            // semantics.
            let l: u16 = if point.x <= 0 { 0 } else { (point.x as u16).min(surface.width) };
            let t: u16 = if point.y <= 0 { 0 } else { (point.y as u16).min(surface.height) };
            let r = l.saturating_add(tile.width).min(surface.width);
            let b = t.saturating_add(tile.height).min(surface.height);
            if l >= r || t >= b {
                continue;
            }
            let copy_w = r - l;
            for row in 0..(b - t) {
                let dst_off = (usize::from(t) + usize::from(row)) * dst_stride + usize::from(l) * 4;
                let src_off = usize::from(row) * tile_stride;
                let dst_end = dst_off + usize::from(copy_w) * 4;
                let src_end = src_off + usize::from(copy_w) * 4;
                surface.pixels_rgba[dst_off..dst_end]
                    .copy_from_slice(&tile.pixels_rgba[src_off..src_end]);
            }
            surface.mark_dirty(l, t, r, b);
        }
    }

    fn on_evict_cache_entry(&mut self, cache_slot: u16) {
        log::info!("[DIAG-egfx] on_evict_cache_entry slot={cache_slot}");
        self.cache.evict(cache_slot);
    }

    fn on_start_frame(&mut self, frame_id: u32, _timestamp: u32) {
        log::info!("[DIAG-egfx] on_start_frame fid={frame_id}");
    }

    fn on_end_frame(&mut self, frame_id: u32) -> Option<u32> {
        log::info!("[DIAG-egfx] on_end_frame fid={frame_id}");
        for surface in self.surfaces.values_mut() {
            let Some((dl, dt, dr, db)) = surface.dirty_rect.take() else {
                continue;
            };
            let Some((ox, oy)) = surface.output_origin else {
                continue;
            };
            // Output origin is u32 per the trait; clip to u16 range
            // since FrameSink::blit_rgba operates in desktop u16 coords.
            let (Ok(ox), Ok(oy)) = (u16::try_from(ox), u16::try_from(oy)) else {
                continue;
            };
            // Extract the dirty sub-rect from the surface's RGBA buffer
            // — only those pixels go to the sink, so untouched regions
            // (especially fast-path Bitmap pixels already on the canvas)
            // are NOT overwritten with our zero-init surface buffer.
            let rect_w = dr - dl;
            let rect_h = db - dt;
            let stride = usize::from(surface.width) * 4;
            let mut tile = alloc::vec![0u8; usize::from(rect_w) * usize::from(rect_h) * 4];
            for row in 0..rect_h {
                let src_row = (usize::from(dt) + usize::from(row)) * stride
                    + usize::from(dl) * 4;
                let dst_row = usize::from(row) * usize::from(rect_w) * 4;
                let row_bytes = usize::from(rect_w) * 4;
                tile[dst_row..dst_row + row_bytes]
                    .copy_from_slice(&surface.pixels_rgba[src_row..src_row + row_bytes]);
            }
            self.sink
                .blit_rgba(ox + dl, oy + dt, rect_w, rect_h, &tile);
        }
        // Default: ack with queue depth 0 (no backpressure signal).
        Some(0)
    }
}

/// Composite raw BGR pixel bytes (3 bytes/pixel, no alpha) into the
/// surface's RGBA buffer at `dest_rect`. Per-pixel BGR→RGB swap with
/// alpha forced to `0xFF`. Used by the ClearCodec dispatch arm — its
/// decoder produces `width*height*3` bytes of BGR pixels.
fn composite_bgr_to_rgba(
    surface: &mut SurfaceState,
    dest_rect: GfxRect16,
    bgr: &[u8],
) {
    let rect_w = dest_rect.right.saturating_sub(dest_rect.left);
    let rect_h = dest_rect.bottom.saturating_sub(dest_rect.top);
    if rect_w == 0 || rect_h == 0 {
        return;
    }
    let stride = usize::from(surface.width) * 4;
    for row in 0..rect_h {
        let src_row_off = usize::from(row) * usize::from(rect_w) * 3;
        let dst_y = usize::from(dest_rect.top) + usize::from(row);
        if dst_y >= usize::from(surface.height) {
            break;
        }
        let dst_row_off = dst_y * stride + usize::from(dest_rect.left) * 4;
        for col in 0..rect_w {
            let src_off = src_row_off + usize::from(col) * 3;
            let dst_off = dst_row_off + usize::from(col) * 4;
            if src_off + 3 > bgr.len() {
                break;
            }
            if dst_off + 4 > surface.pixels_rgba.len() {
                break;
            }
            // BGR (3 bytes) → RGBA: B/G/R bytes swap into R/G/B + alpha 0xFF.
            surface.pixels_rgba[dst_off] = bgr[src_off + 2];
            surface.pixels_rgba[dst_off + 1] = bgr[src_off + 1];
            surface.pixels_rgba[dst_off + 2] = bgr[src_off];
            surface.pixels_rgba[dst_off + 3] = 0xFF;
        }
    }
    surface.mark_dirty(dest_rect.left, dest_rect.top, dest_rect.right, dest_rect.bottom);
}

/// Composite raw BGRA pixel bytes into the surface's RGBA buffer at
/// `dest_rect`. Per-pixel BGRA→RGBA swap (byte 0 ↔ byte 2). Out-of-range
/// rectangles are clipped silently.
fn composite_uncompressed_bgra_to_rgba(
    surface: &mut SurfaceState,
    dest_rect: GfxRect16,
    bitmap_data: &[u8],
) {
    let rect_w = dest_rect.right.saturating_sub(dest_rect.left);
    let rect_h = dest_rect.bottom.saturating_sub(dest_rect.top);
    if rect_w == 0 || rect_h == 0 {
        return;
    }

    let stride = usize::from(surface.width) * 4;
    for row in 0..rect_h {
        let src_row_off = usize::from(row) * usize::from(rect_w) * 4;
        let dst_y = usize::from(dest_rect.top) + usize::from(row);
        if dst_y >= usize::from(surface.height) {
            break;
        }
        let dst_row_off = dst_y * stride + usize::from(dest_rect.left) * 4;
        for col in 0..rect_w {
            let src_off = src_row_off + usize::from(col) * 4;
            let dst_off = dst_row_off + usize::from(col) * 4;
            if src_off + 4 > bitmap_data.len() {
                break;
            }
            if dst_off + 4 > surface.pixels_rgba.len() {
                break;
            }
            // BGRA → RGBA
            surface.pixels_rgba[dst_off] = bitmap_data[src_off + 2];
            surface.pixels_rgba[dst_off + 1] = bitmap_data[src_off + 1];
            surface.pixels_rgba[dst_off + 2] = bitmap_data[src_off];
            surface.pixels_rgba[dst_off + 3] = bitmap_data[src_off + 3];
        }
    }
    surface.mark_dirty(dest_rect.left, dest_rect.top, dest_rect.right, dest_rect.bottom);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Test-only sink that records every `blit_rgba` call as a tuple.
    #[derive(Default)]
    struct CaptureSink {
        blits: Vec<(u16, u16, u16, u16, Vec<u8>)>,
    }

    impl FrameSink for CaptureSink {
        fn blit_rgba(
            &mut self,
            dest_left: u16,
            dest_top: u16,
            width: u16,
            height: u16,
            pixels_rgba: &[u8],
        ) {
            self.blits
                .push((dest_left, dest_top, width, height, pixels_rgba.to_vec()));
        }
    }

    fn one_pixel_bgra() -> Vec<u8> {
        vec![0x10, 0x20, 0x30, 0xFF]
    }

    fn full_surface_bgra(pixel: &[u8], w: usize, h: usize) -> Vec<u8> {
        pixel.iter().copied().cycle().take(w * h * 4).collect()
    }

    /// PRD #35 Module B (renderer cache wire-up): end-to-end roundtrip.
    /// Paint a known colour into a source surface, snapshot it to a cache
    /// slot via `on_surface_to_cache`, then blit from that slot onto a
    /// different destination surface via `on_cache_to_surface`. The
    /// destination's frame must carry the source colour. Verifies the
    /// public renderer contract (frame sink output), not the internal
    /// cache field.
    #[test]
    fn cache_roundtrip_solid_fill_then_cache_to_other_surface() {
        let mut renderer = GfxRenderer::new(CaptureSink::default());

        // Source: 4×4 at desktop origin (0,0), filled solid red.
        renderer.on_create_surface(1, 4, 4, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(1, 0, 0);
        renderer.on_solid_fill(
            1,
            GfxColor32 { r: 0xFF, g: 0x00, b: 0x00, xa: 0xFF },
            &[GfxRect16 { left: 0, top: 0, right: 4, bottom: 4 }],
        );
        renderer.on_surface_to_cache(
            1,
            0xDEAD_BEEF,
            7,
            GfxRect16 { left: 0, top: 0, right: 4, bottom: 4 },
        );

        // Destination: 4×4 at desktop origin (10,0), initially empty.
        renderer.on_create_surface(2, 4, 4, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(2, 10, 0);
        renderer.on_cache_to_surface(7, 2, &[GfxPoint16 { x: 0, y: 0 }]);
        renderer.on_end_frame(1);

        let sink = renderer.sink();
        let dest_blits: Vec<_> = sink
            .blits
            .iter()
            .filter(|(l, _, _, _, _)| *l == 10)
            .collect();
        assert_eq!(
            dest_blits.len(),
            1,
            "cache_to_surface must produce one blit at the destination's mapped origin"
        );
        let (_, _, _, _, pixels) = dest_blits[0];
        assert_eq!(
            &pixels[0..4],
            &[0xFF, 0x00, 0x00, 0xFF],
            "first pixel at destination must be the cached red (RGBA)"
        );
    }

    /// PRD #35 Module B: after `EvictCacheEntry`, a subsequent
    /// `CacheToSurface` for the same slot must produce no blit. The
    /// server can issue evict before reusing a slot (and may even race
    /// an in-flight cache lookup); the client honours the evict.
    #[test]
    fn cache_evict_then_cache_to_surface_is_silent() {
        let mut renderer = GfxRenderer::new(CaptureSink::default());

        renderer.on_create_surface(1, 4, 4, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(1, 0, 0);
        renderer.on_solid_fill(
            1,
            GfxColor32 { r: 0x00, g: 0xFF, b: 0x00, xa: 0xFF },
            &[GfxRect16 { left: 0, top: 0, right: 4, bottom: 4 }],
        );
        renderer.on_surface_to_cache(
            1,
            0xCAFE_BABE,
            9,
            GfxRect16 { left: 0, top: 0, right: 4, bottom: 4 },
        );
        renderer.on_evict_cache_entry(9);

        // Destination surface at (20, 0). Without the evict, the cached
        // green tile would land here; with the evict, the cache_to_surface
        // is a silent no-op and the destination stays clean.
        renderer.on_create_surface(2, 4, 4, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(2, 20, 0);
        renderer.on_cache_to_surface(9, 2, &[GfxPoint16 { x: 0, y: 0 }]);
        renderer.on_end_frame(1);

        let sink = renderer.sink();
        let dest_blits: Vec<_> = sink
            .blits
            .iter()
            .filter(|(l, _, _, _, _)| *l == 20)
            .collect();
        assert!(
            dest_blits.is_empty(),
            "evicted slot must not produce a blit at the destination, got {} blits",
            dest_blits.len()
        );
    }

    /// PRD #35 Module B (cache slice): the cache module's core contract.
    /// An inserted tile is retrievable bit-for-bit through the trait's
    /// public interface; evicting a slot makes it unfindable. Tests
    /// behaviour, not internal storage: the trait could be backed by a
    /// HashMap, an LRU, a slab — none of that should be observable.
    #[test]
    fn gfx_cache_insert_get_evict_roundtrip() {
        use super::cache::{CachedTile, GfxCache, InMemoryGfxCache};
        let mut cache = InMemoryGfxCache::new();
        let tile = CachedTile {
            width: 4,
            height: 4,
            pixels_rgba: vec![0xAB; 4 * 4 * 4],
        };
        cache.insert(7, tile.clone());
        let got = cache.get(7).expect("inserted slot must be retrievable");
        assert_eq!(got.width, tile.width);
        assert_eq!(got.height, tile.height);
        assert_eq!(got.pixels_rgba, tile.pixels_rgba);

        cache.evict(7);
        assert!(cache.get(7).is_none(), "evicted slot must be gone");
    }

    /// ClearCodec (codec_id 0x0008): a minimum-valid 14-byte all-zero
    /// header decodes to a zero-pixel BGR buffer, which the adapter
    /// must convert to RGBA with alpha 0xFF and blit at the mapped
    /// surface origin. This pins the `BGR → RGBA + alpha=0xFF` byte
    /// conversion at the dispatch boundary.
    ///
    /// 14 bytes = flags(1) + seq(1) + residual_count(4) + bands_count(4)
    /// + subcodec_count(4); all zero so no per-component decoders run.
    /// Per `justrdp_graphics::clearcodec` this returns `width*height*3`
    /// bytes of zeros.
    #[test]
    fn clearcodec_zero_header_blits_zero_rgba_with_alpha_one() {
        let mut renderer = GfxRenderer::new(CaptureSink::default());

        renderer.on_create_surface(8, 2, 2, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(8, 5, 5);

        let zero_clearcodec = vec![0u8; 14];
        renderer.on_wire_to_surface_1(
            8,
            0x0008, // RDPGFX_CODECID_CLEARCODEC
            GfxPixelFormat::ARGB_8888,
            GfxRect16 { left: 0, top: 0, right: 2, bottom: 2 },
            &zero_clearcodec,
        );
        renderer.on_end_frame(1);

        let sink = renderer.sink();
        assert_eq!(sink.blits.len(), 1, "ClearCodec dispatch must produce one blit");
        let (x, y, w, h, pixels) = &sink.blits[0];
        assert_eq!((*x, *y, *w, *h), (5, 5, 2, 2));
        // 4 pixels × 4 bytes RGBA = 16 bytes. Each pixel: R=0, G=0, B=0, A=0xFF.
        let expected: Vec<u8> = vec![0, 0, 0, 0xFF].repeat(4);
        assert_eq!(pixels, &expected);
    }

    /// `MutexFrameSink` forwards every `blit_rgba` call to the inner
    /// sink behind the shared `Arc<Mutex<...>>`. Two clones writing to
    /// the same inner sink see merged blits — the contract that lets
    /// the EGFX SVC pump and `run_session` share one canvas.
    #[test]
    fn mutex_frame_sink_forwards_blits_to_shared_inner() {
        let inner = Arc::new(Mutex::new(CaptureSink::default()));
        let mut a = MutexFrameSink::new(inner.clone());
        let mut b = MutexFrameSink::new(inner.clone());

        a.blit_rgba(1, 2, 3, 4, &[0xAA; 48]);
        b.blit_rgba(10, 20, 30, 40, &[0xBB; 4800]);

        let captured = inner.lock().unwrap();
        assert_eq!(captured.blits.len(), 2, "both clones write to same sink");
        assert_eq!(captured.blits[0].0, 1);
        assert_eq!(captured.blits[1].0, 10);
    }

    /// Tracer-bullet: full data flow through the adapter for the simplest
    /// possible codec (Uncompressed = 0x0000). Proves create_surface +
    /// map_surface_to_output + on_wire_to_surface_1 + on_end_frame
    /// produces a `blit_rgba` at the mapped origin with BGRA→RGBA byte
    /// swap applied.
    #[test]
    fn uncompressed_full_surface_blits_at_mapped_origin_after_end_frame() {
        let mut renderer = GfxRenderer::new(CaptureSink::default());

        renderer.on_create_surface(1, 64, 64, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(1, 10, 20);

        // 64×64 uniform BGRA pixel: B=0x10, G=0x20, R=0x30, A=0xFF.
        let bgra: Vec<u8> = vec![0x10, 0x20, 0x30, 0xFF].repeat(64 * 64);
        renderer.on_wire_to_surface_1(
            1,
            0x0000, // RDPGFX_CODECID_UNCOMPRESSED
            GfxPixelFormat::ARGB_8888,
            GfxRect16 { left: 0, top: 0, right: 64, bottom: 64 },
            &bgra,
        );

        let ack = renderer.on_end_frame(1);
        assert_eq!(ack, Some(0), "end_frame must ack with queue depth 0");

        let sink = renderer.sink();
        assert_eq!(sink.blits.len(), 1, "exactly one blit expected");
        let (x, y, w, h, pixels) = &sink.blits[0];
        assert_eq!((*x, *y, *w, *h), (10, 20, 64, 64));
        assert_eq!(pixels.len(), 64 * 64 * 4);
        // Each RGBA pixel is the BGRA input with bytes 0↔2 swapped.
        let expected: Vec<u8> = vec![0x30, 0x20, 0x10, 0xFF].repeat(64 * 64);
        assert_eq!(pixels, &expected);
    }

    /// `dest_rect` selects the destination sub-region inside the surface.
    /// Only pixels inside the rect are dirty; `on_end_frame` blits ONLY
    /// the dirty sub-rect (offset to its mapped origin) — never the
    /// untouched surface area, which would otherwise overwrite fast-path
    /// Bitmap pixels already on the canvas with our zero-init buffer.
    #[test]
    fn wire_to_surface_1_blits_only_dirty_dest_rect_at_mapped_origin() {
        let mut renderer = GfxRenderer::new(CaptureSink::default());

        renderer.on_create_surface(1, 64, 64, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(1, 100, 200);

        // 32×32 region of pure red (BGRA: B=0, G=0, R=0xFF, A=0xFF).
        let red_bgra: Vec<u8> = vec![0x00, 0x00, 0xFF, 0xFF].repeat(32 * 32);
        renderer.on_wire_to_surface_1(
            1,
            0x0000,
            GfxPixelFormat::ARGB_8888,
            GfxRect16 { left: 16, top: 16, right: 48, bottom: 48 },
            &red_bgra,
        );
        renderer.on_end_frame(1);

        let sink = renderer.sink();
        assert_eq!(sink.blits.len(), 1);
        let (x, y, w, h, pixels) = &sink.blits[0];
        // Blit lands at (mapped_origin + dest_rect.left, mapped_origin + dest_rect.top)
        // and is exactly the dest_rect size — NOT the full 64×64 surface.
        assert_eq!((*x, *y, *w, *h), (100 + 16, 200 + 16, 32, 32));
        // 32 × 32 × 4 RGBA = 4096 bytes (every pixel = swapped red).
        let expected: Vec<u8> = vec![0xFF, 0x00, 0x00, 0xFF].repeat(32 * 32);
        assert_eq!(pixels, &expected);
    }

    use justrdp_graphics::avc::{AvcDecoder, AvcError, Yuv420Frame};

    #[derive(Default)]
    struct RecordedCalls {
        chunks: Vec<Vec<u8>>,
    }

    /// Mock `AvcDecoder` that records every byte slice it sees. Uses
    /// `Arc<Mutex<...>>` so the mock is naturally `Send`-safe (the
    /// `AvcDecoder` trait requires `Send`); single-threaded tests still
    /// work because `Mutex::lock` succeeds on uncontended mutexes.
    struct RecordingDecoder {
        calls: Arc<Mutex<RecordedCalls>>,
    }

    impl AvcDecoder for RecordingDecoder {
        fn decode_frame(&mut self, annex_b: &[u8]) -> Result<Option<Yuv420Frame>, AvcError> {
            self.calls.lock().unwrap().chunks.push(annex_b.to_vec());
            Ok(None) // mock — no actual decode
        }
    }

    /// PRD #35 Module B: AVC420 payloads carry an envelope before the
    /// H.264 bitstream. MS-RDPEGFX 2.2.4.4 RDPGFX_AVC420_BITMAP_STREAM
    /// is `numRegionRects(u32) + regionRects[N×8] + quantQualityVals[N×2]
    /// + avc420EncodedBitstream`. The renderer must parse the envelope
    /// and pass only the inner Annex B bytes to the registered
    /// `AvcDecoder`. Earlier behaviour passed the entire wire payload
    /// verbatim, which the decoder would misinterpret as garbage NALU
    /// prefix.
    #[test]
    fn avc420_unwraps_envelope_and_passes_inner_annex_b() {
        let calls = Arc::new(Mutex::new(RecordedCalls::default()));
        let mut renderer = GfxRenderer::new(CaptureSink::default());
        renderer.set_avc_decoder(alloc::boxed::Box::new(RecordingDecoder {
            calls: calls.clone(),
        }));

        renderer.on_create_surface(4, 16, 16, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(4, 0, 0);

        let annex_b: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42];
        let mut envelope: Vec<u8> = Vec::new();
        envelope.extend_from_slice(&1u32.to_le_bytes()); // numRegionRects = 1
        // regionRect: left=0 top=0 right=16 bottom=16 (8 bytes)
        envelope.extend_from_slice(&0u16.to_le_bytes());
        envelope.extend_from_slice(&0u16.to_le_bytes());
        envelope.extend_from_slice(&16u16.to_le_bytes());
        envelope.extend_from_slice(&16u16.to_le_bytes());
        // quantQualityVal: qpVal=30 qualityVal=100 (2 bytes)
        envelope.push(30);
        envelope.push(100);
        envelope.extend_from_slice(&annex_b);

        renderer.on_wire_to_surface_1(
            4,
            0x000B, // RDPGFX_CODECID_AVC420
            GfxPixelFormat::ARGB_8888,
            GfxRect16 { left: 0, top: 0, right: 16, bottom: 16 },
            &envelope,
        );

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.chunks.len(), 1, "decoder must be called once");
        assert_eq!(
            recorded.chunks[0], annex_b,
            "decoder must receive the inner Annex B stream, envelope stripped"
        );
    }

    /// PRD #35 Module B: AVC444V2 (codec_id 0x000F) and AVC444 (0x000E)
    /// wrap one or two AVC420 sub-streams. MS-RDPEGFX 2.2.4.5 layout:
    /// `cbAvc420EncodedBitstream1(u32 with LC in low bits) +
    /// avc420EncodedBitstream1(stream1) [+ avc420EncodedBitstream2]`.
    /// Only the inner H.264 Annex B bytes of stream1 should reach the
    /// decoder for this slice; stream2 (auxiliary view) is a follow-up.
    #[test]
    fn avc444_unwraps_outer_then_inner_envelope_to_decoder() {
        let calls = Arc::new(Mutex::new(RecordedCalls::default()));
        let mut renderer = GfxRenderer::new(CaptureSink::default());
        renderer.set_avc_decoder(alloc::boxed::Box::new(RecordingDecoder {
            calls: calls.clone(),
        }));

        renderer.on_create_surface(5, 16, 16, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(5, 0, 0);

        let annex_b: Vec<u8> = vec![0xCA, 0xFE, 0xBA, 0xBE];

        // Inner AVC420 envelope (1 region rect + 1 QQ + annex_b).
        let mut inner: Vec<u8> = Vec::new();
        inner.extend_from_slice(&1u32.to_le_bytes());
        inner.extend_from_slice(&0u16.to_le_bytes());
        inner.extend_from_slice(&0u16.to_le_bytes());
        inner.extend_from_slice(&16u16.to_le_bytes());
        inner.extend_from_slice(&16u16.to_le_bytes());
        inner.push(20);
        inner.push(80);
        inner.extend_from_slice(&annex_b);

        // Outer AVC444 envelope: cbAvc420EncodedBitstream1 packs
        // 30-bit length + 2-bit LC (luma+chroma=1 → bit 0 set).
        let outer_len_lc = ((inner.len() as u32) << 2) | 0b01;
        let mut envelope: Vec<u8> = Vec::new();
        envelope.extend_from_slice(&outer_len_lc.to_le_bytes());
        envelope.extend_from_slice(&inner);

        renderer.on_wire_to_surface_1(
            5,
            0x000E, // RDPGFX_CODECID_AVC444
            GfxPixelFormat::ARGB_8888,
            GfxRect16 { left: 0, top: 0, right: 16, bottom: 16 },
            &envelope,
        );

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.chunks.len(), 1, "decoder must be called once for stream1");
        assert_eq!(
            recorded.chunks[0], annex_b,
            "decoder must receive inner Annex B, both envelopes stripped"
        );
    }

    /// `on_reset_graphics` discards the entire surface map. After reset,
    /// writes to any previously-created surface_id must drop silently.
    #[test]
    fn reset_graphics_clears_all_surfaces() {
        let mut renderer = GfxRenderer::new(CaptureSink::default());

        renderer.on_create_surface(3, 16, 16, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(3, 0, 0);
        renderer.on_reset_graphics(1024, 768, &[]);

        let bgra = full_surface_bgra(&one_pixel_bgra(), 16, 16);
        renderer.on_wire_to_surface_1(
            3,
            0x0000,
            GfxPixelFormat::ARGB_8888,
            GfxRect16 { left: 0, top: 0, right: 16, bottom: 16 },
            &bgra,
        );
        renderer.on_end_frame(1);

        assert!(
            renderer.sink().blits.is_empty(),
            "reset_graphics must purge the surface map; subsequent writes drop"
        );
    }

    /// An unimplemented codec (ClearCodec=0x0008 in #28's scope) must
    /// drop the payload without panic and without dirtying the surface
    /// — otherwise `on_end_frame` would emit a stale/zero blit and the
    /// remote desktop would flash blank rectangles.
    #[test]
    fn unknown_codec_drops_silently_and_emits_no_blit() {
        let mut renderer = GfxRenderer::new(CaptureSink::default());

        renderer.on_create_surface(2, 32, 32, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(2, 100, 200);

        // Arbitrary garbage bytes — adapter must not interpret them
        // since codec_id 0x0008 (ClearCodec) has no decoder yet.
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFA, 0xCE, 0xCA, 0xFE];
        renderer.on_wire_to_surface_1(
            2,
            0x0008, // RDPGFX_CODECID_CLEARCODEC — no decoder wired in #28
            GfxPixelFormat::ARGB_8888,
            GfxRect16 { left: 0, top: 0, right: 32, bottom: 32 },
            &garbage,
        );
        renderer.on_end_frame(1);

        assert!(
            renderer.sink().blits.is_empty(),
            "unknown codec must produce no blit (surface stays clean)"
        );
    }

    /// After `on_delete_surface`, subsequent writes to the same surface_id
    /// must drop silently (no panic, no blit on next end_frame).
    #[test]
    fn write_to_deleted_surface_emits_no_blit() {
        let mut renderer = GfxRenderer::new(CaptureSink::default());

        renderer.on_create_surface(7, 32, 32, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(7, 0, 0);
        renderer.on_delete_surface(7);

        let bgra = full_surface_bgra(&one_pixel_bgra(), 32, 32);
        renderer.on_wire_to_surface_1(
            7,
            0x0000,
            GfxPixelFormat::ARGB_8888,
            GfxRect16 { left: 0, top: 0, right: 32, bottom: 32 },
            &bgra,
        );
        renderer.on_end_frame(1);

        assert!(
            renderer.sink().blits.is_empty(),
            "writes to a deleted surface must produce no blits"
        );
    }
}
