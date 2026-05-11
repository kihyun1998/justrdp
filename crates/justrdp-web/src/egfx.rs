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
use justrdp_egfx::{GfxColor32, GfxHandler, GfxMonitorDef, GfxPixelFormat, GfxRect16};
use justrdp_graphics::avc::AvcDecoder;

use crate::render::FrameSink;

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
    /// Set on each composite into the surface; cleared after the next
    /// `on_end_frame` blits the surface to the sink.
    dirty: bool,
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
}

impl<S: FrameSink + Send + 'static> GfxRenderer<S> {
    /// Create a new adapter wrapping the given sink.
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            surfaces: BTreeMap::new(),
            avc_decoder: None,
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
        let pixels_rgba = alloc::vec![0u8; usize::from(width) * usize::from(height) * 4];
        self.surfaces.insert(
            surface_id,
            SurfaceState {
                width,
                height,
                output_origin: None,
                pixels_rgba,
                dirty: false,
            },
        );
    }

    fn on_delete_surface(&mut self, surface_id: u16) {
        self.surfaces.remove(&surface_id);
    }

    fn on_map_surface_to_output(
        &mut self,
        surface_id: u16,
        output_origin_x: u32,
        output_origin_y: u32,
    ) {
        if let Some(s) = self.surfaces.get_mut(&surface_id) {
            s.output_origin = Some((output_origin_x, output_origin_y));
        }
    }

    fn on_reset_graphics(
        &mut self,
        _width: u32,
        _height: u32,
        _monitors: &[GfxMonitorDef],
    ) {
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
            // AVC420 / AVC444 / AVC444V2 — feed the raw bitmap_data to
            // the registered AvcDecoder. The decoder is responsible for
            // unwrapping the EGFX AVC envelope (RDPGFX_AVC420_BITMAP_STREAM
            // or _AVC444_) before invoking its H.264 backend; PRD #28's
            // scope is the dispatch boundary, not envelope parsing.
            // Without a registered decoder, AVC payloads drop silently.
            0x000B | 0x000E | 0x000F => {
                if let Some(decoder) = self.avc_decoder.as_mut() {
                    let _ = decoder.decode_frame(bitmap_data);
                    let _ = surface; // YUV→RGBA composite is a follow-up cycle
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
        _surface_id: u16,
        _fill_color: GfxColor32,
        _rectangles: &[GfxRect16],
    ) {
        // Out of scope for #28.
    }

    fn on_start_frame(&mut self, _frame_id: u32, _timestamp: u32) {}

    fn on_end_frame(&mut self, _frame_id: u32) -> Option<u32> {
        for surface in self.surfaces.values_mut() {
            if !surface.dirty {
                continue;
            }
            let Some((ox, oy)) = surface.output_origin else {
                surface.dirty = false;
                continue;
            };
            // Output origin is u32 per the trait; FrameSink::blit_rgba
            // takes u16 so out-of-range origins skip silently.
            let (Ok(ox), Ok(oy)) = (u16::try_from(ox), u16::try_from(oy)) else {
                surface.dirty = false;
                continue;
            };
            self.sink
                .blit_rgba(ox, oy, surface.width, surface.height, &surface.pixels_rgba);
            surface.dirty = false;
        }
        // Default: ack with queue depth 0 (no backpressure signal).
        Some(0)
    }
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
    surface.dirty = true;
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
    /// Pixels outside the rect must remain the surface's prior content
    /// (zero in this test); pixels inside must be the BGRA→RGBA-swapped
    /// `bitmap_data`.
    #[test]
    fn wire_to_surface_1_composites_only_inside_dest_rect() {
        let mut renderer = GfxRenderer::new(CaptureSink::default());

        renderer.on_create_surface(1, 64, 64, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(1, 0, 0);

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
        let pixels = &sink.blits[0].4;
        assert_eq!(pixels.len(), 64 * 64 * 4);

        // Pixel (0, 0) — outside the rect — must still be zero.
        let p_corner = &pixels[0..4];
        assert_eq!(p_corner, &[0, 0, 0, 0], "corner pixel must remain unwritten");

        // Pixel (32, 32) — inside the rect — must be the swapped red.
        let center_off = (32 * 64 + 32) * 4;
        let p_center = &pixels[center_off..center_off + 4];
        assert_eq!(
            p_center,
            &[0xFF, 0x00, 0x00, 0xFF],
            "center pixel must be RGBA red after BGRA swap"
        );

        // Pixel (15, 15) — just outside top-left of rect — must remain zero.
        let just_outside_off = (15 * 64 + 15) * 4;
        assert_eq!(&pixels[just_outside_off..just_outside_off + 4], &[0, 0, 0, 0]);
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

    /// AVC420 (codec_id 0x000B) payloads must reach the registered
    /// `AvcDecoder` byte-identical. Without a registered decoder, the
    /// payload drops silently (verified separately in `unknown_codec_*`).
    #[test]
    fn avc420_routes_to_registered_avc_decoder() {
        let calls = Arc::new(Mutex::new(RecordedCalls::default()));
        let mut renderer = GfxRenderer::new(CaptureSink::default());
        renderer.set_avc_decoder(alloc::boxed::Box::new(RecordingDecoder {
            calls: calls.clone(),
        }));

        renderer.on_create_surface(4, 16, 16, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(4, 0, 0);

        let nal = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42]; // arbitrary "Annex B" prefix
        renderer.on_wire_to_surface_1(
            4,
            0x000B, // RDPGFX_CODECID_AVC420
            GfxPixelFormat::ARGB_8888,
            GfxRect16 { left: 0, top: 0, right: 16, bottom: 16 },
            &nal,
        );

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.chunks.len(), 1, "decoder must be called once");
        assert_eq!(recorded.chunks[0], nal, "decoder must receive bytes verbatim");
    }

    /// AVC444 (codec_id 0x000E) shares the same decoder slot as AVC420
    /// — both H.264 — so a registered decoder must be invoked for both.
    #[test]
    fn avc444_routes_to_same_avc_decoder() {
        let calls = Arc::new(Mutex::new(RecordedCalls::default()));
        let mut renderer = GfxRenderer::new(CaptureSink::default());
        renderer.set_avc_decoder(alloc::boxed::Box::new(RecordingDecoder {
            calls: calls.clone(),
        }));

        renderer.on_create_surface(5, 16, 16, GfxPixelFormat::ARGB_8888);
        renderer.on_map_surface_to_output(5, 0, 0);

        let nal = vec![0xCA, 0xFE, 0xBA, 0xBE];
        renderer.on_wire_to_surface_1(
            5,
            0x000E, // RDPGFX_CODECID_AVC444
            GfxPixelFormat::ARGB_8888,
            GfxRect16 { left: 0, top: 0, right: 16, bottom: 16 },
            &nal,
        );

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.chunks.len(), 1);
        assert_eq!(recorded.chunks[0], nal);
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
