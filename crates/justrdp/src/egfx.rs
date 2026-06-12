//! The EGFX Graphics Pipeline processor (MS-RDPEGFX) — the [`DvcProcessor`] for the
//! `Microsoft::Windows::RDS::Graphics` dynamic channel, the production graphics path this
//! project exists to unlock (the ironrdp 0x0100 gate-flag story, plan.md §0).
//!
//! justrdp **owns the surface model** (ADR-0002): the off-screen surface store, the bitmap
//! cache, the blit/fill/cache ops, and the dirty-region batching live here. The tile *codecs*
//! are phase-1 bootstrap wrappers (`justrdp-codecs::egfx`, ADR-0003): zgfx bulk
//! decompression, RemoteFX Progressive, and ClearCodec ride `ironrdp-graphics` until the
//! self-owned rewrites land. The client speaks first: `start()` sends a Caps Advertise pinned
//! to CAPVERSION_8 — the RemoteFX/Progressive/Clear/Planar era — which structurally keeps the
//! server away from AVC (H.264), for which no decoder exists yet.
//!
//! WireToSurface1 RemoteFX (`CODECID_CAVIDEO`) is logged-and-skipped: the bootstrap crate has
//! no high-level decoder for the legacy TS_RFX container and real V8 servers prefer
//! Progressive (issue #9's own hedge); it arrives with the phase-2 codec rewrites.

use crate::dvc::{DvcProcessor, ProcessorOutput};
use crate::framebuffer::FrameUpdate;
use justrdp_codecs::clearcodec::Clear;
use justrdp_codecs::color::{self, Palette};
use justrdp_codecs::egfx::{Progressive, Zgfx};
use justrdp_codecs::planar;
use justrdp_pdu::DecodeError;
use justrdp_pdu::egfx::{self, EgfxPdu, Rect16};

/// Per-axis cap on surface dimensions. The spec ceiling is 32766 (MS-RDPEGFX 2.2.2.14); real
/// surfaces track the desktop. The cap bounds a hostile CreateSurface before allocation.
const MAX_SURFACE_DIM: u16 = 16384;

/// Total RGBA bytes across all live surfaces (allocation bound, the reassembly-cap
/// precedent). A 4K desktop's primary surface is ~33 MiB; servers keep a handful.
const MAX_TOTAL_SURFACE_BYTES: usize = 256 << 20;

/// The bitmap-cache budget for CAPVERSION_8 with no SMALL_CACHE flag (MS-RDPEGFX 3.3.8.2).
const MAX_CACHE_BYTES: usize = 100 << 20;

/// Above this many dirty rectangles a frame flush collapses to one bounding box per surface
/// (bounds the per-frame output count without dropping content).
const MAX_DIRTY_RECTS: usize = 64;

/// A dirty region in surface coordinates: `(x, y, width, height)`.
type DirtyRect = (u16, u16, u16, u16);

/// One off-screen surface: an RGBA8888 top-down buffer plus its output mapping and the
/// regions touched since the last flush.
struct Surface {
    id: u16,
    width: u16,
    height: u16,
    rgba: Vec<u8>,
    /// Output-space position of the surface's (0,0), once MapSurfaceToOutput arrives.
    mapped: Option<(u32, u32)>,
    dirty: Vec<DirtyRect>,
}

impl Surface {
    fn bytes(width: u16, height: u16) -> usize {
        usize::from(width) * usize::from(height) * 4
    }

    /// Record a touched region, eagerly collapsing to one bounding box past
    /// [`MAX_DIRTY_RECTS`] — a server that delays its End Frame (or floods SolidFill rects)
    /// must not grow the list without bound (the allocation-cap discipline).
    fn mark_dirty(&mut self, rect: DirtyRect) {
        self.dirty.push(rect);
        if self.dirty.len() > MAX_DIRTY_RECTS {
            let left = self.dirty.iter().map(|r| r.0).min().unwrap_or(0);
            let top = self.dirty.iter().map(|r| r.1).min().unwrap_or(0);
            let right = self
                .dirty
                .iter()
                .map(|r| r.0.saturating_add(r.2))
                .max()
                .unwrap_or(0);
            let bottom = self
                .dirty
                .iter()
                .map(|r| r.1.saturating_add(r.3))
                .max()
                .unwrap_or(0);
            self.dirty.clear();
            self.dirty.push((left, top, right - left, bottom - top));
        }
    }

    /// Copy `src` (RGBA, `src_stride_px` pixels per row, `copy_w × copy_h`) to `(x, y)`,
    /// clipping to the surface; negative destinations clip the source accordingly.
    fn blit(&mut self, x: i32, y: i32, copy_w: u16, copy_h: u16, src: &[u8], src_stride_px: usize) {
        let skip_x = usize::try_from(-x.min(0)).unwrap_or(0);
        let skip_y = usize::try_from(-y.min(0)).unwrap_or(0);
        let dst_x = usize::try_from(x.max(0)).unwrap_or(0);
        let dst_y = usize::try_from(y.max(0)).unwrap_or(0);
        let w = usize::from(copy_w)
            .saturating_sub(skip_x)
            .min(usize::from(self.width).saturating_sub(dst_x))
            .min(src_stride_px.saturating_sub(skip_x));
        let h = usize::from(copy_h)
            .saturating_sub(skip_y)
            .min(usize::from(self.height).saturating_sub(dst_y));
        if w == 0 || h == 0 {
            return;
        }
        let stride = usize::from(self.width) * 4;
        for row in 0..h {
            let src_off = (skip_y + row) * src_stride_px * 4 + skip_x * 4;
            let Some(src_row) = src.get(src_off..src_off + w * 4) else {
                break; // short source: copy what exists
            };
            let dst_off = (dst_y + row) * stride + dst_x * 4;
            self.rgba[dst_off..dst_off + w * 4].copy_from_slice(src_row);
        }
        self.mark_dirty((dst_x as u16, dst_y as u16, w as u16, h as u16));
    }

    /// Extract a rectangle (clipped) as `(width, height, tight RGBA)`.
    fn extract(&self, x: u16, y: u16, w: u16, h: u16) -> (u16, u16, Vec<u8>) {
        let w = w.min(self.width.saturating_sub(x));
        let h = h.min(self.height.saturating_sub(y));
        let stride = usize::from(self.width) * 4;
        let mut out = Vec::with_capacity(usize::from(w) * usize::from(h) * 4);
        for row in 0..usize::from(h) {
            let off = (usize::from(y) + row) * stride + usize::from(x) * 4;
            out.extend_from_slice(&self.rgba[off..off + usize::from(w) * 4]);
        }
        (w, h, out)
    }

    /// Fill a rectangle (clipped) with one RGBA pixel.
    fn fill(&mut self, rect: Rect16, rgba: [u8; 4]) {
        let x = rect.left.min(self.width);
        let y = rect.top.min(self.height);
        let w = rect.width().min(self.width.saturating_sub(x));
        let h = rect.height().min(self.height.saturating_sub(y));
        if w == 0 || h == 0 {
            return;
        }
        let stride = usize::from(self.width) * 4;
        for row in 0..usize::from(h) {
            let off = (usize::from(y) + row) * stride + usize::from(x) * 4;
            for px in self.rgba[off..off + usize::from(w) * 4].chunks_exact_mut(4) {
                px.copy_from_slice(&rgba);
            }
        }
        self.mark_dirty((x, y, w, h));
    }
}

/// One cached bitmap (SurfaceToCache → CacheToSurface).
struct CachedBitmap {
    width: u16,
    height: u16,
    rgba: Vec<u8>,
}

/// The EGFX channel processor: transport codec state + the owned surface model.
pub(crate) struct GraphicsProcessor {
    zgfx: Zgfx,
    progressive: Progressive,
    clear: Clear,
    surfaces: Vec<Surface>,
    cache: std::collections::HashMap<u16, CachedBitmap>,
    cache_bytes: usize,
    confirmed_version: Option<u32>,
    frames_decoded: u32,
    in_frame: bool,
}

impl Default for GraphicsProcessor {
    fn default() -> Self {
        Self {
            zgfx: Zgfx::new(),
            progressive: Progressive::new(),
            clear: Clear::new(),
            surfaces: Vec::new(),
            cache: std::collections::HashMap::new(),
            cache_bytes: 0,
            confirmed_version: None,
            frames_decoded: 0,
            in_frame: false,
        }
    }
}

fn invalid(field: &'static str, reason: &'static str) -> DecodeError {
    DecodeError::InvalidField { field, reason }
}

impl GraphicsProcessor {
    fn surface_mut(&mut self, id: u16) -> Option<&mut Surface> {
        self.surfaces.iter_mut().find(|s| s.id == id)
    }

    fn total_surface_bytes(&self) -> usize {
        self.surfaces.iter().map(|s| s.rgba.len()).sum()
    }

    /// Decode one WireToSurface1 payload into top-down RGBA of the destination rectangle's
    /// size, or `None` for codecs justrdp does not decode yet (logged, skipped).
    fn decode_wts1(
        &mut self,
        codec_id: u16,
        rect: Rect16,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, DecodeError> {
        let (w, h) = (rect.width(), rect.height());
        let (uw, uh) = (usize::from(w), usize::from(h));
        match codec_id {
            egfx::CODECID_UNCOMPRESSED => {
                if data.len() < uw * uh * 4 {
                    return Err(invalid(
                        "RDPGFX_WIRE_TO_SURFACE_PDU_1",
                        "uncompressed data shorter than the destination rectangle",
                    ));
                }
                // 32bpp BGRX/BGRA, top-down (EGFX surfaces are top-down, unlike the GDI
                // legacy bottom-up of the slow path).
                let rgba = color::to_rgba(data, uw, uh, 32, &Palette::default(), false)
                    .map_err(|e| {
                        tracing::warn!(target: "rdp_egfx", error = %e, "uncompressed WTS1 conversion failed");
                        invalid("RDPGFX_WIRE_TO_SURFACE_PDU_1", "uncompressed pixel conversion failed")
                    })?;
                Ok(Some(rgba))
            }
            // Tile-codec failures below are warn-and-skip, not fatal: during the ADR-0003
            // bootstrap the decoder may simply be incomplete (proven on the real VM: the
            // oracle's ClearCodec rejects some genuine server streams). The region keeps its
            // previous content and the next repaint usually heals it; killing the session
            // over a decoder limitation would be worse than a transient hole. Protocol-level
            // failures (zgfx, PDU framing, allocation bounds) stay fatal.
            egfx::CODECID_PLANAR => {
                let Ok(bgr) = planar::decompress(data, uw, uh).map_err(|e| {
                    tracing::warn!(target: "rdp_egfx", error = %e, "planar WTS1 decode failed — region skipped");
                }) else {
                    return Ok(None);
                };
                let Ok(rgba) = color::to_rgba(&bgr, uw, uh, 24, &Palette::default(), false)
                    .map_err(|e| {
                        tracing::warn!(target: "rdp_egfx", error = %e, "planar WTS1 conversion failed — region skipped");
                    })
                else {
                    return Ok(None);
                };
                Ok(Some(rgba))
            }
            egfx::CODECID_CLEARCODEC => {
                let Ok(bgra) = self.clear.decode_to_bgra(data, w, h).map_err(|e| {
                    tracing::warn!(target: "rdp_egfx", error = %e, "ClearCodec WTS1 decode failed — region skipped");
                }) else {
                    return Ok(None);
                };
                let Ok(rgba) = color::to_rgba(&bgra, uw, uh, 32, &Palette::default(), false)
                    .map_err(|e| {
                        tracing::warn!(target: "rdp_egfx", error = %e, "ClearCodec conversion failed — region skipped");
                    })
                else {
                    return Ok(None);
                };
                Ok(Some(rgba))
            }
            // RemoteFX non-progressive: phase-2 rewrite territory (no bootstrap API; the
            // V8 test server prefers Progressive — issue #9's hedge). Skipped, not fatal.
            egfx::CODECID_CAVIDEO => {
                tracing::warn!(target: "rdp_egfx", "WTS1 RemoteFX (CAVIDEO) not decoded yet — region skipped");
                Ok(None)
            }
            other => {
                tracing::debug!(target: "rdp_egfx", codec_id = other, "unsupported WTS1 codec skipped");
                Ok(None)
            }
        }
    }

    /// Handle one decoded EGFX PDU, accumulating processor outputs.
    fn handle(
        &mut self,
        pdu: EgfxPdu<'_>,
        outputs: &mut Vec<ProcessorOutput>,
    ) -> Result<(), DecodeError> {
        match pdu {
            EgfxPdu::CapsConfirm { version, flags } => {
                tracing::info!(target: "rdp_egfx_caps", version, flags, "EGFX caps confirmed");
                self.confirmed_version = Some(version);
            }
            EgfxPdu::ResetGraphics { width, height } => {
                tracing::debug!(target: "rdp_egfx", width, height, "ResetGraphics");
                let width = u16::try_from(width).map_err(|_| {
                    invalid("RDPGFX_RESET_GRAPHICS_PDU", "output width exceeds u16")
                })?;
                let height = u16::try_from(height).map_err(|_| {
                    invalid("RDPGFX_RESET_GRAPHICS_PDU", "output height exceeds u16")
                })?;
                outputs.push(ProcessorOutput::OutputResized { width, height });
            }
            EgfxPdu::CreateSurface {
                surface_id,
                width,
                height,
                pixel_format: _,
            } => {
                if width == 0 || height == 0 || width > MAX_SURFACE_DIM || height > MAX_SURFACE_DIM
                {
                    return Err(invalid(
                        "RDPGFX_CREATE_SURFACE_PDU",
                        "surface dimensions out of bounds",
                    ));
                }
                self.surfaces.retain(|s| s.id != surface_id);
                if self.total_surface_bytes() + Surface::bytes(width, height)
                    > MAX_TOTAL_SURFACE_BYTES
                {
                    return Err(invalid(
                        "RDPGFX_CREATE_SURFACE_PDU",
                        "total surface allocation exceeds the cap",
                    ));
                }
                tracing::debug!(target: "rdp_egfx", surface_id, width, height, "CreateSurface");
                self.surfaces.push(Surface {
                    id: surface_id,
                    width,
                    height,
                    rgba: vec![0; Surface::bytes(width, height)],
                    mapped: None,
                    dirty: Vec::new(),
                });
            }
            EgfxPdu::DeleteSurface { surface_id } => {
                tracing::debug!(target: "rdp_egfx", surface_id, "DeleteSurface");
                self.surfaces.retain(|s| s.id != surface_id);
            }
            EgfxPdu::MapSurfaceToOutput {
                surface_id,
                origin_x,
                origin_y,
            } => {
                tracing::debug!(target: "rdp_egfx", surface_id, origin_x, origin_y, "MapSurfaceToOutput");
                if let Some(surface) = self.surface_mut(surface_id) {
                    surface.mapped = Some((origin_x, origin_y));
                    // Repaint the whole surface at its new position.
                    let (w, h) = (surface.width, surface.height);
                    surface.mark_dirty((0, 0, w, h));
                }
            }
            EgfxPdu::StartFrame { frame_id } => {
                tracing::trace!(target: "rdp_egfx", frame_id, "StartFrame");
                self.in_frame = true;
            }
            EgfxPdu::EndFrame { frame_id } => {
                tracing::trace!(target: "rdp_egfx", frame_id, "EndFrame");
                self.in_frame = false;
                self.frames_decoded = self.frames_decoded.wrapping_add(1);
                self.flush_dirty(outputs);
                // Raw, not segment-wrapped — client→server EGFX asymmetry, see start().
                outputs.push(ProcessorOutput::Send(egfx::encode_frame_acknowledge(
                    frame_id,
                    self.frames_decoded,
                )));
            }
            EgfxPdu::WireToSurface1 {
                surface_id,
                codec_id,
                pixel_format: _,
                dest_rect,
                data,
            } => {
                if let Some(rgba) = self.decode_wts1(codec_id, dest_rect, data)? {
                    let (w, h) = (dest_rect.width(), dest_rect.height());
                    let surface = self.surface_mut(surface_id).ok_or(invalid(
                        "RDPGFX_WIRE_TO_SURFACE_PDU_1",
                        "unknown destination surface",
                    ))?;
                    surface.blit(
                        i32::from(dest_rect.left),
                        i32::from(dest_rect.top),
                        w,
                        h,
                        &rgba,
                        usize::from(w),
                    );
                }
            }
            EgfxPdu::WireToSurface2 {
                surface_id,
                codec_id,
                codec_context_id,
                pixel_format: _,
                data,
            } => {
                if codec_id != egfx::CODECID_CAPROGRESSIVE {
                    tracing::debug!(target: "rdp_egfx", codec_id, "unsupported WTS2 codec skipped");
                    return Ok(());
                }
                let (sw, sh) = match self.surfaces.iter().find(|s| s.id == surface_id) {
                    Some(s) => (s.width, s.height),
                    None => {
                        return Err(invalid(
                            "RDPGFX_WIRE_TO_SURFACE_PDU_2",
                            "unknown destination surface",
                        ));
                    }
                };
                // Warn-and-skip on failure, like the WTS1 codecs: a bootstrap-decoder
                // limitation must not kill the session (the tile state may desync until the
                // next first-pass repaint, which servers send periodically).
                let Ok(tiles) = self.progressive.decode(codec_context_id, sw, sh, data).map_err(
                    |e| {
                        tracing::warn!(target: "rdp_egfx", error = %e, "progressive decode failed — pass skipped");
                    },
                ) else {
                    return Ok(());
                };
                // Re-fetched rather than held across the decode (borrow split with the
                // progressive decoder); a vanished surface is a skip, never a panic.
                let Some(surface) = self.surface_mut(surface_id) else {
                    return Ok(());
                };
                for tile in tiles {
                    surface.blit(
                        i32::from(tile.x_idx) * 64,
                        i32::from(tile.y_idx) * 64,
                        64,
                        64,
                        &tile.rgba,
                        64,
                    );
                }
            }
            EgfxPdu::DeleteEncodingContext {
                surface_id: _,
                codec_context_id,
            } => {
                self.progressive.delete_context(codec_context_id);
            }
            EgfxPdu::SolidFill {
                surface_id,
                color_bgrx,
                rects,
            } => {
                let rgba = [color_bgrx[2], color_bgrx[1], color_bgrx[0], 255];
                let surface = self.surface_mut(surface_id).ok_or(invalid(
                    "RDPGFX_SOLIDFILL_PDU",
                    "unknown destination surface",
                ))?;
                for rect in rects {
                    surface.fill(rect, rgba);
                }
            }
            EgfxPdu::SurfaceToSurface {
                src_surface_id,
                dest_surface_id,
                src_rect,
                dest_points,
            } => {
                let (w, h, pixels) = self
                    .surfaces
                    .iter()
                    .find(|s| s.id == src_surface_id)
                    .ok_or(invalid(
                        "RDPGFX_SURFACE_TO_SURFACE_PDU",
                        "unknown source surface",
                    ))?
                    .extract(
                        src_rect.left,
                        src_rect.top,
                        src_rect.width(),
                        src_rect.height(),
                    );
                let dest = self.surface_mut(dest_surface_id).ok_or(invalid(
                    "RDPGFX_SURFACE_TO_SURFACE_PDU",
                    "unknown destination surface",
                ))?;
                for pt in dest_points {
                    dest.blit(
                        i32::from(pt.x),
                        i32::from(pt.y),
                        w,
                        h,
                        &pixels,
                        usize::from(w),
                    );
                }
            }
            EgfxPdu::SurfaceToCache {
                surface_id,
                cache_key: _,
                cache_slot,
                src_rect,
            } => {
                let (w, h, rgba) = self
                    .surfaces
                    .iter()
                    .find(|s| s.id == surface_id)
                    .ok_or(invalid(
                        "RDPGFX_SURFACE_TO_CACHE_PDU",
                        "unknown source surface",
                    ))?
                    .extract(
                        src_rect.left,
                        src_rect.top,
                        src_rect.width(),
                        src_rect.height(),
                    );
                if let Some(old) = self.cache.remove(&cache_slot) {
                    self.cache_bytes -= old.rgba.len();
                }
                if self.cache_bytes + rgba.len() > MAX_CACHE_BYTES {
                    return Err(invalid(
                        "RDPGFX_SURFACE_TO_CACHE_PDU",
                        "bitmap cache exceeds the CAPVERSION_8 budget",
                    ));
                }
                self.cache_bytes += rgba.len();
                self.cache.insert(
                    cache_slot,
                    CachedBitmap {
                        width: w,
                        height: h,
                        rgba,
                    },
                );
            }
            EgfxPdu::CacheToSurface {
                cache_slot,
                surface_id,
                dest_points,
            } => {
                let entry = self
                    .cache
                    .get(&cache_slot)
                    .ok_or(invalid("RDPGFX_CACHE_TO_SURFACE_PDU", "unknown cache slot"))?;
                let (w, h) = (entry.width, entry.height);
                let pixels = entry.rgba.clone();
                let dest = self.surface_mut(surface_id).ok_or(invalid(
                    "RDPGFX_CACHE_TO_SURFACE_PDU",
                    "unknown destination surface",
                ))?;
                for pt in dest_points {
                    dest.blit(
                        i32::from(pt.x),
                        i32::from(pt.y),
                        w,
                        h,
                        &pixels,
                        usize::from(w),
                    );
                }
            }
            EgfxPdu::EvictCacheEntry { cache_slot } => {
                if let Some(old) = self.cache.remove(&cache_slot) {
                    self.cache_bytes -= old.rgba.len();
                }
            }
            EgfxPdu::Unknown { cmd_id } => {
                tracing::debug!(target: "rdp_egfx", cmd_id, "unknown EGFX command skipped");
            }
        }
        Ok(())
    }

    /// Emit the accumulated dirty regions of every output-mapped surface as frames.
    fn flush_dirty(&mut self, outputs: &mut Vec<ProcessorOutput>) {
        for surface in &mut self.surfaces {
            if surface.dirty.is_empty() {
                continue;
            }
            let Some((ox, oy)) = surface.mapped else {
                surface.dirty.clear(); // off-screen scratch surface: nothing to show yet
                continue;
            };
            let rects = core::mem::take(&mut surface.dirty);
            for (x, y, w, h) in rects {
                let (w, h, pixels) = {
                    let stride = usize::from(surface.width) * 4;
                    let w = w.min(surface.width.saturating_sub(x));
                    let h = h.min(surface.height.saturating_sub(y));
                    let mut out = Vec::with_capacity(usize::from(w) * usize::from(h) * 4);
                    for row in 0..usize::from(h) {
                        let off = (usize::from(y) + row) * stride + usize::from(x) * 4;
                        out.extend_from_slice(&surface.rgba[off..off + usize::from(w) * 4]);
                    }
                    (w, h, out)
                };
                if w == 0 || h == 0 {
                    continue;
                }
                // `ox`/`oy` are attacker-controlled u32s from MapSurfaceToOutput: the sum
                // must neither overflow nor exceed the addressable output.
                let (Some(out_x), Some(out_y)) = (
                    ox.checked_add(u32::from(x))
                        .and_then(|v| u16::try_from(v).ok()),
                    oy.checked_add(u32::from(y))
                        .and_then(|v| u16::try_from(v).ok()),
                ) else {
                    continue; // mapped beyond the addressable output: nothing visible
                };
                outputs.push(ProcessorOutput::Frame(FrameUpdate {
                    x: out_x,
                    y: out_y,
                    width: w,
                    height: h,
                    pixels,
                }));
            }
        }
    }
}

impl DvcProcessor for GraphicsProcessor {
    fn channel_name(&self) -> &'static str {
        egfx::CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> Vec<ProcessorOutput> {
        // Newest first, AVC structurally excluded: 10 with AVC_DISABLED, 8.1 without
        // AVC420_ENABLED, and the V8 baseline. Every confirmed version leaves the server on
        // codecs justrdp decodes (Progressive / ClearCodec / Planar / Uncompressed).
        //
        // Sent RAW: EGFX segmentation is asymmetric — only server→client traffic rides
        // RDP_SEGMENTED_DATA; a client→server PDU wrapped in a segment header gets the whole
        // connection reset (proven on the real VM: the server reads 0xE0 0x04 as a garbage
        // cmdId and kills the session; raw proceeds to Caps Confirm).
        let capsets = [
            (egfx::CAPVERSION_10, egfx::CAPS_FLAG_AVC_DISABLED),
            (egfx::CAPVERSION_8_1, 0),
            (egfx::CAPVERSION_8, 0),
        ];
        tracing::debug!(target: "rdp_egfx_caps", count = capsets.len(), "EGFX caps advertised");
        vec![ProcessorOutput::Send(egfx::encode_caps_advertise(&capsets))]
    }

    fn process(&mut self, message: &[u8]) -> Result<Vec<ProcessorOutput>, DecodeError> {
        let blob = self.zgfx.decompress(message).map_err(|e| {
            tracing::warn!(target: "rdp_egfx", error = %e, "zgfx decompression failed");
            invalid("RDP_SEGMENTED_DATA", "zgfx decompression failed")
        })?;
        let mut outputs = Vec::new();
        for pdu in egfx::decode_all(&blob)? {
            self.handle(pdu, &mut outputs)?;
        }
        if !self.in_frame {
            // Draw ops outside a Start/End Frame bracket (spec-legal, rare): show them now.
            self.flush_dirty(&mut outputs);
        }
        Ok(outputs)
    }

    fn close(&mut self) {
        *self = GraphicsProcessor::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dvc::ProcessorOutput as Out;

    fn header(cmd_id: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&cmd_id.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Feed one server EGFX PDU (uncompressed-segment wrapped, as a real server may send).
    fn feed(p: &mut GraphicsProcessor, cmd_id: u16, body: &[u8]) -> Vec<Out> {
        let message = egfx::wrap_uncompressed(&header(cmd_id, body));
        p.process(&message).unwrap()
    }

    fn create_surface(p: &mut GraphicsProcessor, id: u16, w: u16, h: u16) {
        let mut body = Vec::new();
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(&w.to_le_bytes());
        body.extend_from_slice(&h.to_le_bytes());
        body.push(egfx::PIXEL_FORMAT_XRGB_8888);
        assert!(feed(p, egfx::CMDID_CREATE_SURFACE, &body).is_empty());
    }

    fn map_surface(p: &mut GraphicsProcessor, id: u16, x: u32, y: u32) -> Vec<Out> {
        let mut body = Vec::new();
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&x.to_le_bytes());
        body.extend_from_slice(&y.to_le_bytes());
        feed(p, egfx::CMDID_MAP_SURFACE_TO_OUTPUT, &body)
    }

    fn solid_fill_body(id: u16, bgrx: [u8; 4], rect: [u16; 4]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(&bgrx);
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in rect {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body
    }

    #[test]
    fn start_advertises_caps_raw_with_avc_disabled() {
        let mut p = GraphicsProcessor::default();
        let outputs = p.start(11);
        let [Out::Send(message)] = outputs.as_slice() else {
            panic!("expected one send, got {outputs:?}");
        };
        // Raw EGFX PDU — client→server traffic is NOT segment-wrapped (real-VM-proven).
        assert_eq!(&message[..2], &egfx::CMDID_CAPS_ADVERTISE.to_le_bytes());
        assert!(
            message
                .windows(4)
                .any(|w| w == egfx::CAPVERSION_8.to_le_bytes())
        );
        assert!(
            message
                .windows(4)
                .any(|w| w == egfx::CAPVERSION_10.to_le_bytes())
        );
        // Every 10.x capset carries AVC_DISABLED (no H.264 decoder).
        let v10_at = message
            .windows(4)
            .position(|w| w == egfx::CAPVERSION_10.to_le_bytes())
            .unwrap();
        let flags = u32::from_le_bytes(message[v10_at + 8..v10_at + 12].try_into().unwrap());
        assert_eq!(flags, egfx::CAPS_FLAG_AVC_DISABLED);
    }

    #[test]
    fn caps_confirm_is_recorded() {
        let mut p = GraphicsProcessor::default();
        let mut body = Vec::new();
        body.extend_from_slice(&egfx::CAPVERSION_8.to_le_bytes());
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        assert!(feed(&mut p, egfx::CMDID_CAPS_CONFIRM, &body).is_empty());
        assert_eq!(p.confirmed_version, Some(egfx::CAPVERSION_8));
    }

    #[test]
    fn reset_graphics_resizes_the_output() {
        let mut p = GraphicsProcessor::default();
        let mut body = vec![0u8; 332];
        body[0..4].copy_from_slice(&1024u32.to_le_bytes());
        body[4..8].copy_from_slice(&768u32.to_le_bytes());
        let outputs = feed(&mut p, egfx::CMDID_RESET_GRAPHICS, &body);
        assert_eq!(
            outputs,
            vec![Out::OutputResized {
                width: 1024,
                height: 768,
            }]
        );
    }

    #[test]
    fn solid_fill_inside_a_frame_flushes_at_end_frame_with_ack() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 16, 8);
        // Mapping marks the whole surface dirty, but un-bracketed ops flush immediately.
        let outputs = map_surface(&mut p, 1, 0, 0);
        assert_eq!(outputs.len(), 1, "map flushes the initial (black) surface");

        // StartFrame; fill red; nothing flushes until EndFrame.
        let mut start = vec![0u8; 8];
        start[4..8].copy_from_slice(&7u32.to_le_bytes());
        assert!(feed(&mut p, egfx::CMDID_START_FRAME, &start).is_empty());
        assert!(
            feed(
                &mut p,
                egfx::CMDID_SOLID_FILL,
                &solid_fill_body(1, [0, 0, 255, 0], [2, 1, 6, 3]),
            )
            .is_empty()
        );
        let outputs = feed(&mut p, egfx::CMDID_END_FRAME, &7u32.to_le_bytes());
        let [Out::Frame(frame), Out::Send(ack)] = outputs.as_slice() else {
            panic!("expected frame + ack, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y, frame.width, frame.height), (2, 1, 4, 2));
        assert!(frame.pixels.chunks_exact(4).all(|p| p == [255, 0, 0, 255]));
        // The ack is a RAW FrameAcknowledge for frame 7 (no segment wrapping outbound).
        assert_eq!(&ack[..2], &egfx::CMDID_FRAME_ACKNOWLEDGE.to_le_bytes());
        assert_eq!(&ack[12..16], &7u32.to_le_bytes());
    }

    #[test]
    fn mapped_offset_translates_to_output_coordinates() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 8, 8);
        map_surface(&mut p, 1, 100, 50);
        let outputs = feed(
            &mut p,
            egfx::CMDID_SOLID_FILL,
            &solid_fill_body(1, [1, 2, 3, 0], [0, 0, 4, 4]),
        );
        let [Out::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y), (100, 50));
    }

    #[test]
    fn wts1_uncompressed_blits_bgrx_as_rgba() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 4, 4);
        map_surface(&mut p, 1, 0, 0);
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&egfx::CODECID_UNCOMPRESSED.to_le_bytes());
        body.push(egfx::PIXEL_FORMAT_XRGB_8888);
        for v in [1u16, 1, 3, 3] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        let data: Vec<u8> = (0..4).flat_map(|_| [10u8, 20, 30, 0]).collect(); // BGRX
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&data);
        let outputs = feed(&mut p, egfx::CMDID_WIRE_TO_SURFACE_1, &body);
        let [Out::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y, frame.width, frame.height), (1, 1, 2, 2));
        assert_eq!(&frame.pixels[..4], &[30, 20, 10, 255]); // BGR → RGB
    }

    #[test]
    fn surface_cache_round_trip_pastes_pixels() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 8, 8);
        map_surface(&mut p, 1, 0, 0);
        feed(
            &mut p,
            egfx::CMDID_SOLID_FILL,
            &solid_fill_body(1, [0, 255, 0, 0], [0, 0, 2, 2]), // green 2×2 at origin
        );
        // Cache the green square (slot 5).
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&5u16.to_le_bytes());
        for v in [0u16, 0, 2, 2] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        assert!(feed(&mut p, egfx::CMDID_SURFACE_TO_CACHE, &body).is_empty());
        // Paste it at (6,6).
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [6i16, 6] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        let outputs = feed(&mut p, egfx::CMDID_CACHE_TO_SURFACE, &body);
        let [Out::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y, frame.width, frame.height), (6, 6, 2, 2));
        assert!(frame.pixels.chunks_exact(4).all(|p| p == [0, 255, 0, 255]));
        // Evict frees the budget.
        feed(&mut p, egfx::CMDID_EVICT_CACHE_ENTRY, &5u16.to_le_bytes());
        assert_eq!(p.cache_bytes, 0);
    }

    #[test]
    fn surface_to_surface_copies_between_surfaces() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 4, 4);
        create_surface(&mut p, 2, 4, 4);
        map_surface(&mut p, 2, 0, 0);
        feed(
            &mut p,
            egfx::CMDID_SOLID_FILL,
            &solid_fill_body(1, [9, 9, 9, 0], [0, 0, 4, 4]),
        );
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes()); // src
        body.extend_from_slice(&2u16.to_le_bytes()); // dst
        for v in [0u16, 0, 2, 2] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [1i16, 1] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        let outputs = feed(&mut p, egfx::CMDID_SURFACE_TO_SURFACE, &body);
        let [Out::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y, frame.width, frame.height), (1, 1, 2, 2));
        assert_eq!(&frame.pixels[..4], &[9, 9, 9, 255]);
    }

    #[test]
    fn hostile_create_surface_is_bounded() {
        let mut p = GraphicsProcessor::default();
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&u16::MAX.to_le_bytes());
        body.extend_from_slice(&u16::MAX.to_le_bytes());
        body.push(egfx::PIXEL_FORMAT_XRGB_8888);
        let message = egfx::wrap_uncompressed(&header(egfx::CMDID_CREATE_SURFACE, &body));
        assert!(p.process(&message).is_err());
    }

    #[test]
    fn unknown_commands_and_codecs_are_skipped() {
        let mut p = GraphicsProcessor::default();
        assert!(feed(&mut p, 0x0016, &[0; 8]).is_empty()); // QoE ack: unknown, skipped
        create_surface(&mut p, 1, 4, 4);
        // CAVIDEO WTS1: logged + skipped, no error, no frame.
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&egfx::CODECID_CAVIDEO.to_le_bytes());
        body.push(egfx::PIXEL_FORMAT_XRGB_8888);
        for v in [0u16, 0, 4, 4] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&[0xAB; 4]);
        assert!(feed(&mut p, egfx::CMDID_WIRE_TO_SURFACE_1, &body).is_empty());
    }

    #[test]
    fn garbage_zgfx_is_a_typed_error() {
        let mut p = GraphicsProcessor::default();
        assert!(p.process(&[0x12, 0x34]).is_err());
    }

    #[test]
    fn hostile_map_origin_does_not_overflow_or_emit() {
        // A u32::MAX output origin must neither panic (debug overflow) nor produce frames —
        // the surface is mapped beyond the addressable output.
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 4, 4);
        assert!(map_surface(&mut p, 1, u32::MAX, u32::MAX).is_empty());
        let outputs = feed(
            &mut p,
            egfx::CMDID_SOLID_FILL,
            &solid_fill_body(1, [1, 1, 1, 0], [0, 0, 4, 4]),
        );
        assert!(
            outputs.is_empty(),
            "unaddressable mapping must drop frames, got {outputs:?}"
        );
    }

    #[test]
    fn dirty_rects_collapse_past_the_cap_without_unbounded_growth() {
        // 100 tiny fills inside one never-ending frame: the dirty list must collapse to a
        // bounding box instead of growing per rect, and the EndFrame flush stays small.
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 256, 2);
        map_surface(&mut p, 1, 0, 0);
        let mut start = vec![0u8; 8];
        start[4..8].copy_from_slice(&1u32.to_le_bytes());
        feed(&mut p, egfx::CMDID_START_FRAME, &start);
        for i in 0..100u16 {
            assert!(
                feed(
                    &mut p,
                    egfx::CMDID_SOLID_FILL,
                    &solid_fill_body(1, [9, 9, 9, 0], [i * 2, 0, i * 2 + 1, 1]),
                )
                .is_empty()
            );
        }
        assert!(
            p.surfaces[0].dirty.len() <= MAX_DIRTY_RECTS + 1,
            "dirty list grew unbounded: {}",
            p.surfaces[0].dirty.len()
        );
        let outputs = feed(&mut p, egfx::CMDID_END_FRAME, &1u32.to_le_bytes());
        // A handful of frames (collapsed regions) plus the ack — not one per fill.
        assert!(
            outputs.len() <= MAX_DIRTY_RECTS + 2,
            "got {} outputs",
            outputs.len()
        );
        assert!(
            matches!(outputs.last(), Some(Out::Send(_))),
            "ack must close the frame"
        );
    }
}
