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
//! WireToSurface1 RemoteFX (`CODECID_CAVIDEO`) decodes through the self-owned
//! `justrdp-codecs::rfx` decoder (issue #58, ADR-0007) — it skipped the bootstrap phase
//! outright (the bootstrap crate has no assembled TS_RFX decoder, and real V8 servers prefer
//! Progressive, so the real VM cannot exercise it; the synthetic differential corpus is the
//! verification ceiling).

use crate::dvc::{DvcProcessor, ProcessorOutput};
use crate::framebuffer::{FrameUpdate, Framebuffer};
use justrdp_codecs::clearcodec::Clear;
use justrdp_codecs::color::{self, Palette};
use justrdp_codecs::egfx::Zgfx;
// The self-owned Progressive decoder (#171), wired here in #172. It keys its tile store by
// **surface**, which is what retires the `codecContextId` bookkeeping this module used to carry.
use justrdp_codecs::planar;
use justrdp_codecs::rfx::RemoteFx;
use justrdp_codecs::rfx::progressive::Progressive;
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
    /// Reused zgfx output buffer — one allocation across messages (#86).
    zgfx_blob: Vec<u8>,
    progressive: Progressive,
    clear: Clear,
    remotefx: RemoteFx,
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
            zgfx_blob: Vec::new(),
            progressive: Progressive::new(),
            clear: Clear::new(),
            remotefx: RemoteFx::new(),
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

    /// Remove a surface and free the Progressive tile store held for it. Used by both
    /// DeleteSurface and the CreateSurface replace path — a server that recreates a surface id
    /// (resize/reconnect) must not strand the old grid's 48 KiB-per-tile state.
    ///
    /// **This is the only thing that frees Progressive state**, which is #170's decision and the
    /// inverse of what this module did while it drove the id-keyed bootstrap decoder: see the
    /// `ResetGraphics` and `DeleteEncodingContext` arms for why the other two frees had to go.
    fn remove_surface(&mut self, surface_id: u16) {
        self.progressive.delete_surface(surface_id);
        self.surfaces.retain(|s| s.id != surface_id);
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
            // RemoteFX non-progressive: the self-owned TS_RFX decoder (issue #58). A
            // headers-only payload legitimately paints nothing (`Ok(None)` from the codec);
            // a malformed stream warn-and-skips like the sibling codecs.
            egfx::CODECID_CAVIDEO => {
                let Ok(rgba) = self.remotefx.decode_to_rgba(data, w, h).map_err(|e| {
                    tracing::warn!(target: "rdp_egfx", error = %e, "RemoteFX WTS1 decode failed — region skipped");
                }) else {
                    return Ok(None);
                };
                Ok(rgba)
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
                // **Frees nothing, deliberately** (#170/#172). Dropping Progressive state here
                // was correct while the bootstrap decoder keyed contexts by `codecContextId`
                // with no cap — an unfreed context was an unbounded leak, which is #83's fix.
                // Keyed by surface it inverts into a desync: the server's *encoder* keeps its
                // reference frames across a reset, and `RFX_TILE_DIFFERENCE` (1405 of 2943 real
                // first passes) adds against them, so a client that cleared while the server did
                // not decodes every later difference tile against zeroes — silently, with `Ok`,
                // until the next non-difference first pass repairs that tile. An encoder that
                // *did* reset cannot send a difference tile at all, so keeping cannot desync.
                // `SurfaceStore` has no `reset` and this PDU carries no surface id: there is
                // nothing to call, and a loop over live surfaces would reintroduce the defect.
                // Surfaces are left to the server's explicit Create/Delete, as before.
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
                self.remove_surface(surface_id);
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
                // Free the surface's Progressive context with it (issue #83): the oracle keys
                // contexts by id, so without this the context outlives the surface and leaks
                // across the delete/recreate cycles servers do on resize/reconnect.
                self.remove_surface(surface_id);
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
                // The dirty regions are blitted by `flush_frames` after the payload (#163).
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
                // Held across the decode rather than looked up again after it. The decoder
                // paints through a sink, so the surface must be borrowed *while* it walks the
                // payload — which the previous shape could not do, because `surface_mut` takes
                // `&mut self` and would have borrowed the decoder with it. Reaching for the two
                // fields directly keeps the borrows disjoint.
                let Some(surface) = self.surfaces.iter_mut().find(|s| s.id == surface_id) else {
                    return Err(invalid(
                        "RDPGFX_WIRE_TO_SURFACE_PDU_2",
                        "unknown destination surface",
                    ));
                };
                let (sw, sh) = (surface.width, surface.height);
                // No context bookkeeping: the store is keyed by surface (#170), so a stream
                // moving to a new `codecContextId` is not an event at all. The eviction this
                // arm used to perform existed only to cap the id-keyed oracle (#83).
                let decoded = self.progressive.decode(surface_id, sw, sh, data, |rect| {
                    // The source offset rides the *slice*, not a parameter: `blit`'s slice start
                    // and `src_stride_px` are independent, so row `r` of the copy lands on tile
                    // pixel `(src_x, src_y + r)` at a stride of `TILE_DIM`. #158 recorded that
                    // `Surface::blit` "cannot express a source offset" and that this issue would
                    // have to widen it — measured false, see
                    // `blit_expresses_a_source_offset_by_slicing_the_tile`.
                    let stride = usize::from(justrdp_pdu::rfx::TILE_DIM);
                    let off = (usize::from(rect.src_y) * stride + usize::from(rect.src_x)) * 4;
                    // `get`, not an index. `src_x`/`src_y` are inside the tile by the decoder's
                    // contract — asserted on every input the `progressive_assembly` fuzz target
                    // sees — but that contract is held by arithmetic, not by a type, and this is
                    // the core panicking on a value a *server* ultimately drove
                    // (`docs/map/invariant/untrusted-decode-never-panics.md`). A skipped
                    // rectangle costs one tile of one frame; a panic costs the session.
                    let Some(src) = rect.tile.get(off..) else {
                        return;
                    };
                    surface.blit(
                        i32::from(rect.x),
                        i32::from(rect.y),
                        rect.width,
                        rect.height,
                        src,
                        stride,
                    );
                });
                // The corpus-capture harness (ADR-0011's other half). It rode inside the
                // bootstrap decoder until #172; the payload is what is being captured, not a
                // decode, so it is a free function over the wire bytes now — and it stays here
                // because the fixture format records the `codecContextId`, which the
                // surface-keyed decoder never sees (`justrdp-codecs/src/capture.rs`).
                if let Some(dir) = justrdp_codecs::capture::progressive_capture_dir() {
                    let status = match &decoded {
                        Ok(o) => format!("ok:{}", o.tiles_decoded),
                        Err(e) => format!("err:{e}"),
                    };
                    justrdp_codecs::capture::progressive_payload(
                        &dir,
                        data,
                        codec_context_id,
                        sw,
                        sh,
                        &status,
                    );
                }
                // Warn-and-skip on failure, like the WTS1 codecs: a malformed payload must not
                // kill the session (the tile state may desync until the next first-pass
                // repaint, which servers send periodically).
                match decoded {
                    Err(e) => {
                        tracing::warn!(target: "rdp_egfx", error = %e, "progressive payload rejected — pass skipped");
                    }
                    Ok(outcome) => {
                        // A per-tile failure is not a payload failure, so it is reported rather
                        // than returned — logging it is the only thing that makes the difference
                        // between a painted pass and a wholly skipped one visible at all.
                        if outcome.fatal.is_some()
                            || outcome.first_error.is_some()
                            || !outcome.anomalies.is_empty()
                        {
                            tracing::warn!(
                                target: "rdp_egfx",
                                surface_id,
                                decoded = outcome.tiles_decoded,
                                skipped = outcome.tiles_skipped,
                                painted = outcome.rects_painted,
                                anomalies = outcome.anomalies.len(),
                                fatal = ?outcome.fatal,
                                first_error = ?outcome.first_error,
                                "progressive payload decoded with findings",
                            );
                        }
                    }
                }
            }
            EgfxPdu::DeleteEncodingContext {
                surface_id: _,
                codec_context_id,
            } => {
                // **A no-op, deliberately** (#170/#172), and the call is kept as the record of
                // that: `SurfaceStore::delete_context` exists and does nothing, because the
                // store is keyed by surface and a context id names nothing it holds. FreeRDP's
                // handler is a literal no-op too (`gdi/gfx.c:1239-1246`). Freeing here was
                // #83's fix for the id-keyed bootstrap decoder and inverts for the same reason
                // `ResetGraphics` does — see that arm.
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
                // Field-level borrows (`cache` immutably, `surfaces` mutably) are disjoint,
                // so the cached pixels blit without a per-apply clone of the whole entry
                // (#84) — the `surface_mut` helper would borrow all of `self` and force it.
                let dest = self
                    .surfaces
                    .iter_mut()
                    .find(|s| s.id == surface_id)
                    .ok_or(invalid(
                        "RDPGFX_CACHE_TO_SURFACE_PDU",
                        "unknown destination surface",
                    ))?;
                for pt in dest_points {
                    dest.blit(
                        i32::from(pt.x),
                        i32::from(pt.y),
                        entry.width,
                        entry.height,
                        &entry.rgba,
                        usize::from(entry.width),
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

    /// Handle every EGFX PDU in one decompressed blob.
    fn process_blob(&mut self, blob: &[u8]) -> Result<Vec<ProcessorOutput>, DecodeError> {
        let mut outputs = Vec::new();
        for pdu in egfx::decode_all(blob)? {
            self.handle(pdu, &mut outputs)?;
        }
        Ok(outputs)
    }

    /// Blit the accumulated dirty regions of every output-mapped surface straight into
    /// `framebuffer` — no intermediate owned extract (ADR-0010 slice #163) — and return the
    /// dirty rects in output coordinates.
    fn blit_dirty(&mut self, framebuffer: &mut Framebuffer) -> Vec<FrameUpdate> {
        let mut frames = Vec::new();
        for surface in &mut self.surfaces {
            if surface.dirty.is_empty() {
                continue;
            }
            let Some((ox, oy)) = surface.mapped else {
                surface.dirty.clear(); // off-screen scratch surface: nothing to show yet
                continue;
            };
            let sw = usize::from(surface.width);
            let rects = core::mem::take(&mut surface.dirty);
            for (x, y, w, h) in rects {
                let w = w.min(surface.width.saturating_sub(x));
                let h = h.min(surface.height.saturating_sub(y));
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
                // Blit the surface sub-region directly: pass the region's start offset and the
                // full surface stride so `Framebuffer::blit` copies it row by row into the
                // framebuffer — the extract Vec the bridge used to carry is gone (#163).
                let src_off = (usize::from(y) * sw + usize::from(x)) * 4;
                if let Some(update) =
                    framebuffer.blit(out_x, out_y, w, h, &surface.rgba[src_off..], sw)
                {
                    frames.push(update);
                }
            }
        }
        frames
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
        // The blob buffer is taken out of `self` (the PDU handlers need `&mut self` while
        // the blob is borrowed) and put back after, so one allocation serves every message
        // on the channel (#86).
        let mut blob = core::mem::take(&mut self.zgfx_blob);
        let result = self
            .zgfx
            .decompress_into(message, &mut blob)
            .map_err(|e| {
                tracing::warn!(target: "rdp_egfx", error = %e, "zgfx decompression failed");
                invalid("RDP_SEGMENTED_DATA", "zgfx decompression failed")
            })
            .and_then(|()| self.process_blob(&blob));
        self.zgfx_blob = blob;
        result
    }

    fn flush_frames(&mut self, framebuffer: &mut Framebuffer) -> Vec<FrameUpdate> {
        // Only flush completed frames: mid-bracket dirty (a Start Frame whose End Frame is in a
        // later payload) waits, matching the pre-#163 behavior where the EndFrame handler drove
        // the flush. Unbracketed draw ops (in_frame already false) flush at once.
        if self.in_frame {
            return Vec::new();
        }
        self.blit_dirty(framebuffer)
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

    /// **This falsifies #158's recorded claim** that `Surface::blit` "cannot express a
    /// source offset". It can: the source *slice start* and `src_stride_px` are independent, so
    /// a rectangle at `(src_x, src_y)` of a 64-px-stride tile is reached by slicing the tile and
    /// keeping the stride at 64. Row `r` then lands at `(src_x, src_y + r)` by construction.
    #[test]
    fn blit_expresses_a_source_offset_by_slicing_the_tile() {
        // A 4x4 tile whose pixels encode their own coordinates in R and G.
        let stride = 4usize;
        let mut tile = vec![0u8; stride * 4 * 4];
        for y in 0..4usize {
            for x in 0..stride {
                let o = (y * stride + x) * 4;
                tile[o] = x as u8;
                tile[o + 1] = y as u8;
                tile[o + 3] = 255;
            }
        }

        let mut surface = Surface {
            id: 1,
            width: 8,
            height: 8,
            rgba: vec![0; 8 * 8 * 4],
            mapped: None,
            dirty: Vec::new(),
        };
        // Paint the tile's bottom-right 2x2 (src 2,2) at destination (5,3) — a *positive*
        // destination, which is the case the negative-x trick cannot reach.
        let (src_x, src_y, w, h) = (2usize, 2usize, 2u16, 2u16);
        surface.blit(5, 3, w, h, &tile[(src_y * stride + src_x) * 4..], stride);

        let at = |x: usize, y: usize| {
            let o = (y * 8 + x) * 4;
            (surface.rgba[o], surface.rgba[o + 1])
        };
        assert_eq!(at(5, 3), (2, 2), "top-left of the copy");
        assert_eq!(at(6, 3), (3, 2));
        assert_eq!(at(5, 4), (2, 3));
        assert_eq!(at(6, 4), (3, 3), "bottom-right of the copy");
        // Nothing outside the 2x2 was touched, so the offset moved the *source* and not the
        // destination — the failure mode a stride/offset mix-up produces.
        assert_eq!(at(4, 3), (0, 0));
        assert_eq!(at(7, 3), (0, 0));
        assert_eq!(at(5, 2), (0, 0));
        assert_eq!(at(5, 5), (0, 0));
        assert_eq!(
            surface.dirty,
            vec![(5, 3, 2, 2)],
            "dirty is the painted rect"
        );
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

    /// Blit the processor's accumulated dirty regions into a fresh framebuffer big enough for
    /// these tests' mapped outputs, returning it with the dirty rects (ADR-0010 #163). The
    /// framebuffer is the authoritative screen state, so tests assert its pixels — not the frame
    /// list, whose granularity now coalesces per payload (e.g. a map's whole-surface rect plus a
    /// fill rect).
    fn flush(p: &mut GraphicsProcessor) -> (Framebuffer, Vec<FrameUpdate>) {
        let mut fb = Framebuffer::new(256, 256);
        let frames = p.flush_frames(&mut fb);
        (fb, frames)
    }

    /// One flushed rect's RGBA pixels, read back out of the framebuffer.
    fn region(fb: &Framebuffer, f: &FrameUpdate) -> Vec<u8> {
        let mut px = vec![0u8; usize::from(f.width) * usize::from(f.height) * 4];
        fb.copy_rect_into(f.x, f.y, f.width, f.height, &mut px);
        px
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
        // Mapping marks the whole surface dirty but no longer flushes mid-process (ADR-0010 #163:
        // the session drains dirty into the framebuffer after the payload).
        assert!(map_surface(&mut p, 1, 0, 0).is_empty());

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
        // EndFrame now emits only the raw FrameAcknowledge; the pixels flush separately.
        let [Out::Send(ack)] = outputs.as_slice() else {
            panic!("expected the frame ack, got {outputs:?}");
        };
        // The ack is a RAW FrameAcknowledge for frame 7 (no segment wrapping outbound).
        assert_eq!(&ack[..2], &egfx::CMDID_FRAME_ACKNOWLEDGE.to_le_bytes());
        assert_eq!(&ack[12..16], &7u32.to_le_bytes());
        // Flush drains the dirty into the framebuffer: the red fill lands at (2,1,4,2). The
        // framebuffer is authoritative, so read it at the known rect (frame-list granularity now
        // coalesces per payload).
        let (fb, frames) = flush(&mut p);
        assert!(!frames.is_empty(), "the fill flushes");
        let fill = region(
            &fb,
            &FrameUpdate {
                x: 2,
                y: 1,
                width: 4,
                height: 2,
            },
        );
        assert!(fill.chunks_exact(4).all(|p| p == [255, 0, 0, 255]));
    }

    #[test]
    fn mapped_offset_translates_to_output_coordinates() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 8, 8);
        map_surface(&mut p, 1, 100, 50);
        assert!(
            feed(
                &mut p,
                egfx::CMDID_SOLID_FILL,
                &solid_fill_body(1, [1, 2, 3, 0], [0, 0, 4, 4]),
            )
            .is_empty()
        );
        let (_fb, frames) = flush(&mut p);
        assert!(!frames.is_empty(), "the mapped surface flushes");
        assert!(
            frames.iter().all(|f| (f.x, f.y) == (100, 50)),
            "every dirty rect translates to the (100,50) output origin, got {frames:?}"
        );
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
        assert!(feed(&mut p, egfx::CMDID_WIRE_TO_SURFACE_1, &body).is_empty());
        let (fb, _frames) = flush(&mut p);
        let px = region(
            &fb,
            &FrameUpdate {
                x: 1,
                y: 1,
                width: 2,
                height: 2,
            },
        );
        assert_eq!(&px[..4], &[30, 20, 10, 255]); // BGR → RGB
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
        assert!(feed(&mut p, egfx::CMDID_CACHE_TO_SURFACE, &body).is_empty());
        let (fb, _frames) = flush(&mut p);
        let px = region(
            &fb,
            &FrameUpdate {
                x: 6,
                y: 6,
                width: 2,
                height: 2,
            },
        );
        assert!(px.chunks_exact(4).all(|p| p == [0, 255, 0, 255]));
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
        assert!(feed(&mut p, egfx::CMDID_SURFACE_TO_SURFACE, &body).is_empty());
        let (fb, _frames) = flush(&mut p);
        let px = region(
            &fb,
            &FrameUpdate {
                x: 1,
                y: 1,
                width: 2,
                height: 2,
            },
        );
        assert_eq!(&px[..4], &[9, 9, 9, 255]);
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
        // Malformed CAVIDEO WTS1 (garbage, not a TS_RFX stream): warn-and-skip — no error,
        // no frame, session survives (the sibling-codec failure contract).
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

    /// Build a minimal valid TS_RFX payload: one full-tile region plus one tile whose three
    /// components are the given RLGR bytes (entropy: RLGR1, quants: all-1 exponents).
    fn cavideo_payload(component: &[u8]) -> Vec<u8> {
        fn push_block(out: &mut Vec<u8>, ty: u16, channel_id: u8, body: &[u8]) {
            out.extend_from_slice(&ty.to_le_bytes());
            out.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
            out.push(1);
            out.push(channel_id);
            out.extend_from_slice(body);
        }
        let mut data = Vec::new();
        let mut region = vec![0x01u8];
        region.extend_from_slice(&1u16.to_le_bytes());
        for v in [0u16, 0, 64, 64] {
            region.extend_from_slice(&v.to_le_bytes());
        }
        region.extend_from_slice(&0xCAC1u16.to_le_bytes());
        region.extend_from_slice(&1u16.to_le_bytes());
        push_block(&mut data, 0xCCC6, 0, &region);
        let mut tile = Vec::new();
        tile.extend_from_slice(&0xCAC3u16.to_le_bytes());
        tile.extend_from_slice(&((6 + 13 + component.len() * 3) as u32).to_le_bytes());
        tile.extend_from_slice(&[0, 0, 0]); // quant indices
        tile.extend_from_slice(&0u16.to_le_bytes()); // xIdx
        tile.extend_from_slice(&0u16.to_le_bytes()); // yIdx
        for _ in 0..3 {
            tile.extend_from_slice(&(component.len() as u16).to_le_bytes());
        }
        for _ in 0..3 {
            tile.extend_from_slice(component);
        }
        let properties: u16 = 0x01 | (1 << 4) | (1 << 6) | (0x01 << 10) | (1 << 14);
        let mut tileset = Vec::new();
        tileset.extend_from_slice(&0xCAC2u16.to_le_bytes());
        tileset.extend_from_slice(&0u16.to_le_bytes());
        tileset.extend_from_slice(&properties.to_le_bytes());
        tileset.push(1); // numQuant
        tileset.push(64); // tileSize
        tileset.extend_from_slice(&1u16.to_le_bytes()); // numTiles
        tileset.extend_from_slice(&(tile.len() as u32).to_le_bytes());
        tileset.extend_from_slice(&[0x11; 5]); // all-1 quant exponents (no shift)
        tileset.extend_from_slice(&tile);
        push_block(&mut data, 0xCCC7, 0, &tileset);
        data
    }

    #[test]
    fn wts1_remotefx_cavideo_decodes_to_a_frame() {
        // An all-zero-coefficient tile reconstructs to Y = Cb = Cr = 0, which the RemoteFX
        // inverse color transform maps to mid gray: (0 + 4096) · 2¹⁶ ≫ 21 = 128 per channel.
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 64, 64);
        map_surface(&mut p, 1, 0, 0);
        let payload = cavideo_payload(&[0x00; 8]);
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&egfx::CODECID_CAVIDEO.to_le_bytes());
        body.push(egfx::PIXEL_FORMAT_XRGB_8888);
        for v in [0u16, 0, 64, 64] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        body.extend_from_slice(&payload);
        assert!(feed(&mut p, egfx::CMDID_WIRE_TO_SURFACE_1, &body).is_empty());
        let (fb, frames) = flush(&mut p);
        assert!(!frames.is_empty(), "the cavideo frame flushes");
        let pixels = region(
            &fb,
            &FrameUpdate {
                x: 0,
                y: 0,
                width: 64,
                height: 64,
            },
        );
        assert!(
            pixels.chunks_exact(4).all(|p| p == [128, 128, 128, 255]),
            "zero spectrum must decode to mid gray, got {:?}…",
            &pixels[..8]
        );
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
        assert!(
            feed(
                &mut p,
                egfx::CMDID_SOLID_FILL,
                &solid_fill_body(1, [1, 1, 1, 0], [0, 0, 4, 4]),
            )
            .is_empty()
        );
        let (_fb, frames) = flush(&mut p);
        assert!(
            frames.is_empty(),
            "unaddressable mapping must drop frames, got {frames:?}"
        );
    }

    /// Feed one WireToSurface2 PDU (surface, codec, context id, raw codec data).
    fn wts2(p: &mut GraphicsProcessor, surface_id: u16, codec_id: u16, ctx_id: u32, data: &[u8]) {
        let mut body = Vec::new();
        body.extend_from_slice(&surface_id.to_le_bytes());
        body.extend_from_slice(&codec_id.to_le_bytes());
        body.extend_from_slice(&ctx_id.to_le_bytes());
        body.push(egfx::PIXEL_FORMAT_XRGB_8888);
        body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // bitmapDataLength (#193)
        body.extend_from_slice(data);
        // Garbage Progressive payloads warn-and-skip (no frame), so no output is expected.
        assert!(feed(p, egfx::CMDID_WIRE_TO_SURFACE_2, &body).is_empty());
    }

    /// The **minimum** Progressive payload that puts a tile in the store: one region with one
    /// clip rect (`clip`, in surface coordinates) and one `WBT_TILE_SIMPLE` at grid (0, 0)
    /// whose three component streams are one zero byte each.
    ///
    /// Wire knowledge duplicated here on purpose, and kept to the degenerate case for the same
    /// reason. Every other Progressive test in this module has only ever fed *garbage*, so
    /// nothing here has ever proved that a payload reaches a surface at all — the shape
    /// `docs/map/invariant/a-later-stage-can-hide-an-earlier-defect.md` names, since the blit
    /// runs happily over whatever the decoder returns, including nothing. What the pixels
    /// should be is the corpus suite's question
    /// (`justrdp-codecs/tests/progressive_assembly_corpus.rs`); what this answers is whether
    /// the wiring carries them, which is the only half that lives in this crate.
    ///
    /// One byte per component rather than zero, which is not a detail: an *empty* stream is
    /// `Rlgr(EmptyInput)` and the tile is skipped, so a payload that looks even more minimal
    /// would have quietly asserted nothing. A single zero byte decodes to zero coefficients, so
    /// the tile is flat mid-grey (`128, 128, 128, 255` — `YCbCr(0,0,0)`), which is *visible*
    /// against a zeroed surface. Being flat, it cannot discriminate a **source-offset** error;
    /// that is `blit_expresses_a_source_offset_by_slicing_the_tile`'s job here and the corpus
    /// suite's over real tiles.
    fn progressive_one_tile_payload(clip: (u16, u16, u16, u16)) -> Vec<u8> {
        use justrdp_pdu::rfx::progressive as prog;

        fn block(out: &mut Vec<u8>, block_type: u16, body: &[u8]) {
            out.extend_from_slice(&block_type.to_le_bytes());
            out.extend_from_slice(&((6 + body.len()) as u32).to_le_bytes());
            out.extend_from_slice(body);
        }

        // WBT_TILE_SIMPLE: quantIdx x3, xIdx, yIdx, flags, then four zero lengths.
        let mut tile_body = vec![0u8, 0, 0];
        tile_body.extend_from_slice(&0u16.to_le_bytes()); // xIdx
        tile_body.extend_from_slice(&0u16.to_le_bytes()); // yIdx
        tile_body.push(0); // flags: not RFX_TILE_DIFFERENCE
        for _ in 0..3 {
            tile_body.extend_from_slice(&1u16.to_le_bytes()); // yLen / cbLen / crLen
        }
        tile_body.extend_from_slice(&0u16.to_le_bytes()); // tailLen
        tile_body.extend_from_slice(&[0x00, 0x00, 0x00]); // one RLGR byte per component
        let mut tiles = Vec::new();
        block(&mut tiles, prog::BLOCK_TILE_SIMPLE, &tile_body);

        let mut region = vec![64u8]; // tileSize, the only value CT_TILE_64x64 permits
        region.extend_from_slice(&1u16.to_le_bytes()); // numRects
        region.push(1); // numQuant
        region.push(0); // numProgQuant
        region.push(prog::REGION_FLAG_DWT_REDUCE_EXTRAPOLATE); // 52 of 52 real regions set it
        region.extend_from_slice(&1u16.to_le_bytes()); // numTiles
        region.extend_from_slice(&(tiles.len() as u32).to_le_bytes()); // tileDataSize
        for v in [clip.0, clip.1, clip.2, clip.3] {
            region.extend_from_slice(&v.to_le_bytes()); // the region's one clip rect
        }
        // One quant table, every band at 6 — the corpus minimum, and the floor below which
        // FreeRDP would reject the region (we decode it, see the divergence table).
        region.extend_from_slice(&[0x66; 5]);
        region.extend_from_slice(&tiles);

        let mut out = Vec::new();
        let mut frame_begin = 0u32.to_le_bytes().to_vec();
        frame_begin.extend_from_slice(&1u16.to_le_bytes()); // regionCount
        block(&mut out, prog::BLOCK_FRAME_BEGIN, &frame_begin);
        block(&mut out, prog::BLOCK_REGION, &region);
        block(&mut out, prog::BLOCK_FRAME_END, &[]);
        out
    }

    fn delete_surface(p: &mut GraphicsProcessor, id: u16) {
        feed(p, egfx::CMDID_DELETE_SURFACE, &id.to_le_bytes());
    }

    /// **The first test in this crate to prove a Progressive payload reaches a surface.**
    /// Every other one here has fed garbage, so the blit ran over an empty tile list and passed
    /// — the shape `docs/map/invariant/a-later-stage-can-hide-an-earlier-defect.md` names. What
    /// the pixels should be for a *real* stream is the corpus suite's question; that they arrive
    /// at all is this crate's, and it had no answer until #172 wired the self-owned decoder.
    #[test]
    fn a_progressive_payload_paints_its_tile_into_the_surface() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 64, 64);
        let payload = progressive_one_tile_payload((0, 0, 64, 64));
        wts2(&mut p, 1, egfx::CODECID_CAPROGRESSIVE, 7, &payload);

        assert_eq!(p.progressive.painted_tiles(), 1);
        assert_eq!(
            &p.surfaces[0].rgba[..4],
            &[128, 128, 128, 255],
            "a flat zero-coefficient tile is mid-grey, and the surface started at zero"
        );
        assert!(
            p.surfaces[0]
                .rgba
                .chunks(4)
                .all(|px| px == [128, 128, 128, 255]),
            "the whole 64x64 tile is painted when the region's rect covers it"
        );
        assert_eq!(p.surfaces[0].dirty, vec![(0, 0, 64, 64)]);
    }

    /// The clip is what #171 added and #172 wires: a tile is painted **only where its region's
    /// rects reach**, where the retired bootstrap decoder handed back whole 64x64 tiles for the
    /// caller to blit entire. Measured over the captured session the difference is 57 386 of
    /// 1 024 000 pixels, so this is a picture change and not a dirty-rect optimisation.
    ///
    /// Asserted as a *boundary* — inside grey, outside untouched — because a clip that is off by
    /// a row or that ignores the rect entirely both produce "some grey pixels".
    #[test]
    fn a_region_rect_clips_the_tile_it_paints() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 64, 64);
        let payload = progressive_one_tile_payload((16, 16, 32, 32));
        wts2(&mut p, 1, egfx::CODECID_CAPROGRESSIVE, 7, &payload);

        let px = |x: usize, y: usize| {
            let o = (y * 64 + x) * 4;
            [
                p.surfaces[0].rgba[o],
                p.surfaces[0].rgba[o + 1],
                p.surfaces[0].rgba[o + 2],
                p.surfaces[0].rgba[o + 3],
            ]
        };
        const GREY: [u8; 4] = [128, 128, 128, 255];
        const UNTOUCHED: [u8; 4] = [0, 0, 0, 0];
        assert_eq!(px(16, 16), GREY, "the rect's top-left corner");
        assert_eq!(px(47, 47), GREY, "the rect's bottom-right corner");
        assert_eq!(px(15, 16), UNTOUCHED, "one column left of the rect");
        assert_eq!(px(16, 15), UNTOUCHED, "one row above the rect");
        assert_eq!(px(48, 47), UNTOUCHED, "one column right of the rect");
        assert_eq!(px(47, 48), UNTOUCHED, "one row below the rect");
        assert_eq!(
            p.surfaces[0].dirty,
            vec![(16, 16, 32, 32)],
            "the dirty rect follows the clip, not the tile"
        );
        assert_eq!(
            p.surfaces[0]
                .rgba
                .chunks(4)
                .filter(|px| *px == GREY)
                .count(),
            32 * 32,
            "exactly the rect's area is painted - no spill, no shortfall"
        );
    }

    /// The four tests below pin **lifecycle wiring**: which surface's tile store survives which
    /// PDU. They drive a real payload rather than the garbage the bootstrap-era versions used,
    /// and the difference is load-bearing rather than cosmetic. The bootstrap decoder recorded a
    /// context on *reference*, before decoding, so garbage still registered; the self-owned one
    /// parses first and never reaches the store. More importantly, `live_surfaces()` alone
    /// cannot tell a surviving store from one thrown away and re-created empty — the grid is
    /// ensured on every payload — so these assert on `painted_tiles()`, which is the thing an
    /// erroneous free actually destroys.
    #[test]
    fn delete_surface_frees_the_surfaces_tile_store() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 64, 64);
        wts2(
            &mut p,
            1,
            egfx::CODECID_CAPROGRESSIVE,
            7,
            &progressive_one_tile_payload((0, 0, 64, 64)),
        );
        assert_eq!(p.progressive.painted_tiles(), 1);

        delete_surface(&mut p, 1);
        assert_eq!(
            p.progressive.live_surfaces(),
            0,
            "DeleteSurface must free the surface's tile store - it is the only thing that does"
        );
        assert_eq!(p.progressive.painted_tiles(), 0);
    }

    /// **The inverse of the retired `reset_graphics_clears_contexts_but_keeps_surfaces`**
    /// (#170/#172). That test asserted the bootstrap behaviour and passed, which is the
    /// strongest possible "do not touch this" — so it is inverted here rather than deleted, and
    /// this doc is why the inversion is the correct direction.
    ///
    /// Clearing on `RESETGRAPHICS` is #83's fix and is right while contexts are keyed by
    /// `codecContextId` with no cap, where an unfreed context is an unbounded leak. Keyed by
    /// surface it becomes a **desync**: the server's *encoder* keeps its reference frames across
    /// a reset and `RFX_TILE_DIFFERENCE` adds against them, so a client that cleared while the
    /// server did not decodes every later difference tile against zeroes — silently, with `Ok`,
    /// until the next non-difference first pass repairs that tile. An encoder that *did* reset
    /// cannot send a difference tile at all, so keeping cannot desync in the other direction.
    #[test]
    fn reset_graphics_keeps_the_tile_stores_it_used_to_clear() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 64, 64);
        create_surface(&mut p, 2, 64, 64);
        let payload = progressive_one_tile_payload((0, 0, 64, 64));
        wts2(&mut p, 1, egfx::CODECID_CAPROGRESSIVE, 7, &payload);
        wts2(&mut p, 2, egfx::CODECID_CAPROGRESSIVE, 8, &payload);
        assert_eq!(p.progressive.painted_tiles(), 2);

        let mut body = vec![0u8; 332];
        body[0..4].copy_from_slice(&64u32.to_le_bytes());
        body[4..8].copy_from_slice(&64u32.to_le_bytes());
        feed(&mut p, egfx::CMDID_RESET_GRAPHICS, &body);

        assert_eq!(
            p.progressive.painted_tiles(),
            2,
            "ResetGraphics must free no tile state - the server's encoder did not reset either"
        );
        assert_eq!(p.progressive.live_surfaces(), 2);
        assert_eq!(
            p.surfaces.len(),
            2,
            "ResetGraphics drops neither surfaces nor their stores"
        );
    }

    /// **The inverse of the retired `a_new_context_id_on_a_surface_evicts_the_previous`.** That
    /// eviction existed only to cap the id-keyed bootstrap decoder, which would otherwise
    /// accumulate one context per id on a single live surface (#83). Keyed by surface there is
    /// nothing to accumulate and nothing to evict, so a stream moving to a new `codecContextId`
    /// must be a **non-event**.
    ///
    /// The second payload deliberately paints *nothing* (its region clips to a 1x1 rect outside
    /// the tile), so the tile that survives can only be the first one's. An earlier revision fed
    /// an empty payload and asserted `live_surfaces()`, which could not fail: the grid is
    /// re-ensured on every payload, so a store thrown away and re-created empty reads exactly
    /// like one that was kept.
    #[test]
    fn a_new_context_id_on_a_surface_is_not_an_event() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 128, 128);
        wts2(
            &mut p,
            1,
            egfx::CODECID_CAPROGRESSIVE,
            7,
            &progressive_one_tile_payload((0, 0, 64, 64)),
        );
        assert_eq!(p.progressive.painted_tiles(), 1);

        wts2(&mut p, 1, egfx::CODECID_CAPROGRESSIVE, 9, &[]);
        assert_eq!(
            p.progressive.painted_tiles(),
            1,
            "one surface is one store, whatever context id its stream claims"
        );

        // And the explicit free is a no-op for the same reason: a context id names nothing the
        // store holds. FreeRDP's handler is a literal no-op too (`gdi/gfx.c:1239-1246`).
        let mut body = 1u16.to_le_bytes().to_vec();
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&9u32.to_le_bytes());
        feed(&mut p, egfx::CMDID_DELETE_ENCODING_CONTEXT, &body);
        assert_eq!(
            p.progressive.painted_tiles(),
            1,
            "DeleteEncodingContext must free nothing - the call is kept as the record of that"
        );
    }

    #[test]
    fn recreating_a_surface_id_frees_the_old_tile_store() {
        // Servers recreate a surface id on resize/reconnect without a DeleteSurface. The old
        // grid must go with it: its tile indices were computed against the old `gridWidth`, so
        // keeping it would address every later tile wrongly (#170).
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 64, 64);
        wts2(
            &mut p,
            1,
            egfx::CODECID_CAPROGRESSIVE,
            7,
            &progressive_one_tile_payload((0, 0, 64, 64)),
        );
        assert_eq!(p.progressive.painted_tiles(), 1);

        create_surface(&mut p, 1, 128, 128);
        assert_eq!(
            p.progressive.live_surfaces(),
            0,
            "the CreateSurface replace path must free the old store, not strand it"
        );
        assert_eq!(p.progressive.painted_tiles(), 0);
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
