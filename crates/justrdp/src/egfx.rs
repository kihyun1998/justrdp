//! The EGFX Graphics Pipeline processor (MS-RDPEGFX) — the [`DvcProcessor`] for the
//! `Microsoft::Windows::RDS::Graphics` dynamic channel, the production graphics path this
//! project exists to unlock (the ironrdp 0x0100 gate-flag story, plan.md §0).
//!
//! justrdp **owns the surface model** (ADR-0002): the off-screen surface store, the bitmap
//! cache, the blit/fill/cache ops, and the dirty-region batching live here. Every codec on this
//! path is now self-owned — zgfx bulk decompression was the last delegation and it went in #189,
//! so `ironrdp-graphics` is out of the runtime graph entirely (ADR-0003 phase 3, ADR-0011).
//! The client speaks first: `start()` sends a Caps Advertise carrying the host's `EgfxConfig`
//! (ADR-0015) — by default six capsets, 8 through CAPVERSION_104 without 10.1. The ladder is chosen
//! by which versions this client can *honour* rather than by how high the number goes — 10.5 and
//! 10.6 make the scaled map-surface command a MUST, and offering them to a real WS2022 server got
//! 10.6 confirmed and **zero** frames painted with no error anywhere (#271). AVC (H.264) stays
//! structurally excluded: every advertised 10.x capset carries `CAPS_FLAG_AVC_DISABLED`, and 10.1,
//! which implies AVC444v2 with no flag to decline it, is not advertised (#296). The derivation is
//! in `caps_advertise()` and `capset()`.
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
use justrdp_codecs::zgfx::Zgfx;
// The self-owned Progressive decoder (#171), wired here in #172. It keys its tile store by
// **surface**, which is what retires the `codecContextId` bookkeeping this module used to carry.
use justrdp_codecs::planar;
use justrdp_codecs::rfx::RemoteFx;
use justrdp_codecs::rfx::progressive::Progressive;
use justrdp_pdu::DecodeError;
use justrdp_pdu::egfx::{self, EgfxPdu, Rect16};

/// Per-axis cap on surface dimensions, and **ours rather than the spec's**: MS-RDPEGFX 2.2.2.9
/// states no maximum for a `CreateSurface` edge, so the wire ceiling is `u16::MAX`. 2.2.2.14's
/// 32766 is [`crate::framebuffer::MAX_DESKTOP_DIM`]'s quantity, not this one. Real surfaces
/// track the desktop; the cap bounds a hostile CreateSurface before allocation. Why it is not
/// raised, and what that diverges from: ADR-0009's 2026-09-16 amendment (#286).
const MAX_SURFACE_DIM: u16 = 16384;

/// Total RGBA bytes across all live surfaces (allocation bound, the reassembly-cap
/// precedent). A 4K desktop's primary surface is ~33 MiB; servers keep a handful.
const MAX_TOTAL_SURFACE_BYTES: usize = 256 << 20;

/// The bitmap-cache budget when the confirmed capset asks for no small cache
/// (MS-RDPEGFX 3.3.1.4).
const MAX_CACHE_BYTES: usize = 100 << 20;

/// The bitmap-cache budget under a confirmed 10.3, THINCLIENT or SMALL_CACHE (3.3.1.4).
const SMALL_CACHE_BYTES: usize = 16 << 20;

/// The highest one-based cache slot [`MAX_CACHE_BYTES`] pairs with (3.3.1.4).
const MAX_CACHE_SLOTS: u16 = 25_600;

/// The highest one-based cache slot [`SMALL_CACHE_BYTES`] pairs with (3.3.1.4).
const SMALL_CACHE_SLOTS: u16 = 4_096;

/// The capability versions this client can honour, oldest first: the default ladder, and the
/// set [`EgfxConfig::versions`] is drawn from.
const HONOURED_VERSIONS: [u32; 6] = [
    egfx::CAPVERSION_8,
    egfx::CAPVERSION_8_1,
    egfx::CAPVERSION_10,
    egfx::CAPVERSION_102,
    egfx::CAPVERSION_103,
    egfx::CAPVERSION_104,
];

/// What the graphics channel advertises in its Caps Advertise (MS-RDPEGFX 2.2.2.18).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgfxConfig {
    /// The capability versions to advertise, in any order, drawn from `CAPVERSION_8`, `_8_1`,
    /// `_10`, `_102`, `_103` and `_104`; `None` advertises all of them. They reach the
    /// wire oldest first, each with the flags this client derives for it.
    pub versions: Option<Vec<u32>>,
    /// The bitmap cache to ask the server for.
    pub cache: EgfxCacheMode,
}

/// The bitmap cache an [`EgfxConfig`] asks for (MS-RDPEGFX 2.2.3, 3.3.1.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EgfxCacheMode {
    /// 100 MB: no cache flag.
    #[default]
    Standard,
    /// 16 MB: `CAPS_FLAG_SMALL_CACHE` on every advertised version that defines it.
    Small,
    /// `CAPS_FLAG_THINCLIENT` on 8 and 8.1 (16 MB, and RemoteFX in place of RemoteFX
    /// Progressive); `CAPS_FLAG_SMALL_CACHE` on the later versions that define it.
    ThinClient,
}

/// Why an [`EgfxConfig`] cannot be advertised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgfxConfigError {
    /// `versions` names no version (3.3.5.18: one or more capsets).
    Empty,
    /// `versions` names this version more than once (3.3.5.18).
    Duplicate(u32),
    /// A version this client cannot honour, or one 2.2.3 does not specify.
    NotAdvertisable(u32),
}

impl core::fmt::Display for EgfxConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "no EGFX capability version to advertise"),
            Self::Duplicate(v) => write!(f, "EGFX capability version 0x{v:08X} named twice"),
            Self::NotAdvertisable(v) => {
                write!(f, "EGFX capability version 0x{v:08X} cannot be advertised")
            }
        }
    }
}

impl core::error::Error for EgfxConfigError {}

impl EgfxConfig {
    /// The capsets this config advertises, oldest first.
    fn capsets(&self) -> Result<Vec<egfx::CapSet>, EgfxConfigError> {
        if let Some(versions) = &self.versions {
            if versions.is_empty() {
                return Err(EgfxConfigError::Empty);
            }
            for (i, version) in versions.iter().enumerate() {
                if !HONOURED_VERSIONS.contains(version) {
                    return Err(EgfxConfigError::NotAdvertisable(*version));
                }
                if versions[..i].contains(version) {
                    return Err(EgfxConfigError::Duplicate(*version));
                }
            }
        }
        Ok(ladder(self.versions.as_deref(), self.cache))
    }
}

/// The capsets for `versions` (every honoured version when `None`), oldest first.
fn ladder(versions: Option<&[u32]>, cache: EgfxCacheMode) -> Vec<egfx::CapSet> {
    HONOURED_VERSIONS
        .into_iter()
        .filter(|version| versions.is_none_or(|versions| versions.contains(version)))
        .map(|version| capset(version, cache))
        .collect()
}

/// One honoured version's capset: `AVC_DISABLED` on every 10.x, and the cache flag where 2.2.3
/// defines one for that version.
fn capset(version: u32, cache: EgfxCacheMode) -> egfx::CapSet {
    let early = matches!(version, egfx::CAPVERSION_8 | egfx::CAPVERSION_8_1);
    let avc = if early {
        0
    } else {
        egfx::CAPS_FLAG_AVC_DISABLED
    };
    let cache = match cache {
        EgfxCacheMode::Standard => 0,
        _ if version == egfx::CAPVERSION_103 => 0,
        EgfxCacheMode::ThinClient if early => egfx::CAPS_FLAG_THINCLIENT,
        EgfxCacheMode::Small | EgfxCacheMode::ThinClient => egfx::CAPS_FLAG_SMALL_CACHE,
    };
    egfx::CapSet::Flags {
        version,
        flags: avc | cache,
    }
}

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
    /// Total by construction, and said here because
    /// [the invariant] requires
    /// a site that satisfies it that way to say so: every caller is downstream of
    /// `CREATE_SURFACE`'s `> MAX_SURFACE_DIM` refusal, so both factors are at most 16384 and the
    /// product is at most 1 GiB, which fits a 32-bit `usize`. The note's derivation *does* return
    /// this line, so without this comment a reader running it lands on a hit with nothing to
    /// adjudicate against.
    ///
    /// [the invariant]: https://github.com/kihyun1998/justrdp/blob/master/docs/map/invariant/decoder-dimension-overflow-32bit.md
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
    ///
    /// Returns the bytes actually painted **after clipping**, which is what the per-frame paint
    /// budget is charged (#268). The clipped figure is the only honest one: a destination point
    /// far off the surface costs nothing and must not be charged as if it did.
    fn blit(
        &mut self,
        x: i32,
        y: i32,
        copy_w: u16,
        copy_h: u16,
        src: &[u8],
        src_stride_px: usize,
    ) -> usize {
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
            return 0;
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
        w * h * 4
    }

    /// Extract a rectangle (clipped) as `(width, height, tight RGBA)`.
    ///
    /// The reserve is total by construction, for the same reason `Surface::bytes` is and stated
    /// for the same reason ([the invariant]
    /// asks a by-construction site to say so, and its derivation returns this line): the first
    /// two statements clip `w`/`h` to *this* surface's own dimensions before any multiply, so
    /// the reserve is bounded by a buffer that already exists — and therefore by
    /// `MAX_TOTAL_SURFACE_BYTES`, not by the arguments.
    ///
    /// **That is a claim about the multiply and it used to be written as a claim about the
    /// function** (#268). Clipping `w` does not clip `x`: at `x > self.width` the width goes to
    /// zero while the row loop still runs, and `&self.rgba[off..off]` panics on a slice whose
    /// *start* is past the end — a zero-length read at an out-of-range offset. The zero-extent
    /// return below is what `blit`, `fill` and `blit_dirty` each already had; this was the one
    /// of the four without it, which is also why the territory's "an off-surface rectangle is
    /// clipped by `Surface::blit` today" read as covering all four sites and did not.
    ///
    /// **Only the `w` half is load-bearing, and the `h` half is kept anyway.** Measured: mutating
    /// the condition to `w == 0` alone leaves the test green, because at `h == 0` the row loop
    /// never runs and the pre-guard behaviour is already identical. It stays because `blit`,
    /// `fill` and `blit_dirty` all read `w == 0 || h == 0` and a reader comparing the four should
    /// not have to work out why one is spelled differently — ADR-0012 §3, one quantity one answer
    /// across a family. Said here so the symmetry is not later mistaken for coverage.
    ///
    /// [the invariant]: https://github.com/kihyun1998/justrdp/blob/master/docs/map/invariant/decoder-dimension-overflow-32bit.md
    fn extract(&self, x: u16, y: u16, w: u16, h: u16) -> (u16, u16, Vec<u8>) {
        let w = w.min(self.width.saturating_sub(x));
        let h = h.min(self.height.saturating_sub(y));
        if w == 0 || h == 0 {
            return (w, h, Vec::new());
        }
        let stride = usize::from(self.width) * 4;
        let mut out = Vec::with_capacity(usize::from(w) * usize::from(h) * 4);
        for row in 0..usize::from(h) {
            let off = (usize::from(y) + row) * stride + usize::from(x) * 4;
            out.extend_from_slice(&self.rgba[off..off + usize::from(w) * 4]);
        }
        (w, h, out)
    }

    /// Fill a rectangle (clipped) with one RGBA pixel. Returns the bytes painted after
    /// clipping, for the per-frame paint budget (#268) — see [`Surface::blit`].
    fn fill(&mut self, rect: Rect16, rgba: [u8; 4]) -> usize {
        let x = rect.left.min(self.width);
        let y = rect.top.min(self.height);
        let w = rect.width().min(self.width.saturating_sub(x));
        let h = rect.height().min(self.height.saturating_sub(y));
        if w == 0 || h == 0 {
            return 0;
        }
        let stride = usize::from(self.width) * 4;
        for row in 0..usize::from(h) {
            let off = (usize::from(y) + row) * stride + usize::from(x) * 4;
            for px in self.rgba[off..off + usize::from(w) * 4]
                .as_chunks_mut::<4>()
                .0
            {
                px.copy_from_slice(&rgba);
            }
        }
        self.mark_dirty((x, y, w, h));
        usize::from(w) * usize::from(h) * 4
    }
}

/// Record that a list-bearing command was cut short by the per-frame paint budget (#268).
///
/// Skipping is the tolerant direction and it is **silent by construction** — the frame still
/// acknowledges and the session continues, so the only difference a host can observe is pixels
/// that were never painted. ADR-0009 §3(b) is explicit that a tolerance nobody can see is
/// indistinguishable from a bug, and this territory already carries a `## Known holes` entry
/// for exactly that shape on the clipping path. The record is what makes this a tolerance.
fn note_budget(pdu: &'static str, declared: usize, painted: usize) {
    if declared > painted {
        tracing::warn!(
            target: "rdp_egfx",
            pdu,
            declared,
            painted,
            skipped = declared - painted,
            "per-frame paint budget reached; the remaining entries were skipped",
        );
    }
}

/// One cached bitmap (SurfaceToCache → CacheToSurface).
struct CachedBitmap {
    width: u16,
    height: u16,
    rgba: Vec<u8>,
}

/// The EGFX channel processor: transport codec state + the owned surface model.
pub struct GraphicsProcessor {
    /// The capsets every Caps Advertise on this channel carries.
    capsets: Vec<egfx::CapSet>,
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
    /// The `flags` of the confirmed capset.
    confirmed_flags: u32,
    frames_decoded: u32,
    in_frame: bool,
    /// RGBA bytes painted by the list-bearing commands since this frame opened (#268). The
    /// ceiling is [`MAX_TOTAL_SURFACE_BYTES`], **derived rather than picked**: the most a frame
    /// can legitimately paint is every surface that could exist, once — and past that it is
    /// repainting pixels it already painted. Measured against a real WS2022 server, the busiest
    /// of 89 frames painted 4 096 000 bytes, exactly one 1280x800 desktop, so the ceiling sits
    /// ~64x above observed traffic while the unbounded case reached ~6.4 TiB in one PDU.
    frame_paint: usize,
    /// A 3.3.5.19 reset was sent and its confirm has not arrived: every server PDU but a
    /// confirm is ignored.
    awaiting_confirm: bool,
    /// This channel binding has spent its one reset.
    reset_spent: bool,
}

/// Why handling one EGFX PDU failed.
enum Failure {
    /// A reference to state this client does not hold — a surface or cache slot — or an
    /// uncompressed payload that does not decode. A 3.3.5.19 reset can recover it.
    Miss(DecodeError),
    /// Every other failure ends the session.
    Fatal(DecodeError),
}

impl From<DecodeError> for Failure {
    fn from(error: DecodeError) -> Self {
        Failure::Fatal(error)
    }
}

fn miss(field: &'static str, reason: &'static str) -> Failure {
    Failure::Miss(invalid(field, reason))
}

impl Default for GraphicsProcessor {
    fn default() -> Self {
        Self {
            capsets: ladder(None, EgfxCacheMode::Standard),
            zgfx: Zgfx::new(),
            zgfx_blob: Vec::new(),
            progressive: Progressive::new(),
            clear: Clear::new(),
            remotefx: RemoteFx::new(),
            surfaces: Vec::new(),
            cache: std::collections::HashMap::new(),
            cache_bytes: 0,
            confirmed_version: None,
            confirmed_flags: 0,
            frames_decoded: 0,
            in_frame: false,
            frame_paint: 0,
            awaiting_confirm: false,
            reset_spent: false,
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
                // Total for the whole `Rect16`, not only for what the caller's `MAX_SURFACE_DIM`
                // bound admits — ADR-0012 §1: the parser's guarantee is not held at the point of
                // use, and this function's signature takes a bare rectangle. Only observable
                // where `usize` is 32 bits; on 64-bit the widest product fits.
                let needed = uw
                    .checked_mul(uh)
                    .and_then(|n| n.checked_mul(4))
                    .ok_or_else(|| {
                        invalid(
                            "RDPGFX_WIRE_TO_SURFACE_PDU_1",
                            "destination rectangle's byte count overflows usize",
                        )
                    })?;
                if data.len() < needed {
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
    ) -> Result<(), Failure> {
        match pdu {
            EgfxPdu::CapsConfirm { version, flags } => {
                // 3.3.5.19: a capability set "not specified in section 2.2.3" MUST be
                // ignored; only a specified one is stored and adhered to. Recognising a
                // version and adhering to it are different acts — the versions this client
                // declines to *advertise* are still recognised here, because a confirm naming
                // one is a server disagreeing with us, not a malformed PDU.
                if !egfx::is_specified_capversion(version) {
                    tracing::warn!(
                        target: "rdp_egfx_caps",
                        version,
                        "EGFX caps confirm names a version outside 2.2.3 — ignored"
                    );
                    return Ok(());
                }
                tracing::info!(target: "rdp_egfx_caps", version, flags, "EGFX caps confirmed");
                self.confirmed_version = Some(version);
                self.confirmed_flags = flags;
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
                    )
                    .into());
                }
                self.remove_surface(surface_id);
                if self.total_surface_bytes() + Surface::bytes(width, height)
                    > MAX_TOTAL_SURFACE_BYTES
                {
                    return Err(invalid(
                        "RDPGFX_CREATE_SURFACE_PDU",
                        "total surface allocation exceeds the cap",
                    )
                    .into());
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
                self.frame_paint = 0;
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
                // A destination rectangle is not merely *where* the bitmap lands, it is the
                // bitmap's dimensions: `[MS-RDPEGFX]` 2.2.2.1 says destRect specifies "the
                // dimensions (width and height) of the bitmap data encapsulated in the
                // bitmapData field", and 2.2.1.2 bounds its four fields at `u16` and states
                // nothing else — no maximum, no non-zero requirement. So for every codec that
                // *expands* its input, the rectangle alone decides how much memory the decode
                // allocates, and a server picks it. 65535 x 65535 x 4 is 17_179_344_900 bytes.
                // Measured on the CAVIDEO arm with a 93-byte tileset (#263): i686 panicked with
                // a multiply overflow inside `rfx::opaque_black`, and x86-64 — where that
                // product does *not* overflow — allocated the whole 16 GiB and returned `Ok`
                // after 18.9 seconds. That second row is **host-conditional and the condition
                // makes it worse, not better**: it held on a box with 24.8 GiB of commit
                // available, and on a smaller one `alloc_zeroed` fails, which is
                // `handle_alloc_error` and therefore `abort` — not a `Result`, not catchable,
                // and fatal to the host process rather than to the RDP task. **No *overflow*
                // check can reach either outcome**, which is why this bounds the rectangle
                // rather than checking the multiplication. (A magnitude comparison is also an
                // arithmetic guard and could reach it; what the codec lacks is a principled
                // number, which this layer has.)
                //
                // The ceiling is `MAX_TOTAL_SURFACE_BYTES`, and it is *derived* rather than
                // picked: `CREATE_SURFACE` below refuses when `total_surface_bytes() +
                // Surface::bytes(w, h)` passes it, so **no single admissible surface exceeds it**
                // — and a destRect is in surface coordinates. A rectangle whose RGBA is larger
                // than every surface that can exist therefore names a bitmap nothing could ever
                // hold, and refusing it loses no legitimate rectangle at all. A per-axis
                // `MAX_SURFACE_DIM` bound was written first and is 4x looser: 16384 x 16384 x 4
                // is 1 GiB, i.e. four times the budget the whole surface set has to share.
                //
                // Deliberately *not* the destination surface's own width and height, which is
                // tighter again and what FreeRDP does (`is_within_surface`, `gdi/gfx.c:386`,
                // refusing before its `1ull * bpp * w * h` at `:390`; `ironrdp-egfx` checks the
                // same condition and only `warn!`s): a partially off-surface rectangle is
                // clipped by `Surface::blit` today, and ADR-0009 says not to trade a tolerance
                // we already have for a bound the spec never asked for. Stated as the code fact
                // it is — no capture in this repo has ever recorded a real server sending an
                // off-surface destRect, so the tolerance being kept is unobserved too.
                //
                // `Surface::blit` is named here because it is the only routine a *destRect*
                // reaches, not as shorthand for the surface model. The same sentence copied into
                // the territory record dropped that scope and was read as covering all four
                // surface routines, one of which (`Surface::extract`) clipped its extent and
                // indexed by an unclipped origin until #268.
                //
                // Here rather than inside `decode_wts1` for two reasons that agree. It is fatal
                // for *every* codec — including the tile codecs `decode_wts1` warn-and-skips,
                // whose own comment scopes that tolerance to "the decoder may simply be
                // incomplete" and names allocation bounds as staying fatal — and every expanding
                // arm carried the hazard, not just CAVIDEO: PLANAR allocates `w*h` per plane and
                // ClearCodec expands likewise, so a per-arm guard would have been three guards.
                // Keeping it out of the dispatcher also leaves that function total for its own
                // bare `Rect16` signature and, crucially, *testable* for it — a guard placed
                // where it makes the arithmetic below unreachable cannot redden.
                let admissible = usize::from(dest_rect.width())
                    .checked_mul(usize::from(dest_rect.height()))
                    .and_then(|px| px.checked_mul(4))
                    .is_some_and(|bytes| bytes <= MAX_TOTAL_SURFACE_BYTES);
                if !admissible {
                    return Err(invalid(
                        "RDPGFX_WIRE_TO_SURFACE_PDU_1",
                        "destination rectangle is larger than any admissible surface",
                    )
                    .into());
                }
                if let Some(rgba) = self
                    .decode_wts1(codec_id, dest_rect, data)
                    .map_err(Failure::Miss)?
                {
                    let (w, h) = (dest_rect.width(), dest_rect.height());
                    let surface = self.surface_mut(surface_id).ok_or(miss(
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
                    return Err(miss(
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
                let budget = MAX_TOTAL_SURFACE_BYTES.saturating_sub(self.frame_paint);
                let surface = self
                    .surface_mut(surface_id)
                    .ok_or(miss("RDPGFX_SOLIDFILL_PDU", "unknown destination surface"))?;
                let declared = rects.len();
                let mut painted = 0usize;
                let mut done = 0usize;
                for rect in rects {
                    if painted >= budget {
                        break;
                    }
                    painted += surface.fill(rect, rgba);
                    done += 1;
                }
                self.frame_paint += painted;
                note_budget("RDPGFX_SOLIDFILL_PDU", declared, done);
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
                    .ok_or(miss(
                        "RDPGFX_SURFACE_TO_SURFACE_PDU",
                        "unknown source surface",
                    ))?
                    .extract(
                        src_rect.left,
                        src_rect.top,
                        src_rect.width(),
                        src_rect.height(),
                    );
                let budget = MAX_TOTAL_SURFACE_BYTES.saturating_sub(self.frame_paint);
                let dest = self.surface_mut(dest_surface_id).ok_or(miss(
                    "RDPGFX_SURFACE_TO_SURFACE_PDU",
                    "unknown destination surface",
                ))?;
                let declared = dest_points.len();
                let mut painted = 0usize;
                let mut done = 0usize;
                for pt in dest_points {
                    if painted >= budget {
                        break;
                    }
                    painted += dest.blit(
                        i32::from(pt.x),
                        i32::from(pt.y),
                        w,
                        h,
                        &pixels,
                        usize::from(w),
                    );
                    done += 1;
                }
                self.frame_paint += painted;
                note_budget("RDPGFX_SURFACE_TO_SURFACE_PDU", declared, done);
            }
            EgfxPdu::SurfaceToCache {
                surface_id,
                cache_key: _,
                cache_slot,
                src_rect,
            } => {
                if self.cache_slot_out_of_range("RDPGFX_SURFACE_TO_CACHE_PDU", cache_slot) {
                    return Ok(());
                }
                let (w, h, rgba) = self
                    .surfaces
                    .iter()
                    .find(|s| s.id == surface_id)
                    .ok_or(miss(
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
                if self.cache_bytes + rgba.len() > self.cache_budget() {
                    return Err(invalid(
                        "RDPGFX_SURFACE_TO_CACHE_PDU",
                        "bitmap cache exceeds the confirmed capset's budget",
                    )
                    .into());
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
                if self.cache_slot_out_of_range("RDPGFX_CACHE_TO_SURFACE_PDU", cache_slot) {
                    return Ok(());
                }
                let budget = MAX_TOTAL_SURFACE_BYTES.saturating_sub(self.frame_paint);
                let entry = self
                    .cache
                    .get(&cache_slot)
                    .ok_or(miss("RDPGFX_CACHE_TO_SURFACE_PDU", "unknown cache slot"))?;
                // Field-level borrows (`cache` immutably, `surfaces` mutably) are disjoint,
                // so the cached pixels blit without a per-apply clone of the whole entry
                // (#84) — the `surface_mut` helper would borrow all of `self` and force it.
                let dest = self
                    .surfaces
                    .iter_mut()
                    .find(|s| s.id == surface_id)
                    .ok_or(miss(
                        "RDPGFX_CACHE_TO_SURFACE_PDU",
                        "unknown destination surface",
                    ))?;
                let declared = dest_points.len();
                let mut painted = 0usize;
                let mut done = 0usize;
                for pt in dest_points {
                    if painted >= budget {
                        break;
                    }
                    painted += dest.blit(
                        i32::from(pt.x),
                        i32::from(pt.y),
                        entry.width,
                        entry.height,
                        &entry.rgba,
                        usize::from(entry.width),
                    );
                    done += 1;
                }
                self.frame_paint += painted;
                note_budget("RDPGFX_CACHE_TO_SURFACE_PDU", declared, done);
            }
            EgfxPdu::EvictCacheEntry { cache_slot } => {
                if self.cache_slot_out_of_range("RDPGFX_EVICT_CACHE_ENTRY_PDU", cache_slot) {
                    return Ok(());
                }
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
        // The paint budget is scoped to a frame, and draw commands do not require one: no arm
        // checks `in_frame` before painting, so a server that never sends StartFrame would sit
        // outside frame-scoped accounting forever. Charging unbracketed painting per *message*
        // closes that without narrowing the frame case. The real server measured for #268 sent
        // 0 unbracketed draws, so this guards a path nothing observed rather than a common one.
        if !self.in_frame {
            self.frame_paint = 0;
        }
        let mut outputs = Vec::new();
        for pdu in egfx::decode_all(blob)? {
            if self.awaiting_confirm {
                if !matches!(pdu, EgfxPdu::CapsConfirm { .. }) {
                    continue;
                }
                self.awaiting_confirm = false;
            }
            match self.handle(pdu, &mut outputs) {
                Ok(()) => {}
                Err(Failure::Fatal(error)) => return Err(error),
                Err(Failure::Miss(error)) if !self.can_reset() => return Err(error),
                Err(Failure::Miss(error)) => {
                    tracing::warn!(
                        target: "rdp_egfx",
                        %error,
                        version = self.confirmed_version,
                        "EGFX channel reset (3.3.5.19)"
                    );
                    self.reset_channel();
                    outputs.push(ProcessorOutput::Send(self.caps_advertise()));
                }
            }
        }
        Ok(outputs)
    }

    /// 3.3.5.19 offers the reset once VERSION103 or later is confirmed; a channel binding
    /// spends at most one.
    fn can_reset(&self) -> bool {
        !self.reset_spent
            && matches!(
                self.confirmed_version,
                Some(
                    egfx::CAPVERSION_103
                        | egfx::CAPVERSION_104
                        | egfx::CAPVERSION_105
                        | egfx::CAPVERSION_106
                        | egfx::CAPVERSION_107
                )
            )
    }

    /// Return the channel to its initial state, keeping the zgfx history, and wait for the
    /// server's confirm.
    fn reset_channel(&mut self) {
        *self = GraphicsProcessor {
            capsets: core::mem::take(&mut self.capsets),
            zgfx: core::mem::take(&mut self.zgfx),
            zgfx_blob: core::mem::take(&mut self.zgfx_blob),
            awaiting_confirm: true,
            reset_spent: true,
            ..GraphicsProcessor::default()
        };
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

impl GraphicsProcessor {
    /// The client's Caps Advertise: what [`DvcProcessor::start`] sends and a reset resends, as a
    /// raw EGFX PDU with no segment header.
    fn caps_advertise(&self) -> Vec<u8> {
        let count = self.capsets.len();
        tracing::debug!(target: "rdp_egfx_caps", count, "EGFX caps advertised");
        egfx::encode_caps_advertise(&self.capsets)
    }

    /// A processor that advertises `config`.
    pub fn new(config: &EgfxConfig) -> Result<Self, EgfxConfigError> {
        Ok(Self {
            capsets: config.capsets()?,
            ..Self::default()
        })
    }

    /// Whether the confirmed capset selected the 16 MB cache (3.3.1.4). Both the byte budget
    /// and the slot maximum read it, so the two cannot disagree about which cache was confirmed.
    fn small_cache(&self) -> bool {
        let small = egfx::CAPS_FLAG_THINCLIENT | egfx::CAPS_FLAG_SMALL_CACHE;
        match self.confirmed_version {
            Some(egfx::CAPVERSION_103) => true,
            Some(_) => self.confirmed_flags & small != 0,
            None => false,
        }
    }

    /// The bitmap-cache size the confirmed capset allows (3.3.1.4).
    fn cache_budget(&self) -> usize {
        if self.small_cache() {
            SMALL_CACHE_BYTES
        } else {
            MAX_CACHE_BYTES
        }
    }

    /// The highest cache slot the confirmed capset allows (3.3.1.4).
    fn max_cache_slot(&self) -> u16 {
        if self.small_cache() {
            SMALL_CACHE_SLOTS
        } else {
            MAX_CACHE_SLOTS
        }
    }

    /// Whether `cache_slot` falls outside 3.3.1.4's one-based range for the confirmed cache.
    /// Out-of-range is warned and the PDU is skipped (ADR-0009 row 4); the check runs before
    /// the cache lookup, so it never becomes the [`Failure::Miss`] an unfilled slot produces.
    fn cache_slot_out_of_range(&self, pdu: &'static str, cache_slot: u16) -> bool {
        let max = self.max_cache_slot();
        let out = cache_slot == 0 || cache_slot > max;
        if out {
            tracing::warn!(
                target: "rdp_egfx",
                pdu,
                cache_slot,
                max,
                "cache slot outside 3.3.1.4's one-based range; the PDU was skipped",
            );
        }
        out
    }
}

impl DvcProcessor for GraphicsProcessor {
    fn channel_name(&self) -> &'static str {
        egfx::CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> Vec<ProcessorOutput> {
        vec![ProcessorOutput::Send(self.caps_advertise())]
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
        *self = GraphicsProcessor {
            capsets: core::mem::take(&mut self.capsets),
            ..GraphicsProcessor::default()
        };
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
        let mut fb =
            Framebuffer::new(256, 256).expect("the test desktop size is within MAX_DESKTOP_DIM");
        let frames = p.flush_frames(&mut fb);
        (fb, frames)
    }

    /// One flushed rect's RGBA pixels, read back out of the framebuffer.
    fn region(fb: &Framebuffer, f: &FrameUpdate) -> Vec<u8> {
        let mut px = vec![0u8; usize::from(f.width) * usize::from(f.height) * 4];
        fb.copy_rect_into(f.x, f.y, f.width, f.height, &mut px)
            .expect("a FrameUpdate this framebuffer produced is in bounds");
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

    /// The ladder stops where the client can meet the obligation, not where the numbers run
    /// out. `[MS-RDPEGFX]` 1.5.1 makes VERSION_105, VERSION_106 and VERSION_107-without-
    /// `SCALEDMAP_DISABLE` a MUST to process `RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU`, and
    /// this client does not — measured: advertising them made a real server confirm 106,
    /// send that command, and paint **zero** frames while the session stayed healthy.
    /// VERSION_101 is absent for the same reason: 1.7 has it imply AVC/H.264 in YUV444v2 mode,
    /// and its reserved bytes leave no `AVC_DISABLED` to decline that with.
    #[test]
    fn the_advertised_ladder_reaches_104_and_stops_there() {
        let mut p = GraphicsProcessor::default();
        let outputs = p.start(11);
        let [Out::Send(message)] = outputs.as_slice() else {
            panic!("expected one send, got {outputs:?}");
        };
        let advertised = |v: u32| message.windows(4).any(|w| w == v.to_le_bytes());
        for v in [
            egfx::CAPVERSION_8,
            egfx::CAPVERSION_8_1,
            egfx::CAPVERSION_10,
            egfx::CAPVERSION_102,
            egfx::CAPVERSION_103,
            egfx::CAPVERSION_104,
        ] {
            assert!(advertised(v), "0x{v:08X} should be advertised");
        }
        assert!(
            !advertised(egfx::CAPVERSION_101),
            "0x000A0100 obliges AVC444v2 this client cannot decode"
        );
        for v in [
            egfx::CAPVERSION_105,
            egfx::CAPVERSION_106,
            egfx::CAPVERSION_106_ERR,
            egfx::CAPVERSION_107,
        ] {
            assert!(
                !advertised(v),
                "0x{v:08X} obliges a scaled map-surface this client cannot honour"
            );
        }
    }

    /// The capsets a Caps Advertise carries, as `(version, capsData)` in wire order.
    fn advertised_capsets(message: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let count = u16::from_le_bytes(message[8..10].try_into().unwrap());
        let mut at = 10;
        let mut capsets = Vec::new();
        for _ in 0..count {
            let version = u32::from_le_bytes(message[at..at + 4].try_into().unwrap());
            let len = u32::from_le_bytes(message[at + 4..at + 8].try_into().unwrap()) as usize;
            capsets.push((version, message[at + 8..at + 8 + len].to_vec()));
            at += 8 + len;
        }
        assert_eq!(at, message.len(), "the advertise holds exactly its capsets");
        capsets
    }

    fn started(config: &EgfxConfig) -> Vec<(u32, Vec<u8>)> {
        let mut p = GraphicsProcessor::new(config).expect("a valid config");
        let outputs = p.start(11);
        let [Out::Send(message)] = outputs.as_slice() else {
            panic!("expected one send, got {outputs:?}");
        };
        advertised_capsets(message)
    }

    fn flags_of(capsets: &[(u32, Vec<u8>)]) -> Vec<(u32, Option<u32>)> {
        capsets
            .iter()
            .map(|(version, data)| {
                let flags =
                    (data.len() == 4).then(|| u32::from_le_bytes(data[..].try_into().unwrap()));
                (*version, flags)
            })
            .collect()
    }

    #[test]
    fn a_config_naming_versions_advertises_only_those() {
        let config = EgfxConfig {
            versions: Some(vec![egfx::CAPVERSION_104, egfx::CAPVERSION_10]),
            ..EgfxConfig::default()
        };
        assert_eq!(
            flags_of(&started(&config)),
            vec![
                (egfx::CAPVERSION_10, Some(egfx::CAPS_FLAG_AVC_DISABLED)),
                (egfx::CAPVERSION_104, Some(egfx::CAPS_FLAG_AVC_DISABLED)),
            ]
        );
    }

    #[test]
    fn the_default_config_advertises_the_default_ladder() {
        let avc_off = Some(egfx::CAPS_FLAG_AVC_DISABLED);
        assert_eq!(
            flags_of(&started(&EgfxConfig::default())),
            vec![
                (egfx::CAPVERSION_8, Some(0)),
                (egfx::CAPVERSION_8_1, Some(0)),
                (egfx::CAPVERSION_10, avc_off),
                (egfx::CAPVERSION_102, avc_off),
                (egfx::CAPVERSION_103, avc_off),
                (egfx::CAPVERSION_104, avc_off),
            ]
        );
    }

    #[test]
    fn a_version_the_client_cannot_honour_is_refused() {
        for version in [
            egfx::CAPVERSION_105,
            egfx::CAPVERSION_106,
            egfx::CAPVERSION_106_ERR,
            egfx::CAPVERSION_107,
            egfx::CAPVERSION_101,
            0xDEAD_BEEF,
        ] {
            let config = EgfxConfig {
                versions: Some(vec![egfx::CAPVERSION_104, version]),
                ..EgfxConfig::default()
            };
            assert_eq!(
                GraphicsProcessor::new(&config).err(),
                Some(EgfxConfigError::NotAdvertisable(version))
            );
        }
    }

    /// 3.3.5.18: *"one or more of the capability sets"*, and *"Each capability set type MUST NOT
    /// appear more than once."*
    #[test]
    fn an_empty_or_repeated_version_list_is_refused() {
        let empty = EgfxConfig {
            versions: Some(Vec::new()),
            ..EgfxConfig::default()
        };
        assert_eq!(
            GraphicsProcessor::new(&empty).err(),
            Some(EgfxConfigError::Empty)
        );
        let repeated = EgfxConfig {
            versions: Some(vec![
                egfx::CAPVERSION_10,
                egfx::CAPVERSION_8,
                egfx::CAPVERSION_10,
            ]),
            ..EgfxConfig::default()
        };
        assert_eq!(
            GraphicsProcessor::new(&repeated).err(),
            Some(EgfxConfigError::Duplicate(egfx::CAPVERSION_10))
        );
    }

    /// Each flag goes only where 2.2.3 defines it for that version: SMALL_CACHE is absent from
    /// 10.3 (whose selection implies the small cache, 3.3.1.4), and
    /// THINCLIENT exists only on 8 and 8.1, so a thin client asks for the small cache above them.
    #[test]
    fn the_cache_mode_sets_each_flag_only_where_its_version_defines_it() {
        let avc_off = egfx::CAPS_FLAG_AVC_DISABLED;
        let small = egfx::CAPS_FLAG_SMALL_CACHE;
        let thin = egfx::CAPS_FLAG_THINCLIENT;
        for (cache, v8, above) in [
            (EgfxCacheMode::Small, small, small),
            (EgfxCacheMode::ThinClient, thin, small),
        ] {
            let config = EgfxConfig {
                cache,
                ..EgfxConfig::default()
            };
            assert_eq!(
                flags_of(&started(&config)),
                vec![
                    (egfx::CAPVERSION_8, Some(v8)),
                    (egfx::CAPVERSION_8_1, Some(v8)),
                    (egfx::CAPVERSION_10, Some(avc_off | above)),
                    (egfx::CAPVERSION_102, Some(avc_off | above)),
                    (egfx::CAPVERSION_103, Some(avc_off)),
                    (egfx::CAPVERSION_104, Some(avc_off | above)),
                ],
                "{cache:?}"
            );
        }
    }

    /// The configured ladder is what a 3.3.5.19 reset and a reopened channel advertise too.
    #[test]
    fn a_reset_and_a_reopened_channel_advertise_the_configured_ladder() {
        let config = EgfxConfig {
            versions: Some(vec![egfx::CAPVERSION_104]),
            cache: EgfxCacheMode::Small,
        };
        let mut p = GraphicsProcessor::new(&config).unwrap();
        let opening = p.start(0);
        assert_eq!(
            opening,
            vec![Out::Send(egfx::encode_caps_advertise(&[
                egfx::CapSet::Flags {
                    version: egfx::CAPVERSION_104,
                    flags: egfx::CAPS_FLAG_AVC_DISABLED | egfx::CAPS_FLAG_SMALL_CACHE,
                }
            ]))]
        );
        feed(
            &mut p,
            egfx::CMDID_CAPS_CONFIRM,
            &caps_confirm_body(egfx::CAPVERSION_104),
        );
        let outputs = feed(
            &mut p,
            egfx::CMDID_CACHE_TO_SURFACE,
            &cache_to_surface_body(9, 1),
        );
        assert_eq!(
            outputs, opening,
            "the reset re-advertises the configured ladder"
        );

        p.close();
        assert_eq!(p.start(0), opening, "a reopened channel advertises it");
    }

    /// 3.3.1.4: the bitmap cache is 16 MB when the confirmed capset is 10.3, or when it carries
    /// THINCLIENT or SMALL_CACHE; 100 MB otherwise.
    #[test]
    fn the_cache_budget_follows_the_confirmed_capset() {
        // 2048x2049 RGBA is 8 KiB past 16 MiB.
        let over_16_mib = |version: u32, flags: u32| {
            let mut p = GraphicsProcessor::default();
            let confirm = [
                version.to_le_bytes(),
                4u32.to_le_bytes(),
                flags.to_le_bytes(),
            ]
            .concat();
            feed(&mut p, egfx::CMDID_CAPS_CONFIRM, &confirm);
            create_surface(&mut p, 1, 2048, 2049);
            let mut body = Vec::new();
            body.extend_from_slice(&1u16.to_le_bytes());
            body.extend_from_slice(&0u64.to_le_bytes());
            body.extend_from_slice(&5u16.to_le_bytes());
            for v in [0u16, 0, 2048, 2049] {
                body.extend_from_slice(&v.to_le_bytes());
            }
            let message = egfx::wrap_uncompressed(&header(egfx::CMDID_SURFACE_TO_CACHE, &body));
            p.process(&message).is_ok()
        };
        assert!(over_16_mib(egfx::CAPVERSION_104, 0), "100 MB at 10.4");
        assert!(over_16_mib(egfx::CAPVERSION_8, 0), "100 MB at 8");
        assert!(
            !over_16_mib(egfx::CAPVERSION_103, 0),
            "16 MB at 10.3, flags or not"
        );
        assert!(
            !over_16_mib(egfx::CAPVERSION_104, egfx::CAPS_FLAG_SMALL_CACHE),
            "16 MB with SMALL_CACHE"
        );
        assert!(
            !over_16_mib(egfx::CAPVERSION_8, egfx::CAPS_FLAG_THINCLIENT),
            "16 MB with THINCLIENT"
        );
    }

    /// 3.3.1.4: a bitmap is stored in "a variable-length slot (identified by a one-based slot
    /// index)", and "the maximum possible number of variable-length slots is 25,600 in the case
    /// of a 100 MB cache and 4,096 in the case of a 16 MB cache". A slot outside that range is
    /// skipped and the session continues (ADR-0009 row 4).
    #[test]
    fn a_cache_slot_outside_3_3_1_4s_range_is_skipped() {
        let mut p = confirmed(egfx::CAPVERSION_104);
        for slot in [0u16, 25_601, u16::MAX] {
            feed(
                &mut p,
                egfx::CMDID_SURFACE_TO_CACHE,
                &surface_to_cache_body(1, slot, 8, 8),
            );
            assert!(p.cache.is_empty(), "slot {slot} must not be stored");
            assert_eq!(p.cache_bytes, 0, "slot {slot} must not be charged");
        }
        for slot in [1u16, 25_600] {
            feed(
                &mut p,
                egfx::CMDID_SURFACE_TO_CACHE,
                &surface_to_cache_body(1, slot, 8, 8),
            );
            assert!(p.cache.contains_key(&slot), "slot {slot} is in range");
        }
    }

    /// The slot maximum and the byte budget are the same derivation off the confirmed capset,
    /// so the two cannot disagree about which cache size was confirmed.
    #[test]
    fn the_cache_slot_maximum_follows_the_confirmed_capset() {
        let stored = |version: u32, flags: u32, slot: u16| {
            let mut p = GraphicsProcessor::default();
            let confirm = [
                version.to_le_bytes(),
                4u32.to_le_bytes(),
                flags.to_le_bytes(),
            ]
            .concat();
            feed(&mut p, egfx::CMDID_CAPS_CONFIRM, &confirm);
            create_surface(&mut p, 1, 8, 8);
            feed(
                &mut p,
                egfx::CMDID_SURFACE_TO_CACHE,
                &surface_to_cache_body(1, slot, 8, 8),
            );
            p.cache.contains_key(&slot)
        };
        assert!(stored(egfx::CAPVERSION_103, 0, 4_096), "4096 fits 16 MB");
        assert!(
            !stored(egfx::CAPVERSION_103, 0, 4_097),
            "4097 is past the 16 MB cache's slots"
        );
        assert!(
            !stored(egfx::CAPVERSION_104, egfx::CAPS_FLAG_SMALL_CACHE, 4_097),
            "SMALL_CACHE narrows the slots as it narrows the bytes"
        );
        assert!(
            !stored(egfx::CAPVERSION_8, egfx::CAPS_FLAG_THINCLIENT, 4_097),
            "THINCLIENT narrows the slots as it narrows the bytes"
        );
        assert!(
            stored(egfx::CAPVERSION_104, 0, 4_097),
            "the 100 MB cache reaches past 4096"
        );
        assert!(
            !stored(egfx::CAPVERSION_104, 0, 25_601),
            "25601 is past the 100 MB cache's slots"
        );
    }

    /// The slot range must not skip what a real server sends. Measured against the WS2022 VM on
    /// 2026-09-18, four runs and 9 965 observations: slots are a plain counter from **2**,
    /// contiguous and strictly increasing, never reused and never evicted, and the highest seen
    /// was **216** — in the run that confirmed 10.3, whose 4 096 is the tighter of the two
    /// bounds. So the guard sits ~19x above the traffic it has to let through, and this pins
    /// that: narrowing either constant under observed traffic reddens here rather than in the
    /// field.
    #[test]
    fn the_slot_range_does_not_reach_the_slots_the_real_server_sends() {
        let mut p = GraphicsProcessor::default();
        let confirm = [
            egfx::CAPVERSION_103.to_le_bytes(),
            4u32.to_le_bytes(),
            0u32.to_le_bytes(),
        ]
        .concat();
        feed(&mut p, egfx::CMDID_CAPS_CONFIRM, &confirm);
        create_surface(&mut p, 1, 8, 8);
        for slot in 2u16..=216 {
            feed(
                &mut p,
                egfx::CMDID_SURFACE_TO_CACHE,
                &surface_to_cache_body(1, slot, 8, 8),
            );
        }
        assert_eq!(
            p.cache.len(),
            215,
            "every slot the real server was seen to use must be stored, none skipped"
        );
        assert!(
            p.max_cache_slot() >= 216,
            "the 16 MB cache's slot bound still clears observed traffic"
        );
    }

    /// Before any Caps Confirm the 100 MB default applies to the slots as it does to the bytes.
    #[test]
    fn the_slot_maximum_defaults_to_the_100_mb_cache_before_any_confirm() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 8, 8);
        feed(
            &mut p,
            egfx::CMDID_SURFACE_TO_CACHE,
            &surface_to_cache_body(1, 25_600, 8, 8),
        );
        assert!(
            p.cache.contains_key(&25_600),
            "the pre-confirm default is 100 MB"
        );
        feed(
            &mut p,
            egfx::CMDID_SURFACE_TO_CACHE,
            &surface_to_cache_body(1, 25_601, 8, 8),
        );
        assert!(!p.cache.contains_key(&25_601), "and it still has a maximum");
    }

    /// The range check is **not** a semantic miss: it runs before the lookup, so an
    /// out-of-range slot skips rather than taking 3.3.5.19's reset. The in-range unfilled slot
    /// keeps taking the reset — that contrast is the whole point of the ordering.
    #[test]
    fn an_out_of_range_paste_skips_where_an_unfilled_one_resets() {
        let mut p = confirmed(egfx::CAPVERSION_104);
        let outputs = feed(
            &mut p,
            egfx::CMDID_CACHE_TO_SURFACE,
            &cache_to_surface_body(0, 1),
        );
        assert!(outputs.is_empty(), "an out-of-range paste sends nothing");
        assert_eq!(
            p.confirmed_version,
            Some(egfx::CAPVERSION_104),
            "and the channel is not reset"
        );

        let outputs = feed(
            &mut p,
            egfx::CMDID_CACHE_TO_SURFACE,
            &cache_to_surface_body(9, 1),
        );
        assert_eq!(
            outputs,
            vec![advertise()],
            "an unfilled in-range slot resets"
        );
    }

    /// An evict naming a slot outside the range frees nothing — which was **already** true
    /// before the range check, because the fill path is what keeps such a slot from ever being
    /// occupied. So this asserts the in-range behaviour and the absence of collateral damage;
    /// the guard's own effect on this PDU is the `rdp_egfx` warn, and this crate has no
    /// tracing-assertion facility to reach it (neither does #268's row-3 warn).
    #[test]
    fn an_out_of_range_evict_frees_nothing_and_an_in_range_one_still_works() {
        let mut p = confirmed(egfx::CAPVERSION_104);
        feed(
            &mut p,
            egfx::CMDID_SURFACE_TO_CACHE,
            &surface_to_cache_body(1, 1, 8, 8),
        );
        let charged = p.cache_bytes;
        assert!(charged > 0, "the cache was filled");

        for slot in [0u16, 25_601] {
            feed(&mut p, egfx::CMDID_EVICT_CACHE_ENTRY, &evict_body(slot));
        }
        assert!(
            p.cache.contains_key(&1),
            "an out-of-range evict frees nothing"
        );
        assert_eq!(p.cache_bytes, charged, "and charges nothing back");

        feed(&mut p, egfx::CMDID_EVICT_CACHE_ENTRY, &evict_body(1));
        assert!(p.cache.is_empty(), "an in-range evict still works");
        assert_eq!(p.cache_bytes, 0);
    }

    /// 3.3.5.19: *"If the capability set received in capsSet field ... is not specified in
    /// section 2.2.3, the client MUST ignore the capability set."* Storing it would make a
    /// version we never advertised, and cannot honour, the one the rest of the channel
    /// adheres to.
    #[test]
    fn a_confirm_naming_a_version_outside_2_2_3_is_ignored() {
        let mut p = GraphicsProcessor::default();
        let mut body = Vec::new();
        body.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        assert!(feed(&mut p, egfx::CMDID_CAPS_CONFIRM, &body).is_empty());
        assert_eq!(p.confirmed_version, None);
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

    fn caps_confirm_body(version: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&version.to_le_bytes());
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body
    }

    fn cache_to_surface_body(slot: u16, surface: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&slot.to_le_bytes());
        body.extend_from_slice(&surface.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&[0, 0, 0, 0]);
        body
    }

    fn surface_to_cache_body(surface: u16, slot: u16, w: u16, h: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&surface.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&slot.to_le_bytes());
        for v in [0u16, 0, w, h] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body
    }

    fn evict_body(slot: u16) -> Vec<u8> {
        slot.to_le_bytes().to_vec()
    }

    fn create_surface_body(id: u16, w: u16, h: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(&w.to_le_bytes());
        body.extend_from_slice(&h.to_le_bytes());
        body.push(egfx::PIXEL_FORMAT_XRGB_8888);
        body
    }

    /// Several PDUs in one uncompressed message, as one `process` call.
    fn feed_blob(
        p: &mut GraphicsProcessor,
        pdus: &[(u16, Vec<u8>)],
    ) -> Result<Vec<Out>, DecodeError> {
        let mut blob = Vec::new();
        for (cmd_id, body) in pdus {
            blob.extend_from_slice(&header(*cmd_id, body));
        }
        p.process(&egfx::wrap_uncompressed(&blob))
    }

    fn advertise() -> Out {
        GraphicsProcessor::default().start(0).remove(0)
    }

    /// A processor whose server confirmed `version`, with surface 1 (8x8) created.
    fn confirmed(version: u32) -> GraphicsProcessor {
        let mut p = GraphicsProcessor::default();
        feed(
            &mut p,
            egfx::CMDID_CAPS_CONFIRM,
            &caps_confirm_body(version),
        );
        create_surface(&mut p, 1, 8, 8);
        p
    }

    /// 3.3.5.19: from a confirmed 10.3 the client "can resend the RDPGFX_CAPS_ADVERTISE_PDU
    /// message during the connection to reset the protocol". A semantic miss — here a
    /// `CacheToSurface` naming a slot never filled — takes that rung instead of failing.
    /// Outputs produced earlier in the same message (the frame acknowledgement) are kept and
    /// precede the advertise, which is the one [`DvcProcessor::start`] sends.
    #[test]
    fn a_semantic_miss_at_10_4_resends_the_advertise_instead_of_failing() {
        let mut p = confirmed(egfx::CAPVERSION_104);
        let outputs = feed_blob(
            &mut p,
            &[
                (egfx::CMDID_START_FRAME, vec![0; 8]),
                (egfx::CMDID_END_FRAME, vec![0; 4]),
                (egfx::CMDID_CACHE_TO_SURFACE, cache_to_surface_body(9, 1)),
            ],
        )
        .expect("a miss at 10.4 is recovered, not returned");
        assert_eq!(
            outputs,
            vec![Out::Send(egfx::encode_frame_acknowledge(0, 1)), advertise()]
        );
        assert!(p.surfaces.is_empty(), "the channel state is reset");
        assert_eq!(
            p.confirmed_version, None,
            "nothing is confirmed until the new confirm"
        );
    }

    /// 3.3.5.19: the client "MUST ignore any messages sent by the server until
    /// RDPGFX_CAPS_CONFIRM_PDU message is received" — per PDU, so a confirm sharing a message
    /// with what follows it lets what follows through.
    #[test]
    fn until_the_confirm_every_server_pdu_is_ignored() {
        let mut p = confirmed(egfx::CAPVERSION_104);
        feed(
            &mut p,
            egfx::CMDID_CACHE_TO_SURFACE,
            &cache_to_surface_body(9, 1),
        );
        let outputs = feed_blob(
            &mut p,
            &[
                (egfx::CMDID_CREATE_SURFACE, create_surface_body(2, 8, 8)),
                (egfx::CMDID_START_FRAME, vec![0; 8]),
                (egfx::CMDID_END_FRAME, vec![0; 4]),
                (
                    egfx::CMDID_CAPS_CONFIRM,
                    caps_confirm_body(egfx::CAPVERSION_104),
                ),
                (egfx::CMDID_CREATE_SURFACE, create_surface_body(3, 8, 8)),
            ],
        )
        .unwrap();
        assert!(
            outputs.is_empty(),
            "an ignored EndFrame is not acknowledged"
        );
        let ids: Vec<u16> = p.surfaces.iter().map(|s| s.id).collect();
        assert_eq!(ids, vec![3]);
        assert_eq!(p.confirmed_version, Some(egfx::CAPVERSION_104));
    }

    /// A confirm naming a version outside 2.2.3 is ignored as a capability set but still ends
    /// the wait: waiting for one this client would store would leave the channel ignoring the
    /// server for the rest of the session.
    #[test]
    fn a_confirm_outside_2_2_3_still_ends_the_wait() {
        let mut p = confirmed(egfx::CAPVERSION_104);
        feed(
            &mut p,
            egfx::CMDID_CACHE_TO_SURFACE,
            &cache_to_surface_body(9, 1),
        );
        feed(
            &mut p,
            egfx::CMDID_CAPS_CONFIRM,
            &caps_confirm_body(0xDEAD_BEEF),
        );
        create_surface(&mut p, 4, 8, 8);
        assert_eq!(p.surfaces.len(), 1);
        assert_eq!(p.confirmed_version, None);
    }

    /// 3.3.5.19 offers the resend from VERSION103 upward only; below it, and with no confirm at
    /// all, a miss still ends the session (ADR-0014 Decision 1).
    #[test]
    fn below_10_3_a_miss_still_fails() {
        for version in [None, Some(egfx::CAPVERSION_8), Some(egfx::CAPVERSION_102)] {
            let mut p = GraphicsProcessor::default();
            if let Some(v) = version {
                feed(&mut p, egfx::CMDID_CAPS_CONFIRM, &caps_confirm_body(v));
            }
            create_surface(&mut p, 1, 8, 8);
            assert!(
                feed_blob(
                    &mut p,
                    &[(egfx::CMDID_CACHE_TO_SURFACE, cache_to_surface_body(9, 1))]
                )
                .is_err(),
                "confirmed {version:?} cannot reset"
            );
        }
        for version in [
            egfx::CAPVERSION_103,
            egfx::CAPVERSION_104,
            egfx::CAPVERSION_105,
            egfx::CAPVERSION_106,
            egfx::CAPVERSION_107,
        ] {
            let mut p = confirmed(version);
            assert_eq!(
                feed_blob(
                    &mut p,
                    &[(egfx::CMDID_CACHE_TO_SURFACE, cache_to_surface_body(9, 1))]
                ),
                Ok(vec![advertise()]),
                "confirmed 0x{version:08X} can reset"
            );
        }
    }

    /// One reset per channel binding: a second miss after the new confirm fails, so a miss the
    /// server reproduces after every reset cannot loop.
    #[test]
    fn a_second_miss_after_a_reset_fails() {
        let mut p = confirmed(egfx::CAPVERSION_104);
        feed(
            &mut p,
            egfx::CMDID_CACHE_TO_SURFACE,
            &cache_to_surface_body(9, 1),
        );
        feed(
            &mut p,
            egfx::CMDID_CAPS_CONFIRM,
            &caps_confirm_body(egfx::CAPVERSION_104),
        );
        create_surface(&mut p, 1, 8, 8);
        assert!(
            feed_blob(
                &mut p,
                &[(egfx::CMDID_CACHE_TO_SURFACE, cache_to_surface_body(9, 1))]
            )
            .is_err()
        );
        // A new binding starts with a fresh allowance.
        p.close();
        let mut p2 = p;
        feed(
            &mut p2,
            egfx::CMDID_CAPS_CONFIRM,
            &caps_confirm_body(egfx::CAPVERSION_104),
        );
        assert_eq!(
            feed_blob(
                &mut p2,
                &[(egfx::CMDID_CACHE_TO_SURFACE, cache_to_surface_body(9, 1))]
            ),
            Ok(vec![advertise()])
        );
    }

    /// Which failures take the reset rung (ADR-0014, 2026-09-17 amendment): references to state
    /// this client does not hold, and an uncompressed payload that does not decode. Every other
    /// failure still ends the session, at 10.4 as below it.
    #[test]
    fn only_semantic_misses_take_the_reset() {
        let wts1 = |surface: u16, codec: u16, rect: (u16, u16, u16, u16), data: &[u8]| {
            let mut b = Vec::new();
            b.extend_from_slice(&surface.to_le_bytes());
            b.extend_from_slice(&codec.to_le_bytes());
            b.push(egfx::PIXEL_FORMAT_XRGB_8888);
            for v in [rect.0, rect.1, rect.2, rect.3] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b.extend_from_slice(&(data.len() as u32).to_le_bytes());
            b.extend_from_slice(data);
            b
        };
        let s2s = |src: u16, dst: u16| {
            let mut b = Vec::new();
            b.extend_from_slice(&src.to_le_bytes());
            b.extend_from_slice(&dst.to_le_bytes());
            b.extend_from_slice(&[0, 0, 0, 0, 2, 0, 2, 0]);
            b.extend_from_slice(&1u16.to_le_bytes());
            b.extend_from_slice(&[0, 0, 0, 0]);
            b
        };
        let s2c = |surface: u16| {
            let mut b = Vec::new();
            b.extend_from_slice(&surface.to_le_bytes());
            b.extend_from_slice(&0u64.to_le_bytes());
            b.extend_from_slice(&5u16.to_le_bytes());
            b.extend_from_slice(&[0, 0, 0, 0, 2, 0, 2, 0]);
            b
        };
        let mut wts2 = Vec::new();
        wts2.extend_from_slice(&7u16.to_le_bytes());
        wts2.extend_from_slice(&egfx::CODECID_CAPROGRESSIVE.to_le_bytes());
        wts2.extend_from_slice(&1u32.to_le_bytes());
        wts2.push(egfx::PIXEL_FORMAT_XRGB_8888);
        wts2.extend_from_slice(&0u32.to_le_bytes());

        let misses: [(&str, u16, Vec<u8>); 9] = [
            (
                "WTS1 unknown surface",
                egfx::CMDID_WIRE_TO_SURFACE_1,
                wts1(7, egfx::CODECID_UNCOMPRESSED, (0, 0, 1, 1), &[0; 4]),
            ),
            (
                "WTS1 uncompressed too short",
                egfx::CMDID_WIRE_TO_SURFACE_1,
                wts1(1, egfx::CODECID_UNCOMPRESSED, (0, 0, 2, 2), &[0; 4]),
            ),
            ("WTS2 unknown surface", egfx::CMDID_WIRE_TO_SURFACE_2, wts2),
            (
                "SolidFill unknown surface",
                egfx::CMDID_SOLID_FILL,
                solid_fill_body(7, [0; 4], [0, 0, 1, 1]),
            ),
            (
                "SurfaceToSurface unknown source",
                egfx::CMDID_SURFACE_TO_SURFACE,
                s2s(7, 1),
            ),
            (
                "SurfaceToSurface unknown destination",
                egfx::CMDID_SURFACE_TO_SURFACE,
                s2s(1, 7),
            ),
            (
                "SurfaceToCache unknown surface",
                egfx::CMDID_SURFACE_TO_CACHE,
                s2c(7),
            ),
            (
                "CacheToSurface unknown slot",
                egfx::CMDID_CACHE_TO_SURFACE,
                cache_to_surface_body(9, 1),
            ),
            (
                "CacheToSurface unknown surface",
                egfx::CMDID_CACHE_TO_SURFACE,
                cache_to_surface_body(5, 7),
            ),
        ];
        for (name, cmd_id, body) in misses {
            let mut p = confirmed(egfx::CAPVERSION_104);
            feed(&mut p, egfx::CMDID_SURFACE_TO_CACHE, &s2c(1));
            assert_eq!(
                feed_blob(&mut p, &[(cmd_id, body)]),
                Ok(vec![advertise()]),
                "{name} should take the reset"
            );
        }

        let mut reset_graphics = vec![0u8; 332];
        reset_graphics[..4].copy_from_slice(&70_000u32.to_le_bytes());
        reset_graphics[4..8].copy_from_slice(&600u32.to_le_bytes());
        let fatals: [(&str, u16, Vec<u8>); 4] = [
            (
                "CreateSurface out of bounds",
                egfx::CMDID_CREATE_SURFACE,
                create_surface_body(2, 0, 8),
            ),
            (
                "ResetGraphics wider than u16",
                egfx::CMDID_RESET_GRAPHICS,
                reset_graphics,
            ),
            (
                "WTS1 rectangle no surface could hold",
                egfx::CMDID_WIRE_TO_SURFACE_1,
                wts1(1, egfx::CODECID_UNCOMPRESSED, (0, 0, 65535, 65535), &[]),
            ),
            ("framing", egfx::CMDID_START_FRAME, vec![0; 2]),
        ];
        for (name, cmd_id, body) in fatals {
            let mut p = confirmed(egfx::CAPVERSION_104);
            assert!(
                feed_blob(&mut p, &[(cmd_id, body)]).is_err(),
                "{name} should still fail"
            );
        }
    }

    /// The server keeps its zgfx history across the reset (measured, #272), so the client must
    /// too: a message after the reset whose only token is a back-reference into bytes written
    /// before it decodes to the confirm. With a fresh window it would decode to zeroes, which
    /// fail as framing.
    #[test]
    fn the_zgfx_history_survives_a_reset() {
        let mut p = GraphicsProcessor::default();
        let confirm = header(
            egfx::CMDID_CAPS_CONFIRM,
            &caps_confirm_body(egfx::CAPVERSION_104),
        );
        let miss = header(egfx::CMDID_CACHE_TO_SURFACE, &cache_to_surface_body(9, 1));
        assert_eq!((confirm.len(), miss.len()), (20, 18));
        let mut first = confirm.clone();
        first.extend_from_slice(&miss);
        assert_eq!(
            p.process(&egfx::wrap_uncompressed(&first)),
            Ok(vec![advertise()])
        );
        // One match token: 10010 (7 value bits, base 32) 0000110 (distance 38), then the length
        // 20 as 1110 (k = 3) 0100 (16 + 4) — 20 bits, 4 unused.
        let second = [0xE0, 0x24, 0b1001_0000, 0b0110_1110, 0b0100_0000, 0x04];
        assert_eq!(p.process(&second), Ok(vec![]));
        assert_eq!(p.confirmed_version, Some(egfx::CAPVERSION_104));
    }

    /// The server resets its ClearCodec glyph and V-bar state across the reset (measured,
    /// #272: kept caches painted wrong glyphs), so the client must too: a glyph hit after the
    /// reset on an index stored before it misses and paints nothing.
    #[test]
    fn clearcodec_glyphs_do_not_survive_a_reset() {
        let clear = |surface: u16, stream: &[u8]| {
            let mut b = Vec::new();
            b.extend_from_slice(&surface.to_le_bytes());
            b.extend_from_slice(&egfx::CODECID_CLEARCODEC.to_le_bytes());
            b.push(egfx::PIXEL_FORMAT_XRGB_8888);
            for v in [0u16, 0, 4, 4] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b.extend_from_slice(&(stream.len() as u32).to_le_bytes());
            b.extend_from_slice(stream);
            b
        };
        // Store glyph 7: a 4x4 white residual run. Then hit it.
        let mut store = vec![0x01, 0, 7, 0];
        store.extend_from_slice(&4u32.to_le_bytes());
        store.extend_from_slice(&0u32.to_le_bytes());
        store.extend_from_slice(&0u32.to_le_bytes());
        store.extend_from_slice(&[0xFF, 0xFF, 0xFF, 16]);
        let hit = [0x03, 1, 7, 0];
        let white_at_origin = |p: &mut GraphicsProcessor| {
            map_surface(p, 1, 0, 0);
            let (fb, _) = flush(p);
            region(
                &fb,
                &FrameUpdate {
                    x: 0,
                    y: 0,
                    width: 1,
                    height: 1,
                },
            ) == [255, 255, 255, 255]
        };

        let mut p = confirmed(egfx::CAPVERSION_104);
        feed(&mut p, egfx::CMDID_WIRE_TO_SURFACE_1, &clear(1, &store));
        feed(
            &mut p,
            egfx::CMDID_SOLID_FILL,
            &solid_fill_body(1, [0; 4], [0, 0, 4, 4]),
        );
        feed(&mut p, egfx::CMDID_WIRE_TO_SURFACE_1, &clear(1, &hit));
        assert!(
            white_at_origin(&mut p),
            "the hit paints the stored glyph before a reset"
        );

        feed(
            &mut p,
            egfx::CMDID_CACHE_TO_SURFACE,
            &cache_to_surface_body(9, 1),
        );
        feed(
            &mut p,
            egfx::CMDID_CAPS_CONFIRM,
            &caps_confirm_body(egfx::CAPVERSION_104),
        );
        create_surface(&mut p, 1, 8, 8);
        feed(&mut p, egfx::CMDID_WIRE_TO_SURFACE_1, &clear(1, &hit));
        assert!(
            !white_at_origin(&mut p),
            "the glyph did not survive the reset"
        );
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
        assert!(
            fill.as_chunks::<4>()
                .0
                .iter()
                .all(|p| *p == [255, 0, 0, 255])
        );
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
        assert!(px.as_chunks::<4>().0.iter().all(|p| *p == [0, 255, 0, 255]));
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

    /// `[MS-RDPEGFX]` 2.2.1.2 bounds a `RDPGFX_RECT16`'s four fields at `u16` and states nothing
    /// else — no maximum, no non-zero requirement, no ordering rule — and 2.2.2.1 makes the
    /// rectangle *"the dimensions of the bitmap data encapsulated in the bitmapData field"*. So on
    /// any arm whose codec **expands** its input, the rectangle alone decides the output size, and
    /// 65535 x 65535 x 4 is 17_179_344_900 bytes. Measured before this guard (#263), driving the
    /// CAVIDEO arm with a **93-byte** tileset:
    ///
    /// | target | before |
    /// |---|---|
    /// | `i686-pc-windows-msvc` | panic in `rfx::opaque_black`, *attempt to multiply with overflow* |
    /// | `x86_64-pc-windows-msvc` | `Ok`, 16 GiB allocated, 18.9 s, no error — 93 bytes in |
    ///
    /// **The second row is why the guard bounds the rectangle instead of only checking the
    /// arithmetic.** #263 proposed a `checked_mul`; that closes the target which already failed
    /// loudly and cannot see the one that quietly serves the allocation, because on 64-bit the
    /// product does not overflow. Both references reach the same place from the other side:
    /// FreeRDP's `is_within_surface` (`gdi/gfx.c:386`) refuses *before* its `1ull * bpp * w * h`
    /// at `:390`, and `ironrdp-egfx` checks the same condition and only `warn!`s.
    ///
    /// The boundary case pins that it is a bound and not a rejection of large rectangles: at
    /// exactly `MAX_SURFACE_DIM` the PDU is admitted and fails on its *own* short payload.
    #[test]
    fn a_destination_rectangle_no_surface_could_hold_is_refused_before_any_decode() {
        fn wts1(codec_id: u16, right: u16, bottom: u16, data: &[u8]) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&1u16.to_le_bytes()); // surfaceId
            body.extend_from_slice(&codec_id.to_le_bytes());
            body.push(egfx::PIXEL_FORMAT_XRGB_8888);
            for v in [0u16, 0, right, bottom] {
                body.extend_from_slice(&v.to_le_bytes());
            }
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(data);
            body
        }

        // The CAVIDEO arm: a valid tileset, so the decode is actually entered. This is the case
        // that allocated 16 GiB on x86-64 and panicked on i686.
        let payload = cavideo_payload(&[0x00; 8]);
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 64, 64);
        let message = egfx::wrap_uncompressed(&header(
            egfx::CMDID_WIRE_TO_SURFACE_1,
            &wts1(egfx::CODECID_CAVIDEO, u16::MAX, u16::MAX, &payload),
        ));
        assert!(
            p.process(&message).is_err(),
            "a maximal destRect must be refused before the codec is reached"
        );

        // The uncompressed arm reaches the same refusal, and reaches it at the same place —
        // above the `match`, so no arm can be added that quietly skips it.
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 64, 64);
        let message = egfx::wrap_uncompressed(&header(
            egfx::CMDID_WIRE_TO_SURFACE_1,
            &wts1(egfx::CODECID_UNCOMPRESSED, u16::MAX, u16::MAX, &[0xAB; 16]),
        ));
        assert!(p.process(&message).is_err());

        // Not a rejection of large rectangles. `MAX_TOTAL_SURFACE_BYTES` is 256 MiB, so the
        // widest admitted square is 8192 x 8192 (exactly 268_435_456 bytes of RGBA): at the cap
        // the bound admits the PDU and the *payload* is what fails, and one pixel past it the
        // bound is what fails. Both outcomes are `Err`, so `is_err()` cannot tell them apart —
        // the assertion has to name which error, or an off-by-one is invisible. Measured: it
        // was. Written first as a direct `decode_wts1` call, this stayed green under a
        // `>` -> `>=` mutation, because a direct call does not pass the call site the bound
        // lives at. It goes through `process` for that reason.
        let at = |right: u16, bottom: u16| {
            let mut p = GraphicsProcessor::default();
            create_surface(&mut p, 1, 64, 64);
            let message = egfx::wrap_uncompressed(&header(
                egfx::CMDID_WIRE_TO_SURFACE_1,
                &wts1(egfx::CODECID_UNCOMPRESSED, right, bottom, &[0xAB; 16]),
            ));
            p.process(&message).unwrap_err()
        };
        assert_eq!(
            at(8192, 8192),
            invalid(
                "RDPGFX_WIRE_TO_SURFACE_PDU_1",
                "uncompressed data shorter than the destination rectangle"
            ),
            "at the cap the rectangle is admitted and the short payload is what fails"
        );
        assert_eq!(
            at(8192, 8193),
            invalid(
                "RDPGFX_WIRE_TO_SURFACE_PDU_1",
                "destination rectangle is larger than any admissible surface"
            ),
            "one row past the cap the bound is what fails"
        );
    }

    /// The other half of the pair above, and the reason the `MAX_SURFACE_DIM` bound was lifted
    /// out of `decode_wts1` rather than left inside it: with the bound in the same function, the
    /// `checked_mul` below it could never be reached and its mutation could not redden — a guard
    /// with no firing mechanism, which is the defect the graph's own `place` node argues against.
    /// Called directly with a bare `Rect16`, `decode_wts1` is total for the whole parameter type
    /// ([ADR-0012] §1: the caller's
    /// guarantee is not this function's contract).
    ///
    /// Target-gated like the five sibling codec guards (`color`, `planar`, `pointer`, `rle`,
    /// `rfx`): 65535 x 65535 x 4 = 17_179_344_900 exceeds `u32::MAX` and fits 64 bits, so only
    /// a 32-bit `usize` can observe the refusal (memory `wasm32_overflow_proof_via_i686`).
    ///
    /// [ADR-0012]: https://github.com/kihyun1998/justrdp/blob/master/docs/adr/0012-consumption-site-totality.md
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn decode_wts1_is_total_for_a_rectangle_its_caller_would_have_refused() {
        let mut p = GraphicsProcessor::default();
        let rect = Rect16 {
            left: 0,
            top: 0,
            right: u16::MAX,
            bottom: u16::MAX,
        };
        assert_eq!(
            p.decode_wts1(egfx::CODECID_UNCOMPRESSED, rect, &[0xAB; 16])
                .unwrap_err(),
            invalid(
                "RDPGFX_WIRE_TO_SURFACE_PDU_1",
                "destination rectangle's byte count overflows usize"
            )
        );
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
            pixels
                .as_chunks::<4>()
                .0
                .iter()
                .all(|p| *p == [128, 128, 128, 255]),
            "zero spectrum must decode to mid gray, got {:?}…",
            &pixels[..8]
        );
    }

    #[test]
    fn garbage_zgfx_is_a_typed_error() {
        let mut p = GraphicsProcessor::default();
        assert!(p.process(&[0x12, 0x34]).is_err());
    }

    /// The #189 regression, pinned at the boundary the panic actually reached rather than one
    /// layer down. Each of these crafted `RDP_SEGMENTED_DATA` messages **panicked** through the
    /// bootstrap wrapper — `mid > len` from a `split_at` on a server-chosen `u32`, `attempt to
    /// subtract with overflow` from the unused-bit arithmetic, and a bit-cursor index — and a
    /// panic here kills the host's session, which is what
    /// `docs/map/invariant/untrusted-decode-never-panics.md` forbids. zgfx is the outermost
    /// decoder on this path, so it is also the one every EGFX byte crosses first.
    #[test]
    fn crafted_segmented_data_is_a_typed_error_not_a_panic() {
        for message in [
            &[0xE1u8, 1, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F][..],
            &[0xE0, 0x24, 0x05][..],
            &[0xE0, 0x24, 0x00, 0x00][..],
            &[0xE0, 0x24, 0x88, 0x00, 0x00, 0x00, 0x07][..],
        ] {
            let mut p = GraphicsProcessor::default();
            assert!(
                p.process(message).is_err(),
                "expected a typed error for {message:02x?}"
            );
        }
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
    /// `SURFACE_TO_SURFACE` and `SURFACE_TO_CACHE` hand `Surface::extract` a `src_rect` straight
    /// off the wire, and the territory's recorded position is that an off-surface rectangle is
    /// **clipped** rather than refused (the reason justrdp declines FreeRDP's `is_within_surface`).
    /// That was true of `blit` and `fill` and false here: `extract` clipped `w`/`h` but never `x`,
    /// and with no zero-extent early return the loop still ran and indexed `rgba` past its end.
    ///
    /// The boundary is exact — `left == width` lands the slice start on `rgba.len()`, which is a
    /// legal empty slice, and one pixel further is out of range. So the assertion has to sit on
    /// both sides of it or it is asserting the arithmetic it was written for.
    #[test]
    fn a_source_rect_past_the_surface_is_clipped_rather_than_indexed() {
        fn s2c(p: &mut GraphicsProcessor, id: u16, r: [u16; 4]) -> Vec<Out> {
            let mut b = Vec::new();
            b.extend_from_slice(&id.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&9u16.to_le_bytes());
            for f in r {
                b.extend_from_slice(&f.to_le_bytes());
            }
            feed(p, egfx::CMDID_SURFACE_TO_CACHE, &b)
        }
        fn s2s(p: &mut GraphicsProcessor, src: u16, dst: u16, r: [u16; 4]) -> Vec<Out> {
            let mut b = Vec::new();
            b.extend_from_slice(&src.to_le_bytes());
            b.extend_from_slice(&dst.to_le_bytes());
            for f in r {
                b.extend_from_slice(&f.to_le_bytes());
            }
            b.extend_from_slice(&1u16.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
            feed(p, egfx::CMDID_SURFACE_TO_SURFACE, &b)
        }

        // A plain desktop-sized surface: the defect needs no unusual geometry and no large count.
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 1920, 1080);
        create_surface(&mut p, 2, 1920, 1080);

        // `left == width` — the last in-range start offset, and already fine before the guard.
        assert!(s2c(&mut p, 1, [1920, 1079, 1921, 1080]).is_empty());
        // One pixel past it, which is where the slice start leaves the buffer.
        assert!(s2c(&mut p, 1, [1921, 1079, 1922, 1080]).is_empty());
        // And far past, so the assertion is not pinned to an off-by-one.
        assert!(s2c(&mut p, 1, [60000, 0, 60001, 1080]).is_empty());
        // The same rectangle reaches `extract` through the other command too.
        assert!(s2s(&mut p, 1, 2, [1921, 1079, 1922, 1080]).is_empty());
        assert!(s2s(&mut p, 1, 2, [60000, 0, 60001, 1080]).is_empty());

        // Clipped means *nothing painted*, not "painted somewhere else": an out-of-surface
        // source contributes no pixels, so the destination is untouched and stays undirtied.
        assert!(
            p.surfaces[1].dirty.is_empty(),
            "an off-surface source must paint nothing",
        );
        // The top axis clips independently of the left one. **This line observes nothing about
        // the panic** and is here as documentation, not as coverage: at `h == 0` the row loop
        // never runs, so the guard's `h` half is inert and its mutation is green (see `extract`).
        assert!(s2c(&mut p, 1, [0, 1081, 1920, 1082]).is_empty());
    }
    fn cache_body(surface: u16, slot: u16, w: u16, h: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&surface.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&slot.to_le_bytes());
        for f in [0u16, 0, w, h] {
            b.extend_from_slice(&f.to_le_bytes());
        }
        b
    }

    fn paste_body(slot: u16, surface: u16, n: usize) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&slot.to_le_bytes());
        b.extend_from_slice(&surface.to_le_bytes());
        b.extend_from_slice(&(n as u16).to_le_bytes());
        for _ in 0..n {
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
        }
        b
    }

    /// Feed several PDUs in ONE message, which is what a real server does — the WS2022 VM
    /// measured for #268 sent up to 266 PDUs per message. A helper that wraps one PDU per
    /// message cannot tell a per-frame reset from a per-message one.
    fn feed_many(p: &mut GraphicsProcessor, pdus: &[(u16, Vec<u8>)]) -> Vec<Out> {
        let mut blob = Vec::new();
        for (cmd_id, body) in pdus {
            blob.extend_from_slice(&header(*cmd_id, body));
        }
        p.process(&egfx::wrap_uncompressed(&blob)).unwrap()
    }

    /// Two surfaces of `dim x dim` and a cache entry of the same size in slot 7.
    fn two_surfaces_and_a_cached_bitmap(dim: u16) -> GraphicsProcessor {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, dim, dim);
        create_surface(&mut p, 2, dim, dim);
        assert!(
            feed(
                &mut p,
                egfx::CMDID_SURFACE_TO_CACHE,
                &cache_body(1, 7, dim, dim)
            )
            .is_empty()
        );
        p
    }

    /// `CACHE_TO_SURFACE` blits once per server-declared point, and both the count and the
    /// cached bitmap are the server's to choose — so a fixed 262 KB PDU bought unbounded CPU
    /// and returned `Ok` (#268). The bound is a per-frame paint budget, and the ceiling is
    /// `MAX_TOTAL_SURFACE_BYTES` **derived, not picked**: the most a frame can legitimately
    /// paint is every surface that could exist, once.
    ///
    /// The assertion is on the *budget*, never on elapsed time — #262 paid 56.4 runner-hours
    /// for the lesson that a test which takes two minutes and passes is indistinguishable from
    /// one that hangs.
    #[test]
    fn a_paste_list_is_cut_at_the_per_frame_paint_budget() {
        // A 1 MiB cached bitmap: the budget admits 256 pastes of it and no more.
        let mut p = two_surfaces_and_a_cached_bitmap(64);
        let one_paste = 64 * 64 * 4;

        let outputs = feed(
            &mut p,
            egfx::CMDID_CACHE_TO_SURFACE,
            &paste_body(7, 2, 65535),
        );
        assert!(outputs.is_empty(), "the command is tolerated, not refused");
        assert_eq!(
            p.frame_paint, MAX_TOTAL_SURFACE_BYTES,
            "65535 pastes must stop exactly at the budget, not run past it",
        );
        assert_eq!(
            MAX_TOTAL_SURFACE_BYTES / one_paste,
            16_384,
            "16384 pastes fit"
        );
    }

    /// The budget must not refuse what a real server sends. Measured against the WS2022 VM for
    /// #268: 2 748 `CACHE_TO_SURFACE` PDUs, **every one with `destPtsCount == 1`**, cache
    /// entries of 64x64 or 64x32, and a busiest frame of 4 096 000 bytes — exactly one
    /// 1280x800 desktop, which is ~64x under the ceiling.
    #[test]
    fn the_budget_does_not_reach_traffic_the_real_server_sends() {
        let mut p = GraphicsProcessor::default();
        create_surface(&mut p, 1, 1280, 800);
        create_surface(&mut p, 2, 1280, 800);
        assert!(
            feed(
                &mut p,
                egfx::CMDID_SURFACE_TO_CACHE,
                &cache_body(1, 7, 64, 64)
            )
            .is_empty()
        );

        let mut start = vec![0u8; 8];
        start[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(feed(&mut p, egfx::CMDID_START_FRAME, &start).is_empty());
        // One paste per PDU, as observed, many times over.
        for _ in 0..2_000 {
            assert!(feed(&mut p, egfx::CMDID_CACHE_TO_SURFACE, &paste_body(7, 2, 1)).is_empty());
        }
        assert_eq!(
            p.frame_paint,
            2_000 * 64 * 64 * 4,
            "every observed-shape paste must land, none skipped",
        );
        assert!(p.frame_paint < MAX_TOTAL_SURFACE_BYTES);
    }

    /// The budget is per *frame*, so it must come back — and the two resets are different
    /// mechanisms that a one-PDU-per-message helper cannot tell apart. A real server packs
    /// many PDUs into one message (266 measured), so several frames share a message and the
    /// StartFrame reset is the one doing the work there. Measured by mutation: with only the
    /// per-message reset, the second paste below paints nothing.
    #[test]
    fn a_new_frame_restores_the_budget_within_a_single_message() {
        let mut p = two_surfaces_and_a_cached_bitmap(64);
        let one_paste = 64 * 64 * 4;
        let mut start = vec![0u8; 8];
        start[4..8].copy_from_slice(&9u32.to_le_bytes());

        // One message: exhaust the budget, open a frame, paste four more.
        let outputs = feed_many(
            &mut p,
            &[
                (egfx::CMDID_CACHE_TO_SURFACE, paste_body(7, 2, 65535)),
                (egfx::CMDID_START_FRAME, start),
                (egfx::CMDID_CACHE_TO_SURFACE, paste_body(7, 2, 4)),
            ],
        );
        assert!(outputs.is_empty(), "tolerated, not refused");
        assert_eq!(
            p.frame_paint,
            4 * one_paste,
            "StartFrame must restore the budget mid-message, not only between messages",
        );
    }

    /// And the per-message reset covers the case StartFrame cannot: draw commands do not
    /// require a frame — no arm checks `in_frame` before painting — so a server that never
    /// sends StartFrame would otherwise sit outside the accounting forever.
    #[test]
    fn an_unbracketed_message_restores_the_budget_on_its_own() {
        let mut p = two_surfaces_and_a_cached_bitmap(64);
        let one_paste = 64 * 64 * 4;

        assert!(
            feed(
                &mut p,
                egfx::CMDID_CACHE_TO_SURFACE,
                &paste_body(7, 2, 65535)
            )
            .is_empty()
        );
        assert_eq!(p.frame_paint, MAX_TOTAL_SURFACE_BYTES, "budget exhausted");
        assert!(feed(&mut p, egfx::CMDID_CACHE_TO_SURFACE, &paste_body(7, 2, 4)).is_empty());
        assert_eq!(
            p.frame_paint,
            4 * one_paste,
            "a message with no frame open starts fresh",
        );
    }

    /// Inside one frame the budget is shared rather than granted per PDU.
    #[test]
    fn pdus_inside_one_frame_share_the_budget() {
        let mut p = two_surfaces_and_a_cached_bitmap(64);
        let mut start = vec![0u8; 8];
        start[4..8].copy_from_slice(&3u32.to_le_bytes());
        let outputs = feed_many(
            &mut p,
            &[
                (egfx::CMDID_START_FRAME, start),
                (egfx::CMDID_CACHE_TO_SURFACE, paste_body(7, 2, 10_000)),
                (egfx::CMDID_CACHE_TO_SURFACE, paste_body(7, 2, 10_000)),
            ],
        );
        assert!(outputs.is_empty());
        assert_eq!(
            p.frame_paint, MAX_TOTAL_SURFACE_BYTES,
            "two PDUs in one frame share one budget rather than each getting their own",
        );
    }

    /// `SOLID_FILL` and `SURFACE_TO_SURFACE` carry the same wire shape and were not named in
    /// the issue. ADR-0012 §3 asks a family for one answer, so all three are charged.
    #[test]
    fn solid_fill_and_surface_to_surface_are_charged_to_the_same_budget() {
        let mut p = two_surfaces_and_a_cached_bitmap(64);
        let mut body = Vec::new();
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(&[0u8, 0, 255, 0]);
        body.extend_from_slice(&65535u16.to_le_bytes());
        for _ in 0..65535 {
            for f in [0u16, 0, 64, 64] {
                body.extend_from_slice(&f.to_le_bytes());
            }
        }
        assert!(feed(&mut p, egfx::CMDID_SOLID_FILL, &body).is_empty());
        assert_eq!(
            p.frame_paint, MAX_TOTAL_SURFACE_BYTES,
            "SOLID_FILL is bounded"
        );

        let mut p = two_surfaces_and_a_cached_bitmap(64);
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
        for f in [0u16, 0, 64, 64] {
            body.extend_from_slice(&f.to_le_bytes());
        }
        body.extend_from_slice(&65535u16.to_le_bytes());
        for _ in 0..65535 {
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
        }
        assert!(feed(&mut p, egfx::CMDID_SURFACE_TO_SURFACE, &body).is_empty());
        assert_eq!(
            p.frame_paint, MAX_TOTAL_SURFACE_BYTES,
            "SURFACE_TO_SURFACE is bounded",
        );
    }

    // ── #267 — the ADR-0008 artifacts for the graphics processor ─────────────────────────
    //
    // `GraphicsProcessor::process` is the EGFX live path and carried **neither** artifact.
    // `fuzz_targets/egfx.rs` and `decode_all_never_panics_on_arbitrary_input` are both the
    // *PDU crate's*, and the invariant's two derivations matched them here **by module name** —
    // the fourth instance of the trap `untrusted-decode-never-panics.md` already records for
    // `pointer` (#203), `license` (#230) and `tls` (#241), one crate further out each time. It
    // is not theoretical here: two defects were found in this module by hand in two weeks —
    // #268's unbounded paste loop, and `Surface::extract`'s out-of-range slice panic at
    // `left == width + 1` with `destPtsCount == 1`.
    //
    // **The generator is the work, and it generates a *sequence*.** Every other no-panic
    // property in this workspace drives a stateless parse; this subject is not one. The
    // processor carries the zgfx LZ77 history, the Progressive tile store, the ClearCodec
    // caches, the surface list and the bitmap cache across messages — and #268's defect was
    // funded by exactly that: a 262 KB PDU whose cost came from a bitmap an *earlier* message
    // had cached, which is the third adjudication question the invariant note asks. A
    // single-message property is blind to that class by construction.
    //
    // **Prior art, read raw rather than summarised.** `ironrdp-fuzzing`'s `egfx_multi_frame`
    // generates typed PDUs and re-encodes them instead of feeding arbitrary bytes to the
    // processor. Its mechanism does not transfer — every encoder in `justrdp-pdu` writes
    // client-to-server (ADR-0008's 2026-09-04 amendment), so there is nothing to re-encode a
    // *server* PDU with and the bodies are assembled below — but its *shape* is right, and
    // the reason is now measured rather than inherited.
    //
    // **Throwaway probe, 2026-09-07: 20 000 arbitrary blobs of 0..=512 bytes, wrapped the
    // way this ticket names, produced `decode_all` Ok 44 times — every one of them the
    // empty blob — and decoded a non-empty PDU ZERO times.** No surface was created and no
    // frame was painted. So an undirected generator does not reach the per-command arms,
    // and does not reach `decode_all`'s body either: `RDPGFX_HEADER`'s
    // `pdu_length < 8 || pdu_length > rest.len()` consistency check refuses essentially
    // every random blob. That is the whole justification for the structured generator
    // below, and it is an exact 0/20 000 rather than #230's estimated 6.7e-11. Probe
    // deleted; the number lives here.

    use proptest::prelude::*;

    /// One server EGFX command as the generator emits it: a `cmdId` and the body bytes
    /// `decode_all` hands to `GraphicsProcessor::handle`.
    #[derive(Debug, Clone)]
    struct Cmd {
        cmd_id: u16,
        body: Vec<u8>,
    }

    /// Little-endian body writer — the generator's half of a wire format this crate only ever
    /// decodes. It exists because `justrdp-pdu` has no server-side encoder to borrow.
    #[derive(Default)]
    struct Body(Vec<u8>);

    impl Body {
        fn u8(mut self, v: u8) -> Self {
            self.0.push(v);
            self
        }
        fn u16(mut self, v: u16) -> Self {
            self.0.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn u32(mut self, v: u32) -> Self {
            self.0.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn rect(self, r: (u16, u16, u16, u16)) -> Self {
            self.u16(r.0).u16(r.1).u16(r.2).u16(r.3)
        }
        fn bytes(mut self, v: &[u8]) -> Self {
            self.0.extend_from_slice(v);
            self
        }
        fn done(self, cmd_id: u16) -> Cmd {
            Cmd {
                cmd_id,
                body: self.0,
            }
        }
    }

    /// Surface ids from a **tiny** pool, so a command can find a surface an earlier one
    /// created. Without the correlation every arm past `surface_mut` short-circuits on "unknown
    /// surface" and the property asserts the lookup instead of the handler — #211's `nscodec`
    /// finding in its second form, where the generator is wide enough to be admitted and never
    /// coincides with the state the arm needs.
    fn surface_id() -> impl Strategy<Value = u16> {
        prop_oneof![8 => 0u16..=2, 1 => any::<u16>()]
    }

    /// Surface dimensions, weighted onto the three places the arithmetic changes: a real
    /// surface, the `MAX_SURFACE_DIM` refusal on both sides of it, and the full `u16` a server
    /// may pick (`[MS-RDPEGFX]` 2.2.2.14 caps at 32766; nothing on the wire enforces it).
    fn dim() -> impl Strategy<Value = u16> {
        prop_oneof![
            6 => 1u16..=64,
            2 => (MAX_SURFACE_DIM - 1)..=(MAX_SURFACE_DIM + 1),
            1 => any::<u16>(),
        ]
    }

    /// Rectangle edges. The near-maximal arm is what #263 was: `[MS-RDPEGFX]` 2.2.1.2 places no
    /// bound on a `RDPGFX_RECT16` beyond the type, and a maximal `destRect` panicked on i686.
    fn coord() -> impl Strategy<Value = u16> {
        prop_oneof![
            6 => 0u16..=64,
            2 => 65_400u16..=65_535,
            1 => any::<u16>(),
        ]
    }

    fn rect() -> impl Strategy<Value = (u16, u16, u16, u16)> {
        (coord(), coord(), coord(), coord())
    }

    /// A destination **point** coordinate, and it is deliberately not [`coord`].
    ///
    /// `Point16::decode` reads the field as `read_u16_le() as i16`, so `coord`'s near-maximal
    /// arm folds entirely onto *negative* destinations — which clip through the `-x.min(0)`
    /// path and can never produce the failure that lives past a surface's right edge. Measured:
    /// with `coord` on both, deleting `Surface::blit`'s zero-extent early return left this
    /// file's no-panic property **green**, because `dst_x >= width` was unreachable. The window
    /// below is the one that matters — positive, just past a generated surface, and up against
    /// `i16::MAX` — with the full type kept on its own arm.
    fn point_coord() -> impl Strategy<Value = u16> {
        prop_oneof![
            5 => 0u16..=64,
            3 => 65u16..=200,
            1 => (i16::MAX as u16 - 8)..=(i16::MAX as u16),
            1 => any::<u16>(),
        ]
    }

    /// A `MapSurfaceToOutput` origin: the server-controlled `u32` pair that `blit_dirty` adds a
    /// surface coordinate to and narrows to `u16`. **Only `flush_frames` reaches it**, which is
    /// why this property drives the pair rather than `process` alone. Weighted at the `u16`
    /// boundary, which is where the narrowing decides between a blit and a skip.
    fn origin() -> impl Strategy<Value = u32> {
        prop_oneof![
            5 => 0u32..=64,
            3 => (u32::from(u16::MAX) - 8)..=(u32::from(u16::MAX) + 8),
            1 => any::<u32>(),
        ]
    }

    /// Cache slots from a tiny pool for the same reason as [`surface_id`]: a paste that names a
    /// slot no `SURFACE_TO_CACHE` filled never reaches the blit loop. The pool keeps **0**, and
    /// the unconstrained arm is kept, because since #297 both are the skipped side of §3.3.1.4's
    /// one-based range (25 600 / 4 096) rather than unchecked `HashMap` keys — so between them
    /// the two arms drive the guard as well as the slots that clear it.
    fn cache_slot() -> impl Strategy<Value = u16> {
        prop_oneof![8 => 0u16..=3, 1 => any::<u16>()]
    }

    /// **The exact-match gate this subject's reach turns on.** `decode_wts1` dispatches on
    /// `codec_id` by equality, so a uniform `u16` clears it ~5 times in 65536 and every codec
    /// arm goes unexercised while the property still runs green — the shape `color.rs`'s
    /// `depth()` records and `nscodec` shipped once.
    fn codec_id() -> impl Strategy<Value = u16> {
        prop_oneof![
            8 => prop::sample::select(vec![
                egfx::CODECID_UNCOMPRESSED,
                egfx::CODECID_PLANAR,
                egfx::CODECID_CLEARCODEC,
                egfx::CODECID_CAVIDEO,
                egfx::CODECID_CAPROGRESSIVE,
                egfx::CODECID_ALPHA,
            ]),
            1 => any::<u16>(),
        ]
    }

    fn pixel_format() -> impl Strategy<Value = u8> {
        prop_oneof![
            8 => prop::sample::select(vec![
                egfx::PIXEL_FORMAT_XRGB_8888,
                egfx::PIXEL_FORMAT_ARGB_8888,
            ]),
            1 => any::<u8>(),
        ]
    }

    /// The **declared** entry count of a list-bearing command, at the full type range.
    ///
    /// It is deliberately independent of how many entries `entry_budget` actually emits, and
    /// that split is what buys the full range for free: a declared count larger than the bytes
    /// present is refused by `Point16::decode`, which is the reject branch, and a declared
    /// count the bytes *do* cover costs 4-8 bytes each — #268's whole point. So the type range
    /// is driven without generating 524 KB bodies 512 times.
    fn declared_count() -> impl Strategy<Value = u16> {
        prop_oneof![
            5 => 0u16..=2,
            3 => 3u16..=64,
            2 => any::<u16>(),
        ]
    }

    /// How many list entries are actually written. **A budget trade, not a threat model** — a
    /// server may send 65 535 (#268 measured what that costs), and this caps at 600 so a
    /// 512-case run stays inside `test.yml`'s 20-minute job. `declared_count` keeps the full
    /// range driven; what this bounds is only the *work*, which `frame_paint` now bounds in
    /// production too.
    fn entry_budget() -> impl Strategy<Value = usize> {
        prop_oneof![7 => 0usize..=8, 2 => 9usize..=64, 1 => 400usize..=600]
    }

    /// A codec payload. Bounded at 512 bytes on the same budget grounds, and stated because
    /// ADR-0008's strategy rule was amended (#263) precisely to stop a budget bound being
    /// written up as fidelity: a real bitstream is far larger, and this reaches each decoder's
    /// entry and its early refusals rather than its deep loops.
    fn payload() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..=512)
    }

    /// One command. Every arm a real server sends, plus an arbitrary-`cmdId` arm so the
    /// `Unknown` skip and the header's own refusals stay driven.
    fn cmd() -> impl Strategy<Value = Cmd> {
        prop_oneof![
            2 => (any::<u32>(), any::<u32>()).prop_map(|(v, f)| Body::default()
                .u32(v)
                .u32(4)
                .u32(f)
                .done(egfx::CMDID_CAPS_CONFIRM)),
            // A version a semantic miss can reset from; an arbitrary `u32` is almost never one.
            1 => any::<u32>().prop_map(|f| Body::default()
                .u32(egfx::CAPVERSION_104)
                .u32(4)
                .u32(f)
                .done(egfx::CMDID_CAPS_CONFIRM)),
            2 => (any::<u32>(), any::<u32>()).prop_map(|(w, h)| Body::default()
                .u32(w)
                .u32(h)
                .done(egfx::CMDID_RESET_GRAPHICS)),
            6 => (surface_id(), dim(), dim(), pixel_format()).prop_map(|(s, w, h, pf)| {
                Body::default()
                    .u16(s)
                    .u16(w)
                    .u16(h)
                    .u8(pf)
                    .done(egfx::CMDID_CREATE_SURFACE)
            }),
            2 => surface_id()
                .prop_map(|s| Body::default().u16(s).done(egfx::CMDID_DELETE_SURFACE)),
            5 => (surface_id(), origin(), origin()).prop_map(|(s, x, y)| {
                Body::default()
                    .u16(s)
                    .u16(0)
                    .u32(x)
                    .u32(y)
                    .done(egfx::CMDID_MAP_SURFACE_TO_OUTPUT)
            }),
            4 => any::<u32>()
                .prop_map(|f| Body::default().u32(0).u32(f).done(egfx::CMDID_START_FRAME)),
            4 => any::<u32>().prop_map(|f| Body::default().u32(f).done(egfx::CMDID_END_FRAME)),
            6 => (surface_id(), codec_id(), pixel_format(), rect(), payload()).prop_map(
                |(s, c, pf, r, d)| Body::default()
                    .u16(s)
                    .u16(c)
                    .u8(pf)
                    .rect(r)
                    .u32(d.len() as u32)
                    .bytes(&d)
                    .done(egfx::CMDID_WIRE_TO_SURFACE_1)
            ),
            4 => (surface_id(), codec_id(), any::<u32>(), pixel_format(), payload()).prop_map(
                |(s, c, ctx, pf, d)| Body::default()
                    .u16(s)
                    .u16(c)
                    .u32(ctx)
                    .u8(pf)
                    .u32(d.len() as u32)
                    .bytes(&d)
                    .done(egfx::CMDID_WIRE_TO_SURFACE_2)
            ),
            1 => (surface_id(), any::<u32>()).prop_map(|(s, c)| Body::default()
                .u16(s)
                .u32(c)
                .done(egfx::CMDID_DELETE_ENCODING_CONTEXT)),
            4 => (
                surface_id(),
                any::<[u8; 4]>(),
                declared_count(),
                entry_budget(),
                rect(),
            )
                .prop_map(|(s, col, n, k, r)| {
                    let mut b = Body::default().u16(s).bytes(&col).u16(n);
                    for _ in 0..k {
                        b = b.rect(r);
                    }
                    b.done(egfx::CMDID_SOLID_FILL)
                }),
            4 => (
                surface_id(),
                surface_id(),
                rect(),
                declared_count(),
                entry_budget(),
                point_coord(),
                point_coord(),
            )
                .prop_map(|(src, dst, r, n, k, x, y)| {
                    let mut b = Body::default().u16(src).u16(dst).rect(r).u16(n);
                    for _ in 0..k {
                        b = b.u16(x).u16(y);
                    }
                    b.done(egfx::CMDID_SURFACE_TO_SURFACE)
                }),
            5 => (surface_id(), any::<u32>(), any::<u32>(), cache_slot(), rect()).prop_map(
                |(s, lo, hi, slot, r)| Body::default()
                    .u16(s)
                    .u32(lo)
                    .u32(hi)
                    .u16(slot)
                    .rect(r)
                    .done(egfx::CMDID_SURFACE_TO_CACHE)
            ),
            5 => (
                cache_slot(),
                surface_id(),
                declared_count(),
                entry_budget(),
                point_coord(),
                point_coord(),
            )
                .prop_map(|(slot, s, n, k, x, y)| {
                    let mut b = Body::default().u16(slot).u16(s).u16(n);
                    for _ in 0..k {
                        b = b.u16(x).u16(y);
                    }
                    b.done(egfx::CMDID_CACHE_TO_SURFACE)
                }),
            1 => cache_slot()
                .prop_map(|s| Body::default().u16(s).done(egfx::CMDID_EVICT_CACHE_ENTRY)),
            2 => (any::<u16>(), prop::collection::vec(any::<u8>(), 0..=64))
                .prop_map(|(id, b)| Body::default().bytes(&b).done(id)),
        ]
    }

    /// A session: several messages, each carrying several commands. Both dimensions matter and
    /// they are not interchangeable — commands in one blob share a `process` call and a paint
    /// budget, while a new message is where state established earlier gets spent.
    fn session() -> impl Strategy<Value = Vec<Vec<Cmd>>> {
        (
            any::<bool>(),
            prop::collection::vec(prop::collection::vec(cmd(), 0..=6), 1..=4),
        )
            .prop_map(|(bootstrap, mut messages)| {
                if bootstrap {
                    messages.insert(0, prologue());
                }
                messages
            })
    }

    /// A valid opening message: one surface, mapped, with one cache slot filled.
    ///
    /// **Measured, not decorative.** Without it, deleting `Surface::blit`'s zero-extent early
    /// return left the property green: that panic needs `dst_x` past the surface *and* a live
    /// cached bitmap to paste, which is a three-command correlated sequence
    /// (create -> surface-to-cache -> cache-to-surface) that independently drawn commands
    /// almost never assemble. The correlated pools in `surface_id` and `cache_slot` get the
    /// *ids* to coincide; this gets the *order* to. `ironrdp-fuzzing`'s `egfx_multi_frame` does
    /// the same thing one step earlier, calling `DvcProcessor::start` before its loop.
    ///
    /// It is prepended only half the time, so the reject paths a server hits by sending a draw
    /// for a surface that does not exist stay driven at the same rate they were.
    fn prologue() -> Vec<Cmd> {
        vec![
            Body::default()
                .u16(1)
                .u16(64)
                .u16(64)
                .u8(egfx::PIXEL_FORMAT_XRGB_8888)
                .done(egfx::CMDID_CREATE_SURFACE),
            Body::default()
                .u16(1)
                .u16(0)
                .u32(0)
                .u32(0)
                .done(egfx::CMDID_MAP_SURFACE_TO_OUTPUT),
            Body::default()
                .u16(1)
                .u32(0)
                .u32(0)
                .u16(2)
                .rect((0, 0, 32, 32))
                .done(egfx::CMDID_SURFACE_TO_CACHE),
        ]
    }

    /// Drive one session the way `Drdynvc` does.
    ///
    /// **`flush_frames` runs only on an `Ok`**: `Drdynvc::on_svc_payload` propagates a processor
    /// error with `?` and `SessionStateMachine::on_drdynvc`'s flush sits after it, so flushing a
    /// payload whose `process` failed is a sequence the live path cannot produce. #263 recorded
    /// the cost of the general form — an assertion routed past the call site the production path
    /// uses comes back green over a removed guard.
    fn drive(p: &mut GraphicsProcessor, fb: &mut Framebuffer, session: &[Vec<Cmd>]) {
        for message in session {
            let mut blob = Vec::new();
            for c in message {
                blob.extend_from_slice(&header(c.cmd_id, &c.body));
            }
            if p.process(&egfx::wrap_uncompressed(&blob)).is_ok() {
                let _ = p.flush_frames(fb);
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// [untrusted decode never panics],
        /// on the EGFX live path (#267). Reaching the end is the assertion; `proptest` shrinks
        /// any panic to a minimal counterexample.
        ///
        /// 512 cases rather than the 2048 the PDU-crate properties use: a case here is a whole
        /// session of up to 24 commands through five decoders, not one parse.
        ///
        /// **`proptest-regressions/egfx.txt` carries two seeds that are not from a real
        /// failure.** Both were shrunk while ablating a guard to prove this property can
        /// fail: one replays create-surface -> surface-to-cache and reaches
        /// `Surface::extract`, the other adds the mapping and a wire-to-surface and reaches
        /// `Surface::blit`. They are kept deliberately — without them, whether a run drives
        /// those two routines is left to the RNG. The note is here rather than in that file
        /// because ADR-0001's tree rule makes `proptest-regressions/` generated and never
        /// authored, so a comment written into it is one proptest rewrite from gone.
        ///
        /// **Three things it deliberately does not reach**, stated because a property is
        /// judged by what it cannot see and an unstated non-reach reads as coverage:
        /// - **zgfx.** Every message goes in through `wrap_uncompressed`, so the
        ///   decompressor is bypassed. That is `fuzz_targets/zgfx.rs`'s subject, and
        ///   `ironrdp-fuzzing` splits its own the same way and says so.
        /// - **A lying `pduLength`.** Every command here is emitted with a correct header,
        ///   so the header walk's own refusals are driven by `fuzz_targets/egfx.rs` on the
        ///   PDU crate and not from here. The processor adds nothing to that path — it
        ///   propagates `decode_all`'s error — so this is a stated non-reach, not a hole.
        /// - **Progressive's deep loops.** Payloads are 512 arbitrary bytes, which reaches
        ///   each codec's entry and early refusals, not `paint_tile`'s `numTiles`x`numRects`
        ///   quadratic — an open member the invariant note already names.
        ///
        /// [untrusted decode never panics]: https://github.com/kihyun1998/justrdp/blob/master/docs/map/invariant/untrusted-decode-never-panics.md
        #[test]
        fn graphics_processor_is_total_over_arbitrary_sessions(session in session()) {
            let mut p = GraphicsProcessor::default();
            let mut fb = Framebuffer::new(1280, 800).expect("framebuffer");
            drive(&mut p, &mut fb, &session);
        }
    }

    /// **The generator's reach, asserted rather than assumed** — the sibling of `color.rs`'s
    /// `the_generator_reaches_past_the_depth_gate`, and the check #230 measured the need for at
    /// 6.7e-11 per case.
    ///
    /// Each row is a shape `cmd` emits, and each asserts an *observable* effect of the arm it is
    /// named for. Without it a green here means only that nothing panicked on the way to a
    /// `surface_mut` that returned `None`.
    #[test]
    fn the_generator_reaches_every_stateful_arm() {
        let mut p = GraphicsProcessor::default();
        let mut fb = Framebuffer::new(1280, 800).expect("framebuffer");

        // Create + map: the prologue every other arm depends on.
        let prologue = vec![
            Body::default()
                .u16(1)
                .u16(64)
                .u16(64)
                .u8(egfx::PIXEL_FORMAT_XRGB_8888)
                .done(egfx::CMDID_CREATE_SURFACE),
            Body::default()
                .u16(1)
                .u16(0)
                .u32(0)
                .u32(0)
                .done(egfx::CMDID_MAP_SURFACE_TO_OUTPUT),
        ];
        drive(&mut p, &mut fb, &[prologue]);
        assert_eq!(p.surfaces.len(), 1, "CreateSurface arm reached");

        // The dimension refusal, asserted directly. An ablation of it is **masked**: at 65535
        // square the byte total is 17 GB and `MAX_TOTAL_SURFACE_BYTES` refuses it anyway, so
        // removing this guard alone left every test in this file green. Two guards cover the
        // same input and only the outer one was observable; this row makes the inner one so.
        let oversize = vec![
            Body::default()
                .u16(9)
                .u16(MAX_SURFACE_DIM + 1)
                .u16(1)
                .u8(egfx::PIXEL_FORMAT_XRGB_8888)
                .done(egfx::CMDID_CREATE_SURFACE),
        ];
        drive(&mut p, &mut fb, &[oversize]);
        assert_eq!(
            p.surfaces.len(),
            1,
            "a surface one pixel past MAX_SURFACE_DIM is refused, and the refusal is this \r
             guard rather than the byte-total one it hides behind",
        );
        assert_eq!(
            p.surfaces[0].mapped,
            Some((0, 0)),
            "MapSurfaceToOutput arm reached"
        );

        // A bracketed SolidFill: the frame bracket, the paint budget and the dirty list.
        let frame = vec![
            Body::default().u32(0).u32(7).done(egfx::CMDID_START_FRAME),
            Body::default()
                .u16(1)
                .bytes(&[1, 2, 3, 0])
                .u16(1)
                .rect((0, 0, 8, 8))
                .done(egfx::CMDID_SOLID_FILL),
        ];
        drive(&mut p, &mut fb, &[frame]);
        assert!(p.in_frame, "StartFrame arm reached");
        assert_eq!(
            p.frame_paint,
            8 * 8 * 4,
            "SolidFill painted, and was charged"
        );

        // The cache round trip: fill a slot, then paste it — the #268 shape, and the pair the
        // correlated `cache_slot()` / `surface_id()` pools exist for.
        let cache = vec![
            Body::default()
                .u16(1)
                .u32(0)
                .u32(0)
                .u16(2)
                .rect((0, 0, 8, 8))
                .done(egfx::CMDID_SURFACE_TO_CACHE),
            Body::default()
                .u16(2)
                .u16(1)
                .u16(1)
                .u16(4)
                .u16(4)
                .done(egfx::CMDID_CACHE_TO_SURFACE),
        ];
        drive(&mut p, &mut fb, &[cache]);
        assert_eq!(p.cache.len(), 1, "SurfaceToCache arm reached");
        assert!(p.cache_bytes > 0, "the cache accounting moved");
        assert!(
            p.frame_paint > 8 * 8 * 4,
            "CacheToSurface pasted into the same frame"
        );

        // EndFrame closes the bracket and produces the frame-ack the manager sends.
        let mut p2 = GraphicsProcessor::default();
        let mut fb2 = Framebuffer::new(1280, 800).expect("framebuffer");
        let end = vec![Body::default().u32(7).done(egfx::CMDID_END_FRAME)];
        drive(&mut p2, &mut fb2, &[end]);
        assert_eq!(p2.frames_decoded, 1, "EndFrame arm reached");

        // The 3.3.5.19 reset: a confirm at 10.4, then a paste from a slot never filled.
        let mut p5 = GraphicsProcessor::default();
        let mut fb5 = Framebuffer::new(1280, 800).expect("framebuffer");
        let reset = vec![
            Body::default()
                .u32(egfx::CAPVERSION_104)
                .u32(4)
                .u32(0)
                .done(egfx::CMDID_CAPS_CONFIRM),
            Body::default()
                .u16(3)
                .u16(1)
                .u16(1)
                .u16(0)
                .u16(0)
                .done(egfx::CMDID_CACHE_TO_SURFACE),
        ];
        drive(&mut p5, &mut fb5, &[reset]);
        assert!(
            p5.awaiting_confirm && p5.reset_spent,
            "the reset arm reached"
        );

        // WireToSurface1 with a real codec id: the exact-match gate `codec_id()` is weighted for.
        let mut p3 = GraphicsProcessor::default();
        let mut fb3 = Framebuffer::new(1280, 800).expect("framebuffer");
        let wts1 = vec![
            Body::default()
                .u16(1)
                .u16(4)
                .u16(4)
                .u8(egfx::PIXEL_FORMAT_XRGB_8888)
                .done(egfx::CMDID_CREATE_SURFACE),
            Body::default()
                .u16(1)
                .u16(0)
                .u32(0)
                .u32(0)
                .done(egfx::CMDID_MAP_SURFACE_TO_OUTPUT),
            Body::default()
                .u16(1)
                .u16(egfx::CODECID_UNCOMPRESSED)
                .u8(egfx::PIXEL_FORMAT_XRGB_8888)
                .rect((0, 0, 2, 2))
                .u32(16)
                .bytes(&[0x7Fu8; 16])
                .done(egfx::CMDID_WIRE_TO_SURFACE_1),
        ];
        let mut blob = Vec::new();
        for c in &wts1 {
            blob.extend_from_slice(&header(c.cmd_id, &c.body));
        }
        p3.process(&egfx::wrap_uncompressed(&blob))
            .expect("well-formed");
        // Not `frame_paint`: the per-frame paint budget is charged by the three *list-bearing*
        // commands only (#268), so it stays 0 here and would have made this row vacuous. The
        // dirty region the decode produced is the observable that actually distinguishes
        // "decoded and painted" from "dispatched and dropped".
        assert!(
            p3.surfaces[0].dirty.contains(&(0, 0, 2, 2)),
            "the uncompressed codec arm decoded and painted; dirty was {:?}",
            p3.surfaces[0].dirty,
        );
        assert!(
            !p3.flush_frames(&mut fb3).is_empty(),
            "and the frame reached the framebuffer"
        );

        // And the `blit_dirty` narrowing, which only `flush_frames` reaches: an origin past the
        // addressable output must skip rather than blit, and one inside must produce a frame.
        for (origin, want_any) in [(0u32, true), (u32::from(u16::MAX), false)] {
            let mut p4 = GraphicsProcessor::default();
            let mut fb4 = Framebuffer::new(1280, 800).expect("framebuffer");
            let msg = vec![
                Body::default()
                    .u16(1)
                    .u16(4)
                    .u16(4)
                    .u8(egfx::PIXEL_FORMAT_XRGB_8888)
                    .done(egfx::CMDID_CREATE_SURFACE),
                Body::default()
                    .u16(1)
                    .u16(0)
                    .u32(origin)
                    .u32(0)
                    .done(egfx::CMDID_MAP_SURFACE_TO_OUTPUT),
                Body::default()
                    .u16(1)
                    .bytes(&[1, 2, 3, 0])
                    .u16(1)
                    .rect((0, 0, 4, 4))
                    .done(egfx::CMDID_SOLID_FILL),
            ];
            let mut blob = Vec::new();
            for c in &msg {
                blob.extend_from_slice(&header(c.cmd_id, &c.body));
            }
            p4.process(&egfx::wrap_uncompressed(&blob))
                .expect("well-formed");
            assert_eq!(
                !p4.flush_frames(&mut fb4).is_empty(),
                want_any,
                "blit_dirty's u16 narrowing decides this at origin {origin}, and only \r
                 flush_frames reaches it",
            );
        }
    }
}
