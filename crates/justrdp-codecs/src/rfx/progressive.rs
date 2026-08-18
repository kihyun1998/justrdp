//! Multi-pass RemoteFX **Progressive** tile decode — the state-machine heart of epic #158
//! (issue #169, slice 3). A tile is painted once coarsely and then refined by any number of
//! later passes, so the coefficient and sign stores live *between* `WireToSurface2` payloads
//! rather than inside one.
//!
//! ```text
//! TILE_FIRST / TILE_SIMPLE   RLGR1 → capture sign → LL3 delta → dequantize → [+ store] → iDWT → ICT
//! TILE_UPGRADE               SRL/raw refine the store in place  →  copy of store → iDWT → ICT
//! ```
//!
//! The entropy layer is [`super::srl`] (#168), the transforms are [`super::dwt`] /
//! [`super::dwt_extrapolate`] and [`super::quant`], the colour step is
//! [`crate::color::rfx_ycbcr_to_rgba`]. This module owns only what is genuinely
//! Progressive-shaped: the cross-pass store, the per-band bit-position arithmetic, and the
//! two entry points.
//!
//! Derived from `progressive_decompress_tile_first` (`progressive.c:930-1073`) and
//! `progressive_decompress_tile_upgrade` (`:1332-1513`) — the tie-break reference, because
//! ADR-0011 / #194 disqualify the `ironrdp-graphics` oracle for Progressive.
//!
//! # The store is per surface, not per codec context
//!
//! A tile is addressed by its grid coordinates, and the grid is a property of the *surface*
//! (`zIdx = yIdx * gridWidth + xIdx`, `progressive.c:471`), so the surface is the only key
//! under which a tile index means anything. FreeRDP keys the whole store by `surfaceId`
//! (`:314`) and treats the block stream's `ctxId` as advisory, warning when it is non-zero
//! (`:1999`) and reading it nowhere else. The bootstrap oracle keys by `codecContextId`
//! instead, which is why `justrdp::egfx` carries a per-surface eviction workaround (#83) — it
//! records that the self-owned decoder retires it, and this is that decoder.
//!
//! The store's *lifecycle* — what creates a grid, what frees one, and what only looks as if it
//! should — is [`SurfaceStore`] (#170), which also owns the per-payload block ordering
//! ([`order_payload`]). What slice 3 fixed is only what the store is keyed by.
//!
//! # Two places the arithmetic can fail, and one place the references disagree
//!
//! Every band's **bit position** is `quant + prog_quant` — a *sum* of two 4-bit nibbles, so
//! it reaches 30, not 15 ([`super::srl::MAX_BIT_POS`]). Two derived values come off it and
//! each has a guard, both of them FreeRDP's:
//!
//! - `shift = bitPos - 1` (`progressive_rfx_quant_lsub(&shift, 1)`, `:98-138`) — every band
//!   must have `bitPos >= 1` or the tile is rejected.
//! - `numBits = previous_bitPos - bitPos` (`progressive_rfx_quant_sub`, `:143-189`) — an
//!   upgrade pass may only ever make a band *finer*, so an underflow rejects the tile.
//!
//! What we do **not** reproduce is FreeRDP's `quantVal >= 6` floor on the base quant table
//! (`progressive.c:2177`). The shift formula is total for `1 <= bitPos <= 16` — the window the
//! guards above and below leave open — and FreeRDP's floor sits *inside* that window rather
//! than at its edge, so refusing a band below 6 buys no arithmetic safety. Under ADR-0009 the
//! formula is applied to whatever arrives.
//!
//! **The references do differ here, and this issue's account of *how* did not survive
//! reading them.** #167 recorded that `ironrdp-graphics` "defines a rounding right-shift for
//! `q < 6`". It does not, and never has: `dequantize_component_ccq` is byte-identical in
//! 0.8.0, 0.8.1 and 0.9.0 — `factor = q.saturating_sub(1); if factor > 0 { *coeff <<= factor }`
//! (`progressive.rs:467`) — and no earlier published version ships a Progressive decoder at
//! all. The rounding right-shift that description matches is `quantize_component_ccq`, the
//! *encoder* (`progressive.rs:315`). So the oracle simply applies the formula, FreeRDP
//! rejects the region, and the disagreement is reject-versus-accept rather than the two
//! different acceptances #167 described. The corpus cannot arbitrate it: no real region
//! carries a band below 6.
//!
//! # The layout mismatch this slice refuses rather than reproduces
//!
//! The first-pass decoder branches on `RFX_DWT_REDUCE_EXTRAPOLATE` (`:877`); the upgrade path
//! hardcodes the extrapolate band walk and takes no flag (`:1284-1324`). On a region that
//! omits the flag, FreeRDP therefore writes a first pass at one set of band offsets and
//! applies refinements at another — plausible pixels, no error, the silent shape #167 records.
//! [`TileGrid::decode_upgrade`] returns [`ProgressiveError::UpgradeWithoutExtrapolate`]
//! instead. That is stricter than FreeRDP on a receive path and carries a
//! deliberate-divergence row; it is unreachable on the corpus (52 of 52 regions set the flag),
//! so it is a FreeRDP-derived hypothesis rather than a measured behaviour — which is precisely
//! why guessing what such a server meant would be worse than refusing it.

use std::collections::HashMap;

use justrdp_pdu::rfx::TILE_DIM;
use justrdp_pdu::rfx::progressive::{
    FirstPassTile, ProgressiveMessage, ProgressiveQuant, ProgressiveRegion, QUALITY_FULL,
    REGION_FLAG_DWT_REDUCE_EXTRAPOLATE, TILE_FLAG_DIFFERENCE, UpgradeTile,
};

use super::quant::{BANDS_EXTRAPOLATE, BANDS_STANDARD, COMPONENT_LEN};
use super::{dwt, dwt_extrapolate, quant, rlgr, srl};
use crate::color;

/// Bytes one decoded tile occupies as RGBA8888.
pub const TILE_RGBA_LEN: usize = (TILE_DIM as usize) * (TILE_DIM as usize) * 4;

/// Why a Progressive tile failed to decode. Malformed input is always a typed error, never a
/// panic — [`crate::rfx::RfxError`]'s contract, and the invariant
/// `docs/map/invariant/untrusted-decode-never-panics.md` judges this surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressiveError {
    /// A first-pass component's RLGR stream is malformed.
    Rlgr(rlgr::RlgrError),
    /// An upgrade pass's SRL/raw refinement could not be applied. The tile's store is
    /// **discarded** when this happens: the pass refines in place and has already mutated an
    /// arbitrary prefix, so keeping it would carry a half-applied pass into every later
    /// refinement (#168's handover).
    Srl(srl::SrlError),
    /// A band's `bitPos` is 0, so `shift = bitPos - 1` has no value
    /// (`progressive_rfx_quant_lsub`, `progressive.c:98-138`).
    ZeroBitPosition,
    /// A first-pass band's dequantization shift is 16 or wider. Reachable because
    /// `shift = quant + prog_quant - 1` runs to 29, not to 15.
    ///
    /// FreeRDP's shift primitive refuses the same widths — `return -1` on both the generic
    /// and SSE3 paths (`prim_shift.c:38-39`) — but **what it does with the refusal is not
    /// what we do**, and the difference is worth stating rather than glossing. The `-1`
    /// propagates up to `progressive_decompress_tile_first`, whose caller is a
    /// `void CALLBACK` work item that discards it (`progressive.c:1659-1684`); the tile stays
    /// in `updatedTileIndices` and is blitted anyway, from a `sign` array that was already
    /// overwritten. FreeRDP therefore paints a stale tile and reports success. We fail the
    /// tile.
    ShiftOutOfRange(u8),
    /// An upgrade pass declared a *coarser* bit position than the pass before it, so
    /// `numBits = previous - current` underflows (`progressive_rfx_quant_sub`, `:143-189`).
    BitPositionUnderflow,
    /// A tile's `quantIdx` or `quality` is outside the region's tables. The parser validates
    /// both, but [`ProgressiveRegion`]'s fields are `pub`, so the guarantee lives in the
    /// parser and not in the type — the same shape as #211.
    QuantIndexOutOfRange,
    /// The tile's grid coordinates fall outside the surface.
    ///
    /// **Checked per axis, where the reference checks the linear index.** FreeRDP's bound is
    /// `zIdx >= surface->tilesSize` alone (`progressive.c:473-477`), so `(gridWidth + 5, 0)`
    /// passes it and aliases onto `(5, 1)` — a silent write to the wrong tile. Ours refuses
    /// that. It is also narrower in the other direction: FreeRDP's grid rounds *up to the next
    /// multiple* (`gridWidth = (width + (64 - width % 64)) / 64`, `progressive.c:447`, so
    /// 1280 -> 21 where `div_ceil` gives 20) and it 16-aligns the width before that
    /// (`gdi/gfx.c:1284`), so its grid is at least as wide as ours for every surface and it
    /// accepts a column we reject. Unreachable on the corpus, whose widest tile index is 19 on
    /// a 1280-wide surface.
    TileOutsideSurface {
        /// Column index the tile claimed.
        x_idx: u16,
        /// Row index the tile claimed.
        y_idx: u16,
    },
    /// An upgrade pass arrived for a tile no first pass has painted, so there is nothing to
    /// refine. FreeRDP refines a zeroed cache entry; we refuse, because the result is a tile
    /// built from refinements alone with no sign information to route them by.
    NoFirstPass {
        /// Column index the tile claimed.
        x_idx: u16,
        /// Row index the tile claimed.
        y_idx: u16,
    },
    /// An upgrade tile arrived for a tile whose store was written under the **non**-extrapolate
    /// layout, which the upgrade band walk has no variant for — see the module doc.
    /// Deliberately stricter than FreeRDP.
    UpgradeWithoutExtrapolate,
    /// The region carrying this upgrade declares a different band layout from the one the
    /// tile's store was written at. FreeRDP would refine at one layout and reconstruct at the
    /// other; we refuse rather than pick.
    LayoutChangedBetweenPasses,
    /// The caller's output buffer is not [`TILE_RGBA_LEN`] bytes.
    OutputBufferSize(usize),
    /// A payload carried two `RFX_PROGRESSIVE_FRAME_BEGIN` blocks. One of only two ordering
    /// violations FreeRDP refuses to continue past (`-1008`, `progressive.c:1921-1925`).
    DuplicateFrameBegin,
    /// A payload carried `RFX_PROGRESSIVE_FRAME_BEGIN` after `RFX_PROGRESSIVE_FRAME_END`. The
    /// other hard error (`progressive.c:1927-1932`).
    FrameBeginAfterFrameEnd,
}

impl core::fmt::Display for ProgressiveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProgressiveError::Rlgr(e) => write!(f, "RLGR decode: {e}"),
            ProgressiveError::Srl(e) => write!(f, "upgrade-pass refinement: {e}"),
            ProgressiveError::ZeroBitPosition => {
                write!(f, "a band's bit position is 0, so its shift is undefined")
            }
            ProgressiveError::ShiftOutOfRange(n) => {
                write!(
                    f,
                    "a band's dequantization shift is {n}, which must be under 16"
                )
            }
            ProgressiveError::BitPositionUnderflow => write!(
                f,
                "an upgrade pass declared a coarser bit position than the previous pass"
            ),
            ProgressiveError::QuantIndexOutOfRange => {
                write!(f, "a tile's quant index or quality is outside its table")
            }
            ProgressiveError::TileOutsideSurface { x_idx, y_idx } => {
                write!(f, "tile ({x_idx}, {y_idx}) lies outside the surface grid")
            }
            ProgressiveError::NoFirstPass { x_idx, y_idx } => {
                write!(f, "upgrade pass for unpainted tile ({x_idx}, {y_idx})")
            }
            ProgressiveError::UpgradeWithoutExtrapolate => write!(
                f,
                "upgrade pass for a tile stored under the non-extrapolate band layout"
            ),
            ProgressiveError::LayoutChangedBetweenPasses => write!(
                f,
                "the band layout changed between this tile's first pass and this upgrade"
            ),
            ProgressiveError::OutputBufferSize(n) => {
                write!(
                    f,
                    "tile output buffer is {n} bytes, expected {TILE_RGBA_LEN}"
                )
            }
            ProgressiveError::DuplicateFrameBegin => {
                write!(f, "duplicate RFX_PROGRESSIVE_FRAME_BEGIN in one payload")
            }
            ProgressiveError::FrameBeginAfterFrameEnd => write!(
                f,
                "RFX_PROGRESSIVE_FRAME_BEGIN after RFX_PROGRESSIVE_FRAME_END in one payload"
            ),
        }
    }
}

impl core::error::Error for ProgressiveError {}

impl From<rlgr::RlgrError> for ProgressiveError {
    fn from(e: rlgr::RlgrError) -> Self {
        ProgressiveError::Rlgr(e)
    }
}

impl From<srl::SrlError> for ProgressiveError {
    fn from(e: srl::SrlError) -> Self {
        ProgressiveError::Srl(e)
    }
}

/// One tile's cross-pass state: what a later `WireToSurface2` payload refines.
///
/// `current` is the coefficient store and `sign` is the tri-state routing array the upgrade
/// entropy layer reads (positive/negative → the raw stream, zero → SRL). `sign` is captured
/// from the RLGR output **before** the LL3 delta and the dequantization shifts, matching
/// `CopyMemory(sign, buffer, 4096 * 2)` at `progressive.c:876` — the sign of a *quantized*
/// coefficient, not of a reconstructed one.
///
/// 48 KiB per tile (three components × 4096 × two `i16` arrays), so instances are only
/// created for tiles a first pass has actually painted.
#[derive(Debug, Clone)]
pub struct TileState {
    current: [[i16; COMPONENT_LEN]; 3],
    sign: [[i16; COMPONENT_LEN]; 3],
    /// Per-component `quant + prog_quant` as of the last applied pass — what the next
    /// upgrade's `numBits` is measured against.
    bit_pos: [ProgressiveQuant; 3],
    /// The band layout this store was **written at**, taken from the region that carried the
    /// first pass.
    ///
    /// Recorded because region flags are per-`WBT_REGION` and a tile's passes need not arrive
    /// in the same region: reading the *current* region's flag to decide whether a refinement
    /// is compatible answers a question about the wrong pass. That was this module's own bug
    /// until #169's completeness pass reproduced it — a first pass in a region without
    /// `RFX_DWT_REDUCE_EXTRAPOLATE` followed by an upgrade in a region with it returned
    /// `Ok(())`, which is exactly the silent mismatch the guard exists to refuse.
    extrapolate: bool,
    /// Passes applied to this tile: 1 after a first pass, one more per upgrade.
    ///
    /// **Not FreeRDP's `tile->pass`**, which is *reset* to 1 by every first pass
    /// (`progressive.c:956`) and only incremented by upgrades (`:1368`). Ours counts
    /// cumulatively because a repeat first pass is a normal event on this server — 2943 of
    /// them over 260 tiles in one captured session — and "how many times has this tile been
    /// touched" is the question a caller can actually use. Nothing in the decode reads it;
    /// FreeRDP's own reads are a debug log line.
    passes: u32,
}

impl TileState {
    fn new() -> Box<Self> {
        Box::new(Self {
            current: [[0; COMPONENT_LEN]; 3],
            sign: [[0; COMPONENT_LEN]; 3],
            bit_pos: [ZERO_QUANT; 3],
            extrapolate: false,
            passes: 0,
        })
    }

    /// How many passes this tile has absorbed, counting every first pass and every upgrade.
    /// See the field for how this differs from FreeRDP's `tile->pass`.
    pub fn passes(&self) -> u32 {
        self.passes
    }

    /// The band layout this tile's coefficients were written at.
    pub fn is_extrapolate(&self) -> bool {
        self.extrapolate
    }

    /// Per-component `quant + prog_quant` as of the last applied pass — what the next
    /// upgrade's `numBits` is measured against. Exposed so a harness can census the derived
    /// arithmetic rather than the raw wire nibbles, which are a different quantity.
    pub fn bit_positions(&self) -> [ProgressiveQuant; 3] {
        self.bit_pos
    }

    /// One component's coefficient store, `0 = Y`, `1 = Cb`, `2 = Cr`.
    ///
    /// Exposed for verification: without it a harness can only observe the *pixels* a pass
    /// produced, and an upgrade pass that refined nothing paints the same pixels as the pass
    /// before it. Deleting the whole refinement was invisible to the corpus gate until this
    /// existed.
    pub fn coefficients(&self, component: usize) -> Option<&[i16]> {
        self.current.get(component).map(|c| c.as_slice())
    }

    /// One component's sign store — the tri-state array the upgrade entropy layer routes by,
    /// holding the coefficients exactly as the entropy decoder produced them.
    pub fn signs(&self, component: usize) -> Option<&[i16]> {
        self.sign.get(component).map(|c| c.as_slice())
    }
}

const ZERO_QUANT: ProgressiveQuant = ProgressiveQuant {
    ll3: 0,
    hl3: 0,
    lh3: 0,
    hh3: 0,
    hl2: 0,
    lh2: 0,
    hh2: 0,
    hl1: 0,
    lh1: 0,
    hh1: 0,
};

/// The `QUALITY_FULL` sentinel's progressive-quant table: all zeroes, so `bitPos = quant` and
/// `shift = quant - 1`.
///
/// Not a table lookup — `quality = 0xFF` means *no progressive quantization*, and FreeRDP's
/// `quantProgValFull` is a `calloc`'d struct it never fills (`progressive.c:2646-2654`).
/// Indexing a table by the sentinel is the oracle defect the corpus canary pins (#194).
const FULL_QUALITY: ProgressiveQuant = ZERO_QUANT;

/// Reusable per-call working buffers. Held by the caller so a frame's worth of tiles costs
/// one allocation rather than one per tile (`progressive->bufferPool`, `progressive.c:2667`).
#[derive(Debug)]
pub struct Scratch {
    component: Box<[i16; COMPONENT_LEN]>,
    temp: Box<[i16; COMPONENT_LEN]>,
    planes: [Box<[i16; COMPONENT_LEN]>; 3],
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

impl Scratch {
    /// Allocate one set of working buffers.
    pub fn new() -> Self {
        Self {
            component: Box::new([0; COMPONENT_LEN]),
            temp: Box::new([0; COMPONENT_LEN]),
            planes: [
                Box::new([0; COMPONENT_LEN]),
                Box::new([0; COMPONENT_LEN]),
                Box::new([0; COMPONENT_LEN]),
            ],
        }
    }
}

/// One surface's Progressive tile store: the grid its `xIdx`/`yIdx` are indices into, plus
/// the [`TileState`] of every tile a first pass has painted.
///
/// Tiles are held in a map rather than a dense array so an oversized surface costs nothing
/// until it is actually painted. The memory a peer can make this hold is then bounded by the
/// surface's tile count — but **the multiplier is worth carrying to #171 rather than
/// re-deriving**: a [`TileState`] is 48 KiB and covers 64 x 64 pixels, i.e. 16 KiB of RGBA,
/// so a fully-painted surface costs *three bytes of tile state per byte of framebuffer*.
/// `justrdp::egfx` caps a session at 256 MiB of surface, which is 16,384 tiles and therefore
/// ~768 MiB of store that its `total_surface_bytes` accounting does not currently see. The
/// dimensions come from a server `CREATESURFACE`, not from the host.
#[derive(Debug)]
pub struct TileGrid {
    grid_width: usize,
    grid_height: usize,
    tiles: HashMap<u32, Box<TileState>>,
}

impl TileGrid {
    /// A store for a `width × height` surface. The grid rounds up, so a surface whose last
    /// row or column is partial still has a tile for it (the corpus' 1280×800 surface is
    /// 20 × 13 tiles, and the bottom row covers only 32 of its 64 rows).
    pub fn new(width: u16, height: u16) -> Self {
        let (grid_width, grid_height) = grid_size_for(width, height);
        Self {
            grid_width,
            grid_height,
            tiles: HashMap::new(),
        }
    }

    /// The grid's `(columns, rows)` — the stride a tile index is resolved against, and
    /// therefore the thing that decides whether a resized surface may keep this store
    /// ([`SurfaceStore::grid_mut`]).
    pub fn grid_size(&self) -> (usize, usize) {
        (self.grid_width, self.grid_height)
    }

    /// The number of tiles this surface currently holds cross-pass state for.
    pub fn painted_tiles(&self) -> usize {
        self.tiles.len()
    }

    /// The cross-pass state of one tile, if a first pass has painted it.
    pub fn tile(&self, x_idx: u16, y_idx: u16) -> Option<&TileState> {
        self.z_index(x_idx, y_idx)
            .ok()
            .and_then(|z| self.tiles.get(&z))
            .map(Box::as_ref)
    }

    /// `zIdx = yIdx * gridWidth + xIdx`, bounded against the grid — the check the parse layer
    /// cannot make, because the surface dimensions are not in the block stream (#167's
    /// handover). The arithmetic is done in `usize` and the *inputs* are `u16`, so it cannot
    /// overflow on a 32-bit target: `65535 * 1024 + 65535` is well inside `u32`
    /// (`docs/map/invariant/decoder-dimension-overflow-32bit.md`).
    fn z_index(&self, x_idx: u16, y_idx: u16) -> Result<u32, ProgressiveError> {
        let (x, y) = (usize::from(x_idx), usize::from(y_idx));
        if x >= self.grid_width || y >= self.grid_height {
            return Err(ProgressiveError::TileOutsideSurface { x_idx, y_idx });
        }
        let z = y * self.grid_width + x;
        u32::try_from(z).map_err(|_| ProgressiveError::TileOutsideSurface { x_idx, y_idx })
    }

    /// Decode a `TILE_FIRST` or `TILE_SIMPLE` tile: seed this tile's cross-pass store and
    /// paint `out` (64 × 64 RGBA8888, top-down).
    ///
    /// Follows `progressive_decompress_tile_first` (`progressive.c:930-1073`). A tile
    /// carrying `RFX_TILE_DIFFERENCE` adds its coefficients to the store it already holds
    /// (saturating, `prim_add.c:59-69`) instead of replacing it — the inter-frame delta,
    /// which is a different mechanism from the LL3 delta below it and is *not* gated by the
    /// same flag.
    pub fn decode_first(
        &mut self,
        tile: &FirstPassTile<'_>,
        region: &ProgressiveRegion<'_>,
        scratch: &mut Scratch,
        out: &mut [u8],
    ) -> Result<(), ProgressiveError> {
        if out.len() != TILE_RGBA_LEN {
            return Err(ProgressiveError::OutputBufferSize(out.len()));
        }
        let z = self.z_index(tile.x_idx, tile.y_idx)?;
        let extrapolate = region.flags & REGION_FLAG_DWT_REDUCE_EXTRAPOLATE != 0;
        let prog = prog_quants(region, tile.quality)?;
        let quants = base_quants(
            region,
            [tile.quant_idx_y, tile.quant_idx_cb, tile.quant_idx_cr],
        )?;

        // Both derived tables, for all three components, before anything is mutated: a tile
        // whose arithmetic does not work out must leave the store exactly as it was.
        let mut bit_pos = [ZERO_QUANT; 3];
        let mut shift = [ZERO_QUANT; 3];
        for c in 0..3 {
            bit_pos[c] = quant_add(&quants[c], &prog[c]);
            shift[c] = first_pass_shift(&bit_pos[c])?;
        }

        let coeff_diff = tile.flags & TILE_FLAG_DIFFERENCE != 0;
        let data = [tile.y_data, tile.cb_data, tile.cr_data];

        // The store is entered here and **discarded on any failure below**. The entropy
        // decode is fallible per component, so a failure at Cb would otherwise leave Y
        // holding this pass's coefficients, Cb and Cr the previous pass's, and `bit_pos` the
        // previous pass's — a mixture a later upgrade then refines with `Ok(())`, measuring
        // `numBits` against one pass over another pass's coefficients. That is the same
        // non-local corruption `SrlError` is discarded for (#168), and `decode_first` had no
        // equivalent until #169's completeness pass reproduced it.
        let state = self.tiles.entry(z).or_insert_with(TileState::new);
        let painted = (|| -> Result<(), ProgressiveError> {
            for c in 0..3 {
                rlgr::decode(
                    justrdp_pdu::rfx::EntropyAlgorithm::Rlgr1,
                    data[c],
                    scratch.component.as_mut_slice(),
                )?;
                // The sign store is the *quantized* coefficients, captured before the LL3
                // delta and before the shifts (`progressive.c:876`).
                state.sign[c].copy_from_slice(scratch.component.as_slice());
                dequantize_first_pass(scratch.component.as_mut_slice(), &shift[c], extrapolate);

                if coeff_diff {
                    for (buf, cur) in scratch
                        .component
                        .iter_mut()
                        .zip(state.current[c].iter_mut())
                    {
                        let sum = buf.saturating_add(*cur);
                        *buf = sum;
                        *cur = sum;
                    }
                } else {
                    state.current[c].copy_from_slice(scratch.component.as_slice());
                }

                if extrapolate {
                    dwt_extrapolate::decode(
                        scratch.component.as_mut_slice(),
                        scratch.temp.as_mut_slice(),
                    );
                } else {
                    dwt::decode(
                        scratch.component.as_mut_slice(),
                        scratch.temp.as_mut_slice(),
                    );
                }
                scratch.planes[c].copy_from_slice(scratch.component.as_slice());
            }
            state.bit_pos = bit_pos;
            state.extrapolate = extrapolate;
            state.passes += 1;
            Ok(())
        })();

        if let Err(e) = painted {
            self.tiles.remove(&z);
            return Err(e);
        }

        color::rfx_ycbcr_to_rgba(
            scratch.planes[0].as_slice(),
            scratch.planes[1].as_slice(),
            scratch.planes[2].as_slice(),
            out,
        );
        Ok(())
    }

    /// Decode a `TILE_UPGRADE` tile: refine this tile's store in place and repaint `out`.
    ///
    /// Follows `progressive_decompress_tile_upgrade` (`progressive.c:1332-1513`). The inverse
    /// DWT runs over a *copy* of the store, never over the store itself
    /// (`progressive_rfx_dwt_2d_decode(..., reverse = TRUE)`, `:821-822`) — which is also why
    /// `RFX_TILE_DIFFERENCE` has no effect on this path.
    pub fn decode_upgrade(
        &mut self,
        tile: &UpgradeTile<'_>,
        region: &ProgressiveRegion<'_>,
        scratch: &mut Scratch,
        out: &mut [u8],
    ) -> Result<(), ProgressiveError> {
        if out.len() != TILE_RGBA_LEN {
            return Err(ProgressiveError::OutputBufferSize(out.len()));
        }
        let z = self.z_index(tile.x_idx, tile.y_idx)?;
        let prog = prog_quants(region, Some(tile.quality))?;
        let quants = base_quants(
            region,
            [tile.quant_idx_y, tile.quant_idx_cb, tile.quant_idx_cr],
        )?;
        let Some(state) = self.tiles.get(&z) else {
            return Err(ProgressiveError::NoFirstPass {
                x_idx: tile.x_idx,
                y_idx: tile.y_idx,
            });
        };

        // Both layout checks are against **the store**, not against this region. Region flags
        // are per-`WBT_REGION` and a tile's passes need not arrive in the same region, so the
        // current region's flag describes the wrong pass.
        if !state.extrapolate {
            // There is no non-extrapolate band walk to refine with — the upgrade path has one
            // layout and it is the extrapolate one (`progressive.c:1284-1324`).
            return Err(ProgressiveError::UpgradeWithoutExtrapolate);
        }
        if region.flags & REGION_FLAG_DWT_REDUCE_EXTRAPOLATE == 0 {
            // The walk would match but the reconstruction would not: FreeRDP forwards the
            // *current* region's flag to the inverse DWT (`progressive.c:1327-1328`) while
            // hardcoding the extrapolate walk, so it would refine one layout and transform
            // another. Refused rather than picked.
            return Err(ProgressiveError::LayoutChangedBetweenPasses);
        }

        // Every derived table for all three components before any refinement is applied —
        // FreeRDP's own ordering (`:1439-1447`), and the reason a tile whose bit positions do
        // not line up leaves the store untouched rather than half-refined.
        let mut bit_pos = [ZERO_QUANT; 3];
        let mut num_bits = [ZERO_QUANT; 3];
        let mut shift = [ZERO_QUANT; 3];
        {
            let state = &self.tiles[&z];
            for c in 0..3 {
                bit_pos[c] = quant_add(&quants[c], &prog[c]);
                num_bits[c] = quant_sub(&state.bit_pos[c], &bit_pos[c])?;
                // `shift` here feeds `srl::upgrade_component`, which is total for any `u8`
                // and reports an unrepresentable refinement as a typed error (#168). Only the
                // `bitPos >= 1` half of the first pass's guard applies on this path — the
                // 16-bit shift primitive is not in it.
                shift[c] = upgrade_shift(&bit_pos[c])?;
            }
        }

        let streams = [
            (tile.y_srl, tile.y_raw),
            (tile.cb_srl, tile.cb_raw),
            (tile.cr_srl, tile.cr_raw),
        ];
        let state = self
            .tiles
            .get_mut(&z)
            .expect("presence checked immediately above");

        for c in 0..3 {
            let (srl_data, raw_data) = streams[c];
            if let Err(e) = srl::upgrade_component(
                srl_data,
                raw_data,
                &shift[c],
                &num_bits[c],
                &mut state.current[c],
                &mut state.sign[c],
            ) {
                // The refinement mutates in place and has already touched an arbitrary
                // prefix, so the store is discarded rather than kept (#168's handover). The
                // next first pass for this tile re-seeds it.
                self.tiles.remove(&z);
                return Err(ProgressiveError::Srl(e));
            }
            scratch
                .component
                .copy_from_slice(state.current[c].as_slice());
            dwt_extrapolate::decode(
                scratch.component.as_mut_slice(),
                scratch.temp.as_mut_slice(),
            );
            scratch.planes[c].copy_from_slice(scratch.component.as_slice());
        }

        state.bit_pos = bit_pos;
        state.passes += 1;
        color::rfx_ycbcr_to_rgba(
            scratch.planes[0].as_slice(),
            scratch.planes[1].as_slice(),
            scratch.planes[2].as_slice(),
            out,
        );
        Ok(())
    }
}

/// Resolve a tile's three base-quant entries. The parser validates every index, but
/// [`ProgressiveRegion`] is a `pub` struct with `pub` fields, so the guarantee lives in the
/// parser rather than in the type — the same shape #211 records for `dequantize`.
fn base_quants(
    region: &ProgressiveRegion<'_>,
    indices: [u8; 3],
) -> Result<[ProgressiveQuant; 3], ProgressiveError> {
    let mut out = [ZERO_QUANT; 3];
    for (slot, idx) in out.iter_mut().zip(indices) {
        *slot = *region
            .quants
            .get(usize::from(idx))
            .ok_or(ProgressiveError::QuantIndexOutOfRange)?;
    }
    Ok(out)
}

/// Resolve a tile's progressive-quant triple. `None` (TILE_SIMPLE, which carries no quality
/// byte) and [`QUALITY_FULL`] both mean *no progressive quantization*.
fn prog_quants(
    region: &ProgressiveRegion<'_>,
    quality: Option<u8>,
) -> Result<[ProgressiveQuant; 3], ProgressiveError> {
    match quality {
        None | Some(QUALITY_FULL) => Ok([FULL_QUALITY; 3]),
        Some(q) => {
            let entry = region
                .prog_quants
                .get(usize::from(q))
                .ok_or(ProgressiveError::QuantIndexOutOfRange)?;
            Ok([entry.y, entry.cb, entry.cr])
        }
    }
}

/// The per-band nibbles of a [`ProgressiveQuant`] in band order — the same order
/// [`BANDS_STANDARD`] / [`BANDS_EXTRAPOLATE`] and [`super::srl`] use.
fn bands_of(q: &ProgressiveQuant) -> [u8; 10] {
    [
        q.hl1, q.lh1, q.hh1, q.hl2, q.lh2, q.hh2, q.hl3, q.lh3, q.hh3, q.ll3,
    ]
}

/// Rebuild a [`ProgressiveQuant`] from per-band values in [`bands_of`] order.
fn quant_from_bands(v: [u8; 10]) -> ProgressiveQuant {
    ProgressiveQuant {
        hl1: v[0],
        lh1: v[1],
        hh1: v[2],
        hl2: v[3],
        lh2: v[4],
        hh2: v[5],
        hl3: v[6],
        lh3: v[7],
        hh3: v[8],
        ll3: v[9],
    }
}

/// `bitPos = quant + prog_quant`, band by band (`progressive_rfx_quant_add`,
/// `progressive.c:81-95`). Both operands are 4-bit nibbles off the wire, so the sum is at
/// most 30 and cannot overflow `u8` — but the *type* does not say so, and the sum is exactly
/// the value #168 proved is not a nibble, so it saturates rather than wrapping.
fn quant_add(a: &ProgressiveQuant, b: &ProgressiveQuant) -> ProgressiveQuant {
    let (a, b) = (bands_of(a), bands_of(b));
    let mut out = [0u8; 10];
    for i in 0..10 {
        out[i] = a[i].saturating_add(b[i]);
    }
    quant_from_bands(out)
}

/// `numBits = previous - current`, band by band, rejecting the tile on any underflow
/// (`progressive_rfx_quant_sub`, `progressive.c:143-189`). An upgrade pass may only refine.
fn quant_sub(
    previous: &ProgressiveQuant,
    current: &ProgressiveQuant,
) -> Result<ProgressiveQuant, ProgressiveError> {
    let (p, c) = (bands_of(previous), bands_of(current));
    let mut out = [0u8; 10];
    for i in 0..10 {
        out[i] = p[i]
            .checked_sub(c[i])
            .ok_or(ProgressiveError::BitPositionUnderflow)?;
    }
    Ok(quant_from_bands(out))
}

/// `shift = bitPos - 1`, band by band, and the two ways FreeRDP refuses the result.
///
/// - A band whose `bitPos` is 0 has no shift at all — `progressive_rfx_quant_lsub(&shift, 1)`
///   returns `FALSE` and the tile is dropped (`progressive.c:98-138`, called at `:1023`).
/// - A shift of **16 or more** is refused by the shift primitive itself, which returns `-1`
///   (`prim_shift.c:38-39`, reached via `progressive_rfx_decode_block` at
///   `progressive.c:850-858`). We fail the tile on it; FreeRDP's own handling of that `-1` is
///   weaker — see [`ProgressiveError::ShiftOutOfRange`].
///
/// The second is easy to miss because the value looks bounded: `bitPos = quant + prog_quant`
/// is a *sum* of two nibbles, so it reaches [`super::srl::MAX_BIT_POS`] (30) and `shift`
/// reaches 29 — and more than half of that range is refused here. Checking here rather than at the shift keeps the whole
/// derived table validated before the store is touched — a tile whose arithmetic does not
/// work out must leave the previous pass exactly as it was.
fn first_pass_shift(bit_pos: &ProgressiveQuant) -> Result<ProgressiveQuant, ProgressiveError> {
    let b = bands_of(bit_pos);
    let mut out = [0u8; 10];
    for i in 0..10 {
        let shift = b[i]
            .checked_sub(1)
            .ok_or(ProgressiveError::ZeroBitPosition)?;
        if shift >= 16 {
            return Err(ProgressiveError::ShiftOutOfRange(shift));
        }
        out[i] = shift;
    }
    Ok(quant_from_bands(out))
}

/// `shift = bitPos - 1` for the upgrade path, which shares only the first of
/// [`first_pass_shift`]'s two refusals: the refinement accumulate is written by hand in
/// FreeRDP (`progressive.c:1221-1224`) rather than going through the shift primitive, so a
/// width of 16 or more is not refused there. What bounds it instead is
/// [`super::srl::upgrade_component`]'s own contract — total for any `u8`, with an
/// unrepresentable result as a typed error.
fn upgrade_shift(bit_pos: &ProgressiveQuant) -> Result<ProgressiveQuant, ProgressiveError> {
    let b = bands_of(bit_pos);
    let mut out = [0u8; 10];
    for i in 0..10 {
        out[i] = b[i]
            .checked_sub(1)
            .ok_or(ProgressiveError::ZeroBitPosition)?;
    }
    Ok(quant_from_bands(out))
}

/// The first pass's two inverse steps between entropy decode and the DWT: reconstruct the LL3
/// band's differential coding, then shift every band left by its own `shift` nibble
/// (`progressive_rfx_decode_component`, `progressive.c:861-928`).
///
/// The band table is chosen by the region's flag — this is the branch the upgrade path does
/// not have, and the reason [`TileGrid::decode_upgrade`] refuses the combination.
///
/// The shift itself is a **wrapping 16-bit** one, not a saturating or widening one:
/// FreeRDP's primitive is `(int16_t)(((UINT32)val << sh) & 0xFFFF)` (`prim_shift.c:27-31`),
/// which is also what the sibling WireToSurface1 dequantizer does. Shift widths of 16 or more
/// are rejected before any of this runs — see [`first_pass_shift`].
fn dequantize_first_pass(component: &mut [i16], shift: &ProgressiveQuant, extrapolate: bool) {
    let bands = if extrapolate {
        BANDS_EXTRAPOLATE
    } else {
        BANDS_STANDARD
    };
    let (ll3_offset, ll3_len) = bands[9];
    quant::ll3_delta_decode(&mut component[ll3_offset..ll3_offset + ll3_len]);

    for (&(offset, length), factor) in bands.iter().zip(bands_of(shift)) {
        debug_assert!(factor < 16, "first_pass_shift rejects a wider shift");
        if factor == 0 {
            continue;
        }
        for value in &mut component[offset..offset + length] {
            *value <<= factor;
        }
    }
}

/// An ordering rule the payload broke that FreeRDP **tolerates** — it logs and carries on.
///
/// Reported rather than logged because this crate has no logging dependency, and reported at
/// all because the alternative is silence: the assembly layer (#171) turns these into the
/// `WLog_WARN` FreeRDP emits, and a test can assert that a stream tripped exactly the row it
/// was built to trip. The two violations FreeRDP does *not* tolerate are
/// [`ProgressiveError::DuplicateFrameBegin`] and [`ProgressiveError::FrameBeginAfterFrameEnd`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderAnomaly {
    /// A second `RFX_PROGRESSIVE_SYNC` (`progressive.c:1879-1880`).
    DuplicateSync,
    /// A second `RFX_PROGRESSIVE_CONTEXT` (`progressive.c:2012-2013`).
    DuplicateContext,
    /// `RFX_PROGRESSIVE_CONTEXT` after `RFX_PROGRESSIVE_FRAME_BEGIN` (`progressive.c:2008`).
    ContextAfterFrameBegin,
    /// `RFX_PROGRESSIVE_CONTEXT` after `RFX_PROGRESSIVE_FRAME_END` (`progressive.c:2010`).
    ContextAfterFrameEnd,
    /// `RFX_PROGRESSIVE_FRAME_END` with no preceding `FRAME_BEGIN` (`progressive.c:1967`).
    ///
    /// Tolerated, but it still ends the frame: everything after it sees `FLAG_WBT_FRAME_END`,
    /// so a later `FRAME_BEGIN` is fatal and a later region is skipped. A stray `FRAME_END`
    /// therefore costs the rest of the payload even though the block itself is forgiven.
    FrameEndWithoutFrameBegin,
    /// A second `RFX_PROGRESSIVE_FRAME_END` (`progressive.c:1969-1970`).
    DuplicateFrameEnd,
    /// A region arrived before `FRAME_BEGIN`; **this region is skipped**, the payload
    /// continues (`progressive.c:2146-2150`).
    RegionBeforeFrameBegin,
    /// A region arrived after `FRAME_END`; skipped the same way (`progressive.c:2151-2155`).
    RegionAfterFrameEnd,
}

/// Which of one payload's regions survive the block-ordering rules, and what the payload broke
/// getting there. Produced by [`order_payload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadOrder<'m, 'a> {
    /// The regions to decode into the surface's store, in wire order. Shorter than the
    /// payload's region count exactly when a region was skipped — every skip has a matching
    /// [`OrderAnomaly`].
    ///
    /// **Decoding these is not the same as presenting them.** FreeRDP clips a payload's whole
    /// accumulated dirty set against one region's rects and blits that
    /// (`update_tiles`, `progressive.c:2329-2352`) — it does not blit each region as it walks.
    /// Where a payload carries more than one region, or [`Self::fatal`] is set, "decode these"
    /// and "show these" diverge, and resolving that is the assembly layer's (#171).
    pub regions: Vec<&'m ProgressiveRegion<'a>>,
    /// Every tolerated rule violation, in the order the blocks tripped them. A payload may
    /// trip several: FreeRDP's checks are independent `if`s, not an `else if` chain.
    pub anomalies: Vec<OrderAnomaly>,
    /// The ordering violation that ended the walk, if one did — always
    /// [`ProgressiveError::DuplicateFrameBegin`] or
    /// [`ProgressiveError::FrameBeginAfterFrameEnd`], the only two FreeRDP refuses to continue
    /// past.
    ///
    /// **The regions before it still stand.** This is deliberately not an `Err`, because the
    /// alternative contradicts this function's own rule for the skip rows — a stray region
    /// must not cost the well-formed ones beside it, and neither may a late block. FreeRDP
    /// decodes each region into the store as it walks (`progressive.c:2461-2467`) and its
    /// `goto fail` skips only the blit, leaving `rc = 1`: the payload reports **success** and
    /// the already-decoded tiles stay dirty for the next payload of the frame. So a caller
    /// decodes [`Self::regions`] either way and withholds the *presentation* when this is set.
    pub fatal: Option<ProgressiveError>,
}

/// Apply FreeRDP's block-ordering rules to **one** `WireToSurface2` payload's message list.
///
/// # This is per payload, and that is the whole design
///
/// FreeRDP keeps the rules in a bitmask (`WBT_STATE_FLAG`, `progressive.h:204-210`) that reads
/// like decoder state — and `progressive_decompress` zeroes it at its top
/// (`progressive.c:2463`), while `gdi_SurfaceCommand_Progressive` calls that function once per
/// surface command (`gdi/gfx.c:1116`). So the mask never spans two payloads, and this is a
/// pure function over one message list rather than a field on a decoder.
///
/// The distinction is not academic. Censused over the 52-payload corpus, **51 payloads are
/// `FRAME_BEGIN REGION FRAME_END`** with no `SYNC` and no `CONTEXT` — the server sends the
/// header blocks once per stream. Carried across payloads, payload 2's `FRAME_BEGIN` is a
/// duplicate *and* follows payload 1's `FRAME_END`, so both hard errors fire: measured,
/// per-stream state rejects **51 of 52** real payloads where per-payload state rejects none.
/// [`crate::rfx::progressive`]'s corpus test asserts that number rather than describing it.
///
/// # Three outcomes, not two
///
/// FreeRDP's six conditions produce three different outcomes, so a single "validate the
/// ordering" pass would be wrong on four of the six rows: two are fatal, two skip *one region*
/// and continue, and the rest are logged and ignored. Neither `SYNC` nor `CONTEXT` is ever
/// *required* — nothing anywhere reads `FLAG_WBT_SYNC` or `FLAG_WBT_CONTEXT` except its own
/// duplicate check, which is the same tolerance the deliberate-divergence table records for
/// `codecContextId` (#194).
///
/// # The one thing this drops, and why it is inert rather than harmless
///
/// `PROGRESSIVE_BLOCK_CONTEXT` *is* cross-payload state in FreeRDP — a decoder struct field
/// (`progressive.h:220`) that `progressive->state = 0` does not touch, so on a payload with no
/// `CONTEXT` block its `flags` are whatever the last one left. This function takes a message
/// list and returns regions; those flags go nowhere. That is safe **only for as long as
/// `RFX_SUBBAND_DIFFING` stays inert**: both consumers declare the parameter dead
/// (`WINPR_ATTR_UNUSED BOOL subbandDiff`, `progressive.c:866` and `:1265`) and the sole live
/// read of `context->flags` is a `WLog_WARN` (`:1436`). #168 settled the same point from the
/// other direction. If a reference ever gives the flag an effect, this is the line that breaks.
pub fn order_payload<'m, 'a>(messages: &'m [ProgressiveMessage<'a>]) -> PayloadOrder<'m, 'a> {
    // FreeRDP's `WBT_STATE_FLAG` bits, as booleans — the mask buys nothing here, and the
    // names are what the conditions below actually read.
    let (mut sync, mut context, mut frame_begin, mut frame_end) = (false, false, false, false);
    let mut order = PayloadOrder {
        regions: Vec::new(),
        anomalies: Vec::new(),
        fatal: None,
    };

    for message in messages {
        match message {
            ProgressiveMessage::Sync => {
                if sync {
                    order.anomalies.push(OrderAnomaly::DuplicateSync);
                }
                sync = true;
            }
            ProgressiveMessage::Context { .. } => {
                // Three independent checks, in FreeRDP's order — a block can trip all three.
                if frame_begin {
                    order.anomalies.push(OrderAnomaly::ContextAfterFrameBegin);
                }
                if frame_end {
                    order.anomalies.push(OrderAnomaly::ContextAfterFrameEnd);
                }
                if context {
                    order.anomalies.push(OrderAnomaly::DuplicateContext);
                }
                context = true;
            }
            ProgressiveMessage::FrameBegin { .. } => {
                // The walk stops here, but what it already accepted is kept — see
                // `PayloadOrder::fatal`.
                if frame_begin {
                    order.fatal = Some(ProgressiveError::DuplicateFrameBegin);
                    break;
                }
                if frame_end {
                    order.fatal = Some(ProgressiveError::FrameBeginAfterFrameEnd);
                    break;
                }
                frame_begin = true;
            }
            ProgressiveMessage::FrameEnd => {
                if !frame_begin {
                    order
                        .anomalies
                        .push(OrderAnomaly::FrameEndWithoutFrameBegin);
                }
                if frame_end {
                    order.anomalies.push(OrderAnomaly::DuplicateFrameEnd);
                }
                frame_end = true;
            }
            ProgressiveMessage::Region(region) => {
                // The skip is per region, not per payload: a stray region must not cost the
                // well-formed ones beside it.
                if !frame_begin {
                    order.anomalies.push(OrderAnomaly::RegionBeforeFrameBegin);
                } else if frame_end {
                    order.anomalies.push(OrderAnomaly::RegionAfterFrameEnd);
                } else {
                    order.regions.push(region);
                }
            }
        }
    }

    order
}

/// Every live surface's Progressive tile store — the object whose lifecycle is issue #170.
///
/// # What frees a store, and what does not
///
/// Read off the reference rather than reasoned from the PDU names, because the two disagree:
///
/// | Event | Effect | Reference |
/// |---|---|---|
/// | first `WireToSurface2` for a surface | create, lazily | `progressive.c:543-563` |
/// | `RDPGFX_CMDID_DELETESURFACE` | **free** — the only free path | `gdi/gfx.c:1366` |
/// | `RDPGFX_CMDID_DELETEENCODINGCONTEXT` | **nothing** | `gdi/gfx.c:1239-1246` |
/// | `RDPGFX_CMDID_RESETGRAPHICS` | **nothing** (surface *pixels* are wiped) | `progressive.c:2635` |
/// | channel close | free everything, **by dropping this** — there is no method | `justrdp/src/egfx.rs:725` |
///
/// **`DELETEENCODINGCONTEXT` frees nothing, but not because it names nothing.** The PDU
/// carries a `surfaceId` beside the `codecContextId` (`[MS-RDPEGFX]` 2.2.2.13; our parser
/// decodes both, `justrdp-pdu/src/egfx.rs:224-228`), so a surface-keyed store *could* honour
/// it exactly. The reason to ignore it is tolerance, not inability: `[MS-RDPEGFX]` has no
/// client-side processing rule compelling the free, FreeRDP's handler is a literal no-op
/// (`WINPR_UNUSED` on both arguments), and a server that sends this and then a
/// `RFX_TILE_DIFFERENCE` tile is decoded **correctly** by keeping the store and against
/// zeroes by freeing it. Under ADR-0009 the tolerant branch wins. What that gives up is the
/// server's only way to say "you may reclaim this", which leaves `DELETESURFACE` as the sole
/// free path on a desktop surface that is never deleted.
///
/// The `codecContextId` is separately not an identity here: FreeRDP reads it once, warns when
/// it is non-zero (`progressive.c:1999`) and never uses it again, and the corpus carries 24
/// distinct ids over 52 payloads on **one** surface.
///
/// **`RESETGRAPHICS` not freeing needs its citation read to the end.** `gdi_ResetGraphics`
/// runs to `gdi/gfx.c:170`, and after wiping the surfaces it calls `freerdp_client_codecs_reset`
/// twice (`:156`, `:161`) — which reaches `progressive_context_reset`. That looks like a free
/// and is not: the function is `return (progressive != nullptr);` (`progressive.c:2635`). The
/// row is right because of the stub, so the stub is what it cites.
///
/// Keeping is also the weakly dominant choice on its own terms. The server's *encoder* holds
/// reference frames across a reset, and `RFX_TILE_DIFFERENCE` — which 1405 of 2943 real first
/// passes carry — adds against that shared reference; an encoder that *did* reset cannot send
/// a difference tile at all, since a diff against zero is a plain first pass. So keeping is
/// harmless when the server resets and necessary when it does not, while clearing is wrong in
/// the second case. `[MS-RDPEGFX]` 2.2.2.14 is silent, so neither branch is spec-mandated.
///
/// # There is deliberately no `reset`, and that is the guard rather than a doc note
///
/// Clearing every store at once is a real event — the EGFX channel closing — and it already has
/// a mechanism: `GraphicsProcessor::close()` is `*self = GraphicsProcessor::default()`
/// (`justrdp/src/egfx.rs:725`, reached from `dvc.rs:356` on `DvcMessage::Close`), which drops
/// this store along with the surfaces, the cache and the mappings. A `reset` here would
/// duplicate that, and of the two only the duplicate can be misused: `*self = default()` is
/// obviously wrong in a `RESETGRAPHICS` handler because it discards far more than the PDU
/// touches, while `store.reset()` reads exactly right there and is the desync above.
///
/// So the method is absent, and what remains is [`SurfaceStore::delete_surface`], which
/// **requires a surface id**. `RDPGFX_CMDID_RESETGRAPHICS` carries a width and a height and no
/// surface id (`[MS-RDPEGFX]` 2.2.2.14), so it has nothing to call: the mistake is unspellable
/// rather than merely documented. Keep it that way — an "and clear everything" convenience here
/// hands the footgun straight back.
///
/// # The live client still does the opposite, and a passing test pins it
///
/// `justrdp::egfx` today calls `Progressive::reset()` on `RESETGRAPHICS`
/// (`justrdp/src/egfx.rs:319`) and really frees on `DELETEENCODINGCONTEXT` (`:484`), and
/// `reset_graphics_clears_contexts_but_keeps_surfaces` (`:1206`) asserts the first. Both are
/// **correct for the bootstrap oracle**, which keys by `codecContextId` with no cap — that is
/// #83's fix, and under id keying an unfreed context is an unbounded leak. They stop being
/// correct the moment the store is surface-keyed. Retiring those two call sites and that test
/// belongs to the slice that swaps the decoder (#172); it is named here because a green test
/// asserting the retired behaviour is the strongest possible "do not touch this", and nothing
/// else in the tree says otherwise.
///
/// # What this table does *not* cover
///
/// FreeRDP's per-surface context holds a second sub-state with its own reset trigger:
/// `frameId`, `numUpdatedTiles`, `updatedTileIndices` and a per-tile `dirty` flag
/// (`progressive.h:190-201`), cleared not by any of the rows above but by the frame id
/// changing (`progressive.c:2437-2441`). It decides *what gets blitted* — `update_tiles` walks
/// every tile dirtied so far in the current frame, not just this payload's (`:2346`) — which
/// is why FreeRDP persists decoded pixels per tile at all. [`TileGrid`] keeps coefficients and
/// writes pixels into a caller's buffer, so it models none of this. Deferred-blit behaviour is
/// therefore not merely unimplemented but unreachable from the current shape; it is the
/// assembly layer's (#171), recorded here so that slice does not inherit a table that reads
/// complete.
///
/// # The leak is closed by the key, not by a cap
///
/// #83 asked for a defensive cap on the live-context count, because an id-keyed map with no
/// cap grows for the life of the session — on the corpus, 24 contexts in 75 seconds with no
/// teardown, and 2940 live tile stores against 260. Keyed by surface there is nothing left to
/// cap: the store holds one grid per live surface and `justrdp::egfx` already budgets those
/// (`MAX_TOTAL_SURFACE_BYTES`). What that budget does *not* yet see is the grid's own cost —
/// a `TileState` is 48 KiB per 16 KiB of RGBA — which is why [`SurfaceStore::live_surfaces`]
/// and [`TileGrid::painted_tiles`] are observable; the accounting itself is #171's.
///
/// # What the corpus cannot say
///
/// It contains **no teardown at all** — no `DELETESURFACE`, no `DELETEENCODINGCONTEXT`, no
/// reset. So every row above except "create, lazily" rests on FreeRDP alone, which under this
/// repo's receive-path tie-breaker makes them hypotheses rather than measured behaviour
/// (`docs/agents/theflow.md`). They are recorded here so the next capture can falsify them.
#[derive(Debug, Default)]
pub struct SurfaceStore {
    grids: HashMap<u16, TileGrid>,
}

impl SurfaceStore {
    /// A store holding no surfaces.
    pub fn new() -> Self {
        Self {
            grids: HashMap::new(),
        }
    }

    /// This surface's tile store, created on first use and **reused** afterwards — the reuse
    /// is what carries a tile's coefficients from one payload to the next.
    ///
    /// A grid whose dimensions would no longer match `width`/`height` is **replaced** rather
    /// than reused, and that is a deliberate divergence: FreeRDP's create is idempotent on the
    /// surface id alone (`progressive.c:546-548`), so a surface recreated at a new size keeps
    /// the old `gridWidth` and every `zIdx = yIdx * gridWidth + xIdx` silently addresses the
    /// wrong tile.
    ///
    /// The comparison is on the **grid**, not on the pixel dimensions: a surface that shrinks
    /// from 1280 to 1277 keeps a 20-column grid, so every tile index still means what it meant
    /// and there is nothing to discard. Only the *width* can invalidate an index that way;
    /// height is compared too, and deliberately — a grid that lost rows has tiles addressable
    /// past its own end, and discarding is the safe direction on the axis that cannot alias.
    ///
    /// **This branch is currently unreachable through the client, and that is the point.**
    /// `[MS-RDPEGFX]` has no surface-resize PDU and `justrdp::egfx` writes a surface's
    /// dimensions once at `CREATESURFACE` (`justrdp/src/egfx.rs:354`), dropping the whole
    /// surface through `remove_surface` when an id is reused — so the dims handed here always
    /// match. That is a property of today's caller, not of this type, and it is exactly the
    /// kind of caller-side guarantee that stops holding quietly. The check costs one
    /// comparison; the failure it prevents is silent wrong pixels.
    ///
    /// It does **not** cover a `CREATESURFACE` that reuses an id at the *same* size: the
    /// stride is unchanged, so a brand-new surface inherits the previous one's coefficients
    /// while its RGBA starts zeroed. FreeRDP has the same hole. Closing it needs the caller to
    /// call [`SurfaceStore::delete_surface`] on the replace path, which is #172's wiring.
    pub fn grid_mut(&mut self, surface_id: u16, width: u16, height: u16) -> &mut TileGrid {
        let wanted = grid_size_for(width, height);
        if self
            .grids
            .get(&surface_id)
            .is_some_and(|g| g.grid_size() != wanted)
        {
            self.grids.remove(&surface_id);
        }
        self.grids
            .entry(surface_id)
            .or_insert_with(|| TileGrid::new(width, height))
    }

    /// This surface's tile store, if one has been created — the read-only view, for callers
    /// that must not create one by asking.
    pub fn grid(&self, surface_id: u16) -> Option<&TileGrid> {
        self.grids.get(&surface_id)
    }

    /// Free one surface's store: `RDPGFX_CMDID_DELETESURFACE`, or a `CREATESURFACE` that
    /// replaces a live id. Freeing a surface that has no store is a no-op — a server may
    /// delete a surface no `WireToSurface2` ever reached.
    ///
    /// Discarding a **painted** store is the desync this type's doc argues about, seen from
    /// the inside: every later `RFX_TILE_DIFFERENCE` tile for that surface then adds against
    /// zeroes, and [`TileGrid::decode_first`] reports `Ok` while doing it. Nothing here can
    /// prevent that — the server asked — but a caller that wants it in a log can read
    /// [`SurfaceStore::grid`] and [`TileGrid::painted_tiles`] before calling.
    pub fn delete_surface(&mut self, surface_id: u16) {
        self.grids.remove(&surface_id);
    }

    /// `RDPGFX_CMDID_DELETEENCODINGCONTEXT` — **deliberately frees nothing.**
    ///
    /// It exists as a method rather than as an absence so the decision is met at the call
    /// site: FreeRDP's handler is a literal no-op (`WINPR_UNUSED` on both arguments,
    /// `gdi/gfx.c:1239-1246`), and under surface keying a `codecContextId` names nothing this
    /// store holds. See the type doc for why the id is not an identity on the real wire.
    pub fn delete_context(&mut self, _codec_context_id: u32) {}

    /// How many surfaces currently hold a tile store. The observable #170's lifecycle tests
    /// assert against, and the count #171 needs to charge tile state to the surface budget.
    pub fn live_surfaces(&self) -> usize {
        self.grids.len()
    }
}

/// The tile grid a `width × height` surface addresses — rounded up, so a partial last row or
/// column still has a tile. Shared by [`TileGrid::new`] and the staleness check in
/// [`SurfaceStore::grid_mut`], which must agree by construction rather than by inspection.
fn grid_size_for(width: u16, height: u16) -> (usize, usize) {
    (
        usize::from(width).div_ceil(usize::from(TILE_DIM)),
        usize::from(height).div_ceil(usize::from(TILE_DIM)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::rfx::progressive::ProgressiveCodecQuant;
    use proptest::prelude::*;

    /// A short RLGR1 stream whose first eight HL1 coefficients are
    /// `[0, 0, -2, 0, 0, 2, -1, -1]` — measured, not chosen: it is the shortest input found
    /// that carries zero, positive and negative coefficients, which is what makes the
    /// tri-state sign routing observable. Everything past the stream zero-fills.
    const MIXED_SIGNS: &[u8] = &[0x55, 0xAA, 0x12, 0x34];

    fn uniform(n: u8) -> ProgressiveQuant {
        quant_from_bands([n; 10])
    }

    fn region(
        flags: u8,
        base: ProgressiveQuant,
        prog: Option<ProgressiveQuant>,
    ) -> ProgressiveRegion<'static> {
        ProgressiveRegion {
            rects: Vec::new(),
            quants: vec![base],
            prog_quants: prog
                .map(|q| {
                    vec![ProgressiveCodecQuant {
                        quality: 0,
                        y: q,
                        cb: q,
                        cr: q,
                    }]
                })
                .unwrap_or_default(),
            flags,
            tiles: Vec::new(),
        }
    }

    fn extrapolate_region(base: u8, prog: Option<u8>) -> ProgressiveRegion<'static> {
        region(
            REGION_FLAG_DWT_REDUCE_EXTRAPOLATE,
            uniform(base),
            prog.map(uniform),
        )
    }

    fn first(data: &[u8], quality: Option<u8>, flags: u8) -> FirstPassTile<'_> {
        FirstPassTile {
            quant_idx_y: 0,
            quant_idx_cb: 0,
            quant_idx_cr: 0,
            x_idx: 0,
            y_idx: 0,
            flags,
            quality,
            y_data: data,
            cb_data: data,
            cr_data: data,
            tail_data: &[],
        }
    }

    fn upgrade<'a>(srl: &'a [u8], raw: &'a [u8], quality: u8) -> UpgradeTile<'a> {
        UpgradeTile {
            quant_idx_y: 0,
            quant_idx_cb: 0,
            quant_idx_cr: 0,
            x_idx: 0,
            y_idx: 0,
            quality,
            y_srl: srl,
            y_raw: raw,
            cb_srl: srl,
            cb_raw: raw,
            cr_srl: srl,
            cr_raw: raw,
        }
    }

    fn grid_and_scratch() -> (TileGrid, Scratch, Vec<u8>) {
        (
            TileGrid::new(128, 128),
            Scratch::new(),
            vec![0u8; TILE_RGBA_LEN],
        )
    }

    // ---------------------------------------------------------------------------------------
    // Block ordering (#170). FreeRDP's `WBT_STATE_FLAG` mask, which `progressive_decompress`
    // zeroes at its top (`progressive.c:2463`) — so these are **per-payload** rules.
    // ---------------------------------------------------------------------------------------

    fn frame_begin() -> ProgressiveMessage<'static> {
        ProgressiveMessage::FrameBegin {
            index: 0,
            regions: 1,
        }
    }

    fn context() -> ProgressiveMessage<'static> {
        ProgressiveMessage::Context {
            ctx_id: 0,
            flags: 0,
        }
    }

    fn any_region() -> ProgressiveMessage<'static> {
        ProgressiveMessage::Region(extrapolate_region(6, Some(1)))
    }

    /// **51 of the corpus' 52 payloads are exactly this shape** — no `SYNC`, no `CONTEXT`,
    /// because the server sends the header blocks once per *stream* and this is payload 2..52.
    /// FreeRDP never checks for either block's presence; only for duplicates.
    #[test]
    fn a_payload_with_no_sync_and_no_context_is_the_ordinary_case() {
        let msgs = vec![frame_begin(), any_region(), ProgressiveMessage::FrameEnd];
        let order = order_payload(&msgs);
        assert_eq!(order.fatal, None, "nothing here is fatal");
        assert_eq!(order.regions.len(), 1, "the region must be decoded");
        assert!(
            order.anomalies.is_empty(),
            "no rule is violated: {:?}",
            order.anomalies
        );
    }

    /// The remaining payload — the one that opens the stream.
    #[test]
    fn the_stream_opening_payload_carries_sync_and_context() {
        let msgs = vec![
            ProgressiveMessage::Sync,
            context(),
            frame_begin(),
            any_region(),
            ProgressiveMessage::FrameEnd,
        ];
        let order = order_payload(&msgs);
        assert_eq!(order.regions.len(), 1);
        assert!(order.anomalies.is_empty(), "{:?}", order.anomalies);
    }

    /// One of FreeRDP's two hard errors (`-1008`, `progressive.c:1921-1925`) — **and it does
    /// not cost the regions already accepted.** FreeRDP decodes each region into the store as
    /// it walks (`progressive.c:2461-2467`) and its `goto fail` skips only the blit, leaving
    /// `rc = 1`; refusing the whole payload here would also contradict this module's own rule
    /// for the skip rows, that one bad block must not cost the well-formed ones beside it.
    #[test]
    fn a_duplicate_frame_begin_ends_the_walk_without_discarding_what_it_accepted() {
        let bare = vec![frame_begin(), frame_begin()];
        assert_eq!(
            order_payload(&bare).fatal,
            Some(ProgressiveError::DuplicateFrameBegin)
        );

        let with_a_good_region = vec![frame_begin(), any_region(), frame_begin(), any_region()];
        let order = order_payload(&with_a_good_region);
        assert_eq!(
            order.fatal,
            Some(ProgressiveError::DuplicateFrameBegin),
            "the walk still stops"
        );
        assert_eq!(
            order.regions.len(),
            1,
            "the region before the fatal block survives; the one after it is never reached"
        );
    }

    /// The other (`progressive.c:1927-1932`) — and it is reachable **only** through a stray
    /// `FRAME_END`, because the duplicate check above it runs first. A well-formed
    /// `FRAME_BEGIN … FRAME_END … FRAME_BEGIN` therefore reports the *duplicate*, which is the
    /// order FreeRDP's two `if`s impose and worth pinning: the two errors are not
    /// interchangeable diagnostics for one condition.
    #[test]
    fn a_frame_begin_after_a_frame_end_fails_the_payload() {
        let stray_end = vec![ProgressiveMessage::FrameEnd, frame_begin()];
        assert_eq!(
            order_payload(&stray_end).fatal,
            Some(ProgressiveError::FrameBeginAfterFrameEnd)
        );

        let reopened = vec![frame_begin(), ProgressiveMessage::FrameEnd, frame_begin()];
        assert_eq!(
            order_payload(&reopened).fatal,
            Some(ProgressiveError::DuplicateFrameBegin),
            "the duplicate check runs first, so this is not the after-end error"
        );
    }

    /// A region outside a frame is **dropped, not fatal** — the third of FreeRDP's three
    /// outcomes (`progressive_wb_skip_region`, `progressive.c:2146-2155`). The distinction is
    /// the whole reason this is not a single "validate ordering" pass: a payload that carries
    /// one bad region and one good one must still decode the good one.
    #[test]
    fn a_region_outside_a_frame_is_skipped_and_the_rest_of_the_payload_survives() {
        let before = vec![
            any_region(),
            frame_begin(),
            any_region(),
            ProgressiveMessage::FrameEnd,
        ];
        let order = order_payload(&before);
        assert_eq!(
            order.regions.len(),
            1,
            "the in-frame region decodes, the stray one does not"
        );
        assert_eq!(order.anomalies, vec![OrderAnomaly::RegionBeforeFrameBegin]);

        let after = vec![frame_begin(), ProgressiveMessage::FrameEnd, any_region()];
        let order = order_payload(&after);
        assert!(order.regions.is_empty());
        assert_eq!(order.anomalies, vec![OrderAnomaly::RegionAfterFrameEnd]);
    }

    /// The tolerate-and-continue rows, each asserted with its *side condition*: the region
    /// still decodes. A test that only checked the anomaly would pass against an
    /// implementation that dropped the payload.
    #[test]
    fn the_tolerated_violations_are_reported_without_costing_the_region() {
        let cases: Vec<(Vec<ProgressiveMessage<'_>>, OrderAnomaly)> = vec![
            (
                vec![
                    ProgressiveMessage::Sync,
                    ProgressiveMessage::Sync,
                    frame_begin(),
                    any_region(),
                    ProgressiveMessage::FrameEnd,
                ],
                OrderAnomaly::DuplicateSync,
            ),
            (
                vec![
                    context(),
                    context(),
                    frame_begin(),
                    any_region(),
                    ProgressiveMessage::FrameEnd,
                ],
                OrderAnomaly::DuplicateContext,
            ),
            (
                vec![
                    frame_begin(),
                    context(),
                    any_region(),
                    ProgressiveMessage::FrameEnd,
                ],
                OrderAnomaly::ContextAfterFrameBegin,
            ),
        ];
        for (msgs, expected) in cases {
            let order = order_payload(&msgs);
            assert!(
                order.anomalies.contains(&expected),
                "expected {expected:?}, got {:?}",
                order.anomalies
            );
            assert_eq!(
                order.regions.len(),
                1,
                "{expected:?} must not cost the region"
            );
        }
    }

    /// **A stray `FRAME_END` is forgiven and still ends the frame.** FreeRDP warns and then
    /// sets `FLAG_WBT_FRAME_END` anyway (`progressive.c:1967-1972`), so everything after it is
    /// judged against a closed frame: a following region is skipped and a following
    /// `FRAME_BEGIN` is fatal. The block is tolerated; the rest of the payload is not. This is
    /// the row that makes "tolerated" and "harmless" different words.
    #[test]
    fn a_stray_frame_end_is_tolerated_and_still_closes_the_frame() {
        let alone = vec![ProgressiveMessage::FrameEnd];
        let order = order_payload(&alone);
        assert_eq!(
            order.anomalies,
            vec![OrderAnomaly::FrameEndWithoutFrameBegin]
        );
        assert!(order.regions.is_empty());

        let then_region = vec![ProgressiveMessage::FrameEnd, any_region()];
        let order = order_payload(&then_region);
        assert_eq!(
            order.anomalies,
            vec![
                OrderAnomaly::FrameEndWithoutFrameBegin,
                OrderAnomaly::RegionBeforeFrameBegin
            ],
            "skipped — and reported as before-begin, which is the check FreeRDP returns on first (`progressive.c:2146`), not as after-end"
        );
        assert!(order.regions.is_empty());
    }

    /// `CONTEXT` after `FRAME_END` warns on its own row (`progressive.c:2010`), and a payload
    /// that trips several rows reports each — FreeRDP's checks are independent `if`s, not an
    /// `else if` chain.
    #[test]
    fn a_payload_reports_every_rule_it_breaks() {
        let msgs = vec![
            frame_begin(),
            ProgressiveMessage::FrameEnd,
            context(),
            ProgressiveMessage::FrameEnd,
        ];
        let order = order_payload(&msgs);
        assert_eq!(
            order.anomalies,
            vec![
                OrderAnomaly::ContextAfterFrameBegin,
                OrderAnomaly::ContextAfterFrameEnd,
                OrderAnomaly::DuplicateFrameEnd,
            ]
        );
    }

    // ---------------------------------------------------------------------------------------
    // Surface-store lifecycle (#170).
    // ---------------------------------------------------------------------------------------

    /// Paint one tile into a surface's grid, so a later assertion can tell a *kept* store from
    /// a freshly created empty one. `painted_tiles()` is the observable.
    fn paint_one(store: &mut SurfaceStore, surface_id: u16, w: u16, h: u16) {
        let mut scratch = Scratch::new();
        let mut rgba = vec![0u8; TILE_RGBA_LEN];
        let region = extrapolate_region(6, Some(1));
        store
            .grid_mut(surface_id, w, h)
            .decode_first(
                &first(MIXED_SIGNS, Some(0), 0),
                &region,
                &mut scratch,
                &mut rgba,
            )
            .expect("a well-formed first pass");
    }

    /// FreeRDP creates a surface's store lazily and idempotently
    /// (`progressive_create_surface_context`, `progressive.c:543-563`): the second call finds
    /// the existing one and returns it **without resetting it**, which is what makes a tile's
    /// cross-pass state survive from one payload to the next.
    #[test]
    fn a_surfaces_store_is_created_lazily_and_then_reused() {
        let mut store = SurfaceStore::new();
        assert_eq!(store.live_surfaces(), 0);
        paint_one(&mut store, 7, 1280, 800);
        assert_eq!(store.live_surfaces(), 1);
        assert_eq!(store.grid_mut(7, 1280, 800).painted_tiles(), 1);
        assert_eq!(
            store.live_surfaces(),
            1,
            "reuse must not add a second store"
        );
    }

    /// **`DELETEENCODINGCONTEXT` frees nothing.** FreeRDP's handler is a literal no-op —
    /// `WINPR_UNUSED` on both arguments, `return CHANNEL_RC_OK` (`gdi/gfx.c:1239-1246`) — and
    /// under surface keying there is nothing for a `codecContextId` to name. This is the
    /// assertion that pins #83's semantics to their post-#169 shape.
    #[test]
    fn deleting_an_encoding_context_frees_nothing() {
        let mut store = SurfaceStore::new();
        paint_one(&mut store, 7, 1280, 800);
        store.delete_context(1);
        store.delete_context(24);
        assert_eq!(store.live_surfaces(), 1, "the surface's store is untouched");
        assert_eq!(
            store.grid_mut(7, 1280, 800).painted_tiles(),
            1,
            "and so is every tile in it"
        );
    }

    /// `DeleteSurface` is the only free path (`gdi/gfx.c:1366`).
    #[test]
    fn deleting_a_surface_frees_its_store_and_only_its_store() {
        let mut store = SurfaceStore::new();
        paint_one(&mut store, 7, 1280, 800);
        paint_one(&mut store, 8, 1280, 800);
        store.delete_surface(7);
        assert_eq!(store.live_surfaces(), 1);
        assert_eq!(store.grid_mut(8, 1280, 800).painted_tiles(), 1);
        assert_eq!(
            store.grid_mut(7, 1280, 800).painted_tiles(),
            0,
            "surface 7 comes back empty, not resurrected"
        );
    }

    #[test]
    fn deleting_a_surface_that_was_never_painted_is_a_no_op() {
        let mut store = SurfaceStore::new();
        store.delete_surface(9);
        assert_eq!(store.live_surfaces(), 0);
    }

    /// **Clearing every store at once is a drop, not a method.** The EGFX channel closing is
    /// the only event that wants it, and `GraphicsProcessor::close()` already provides it by
    /// replacing itself wholesale (`justrdp/src/egfx.rs:725`). This asserts the half that lives
    /// in this crate: the store owns its grids outright, so dropping it takes them with it —
    /// which is what makes a `reset` method redundant, and therefore only a way to clear the
    /// stores on `RESETGRAPHICS`, where clearing is wrong.
    #[test]
    fn dropping_the_store_is_what_frees_every_surface() {
        let mut store = SurfaceStore::new();
        paint_one(&mut store, 7, 1280, 800);
        paint_one(&mut store, 8, 640, 480);
        assert_eq!(store.live_surfaces(), 2);

        drop(store);

        // And the type offers no other way to reach zero in one call: `delete_surface` takes a
        // surface id, which `RDPGFX_CMDID_RESETGRAPHICS` does not carry. A rebuilt store is
        // empty, which is the whole of what a `reset` would have bought.
        assert_eq!(SurfaceStore::new().live_surfaces(), 0);
    }

    /// **A grid whose stride would be wrong is replaced, not cleared** — the hole #169 handed
    /// over. `TileGrid::clear()` keeps `grid_width`, so a surface that shrank would keep
    /// mapping `(x_idx, y_idx)` through the old stride and accept coordinates now outside it.
    /// FreeRDP does *not* do this: its create is idempotent on the id alone, so a recreated
    /// surface keeps the old grid.
    #[test]
    fn a_surface_recreated_at_a_new_size_gets_a_new_grid_not_the_old_one() {
        let mut store = SurfaceStore::new();
        paint_one(&mut store, 7, 1280, 800);
        assert_eq!(store.grid_mut(7, 1280, 800).grid_size(), (20, 13));

        // Same id, smaller surface: the stride changes, so the store cannot be carried over.
        let grid = store.grid_mut(7, 640, 480);
        assert_eq!(grid.grid_size(), (10, 8));
        assert_eq!(grid.painted_tiles(), 0, "the old stride's tiles are gone");
        assert_eq!(store.live_surfaces(), 1, "and it is still one surface");
    }

    /// A dimension change too small to move the grid keeps the store — the comparison is on
    /// the *stride*, which is what a tile index means, not on the pixel count.
    #[test]
    fn a_surface_resized_within_its_tile_grid_keeps_its_store() {
        let mut store = SurfaceStore::new();
        paint_one(&mut store, 7, 1280, 800);
        assert_eq!(
            store.grid_mut(7, 1277, 799).painted_tiles(),
            1,
            "20 x 13 either way, so every tile index still means what it meant"
        );
    }

    /// **The sign store is the *quantized* coefficient, captured before the LL3 delta and the
    /// dequantization shifts** (`CopyMemory(sign, buffer, ...)`, `progressive.c:876`).
    ///
    /// The oracle captures it after both (`progressive.rs:84`), and this is the assertion that
    /// tells the two apart: at a shift of 15 a coefficient of `2` dequantizes to `0` (the
    /// shift wraps in 16 bits), so a post-dequantize capture would record "zero" for a
    /// coefficient that is not zero — and every later refinement of it would be routed to the
    /// SRL stream instead of the raw one, for the rest of the tile's life.
    #[test]
    fn the_sign_store_is_the_quantized_coefficients_not_the_dequantized_ones() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        // base 15 + prog 1 = bitPos 16, shift 15 — the widest the first pass accepts.
        let region = extrapolate_region(15, Some(1));
        grid.decode_first(
            &first(MIXED_SIGNS, Some(0), 0),
            &region,
            &mut scratch,
            &mut rgba,
        )
        .expect("first pass decodes");

        let state = &grid.tiles[&0];
        assert_eq!(
            &state.sign[0][..8],
            &[0, 0, -2, 0, 0, 2, -1, -1],
            "the sign store must hold the raw entropy output"
        );
        assert_eq!(
            state.current[0][5], 0,
            "2 << 15 wraps to 0, which is what makes the check below discriminating"
        );
        assert_ne!(
            state.sign[0][5], 0,
            "a post-dequantize capture would have recorded 0 here and mis-routed every later \
             refinement of this coefficient"
        );
    }

    /// The dequantization shift wraps in 16 bits rather than saturating — FreeRDP's
    /// `(int16_t)(((UINT32)val << sh) & 0xFFFF)` (`prim_shift.c:27-31`), the same arithmetic
    /// the sibling WireToSurface1 dequantizer uses. The oracle clamps instead.
    #[test]
    fn the_dequantization_shift_wraps_in_sixteen_bits() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        let region = extrapolate_region(15, Some(1));
        grid.decode_first(
            &first(MIXED_SIGNS, Some(0), 0),
            &region,
            &mut scratch,
            &mut rgba,
        )
        .expect("first pass decodes");
        let state = &grid.tiles[&0];
        // -1 << 15 == i16::MIN, 2 << 15 == 0, -2 << 15 == 0. Saturation would have given
        // i16::MIN, i16::MAX and i16::MIN.
        assert_eq!(state.current[0][6], i16::MIN);
        assert_eq!(state.current[0][5], 0);
        assert_eq!(state.current[0][2], 0);
    }

    /// A plain first pass replaces the store; one carrying `RFX_TILE_DIFFERENCE` adds to it.
    /// These are different mechanisms and the flag gates only the second — the LL3 delta runs
    /// unconditionally either way (`progressive.c:879`, `:921`).
    #[test]
    fn a_difference_tile_accumulates_into_the_store_where_a_plain_one_replaces_it() {
        let region = extrapolate_region(6, None);

        let (mut plain, mut scratch, mut rgba) = grid_and_scratch();
        plain
            .decode_first(
                &first(MIXED_SIGNS, None, 0),
                &region,
                &mut scratch,
                &mut rgba,
            )
            .expect("first pass decodes");
        let once = plain.tiles[&0].current[0][2];
        assert_ne!(once, 0, "the fixture must put a value here to compare");
        plain
            .decode_first(
                &first(MIXED_SIGNS, None, 0),
                &region,
                &mut scratch,
                &mut rgba,
            )
            .expect("second plain pass decodes");
        assert_eq!(
            plain.tiles[&0].current[0][2], once,
            "a plain first pass must replace the store, not accumulate"
        );

        let (mut diff, mut scratch, mut rgba) = grid_and_scratch();
        diff.decode_first(
            &first(MIXED_SIGNS, None, 0),
            &region,
            &mut scratch,
            &mut rgba,
        )
        .expect("first pass decodes");
        diff.decode_first(
            &first(MIXED_SIGNS, None, TILE_FLAG_DIFFERENCE),
            &region,
            &mut scratch,
            &mut rgba,
        )
        .expect("difference pass decodes");
        assert_eq!(
            diff.tiles[&0].current[0][2],
            once * 2,
            "a difference tile must add to the coefficients already stored"
        );
    }

    /// The inter-frame accumulate saturates, matching the `add()` helper that
    /// `general_add_16s_inplace` is built from (`prim_add.c:30-41`, used at `:59-69`) — the opposite of the wrapping shift two steps earlier, which is
    /// why the two are asserted separately rather than as one "overflow behaviour".
    #[test]
    fn the_difference_accumulate_saturates_rather_than_wrapping() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        let region = extrapolate_region(6, None);
        grid.decode_first(
            &first(MIXED_SIGNS, None, 0),
            &region,
            &mut scratch,
            &mut rgba,
        )
        .expect("first pass decodes");
        grid.tiles.get_mut(&0).expect("tile exists").current[0][2] = i16::MIN;

        grid.decode_first(
            &first(MIXED_SIGNS, None, TILE_FLAG_DIFFERENCE),
            &region,
            &mut scratch,
            &mut rgba,
        )
        .expect("difference pass decodes");
        assert_eq!(
            grid.tiles[&0].current[0][2],
            i16::MIN,
            "a negative overflow must clamp at i16::MIN, not wrap to a large positive"
        );
    }

    /// The bit positions thread across passes: an upgrade's `numBits` is measured against what
    /// the *previous* pass left, and the store then carries the new positions forward.
    #[test]
    fn each_pass_leaves_its_bit_positions_for_the_next_one_to_measure_against() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        grid.decode_first(
            &first(MIXED_SIGNS, Some(0), 0),
            &extrapolate_region(6, Some(4)),
            &mut scratch,
            &mut rgba,
        )
        .expect("first pass decodes");
        assert_eq!(grid.tiles[&0].bit_pos[0], uniform(10), "6 + 4");
        assert_eq!(grid.tiles[&0].passes(), 1);

        grid.decode_upgrade(
            &upgrade(&[0x00], &[0x00], 0),
            &extrapolate_region(6, Some(1)),
            &mut scratch,
            &mut rgba,
        )
        .expect("upgrade decodes");
        assert_eq!(grid.tiles[&0].bit_pos[0], uniform(7), "6 + 1");
        assert_eq!(grid.tiles[&0].passes(), 2);
    }

    /// **Which inverse transform the upgrade path runs, pinned directly.**
    ///
    /// Mutation-driven, twice over. Pointing the upgrade path at the classic `dwt::decode`
    /// survived the whole suite including the real corpus, because that gate asserts
    /// acceptance and "not all black" and a wrong transform still produces plausible
    /// non-black pixels. The first replacement for it — a no-op upgrade repainting the first
    /// pass's own output — *also* survived, because the fixture's coefficients are small
    /// enough that the colour step clamps both reconstructions onto the same flat tile. A
    /// test that cannot tell the two apart is not evidence, whatever it asserts.
    ///
    /// So the spectrum is seeded directly, the expected pixels are computed here from the
    /// extrapolate transform, and the classic transform's output is asserted to *differ* —
    /// that last assertion is what makes the first one mean something.
    #[test]
    fn the_upgrade_path_reconstructs_with_the_extrapolate_transform() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        let region = extrapolate_region(6, Some(1));
        grid.decode_first(
            &first(MIXED_SIGNS, Some(0), 0),
            &region,
            &mut scratch,
            &mut rgba,
        )
        .expect("first pass decodes");

        // A deterministic spectrum with energy in every band, written straight into the
        // store so the comparison does not depend on what an entropy fixture happens to hold.
        let spectrum = |component: usize| {
            let mut seed = 0x1234_5678u32 ^ (component as u32).wrapping_mul(0x9E37_79B9);
            let mut buf = [0i16; COMPONENT_LEN];
            for v in &mut buf {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                *v = ((seed % 4001) as i32 - 2000) as i16;
            }
            buf
        };
        {
            let state = grid.tiles.get_mut(&0).expect("tile exists");
            for c in 0..3 {
                state.current[c] = spectrum(c);
            }
        }
        let store = grid.tiles[&0].current;

        let mut repainted = vec![0u8; TILE_RGBA_LEN];
        grid.decode_upgrade(
            &upgrade(&[0xFF; 4], &[0xFF; 4], 0),
            &region,
            &mut scratch,
            &mut repainted,
        )
        .expect("a no-op upgrade decodes");
        assert!(
            grid.tiles[&0].current == store,
            "numBits is zero in every band, so the store must not have moved"
        );

        let paint = |transform: fn(&mut [i16], &mut [i16])| {
            let mut planes = [[0i16; COMPONENT_LEN]; 3];
            let mut temp = vec![0i16; COMPONENT_LEN];
            for (c, plane) in planes.iter_mut().enumerate() {
                *plane = spectrum(c);
                transform(plane.as_mut_slice(), &mut temp);
            }
            let mut out = vec![0u8; TILE_RGBA_LEN];
            color::rfx_ycbcr_to_rgba(&planes[0], &planes[1], &planes[2], &mut out);
            out
        };
        let extrapolate = paint(dwt_extrapolate::decode);
        let classic = paint(dwt::decode);

        assert_ne!(
            extrapolate, classic,
            "this spectrum must distinguish the two transforms, or the assertion below is              vacuous — which is exactly how the previous version of this test passed against              the wrong transform"
        );
        assert_eq!(
            repainted, extrapolate,
            "the upgrade path must reconstruct with the reduce-extrapolate transform"
        );
    }

    /// An upgrade pass may only ever refine. A coarser one underflows `numBits`, and the tile
    /// is rejected with its store untouched — FreeRDP's `progressive_rfx_quant_sub` returning
    /// `FALSE` before anything is written (`progressive.c:1442-1447`).
    #[test]
    fn a_coarser_upgrade_pass_is_rejected_and_leaves_the_store_untouched() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        grid.decode_first(
            &first(MIXED_SIGNS, Some(0), 0),
            &extrapolate_region(6, Some(1)),
            &mut scratch,
            &mut rgba,
        )
        .expect("first pass decodes");
        let before = grid.tiles[&0].current[0];

        let err = grid
            .decode_upgrade(
                &upgrade(&[0xFF], &[0xFF], 0),
                &extrapolate_region(6, Some(5)),
                &mut scratch,
                &mut rgba,
            )
            .expect_err("a coarser pass must be rejected");
        assert_eq!(err, ProgressiveError::BitPositionUnderflow);
        assert_eq!(
            grid.tiles[&0].bit_pos[0],
            uniform(7),
            "the positions must not move"
        );
        assert!(
            grid.tiles[&0].current[0] == before,
            "a rejected pass must not have touched the coefficients"
        );
        assert_eq!(grid.tiles[&0].passes(), 1);
    }

    /// A refinement that cannot be represented discards the tile's store rather than keeping a
    /// half-applied pass — #168's handover, made observable.
    #[test]
    fn a_failed_refinement_discards_the_tiles_store() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        grid.decode_first(
            &first(MIXED_SIGNS, Some(0), 0),
            &extrapolate_region(15, Some(1)),
            &mut scratch,
            &mut rgba,
        )
        .expect("first pass decodes");
        assert_eq!(grid.painted_tiles(), 1);

        // bitPos 16 -> 1 gives numBits 15 and shift 0; an all-ones raw stream drives the
        // largest refinement the stream can express onto a coefficient already at i16::MIN.
        let err = grid
            .decode_upgrade(
                &upgrade(&[], &[0xFF; 8], 0),
                &extrapolate_region(1, Some(0)),
                &mut scratch,
                &mut rgba,
            )
            .expect_err("an unrepresentable refinement must be an error");
        assert!(matches!(err, ProgressiveError::Srl(_)), "got {err:?}");
        assert_eq!(
            grid.painted_tiles(),
            0,
            "the partially-refined store must be discarded, not retained"
        );
    }

    #[test]
    fn a_zero_bit_position_is_rejected_on_both_paths() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        assert_eq!(
            grid.decode_first(
                &first(MIXED_SIGNS, None, 0),
                &extrapolate_region(0, None),
                &mut scratch,
                &mut rgba
            ),
            Err(ProgressiveError::ZeroBitPosition)
        );
        grid.decode_first(
            &first(MIXED_SIGNS, None, 0),
            &extrapolate_region(6, None),
            &mut scratch,
            &mut rgba,
        )
        .expect("first pass decodes");
        assert_eq!(
            grid.decode_upgrade(
                &upgrade(&[], &[], 0),
                &extrapolate_region(0, Some(0)),
                &mut scratch,
                &mut rgba
            ),
            Err(ProgressiveError::ZeroBitPosition)
        );
    }

    /// `shift = quant + prog_quant - 1` runs to 29, and FreeRDP's shift primitive refuses 16
    /// and above by returning `-1` (`prim_shift.c:38-39`), which fails the tile. Easy to miss,
    /// because both operands look like nibbles bounded by 15.
    #[test]
    fn a_first_pass_shift_of_sixteen_or_more_is_rejected() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        // 15 + 1 = 16, shift 15 — accepted.
        assert!(
            grid.decode_first(
                &first(MIXED_SIGNS, Some(0), 0),
                &extrapolate_region(15, Some(1)),
                &mut scratch,
                &mut rgba
            )
            .is_ok()
        );
        // 15 + 2 = 17, shift 16 — refused.
        assert_eq!(
            grid.decode_first(
                &first(MIXED_SIGNS, Some(0), 0),
                &extrapolate_region(15, Some(2)),
                &mut scratch,
                &mut rgba
            ),
            Err(ProgressiveError::ShiftOutOfRange(16))
        );
    }

    /// **The first pass's band table follows the region's flag, and this is the only test
    /// that can say so.**
    ///
    /// Mutation-driven: hardcoding the extrapolate layout here survived the entire suite,
    /// including the whole real-server corpus — 52 of 52 regions set the flag, so no real
    /// traffic distinguishes the branch, and every other unit test uses a *uniform* quant
    /// table, under which the ten bands shift identically and the layout cancels out.
    ///
    /// What does distinguish them is the LL3 delta, whose window is `4015..4096` under
    /// extrapolate and `4032..4096` under the classic layout. With a non-uniform quant the two
    /// give visibly different coefficients, and the seventeen coefficients between the two
    /// offsets are the ones that change hands: `HH3` under one layout, `LL3` under the other.
    #[test]
    fn the_first_pass_band_table_follows_the_regions_extrapolate_flag() {
        // Only LL3 shifts, so the difference cannot come from anywhere else.
        let shift = quant_from_bands([0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        let seed = |buf: &mut [i16]| {
            buf[BANDS_EXTRAPOLATE[9].0] = 1;
            buf[BANDS_STANDARD[9].0] = 1;
        };

        let mut extrapolate = vec![0i16; COMPONENT_LEN];
        seed(&mut extrapolate);
        dequantize_first_pass(&mut extrapolate, &shift, true);

        let mut standard = vec![0i16; COMPONENT_LEN];
        seed(&mut standard);
        dequantize_first_pass(&mut standard, &shift, false);

        // Extrapolate: the prefix sum runs from 4015, so 4015..4032 hold 1 and 4032..4096
        // hold 2 (the second seed adds into the running total); everything then shifts by 3.
        assert_eq!(extrapolate[BANDS_EXTRAPOLATE[9].0], 8);
        assert_eq!(extrapolate[BANDS_STANDARD[9].0 - 1], 8);
        assert_eq!(extrapolate[BANDS_STANDARD[9].0], 16);
        assert_eq!(extrapolate[COMPONENT_LEN - 1], 16);

        // Classic: 4015 is inside HH3, which this quant leaves alone, and the prefix sum
        // starts at 4032.
        assert_eq!(standard[BANDS_EXTRAPOLATE[9].0], 1);
        assert_eq!(standard[BANDS_STANDARD[9].0 - 1], 0);
        assert_eq!(standard[BANDS_STANDARD[9].0], 8);
        assert_eq!(standard[COMPONENT_LEN - 1], 8);

        assert_ne!(
            extrapolate, standard,
            "the two layouts must not dequantize identically, or the branch is decorative"
        );
    }

    /// **The layout guard is keyed on the store, not on the region carrying the upgrade.**
    ///
    /// Region flags are per-`WBT_REGION`, and a tile's passes need not arrive in the same
    /// region. Reading the current region's flag therefore answers a question about the wrong
    /// pass — which is how the first version of this guard let through exactly the case the
    /// module doc says it refuses.
    #[test]
    fn a_layout_that_changes_between_a_tiles_passes_is_refused_in_both_directions() {
        let plain = region(0, uniform(6), Some(uniform(0)));
        let extrapolate = extrapolate_region(6, Some(0));

        // Store written non-extrapolate, upgrade arriving in an extrapolate region: there is
        // no non-extrapolate band walk to refine it with.
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        grid.decode_first(
            &first(MIXED_SIGNS, None, 0),
            &plain,
            &mut scratch,
            &mut rgba,
        )
        .expect("a non-extrapolate first pass is decodable");
        assert_eq!(
            grid.decode_upgrade(&upgrade(&[], &[], 0), &extrapolate, &mut scratch, &mut rgba),
            Err(ProgressiveError::UpgradeWithoutExtrapolate),
            "the guard must follow the store, not the region in hand"
        );

        // Store written extrapolate, upgrade arriving in a non-extrapolate region: the walk
        // would match and the reconstruction would not.
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        grid.decode_first(
            &first(MIXED_SIGNS, None, 0),
            &extrapolate,
            &mut scratch,
            &mut rgba,
        )
        .expect("first pass decodes");
        assert_eq!(
            grid.decode_upgrade(&upgrade(&[], &[], 0), &plain, &mut scratch, &mut rgba),
            Err(ProgressiveError::LayoutChangedBetweenPasses)
        );
    }

    /// **A first pass that fails part-way discards the tile, rather than leaving a mixture of
    /// two passes.**
    ///
    /// The entropy decode is fallible per component, so a failure at Cb would otherwise leave
    /// Y holding this pass's coefficients, Cb and Cr the previous pass's, and `bit_pos` the
    /// previous pass's — and a later upgrade would then refine that mixture and return `Ok`,
    /// measuring `numBits` from one pass against another pass's coefficients. That is the
    /// non-local corruption `SrlError` is discarded for (#168); `decode_first` needs the same
    /// discipline and did not have it.
    #[test]
    fn a_first_pass_that_fails_part_way_discards_the_tile() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        let region = extrapolate_region(6, Some(1));
        grid.decode_first(
            &first(MIXED_SIGNS, Some(0), 0),
            &region,
            &mut scratch,
            &mut rgba,
        )
        .expect("first pass decodes");
        assert_eq!(grid.painted_tiles(), 1);

        // Y decodes, Cb is empty — `RlgrError::EmptyInput`, raised after Y is already written.
        let mut half = first(MIXED_SIGNS, Some(0), 0);
        half.cb_data = &[];
        let err = grid
            .decode_first(&half, &region, &mut scratch, &mut rgba)
            .expect_err("an empty component is an error");
        assert!(matches!(err, ProgressiveError::Rlgr(_)), "got {err:?}");
        assert_eq!(
            grid.painted_tiles(),
            0,
            "the half-written store must be discarded, not left for an upgrade to refine"
        );

        // And the same tile's first fallible step failing must not leave a 48 KiB phantom.
        let mut none = first(MIXED_SIGNS, Some(0), 0);
        none.y_data = &[];
        assert!(
            grid.decode_first(&none, &region, &mut scratch, &mut rgba)
                .is_err()
        );
        assert_eq!(
            grid.painted_tiles(),
            0,
            "no store for a pass that never decoded"
        );
    }

    /// The deliberate divergence: FreeRDP would refine extrapolate offsets over a
    /// non-extrapolate first pass; we refuse the combination instead.
    #[test]
    fn an_upgrade_on_a_non_extrapolate_region_is_refused() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        let plain = region(0, uniform(6), Some(uniform(0)));
        grid.decode_first(
            &first(MIXED_SIGNS, None, 0),
            &plain,
            &mut scratch,
            &mut rgba,
        )
        .expect("a non-extrapolate first pass is perfectly decodable");
        assert_eq!(
            grid.decode_upgrade(&upgrade(&[], &[], 0), &plain, &mut scratch, &mut rgba),
            Err(ProgressiveError::UpgradeWithoutExtrapolate)
        );
    }

    #[test]
    fn an_upgrade_without_a_first_pass_is_refused() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        assert_eq!(
            grid.decode_upgrade(
                &upgrade(&[], &[], 0),
                &extrapolate_region(6, Some(0)),
                &mut scratch,
                &mut rgba
            ),
            Err(ProgressiveError::NoFirstPass { x_idx: 0, y_idx: 0 })
        );
    }

    /// The bound the parse layer cannot make, because the surface dimensions are not in the
    /// block stream (#167's handover). A 128x128 surface is a 2x2 grid.
    #[test]
    fn a_tile_outside_the_surface_grid_is_refused() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        let region = extrapolate_region(6, None);
        let mut tile = first(MIXED_SIGNS, None, 0);
        tile.x_idx = 2;
        assert_eq!(
            grid.decode_first(&tile, &region, &mut scratch, &mut rgba),
            Err(ProgressiveError::TileOutsideSurface { x_idx: 2, y_idx: 0 })
        );
        // The doc's "pixel x = x_idx * 64 overflows a u16 at x_idx >= 1024" case, which must
        // be an error rather than wrapping into a valid-looking index.
        tile.x_idx = u16::MAX;
        tile.y_idx = u16::MAX;
        assert!(matches!(
            grid.decode_first(&tile, &region, &mut scratch, &mut rgba),
            Err(ProgressiveError::TileOutsideSurface { .. })
        ));
    }

    /// The grid rounds up, so a surface whose last row is partial still has tiles for it — the
    /// corpus' 1280x800 surface is 20 x 13 and its bottom row covers 32 of 64 rows.
    #[test]
    fn the_grid_rounds_up_for_a_partial_bottom_row() {
        let grid = TileGrid::new(1280, 800);
        assert_eq!((grid.grid_width, grid.grid_height), (20, 13));
        // Row-major, and asserted where it differs from column-major: on a 20 x 13 grid the
        // bottom-right corner is 259 under *both* orders, so pinning only that corner leaves
        // a transposed index indistinguishable.
        assert_eq!(grid.z_index(1, 0), Ok(1));
        assert_eq!(grid.z_index(0, 1), Ok(20));
        assert_eq!(grid.z_index(19, 12), Ok(259));
        assert!(grid.z_index(20, 0).is_err());
        assert!(grid.z_index(0, 13).is_err());
        // An exact multiple must not gain a phantom column (FreeRDP's
        // `(width + (64 - width % 64)) / 64` does, at `progressive.c:447`).
        assert_eq!(TileGrid::new(128, 128).grid_width, 2);
    }

    /// The parser validates every index, but `ProgressiveRegion`'s fields are `pub`, so the
    /// guarantee lives in the parser and not in the type — #211's shape, refused here rather
    /// than indexed into.
    #[test]
    fn an_out_of_range_quant_index_is_an_error_not_a_panic() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        let region = extrapolate_region(6, None);
        let mut tile = first(MIXED_SIGNS, None, 0);
        tile.quant_idx_cb = 7;
        assert_eq!(
            grid.decode_first(&tile, &region, &mut scratch, &mut rgba),
            Err(ProgressiveError::QuantIndexOutOfRange)
        );
        assert_eq!(
            grid.decode_first(
                &first(MIXED_SIGNS, Some(9), 0),
                &region,
                &mut scratch,
                &mut rgba
            ),
            Err(ProgressiveError::QuantIndexOutOfRange)
        );
    }

    /// `QUALITY_FULL` is a sentinel, not an index — the oracle defect the corpus canary pins
    /// (#194). A region with an empty progressive-quant table must still decode a full-quality
    /// tile.
    #[test]
    fn the_full_quality_sentinel_is_not_a_table_index() {
        let (mut grid, mut scratch, mut rgba) = grid_and_scratch();
        let region = extrapolate_region(6, None);
        assert!(region.prog_quants.is_empty());
        grid.decode_first(
            &first(MIXED_SIGNS, Some(QUALITY_FULL), 0),
            &region,
            &mut scratch,
            &mut rgba,
        )
        .expect("the sentinel must not be looked up");
        assert_eq!(grid.tiles[&0].bit_pos[0], uniform(6), "bitPos = quant + 0");
    }

    #[test]
    fn a_wrongly_sized_output_buffer_is_an_error() {
        let (mut grid, mut scratch, _) = grid_and_scratch();
        let mut small = [0u8; 16];
        assert_eq!(
            grid.decode_first(
                &first(MIXED_SIGNS, None, 0),
                &extrapolate_region(6, None),
                &mut scratch,
                &mut small
            ),
            Err(ProgressiveError::OutputBufferSize(16))
        );
    }

    proptest! {
        // ADR-0008 / #97 — the no-panic property for the multi-pass path. `data` is the
        // attacker-controlled entropy blob; the quant nibbles are generated *outside* the
        // parser's 0..=15 guarantee on purpose, because `ProgressiveQuant`'s fields are `pub`
        // and #168 proved that generating inside the guarantee hides exactly the arithmetic
        // this module does (`quant + prog_quant` is a sum, and `shift` runs to 29).
        //
        // **Per band, not one value for all ten.** The first revision generated a single `u8`
        // and broadcast it, which made every band's `shift` and `num_bits` equal — and a band
        // whose width differs from its neighbours' is precisely what desynchronises the SRL
        // cursor shared across the ten of them (`super::srl`). The fuzz target has always
        // generated per band; this is the PR-gate half, and the fuzz lane is nightly.
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn the_multi_pass_path_never_panics_on_arbitrary_input(
            base in any::<[u8; 10]>(),
            prog in any::<[u8; 10]>(),
            flags in any::<u8>(),
            quality in proptest::option::of(any::<u8>()),
            x_idx in 0u16..=4,
            y_idx in 0u16..=4,
            data in proptest::collection::vec(any::<u8>(), 0..=256),
            srl in proptest::collection::vec(any::<u8>(), 0..=64),
            raw in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let mut grid = TileGrid::new(128, 128);
            let mut scratch = Scratch::new();
            let mut rgba = vec![0u8; TILE_RGBA_LEN];
            let r = region(flags, quant_from_bands(base), Some(quant_from_bands(prog)));

            let mut t = first(&data, quality, flags);
            t.x_idx = x_idx;
            t.y_idx = y_idx;
            let _ = grid.decode_first(&t, &r, &mut scratch, &mut rgba);

            let mut u = upgrade(&srl, &raw, quality.unwrap_or(0));
            u.x_idx = x_idx;
            u.y_idx = y_idx;
            let _ = grid.decode_upgrade(&u, &r, &mut scratch, &mut rgba);
            let _ = grid.decode_upgrade(&u, &r, &mut scratch, &mut rgba);
        }
    }
}
