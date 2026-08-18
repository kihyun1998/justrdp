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
//! (`zIdx = yIdx * gridWidth + xIdx`, `progressive.c:475`), so the surface is the only key
//! under which a tile index means anything. FreeRDP keys the whole store by `surfaceId`
//! (`:314`) and treats the block stream's `ctxId` as advisory, warning when it is non-zero
//! (`:1999`) and reading it nowhere else. The bootstrap oracle keys by `codecContextId`
//! instead, which is why `justrdp::egfx` carries a per-surface eviction workaround (#83) — it
//! records that the self-owned decoder retires it, and this is that decoder.
//!
//! Context-id *lifecycle* (`RDPGFX_CMDID_DELETEENCODINGCONTEXT`, reset) is slice 4's (#170).
//! What this slice fixes is only what the store is keyed by.
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
//! (`:2176`). It is a spec-conformance check rather than a safety one — the shift formula is
//! total for any `bitPos >= 1` — and ADR-0009's tolerant-receive posture makes strictness on
//! a receive path the defect. The pinned oracle imposes no such floor either (it computes
//! `q - 1` and no-ops a non-positive factor, `progressive.rs:467`), so the "the references
//! contradict" framing this issue inherited from #167 does not survive contact with either
//! reference. The corpus cannot arbitrate: no real region carries a band below 6.
//!
//! # The layout mismatch this slice refuses rather than reproduces
//!
//! The first-pass decoder branches on `RFX_DWT_REDUCE_EXTRAPOLATE` (`:877`); the upgrade path
//! hardcodes the extrapolate band walk and takes no flag (`:1281-1321`). On a region that
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
    FirstPassTile, ProgressiveQuant, ProgressiveRegion, QUALITY_FULL,
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
    /// A first-pass band's dequantization shift is 16 or wider, which FreeRDP's shift
    /// primitive refuses outright (`prim_shift.c:38-39`), failing the tile. Reachable because
    /// `shift = quant + prog_quant - 1` runs to 29, not to 15.
    ShiftOutOfRange(u8),
    /// An upgrade pass declared a *coarser* bit position than the pass before it, so
    /// `numBits = previous - current` underflows (`progressive_rfx_quant_sub`, `:143-189`).
    BitPositionUnderflow,
    /// A tile's `quantIdx` or `quality` is outside the region's tables. The parser validates
    /// both, but [`ProgressiveRegion`]'s fields are `pub`, so the guarantee lives in the
    /// parser and not in the type — the same shape as #211.
    QuantIndexOutOfRange,
    /// The tile's grid coordinates fall outside the surface
    /// (`zIdx >= surface->tilesSize`, `progressive.c:479-483`).
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
    /// The region omits `RFX_DWT_REDUCE_EXTRAPOLATE` but carries an upgrade tile — see the
    /// module doc. Deliberately stricter than FreeRDP.
    UpgradeWithoutExtrapolate,
    /// The caller's output buffer is not [`TILE_RGBA_LEN`] bytes.
    OutputBufferSize(usize),
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
                "upgrade pass on a region without RFX_DWT_REDUCE_EXTRAPOLATE"
            ),
            ProgressiveError::OutputBufferSize(n) => {
                write!(
                    f,
                    "tile output buffer is {n} bytes, expected {TILE_RGBA_LEN}"
                )
            }
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
/// `CopyMemory(sign, buffer, 4096 * 2)` at `progressive.c:874` — the sign of a *quantized*
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
    passes: u32,
}

impl TileState {
    fn new() -> Box<Self> {
        Box::new(Self {
            current: [[0; COMPONENT_LEN]; 3],
            sign: [[0; COMPONENT_LEN]; 3],
            bit_pos: [ZERO_QUANT; 3],
            passes: 0,
        })
    }

    /// How many passes (one first pass plus its upgrades) this tile has absorbed.
    pub fn passes(&self) -> u32 {
        self.passes
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
/// `quantProgValFull` is a `calloc`'d struct it never fills (`progressive.c:2645-2656`).
/// Indexing a table by the sentinel is the oracle defect the corpus canary pins (#194).
const FULL_QUALITY: ProgressiveQuant = ZERO_QUANT;

/// Reusable per-call working buffers. Held by the caller so a frame's worth of tiles costs
/// one allocation rather than one per tile (`progressive->bufferPool`, `progressive.c:2668`).
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
/// until it is actually painted; the memory a peer can make this hold is bounded by the
/// surface's own tile count, which the host chose when it created the surface.
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
        Self {
            grid_width: usize::from(width).div_ceil(usize::from(TILE_DIM)),
            grid_height: usize::from(height).div_ceil(usize::from(TILE_DIM)),
            tiles: HashMap::new(),
        }
    }

    /// The number of tiles this surface currently holds cross-pass state for.
    pub fn painted_tiles(&self) -> usize {
        self.tiles.len()
    }

    /// Drop every tile's state (the surface was reset or resized).
    pub fn clear(&mut self) {
        self.tiles.clear();
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
        let state = self.tiles.entry(z).or_insert_with(TileState::new);
        let data = [tile.y_data, tile.cb_data, tile.cr_data];

        for c in 0..3 {
            rlgr::decode(
                justrdp_pdu::rfx::EntropyAlgorithm::Rlgr1,
                data[c],
                scratch.component.as_mut_slice(),
            )?;
            // The sign store is the *quantized* coefficients, captured before the delta and
            // the shifts (`progressive.c:874`).
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
        state.passes += 1;
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
    /// (`progressive_rfx_dwt_2d_decode(..., reverse = TRUE)`, `:815-816`) — which is also why
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
        if region.flags & REGION_FLAG_DWT_REDUCE_EXTRAPOLATE == 0 {
            return Err(ProgressiveError::UpgradeWithoutExtrapolate);
        }
        let z = self.z_index(tile.x_idx, tile.y_idx)?;
        let prog = prog_quants(region, Some(tile.quality))?;
        let quants = base_quants(
            region,
            [tile.quant_idx_y, tile.quant_idx_cb, tile.quant_idx_cr],
        )?;
        if !self.tiles.contains_key(&z) {
            return Err(ProgressiveError::NoFirstPass {
                x_idx: tile.x_idx,
                y_idx: tile.y_idx,
            });
        }

        // Every derived table for all three components before any refinement is applied —
        // FreeRDP's own ordering (`:1436-1452`), and the reason a tile whose bit positions do
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
///   and takes the whole tile down with it (`prim_shift.c:38-39`,
///   `progressive_rfx_decode_block` at `progressive.c:850-858`).
///
/// The second is easy to miss because the value looks bounded: `bitPos = quant + prog_quant`
/// is a *sum* of two nibbles, so `shift` runs to 29 ([`super::srl::MAX_BIT_POS`]) and more
/// than half of that range is refused. Checking here rather than at the shift keeps the whole
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
/// FreeRDP (`progressive.c:1219-1223`) rather than going through the shift primitive, so a
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
/// (`progressive_rfx_decode_component`, `progressive.c:1010-1065`).
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

    /// **The sign store is the *quantized* coefficient, captured before the LL3 delta and the
    /// dequantization shifts** (`CopyMemory(sign, buffer, ...)`, `progressive.c:874`).
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
    /// unconditionally either way (`progressive.c:1020`, `:1057`).
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

    /// The inter-frame accumulate saturates, matching `general_add_16s_inplace`
    /// (`prim_add.c:29-40`) — the opposite of the wrapping shift two steps earlier, which is
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
        // `(width + (64 - width % 64)) / 64` does, at `progressive.c:522`).
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
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn the_multi_pass_path_never_panics_on_arbitrary_input(
            base in any::<u8>(),
            prog in any::<u8>(),
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
            let r = region(flags, uniform(base), Some(uniform(prog)));

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
