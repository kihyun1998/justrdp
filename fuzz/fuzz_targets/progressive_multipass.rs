#![no_main]
//! Fuzz the RemoteFX Progressive **multi-pass tile decoder** (issue #99, epic #158 slice 3).
//! Sibling of `rfx::progressive`'s `the_multi_pass_path_never_panics_on_arbitrary_input`
//! proptest.
//!
//! Distinct from its two neighbours, and the gap between them is the point: `progressive`
//! drives the block-stream *parser*, `progressive_srl` drives one component's upgrade entropy
//! streams, and neither reaches the layer where the two meet — the per-band bit-position
//! arithmetic, the store that survives between passes, and the branch on the region's
//! extrapolate flag.
//!
//! What makes this target able to fail:
//!
//! - **The quant nibbles are unmasked.** The parser produces 0..=15, but `ProgressiveQuant`'s
//!   fields are plain `pub u8`, so the guarantee is the parser's and not the type's. `bitPos`
//!   is their *sum* and `shift` is one less, which is the arithmetic #168 proved is not
//!   nibble-bounded.
//! - **A sequence, not a single call.** The whole subject is cross-pass state, so one first
//!   pass followed by several upgrades against a *live* store reaches what a single decode
//!   never can: an accumulate onto a non-zero prior, a `numBits` measured against a previous
//!   pass's positions, and the discard-on-error path.
//! - **The passes may target different tiles.** A grid with more than one live tile is what
//!   separates "the store works" from "the store is indexed correctly".
//!
//! **`SurfaceStore` and `order_payload` (#170) are deliberately outside this target**, so the
//! absence reads as a decision rather than an oversight. Neither can fail on arbitrary bytes:
//! `order_payload` does no arithmetic and no indexing, and its `match` is exhaustive with no
//! wildcard, so a new `ProgressiveMessage` variant breaks the build instead of falling
//! through; `SurfaceStore` is a `HashMap` keyed by a `u16` the caller supplies, and the only
//! arithmetic under it is `grid_size_for`, which is `u16 -> div_ceil(64) <= 1024` and is
//! already covered by `TileGrid::new` below. What a fuzzer would add is coverage of the
//! *composition*, and that composition does not exist until the assembly layer (#171).

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

use justrdp_codecs::rfx::progressive::{Scratch, TILE_RGBA_LEN, TileGrid};
use justrdp_pdu::rfx::progressive::{
    FirstPassTile, ProgressiveCodecQuant, ProgressiveQuant, ProgressiveRegion, UpgradeTile,
};

/// One pass in the sequence. `First` seeds or replaces a tile's store, `Upgrade` refines it.
#[derive(Arbitrary, Debug)]
enum Pass {
    First {
        data: Vec<u8>,
        quality: Option<u8>,
        flags: u8,
        x_idx: u8,
        y_idx: u8,
    },
    Upgrade {
        srl: Vec<u8>,
        raw: Vec<u8>,
        quality: u8,
        x_idx: u8,
        y_idx: u8,
    },
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// Region flags — bit 0 is `RFX_DWT_REDUCE_EXTRAPOLATE`, and leaving it arbitrary is what
    /// drives both band layouts plus the refusal on the mismatch.
    region_flags: u8,
    /// Two base-quant entries so a `quantIdx` of 1 is in range and 2 is not.
    base: [[u8; 10]; 2],
    /// One progressive-quant entry, so `quality = 0` is in range and anything else is not
    /// (except the `0xFF` sentinel, which is never an index).
    prog: [u8; 10],
    /// Surface size in tiles, bounded well below the grid a real surface has — a large grid
    /// would spend the mutator's budget on indices that are all equally out of range.
    grid_w: u8,
    grid_h: u8,
    passes: Vec<Pass>,
}

fn quant(v: [u8; 10]) -> ProgressiveQuant {
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

fuzz_target!(|input: Input| {
    let width = u16::from(input.grid_w % 8 + 1) * 64;
    let height = u16::from(input.grid_h % 8 + 1) * 64;
    let mut grid = TileGrid::new(width, height);
    let mut scratch = Scratch::new();
    let mut rgba = vec![0u8; TILE_RGBA_LEN];

    let p = quant(input.prog);
    let region = ProgressiveRegion {
        rects: Vec::new(),
        quants: input.base.iter().map(|&b| quant(b)).collect(),
        prog_quants: vec![ProgressiveCodecQuant {
            quality: 0,
            y: p,
            cb: p,
            cr: p,
        }],
        flags: input.region_flags,
        tiles: Vec::new(),
    };

    // Bounded so a pathological input cannot turn a fuzz case into a timeout on its own; the
    // interesting state (a live store, several passes deep) is reached well inside this.
    for pass in input.passes.iter().take(16) {
        let _ = match pass {
            Pass::First {
                data,
                quality,
                flags,
                x_idx,
                y_idx,
            } => grid.decode_first(
                &FirstPassTile {
                    quant_idx_y: 0,
                    quant_idx_cb: *flags & 1,
                    quant_idx_cr: *flags >> 7,
                    x_idx: u16::from(*x_idx),
                    y_idx: u16::from(*y_idx),
                    flags: *flags,
                    quality: *quality,
                    y_data: data,
                    cb_data: data,
                    cr_data: data,
                    tail_data: &[],
                },
                &region,
                &mut scratch,
                &mut rgba,
            ),
            Pass::Upgrade {
                srl,
                raw,
                quality,
                x_idx,
                y_idx,
            } => grid.decode_upgrade(
                &UpgradeTile {
                    quant_idx_y: 0,
                    quant_idx_cb: 0,
                    quant_idx_cr: 1,
                    x_idx: u16::from(*x_idx),
                    y_idx: u16::from(*y_idx),
                    quality: *quality,
                    y_srl: srl,
                    y_raw: raw,
                    cb_srl: raw,
                    cb_raw: srl,
                    cr_srl: srl,
                    cr_raw: raw,
                },
                &region,
                &mut scratch,
                &mut rgba,
            ),
        };
    }
});
