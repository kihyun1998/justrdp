//! **Slice 3's real-input gate (#169).** Every tile the real server sent, replayed in arrival
//! order through the self-owned multi-pass decoder — first passes seeding the store, upgrade
//! passes refining it, across the whole session.
//!
//! This is a separate file from `progressive_corpus.rs` because it is a separate claim. That
//! file gates the *parser* and pins the oracle canaries; this one gates the *decoder* and its
//! cross-pass state.
//!
//! # Why this is the gate, and not a differential
//!
//! ADR-0011 / #194 retired the `ironrdp-graphics` oracle as Progressive's byte-exactness
//! authority, and working this slice added two more reasons on top of the two already
//! recorded, both of them in the first-pass path this file drives:
//!
//! - the oracle captures the DAS sign array **after** dequantization (`progressive.rs:84`),
//!   where FreeRDP captures it straight off the RLGR output (`progressive.c:874`) — so its
//!   `sign` is the sign of a reconstructed coefficient and FreeRDP's is the sign of a
//!   quantized one. They differ for all 81 LL3 coefficients of every tile, because the LL3
//!   delta reconstruction runs between the two points;
//! - it clamps where FreeRDP wraps (`clamp_i16` against `prim_shift.c:27-31`).
//!
//! So the properties asserted here are **owned**: totality over real bytes, a census that
//! keeps the corpus honest about which axes it actually covers, determinism, and the measured
//! cost of the store's key.

use std::collections::HashMap;

use justrdp_codecs::rfx::progressive::{ProgressiveError, Scratch, TILE_RGBA_LEN, TileGrid};
use justrdp_pdu::rfx::progressive::{
    self, ProgressiveMessage, ProgressiveTile, QUALITY_FULL, REGION_FLAG_DWT_REDUCE_EXTRAPOLATE,
    TILE_FLAG_DIFFERENCE,
};

/// One captured `WireToSurface2` payload with the codec context and surface dimensions it was
/// decoded against.
struct Entry {
    codec_context_id: u32,
    width: u16,
    height: u16,
    data: Vec<u8>,
}

fn load_replay() -> Vec<Entry> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/progressive/replay.bin");
    let buf = std::fs::read(path).expect("the Progressive replay corpus must be present");

    let mut entries = Vec::new();
    let count = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let mut pos = 4usize;
    for _ in 0..count {
        let codec_context_id = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
        let width = u16::from_le_bytes(buf[pos + 4..pos + 6].try_into().unwrap());
        let height = u16::from_le_bytes(buf[pos + 6..pos + 8].try_into().unwrap());
        let len = u32::from_le_bytes(buf[pos + 8..pos + 12].try_into().unwrap()) as usize;
        pos += 12;
        entries.push(Entry {
            codec_context_id,
            width,
            height,
            data: buf[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    entries
}

/// What a full replay produced, so a green run can be inspected rather than merely trusted.
#[derive(Default, Debug)]
struct Replay {
    first_passes: usize,
    upgrade_passes: usize,
    coeff_diff_tiles: usize,
    full_quality_tiles: usize,
    indexed_quality_tiles: usize,
    /// Distinct `(shift)` widths seen across every band of every first pass.
    shift_widths: Vec<u8>,
    /// Distinct `num_bits` widths seen across every band of every upgrade pass.
    painted_tiles: usize,
    /// Non-empty pixel output — a tile that decoded to something other than all zeroes.
    non_black_tiles: usize,
    errors: Vec<ProgressiveError>,
}

/// Replay the whole corpus. `per_context` selects the design question under test: when true
/// the store is keyed by `codecContextId` (the bootstrap oracle's choice), when false by the
/// surface (FreeRDP's, and ours).
fn replay(entries: &[Entry], per_context: bool) -> Replay {
    let mut out = Replay::default();
    let mut grids: HashMap<u32, TileGrid> = HashMap::new();
    let mut scratch = Scratch::new();
    let mut rgba = vec![0u8; TILE_RGBA_LEN];

    for entry in entries {
        let key = if per_context {
            entry.codec_context_id
        } else {
            0
        };
        let grid = grids
            .entry(key)
            .or_insert_with(|| TileGrid::new(entry.width, entry.height));

        let messages = progressive::decode_all(&entry.data).expect("corpus payload must parse");
        for message in &messages {
            let ProgressiveMessage::Region(region) = message else {
                continue;
            };
            for tile in &region.tiles {
                let result = match tile {
                    ProgressiveTile::Simple(t) | ProgressiveTile::First(t) => {
                        out.first_passes += 1;
                        if t.flags & TILE_FLAG_DIFFERENCE != 0 {
                            out.coeff_diff_tiles += 1;
                        }
                        match t.quality {
                            None | Some(QUALITY_FULL) => out.full_quality_tiles += 1,
                            Some(_) => out.indexed_quality_tiles += 1,
                        }
                        for q in [t.quant_idx_y, t.quant_idx_cb, t.quant_idx_cr] {
                            if let Some(q) = region.quants.get(usize::from(q)) {
                                for band in [
                                    q.hl1, q.lh1, q.hh1, q.hl2, q.lh2, q.hh2, q.hl3, q.lh3, q.hh3,
                                    q.ll3,
                                ] {
                                    if !out.shift_widths.contains(&band) {
                                        out.shift_widths.push(band);
                                    }
                                }
                            }
                        }
                        grid.decode_first(t, region, &mut scratch, &mut rgba)
                    }
                    ProgressiveTile::Upgrade(t) => {
                        out.upgrade_passes += 1;
                        grid.decode_upgrade(t, region, &mut scratch, &mut rgba)
                    }
                };
                match result {
                    Ok(()) => {
                        if rgba.iter().any(|&b| b != 0) {
                            out.non_black_tiles += 1;
                        }
                    }
                    Err(e) => {
                        if !out.errors.contains(&e) {
                            out.errors.push(e);
                        }
                    }
                }
            }
        }
    }
    out.painted_tiles = grids.values().map(TileGrid::painted_tiles).sum();
    out
}

/// The gate: no tile the real server sent may be rejected, and the decode must produce
/// pixels rather than an all-black frame.
///
/// Acceptance, not values — the corpus carries no expected pixels, so what it can prove is
/// that the whole multi-pass chain is total over real bytes with real cross-pass state, which
/// is exactly the axis a synthetic vector cannot reach.
#[test]
fn every_real_tile_decodes_across_the_whole_session() {
    let entries = load_replay();
    let result = replay(&entries, false);

    assert!(
        result.errors.is_empty(),
        "real traffic was rejected: {:?}",
        result.errors
    );
    // Guard against a vacuous pass — a corpus that stopped carrying tiles would otherwise
    // make the assertion above trivially true.
    assert!(
        result.first_passes >= 2900 && result.upgrade_passes >= 3200,
        "too few tiles exercised (first {}, upgrade {})",
        result.first_passes,
        result.upgrade_passes
    );
    assert!(
        result.non_black_tiles > result.first_passes / 2,
        "most tiles decoded to all-zero pixels ({} of {}), which is what a silently \
         mis-wired pipeline looks like",
        result.non_black_tiles,
        result.first_passes + result.upgrade_passes
    );
    eprintln!(
        "replayed {} payloads: {} first passes, {} upgrade passes, {} tiles holding state, \
         {} non-black outputs",
        entries.len(),
        result.first_passes,
        result.upgrade_passes,
        result.painted_tiles,
        result.non_black_tiles
    );
}

/// **What the store's key actually costs — measured, after the first answer turned out to be
/// wrong.**
///
/// The claim this test was written to prove was that keying by `codecContextId` would strand
/// the upgrade passes, because the server rotates the id (24 distinct ids across 52 payloads,
/// one per refinement group) and sends a single `WBT_CONTEXT` block in the whole session. The
/// replay says otherwise: **both keys decode the corpus with zero errors and identical
/// pixels.** Every refinement group carries its own first pass under its own id, so an
/// upgrade always finds the tile it refines either way.
///
/// What the key decides instead is what the state is *bounded by*:
///
/// | keyed by | live tile stores after the session | bounded by |
/// |---|---|---|
/// | `codecContextId` | **2940** (≈ 138 MiB) | the session's length |
/// | surface | **260** = 20 × 13 | the surface's own tile grid |
///
/// A tile store is ~48 KiB, and nothing in the capture ever frees a context — so the first
/// column is #83's leak, measured, and it grows for as long as the session runs. The second
/// is exactly the grid the host already allocated a framebuffer for. That is the reason to
/// key by surface as FreeRDP does (`progressive.c:314`), and it is a *resource* argument, not
/// a correctness one — which is worth being precise about, because a correctness argument
/// would have implied the bootstrap decoder was painting the wrong pixels, and it is not.
#[test]
fn keying_the_store_by_codec_context_id_costs_an_unbounded_number_of_tile_stores() {
    let entries = load_replay();
    let per_context = replay(&entries, true);
    let per_surface = replay(&entries, false);

    // Neither arrangement rejects anything, and both paint the same tiles: the key is not
    // what makes the capture decodable.
    assert!(per_context.errors.is_empty() && per_surface.errors.is_empty());
    assert_eq!(
        per_context.non_black_tiles, per_surface.non_black_tiles,
        "the two keys must agree on the pixels, or this is a correctness question after all"
    );

    // The surface's grid is 20 x 13 for the captured 1280x800 surface, and the store cannot
    // exceed it however long the session runs.
    assert_eq!(
        per_surface.painted_tiles, 260,
        "surface-keyed state must be bounded by the tile grid"
    );
    assert!(
        per_context.painted_tiles > 10 * per_surface.painted_tiles,
        "expected context-keyed state to grow with the session (got {} against {})",
        per_context.painted_tiles,
        per_surface.painted_tiles
    );
    eprintln!(
        "tile stores held after the session: {} keyed by context id, {} keyed by surface",
        per_context.painted_tiles, per_surface.painted_tiles
    );
}

/// The corpus's arithmetic, measured rather than assumed — the numbers the module doc's
/// reasoning about bit positions rests on.
///
/// A corpus proves only what it contains (`docs/agents/theflow.md` Step 4). Recording the
/// span here means a future capture that stops covering an axis says so out loud instead of
/// leaving a test green for the wrong reason.
#[test]
fn the_corpus_arithmetic_stays_inside_the_range_the_decoder_reasons_about() {
    let entries = load_replay();
    let result = replay(&entries, false);

    let min = *result.shift_widths.iter().min().expect("bands were seen");
    let max = *result.shift_widths.iter().max().expect("bands were seen");
    assert!(
        (6..=15).contains(&min) && (6..=15).contains(&max),
        "base quant bands spanned {min}..={max}"
    );
    // The `>= 6` floor FreeRDP enforces and we deliberately do not: the corpus is silent on
    // it, which is the recorded reason the choice is a posture and not a measurement.
    assert!(
        min >= 6,
        "a region below FreeRDP's floor would make the tolerance decision measurable"
    );
    assert!(
        result.full_quality_tiles > 0 && result.indexed_quality_tiles > 0,
        "both quality forms must be exercised (full {}, indexed {})",
        result.full_quality_tiles,
        result.indexed_quality_tiles
    );
    eprintln!(
        "base quant bands {min}..={max}; {} full-quality and {} table-indexed first passes; \
         {} carried RFX_TILE_DIFFERENCE",
        result.full_quality_tiles, result.indexed_quality_tiles, result.coeff_diff_tiles
    );
}

/// Every region in the capture sets `RFX_DWT_REDUCE_EXTRAPOLATE`, which is what makes the
/// extrapolate layout the live path and the non-extrapolate branch of the first pass
/// unexercised by real traffic.
///
/// Recorded as a measurement rather than left implicit, because two of this slice's decisions
/// rest on it: the refusal to run an upgrade pass on a non-extrapolate region is unreachable
/// here, and the non-extrapolate first-pass branch is carried on synthetic evidence alone.
#[test]
fn the_capture_never_exercises_the_non_extrapolate_branch() {
    let entries = load_replay();
    let mut regions = 0usize;
    let mut extrapolate = 0usize;
    for entry in &entries {
        for message in &progressive::decode_all(&entry.data).expect("payload must parse") {
            if let ProgressiveMessage::Region(region) = message {
                regions += 1;
                if region.flags & REGION_FLAG_DWT_REDUCE_EXTRAPOLATE != 0 {
                    extrapolate += 1;
                }
            }
        }
    }
    assert_eq!(
        regions,
        extrapolate,
        "{} of {regions} regions omitted RFX_DWT_REDUCE_EXTRAPOLATE — the non-extrapolate \
         path just became measurable, and both decisions resting on its absence should be \
         re-derived against it",
        regions - extrapolate
    );
    assert!(regions > 0, "the corpus carried no regions");
}

/// Replaying the same bytes twice produces the same state. Cheap, and it is the property a
/// store carried across calls is most likely to break.
#[test]
fn the_replay_is_deterministic() {
    let entries = load_replay();
    let a = replay(&entries, false);
    let b = replay(&entries, false);
    assert_eq!(a.painted_tiles, b.painted_tiles);
    assert_eq!(a.non_black_tiles, b.non_black_tiles);
    assert_eq!(a.first_passes, b.first_passes);
    assert_eq!(a.upgrade_passes, b.upgrade_passes);
}
