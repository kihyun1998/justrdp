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
//!   where FreeRDP captures it straight off the RLGR output (`progressive.c:876`) — so its
//!   `sign` is the sign of a reconstructed coefficient and FreeRDP's is the sign of a
//!   quantized one, and the LL3 delta reconstruction runs between the two points. Measured
//!   over this corpus: the two capture points disagree on **8369 of 8829** real components.
//!   Not on all of them and never on all 81 coefficients of one — the delta is a prefix sum,
//!   so its first element is always untouched — but on the large majority, and permanently,
//!   because the sign store routes every later refinement of that coefficient;
//! - it clamps where FreeRDP wraps (`clamp_i16` against `prim_shift.c:27-31`).
//!
//! So the properties asserted here are **owned**: totality over real bytes, a census that
//! keeps the corpus honest about which axes it actually covers, determinism, and the measured
//! cost of the store's key.

use std::collections::HashMap;

use justrdp_codecs::rfx::progressive::{
    OrderAnomaly, ProgressiveError, Scratch, SurfaceStore, TILE_RGBA_LEN, TileGrid, TileState,
    order_payload,
};
use justrdp_pdu::rfx::progressive::{
    self, ProgressiveMessage, ProgressiveQuant, ProgressiveRegion, ProgressiveTile, QUALITY_FULL,
    REGION_FLAG_DWT_REDUCE_EXTRAPOLATE, TILE_FLAG_DIFFERENCE,
};

/// The ten per-band nibbles in the order every quant table packs them.
fn bands_of(q: &ProgressiveQuant) -> [u8; 10] {
    [
        q.hl1, q.lh1, q.hh1, q.hl2, q.lh2, q.hh2, q.hl3, q.lh3, q.hh3, q.ll3,
    ]
}

/// The luma progressive-quant bands a tile's `quality` selects; the `0xFF` sentinel and an
/// absent quality both mean "no progressive quantization", i.e. all zeroes.
fn prog_bands(region: &ProgressiveRegion<'_>, quality: Option<u8>) -> [u8; 10] {
    match quality {
        None | Some(QUALITY_FULL) => [0; 10],
        Some(q) => region
            .prog_quants
            .get(usize::from(q))
            .map_or([0; 10], |e| bands_of(&e.y)),
    }
}

/// The surface id the corpus is replayed against. The capture is a single surface and the
/// replay format does not carry its id, so any constant serves — what matters is that every
/// payload uses the *same* one, which is the whole content of "keyed by surface".
const CORPUS_SURFACE_ID: u16 = 0;

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
    /// Distinct base-quant band values seen across every first pass — the raw wire nibbles,
    /// *not* the derived `shift`.
    base_quant_bands: Vec<u8>,
    /// Distinct derived `shift = quant + prog_quant - 1` values across every first pass.
    first_pass_shifts: Vec<u8>,
    /// Distinct derived `num_bits = previous_bit_pos - bit_pos` values across every upgrade.
    upgrade_num_bits: Vec<u8>,
    painted_tiles: usize,
    /// Tiles whose RGB (ignoring alpha, which `rfx_ycbcr_to_rgba` always writes as 255) is
    /// not entirely zero.
    non_black_tiles: usize,
    /// FNV-1a over every decoded tile's RGBA, in decode order. The only field that can see a
    /// pixel change; `non_black_tiles` cannot, because it counts tiles rather than comparing
    /// them.
    pixel_hash: u64,
    /// Upgrade passes that actually moved a coefficient in the store they refined.
    upgrades_that_refined: usize,
    ok: usize,
    errors: Vec<ProgressiveError>,
}

fn fnv1a(hash: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *hash ^= u64::from(b);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
}

/// Replay the whole corpus. `per_context` selects the design question under test: when true
/// the store is keyed by `codecContextId` (the bootstrap oracle's choice), when false by the
/// surface (FreeRDP's, and ours).
fn replay(entries: &[Entry], per_context: bool) -> Replay {
    let mut out = Replay {
        // FNV-1a offset basis.
        pixel_hash: 0xcbf2_9ce4_8422_2325,
        ..Replay::default()
    };
    // The surface-keyed side is driven through the real `SurfaceStore` (#170) rather than a
    // second copy of its lookup, so the two cannot drift. The context-keyed side stays a bare
    // map on purpose: it is the counterfactual this file exists to price, and `SurfaceStore`
    // deliberately cannot express it.
    let mut store = SurfaceStore::new();
    let mut context_grids: HashMap<u32, TileGrid> = HashMap::new();
    let mut scratch = Scratch::new();
    let mut rgba = vec![0u8; TILE_RGBA_LEN];

    for entry in entries {
        let grid = if per_context {
            context_grids
                .entry(entry.codec_context_id)
                .or_insert_with(|| TileGrid::new(entry.width, entry.height))
        } else {
            store.grid_mut(CORPUS_SURFACE_ID, entry.width, entry.height)
        };

        let messages = progressive::decode_all(&entry.data).expect("corpus payload must parse");
        // Through the block-ordering machine, not around it — otherwise nothing in the repo
        // composes `order_payload` with the decode it gates (#170).
        let order = order_payload(&messages);
        assert!(
            order.fatal.is_none(),
            "no real payload is fatally mis-ordered"
        );
        for region in order.regions {
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
                        let prog = prog_bands(region, t.quality);
                        for q in [t.quant_idx_y, t.quant_idx_cb, t.quant_idx_cr] {
                            let Some(q) = region.quants.get(usize::from(q)) else {
                                continue;
                            };
                            for (band, p) in bands_of(q).into_iter().zip(prog) {
                                if !out.base_quant_bands.contains(&band) {
                                    out.base_quant_bands.push(band);
                                }
                                // The value the decoder actually shifts by, which is what the
                                // module's reasoning is about — a sum of two nibbles, minus one.
                                let shift = band.saturating_add(p).saturating_sub(1);
                                if !out.first_pass_shifts.contains(&shift) {
                                    out.first_pass_shifts.push(shift);
                                }
                            }
                        }
                        grid.decode_first(t, region, &mut scratch, &mut rgba)
                    }
                    ProgressiveTile::Upgrade(t) => {
                        out.upgrade_passes += 1;
                        let previous = grid.tile(t.x_idx, t.y_idx).map(TileState::bit_positions);
                        let prog = prog_bands(region, Some(t.quality));
                        if let (Some(previous), Some(q)) =
                            (previous, region.quants.get(usize::from(t.quant_idx_y)))
                        {
                            for ((prev, base), p) in bands_of(&previous[0])
                                .into_iter()
                                .zip(bands_of(q))
                                .zip(prog)
                            {
                                let num_bits = prev.saturating_sub(base.saturating_add(p));
                                if !out.upgrade_num_bits.contains(&num_bits) {
                                    out.upgrade_num_bits.push(num_bits);
                                }
                            }
                        }
                        let before = grid
                            .tile(t.x_idx, t.y_idx)
                            .and_then(|s| s.coefficients(0))
                            .map(<[i16]>::to_vec);
                        let r = grid.decode_upgrade(t, region, &mut scratch, &mut rgba);
                        if r.is_ok()
                            && let (Some(before), Some(after)) = (
                                before,
                                grid.tile(t.x_idx, t.y_idx).and_then(|s| s.coefficients(0)),
                            )
                            && before != after
                        {
                            out.upgrades_that_refined += 1;
                        }
                        r
                    }
                };
                match result {
                    Ok(()) => {
                        out.ok += 1;
                        fnv1a(&mut out.pixel_hash, &rgba);
                        // Alpha is unconditionally 255 (`color.rs`), so "any non-zero byte"
                        // is true of every successful decode and measures nothing. The RGB
                        // channels are the ones that can be black.
                        if rgba
                            .chunks_exact(4)
                            .any(|px| px[..3].iter().any(|&b| b != 0))
                        {
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
    out.painted_tiles = if per_context {
        context_grids.values().map(TileGrid::painted_tiles).sum()
    } else {
        store
            .grid(CORPUS_SURFACE_ID)
            .map_or(0, TileGrid::painted_tiles)
    };
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
        result.non_black_tiles * 10 > result.ok * 9,
        "{} of {} decoded tiles were entirely black in RGB, which is what a silently          mis-wired pipeline looks like",
        result.ok - result.non_black_tiles,
        result.ok
    );
    // **The refinement has to do something.** Deleting `srl::upgrade_component`'s body
    // entirely left every test in this file green: an upgrade that refines nothing repaints
    // the first pass, which is accepted, non-black and deterministic. Acceptance gates are
    // blind to a no-op by construction, so the effect is asserted directly.
    assert!(
        result.upgrades_that_refined * 2 > result.upgrade_passes,
        "only {} of {} upgrade passes changed a coefficient",
        result.upgrades_that_refined,
        result.upgrade_passes
    );
    eprintln!(
        "replayed {} payloads: {} first passes, {} upgrade passes, {} tiles holding state, \
         {} non-black outputs, {} upgrades that moved a coefficient",
        entries.len(),
        result.first_passes,
        result.upgrade_passes,
        result.painted_tiles,
        result.non_black_tiles,
        result.upgrades_that_refined
    );
}

/// **What the store's key decides — restated twice, because the first two answers were both
/// wrong.**
///
/// The claim this test was written to prove was that keying by `codecContextId` would strand
/// the upgrade passes, since the server rotates the id (24 across 52 payloads) and sends one
/// `WBT_CONTEXT` block in the whole session. Measured: **both keys decode with zero errors**,
/// because every refinement group carries its own first pass under its own id.
///
/// The second answer was that the key is therefore a *resource* question and not a
/// correctness one. That was wrong too, and it was wrong because the evidence offered for it
/// — a count of non-black tiles — cannot see a pixel change at all. Hashing the tiles says
/// the two keyings paint **different pixels**, and the reason is mechanical: a
/// `RFX_TILE_DIFFERENCE` tile adds its coefficients to the store already held for that grid
/// position (`progressive.c:821-826`). Under surface keying that store is the previous
/// frame's content for the same screen position, which is what the flag means. Under context
/// keying a fresh id starts from zeroes, so the difference is added to nothing and the
/// previous frame's contribution is dropped.
///
/// So the key is a correctness question, settled by FreeRDP keying on `surfaceId`
/// (`progressive.c:314`, `:471`) — and it *also* bounds the memory, which is the part that
/// was never in doubt:
///
/// | keyed by | live tile stores after the session | bounded by |
/// |---|---|---|
/// | `codecContextId` | **2940** (48 KiB each ≈ 138 MiB) | the session's length |
/// | surface | **260** = 20 × 13 | the surface's own tile grid |
#[test]
fn the_store_key_changes_the_pixels_and_not_only_the_memory() {
    let entries = load_replay();
    let per_context = replay(&entries, true);
    let per_surface = replay(&entries, false);

    assert!(per_context.errors.is_empty() && per_surface.errors.is_empty());
    assert_eq!(
        per_context.ok, per_surface.ok,
        "neither key rejects anything, so the difference below is not about acceptance"
    );
    assert_ne!(
        per_context.pixel_hash, per_surface.pixel_hash,
        "the two keys must paint differently — if they stopped doing so, the mechanism that          makes the choice matter (RFX_TILE_DIFFERENCE against the previous frame) is no          longer exercised by the corpus, and the decision would need re-deriving"
    );
    assert!(
        per_surface.coeff_diff_tiles > 0,
        "difference tiles are the mechanism; {} of them",
        per_surface.coeff_diff_tiles
    );

    // And the resource half, which was never in doubt.
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
        "tile stores held after the session: {} keyed by context id, {} keyed by surface;          {} difference tiles; pixel hashes {:016x} vs {:016x}",
        per_context.painted_tiles,
        per_surface.painted_tiles,
        per_surface.coeff_diff_tiles,
        per_context.pixel_hash,
        per_surface.pixel_hash
    );
}

/// The corpus's arithmetic, measured rather than assumed — and measured on the **derived**
/// values the decoder reasons about, not on the raw wire nibbles.
///
/// The first version of this test censused `region.quants` alone and called the result
/// `shift_widths`. Those are different quantities: `shift = quant + prog_quant - 1` and
/// `num_bits = previous_bit_pos - bit_pos`, and it is their range — not the nibbles' — that
/// the module's guards are sized against. A census of the input to an arithmetic is not a
/// census of the arithmetic.
#[test]
fn the_corpus_arithmetic_stays_inside_the_range_the_decoder_reasons_about() {
    let entries = load_replay();
    let result = replay(&entries, false);

    let span = |v: &[u8]| (*v.iter().min().unwrap(), *v.iter().max().unwrap());
    let (base_min, base_max) = span(&result.base_quant_bands);
    let (shift_min, shift_max) = span(&result.first_pass_shifts);
    let (bits_min, bits_max) = span(&result.upgrade_num_bits);

    // The base quant stays inside FreeRDP's declared window (`progressive.c:2177` floor,
    // `:2186` ceiling), which is the *reason* the tolerance decision below is a posture and
    // not a measurement: no real region goes under the floor, so the corpus cannot arbitrate
    // whether refusing one is right.
    assert!(
        (6..=15).contains(&base_min) && (6..=15).contains(&base_max),
        "base quant bands spanned {base_min}..={base_max}"
    );
    // The derived shift must stay under 16 or the tile would be refused outright — every one
    // of the 2943 first passes decoded, so this is a consequence, but recording the span says
    // how much headroom the guard actually has on real traffic.
    assert!(
        shift_max < 16,
        "a real first-pass shift reached {shift_max}, which the decoder refuses"
    );
    assert!(
        bits_max <= 30,
        "a real num_bits reached {bits_max}, above rfx::srl::MAX_BIT_POS"
    );
    assert!(
        result.full_quality_tiles > 0 && result.indexed_quality_tiles > 0,
        "both quality forms must be exercised (full {}, indexed {})",
        result.full_quality_tiles,
        result.indexed_quality_tiles
    );
    eprintln!(
        "base quant {base_min}..={base_max}; derived first-pass shift {shift_min}..={shift_max}          (refused at 16); upgrade num_bits {bits_min}..={bits_max} (MAX_BIT_POS 30);          {} full-quality and {} table-indexed first passes; {} carried RFX_TILE_DIFFERENCE",
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

/// **The sign store is the raw entropy output — asserted where the LL3 delta can be seen.**
///
/// The unit test for this pins only HL1 indices 0..8, which the LL3 delta never touches, so
/// moving the delta ahead of the sign capture passed the entire crate suite. On real traffic
/// it does not: the delta is a prefix sum over the 81 LL3 coefficients, and it moves a
/// majority of their signs.
///
/// Both halves are measured here — that the capture is faithful for every one of the 8829
/// real components, and that the check is *discriminating*, i.e. that a delta applied first
/// would actually have produced something else.
#[test]
fn the_sign_store_is_the_raw_entropy_output_on_every_real_component() {
    use justrdp_codecs::rfx::quant::{BANDS_EXTRAPOLATE, COMPONENT_LEN};
    use justrdp_codecs::rfx::{quant, rlgr};
    use justrdp_pdu::rfx::EntropyAlgorithm;

    let entries = load_replay();
    let mut grid = TileGrid::new(1280, 800);
    let mut scratch = Scratch::new();
    let mut rgba = vec![0u8; TILE_RGBA_LEN];
    let mut expected = vec![0i16; COMPONENT_LEN];

    let mut components = 0usize;
    let mut mismatches = 0usize;
    let mut delta_would_have_differed = 0usize;
    let (ll3_offset, ll3_len) = BANDS_EXTRAPOLATE[9];

    for entry in &entries {
        for message in &progressive::decode_all(&entry.data).expect("payload must parse") {
            let ProgressiveMessage::Region(region) = message else {
                continue;
            };
            for t in &region.tiles {
                let (ProgressiveTile::Simple(t) | ProgressiveTile::First(t)) = t else {
                    if let ProgressiveTile::Upgrade(u) = t {
                        let _ = grid.decode_upgrade(u, region, &mut scratch, &mut rgba);
                    }
                    continue;
                };
                if grid
                    .decode_first(t, region, &mut scratch, &mut rgba)
                    .is_err()
                {
                    continue;
                }
                let state = grid.tile(t.x_idx, t.y_idx).expect("the pass painted it");
                for (c, data) in [t.y_data, t.cb_data, t.cr_data].into_iter().enumerate() {
                    components += 1;
                    rlgr::decode(EntropyAlgorithm::Rlgr1, data, &mut expected)
                        .expect("the pass decoded, so its entropy stream is valid");
                    if state.signs(c).expect("component exists") != expected.as_slice() {
                        mismatches += 1;
                    }
                    // Would capturing after the LL3 delta have given something else? If not
                    // for any component, this test proves nothing about the ordering.
                    let mut deltaed = expected.clone();
                    quant::ll3_delta_decode(&mut deltaed[ll3_offset..ll3_offset + ll3_len]);
                    if deltaed != expected {
                        delta_would_have_differed += 1;
                    }
                }
            }
        }
    }

    assert_eq!(
        mismatches, 0,
        "{mismatches} of {components} components hold something other than the raw entropy          output in their sign store"
    );
    assert!(
        delta_would_have_differed * 2 > components,
        "only {delta_would_have_differed} of {components} components would decode differently          with the LL3 delta applied first, so this test cannot see the ordering it asserts"
    );
    eprintln!(
        "{components} real components: sign store faithful on all of them; the LL3 delta          would have changed {delta_would_have_differed} of them"
    );
}

/// **`decode_first` selects both the band table and the inverse transform from the region's
/// flag — pinned on real data, because no synthetic fixture can see it.**
///
/// Mutation-driven, and the second attempt. Hardcoding `extrapolate = true` in
/// `decode_first`, and separately hardcoding the transform, each passed the entire crate
/// suite. The corpus alone cannot catch it either — all 52 regions set the flag — so the test
/// has to *construct* the counterfactual: take a real first-pass tile and decode it twice,
/// once under each layout.
///
/// The first attempt used the synthetic `[0x55, 0xAA, 0x12, 0x34]` fixture and failed for an
/// instructive reason: a short RLGR stream leaves every non-zero coefficient inside `HL1`,
/// which begins at offset 0 in **both** layouts, and the LL3 delta then runs over a window of
/// zeros. The two layouts are genuinely indistinguishable on such an input. Only a stream
/// with energy spread across the bands — i.e. a real one — separates them.
#[test]
fn decode_first_selects_the_band_table_and_the_transform_from_the_region_flag() {
    use justrdp_codecs::color;
    use justrdp_codecs::rfx::quant::COMPONENT_LEN;
    use justrdp_codecs::rfx::{dwt, dwt_extrapolate};

    let entries = load_replay();
    // The first payload that carries a first-pass tile inside a region with the flag set.
    let mut found = false;

    for entry in &entries {
        let messages = progressive::decode_all(&entry.data).expect("payload must parse");
        for message in &messages {
            let ProgressiveMessage::Region(region) = message else {
                continue;
            };
            if region.flags & REGION_FLAG_DWT_REDUCE_EXTRAPOLATE == 0 {
                continue;
            }
            let Some(ProgressiveTile::Simple(tile) | ProgressiveTile::First(tile)) = region
                .tiles
                .iter()
                .find(|t| matches!(t, ProgressiveTile::Simple(_) | ProgressiveTile::First(_)))
            else {
                continue;
            };

            let mut without = region.clone();
            without.flags &= !REGION_FLAG_DWT_REDUCE_EXTRAPOLATE;

            let decode = |r: &ProgressiveRegion<'_>| {
                let mut grid = TileGrid::new(entry.width, entry.height);
                let mut scratch = Scratch::new();
                let mut rgba = vec![0u8; TILE_RGBA_LEN];
                grid.decode_first(tile, r, &mut scratch, &mut rgba)
                    .expect("a real first pass decodes under either layout");
                let state = grid.tile(tile.x_idx, tile.y_idx).expect("painted");
                let store: Vec<Vec<i16>> = (0..3)
                    .map(|c| state.coefficients(c).expect("component").to_vec())
                    .collect();
                (store, rgba)
            };
            let (ex_store, ex_pixels) = decode(region);
            let (std_store, std_pixels) = decode(&without);

            // The band table half: the two layouts dequantize differently, so a hardcoded
            // table shows up in the store.
            assert_ne!(
                ex_store, std_store,
                "the two layouts must dequantize this tile differently, or the tile carries                  no energy outside HL1 and cannot distinguish them"
            );

            // The transform half: each reconstruction must use the transform its layout
            // implies, checked against a locally computed expectation.
            let paint = |store: &[Vec<i16>], transform: fn(&mut [i16], &mut [i16])| {
                let mut temp = vec![0i16; COMPONENT_LEN];
                let planes: Vec<Vec<i16>> = store
                    .iter()
                    .map(|c| {
                        let mut plane = c.clone();
                        transform(&mut plane, &mut temp);
                        plane
                    })
                    .collect();
                let mut out = vec![0u8; TILE_RGBA_LEN];
                color::rfx_ycbcr_to_rgba(&planes[0], &planes[1], &planes[2], &mut out);
                out
            };
            assert_ne!(
                paint(&std_store, dwt::decode),
                paint(&std_store, dwt_extrapolate::decode),
                "this store must distinguish the transforms, or the assertions below are vacuous"
            );
            assert_eq!(
                ex_pixels,
                paint(&ex_store, dwt_extrapolate::decode),
                "an extrapolate region must reconstruct with the extrapolate transform"
            );
            assert_eq!(
                std_pixels,
                paint(&std_store, dwt::decode),
                "a non-extrapolate region must reconstruct with the classic transform"
            );
            found = true;
            break;
        }
        if found {
            break;
        }
    }
    assert!(found, "the corpus carried no first-pass tile to test with");
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

// -------------------------------------------------------------------------------------------
// Block ordering over the real capture (#170).
// -------------------------------------------------------------------------------------------

/// **The census that decides whether the ordering rules are per payload or per stream.**
///
/// Every payload the real server sent, run through [`order_payload`]. Two things are asserted,
/// and the second is what gives the first any weight:
///
/// 1. all 52 payloads order cleanly — every region survives, no rule is broken;
/// 2. the *same* messages, judged as one continuous stream, are **rejected** — which is the
///    counterfactual for the reading #170 and #167 were written against.
///
/// 51 of the 52 payloads are `FRAME_BEGIN REGION FRAME_END` with no `SYNC` and no `CONTEXT`,
/// because the server sends the header blocks once per stream. Carried across payloads, the
/// second `FRAME_BEGIN` is a duplicate and every later one follows a `FRAME_END` — so a
/// per-stream mask rejects the whole session after payload 0. FreeRDP zeroes its mask at the
/// top of `progressive_decompress` (`progressive.c:2463`), which `gdi_SurfaceCommand_Progressive`
/// calls once per surface command (`gdi/gfx.c:1116`); this test is that fact, measured on our
/// own parser against real bytes rather than read off theirs.
#[test]
fn every_real_payload_orders_cleanly_and_the_same_bytes_as_one_stream_do_not() {
    let entries = load_replay();
    assert_eq!(entries.len(), 52, "the committed corpus is 52 payloads");

    let mut sequences: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut regions = 0usize;
    let mut anomalies: Vec<OrderAnomaly> = Vec::new();

    for entry in &entries {
        let messages = progressive::decode_all(&entry.data).expect("the corpus parses (#167)");

        let shape: Vec<&str> = messages
            .iter()
            .map(|m| match m {
                ProgressiveMessage::Sync => "SYNC",
                ProgressiveMessage::Context { .. } => "CONTEXT",
                ProgressiveMessage::FrameBegin { .. } => "FRAME_BEGIN",
                ProgressiveMessage::FrameEnd => "FRAME_END",
                ProgressiveMessage::Region(_) => "REGION",
            })
            .collect();
        *sequences.entry(shape.join(" ")).or_default() += 1;

        let order = order_payload(&messages);
        assert!(
            order.fatal.is_none(),
            "a real payload is never fatally mis-ordered"
        );
        regions += order.regions.len();
        anomalies.extend(order.anomalies);
    }

    assert_eq!(
        sequences.get("FRAME_BEGIN REGION FRAME_END").copied(),
        Some(51),
        "the ordinary payload carries neither header block: {sequences:?}"
    );
    assert_eq!(
        sequences
            .get("SYNC CONTEXT FRAME_BEGIN REGION FRAME_END")
            .copied(),
        Some(1),
        "exactly one payload opens the stream: {sequences:?}"
    );
    assert_eq!(regions, 52, "no region may be skipped");
    assert!(
        anomalies.is_empty(),
        "the real server breaks no ordering rule: {anomalies:?}"
    );

    // The counterfactual. Concatenating the payloads *is* the per-stream reading — one mask
    // over every block the session sent — and it is fatal on the second payload.
    let all: Vec<Vec<u8>> = entries.iter().map(|e| e.data.clone()).collect();
    let mut stream = Vec::new();
    for data in &all {
        stream.extend(progressive::decode_all(data).expect("parses"));
    }
    let one_stream = order_payload(&stream);
    assert_eq!(
        one_stream.fatal,
        Some(ProgressiveError::DuplicateFrameBegin),
        "read as one stream, the session dies at payload 1 — which is why the mask is per payload"
    );
    assert_eq!(
        one_stream.regions.len(),
        1,
        "and it dies having accepted exactly payload 0's region"
    );
}

/// The lifecycle this slice owns, driven by the corpus rather than by hand-built messages.
///
/// The capture contains **no teardown of any kind** — no `DELETESURFACE`, no
/// `DELETEENCODINGCONTEXT`, no reset — so what it can prove is the *accumulation* side: one
/// surface, 24 distinct `codecContextId`s, and a store that stays at exactly one grid. That is
/// #83's leak in the form it actually takes, and the form in which the surface key closes it.
#[test]
fn the_whole_session_lives_in_one_surface_store_across_twenty_four_context_ids() {
    let entries = load_replay();
    let context_ids: std::collections::BTreeSet<u32> =
        entries.iter().map(|e| e.codec_context_id).collect();
    assert_eq!(
        context_ids.len(),
        24,
        "the server rotates the context id per refinement group"
    );

    let mut store = SurfaceStore::new();
    let mut scratch = Scratch::new();
    let mut rgba = vec![0u8; TILE_RGBA_LEN];
    for entry in &entries {
        // What the assembly layer (#171) will do per payload: reach for the surface's grid,
        // never for the context id's — and actually decode into it, because a store that is
        // never painted cannot tell a kept one from a cleared one.
        let messages = progressive::decode_all(&entry.data).expect("parses");
        let grid = store.grid_mut(CORPUS_SURFACE_ID, entry.width, entry.height);
        for region in order_payload(&messages).regions {
            for tile in &region.tiles {
                let _ = match tile {
                    ProgressiveTile::Simple(t) | ProgressiveTile::First(t) => {
                        grid.decode_first(t, region, &mut scratch, &mut rgba)
                    }
                    ProgressiveTile::Upgrade(t) => {
                        grid.decode_upgrade(t, region, &mut scratch, &mut rgba)
                    }
                };
            }
        }
        // The server rotates the context id per refinement group; each rotation is a chance
        // for a store keyed by it to start from zeroes. This must cost nothing.
        store.delete_context(entry.codec_context_id);
    }
    assert_eq!(
        store.live_surfaces(),
        1,
        "24 context ids, one surface, one store — and DELETEENCODINGCONTEXT freed none of it"
    );
    assert_eq!(
        store.grid(CORPUS_SURFACE_ID).map(TileGrid::painted_tiles),
        Some(260),
        "every tile of the 20 x 13 grid survived all 52 delete_context calls"
    );

    store.delete_surface(CORPUS_SURFACE_ID);
    assert_eq!(store.live_surfaces(), 0, "DeleteSurface is the free path");
    assert_eq!(
        store.grid(CORPUS_SURFACE_ID).map(TileGrid::painted_tiles),
        None,
        "and it takes every painted tile with it"
    );
}
