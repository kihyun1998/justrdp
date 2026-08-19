//! **Slice 5's owned-basis gate (#171).** The whole `WireToSurface2` pipeline — parse, block
//! ordering, multi-pass tile decode, region clipping — driven over the real server's 52
//! captured payloads, with expectations derived from FreeRDP and from measurement rather than
//! from an oracle diff.
//!
//! # Why this file is the gate and `ironrdp-graphics::progressive` is not
//!
//! ADR-0011 retired the oracle for this codec on seven measured divergences, and #194 measured
//! the blunt one: it decodes **2 of 52** of these payloads. The gate #171 was originally
//! written with — *"byte-identical against the oracle, 100%"* — is unmeetable, and meeting it
//! would mean reproducing the oracle's defects. So the properties asserted here are owned:
//! totality over real bytes, a **measured** clipping census, and a counterfactual that prices
//! the one decision this layer makes that a decoder-level test cannot see.
//!
//! # The counterfactual, and why it is a test rather than a comment
//!
//! `TileGrid::decode_first`/`decode_upgrade` paint a 64 × 64 tile and stop; *where those
//! pixels go* is this layer's. FreeRDP clips every tile against the region's rects
//! (`update_tiles`, `progressive.c:2329-2412`) and the pre-#171 client blits the whole tile
//! (`justrdp/src/egfx.rs`, the WTS2 arm). Those are not two spellings of one behaviour:
//! replayed over this corpus they leave **57 386 of 1 024 000** surface pixels different.
//! [`clipping_to_the_region_rects_changes_the_picture_not_only_the_dirty_rect`] is that
//! measurement, kept as an assertion so the day it stops being true is a red test rather than
//! a silent change of picture.

use justrdp_codecs::rfx::progressive::{
    PayloadOutcome, Progressive, Scratch, SurfaceStore, TILE_RGBA_LEN, order_payload,
};
use justrdp_pdu::rfx::progressive::{self, ProgressiveTile};

/// The surface id the corpus is replayed against. The capture is a single surface and the
/// replay format does not carry its id, so any constant serves — what matters is that every
/// payload uses the *same* one, which is the whole content of "keyed by surface".
const CORPUS_SURFACE_ID: u16 = 0;

/// One captured `WireToSurface2` payload with the surface dimensions it was decoded against.
struct Entry {
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
        let width = u16::from_le_bytes(buf[pos + 4..pos + 6].try_into().unwrap());
        let height = u16::from_le_bytes(buf[pos + 6..pos + 8].try_into().unwrap());
        let len = u32::from_le_bytes(buf[pos + 8..pos + 12].try_into().unwrap()) as usize;
        pos += 12;
        entries.push(Entry {
            width,
            height,
            data: buf[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    entries
}

/// A surface the size of the one the capture was taken against, so a replay can be inspected
/// as pixels rather than only as counters.
struct Canvas {
    width: usize,
    height: usize,
    rgba: Vec<u8>,
}

impl Canvas {
    fn new(width: u16, height: u16) -> Self {
        let (width, height) = (usize::from(width), usize::from(height));
        Self {
            width,
            height,
            rgba: vec![0; width * height * 4],
        }
    }

    /// The blit `justrdp::egfx::Surface::blit` performs, reduced to what this test needs: the
    /// caller has already clipped, so this only copies.
    fn blit(
        &mut self,
        at: (usize, usize),
        size: (usize, usize),
        tile: &[u8],
        from: (usize, usize),
    ) {
        let ((x, y), (w, h), (sx, sy)) = (at, size, from);
        for row in 0..h {
            let src = ((sy + row) * 64 + sx) * 4;
            let dst = ((y + row) * self.width + x) * 4;
            self.rgba[dst..dst + w * 4].copy_from_slice(&tile[src..src + w * 4]);
        }
    }

    fn pixels_differing_from(&self, other: &Canvas) -> usize {
        self.rgba
            .chunks_exact(4)
            .zip(other.rgba.chunks_exact(4))
            .filter(|(a, b)| a != b)
            .count()
    }
}

/// What one whole-corpus replay through the assembled decoder produced.
#[derive(Default)]
struct Assembled {
    payloads: usize,
    tiles_decoded: usize,
    tiles_skipped: usize,
    rects_painted: usize,
    /// Tiles whose paint rects covered the whole visible tile — i.e. the region's rects did
    /// not clip them at all.
    tiles_unclipped: usize,
    /// Tiles the region's rects clipped: painted, but not in full.
    tiles_clipped: usize,
    /// Tiles the region's rects excluded entirely, so nothing was painted for them.
    tiles_excluded: usize,
    painted_pixels: u64,
    anomalies: Vec<String>,
    fatals: usize,
    errors: Vec<String>,
}

/// Replay the corpus through the assembled decoder, painting into `canvas`.
fn replay_assembled(entries: &[Entry], canvas: &mut Canvas) -> Assembled {
    let mut decoder = Progressive::new();
    let mut out = Assembled::default();

    for entry in entries {
        out.payloads += 1;
        // Per-tile coverage is measured here rather than inside the decoder: the decoder emits
        // rects and this is the only place that knows which tile they came from.
        let mut covered: std::collections::HashMap<(u16, u16), u64> =
            std::collections::HashMap::new();
        let mut seen: Vec<(u16, u16)> = Vec::new();

        let outcome: PayloadOutcome = decoder
            .decode(
                CORPUS_SURFACE_ID,
                entry.width,
                entry.height,
                &entry.data,
                |rect| {
                    let origin = (rect.x - rect.src_x, rect.y - rect.src_y);
                    let key = (origin.0 / 64, origin.1 / 64);
                    if !seen.contains(&key) {
                        seen.push(key);
                    }
                    *covered.entry(key).or_default() +=
                        u64::from(rect.width) * u64::from(rect.height);
                    out.painted_pixels += u64::from(rect.width) * u64::from(rect.height);
                    canvas.blit(
                        (usize::from(rect.x), usize::from(rect.y)),
                        (usize::from(rect.width), usize::from(rect.height)),
                        rect.tile,
                        (usize::from(rect.src_x), usize::from(rect.src_y)),
                    );
                },
            )
            .expect("every captured payload must parse and decode");

        out.tiles_decoded += outcome.tiles_decoded;
        out.tiles_skipped += outcome.tiles_skipped;
        out.rects_painted += outcome.rects_painted;
        if outcome.fatal.is_some() {
            out.fatals += 1;
        }
        for anomaly in &outcome.anomalies {
            let text = format!("{anomaly:?}");
            if !out.anomalies.contains(&text) {
                out.anomalies.push(text);
            }
        }
        if let Some(e) = &outcome.first_error {
            let text = format!("{e}");
            if !out.errors.contains(&text) {
                out.errors.push(text);
            }
        }

        // The visible area of a tile is its 64 × 64 square intersected with the surface — the
        // bottom row of this 1280 × 800 surface covers 32 of its 64 lines.
        for key in &seen {
            let (tx, ty) = (u64::from(key.0) * 64, u64::from(key.1) * 64);
            let vw = (tx + 64).min(u64::from(entry.width)) - tx;
            let vh = (ty + 64).min(u64::from(entry.height)) - ty;
            match covered.get(key).copied().unwrap_or(0) {
                0 => out.tiles_excluded += 1,
                n if n == vw * vh => out.tiles_unclipped += 1,
                _ => out.tiles_clipped += 1,
            }
        }
    }
    out
}

/// The counterfactual: the same corpus decoded through the same tile decoder, but blitting each
/// tile whole — the policy the pre-#171 client applies at `justrdp/src/egfx.rs`'s WTS2 arm.
/// Deliberately built from [`SurfaceStore`] directly rather than from a flag on [`Progressive`],
/// so the assembled decoder never grows a switch whose only caller is a test.
fn replay_unclipped(entries: &[Entry], canvas: &mut Canvas) {
    let mut store = SurfaceStore::new();
    let mut scratch = Scratch::new();
    let mut rgba = vec![0u8; TILE_RGBA_LEN];

    for entry in entries {
        let messages = progressive::decode_all(&entry.data).expect("corpus payload must parse");
        let order = order_payload(&messages);
        let grid = store.grid_mut(CORPUS_SURFACE_ID, entry.width, entry.height);
        for region in order.regions {
            for tile in &region.tiles {
                let (x_idx, y_idx, result) = match tile {
                    ProgressiveTile::Simple(t) | ProgressiveTile::First(t) => (
                        t.x_idx,
                        t.y_idx,
                        grid.decode_first(t, region, &mut scratch, &mut rgba),
                    ),
                    ProgressiveTile::Upgrade(t) => (
                        t.x_idx,
                        t.y_idx,
                        grid.decode_upgrade(t, region, &mut scratch, &mut rgba),
                    ),
                };
                if result.is_err() {
                    continue;
                }
                let (x, y) = (usize::from(x_idx) * 64, usize::from(y_idx) * 64);
                let w = (x + 64).min(canvas.width) - x;
                let h = (y + 64).min(canvas.height) - y;
                canvas.blit((x, y), (w, h), &rgba, (0, 0));
            }
        }
    }
}

/// The gate: the assembled pipeline is total over the real server's session.
///
/// Acceptance and shape, not values — the capture carries no expected pixels. What it can
/// prove is that parse → order → multi-pass decode → clip → paint runs end to end over every
/// byte this server sent, rejecting nothing and painting something.
#[test]
fn the_whole_session_assembles_without_rejecting_a_tile() {
    let entries = load_replay();
    let mut canvas = Canvas::new(1280, 800);
    let out = replay_assembled(&entries, &mut canvas);

    assert_eq!(out.payloads, 52, "the corpus is 52 payloads");
    assert_eq!(
        out.tiles_decoded, 6193,
        "2943 first passes + 3250 upgrades, the census #169 pinned"
    );
    assert_eq!(
        (out.tiles_skipped, out.fatals, &out.errors[..]),
        (0, 0, &[][..]),
        "no real tile is rejected and no real payload is fatally mis-ordered"
    );
    assert!(
        out.anomalies.is_empty(),
        "no real payload trips a tolerated ordering rule either: {:?}",
        out.anomalies
    );

    // Painting something is a separate claim from decoding something, and it is the one a
    // clipping bug breaks. Alpha is unconditionally 255, so RGB is what can be black.
    let lit = canvas
        .rgba
        .chunks_exact(4)
        .filter(|px| px[..3].iter().any(|&b| b != 0))
        .count();
    assert!(
        lit > 500_000,
        "the replayed desktop should be mostly non-black, got {lit} of 1024000 lit pixels"
    );
}

/// The census, so the corpus cannot rot silently into "clipping is never exercised".
///
/// Region rects on this server are 64-tall bands, one per tile row, of varying width (the
/// narrowest measured is 20 px) — so a tile at a band's edge is genuinely cut, and 14.7% of
/// them are.
#[test]
fn the_corpus_actually_exercises_the_clip() {
    let entries = load_replay();
    let mut canvas = Canvas::new(1280, 800);
    let out = replay_assembled(&entries, &mut canvas);

    assert_eq!(
        (out.tiles_unclipped, out.tiles_clipped, out.tiles_excluded),
        (5284, 909, 0),
        "measured 2026-08-19: 909 of 6193 tiles are cut by their region's rects, none excluded"
    );
    assert_eq!(
        out.rects_painted, 7095,
        "a clipped tile can meet more than one rect, so rects outnumber tiles"
    );
    assert_eq!(
        out.painted_pixels, 23_332_184,
        "pixels the region rects actually declared damaged"
    );
    // The unclipped counterfactual paints every visible tile pixel; the ratio is the cost of
    // getting this seam wrong, expressed as work the host would redraw for nothing.
    assert_eq!(
        24_848_384 - out.painted_pixels,
        1_516_200,
        "blitting whole tiles would paint 6.10% more pixels than the server declared damaged"
    );
}

/// **The discriminating test for this slice's one real design decision.**
///
/// Turning the clip off is not a performance regression, it is a different picture: the two
/// policies leave 57 386 of the surface's 1 024 000 pixels different after the same 52
/// payloads. Asserted rather than described, because "clipping is only about dirty rects" is
/// the plausible-and-wrong belief this number refutes.
#[test]
fn clipping_to_the_region_rects_changes_the_picture_not_only_the_dirty_rect() {
    let entries = load_replay();

    let mut clipped = Canvas::new(1280, 800);
    replay_assembled(&entries, &mut clipped);

    let mut unclipped = Canvas::new(1280, 800);
    replay_unclipped(&entries, &mut unclipped);

    let differing = clipped.pixels_differing_from(&unclipped);
    assert_eq!(
        differing, 57_386,
        "the clip is load-bearing: it decides 5.6% of the final surface"
    );

    // Both policies reach every pixel, so the difference is content and not coverage — which
    // is what rules out "the clipped run simply painted less".
    for canvas in [&clipped, &unclipped] {
        assert!(
            canvas.rgba.chunks_exact(4).all(|px| px[3] == 255),
            "every pixel of the surface is painted under both policies"
        );
    }
}

/// **Decoding and presenting are separate, and a real payload proves it.** A fatal ordering
/// violation appended to the corpus' opening payload must still seed the store — the region
/// before the violation is well-formed and its coefficients are what the next payload refines —
/// while painting nothing at all.
///
/// FreeRDP's shape exactly: its `goto fail` skips `update_tiles` and leaves `rc = 1`
/// (`progressive.c:2482-2486`), so the payload reports success and the frame is not presented.
/// Built by appending a second `FRAME_BEGIN` to real bytes rather than by hand-rolling a
/// region, because a synthetic region would prove the suppression over a payload that had
/// nothing to paint anyway — which is the vacuous version of this test.
#[test]
fn a_fatal_ordering_violation_still_seeds_the_store_but_paints_nothing() {
    let entries = load_replay();
    let mut stream = entries[0].data.clone();
    // blockType = RFX_PROGRESSIVE_FRAME_BEGIN, blockLen = 6 + 6, frameIndex = 0, regionCount = 1.
    stream.extend_from_slice(&0xCCC1u16.to_le_bytes());
    stream.extend_from_slice(&12u32.to_le_bytes());
    stream.extend_from_slice(&0u32.to_le_bytes());
    stream.extend_from_slice(&1u16.to_le_bytes());

    let mut decoder = Progressive::new();
    let outcome = decoder
        .decode(
            CORPUS_SURFACE_ID,
            entries[0].width,
            entries[0].height,
            &stream,
            |_| panic!("a payload whose ordering is fatal must never reach the sink"),
        )
        .expect("the stream still parses — the violation is in the ordering, not the bytes");

    assert!(
        outcome.fatal.is_some(),
        "the appended FRAME_BEGIN is one of the two violations FreeRDP refuses to continue past"
    );
    assert_eq!(outcome.rects_painted, 0);
    assert!(
        outcome.tiles_decoded > 0,
        "the region before the violation still decodes into the store"
    );
    assert_eq!(
        decoder.painted_tiles(),
        outcome.tiles_decoded,
        "and every one of those tiles is now refinable by the next payload"
    );
}

/// Replaying the same bytes twice must produce the same pixels — and the same pixels as
/// yesterday.
///
/// Determinism alone is self-consistency, and self-consistency is what
/// `docs/map/invariant/a-later-stage-can-hide-an-earlier-defect.md` warns cannot see a value
/// change: a decoder that scrambled every tile's source offset would still be perfectly
/// deterministic. Pinning the surface closes the one gap the counters leave — a defect that
/// preserves rect geometry and pixel *counts* while moving the content, which is exactly what a
/// wrong `src_x`/`src_y` is.
///
/// **When this hash moves**, the change is in the assembly, in the tile decode, or in a
/// transform below it; the neighbouring tests localise which. It is not a number to update
/// until that question is answered.
#[test]
fn the_assembled_surface_is_deterministic_and_pinned() {
    let entries = load_replay();
    let mut first = Canvas::new(1280, 800);
    replay_assembled(&entries, &mut first);
    let mut second = Canvas::new(1280, 800);
    replay_assembled(&entries, &mut second);
    assert_eq!(first.pixels_differing_from(&second), 0, "not deterministic");

    // FNV-1a over the whole surface, in raster order.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in &first.rgba {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    assert_eq!(
        hash, 3_942_531_376_082_079_810,
        "the assembled surface changed — see this test's doc before touching the number"
    );
}

/// The whole session lives in **one** surface store, and its cost is the 3× multiplier #169
/// measured rather than a number this slice re-derives.
#[test]
fn the_store_stays_one_surface_and_its_cost_is_accounted() {
    let entries = load_replay();
    let mut decoder = Progressive::new();
    for entry in &entries {
        decoder
            .decode(
                CORPUS_SURFACE_ID,
                entry.width,
                entry.height,
                &entry.data,
                |_| {},
            )
            .expect("payload decodes");
    }
    assert_eq!(decoder.live_surfaces(), 1, "24 context ids, one surface");
    // 1280 × 800 is a 20 × 13 grid; the session paints all 260 of them.
    assert_eq!(decoder.painted_tiles(), 260);
    assert_eq!(
        decoder.store_bytes(),
        260 * 49_152,
        "48 KiB per painted tile — 12.2 MiB against 4 MiB of framebuffer"
    );
}

/// The budget is a **skip**, not a payload failure: a store that is full must not cost the
/// tiles it already holds, and the session must keep decoding upgrades for them.
///
/// Sized to admit the first 64 tiles and refuse the rest, so the same corpus exercises both
/// sides of the branch in one run.
#[test]
fn a_full_store_skips_new_tiles_and_keeps_refining_the_ones_it_has() {
    let entries = load_replay();
    let mut decoder = Progressive::with_store_budget(64 * 49_152);
    let (mut decoded, mut skipped) = (0usize, 0usize);
    let mut painted = 0u64;

    for entry in &entries {
        let outcome = decoder
            .decode(
                CORPUS_SURFACE_ID,
                entry.width,
                entry.height,
                &entry.data,
                |rect| painted += u64::from(rect.width) * u64::from(rect.height),
            )
            .expect("a full store is not a payload failure");
        decoded += outcome.tiles_decoded;
        skipped += outcome.tiles_skipped;
    }

    assert_eq!(
        decoder.painted_tiles(),
        64,
        "the budget is honoured exactly"
    );
    assert!(skipped > 0, "the corpus wants more than 64 tiles");
    assert!(
        decoded > 64,
        "upgrades for the admitted tiles keep decoding after the store fills: {decoded}"
    );
    assert!(painted > 0, "and they keep painting");
}
