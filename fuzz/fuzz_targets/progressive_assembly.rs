#![no_main]
//! Fuzz the RemoteFX Progressive **assembly layer** (issue #99, epic #158 slice 5 / #171) —
//! the whole `WireToSurface2` path from raw bytes to clipped RGBA rectangles.
//!
//! This is the target `progressive_multipass` said did not yet exist: *"what a fuzzer would add
//! is coverage of the composition, and that composition does not exist until the assembly layer
//! (#171)"*. The three neighbours each drive one layer — `progressive` the block-stream parser,
//! `progressive_srl` one component's upgrade entropy, `progressive_multipass` the cross-pass
//! tile decode against a hand-built region — and none of them reaches:
//!
//! - **the block ordering deciding which regions run.** `order_payload` is a pure function over
//!   a parsed message list, so `progressive_multipass` correctly left it out; here it is
//!   reached through *bytes*, which is the only way its interaction with a malformed stream is
//!   exercised at all.
//! - **the clip arithmetic**, which reads a region's `rects` (server-supplied, `u16`) against a
//!   surface's dimensions (server-supplied at `CREATESURFACE`, and **not** in this stream). Two
//!   independently attacker-controlled sources meeting in one intersection is exactly the shape
//!   `docs/map/invariant/decoder-dimension-overflow-32bit.md` names.
//! - **the store across payloads.** A sequence against one decoder is what reaches an upgrade
//!   applied to a store an earlier payload seeded, the budget refusal, and the grid-replacement
//!   branch when the surface dimensions change under a live store.
//!
//! The sink asserts its own contract, so a rectangle escaping either the tile buffer or the
//! surface is a crash rather than a silent out-of-bounds hand-off to a host that trusts it.
//!
//! # Why this reads its own byte layout instead of deriving `Arbitrary`
//!
//! Because it has to be **seedable**, and #200 measured what happens to a target of this shape
//! that is not: `progressive`, cold, retained 6 inputs totalling 29 bytes from 149M executions,
//! because a magic-plus-nested-lengths grammar is a wall a mutator cannot climb from empty.
//! This target consumes that same grammar, one layer up, so it inherits the same wall.
//!
//! `Arbitrary`'s derived encoding is an implementation detail of that crate — a seeder would
//! have to reproduce it, including the length handling it drives from the *end* of the buffer,
//! and would break silently on a version bump. A layout this file declares can be written by
//! `seed_fuzz_corpus.py` from the committed real-server capture, and the two cannot drift
//! because this comment and that script are the only two places it appears:
//!
//! ```text
//! 0..2   u16 LE   width          ->  clamped up to 1 (0 is not a legal surface)
//! 2..4   u16 LE   height         ->  clamped up to 1
//! 4      u8       flags         ->  bit0 = alternate surface ids, bit1 = resize mid-sequence
//! 5..            payloads       ->  each: u32 LE length, then that many bytes; a truncated
//!                                  final length or body takes whatever remains
//! ```
//!
//! A short input is not rejected — every field falls back to a default, so the mutator is never
//! punished for trimming, which is the behaviour that lets it minimise a crash.

use libfuzzer_sys::fuzz_target;

use justrdp_codecs::rfx::progressive::{Progressive, TILE_RGBA_LEN, TILE_STATE_BYTES};

/// Read the header, then split the rest into length-prefixed payloads.
fn parse(data: &[u8]) -> (u16, u16, u8, Vec<&[u8]>) {
    let u16_at = |i: usize| match (data.get(i), data.get(i + 1)) {
        (Some(&a), Some(&b)) => u16::from_le_bytes([a, b]),
        _ => 0,
    };
    // The full `u16` range on purpose: a real capture is 1280 x 800, and a modulo small enough
    // to look prudent would put the committed seeds *outside* their own grid, so every tile
    // would come back `TileOutsideSurface` and the corpus would prove nothing. Nothing here is
    // sized from the dimensions — `TileGrid` is a `HashMap` and the store has a byte budget —
    // so a 65535-wide surface costs a stride, not an allocation.
    let width = u16_at(0).max(1);
    let height = u16_at(2).max(1);
    let flags = data.get(4).copied().unwrap_or(0);

    let mut payloads = Vec::new();
    let mut pos = 5usize;
    // Bounded so a pathological header cannot turn one case into a timeout; the interesting
    // state (a live store several passes deep) is reached well inside this.
    while pos < data.len() && payloads.len() < 8 {
        let len = match data.get(pos..pos + 4) {
            Some(n) => u32::from_le_bytes([n[0], n[1], n[2], n[3]]) as usize,
            // A truncated length: hand the remainder over rather than dropping it, so a
            // minimised crash keeps its last payload.
            None => {
                payloads.push(&data[pos..]);
                break;
            }
        };
        pos += 4;
        let end = pos.saturating_add(len).min(data.len());
        payloads.push(&data[pos..end]);
        pos = end;
    }
    (width, height, flags, payloads)
}

fuzz_target!(|data: &[u8]| {
    let (width, height, flags, payloads) = parse(data);
    // Tuned against the committed seeds rather than picked: the real session paints 260 tiles,
    // so 64 keeps the budget refusal reachable while still admitting enough of a frame for the
    // clip arithmetic to run. Measured over the 95 seeds, a budget of 8 decodes 672 tiles and 64
    // decodes 4787 -- a seven-fold difference in what the guidance ever sees, for 3 MiB of store.
    let mut decoder = Progressive::with_store_budget(64 * TILE_STATE_BYTES);

    for (i, payload) in payloads.iter().enumerate() {
        let surface_id = if flags & 1 != 0 { (i % 2) as u16 } else { 0 };
        // The grid-replacement branch: a surface whose dimensions change under a live store.
        let (w, h) = if flags & 2 != 0 && i % 2 == 1 {
            (width.saturating_add(64).max(1), height)
        } else {
            (width, height)
        };
        let _ = decoder.decode(surface_id, w, h, payload, |rect| {
            assert_eq!(rect.tile.len(), TILE_RGBA_LEN);
            assert!(usize::from(rect.src_x) + usize::from(rect.width) <= 64);
            assert!(usize::from(rect.src_y) + usize::from(rect.height) <= 64);
            assert!(u32::from(rect.x) + u32::from(rect.width) <= u32::from(w));
            assert!(u32::from(rect.y) + u32::from(rect.height) <= u32::from(h));
        });
    }
});
