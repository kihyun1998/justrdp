//! Replay + differential anchor over the real-VM ClearCodec corpus (issue #56).
//!
//! `fixtures/clearcodec/replay.bin` is one full session's worth of genuine `CODECID_CLEARCODEC`
//! payloads captured from the test VM, **in arrival order** (see the README). Order matters:
//! ClearCodec is stateful (the V-bar and glyph caches span PDUs), so a cache-hit stream only
//! resolves when the earlier streams that populated those entries are replayed first. Decoding a
//! single captured payload in isolation would spuriously miss the cache — these tests replay the
//! whole sequence through one decoder, the way the live session does.
//!
//! Two properties are asserted:
//!
//! 1. The self-owned decoder replays the entire capture without error — the live session does
//!    too (0 rejections), whereas the bootstrap oracle rejects a large fraction.
//! 2. Where the oracle *succeeds*, the self-owned output is byte-identical (ADR-0003 phase-2
//!    acceptance); where the oracle *rejects* with one of its three defective validations, the
//!    self-owned decoder produces pixels instead.

use justrdp_codecs::clearcodec::ClearDecoder;

/// One captured payload with the destination-rectangle dimensions it was decoded against.
struct Entry {
    width: u16,
    height: u16,
    data: Vec<u8>,
}

fn load_replay() -> Vec<Entry> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/clearcodec/replay.bin");
    let buf = std::fs::read(path).expect("the ClearCodec replay corpus must be present");

    let mut entries = Vec::new();
    let count = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let mut pos = 4usize;
    for _ in 0..count {
        let width = u16::from_le_bytes(buf[pos..pos + 2].try_into().unwrap());
        let height = u16::from_le_bytes(buf[pos + 2..pos + 4].try_into().unwrap());
        let len = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        entries.push(Entry {
            width,
            height,
            data: buf[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    entries
}

#[test]
fn corpus_is_present_and_non_trivial() {
    let entries = load_replay();
    assert!(
        entries.len() >= 8,
        "replay corpus is suspiciously small ({} entries)",
        entries.len()
    );
}

/// The headline #56 result: the self-owned decoder replays the full captured session without a
/// single rejection — reproducing, VM-free, what the live capture observed.
///
/// This is also the **no-holes** proof. A Clear-region hole arises only when a stream fails to
/// decode and the core's warn-and-skip policy leaves the region un-painted; zero rejections
/// across the whole capture means zero skips, hence no holes. (Per-pixel blackness cannot stand
/// in for "hole" — a single-entry black palette is legitimate all-black content, e.g. entry 0.)
/// The aggregate non-black tally guards the converse: that the decoder genuinely paints content
/// rather than silently returning zeroed buffers.
#[test]
fn self_owned_replays_full_capture_without_error() {
    let mut decoder = ClearDecoder::new();
    let mut nonblack_total = 0usize;
    for (i, e) in load_replay().iter().enumerate() {
        let out = decoder
            .decode(&e.data, e.width, e.height)
            .unwrap_or_else(|err| {
                panic!(
                    "entry {i} ({}x{}) failed to decode: {err}",
                    e.width, e.height
                )
            });
        assert_eq!(
            out.len(),
            usize::from(e.width) * usize::from(e.height) * 4,
            "entry {i} decoded to the wrong BGRA size"
        );
        nonblack_total += out
            .chunks_exact(4)
            .filter(|px| px[0] != 0 || px[1] != 0 || px[2] != 0)
            .count();
    }
    assert!(
        nonblack_total > 1000,
        "the whole capture decoded to (near-)black ({nonblack_total} non-black px) — the decoder \
         is not painting real content"
    );
}

/// Differential acceptance: feed the ordered sequence to both the self-owned decoder and the
/// `ironrdp-graphics` oracle, each stateful. Where the oracle succeeds, outputs must be
/// byte-identical; where it rejects (its three defective validations), the self-owned decoder
/// must succeed. Asserts the corpus actually exercises the oracle's defects (rejections > 0) and
/// that all three rejection signatures appear, so the fix is genuinely covered.
#[test]
fn self_owned_matches_oracle_where_oracle_succeeds() {
    let entries = load_replay();

    let mut mine = ClearDecoder::new();
    let mut oracle = ironrdp_graphics::clearcodec::ClearCodecDecoder::new();

    let mut oracle_rejections = 0usize;
    let mut saw_short_vbar = false;
    let mut saw_rlex = false;
    let mut saw_vbar_index = false;

    for (i, e) in entries.iter().enumerate() {
        let ours = mine.decode(&e.data, e.width, e.height);
        let theirs = oracle.decode(&e.data, e.width, e.height);

        match theirs {
            Ok(theirs) => {
                let ours = ours.unwrap_or_else(|err| {
                    panic!("entry {i}: self-owned failed where oracle succeeded: {err}")
                });
                assert_eq!(
                    ours, theirs,
                    "entry {i} ({}x{}): self-owned BGRA differs from the oracle on a stream both accept",
                    e.width, e.height
                );
            }
            Err(err) => {
                oracle_rejections += 1;
                let msg = err.to_string();
                if msg.contains("shortVBarCacheMiss") {
                    saw_short_vbar = true;
                }
                if msg.contains("rlex") {
                    saw_rlex = true;
                }
                if msg.contains("vbarIndex") {
                    saw_vbar_index = true;
                }
                assert!(
                    ours.is_ok(),
                    "entry {i}: oracle rejected ({msg}) and the self-owned decoder did too"
                );
            }
        }
    }

    assert!(
        oracle_rejections > 0,
        "corpus never triggered an oracle rejection — it does not exercise the #56 fix"
    );
    assert!(
        saw_short_vbar && saw_rlex && saw_vbar_index,
        "corpus is missing a signature (shortVBarCacheMiss={saw_short_vbar}, rlex={saw_rlex}, vbarIndex={saw_vbar_index})"
    );
}
