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
//!    too (0 rejections).
//! 2. The `ironrdp-graphics` oracle also accepts every entry, and the self-owned output is
//!    byte-identical to it (ADR-0003 phase-2 acceptance).

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
            .as_chunks::<4>()
            .0
            .iter()
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
/// `ironrdp-graphics` oracle, each stateful. Both accept every entry, and the outputs are
/// byte-identical (ADR-0003 phase-2 acceptance).
#[test]
fn self_owned_matches_oracle_on_every_entry() {
    let entries = load_replay();
    assert!(!entries.is_empty(), "the replay corpus is empty");

    let mut mine = ClearDecoder::new();
    let mut oracle = ironrdp_graphics::clearcodec::ClearCodecDecoder::new();

    for (i, e) in entries.iter().enumerate() {
        let ours = mine
            .decode(&e.data, e.width, e.height)
            .unwrap_or_else(|err| panic!("entry {i}: self-owned decoder rejected it: {err}"));
        let theirs = oracle
            .decode(&e.data, e.width, e.height)
            .unwrap_or_else(|err| panic!("entry {i}: oracle rejected it: {err}"));
        assert_eq!(
            ours, theirs,
            "entry {i} ({}x{}): self-owned BGRA differs from the oracle",
            e.width, e.height
        );
    }
}
