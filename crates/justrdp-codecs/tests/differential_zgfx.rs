//! zgfx differential oracle (ADR-0003 phase 2 / ADR-0007): the same `RDP_SEGMENTED_DATA`
//! bytes into `justrdp_codecs::zgfx` and into `ironrdp_graphics::zgfx`, asserting the decoded
//! `Vec<u8>` is byte-identical — and, because zgfx's state spans messages, asserting it over
//! **sequences** rather than one message at a time.
//!
//! What this instrument is and is not. `ironrdp-graphics` shares this project's code lineage
//! ([`oracle-agreement-is-not-independence`](../../../docs/map/invariant/oracle-agreement-is-not-independence.md)),
//! so agreement here is breadth, not independence. The independent expectation lives in
//! `src/zgfx.rs`'s unit tests: the `[MS-RDPEGFX]` sample that FreeRDP and `ironrdp-graphics`
//! reproduce identically, which is the basis ADR-0011 asks for. This file's job is the input
//! space that basis cannot cover — thousands of generated streams, and the history window
//! carrying across them.
//!
//! **The oracle's compressor is not a conforming encoder**, which bounds what can be compared:
//! `wrap_compressed` puts an entire compressed stream in one segment whatever it decompresses
//! to, while `[MS-RDPEGFX]` 3.1.8.1 caps a single segment at 65535 uncompressed bytes and
//! FreeRDP enforces that as a fixed `OutputBuffer[65536]`. Compressed payloads here therefore
//! stay under that ceiling; the divergence itself is pinned by
//! `a_single_segment_expanding_past_the_spec_ceiling_is_refused` below rather than left
//! implicit.

use ironrdp_graphics::zgfx::{CompressionMode, Compressor, Decompressor, compress_and_wrap_egfx};
use justrdp_codecs::zgfx::{Zgfx, ZgfxError};

/// Decode one message with both decoders and assert they agree with each other *and* with the
/// bytes that were compressed. Threaded through both stateful decoders so the caller's
/// sequence is what is being tested.
fn agree(ours: &mut Zgfx, theirs: &mut Decompressor, wire: &[u8], expected: &[u8]) {
    let mine = ours
        .decompress(wire)
        .expect("our decoder accepts the stream");
    let mut oracle = Vec::new();
    theirs
        .decompress(wire, &mut oracle)
        .expect("the oracle accepts the stream");
    assert_eq!(mine, oracle, "our decode differs from the oracle's");
    assert_eq!(mine, expected, "both decoders agree on the wrong bytes");
}

/// A deterministic byte source with tunable repetition, so a payload can be steered from
/// "incompressible" (every token a literal) to "one long match".
fn payload(seed: u64, len: usize, alphabet: u8) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            u8::try_from((state >> 33) % u64::from(alphabet.max(1))).expect("modulo a u8")
        })
        .collect()
}

#[test]
fn a_compressed_stream_decodes_identically_to_the_oracle() {
    // One compressor and one pair of decoders across many messages: the compressor's history
    // grows, so later messages carry matches pointing into earlier ones. That is the property
    // a per-message corpus structurally cannot exercise.
    let mut compressor = Compressor::new();
    let mut ours = Zgfx::new();
    let mut theirs = Decompressor::new();

    for i in 0..64u64 {
        // Vary compressibility: a 4-symbol alphabet is nearly all matches, a 251-symbol one is
        // nearly all literals, and the sizes cross the 3-byte minimum match length.
        let alphabet = if i % 3 == 0 { 4 } else { 251 };
        let len = usize::try_from(1 + (i * 37) % 900).expect("small");
        let data = payload(i, len, alphabet);
        let wire = compress_and_wrap_egfx(&data, &mut compressor, CompressionMode::Always)
            .expect("the oracle compresses");
        agree(&mut ours, &mut theirs, &wire, &data);
    }
}

#[test]
fn every_compression_mode_decodes_identically_to_the_oracle() {
    for mode in [
        CompressionMode::Never,
        CompressionMode::Auto,
        CompressionMode::Always,
    ] {
        let mut compressor = Compressor::new();
        let mut ours = Zgfx::new();
        let mut theirs = Decompressor::new();
        for i in 0..16u64 {
            let data = payload(i + 1000, 400, if i % 2 == 0 { 8 } else { 200 });
            let wire =
                compress_and_wrap_egfx(&data, &mut compressor, mode).expect("the oracle wraps");
            agree(&mut ours, &mut theirs, &wire, &data);
        }
    }
}

#[test]
fn a_multipart_message_past_the_single_segment_limit_decodes_identically() {
    // `wrap_uncompressed` splits at 65535 bytes, so this is the real multipart framing —
    // segmentCount, uncompressedSize, and a per-segment size prefix — rather than the
    // hand-built one in the unit tests.
    let data = payload(7, 150_000, 64);
    let wire = ironrdp_graphics::zgfx::wrap_uncompressed(&data);
    assert_eq!(wire[0], 0xE1, "the fixture is a multipart message");
    agree(&mut Zgfx::new(), &mut Decompressor::new(), &wire, &data);
}

#[test]
fn a_long_run_decodes_identically_to_the_oracle() {
    // A single repeated byte is the overlapping-match extreme: the encoder emits a small
    // distance and a large length, and the decoder's output feeds its own input.
    let data = vec![0x5A; 40_000];
    let mut compressor = Compressor::new();
    let wire = compress_and_wrap_egfx(&data, &mut compressor, CompressionMode::Always)
        .expect("the oracle compresses");
    agree(&mut Zgfx::new(), &mut Decompressor::new(), &wire, &data);
}

#[test]
fn a_message_boundary_is_not_a_history_boundary() {
    // The decisive sequence test: message 2 is *the same bytes* as message 1, so a conforming
    // encoder codes it almost entirely as matches into message 1's history. Decoding message 2
    // alone against a fresh window cannot reproduce it — which is the assertion below.
    let data = payload(99, 800, 32);
    let mut compressor = Compressor::new();
    let first = compress_and_wrap_egfx(&data, &mut compressor, CompressionMode::Always).unwrap();
    let second = compress_and_wrap_egfx(&data, &mut compressor, CompressionMode::Always).unwrap();
    assert!(
        second.len() * 4 < first.len(),
        "the second message should be mostly back-references: {} vs {}",
        second.len(),
        first.len()
    );

    let mut ours = Zgfx::new();
    let mut theirs = Decompressor::new();
    agree(&mut ours, &mut theirs, &first, &data);
    agree(&mut ours, &mut theirs, &second, &data);

    // Same bytes, fresh window: the length is right and the content is not.
    let cold = Zgfx::new().decompress(&second).expect("still well-formed");
    assert_eq!(cold.len(), data.len());
    assert_ne!(
        cold, data,
        "the history window is what makes message 2 mean anything"
    );
}

#[test]
fn a_single_segment_expanding_past_the_spec_ceiling_is_refused() {
    // `[MS-RDPEGFX]` 3.1.8.1 caps a segment at 65535 uncompressed bytes and FreeRDP enforces
    // it; the oracle's compressor does not, so it can wrap a 150 KB payload into one segment.
    // We refuse it, which is a divergence from the *oracle's encoder*, not from the spec.
    let data = vec![0xC3; 150_000];
    let mut compressor = Compressor::new();
    let wire = compress_and_wrap_egfx(&data, &mut compressor, CompressionMode::Always).unwrap();
    assert_eq!(wire[0], 0xE0, "the oracle wrapped it as a single segment");
    assert_eq!(wire[1], 0x24, "...and marked it compressed");

    assert_eq!(
        Zgfx::new().decompress(&wire),
        Err(ZgfxError::SegmentOutputTooLarge)
    );
    // The oracle decodes it, so this is a real difference in behaviour and not a bad fixture.
    let mut oracle_out = Vec::new();
    Decompressor::new()
        .decompress(&wire, &mut oracle_out)
        .expect("the oracle has no output bound at all");
    assert_eq!(oracle_out.len(), 150_000);
}
