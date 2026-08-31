#![no_main]
//! Fuzz the NSCodec RLE plane decoder (epic #132 / issue #138). Sibling of the
//! `decode_plane_never_panics` proptest — same entry point, but libFuzzer's `-timeout` also catches
//! hangs, and coverage guidance reaches the run/literal/tail paths random bytes miss. The NSCodec
//! plane RLE is bounds-critical: the plane bytes are the untrusted, attacker-controlled surface.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

/// `original_size` is bounded so the output allocation stays small and the fuzzer spends its
/// budget on the compressed `plane` bytes.
///
/// **A budget trade, stated as one.** The parenthetical it used to carry — *"the real plane size
/// is width×height from fixed geometry, never the stream"* — is retracted (#263, ADR-0008
/// amendment 2026-08-31): the geometry comes off the wire like everything else, and
/// `decode_plane` takes a `usize`. A `u16` here is already the widest value this lane can
/// usefully drive — it runs 64-bit, where nothing in this arithmetic overflows.
#[derive(Arbitrary, Debug)]
struct Input {
    original_size: u16,
    plane: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let _ = justrdp_codecs::nscodec::decode_plane(&input.plane, usize::from(input.original_size));
});
