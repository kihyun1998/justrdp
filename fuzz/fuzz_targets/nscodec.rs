#![no_main]
//! Fuzz the NSCodec RLE plane decoder (epic #132 / issue #138). Sibling of the
//! `decode_plane_never_panics` proptest — same entry point, but libFuzzer's `-timeout` also catches
//! hangs, and coverage guidance reaches the run/literal/tail paths random bytes miss. The NSCodec
//! plane RLE is bounds-critical: the plane bytes are the untrusted, attacker-controlled surface.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

/// `original_size` is bounded (the real plane size is width×height from fixed geometry, never the
/// stream), so the output allocation stays small and the fuzzer spends its budget on the compressed
/// `plane` bytes.
#[derive(Arbitrary, Debug)]
struct Input {
    original_size: u16,
    plane: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let _ = justrdp_codecs::nscodec::decode_plane(&input.plane, usize::from(input.original_size));
});
