#![no_main]
//! Fuzz the interleaved-RLE decoder (issue #99). Sibling of the `decompress_never_panics`
//! proptest — same entry point, but libFuzzer's `-timeout` also catches hangs, and coverage
//! guidance reaches paths random bytes miss. FreeRDP took an OOB read here (CVE-2024-32460).

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

/// Width/height are bounded (u8) because they arrive from fixed u16 `TS_BITMAP_DATA` header
/// fields, never the stream; keeping them small bounds the output allocation so the fuzzer
/// spends its budget on the compressed `stream`, the real attacker-controlled surface. `bpp_sel`
/// indexes the four real interleaved-RLE depths.
#[derive(Arbitrary, Debug)]
struct Input {
    width: u8,
    height: u8,
    bpp_sel: u8,
    stream: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let bpp = [8u16, 15, 16, 24][(input.bpp_sel & 0x03) as usize];
    let _ = justrdp_codecs::rle::decompress(
        &input.stream,
        usize::from(input.width),
        usize::from(input.height),
        bpp,
    );
});
