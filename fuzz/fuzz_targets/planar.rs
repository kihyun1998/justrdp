#![no_main]
//! Fuzz the RDP6 planar decoder (issue #99). Sibling of planar's `decompress_never_panics`
//! proptest. FreeRDP took an OOB read here (CVE-2024-32458, `planar_skip_plane_rle`).

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

/// `width`/`height` are bounded (u8) — they come from fixed u16 `TS_BITMAP_DATA` header fields,
/// not the stream; `src` (header byte + plane data) is the attacker-controlled surface.
#[derive(Arbitrary, Debug)]
struct Input {
    width: u8,
    height: u8,
    src: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let _ = justrdp_codecs::planar::decompress(
        &input.src,
        usize::from(input.width),
        usize::from(input.height),
    );
});
