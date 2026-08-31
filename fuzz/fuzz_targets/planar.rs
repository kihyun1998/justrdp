#![no_main]
//! Fuzz the RDP6 planar decoder (issue #99). Sibling of planar's `decompress_never_panics`
//! proptest. FreeRDP took an OOB read here (CVE-2024-32458, `planar_skip_plane_rle`).

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

/// `width`/`height` are bounded (u8); `src` (header byte + plane data) is the attacker-controlled
/// surface.
///
/// **The bound used to say *"they come from fixed u16 `TS_BITMAP_DATA` header fields, not the
/// stream"*, and it was wrong twice (#263).** A `TS_BITMAP_DATA` header field *is* the stream,
/// and `decompress`'s parameters are `usize`, not `u16`, so nothing about the wire bounds this
/// signature at all — which is exactly the shape
/// [ADR-0012](../../docs/adr/0012-consumption-site-totality.md) §1 is written about. The `u8`
/// bound is a fuzzing trade, byte budget spent on `src`.
///
/// **The generators are deliberately NOT widened here, and the reason is the lane.** This
/// target runs on `ubuntu-latest` (`fuzz.yml`), i.e. 64-bit, where every one of these
/// products fits a `usize` and the dimension reject arm cannot fire at all. Widening would
/// buy zero new reachable behaviour and cost every case a bigger allocation. The 32-bit half
/// is proved where it can be: `overflow-32bit.yml` runs
/// `cargo test -p justrdp-codecs -p justrdp --target i686-pc-windows-msvc`, which is where
/// the proptest siblings and the directed tests live.
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
