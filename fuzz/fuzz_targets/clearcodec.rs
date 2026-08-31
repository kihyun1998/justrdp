#![no_main]
//! Fuzz the ClearCodec decoder (issue #99). Sibling of clearcodec's `decode_never_panics`
//! proptest. ClearCodec is the OOB-CVE hot spot in FreeRDP (CVE-2020-11040 in
//! `clear_decompress_subcode_rlex`, plus later bands/residual/glyphData advisories).

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

/// `width`/`height` are bounded (u8, widened to u16); `data` (flags + glyph/band/subcodec
/// structure) is the attacker surface. A fresh decoder per run keeps each case independent of
/// cache state.
///
/// **The bound used to say *"they come from fixed EGFX wire fields, not the stream"*, which is
/// a contradiction and is retracted (#263):** an EGFX wire field *is* the stream. These arrive
/// from a WireToSurface1 `destRect`, which `[MS-RDPEGFX]` 2.2.1.2 bounds at `u16` with no
/// maximum. The `u8` bound is a fuzzing trade — byte budget spent on `data` — not a claim
/// about what a server may send.
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
    data: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let _ = justrdp_codecs::clearcodec::ClearDecoder::new().decode(
        &input.data,
        u16::from(input.width),
        u16::from(input.height),
    );
});
