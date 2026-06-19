#![no_main]
//! Fuzz the ClearCodec decoder (issue #99). Sibling of clearcodec's `decode_never_panics`
//! proptest. ClearCodec is the OOB-CVE hot spot in FreeRDP (CVE-2020-11040 in
//! `clear_decompress_subcode_rlex`, plus later bands/residual/glyphData advisories).

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

/// `width`/`height` are bounded (u8, widened to u16) — they come from fixed EGFX wire fields,
/// not the stream; `data` (flags + glyph/band/subcodec structure) is the attacker surface. A
/// fresh decoder per run keeps each case independent of cache state.
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
