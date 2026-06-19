#![no_main]
//! Fuzz the RemoteFX WTS1 decoder (issue #99). Sibling of rfx's `decode_to_rgba_never_panics`
//! proptest. `decode_to_rgba` is the top-level entry, so this one target drives the whole inverse
//! pipeline (TS_RFX block parse -> RLGR entropy -> LL3 delta -> dequant -> inverse DWT -> ICT)
//! from raw bytes — the RLGR entropy loop included.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

/// `width`/`height` are bounded (u8, widened to u16) — they come from fixed u16 destination-rect
/// fields, not the stream; `data` is the attacker-controlled TS_RFX block stream. A fresh decoder
/// per run keeps each case independent of the persisted video-mode verdict.
#[derive(Arbitrary, Debug)]
struct Input {
    width: u8,
    height: u8,
    data: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let _ = justrdp_codecs::rfx::RemoteFx::new().decode_to_rgba(
        &input.data,
        u16::from(input.width),
        u16::from(input.height),
    );
});
