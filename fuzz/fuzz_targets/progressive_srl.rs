#![no_main]
//! Fuzz the RemoteFX Progressive upgrade-pass entropy decoder (issue #99, epic #158 slice 2).
//! Sibling of `rfx::srl`'s `upgrade_component_never_panics_on_arbitrary_input` proptest.
//!
//! Distinct from the `progressive` target, which drives the block-stream *parser*: this one
//! starts where that one stops, at the two per-component bit streams a parsed `UpgradeTile`
//! hands over. Both streams are attacker-controlled, and so are the quant nibbles that become
//! `shift` and `num_bits` — the parser bounds their table *index*, not their value.
//!
//! A derived `Input` rather than a bare `&[u8]`, following `rfx.rs`: the decoder takes four
//! separate inputs and splitting one byte slice into them by hand would spend the mutator's
//! budget on the split rather than on the grammar.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

use justrdp_codecs::rfx::quant::COMPONENT_LEN;
use justrdp_pdu::rfx::progressive::ProgressiveQuant;

/// `shift` and `width` are the ten per-band nibbles of a `RFX_COMPONENT_CODEC_QUANT`, and they
/// are handed over **unmasked**. The parser can only produce 0..=15, but `ProgressiveQuant`'s
/// fields are plain `pub u8`, so the guarantee is the parser's and not the type's — and masking
/// here would make this target unable to reach the class of defect the #168 completeness pass
/// found by hand (a shift overflow at `num_bits >= 32`).
#[derive(Arbitrary, Debug)]
struct Input {
    srl: Vec<u8>,
    raw: Vec<u8>,
    shift: [u8; 10],
    width: [u8; 10],
}

fn quant(n: [u8; 10]) -> ProgressiveQuant {
    ProgressiveQuant {
        hl1: n[0],
        lh1: n[1],
        hh1: n[2],
        hl2: n[3],
        lh2: n[4],
        hh2: n[5],
        hl3: n[6],
        lh3: n[7],
        hh3: n[8],
        ll3: n[9],
    }
}

fuzz_target!(|input: Input| {
    let mut current = [0i16; COMPONENT_LEN];
    let mut sign = [0i16; COMPONENT_LEN];
    let _ = justrdp_codecs::rfx::srl::upgrade_component(
        &input.srl,
        &input.raw,
        &quant(input.shift),
        &quant(input.width),
        &mut current,
        &mut sign,
    );
});
