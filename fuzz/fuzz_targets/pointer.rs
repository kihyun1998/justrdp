#![no_main]
//! Fuzz the pointer-shape decoder (issue #99). Sibling of pointer's
//! `decode_pointer_never_panics` proptest. Both masks must match the stride x height the header
//! implies, but nothing stops a server from lying — so they are the attacker-controlled surface.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use justrdp_codecs::color::Palette;

/// `width`/`height`/`xor_bpp` come from fixed u16 `TS_*POINTERATTRIBUTE` header fields (bounded
/// here); `xor`/`and` are the unbounded mask blobs. `bpp_sel` indexes the five real depths. The
/// palette is the fixed session default — pointer shapes carry none of their own.
#[derive(Arbitrary, Debug)]
struct Input {
    width: u8,
    height: u8,
    bpp_sel: u8,
    xor: Vec<u8>,
    and: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let xor_bpp = [1u16, 8, 16, 24, 32][(input.bpp_sel % 5) as usize];
    let _ = justrdp_codecs::pointer::decode_pointer(
        u16::from(input.width),
        u16::from(input.height),
        xor_bpp,
        &input.xor,
        &input.and,
        &Palette::default(),
    );
});
