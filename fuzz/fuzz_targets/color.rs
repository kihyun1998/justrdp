#![no_main]
//! Fuzz the slow-path pixel converter (#238). `to_rgba` sizes two buffers from wire dimensions
//! and a wire depth, across the crate boundary that carries none of the parser's constraints —
//! ADR-0012's class, and the member that had neither a property nor a target.
//!
//! `width`/`height` arrive as `u8` widened to `usize` rather than as arbitrary `usize`s: the
//! interesting space here is the per-depth row walk and the `bottom_up` flip, which need a
//! source long enough to actually convert. The overflow guards are driven by the proptest
//! sibling instead, which biases toward the products that wrap — including on i686, where the
//! `overflow-32bit` job runs it and x86-64 structurally cannot.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    width: u8,
    height: u8,
    bits_per_pixel: u16,
    bottom_up: bool,
    data: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let palette = justrdp_codecs::color::Palette::default();
    let _ = justrdp_codecs::color::to_rgba(
        &input.data,
        usize::from(input.width),
        usize::from(input.height),
        input.bits_per_pixel,
        &palette,
        input.bottom_up,
    );
});
