#![no_main]
//! Fuzz the pointer-shape decoder (issue #99). Sibling of pointer's
//! `decode_pointer_never_panics` proptest. Both masks must match the stride x height the header
//! implies, but nothing stops a server from lying — so they are the attacker-controlled surface.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use justrdp_codecs::color::Palette;

/// `width`/`height` are bounded (u8, widened to u16); `xor`/`and` are the unbounded mask blobs.
/// `bpp_sel` indexes the five real depths. The palette is the fixed session default — pointer
/// shapes carry none of their own.
///
/// **The bound used to be justified as *"come from fixed u16 `TS_*POINTERATTRIBUTE` header
/// fields"*, and that is a stream field like every other (#263).** What genuinely bounds the
/// *live path* is a different fact worth naming instead: `decode_fastpath` caps a pointer at 96
/// pixels. `decode_pointer`'s own signature admits `u16`, and at 1 bpp its output is 32x the
/// mask — `decode_pointer(65535, 8500, 1, &[0u8; 69_632_000], &[], ..)` requests
/// 2_228_190_000 bytes and panics on `i686-pc-windows-msvc`, which the exact mask-length gate
/// does not prevent. That is a contract question for the function, not something this target
/// can observe.
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
