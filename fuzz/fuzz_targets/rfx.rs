#![no_main]
//! Fuzz the RemoteFX WTS1 decoder (issue #99). Sibling of rfx's `decode_to_rgba_never_panics`
//! proptest. `decode_to_rgba` is the top-level entry, so this one target drives the whole inverse
//! pipeline (TS_RFX block parse -> RLGR entropy -> LL3 delta -> dequant -> inverse DWT -> ICT)
//! from raw bytes — the RLGR entropy loop included.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

/// `width`/`height` are bounded (u8, widened to u16); `data` is the attacker-controlled TS_RFX
/// block stream. A fresh decoder per run keeps each case independent of the persisted video-mode
/// verdict.
///
/// **The bound used to be justified as *"they come from fixed u16 destination-rect fields, not
/// the stream"*, and that sentence is false (#263).** A `RDPGFX_RECT16` **is** a stream field:
/// `[MS-RDPEGFX]` 2.2.1.2 bounds it at `u16` and states no maximum, and 2.2.2.1 makes the
/// rectangle the bitmap's own dimensions. The same sentence sat on the sibling proptest and hid
/// a 32-bit overflow there, so it is retracted rather than reworded. What actually bounds these
/// at `u8` is a fuzzing trade — keeping the byte budget on `data`, where the entropy loop is.
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
    let _ = justrdp_codecs::rfx::RemoteFx::new().decode_to_rgba(
        &input.data,
        u16::from(input.width),
        u16::from(input.height),
    );
});
