#![no_main]
//! Fuzz the pointer *PDU* parsers (issue #230) — `justrdp_pdu::pointer`. Sibling of that module's
//! three `*_never_panics_on_arbitrary_input` proptests.
//!
//! ## Why this is not `pointer.rs`, and why the name mattered
//!
//! `fuzz_targets/pointer.rs` already exists and targets `justrdp_codecs::pointer::decode_pointer`.
//! The two modules share a name and are different code, which is exactly how this surface went
//! uncovered: the untrusted-decode invariant derives *what is fuzzed* from `ls fuzz_targets/` and
//! *what parses untrusted bytes* from a walk of `crates/justrdp-pdu/src`, and `pointer` appears in
//! both lists. For `rfx` that match is real — the codec calls the PDU parser — but
//! `decode_pointer` takes `width`, `height`, `xor_bpp` and both masks **already parsed**, so the
//! `TS_*POINTERATTRIBUTE` header parse that produces them was reached by nothing.
//! See `docs/map/invariant/untrusted-decode-never-panics.md`.
//!
//! ## Why it chains into the codec
//!
//! `justrdp::session::on_pointer` decodes the PDU and hands the fields straight to
//! `decode_pointer` (`justrdp/src/session.rs:374`, `:554`), so that composition is the live path
//! and this target drives it whole. It is not redundant with `pointer.rs`: that target generates
//! `width`/`height` as `u8`, while this one reaches the codec only through the parser's own
//! 96-pixel cap and its two `u16` mask lengths — a different slice of `decode_pointer`'s input
//! space, and the one a server can actually produce.
//!
//! ## Why no `Entry` selector
//!
//! `gcc` and `mcs` spend a selector arm per entry point because their parsers are separate
//! grammars. These two are one grammar behind two dispatch headers, and both are cheap, so every
//! input drives both — the same reasoning that puts `DisconnectProviderUltimatum::matches` outside
//! `mcs.rs`'s match. The layout is therefore
//!
//! ```text
//! [1-byte updateCode] ++ [payload, verbatim]
//! ```
//!
//! with `data` a trailing `&[u8]` rather than a `Vec<u8>` for the reason `gcc.rs` records at
//! length: measured against `arbitrary` 1.4.2, a `Vec<u8>` field consumes two bytes per element
//! and a trailing slice takes the remainder verbatim. There is no seeder for this target — the
//! repo commits no captured pointer PDU — so nothing outside this file depends on the layout, but
//! it is stated because the next person to add one will need it.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use justrdp_codecs::color::Palette;
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::pointer::PointerUpdate;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    /// The fast-path `updateCode`. Left fully arbitrary: six values reach a parsing arm and the
    /// rest drive the reject arm, which is a `pub fn`'s behaviour on a byte a server chose.
    code: u8,
    data: &'a [u8],
}

/// What `justrdp::session::on_pointer` does with a decoded shape, minus the cursor cache (which is
/// core state, not a parser). 8-bpp shapes resolve through the session palette; a pointer message
/// carries none of its own, so the session default is the faithful input.
fn blit(update: PointerUpdate) {
    let (xor_bpp, attr) = match update {
        // The Color message is implicitly 24-bpp; New carries its own depth.
        PointerUpdate::Color(attr) => (24, attr),
        PointerUpdate::New { xor_bpp, color } => (xor_bpp, color),
        _ => return,
    };
    let _ = justrdp_codecs::pointer::decode_pointer(
        attr.width,
        attr.height,
        xor_bpp,
        &attr.xor_mask,
        &attr.and_mask,
        &Palette::default(),
    );
}

fuzz_target!(|input: Input<'_>| {
    let mut cur = ReadCursor::new(input.data, "fuzz pointer slow-path");
    if let Ok(update) = PointerUpdate::decode_slowpath(&mut cur) {
        blit(update);
    }

    let mut cur = ReadCursor::new(input.data, "fuzz pointer fast-path");
    if let Ok(update) = PointerUpdate::decode_fastpath(input.code, &mut cur) {
        blit(update);
    }
});
