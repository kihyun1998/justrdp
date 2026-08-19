#![no_main]
//! Fuzz the zgfx (RDP8 bulk) decompressor — the outermost decoder on the EGFX path, which
//! every server byte on `Microsoft::Windows::RDS::Graphics` crosses before
//! `justrdp_pdu::egfx::decode_all` (the sibling `egfx` target) sees a command. It had no
//! coverage of either kind until #189, while the `ironrdp-graphics` decompressor it replaced
//! panicked on five of seven hand-crafted messages.
//!
//! Two entry points per case. The undirected one is the real message surface; the directed one
//! prefixes a valid single compressed-segment header, because a descriptor byte and a
//! compression-type nibble gate the token decoder behind 1-in-2048 of random prefixes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_codecs::zgfx::Zgfx::new().decompress(data);

    let mut wrapped = vec![0xE0, 0x24];
    wrapped.extend_from_slice(data);
    let _ = justrdp_codecs::zgfx::Zgfx::new().decompress(&wrapped);
});
