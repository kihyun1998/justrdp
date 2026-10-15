#![no_main]
//! Fuzz the NCRUSH (RDP 6.0) bulk decompressor (#455): the Huffman decode, the offset cache and
//! the history slide.
//!
//! The first byte is the packets' compression flags; the rest is split into packets on one
//! decompressor, so the history, the offset cache and the poison state carry from one packet to
//! the next.

use justrdp_codecs::ncrush::Ncrush;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let mut ncrush = Ncrush::new();
    for packet in rest.chunks(113) {
        let _ = ncrush.decompress(packet, flags);
    }
});
