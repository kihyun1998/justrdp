#![no_main]
//! Fuzz the XCRUSH (RDP 6.1) bulk decompressor (#456): both levels, the chained MPPC included.
//!
//! The first byte is the packets' outer compression flags; the rest is split into packets on one
//! decompressor, so both histories and the poison state carry from one packet to the next.

use justrdp_codecs::xcrush::Xcrush;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let mut xcrush = Xcrush::new();
    for packet in rest.chunks(131) {
        let _ = xcrush.decompress(packet, flags);
    }
});
