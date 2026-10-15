#![no_main]
//! Fuzz the MPPC bulk decompressor (#454) — every compressed fast-path update and slow-path
//! Share Data crosses it before the session decodes a single PDU.
//!
//! The first byte picks the level and the compression flags; the rest is split into packets on
//! one decompressor, so the history and the poison state carry from one packet to the next.

use justrdp_codecs::mppc::{Mppc, MppcLevel};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&head, rest)) = data.split_first() else {
        return;
    };
    let level = if head & 1 == 0 { MppcLevel::Rdp4 } else { MppcLevel::Rdp5 };
    let mut mppc = Mppc::new(level);
    for packet in rest.chunks(97) {
        let _ = mppc.decompress(packet, head & 0xE0);
    }
});
