#![no_main]
//! Fuzz the fast-path update parser (issue #99). Sibling of fastpath's
//! `decode_updates_never_panics` proptest. `decode_updates` splits a fast-path output frame into
//! its update PDUs, every length server-supplied.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `frame_len` and `is_fastpath` re-parse the header `decode_updates` re-parses, and until
    // #230 nothing drove either -- an unchecked read injected into `frame_len` left the whole
    // workspace suite green. Both are cheap enough to run on every input.
    if let Some(&first) = data.first() {
        let _ = justrdp_pdu::fastpath::is_fastpath(first);
    }
    let _ = justrdp_pdu::fastpath::frame_len(data);
    let _ = justrdp_pdu::fastpath::decode_updates(data);
});
