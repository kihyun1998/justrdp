#![no_main]
//! Fuzz the fast-path update parser (issue #99). Sibling of fastpath's
//! `decode_updates_never_panics` proptest. `decode_updates` splits a fast-path output frame into
//! its update PDUs, every length server-supplied.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::fastpath::decode_updates(data);
});
