#![no_main]
//! Fuzz the EGFX PDU parser (issue #99). Sibling of egfx's `decode_all_never_panics` proptest.
//! `decode_all` walks an arbitrary number of RDPGFX_* blocks out of one payload, every length
//! server-supplied — so the whole input is the attacker-controlled surface.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::egfx::decode_all(data);
});
