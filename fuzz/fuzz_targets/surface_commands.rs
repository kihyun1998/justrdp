#![no_main]
//! Fuzz the fast-path Surface Commands parser (issue #150). Sibling of surface_commands'
//! `decode_never_panics_on_arbitrary_input` proptest.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::surface_commands::decode_all(data);
});
