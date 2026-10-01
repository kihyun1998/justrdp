#![no_main]
//! Fuzz the Set Error Info body (issue #354). Sibling of errinfo's
//! `decode_set_error_info_never_panics_on_arbitrary_input` proptest.

use libfuzzer_sys::fuzz_target;
use justrdp_pdu::cursor::ReadCursor;

fuzz_target!(|data: &[u8]| {
    let mut cur = ReadCursor::new(data, "fuzz error info");
    let _ = justrdp_pdu::errinfo::decode_set_error_info(&mut cur);
});
