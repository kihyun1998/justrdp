#![no_main]
//! Fuzz the Save Session Info body (issue #354). Sibling of session_info's
//! `decode_never_panics_on_arbitrary_input` proptest. Four `infoType` variants, the Extended one
//! with two server-length-framed fields.

use libfuzzer_sys::fuzz_target;
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::session_info::SaveSessionInfo;

fuzz_target!(|data: &[u8]| {
    let mut cur = ReadCursor::new(data, "fuzz save session info");
    let _ = SaveSessionInfo::decode(&mut cur);
});
