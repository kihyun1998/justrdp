#![no_main]
//! Fuzz the two Share headers every session-leg PDU is framed in (issue #354). Sibling of
//! share's two `*_never_panics_on_arbitrary_input` proptests; both entry points take every input,
//! as `finalization.rs` does for its shallow parsers.

use libfuzzer_sys::fuzz_target;
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::share::{ShareControlHeader, ShareDataHeader};

fuzz_target!(|data: &[u8]| {
    let mut cur = ReadCursor::new(data, "fuzz share control");
    let _ = ShareControlHeader::decode(&mut cur);

    let mut cur = ReadCursor::new(data, "fuzz share data");
    let _ = ShareDataHeader::decode(&mut cur);
});
