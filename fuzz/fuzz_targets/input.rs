#![no_main]
//! Fuzz the Set Keyboard Indicators body (issue #354), the one server-to-client parser in
//! `justrdp_pdu::input`. Sibling of input's
//! `keyboard_indicators_decode_never_panics_on_arbitrary_input` proptest.

use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::input::KeyboardIndicators;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cur = ReadCursor::new(data, "fuzz keyboard indicators");
    let _ = KeyboardIndicators::decode(&mut cur);
});
