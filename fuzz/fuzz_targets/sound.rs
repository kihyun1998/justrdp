#![no_main]
//! Fuzz the Play Sound PDU parser (issue #354). Sibling of sound's
//! `decode_never_panics_on_arbitrary_input` proptest.

use libfuzzer_sys::fuzz_target;
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::sound::PlaySound;

fuzz_target!(|data: &[u8]| {
    let mut cur = ReadCursor::new(data, "fuzz play-sound");
    let _ = PlaySound::decode(&mut cur);
});
