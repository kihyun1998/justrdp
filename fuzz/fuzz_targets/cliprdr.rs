#![no_main]
//! Fuzz the clipboard PDU parser (#321). Sibling of cliprdr's
//! `decode_never_panics_on_arbitrary_input` proptest.
//!
//! `ClipboardPdu::decode` reads a header whose `dataLen` must cover the message, then walks
//! server-declared capability sets or a Format List whose long names end only at a NUL. The
//! first byte picks the Format List layout the two sides negotiated.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, message)) = data.split_first() else {
        return;
    };
    let _ = justrdp_pdu::cliprdr::ClipboardPdu::decode(message, mode & 1 != 0);
});
