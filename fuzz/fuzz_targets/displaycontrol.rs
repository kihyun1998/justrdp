#![no_main]
//! Fuzz the display-control PDU parser (issue #200). Sibling of displaycontrol's
//! `decode_never_panics_on_arbitrary_input` proptest.
//!
//! `DisplayControlPdu::decode` reads a type/length header and then a server-declared *count* of
//! monitor layout entries — a count that multiplies into a size, which is the arithmetic half of
//! the untrusted-decode class rather than the plain-length half.
//!
//! Measured the weakest bootstrapper of this family (#200): undirected bytes reach 16.5% of its
//! regions and 1 of its 4 functions, against 34-49% for the flatter connect-sequence headers. If
//! any target in this batch turns out to want a seed corpus, it is this one.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::displaycontrol::DisplayControlPdu::decode(data);
});
