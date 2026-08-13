#![no_main]
//! Fuzz the static virtual channel chunk parser (issue #200). Sibling of svc's
//! `decode_never_panics_on_arbitrary_input` proptest.
//!
//! `ChannelChunk::decode` reads the channel PDU header whose `length` declares the size of a
//! message reassembled across *several* chunks — so a wrong value here is not bounded by the
//! current buffer, which is the reassembly-length shape the untrusted-decode invariant names.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::svc::ChannelChunk::decode(data);
});
