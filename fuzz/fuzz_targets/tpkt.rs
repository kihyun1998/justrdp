#![no_main]
//! Fuzz the TPKT framing header (issue #200). Sibling of tpkt's
//! `decode_never_panics_on_arbitrary_input` proptest.
//!
//! `decode` reads the 4-byte TPKT header and returns the body slice its `u16` length field
//! declares — a server-supplied length checked against a buffer the server also framed, which is
//! the narrowest and most-reached instance of the untrusted-length class in the whole library:
//! every non-fast-path byte in the process passes through here.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::tpkt::decode(data);
});
