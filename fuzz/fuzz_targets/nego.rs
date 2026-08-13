#![no_main]
//! Fuzz the RDP negotiation response (issue #200). Sibling of nego's
//! `neg_response_decode_never_panics_on_arbitrary_input` proptest.
//!
//! `NegResponse::decode` reads the server's answer to the negotiation request out of the
//! Connection-Confirm variable part — the PDU that decides which security protocol the whole
//! session then uses, parsed before any of it is authenticated.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::nego::NegResponse::decode(data);
});
