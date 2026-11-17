#![no_main]
//! Fuzz the X.224 TPDU parsers (issue #200). Sibling of x224's three
//! `*_never_panics_on_arbitrary_input` proptests.
//!
//! Each entry point takes a server-framed TPDU and reads it by its length indicator —
//! `decode_connection_confirm` on the connect path (where its variable part carries the
//! negotiation response), `decode_data` on every session PDU after it, and
//! `DisconnectRequest` on any frame from the negotiation on.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::x224::decode_connection_confirm(data);
    let _ = justrdp_pdu::x224::decode_data(data);
    let _ = justrdp_pdu::x224::DisconnectRequest::matches(data);
    let _ = justrdp_pdu::x224::DisconnectRequest::decode(data);
});
