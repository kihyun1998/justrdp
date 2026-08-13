#![no_main]
//! Fuzz the X.224 TPDU parsers (issue #200). Sibling of x224's two
//! `*_never_panics_on_arbitrary_input` proptests.
//!
//! Both entry points take a server-framed TPDU and return an interior slice computed from its
//! length indicator — `decode_connection_confirm` on the connect path (where its variable part
//! carries the negotiation response), `decode_data` on every session PDU after it.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::x224::decode_connection_confirm(data);
    let _ = justrdp_pdu::x224::decode_data(data);
});
