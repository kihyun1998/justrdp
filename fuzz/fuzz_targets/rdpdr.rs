#![no_main]
//! Fuzz the device redirection PDU parser (#336). Sibling of rdpdr's
//! `decode_never_panics_on_arbitrary_input` proptest.
//!
//! `RdpdrPdu::decode` reads an `RDPDR_HEADER`, then fixed fields or a Core Capability Request
//! whose sets are each read to a server-declared `CapabilityLength`.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::rdpdr::RdpdrPdu::decode(data);
});
