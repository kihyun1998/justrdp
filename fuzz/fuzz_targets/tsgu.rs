#![no_main]
//! Fuzz the RD Gateway HTTP transport packet parser (#612). Sibling of tsgu's
//! `decode_never_panics_*` proptests.
//!
//! `Packet::decode` reads a header whose `packetLength` frames the packet, then per packet type
//! a `fieldsPresent` that selects optional fields, `u16` lengths for blobs and strings, and the
//! resource counts of a channel create. A packet that decodes is re-encoded and must decode to
//! the same value.

use justrdp_pdu::tsgu::Packet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = Packet::decode(data) {
        let encoded = packet.encode().expect("a decoded packet fits its length prefixes");
        assert_eq!(Packet::decode(&encoded).expect("re-encoded packet decodes"), packet);
    }
});
