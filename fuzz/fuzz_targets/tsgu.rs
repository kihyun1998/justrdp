#![no_main]
//! Fuzz the RD Gateway HTTP transport packet parser (#612). Sibling of tsgu's
//! `decode_never_panics_*` proptests.
//!
//! `Packet::decode` reads a header whose `packetLength` frames the packet, then per packet type
//! a `fieldsPresent` that selects optional fields, `u16` lengths for blobs and strings, and the
//! resource counts of a channel create. A packet that decodes is re-encoded and must decode to
//! the same value, and the re-encoded length plus the body bytes reported unread is
//! `packetLength`.

use justrdp_pdu::tsgu::{Packet, PacketHeader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((packet, unread)) = Packet::decode_with_unread(data) {
        let encoded = packet.encode().expect("a decoded packet fits its length prefixes");
        let header = PacketHeader::decode(data).expect("a decoded packet has a header");
        assert_eq!(encoded.len() + unread, header.packet_length as usize);
        assert_eq!(Packet::decode(&encoded).expect("re-encoded packet decodes"), packet);
    }
});
