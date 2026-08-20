#![no_main]
//! Fuzz the MCS (T.125) PDU parsers (issue #203). Sibling of mcs's five
//! `*_never_panics_on_arbitrary_input` proptests.
//!
//! ## Why one target with a selector rather than five
//!
//! Unlike `gcc`, these five really are five grammars — but four of them are 2-to-8-byte PER
//! `DomainMCSPDU`s sharing one `read_domain_choice` prefix, and they saturate in seconds. Five
//! lane jobs would be one target doing work and four idling through a 300s budget. The selector
//! is the shape `rfx.rs` already uses here for the same reason.
//!
//! `decode_connect_response` is the odd one: BER rather than PER, and the only entry point that
//! recurses into another module (the whole `gcc` server tree hangs off it). Its prefix is deep
//! enough to hide `DomainParameters::decode` from 200k **undirected** inputs — the measurement
//! that governs the proptest beside this target, since proptest samples the same way. `mcs.rs`
//! reaches 33.9% of its regions and 6 of its 19 functions that way.
//!
//! It is seeded from a real Connect-Response captured off the test VM, but as an improvement
//! rather than a rescue: the A/B in `gcc.rs` shows coverage guidance climbing a magic prefix on
//! its own. #203 predicted this family would bootstrap without a seed, and for the fuzz lane that
//! prediction held — the undirected figure was never the binding constraint it looked like.
//!
//! ## The byte layout, which is pinned by measurement because a seeder depends on it
//!
//! `data` is `&[u8]` rather than `Vec<u8>`, and that is load-bearing rather than a borrow-checker
//! preference. Measured against `arbitrary` 1.4.2: a `Vec<u8>` field consumes **two** bytes per
//! element -- the element from the front and a keep-going byte from the *back* of the buffer --
//! so a 64-byte input yields a 32-byte `data` that is not the bytes anyone wrote. A trailing
//! `&[u8]` takes the remainder verbatim. The whole input is therefore
//!
//! ```text
//! [4-byte little-endian u32 selector] ++ [payload, verbatim]
//! arm = (selector as u64 * ARM_COUNT) >> 32
//! ```
//!
//! which is what `.github/scripts/seed_fuzz_corpus.py` writes, and what makes a corpus entry
//! readable as "a selector and a real PDU". `fuzz/Cargo.lock` is tracked, so the `arbitrary` bump
//! that would reinterpret it arrives as a reviewable diff -- the same argument `seed_progressive_srl`
//! records for its committed bytes.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

/// Which parser `data` is handed to.
#[derive(Arbitrary, Debug)]
enum Entry {
    ConnectResponse,
    AttachUserConfirm,
    SendDataIndication,
    ChannelJoinConfirm,
    DisconnectProviderUltimatum,
}

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    entry: Entry,
    data: &'a [u8],
}

fuzz_target!(|input: Input<'_>| {
    use justrdp_pdu::mcs::*;
    let d = input.data;
    // Total by construction (`body.first()`), so it costs nothing to drive on every input rather
    // than spending a selector arm on it — and it is a `pub fn` over server bytes, so leaving it
    // undriven would be a gap the invariant's derivation would keep finding.
    let _ = DisconnectProviderUltimatum::matches(d);
    match input.entry {
        Entry::ConnectResponse => { let _ = decode_connect_response(d); },
        Entry::AttachUserConfirm => { let _ = AttachUserConfirm::decode(d); },
        Entry::SendDataIndication => { let _ = SendDataIndication::decode(d); },
        Entry::ChannelJoinConfirm => { let _ = ChannelJoinConfirm::decode(d); },
        Entry::DisconnectProviderUltimatum => { let _ = DisconnectProviderUltimatum::decode(d); },
    }
});
