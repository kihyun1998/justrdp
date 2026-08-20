#![no_main]
//! Fuzz the GCC conference / settings-block parsers (issue #203). Sibling of gcc's nine
//! `*_never_panics_on_arbitrary_input` proptests.
//!
//! ## Why one target with a selector rather than nine
//!
//! #203 framed this as "nine entry points, no single top-level `decode`", and read that as a
//! choice between nine targets and one selector. Following the call graph says the nine are not
//! nine grammars — they are **two trees**, and only one of them is reachable from the wire:
//!
//! ```text
//! ConferenceCreateResponse::decode        <- mcs::decode_connect_response, i.e. a real server
//!   └ ServerGccBlocks::decode
//!      ├ ServerCoreData::decode  ├ ServerNetworkData::decode  └ ServerSecurityData::decode
//!
//! ClientGccBlocks::decode                 <- nothing outside this crate's own tests
//!   ├ ClientCoreData::decode   ├ ClientSecurityData::decode   └ ClientNetworkData::decode
//! ```
//!
//! So the lane cost of "one target per entry point" is nine jobs to fuzz two roots, while a
//! selector over the *roots* alone would leave the per-block field parsing behind a wall (below).
//! Every entry point is an arm here instead: one lane job, and each parser still has a door that
//! no magic guards.
//!
//! ## The magic prefix, and the two different things it does
//!
//! `ConferenceCreateResponse::decode` demands ~12 bytes of near-exact magic before it reaches a
//! single block — the T.124 OBJECT IDENTIFIER, the `conferenceCreateResponse` choice, `tag == 1`,
//! `result == 0`, one user-data set, the h221NonStandard choice and the literal `"McDn"`. Driven
//! with 200k **undirected** inputs, `gcc.rs` reaches only **11.98% of its regions and 4 of its 32
//! functions**, with all six per-block decoders dark.
//!
//! That number governs the *proptest* half of this module's coverage, because proptest is
//! undirected random sampling — which is the argument for the nine per-entry-point properties
//! beside this target rather than one on the root.
//!
//! **It does not predict what libFuzzer reaches, and #203 assumed it did.** Measured on this
//! lane, same 300s budget, gcc against itself:
//!
//! ```text
//! empty    cov: 515  ft: 1207  corp: 255/21Kb  exec/s: 178573  (53.8M runs)
//! seeded   cov: 699  ft: 1987  corp: 391/94Kb  exec/s:  46166  (13.9M runs)
//! ```
//!
//! No wall: coverage guidance climbs the magic unaided, because a comparison against a byte
//! string feeds libFuzzer's auto-dictionary (`__sanitizer_cov_trace_cmp`) and random sampling has
//! no such mechanism. `rfx::progressive` needed its seed for a different reason — **nested length
//! fields that must agree with each other**, which no dictionary entry can synthesise. Magic
//! constants are climbable; self-consistent arithmetic is not.
//!
//! The seed is kept because it is a measured 36% more coverage and 65% more features in 4x fewer
//! executions, not because the target would be blind without it. The inner arms are kept for what
//! the A/B does not cover: they make each per-block decoder reachable with no prefix at all.
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

/// Which parser `data` is handed to. The first arm is the only one a server can reach; the rest
/// are doors into parsers that arm otherwise guards behind its magic prefix, plus the
/// client-side tree, which is a round-trip aid on the public surface rather than wire input.
#[derive(Arbitrary, Debug)]
enum Entry {
    ConferenceCreateResponse,
    ServerBlocks,
    ServerCore,
    ServerNetwork,
    ServerSecurity,
    ClientBlocks,
    ClientCore,
    ClientSecurity,
    ClientNetwork,
}

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    entry: Entry,
    data: &'a [u8],
}

fuzz_target!(|input: Input<'_>| {
    use justrdp_pdu::gcc::*;
    let d = input.data;
    match input.entry {
        Entry::ConferenceCreateResponse => { let _ = ConferenceCreateResponse::decode(d); },
        Entry::ServerBlocks => { let _ = ServerGccBlocks::decode(d); },
        Entry::ServerCore => { let _ = ServerCoreData::decode(d); },
        Entry::ServerNetwork => { let _ = ServerNetworkData::decode(d); },
        Entry::ServerSecurity => { let _ = ServerSecurityData::decode(d); },
        Entry::ClientBlocks => { let _ = ClientGccBlocks::decode(d); },
        Entry::ClientCore => { let _ = ClientCoreData::decode(d); },
        Entry::ClientSecurity => { let _ = ClientSecurityData::decode(d); },
        Entry::ClientNetwork => { let _ = ClientNetworkData::decode(d); },
    }
});
