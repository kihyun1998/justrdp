#![no_main]
//! Fuzz the RemoteFX Progressive block-stream parser (issue #99). Sibling of progressive's
//! `decode_all_never_panics_on_arbitrary_input` proptest. `decode_all` walks an arbitrary
//! number of RFX_PROGRESSIVE_* blocks out of one WireToSurface2 payload, with lengths nested
//! three deep — block, the region's tile window, then each tile's per-component runs — so the
//! whole input is the attacker-controlled surface.
//!
//! **This target does not bootstrap from an empty corpus, and that is measured** (#200) — which
//! is why `fuzz.yml` seeds it from the real-VM capture before running it. Both halves, same
//! target, same 300s budget:
//!
//! ```text
//! empty:   #148786349  DONE  cov:  62  ft:   64  corp: 6/29b
//! seeded:  #  8277846  DONE  cov: 425  ft: 1713  corp: 198/1153Kb
//! ```
//!
//! From empty, coverage was flat from the 8M mark and guidance retained six inputs totalling
//! **29 bytes** — it never assembled a valid block header, so the nesting above was unreached.
//! `nscodec`, also cold in that run, reached `corp: 85/9477b`, so the wall is this format's
//! magic-plus-nested-lengths grammar rather than cold starts as such. Seeded, the same target
//! reaches 6.9x the coverage in **18x fewer executions**: the exec/s collapse from 494k to 27.5k
//! is the tell that it is now decoding rather than bouncing off a length check.
//!
//! Read a result from this target as valid only if the seeding step ran.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::rfx::progressive::decode_all(data);
});
