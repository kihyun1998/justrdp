#![no_main]
//! Fuzz the RemoteFX Progressive block-stream parser (issue #99). Sibling of progressive's
//! `decode_all_never_panics_on_arbitrary_input` proptest. `decode_all` walks an arbitrary
//! number of RFX_PROGRESSIVE_* blocks out of one WireToSurface2 payload, with lengths nested
//! three deep — block, the region's tile window, then each tile's per-component runs — so the
//! whole input is the attacker-controlled surface.
//!
//! **This target does not bootstrap from an empty corpus, and that is measured** (#200). Its
//! first execution ever, on the run that added it to the lane, ended:
//!
//! ```text
//! #148786349  DONE  cov: 62  ft: 64  corp: 6/29b
//! ```
//!
//! 149M executions, coverage flat from the 8M mark, and a retained corpus of six inputs
//! totalling **29 bytes** — guidance never assembled a valid block header, so the nesting above
//! is unreached. `nscodec`, also running for the first time in the same run under the same 300s
//! budget, reached `corp: 85/9477b` — so this is this format's magic-plus-nested-lengths wall,
//! not a property of cold starts. Until a seed corpus exists, read this target as covering the
//! header reject paths only.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::rfx::progressive::decode_all(data);
});
