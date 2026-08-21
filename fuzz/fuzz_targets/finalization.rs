#![no_main]
//! Fuzz the connection-finalization parsers (issue #237) — `justrdp_pdu::finalization`. Sibling
//! of that module's three `*_never_panics_on_arbitrary_input` proptests.
//!
//! ## Why the module had no target at all, which is not #230's failure
//!
//! #230 closed a family where the roster matched **by module name** and a name lied: `pointer`
//! and `license` each appeared in `ls fuzz_targets/` and in the walk of what parses untrusted
//! bytes, so both read as covered while a different `pub fn` of the same name went undriven.
//!
//! `finalization` is the other shape. It appeared in **neither** list, and in no known-holes
//! entry either, so nothing was wrong about it — nothing mentioned it. The map edge is where
//! that traces to: `docs/map/territory/capability-exchange-activation.md` owns this module and
//! did not claim [untrusted decode never panics](../../docs/map/invariant/untrusted-decode-never-panics.md),
//! so the invariant's own list of territories could not reach it. Both halves of that edge are
//! drawn by the change that adds this file.
//!
//! ## Why one target with no selector
//!
//! `gcc` and `mcs` spend a selector arm per entry point because their parsers are separate
//! grammars with real depth. These three are the shallowest decoders in the crate — two, three
//! and four fixed-width reads respectively, no dispatch, no length field, no cap — so every
//! input drives all three. A selector would cost more than the calls it guards, which is the
//! same judgement `tpkt.rs` and `fastpath.rs` make for their `frame_len` siblings.
//!
//! There is no seeder for this target and no captured finalization PDU in the repo, so the
//! input is the raw `&[u8]` rather than an `Arbitrary` struct — nothing outside this file
//! depends on a layout.
//!
//! ## What the lane adds over the properties: almost nothing, and the honest reason is not
//! the usual one
//!
//! These parsers have no exact-match gate in front of their reads, so undirected bytes reach
//! every one of them — measured at 5 runs each, an unchecked read in any of the three turns its
//! own proptest red every time. So the stable gate already has reachability.
//!
//! An earlier revision of this header claimed the lane's remaining value was `-timeout` (hangs)
//! and coverage guidance over field combinations. **Both are false here, and the correction is
//! worth keeping because the sentence is a template that fits most targets in this directory.**
//! No branch in any of the three parsers depends on a field *value* — every read is stored or
//! discarded unconditionally — so libFuzzer's entire feature set is the nine length checks in
//! `ReadCursor::ensure`, saturated by inputs of length 0..8. And there is no loop anywhere in
//! the three, so `-timeout` has no hang to catch.
//!
//! What the target is actually for: **roster uniformity and regression insurance.** `fuzz.yml`
//! derives its matrix from this directory, so a parser family with no file reads as a decision
//! nobody made — which is the shape #237 exists to close — and the day one of these grows a
//! length field or a loop, the target is already there and already in the matrix. That is a
//! weaker claim than the one it replaces, and it is the true one. The cost is one 300s matrix
//! job guarding nine branches.

use libfuzzer_sys::fuzz_target;
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::finalization::{Control, FontMap, Synchronize};

fuzz_target!(|data: &[u8]| {
    let mut cur = ReadCursor::new(data, "fuzz synchronize");
    let _ = Synchronize::decode(&mut cur);

    let mut cur = ReadCursor::new(data, "fuzz control");
    let _ = Control::decode(&mut cur);

    let mut cur = ReadCursor::new(data, "fuzz font map");
    let _ = FontMap::decode(&mut cur);
});
