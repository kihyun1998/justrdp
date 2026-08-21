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
//! ## What the lane adds over the properties
//!
//! Less than usual, and saying so is the honest form of the entry. These parsers have no
//! exact-match gate in front of their reads, so undirected bytes reach every one of them:
//! measured at 5 runs each, an unchecked read in any of the three turns its own proptest red
//! every time. The lane's distinct value here is its `-timeout` (a hang, which proptest cannot
//! catch) and coverage guidance over the `Control`/`FontMap` field combinations — not
//! reachability, which the stable gate already has.

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
