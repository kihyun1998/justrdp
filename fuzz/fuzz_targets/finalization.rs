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
//! and four fixed-width reads respectively, no length field, no cap — so every input drives all
//! three. A selector would cost more than the calls it guards, which is the same judgement
//! `tpkt.rs` and `fastpath.rs` make for their `frame_len` siblings. (**"No dispatch" stopped
//! being true in #252**, which put a `messageType == SYNCMSGTYPE_SYNC` gate on `Synchronize`;
//! every input still *enters* all three, it just no longer reaches past that one.)
//!
//! The input is the raw `&[u8]` rather than an `Arbitrary` struct — nothing outside this file
//! depends on a layout. This used to add "and no captured finalization PDU in the repo", which
//! **#252 made false**: `justrdp-pdu/tests/fixtures/connect/finalization-replies.bin` holds four
//! real server replies, and `.github/scripts/seed_fuzz_corpus.py`'s `SEEDERS` table is the
//! mechanism for turning them into a seed. Not done here — recorded so it is a decision rather
//! than an omission, and #252's gate is exactly what makes a seed worth more than it used to be.
//!
//! ## What the lane adds over the properties: for two of the three, almost nothing
//!
//! `Control` and `FontMap` have no exact-match gate in front of their reads, so undirected bytes
//! reach every one of them — measured at 5 runs each, an unchecked read in either turns its own
//! proptest red every time. So the stable gate already has reachability there.
//!
//! An earlier revision of this header claimed the lane's remaining value was `-timeout` (hangs)
//! and coverage guidance over field combinations. **Both were false here, and the correction is
//! worth keeping because the sentence is a template that fits most targets in this directory.**
//! No branch in any of the three parsers depended on a field *value* — every read was stored or
//! discarded unconditionally — so libFuzzer's entire feature set was the nine length checks in
//! `ReadCursor::ensure`, saturated by inputs of length 0..8. And there is no loop anywhere in
//! the three, so `-timeout` still has no hang to catch.
//!
//! **#252 inverted the first half for `Synchronize`, and that is worth more than the retraction
//! costs.** Its decode now branches on a field value, so a two-byte comparison stands between
//! undirected input and the `targetUser` read — and climbing a comparison from coverage feedback
//! is precisely what libFuzzer's auto-dictionary does and what `vec(any::<u8>(), 0..=512)`
//! structurally cannot: the proptest needs a hand-weighted arm (it has one) while the lane gets
//! there on its own. For this one parser the nightly lane is now the *stronger* instrument, which
//! is the reverse of what this header spent three paragraphs establishing.
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
