# 0014 — A DVC processor error drops the connection, attributably; the recovery ladder is #272's

- Status: Accepted (issue #270) — Decision 2 implemented by #285; see the Amendments below (2026-09-15, 2026-09-16)
- Date: 2026-09-14
- Kind: **judgement** — the maintainer chose between three shapes whose consequences were
  enumerated (below). A better derivation does not reopen it; the maintainer does.

## Context

Every error a `DvcProcessor` returns ends the session. `Drdynvc::dispatch` propagates it with `?`
(`crates/justrdp/src/dvc.rs:377`), the session machine returns it from `process_bytes`, and the
adapter turns it into `SessionFailure::Protocol` (`crates/justrdp-tokio/src/lib.rs:655-660`).
#270 named four rungs a processor error could sit on — **1** ignore the command, **2** reset the
channel state by re-advertising capabilities (`[MS-RDPEGFX]` 3.3.5.19), **3** close the channel
(`DYNVC_CLOSE`), **4** drop the connection — and asked which error belongs on which.

### What was measured before deciding

- **Rung 3's cost is a frozen screen** (real VM, WS2022, #270 comment 2026-09-02). An unsolicited
  client `DYNVC_CLOSE` on the graphics channel keeps the session, input and drdynvc alive, but
  frames go 778 → 0 under identical stimulus, the server never falls back to slow-path bitmaps and
  never re-offers the channel. One VM is one server (ADR-0009, 2026-09-04 amendment).
- **Rung 1 already exists, deliberately, for part of the family**: tile-codec failures and
  unsupported codecs warn-and-skip (`egfx.rs` `decode_wts1`), an unspecified caps version is
  ignored (3.3.5.19 MUST), over-budget paint entries are skipped (#268), traffic for an unopened id
  is ignored (`virtual-channels.md`). "Every error drops the connection" is true only of errors that
  reach the `?`.
- **Rung 1 is not available where it would matter most.** A zgfx failure poisons the decompressor
  for every later message (`crates/justrdp-codecs/src/zgfx.rs:410-426`), so "ignore" there is
  silent channel death. And a returned `Err` discards every output already produced in the same
  byte batch, FrameAcks included (`crates/justrdp/src/session.rs:289-299`) — a lost FrameAck
  stalls the server, so a message-level "ignore" can itself freeze the screen.
- **The classification is lost at the trait.** `DvcProcessor::process` returns only `DecodeError`
  (`egfx.rs:988`), so `dispatch` cannot tell an unknown cache slot from a zgfx failure. Any
  per-class rung needs a verdict carrier the trait does not have.

### What the references actually say (re-opened at source, not at #270's text)

- **Spec.** `[MS-RDPEGFX]` 3.1.5.1: an unexpected message SHOULD be ignored; an inconsistent
  `pduLength` means the connection SHOULD be dropped. 3.3.5.1–.7 put validity MUSTs on surface
  and cache ids with no stated consequence.
- **Microsoft's client conformance suite** (`microsoft/WindowsProtocolTestSuites` `2447a665`) is
  **permissive, not a drop mandate**. Negative tests call `RDPClientTryDropConnection`, which
  asserts a disconnect only when `DropConnectionForInvalidRequest` is true
  (`Client_RdpTestClassBase.cs:744-763`), and test initialisation sets it **false** for a Windows
  implementation other than 10.3 (`:115-127`); otherwise a non-dropping client logs a warning. For
  a nonexistent cache slot the **test code** calls that helper
  (`RdpegfxSurfaceToCacheToSurfaceTest.cs:639`) while the **design document** says *"Expect a
  frame acknowledge"* (`MS-RDPEGFX_ClientTestDesignSpecification.md:1500`) — the suite disagrees
  with itself.
- **FreeRDP** (`a0114eb`) closes the channel on a processing failure and keeps the session
  (`channels/drdynvc/client/drdynvc_main.c:1520-1521`) — rung 3. Its 2020 refusal of evicting a
  nonexistent cache slot (`17e0d251`) is no longer current: `gdi_EvictCacheEntry` succeeds again
  (`libfreerdp/gdi/gfx.c:1822-1842`).
- **IronRDP** (`be39881`) terminates the session on a processor error; its client-side
  `close_channel` has no production caller — rung 4, justrdp's position.

## Decision

1. **Every error a `DvcProcessor` returns keeps dropping the connection.** No channel close (rung 3)
   is wired as a destination in its own right. The existing rung-1 tolerances listed above are
   unchanged.
2. **The failure becomes attributable.** Today a host receives `SessionFailure::Protocol` and
   cannot tell a graphics-channel failure from a malformed Share Data PDU. The session failure
   must name the dynamic channel whose processor failed. The shape of that carrier is an
   implementation choice, not part of this decision.
3. **The recovery ladder, and the per-class verdict carrier it needs, belong to #272.** Reset is the
   rung with value: it keeps the picture. When #272 builds it, that change decides which classes
   attempt a reset, what a failed or infeasible reset does, and where the verdict lives in the
   trait. Rung 3 is reconsidered only there, as a possible fallback, never here as an end state.

### What this decision did not cover

Recorded so the next pass does not read these as settled by it:

- the rung for a **spec-legal surface or output size above `MAX_SURFACE_DIM` (16384)**, which the
  conformance suite exercises in positive tests at 32766;
- **drdynvc-manager errors** that no channel can be blamed for (malformed drdynvc PDU, SVC
  reassembly), and `[MS-RDPEDYC]` 3.1.5.2.4's "MUST terminate" against the skipped unknown `Cmd`;
- the rung for a **malformed Display Control PDU** (`[MS-RDPEDISP]` was not read);
- the defects the enumeration found on the way, which were carried to the tracker rather than
  decided here.

## Consequences

- **Behaviour is unchanged** for every error class; only what the host learns changes. The
  framing classes stay aligned with 3.1.5.1's SHOULD-drop, and the suite's own permissiveness means
  no conformance expectation moves either way.
- **A user gets an honest disconnect rather than a frozen screen**, and the host — which owns
  reconnect strategy (`CLAUDE.md`) — gets enough to choose a reconnect over a report.
- **The harness premise stays true.** `crates/justrdp/src/lib.rs:45` and
  `fuzz/fuzz_targets/egfx_processor.rs:248` state that flushing after a failed `process` is a
  sequence the live path cannot produce; every non-fatal verdict would have falsified both. #272
  inherits that obligation.
- **Two records carried a premise this enumeration falsified** — that Microsoft's suite tolerates a
  nonexistent cache slot. `egfx-graphics-pipeline.md` and `docs/plan.md` are corrected in the same
  change. #268's skip decision survives on its other ground, a resource ceiling that is ours
  (ADR-0009, 2026-08-31 amendment).
- **Three surfaces called such an error "fatal for the channel"** — `justrdp_codecs::color`'s
  `to_rgba` rationale, `bitmap-codecs.md`, and ADR-0012's consumption-site paragraph. It was always
  the session. The first two are corrected in place; ADR-0012 is left as written and corrected
  here. Each argued *against* refusing on that ground, so the correction strengthens rather than
  overturns them.
- **Channels now have a governing decision**; `virtual-channels.md` said there was none.

## Rejected alternatives

- **Split by class, closing the channel for semantic misses** (unknown surface or cache slot,
  resource caps) while framing and integrity errors keep dropping. Rejected because it builds the
  expensive half of a ladder whose payoff is a frozen screen: a non-`Err` verdict path so FrameAcks
  survive, per-PDU decoding in place of all-or-nothing `decode_all`, a "channel lost, session alive"
  host event that no `SessionOutput` can express today, local teardown, and changes to the harness
  contract — all before the reset that would make a closed channel recoverable exists.
- **Host-injected policy.** Rejected for now because feasibility is state only the core holds — a
  poisoned zgfx cannot be ignored, a reset needs a confirmed version of 103 or above — so the core
  would still have to restrict the host to feasible verdicts and forbid relaxing the integrity
  classes, at the split's full cost plus a host API.
- **Close the graphics channel as FreeRDP does.** The prior art is an example, not an authority;
  this project's own measurement priced it as a frozen screen with no fallback and no signal.

## Amendment (2026-09-15, #285): Decision 2's carrier, and where attribution stops

Decision 2 is implemented, so its *"Today a host receives `SessionFailure::Protocol` and cannot
tell…"* describes the tree before #285. The carrier is `SessionError::DynamicChannel { channel,
error }`, reaching the host inside `SessionFailure::Protocol`; `channel` is the name the processor
registered under (`DvcProcessor::channel_name`). Behaviour is unchanged — the variant still ends
the session. The carrier's shape is a derivation and falls to a better one.

**Where attribution stops is a judgement**, and it is the maintainer's. Only an error a
`DvcProcessor::process` returned is attributed. Shown before implementation, with the alternative
of also naming the channel for it, the maintainer kept a **drdynvc transport failure on a channel
that is open** — the `DYNVC_DATA_FIRST.Length` reassembly cap — as `SessionError::Decode`: the cap
is the manager's bound, not the processor's verdict. The same line leaves two channel-originated
failures unattributed, and neither is settled by this amendment:

- a `SessionError::Framebuffer` raised by an EGFX `OutputResized` — refused in the session machine,
  outside `process` (#286);
- the manager errors this record already listed as not covered (SVC reassembly, a malformed
  drdynvc PDU), which no channel can be blamed for.


## Amendment (2026-09-16, #286): attribution follows the channel that produced the event, not the call that failed

Two things this record left open are settled, and both by the same change.

**The first not-covered bullet is covered.** *"The rung for a spec-legal surface or output size
above `MAX_SURFACE_DIM` (16384), which the conformance suite exercises in positive tests at
32766"* is decided: **the cap stays at 16384 and the refusal keeps ending the session**, recorded
as a deliberate divergence in [ADR-0009](0009-tolerant-negotiation-posture.md)'s 2026-09-16
amendment, where the spec sections, the suite's two positive tests and both references are read
at source. Decision 1 is untouched — it is the *rung* that was open, not the posture, and the
answer is the rung this record already gives everything else.

**And the 2026-09-15 amendment's first unattributed case is closed.** That amendment left *"a
`SessionError::Framebuffer` raised by an EGFX `OutputResized` — refused in the session machine,
outside `process` (#286)"* unsettled. It is now attributed.

### Where attribution stops, restated

Decision 2's line was *"only an error a `DvcProcessor::process` returned is attributed"*, and that
wording made the boundary the **call** rather than the **origin**. The line the maintainer chose
here is: **attribution follows the channel whose processor produced the thing that failed**, and
it is reached by carrying the name rather than by recovering it from an error.

Concretely, `DvcEvent::OutputResized` carries the processor's `channel_name()`, and
`SessionError::Framebuffer` becomes `{ channel: Option<&'static str>, error }` — `Some` for the
EGFX resize, `None` for the two paths no channel produced (the connect sequence's `SessionConfig`
and a reactivation Demand Active). Behaviour is unchanged; the session still ends.

**This does not widen attribution to the manager.** The 2026-09-15 amendment's other case — the
`DYNVC_DATA_FIRST.Length` reassembly cap on an open channel — stays `SessionError::Decode`, and
for the reason recorded there: the cap is the manager's bound, not a processor's verdict. The
distinction this amendment adds is between *a channel's processor produced this* and *a call into
a processor returned this*; the reassembly cap is neither.

**Kind: judgement**, on the same footing as the line it moves. Shown the alternative — moving the
size check into `GraphicsProcessor::process` so the existing path applies untouched — the
maintainer chose the carrier, because the alternative puts the framebuffer's ceiling in a second
place and [ADR-0012](0012-consumption-site-totality.md) §3 asks a family for one answer to one
quantity. The carrier's *shape* remains a derivation and falls to a better one.

### Proof

Wire-format round-trips through `SessionStateMachine::process_bytes`, per ADR-0009's 2026-09-04
amendment (never a mock, never the private method): an EGFX `ResetGraphics` at
`MAX_DESKTOP_DIM + 1` names the Graphics channel, and a desktop size from the connect sequence
names none. Each was seen to fail under its own mutation — attribution off; blanket attribution at
the connect site; a plausible but wrong channel name — and only the targeted test failed each
time.

### Still not covered

The remaining entries of this record's own not-covered list are untouched: drdynvc-manager errors
no channel can be blamed for, `[MS-RDPEDYC]` 3.1.5.2.4's "MUST terminate" for the skipped soft-sync
and unassigned `Cmd` values (narrowed by #287 to exclude Cmd 6/7), and the rung for a malformed
Display Control PDU.
