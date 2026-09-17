# 0014 — A DVC processor error drops the connection, attributably; the recovery ladder is #272's

- Status: Accepted (issue #270) — Decision 2 implemented by #285; Decision 3's reset rung built by #272; see the Amendments below (2026-09-15, 2026-09-16, 2026-09-17)
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

## Amendment (2026-09-17, #272): the 3.3.5.19 reset is the rung for a semantic miss

Decision 3 handed #272 the recovery ladder. #272 measured the reset before building it; the
numbers and how they were taken are in
[EGFX graphics pipeline](../map/territory/egfx-graphics-pipeline.md) under *The 3.3.5.19 reset*.
This amendment records what was decided on them and what the implementation holds.

**Decision 1 narrows.** A `DvcProcessor` error still drops the connection. What changes is that
the graphics processor no longer *returns* an error for a semantic miss once the server has
confirmed VERSION103 or later: it resets the channel and returns `Ok`.

### Judgements — the maintainer's, and only the maintainer reverses them

1. **Build the reset, proven against injected errors, although no real server has produced
   one.** The same day, in order. First the maintainer chose *measure, then build only on a real
   trigger* over *record and park* and *build now*. The measurement found none: 0 processor
   errors and 0 rung-1 warn-and-skip events over two 120 s Start-menu sessions. The ladder was
   recorded as parked (#294). Asked whether a reproduction could be built instead, the
   maintainer was shown the two kinds and what each proves. **Injected** errors prove the
   mechanism but not that a server ever needs it; a **wider real workload** proves the need if
   it finds one. A trigger found in real traffic is more likely a decoder bug than a transient,
   and a reset does not fix a bug the server reproduces. The maintainer chose both: widen the
   census, then build regardless, with the census result recorded. The widened census also found
   none: 0 errors over two 170 s sessions (File Explorer and Control Panel, window drags,
   maximise and restore, scrolling, Alt+Tab, six Display Control resizes each, `connectionType`
   LAN and MODEM, 11 269 and 10 360 frame updates). **So this rung recovers from a failure no
   capture here contains**, and it was built knowing that. That is the part of `start()`'s own
   rationale ("does not ship machinery for a case no capture contains") this judgement
   overrides, and for this rung only.
2. **Only semantic misses take the reset.** Shown the class lines — semantic only, every feasible
   class, or a host on/off switch over a core-chosen line — the maintainer chose **semantic
   only**: an unknown surface id or cache slot, and a codec decode failure. **Framing errors keep
   dropping**, because a zgfx history desynchronised by an earlier defect decodes to plausible
   bytes whose only visible symptom is often an inconsistent `pduLength`, so resetting on one
   re-enters with a history that is poisoned without being flagged. **Server-driven refusals keep
   dropping** (`MAX_SURFACE_DIM`, the surface and cache budgets), because a reset makes the
   server resend the same shape: it recreated the same 1280x800 surface every time. This answers
   [ADR-0009](0009-tolerant-negotiation-posture.md)'s 2026-09-16 amendment, which named its
   `MAX_SURFACE_DIM` row *"a candidate"* for a non-fatal verdict: it is not one.

### Derivations — they fall to a better derivation or a better measurement

- **Recovery is decided inside `process` and returned as `Ok`.** An `Err` that the session
  survives is unsound, not just lossy: `process_bytes` breaks before consuming the failing frame
  and restores the inbox with that frame in it, so the next call decompresses the same EGFX
  message again and advances the zgfx history twice. So the `DvcProcessor` trait, the manager and
  the session machine are unchanged, no new fallible call carries a channel name (#285's concern
  stays inert), and the harness premise in `lib.rs`'s `fuzzing` module and
  `fuzz/fuzz_targets/egfx_processor.rs` stays literally true.
- **Which call sites are misses.** The judgement named classes; the sites are a derivation.
  `Failure::Miss`: an unknown surface in `WireToSurface1`, `WireToSurface2`, `SolidFill`,
  `SurfaceToSurface` (source or destination), `SurfaceToCache` and `CacheToSurface`; an unknown
  cache slot; and an uncompressed `WireToSurface1` payload shorter than its rectangle or failing
  conversion. The tile codecs already warn-and-skip (rung 1), so theirs never reaches here.
  Everything else is `Failure::Fatal`.
- **The zgfx history survives the reset, and ClearCodec's caches do not.** Measured both ways
  on the VM: the server keeps its compressor history (a fresh decompressor decoded 0 of 20
  post-reset messages identically, with no error), and it resets its ClearCodec glyph and V-bar
  state (kept caches painted silently wrong glyphs; fresh caches painted clean). Each is a
  silent failure when wrong, which is why the reset is not `close()`'s
  `*self = GraphicsProcessor::default()`: that rebuilds zgfx.
- **A zgfx failure is not resettable.** A poisoned history can be rebuilt only by a server that
  restarts its compressor, and this one does not.
- **Ignored messages are still decompressed, and the window is per PDU.** About one frame (72
  PDUs in two messages) arrived in flight and its unacknowledged `EndFrame` was tolerated, as
  3.2.5.18's *"assume that the client has disregarded all the messages"* predicts. Outputs the
  failing message produced *before* the miss are kept and precede the advertise.
- **The window ends on any confirm.** A confirm naming a version outside 2.2.3 is still ignored as
  a capability set; if the window waited for an accepted one, such a confirm would leave graphics
  dead with the session healthy, which is rung 3's cost without its signal.
- **One reset per channel binding**, held in state the reset itself does not clear. A miss the
  server reproduces after the reset therefore drops the connection instead of looping. A new
  binding (a server Create after Close) starts with a fresh allowance. The *number* is the
  cheapest bound that terminates, not a measured one: nothing here has ever needed a second.
- **The framebuffer is left alone.** After the confirm the server recreated its surface and
  repainted the whole desktop every time, so neither a clear nor a host event is needed to
  avoid stale pixels on this server. The reset is visible as an `rdp_egfx` warn, per ADR-0009
  §3(b).

### Proof

Unit tests drive `GraphicsProcessor::process`, and one test drives `SessionStateMachine::process_bytes`
round-trips on the wire format. Each was seen to fail under its own mutation, and only its target
test failed:
- a zgfx rebuilt by the reset;
- ClearCodec kept;
- VERSION102 admitted;
- the bound not held;
- no ignore window;
- a window that ends only on a specified version;
- a fatal site classified as a miss and the reverse;
- earlier outputs dropped;
- the reset disabled or the advertise not sent (the session-level test).

On the real VM a throwaway probe appended a `CacheToSurface` for an unfilled slot *after*
decompression. The probe is not in the tree. Injecting on the wire would have written bytes the
server never compressed into the history. The production path took the reset, the confirm
arrived, and the session survived the 70 s window with four further Start-menu cycles (576 frame
updates) painting clean.

### What this amendment did not cover

- The rung for #286's `SessionError::Framebuffer`, refused outside `process`, which therefore
  still ends the session. The ordering hazard recorded on #272 stays unobservable.
- The not-covered lists of the amendments above.
- Progressive, RemoteFX and planar state compared kept against fresh across a reset. Progressive
  is keyed by surface and the server recreated its surface, planar holds no cross-message state,
  and RemoteFX holds only its sticky video-mode refusal. So none is expected to matter, but none
  is measured.
- Whether a host switch is added (#273's territory).
- Any server but one WS2022 box, at any version but 10.4.
