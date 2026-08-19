# 0011 — Zero `ironrdp` is the terminal state: the oracle is scaffolding, not a permanent dependency

- Status: Accepted
- Date: 2026-08-10
- **Amendment (2026-08-13, #194): the basis exists, and the oracle is less capable than this
  record assumed.** Progressive's owned basis landed — a 52-payload real-server corpus
  (`justrdp-codecs/tests/fixtures/progressive/`) plus FreeRDP-derived SRL expectations
  (`tests/progressive_srl_freerdp.rs`), each defect pinned by a canary. Two corrections to the
  Context below, both measured. **(a)** The oracle decodes **2 of 52** payloads, not "rejects
  the first frame" — and a *fourth* defect is the larger cause: it demands a `WBT_CONTEXT`
  block per `codecContextId`, while this server sends one such block ever and then rotates
  through 24 ids. FreeRDP imposes no such requirement (`progressive.c:2129`, `:314`). The two
  failures are independent; skipping the sentinel payload does not save the rest. **(b)** The
  premise that a real-server SRL vector might be unobtainable was **false**, and the cause was
  ours: the capture advertised `connectionType = LAN`, so the server sent full quality on the
  first pass and never refined. Advertising `MODEM` yields 3250 upgrade tiles. Promoted to
  [`capture-coverage-follows-what-we-advertise`](../map/invariant/capture-coverage-follows-what-we-advertise.md).
  The Decision is unchanged; the oracle dev-dependency stays until the self-owned decoder
  exists (#171) and is live (#172), and the canaries are what use it.
- **Amendment (2026-08-18, #168): the oracle's reach extended into the owned basis itself.**
  Slice 2 measured a **fifth** oracle divergence — its SRL state starts at `kp = 0` where
  FreeRDP's starts at `8` (`progressive.c:1272`, unchanged since 2.11.7), so the two
  desynchronise on the first symbol of every component, ahead of the three divergences #194
  named. The finding that matters for *this* record is where it was found: five of the eight
  hand-derived FreeRDP vectors had themselves been computed at `kp = 0` — the oracle's initial
  value, though FreeRDP's own `WINPR_C_ARRAY_INIT` declaration predicts the same mistake, and
  the evidence does not separate the two. So this is **not** recorded as the oracle having
  shaped the basis; it is recorded as the basis having been derived from a range too narrow to
  contain the state it depended on. The Decision is unchanged, and the honest strengthening is
  narrower than it first looked: the owned basis was wrong on its first attempt, which is an
  argument for scheduling the oracle's removal rather than for trusting either instrument.
  Promoted to
  [`oracle-agreement-is-not-independence`](../map/invariant/oracle-agreement-is-not-independence.md)
  as a third violation shape.
- **Amendment (2026-08-18, #169): two more divergences, both in the first pass, and neither
  one the oracle could be patched out of.** Slice 3 measured a **sixth** and **seventh**:
  (6) the oracle captures the DAS sign array *after* dequantization
  (`progressive.rs:84`) where FreeRDP captures it off the raw entropy output
  (`progressive.c:876`) — measured over the corpus, the two capture points disagree on **8369
  of 8829** real components, because the LL3 delta reconstruction runs between them, and the
  error is permanent rather than per-frame because the sign array routes every later
  refinement of that coefficient; (7) the oracle's `dwt_extrapolate` narrows every lifting tap
  with `value as i16` where FreeRDP saturates (`clampi16`), so on an overflowing tap the two
  differ by a full `u16`.
  Two things follow for this record. First, the count is now seven, spread across the parse,
  the entropy layer, the first pass and the transform — the oracle is not defective at a point
  but at every layer of this codec, which is what makes "fix it upstream" (rejected
  alternative B) unavailable rather than merely unattractive. Second, and more useful: **one
  oracle primitive survived and is still in use.** `dwt_extrapolate` is a self-contained
  transform with no stream state, and it agrees coefficient-for-coefficient wherever the
  narrowing seam is unreachable, which is what makes it a usable ADR-0007 stage-boundary
  cross-check. Retirement stays *per codec and per stage*, on evidence — that is the Decision
  working, not an exception to it.
- **Amendment (2026-08-19, #171): the self-owned decoder exists, and the basis proved something
  the oracle structurally could not.** Slice 5 assembled the pipeline
  (`justrdp_codecs::rfx::progressive::Progressive`) and gated it on the owned basis this record
  requires — the 52-payload corpus plus FreeRDP-derived expectations — with a fresh real-VM run
  as the round-trip (**0 tiles skipped, 0 failures**, over 862 tiles the server sent that day).
  Two things belong on this record rather than only in the issue.
  **(a) The oracle is not merely unable to decode this traffic; on the assembly layer it is on
  the wrong side of a picture-changing question.** `ironrdp-graphics::progressive` returns whole
  64 x 64 tiles and never clips them to the region's rects; FreeRDP clips (`update_tiles`,
  `progressive.c:2329-2412`). Measured over the corpus, the two policies leave **57 386 of a
  1 280 x 800 surface's 1 024 000 pixels different**. So a differential against the oracle would
  not merely have been *unmeetable* here — passing it would have required painting the wrong
  picture, which is a stronger statement than the Context below makes and the one that
  retroactively justifies rejecting alternative (B).
  **(b) The owned basis found something no oracle diff could have.** The corpus carries no
  expected pixels, so the decisive instrument was a *counterfactual* — replaying the same bytes
  under both policies and diffing the surfaces. That is only available to a basis you own; a
  differential can compare two implementations but cannot price one implementation's own
  alternative. Recorded because "the owned basis is weaker than a diff, just necessary" is the
  easy reading of this record, and this is a case where it was strictly stronger.
  The Decision is unchanged. The dev-dependency now supports only the canaries and the
  `dwt_extrapolate` stage cross-check; the **runtime** dependency for Progressive dropped in
  #172 (2026-08-19 amendment), which was wiring rather than decoding.
- **Amendment (2026-08-19, #172): Progressive's runtime delegation is gone, and the wiring
  falsified one of epic #158's own recorded premises.** The self-owned decoder is the live
  WireToSurface2 decoder; `ironrdp-graphics` now serves Progressive only as a dev-dependency
  for the canaries and the `dwt_extrapolate` stage cross-check. The runtime graph still holds
  it for **zgfx alone** (#189). Two things worth keeping off the PR body: the epic recorded
  that `Surface::blit` "cannot express a source offset" and that this slice would have to widen
  it — **measured false**, because the blit's slice start and its stride are independent
  parameters, so a source offset is a slice rather than a signature change; and the swap
  *removes* the per-tile `Vec<u8>` the bootstrap wrapper allocated, 6193 x 16 KiB over one
  captured session, which is the frame path's no-owned-pixels invariant reaching one stage
  further up than it had.
- **Amendment (2026-08-19, #189): the runtime half of this record is done, and the reason it
  mattered turned out to be broader than correctness.** zgfx is self-owned
  (`justrdp_codecs::zgfx`), the `egfx-bootstrap` feature is deleted, and
  `cargo tree -p justrdp-tokio -e normal` names **no `ironrdp` crate at all** — the Decision's
  point 1 reached, and the graph is `justrdp → { rustls, sspi }` as ADR-0002 §Notes wrote it.
  Three things belong on the record.
  **(a) A runtime delegation exports the robustness posture too, and no oracle diff measures
  that.** This record's Context is about the oracle being *wrong*; for zgfx it is not wrong —
  it decodes everything its own compressor emits, and the differential in
  `tests/differential_zgfx.rs` passes over sequences. What it *was* is unguarded: probed
  directly, **five of seven** crafted `RDP_SEGMENTED_DATA` messages panicked inside
  `ironrdp_graphics::zgfx` (`mid > len` from a `split_at` on an untrusted `u32`, `attempt to
  subtract with overflow` from `8 * (len - 1) - last_byte`, and three bit-cursor index
  panics), and the panic reached `justrdp::egfx::GraphicsProcessor::process` — the live path,
  because this decompressor sees every EGFX byte before the PDU parser does. That gap was
  **structural, not an oversight**: the fuzz roster derives from `ls fuzz/fuzz_targets/` and
  the no-panic properties live in this repo's own modules, so a delegated decode path cannot
  appear in either by construction. Retiring a delegation is therefore worth doing even where
  the delegate is *correct*.
  **(b) zgfx did not need an owned basis in Progressive's sense, and got one anyway.** The
  `[MS-RDPEGFX]` sample is reproduced byte-identically by FreeRDP
  (`libfreerdp/codec/test/TestFreeRDPCodecZGfx.c`, *"Sample from [MS-RDPEGFX]"*) and by
  `ironrdp-graphics`, so an expectation derived independently of both implementations was
  available for the asking — and its compressed segment matches at distance 31 back into an
  *earlier segment*, which is the cross-message history contract in one vector. The oracle
  keeps its dev-dependency role here as breadth, which is what point 3 of the Decision
  intends.
  **(c) The coverage ceiling, measured rather than assumed.** Instrumented against the VM for
  one session: **25 messages, every one `ZGFX_SEGMENTED_SINGLE` and every one
  `PACKET_COMPRESSED`** — 18 488 literal tokens, 19 024 matches, 7 unencoded runs, longest
  match 5 062 bytes, **longest distance 133 937**, which is past a single segment's 65 535
  ceiling and so is direct evidence of the window spanning messages on a real wire. The
  multipart descriptor `0xE1` **never appeared**; its proof is the spec vector and the
  oracle differential, not the VM.
- Records a decision by the maintainer; supersedes the open-ended dev-dependency premise in [ADR-0003](0003-phased-codecs-differential-oracle.md) phase 3 and [ADR-0007](0007-stage-boundary-codec-verification.md) §Decision
- Related: #158 (Progressive), #189 (zgfx), #194 (Progressive's verification basis)

## Context

Every existing record treats the `ironrdp` dependency as *temporary in the runtime graph* and
*permanent in the test graph*, and none of them says where it ends:

- [ADR-0002](0002-dependency-boundary.md) §Notes writes the target graph as
  `justrdp → { rustls, sspi, ironrdp-graphics (temporary) }` — "temporary" with no terminal
  condition attached.
- [ADR-0003](0003-phased-codecs-differential-oracle.md) phase 3 drops the dependency **per
  codec**, gated on *"100% of oracle comparisons"* — so the oracle outlives every codec it
  gates, by construction.
- [ADR-0007](0007-stage-boundary-codec-verification.md) §Decision states it outright: *"The
  oracle crates remain **dev-dependencies only** (ADR-0003)"* — a statement about what they are,
  written where a statement about how long they last would go.

So "justrdp eventually depends on no `ironrdp` crate at all" is the project's evident intent —
`CLAUDE.md` opens with *"`ironrdp` 을 대체하되"* — and is nowhere a decision. That gap is not
academic: it makes the oracle's authority open-ended, and an instrument nobody has agreed to
retire is one nobody re-examines.

Three findings, all measured against the real WS2022 VM on 2026-08-10 while working #168,
turned that from untidy into load-bearing:

1. **The oracle rejects the first frame this server sends.** Its `TILE_FIRST` tiles carry
   `quality = 0xFF` with `numProgQuant = 0`. `0xFF` is a sentinel — *full quality, no
   progressive quantization* — special-cased by FreeRDP (`progressive.c:997`, `:1407`) and not
   by `ironrdp-graphics`, whose region decode path indexes the progressive-quant table by it and
   fails with `quant index 255 exceeds table length 0` (`progressive.rs:1064`, `:1080`) despite
   documenting the sentinel on `TileState::quality` (`:768`).
2. **The two reference implementations disagree with each other on SRL magnitude coding**
   (FreeRDP truncated-unary from 1, capped at `(1 << numBits) - 1`, `progressive.c:1145-1157`;
   IronRDP Golomb-Rice with `num_bits - 1` remainder bits, `srl.rs:86-101`), and IronRDP's SRL
   tests round-trip against its own encoder, so they are self-consistent by construction and
   cannot arbitrate.
3. **The server sets `RFX_SUBBAND_DIFFING`** (context `flags = 0x01`), which FreeRDP reads and
   then marks `WINPR_ATTR_UNUSED` at both receiving functions, and `ironrdp-graphics` never
   reads at all.

This is the fourth adjudication the oracle has lost in this repo (#122, #127, #118, now this),
and the first where it is wrong on the **live** path rather than merely same-lineage. The map's
`oracle-agreement-is-not-independence` invariant already predicts this shape — *"the oracle
rejects a stream a real Server 2022 sends"* is one of the two violations it names; what it lacks
is an end date.

## Decision

**`ironrdp` is scaffolding. The terminal state is zero `ironrdp` crates in this repo's
dependency graph — runtime *and* development.**

1. **Runtime.** Unchanged from ADR-0003: the `egfx-bootstrap` delegation drops per codec as each
   is self-owned. Progressive's dropped in #172 and zgfx's in #189, which deleted the feature
   itself — **done**: the runtime graph is `justrdp → { rustls, sspi }`.
2. **Development.** The oracle is a *bootstrapping instrument with a retirement condition*, not
   a standing gate. A codec's oracle dev-dependency drops when that codec's correctness rests on
   a basis we own — a real-server corpus plus expectations derived independently of our
   implementation, in the shape [ADR-0007](0007-stage-boundary-codec-verification.md)'s #118
   amendment already requires for the assembly layer. #194 defines that basis for Progressive
   and is the worked example.
3. **The oracle never outranks the owned basis.** Where the oracle and a real-server corpus
   disagree, the corpus wins; where the oracle and FreeRDP disagree, the tie-breaker in
   [`docs/agents/theflow.md`](../agents/theflow.md) already names FreeRDP. This decision adds
   only that a green oracle diff is **not** by itself an exit criterion once an owned basis
   exists for that codec.
4. **`rustls` and `sspi` are unaffected.** They are security-critical, non-RDP-specific leaf
   dependencies (ADR-0002) and are permanent by that decision, not by this one.

### How this was decided

Presented to the maintainer on 2026-08-10 as three options after the VM probe: report the
oracle defect upstream, redefine #171's gate only, or state a terminal zero-`ironrdp` position.
They chose the third and asked that it be written down rather than left implicit in the issue
tracker — *"어차피 새 크레이트를 만들거임 ironrdp 의존 안 하고, 그게 어딘가에는 적혀있어야
한다"*. **This is a scope decision, and reversing it is theirs**; the evidence above is why it is
coherent, not why it is compelled.

## Consequences

- **ADR-0003's phase-3 exit criterion is no longer sufficient on its own.** "100% of oracle
  comparisons" remains a useful bar where the oracle is capable; it stops being *the* bar. Each
  codec's issue states which basis retires its oracle.
- **ADR-0007 keeps its method and loses its permanence.** Stage-boundary verification against
  the oracle's primitives stays exactly as specified — that is real independent math — but its
  *"the oracle crates remain dev-dependencies only"* now reads as a scope statement, not a
  duration.
- **Progressive is the first codec to exercise this**, because it is the first where the oracle
  demonstrably cannot decode real traffic (#194).
- **The runtime half is closed and the development half is not.** `ironrdp-graphics` left the
  runtime graph entirely in #189 (2026-08-19 amendment); it remains a **dev-dependency** of
  `justrdp-codecs`, as does `ironrdp-pdu` of `justrdp-pdu` and `justrdp`, and each retires on
  that codec's or layer's own owned basis. No new tracker structure is created by this record.
- **The `ironrdp-pdu` dev-dependency in `justrdp-pdu` is in scope too.** It is the differential
  oracle for wire round-trips (`tests/differential_ironrdp.rs`), the same instrument in a
  different layer, and the same retirement condition applies: an owned basis, then drop.
- **A cost is accepted.** Removing the oracle removes a real safety net on codecs where no
  real-server corpus is obtainable — CAVIDEO RemoteFX is the standing example (ADR-0007
  §Consequences: *"synthetic-only verification is an explicit ceiling for codecs the VM never
  emits"*). For those, the oracle stays until an owned basis exists, and the honest answer may
  be "not yet".

## Rejected alternatives

- **(A) Keep the oracle as a permanent dev-dependency and treat its defects as noise.** Rejected:
  the instrument is already wrong on the live path, and a gate that cannot decode the traffic
  the product must decode is not measuring the product. Keeping it also leaves the retirement
  question permanently unasked, which is how ADR-0004's `[patch.crates-io]` bridge outlived its
  own condition by six weeks.
- **(B) Fix the oracle upstream and keep depending on it.** Rejected as the *governing* strategy,
  not as a courtesy: an upstream fix helps everyone and may still be worth sending, but making
  this project's correctness bar depend on another project's release cadence reintroduces the
  coupling `CONTEXT.md` §Project intent exists to remove. It is also not one defect — findings 2
  and 3 above are a disagreement between references and an unimplemented flag, neither of which
  an upstream patch resolves.
- **(C) Drop the oracle immediately, everywhere.** Rejected: the oracle is genuinely independent
  math for the transform stages, and for codecs with no capturable real-server stream it is
  currently the only external check. Retirement is per codec, on evidence, not a flag day.
- **(D) Record this in the issue tracker only.** Rejected — and it is what prompted this record.
  #194 states the consequence for one codec; the position it follows from spans ADR-0002,
  ADR-0003 and ADR-0007, and an issue structurally cannot hold a rule that spans decisions.
