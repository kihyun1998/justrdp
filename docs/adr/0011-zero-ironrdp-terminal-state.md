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
  exists (#171/#172), and the canaries are what use it.
- **Amendment (2026-08-18, #168): the oracle's reach extended into the owned basis itself.**
  Slice 2 measured a **fifth** oracle divergence — its SRL state starts at `kp = 0` where
  FreeRDP's starts at `8` (`progressive.c:1272`, unchanged since 2.11.7), so the two
  desynchronise on the first symbol of every component, ahead of the three divergences #194
  named. The finding that matters for *this* record is where it was found: five of the eight
  hand-derived FreeRDP vectors had themselves been computed at `kp = 0`, so the basis built to
  be independent of the oracle had silently adopted its initial state. Re-deriving them
  reproduced the claimed values exactly at `kp = 0`, which is what identified the cause. The
  Decision is unchanged and the argument for it is stronger: an instrument that shapes even the
  expectations written to replace it is scaffolding whose removal has to be *scheduled*, not
  left to taste. Promoted to
  [`oracle-agreement-is-not-independence`](../map/invariant/oracle-agreement-is-not-independence.md)
  as a third violation shape.
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
   is self-owned. The remaining holders are RemoteFX Progressive (epic #158, slice #172) and
   zgfx (#189). When both land, the runtime graph is `justrdp → { rustls, sspi }`.
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
- **Two dependencies remain to retire, and both are already tracked**: `ironrdp-graphics` at
  runtime by #172 and #189, and the dev-dependency per codec by each codec's own basis. No new
  tracker structure is created by this record.
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
