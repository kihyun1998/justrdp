# justrdp MAP — the dependency graph

The layer that answers two questions no other artifact in this repo can:

1. **Horizontal — *if I touch this, what else moves?*** → open the **territory**
   note for the area you are in and read its `## Blast radius`. It is a
   **checklist**: opening a listed territory and finding nothing to do is a correct
   outcome; not opening it is the failure this layer exists to prevent.
2. **Vertical — *what design is this code derived from, and what decision is that
   design derived from?*** → `## Design model` (the rules in force) and
   `## Governing decisions` (the ADR that decided them). A blank
   `## Governing decisions` is not an omission — it is the answer.

The ADRs are indexed by the day a decision was contested, `docs/plan.md` by the
build order, the issues by the work that shipped. None of them is indexed by
**territory**, and none survives its event. That is the gap this fills.

## Reading protocol

- **Read before the design, write after the change.** In
  [`docs/agents/theflow.md`](../agents/theflow.md) the map is Step 1's third ledger
  — opened *before* the boundary is drawn — and swept at Step 6. Reaching for it at
  Step 5 turns everything it would have told you into rework.
- **Step 5's lens brief starts here.** A territory's `## Blast radius` is the
  sibling set for corpus ①, and its `## Cross-cutting invariants` are the facts that
  hold beyond the territory you are standing in. The bindings doc no longer
  hand-lists either; this is the only copy.
- **Two obligations when you land a change**, and the second is what makes the map
  preventive rather than archival:
  1. **Coverage** — is the territory present, and is its blast list still right?
     Coverage may lag.
  2. **Promotion** — *is the fact this fix revealed also true outside this
     territory?* Answer it by grep, in this repo's terms: *"does this hold at any
     site that sizes a buffer from server-declared dimensions / that parses
     untrusted lengths / that forwards pixel data?"* If yes, the change does not
     land until an `invariant/` note exists. Promotion may **not** lag — the first
     site to hit a fact is where it is discovered, and at that moment no node exists.

## Why this layer exists here (measured, not asserted)

Four facts in this repo were each discovered **more than once**, at sites that do
not call each other:

| Fact | Rediscovered at | Cost of no home |
|---|---|---|
| 32-bit dimension overflow | #151 (pointer) → #155 (rle/planar/color) | the same expression, four sites, two discoveries |
| Frame path carries no owned pixels | #85 (design) → #162/#165 (`FrameUpdate`) → #163/#166 (EGFX blit) | three layers, each found after the previous fix |
| Untrusted decode never panics | #98 (proptest) → #99 (fuzz) | one property, two automations |
| Oracle agreement ≠ independence | ADR-0007 amendment #118 → #127 (ClearCodec) | the oracle *lost* an argument it was assumed to win |

Each is now an [`invariant/`](invariant/) note carrying its own discovery history and
a recurrence test.

## What the map cannot answer

- **Only `.md` files in this repo are nodes.** Issues, epics and source files are
  *text inside* notes, never nodes — so the graph cannot show you the hottest things
  in this repo (epics #10–#29, #45, #158) as first-class objects.
- **There is no verified external-fact store.** `## Reference behaviour` is
  `**None.**` in **every** territory: no FreeRDP/IronRDP behaviour is recorded
  anywhere with a pinned `file:line`, although
  [`docs/agents/theflow.md`](../agents/theflow.md)'s tie-breaker table depends on
  exactly that comparison. This is the map's single largest finding, and it is a
  measurement, not an opinion.
- **The map does not track what is not built.** `## Known holes / open` names the
  gaps per territory; the **live roster of unbuilt work is the tracker** — the
  `epic`-labelled issues (decided 2026-08-10, when the two homes were found to
  disagree). `docs/plan.md` §22–§23 (~294 lines, 16% of that file) is the *audit that
  produced them*, kept as a dated snapshot and deliberately not updated as work lands.

## Measurements (M1–M5, taken 2026-08-10)

- **~700 public items** across four crates (`justrdp-pdu` alone: 499, of which 255
  are `pub const`), governed by **10 ADRs**.
- **"surface" appears in 9 of 10 ADRs and is the subject of none.** `session` 7/10,
  `connect` 5/10, both subjects of none. `cursor` and `clipboard`: 0/10.
- **The adapter is 1032 lines of code** (3623 with tests) — the crate where every
  concern the sans-IO core refuses ends up, and the largest file in the repo.
- **A removal obligation outlived its tracker by six weeks.** `Cargo.toml`,
  `.github/dependabot.yml` and ADR-0004 all named the **closed** #61 as the
  `[patch.crates-io]` removal tracker, while ADR-0004's own amendment asserted the
  bridge did not exist — so nothing greppable disagreed. Found by this map's first
  measurement pass; the bridge was removed on 2026-08-10.
- **The `~30-line adapter` claim was false and is now fixed** — it is 1032 lines of
  code (3623 with tests); "~30 lines" was true of the drive loop only, and shipped to
  docs.rs. Corrected in `CLAUDE.md` and `justrdp/src/lib.rs` when this map landed.
- **Fuzzing covers half its surface**: 10 targets, all codec/capability/license;
  13 wire parsers in `justrdp-pdu` have none.

## Conventions

- **Territories overlap on purpose.** A fact that holds in three places is an
  invariant note, not a row forced into one territory.
- **Empty sections stay.** `**None.**` is a greppable answer; deleting the heading
  destroys the finding.
- **Symbols under `## Code`, never line numbers** — a line number is an ungated copy
  of something the compiler owns.
- **Plain relative markdown links**, not wikilinks: GitHub renders only the former,
  Obsidian resolves both.
- **Derive lists that a tool can see; hand-write only what it cannot, and label
  which is which.** Where a note carries a `rg` command, that command is the list.
- **The map links out only.** Never edit an ADR to add a backlink.

## Nodes

Territories: [x224-negotiation](territory/x224-negotiation.md) ·
[tls-transport-security](territory/tls-transport-security.md) ·
[nla-credssp](territory/nla-credssp.md) ·
[mcs-gcc-channel-setup](territory/mcs-gcc-channel-setup.md) ·
[capability-exchange-activation](territory/capability-exchange-activation.md) ·
[licensing](territory/licensing.md) ·
[session-loop-dispatch](territory/session-loop-dispatch.md) ·
[framebuffer-frame-delivery](territory/framebuffer-frame-delivery.md) ·
[egfx-graphics-pipeline](territory/egfx-graphics-pipeline.md) ·
[bitmap-codecs](territory/bitmap-codecs.md) ·
[pointer-cursor](territory/pointer-cursor.md) ·
[input-scancodes](territory/input-scancodes.md) ·
[virtual-channels](territory/virtual-channels.md) ·
[wire-framing](territory/wire-framing.md) ·
[pdu-constants](territory/pdu-constants.md) ·
[adapter-drive-loop](territory/adapter-drive-loop.md) ·
[verification-harness](territory/verification-harness.md) ·
[supply-chain-and-gates](territory/supply-chain-and-gates.md)

Invariants: [decoder-dimension-overflow-32bit](invariant/decoder-dimension-overflow-32bit.md) ·
[untrusted-decode-never-panics](invariant/untrusted-decode-never-panics.md) ·
[frame-path-carries-no-owned-pixels](invariant/frame-path-carries-no-owned-pixels.md) ·
[oracle-agreement-is-not-independence](invariant/oracle-agreement-is-not-independence.md)

**The graph is gated.** `python .github/scripts/check_map.py` (CI: `test.yml` job
`map`) checks that every link and `#anchor` resolves, that every symbol and path under
`## Code` exists, that each note carries its full section set, and that every territory
an invariant claims claims it back. Anchors are the half that fails *silently* — a
missing one falls back to the top of the target document — and the reciprocity check
found four one-way edges on its first run.

**No roster table here on purpose** — "which node is governed by what" lives in the
notes and would rot within days as a second copy. Ask instead:

```sh
# scope every sentinel query to its heading — the same sentinel marks three different holes
rg -lU '## Governing decisions\r?\n\r?\n\*\*None\.\*\*' docs/map/territory/   # nobody decided
rg -lU '## Reference behaviour\r?\n\r?\n\*\*None\.\*\*'  docs/map/territory/   # nobody checked
rg -lU '## Code\r?\n\r?\n\*\*None\.\*\*'                 docs/map/territory/   # nobody built it
ls docs/map/territory/ docs/map/invariant/                                     # the folder is the roster
```

## Coverage

**Complete for what is built**, as of 2026-08-10: 18 territories covering the
connect sequence, the session loop, the graphics path, input, channels, the wire
layer, the adapter, verification and the supply chain. Unbuilt protocol areas
(clipboard, audio, redirection, drawing orders, RD Gateway, H.264, multi-monitor…)
have **no territory** — they live as `epic` issues in the tracker (the roster), with
`docs/plan.md` §22–§23 as the audit snapshot behind them, and a territory appears when
the first slice lands.
