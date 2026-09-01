# thegraph build (justrdp)

The compiled graph for the `thegraph` skill: which nodes this repo has, how many,
what each one's guard and decider are, and which of them are extracted as agents
and scripts. `thegraph` holds the portable **method** (node-type catalog, four
invariants, reasoning habits); this file holds justrdp's **graph**. The method
defers every concrete value here.

**Build stamp** — built from the `thegraph` skill, which is now **three files**, not one:

| File | md5 | bytes |
|---|---|---|
| `thegraph/SKILL.md` — the method: invariants, catalog, habits, traversal | `f73cef09189056e3ed7713a81177becc` | 41 951 |
| `thegraph/NODES.md` — the per-node contracts (**new since the last stamp**) | `82d1538acc2c35dd2fbcb3cecded3f66` | 45 572 |
| `thegraph/BUILD_CONTRACT.md` — the schema this file fills (**new since the last stamp**) | `a4fc95f7e6d1605869a33e8c2bafb2c6` | 9 231 |

Measured 2026-09-02. Recompiled 2026-09-02 by `/grill-the-graph` as an **update** —
diffed against the repo and against the `build_gaps` past runs flushed, *not* recompiled
from the bindings, which the first build consumed. Every generated artifact carries the
same stamp. If the stamp is behind, **warn and continue** — never rebuild on your own; a
rebuild writes agents and scripts, and those pass through the maintainer.

**A one-file stamp is what let two-thirds of the method move unseen.** The previous stamp
named `SKILL.md` alone at 77 920 bytes. The method has since been **split**: `SKILL.md` is
now smaller than that number while the method as a whole is larger, so a check comparing
one size against one file could report either "behind" or "ahead" and neither would
describe what happened. Stamp all three or the check answers a question nobody asked.

**What this recompile measured, so nobody re-derives it.** Nine findings; two of them are
repairs to this build's own artifacts and one is a finding that fixed itself upstream.

① **Invariant ① was violated by all four generated agents — and this build is the
incident the method now records as its war story.** All four carried `Bash`, none carried
a `Runs:` declaration, and `thegraph-sweep` carried `Edit` besides. Read-only is now the
**default** rather than a claim to be matched: only an explicit declaration naming a tool
moves one. Repaired in the [extraction plan](#extraction-plan) — `thegraph-reference`
keeps `Bash` **with** a declaration (its source classes are `curl` / `gh api`, and
`WebFetch` is banned for summarizing); the other three drop everything that can run or
write.

② **The check that enforces ① did not exist.** A grant wider than a brief is invisible to
every other gate — it compiles, tests green and lints clean — so
`scripts/thegraph/grants.py` is generated and joins the `gate` list, which goes **9 → 10
commands**. It asserts the **default**, never the claim: an agent whose description reads
*"proposes edits rather than making them"* passes a check that greps for *"read-only"*.

③ **`build_gaps` recurred #263 → #268, and that is why this run happened.** The `proof`
table's `justrdp` row named a real-VM round-trip, which a conforming server structurally
cannot use to prove a *refusal* of non-conforming input. Two runs substituted two
different things by judgement. `proof` gains a **claim-class axis** on that layer
(conformance / refusal / performance); the layer count stays **4**, exactly as when #250
added the performance class.

④ **The four `unowned` slots are resolved upstream — the coverage check now returns
zero.** `BUILD_CONTRACT.md` names the tracker capability and the war-story index outright,
and generalises node data to *"everything it reads and everything it checks against … its
method, its traps, and the policies it applies to a surface"*, which places the other two
without naming them. **No value in this file changed as a result**, which is the shape the
split itself predicts.

⑤ **`verify`'s exit-2 prose had drifted against its own script.** It prescribed a
`build_gaps` entry for an empty diff; #252 had since made `2` the script's *designed,
documented* answer for that case. So the build was requesting a re-grill for a question it
already answers, and every open-decision run filed one — #268 did. Prose corrected; the
script is unchanged and correct.

⑥ **`reference` said 4 in the roster and 5 in its own section.** `plat` added class 5
(layout prior art) and neither the roster row nor the artifact row followed. It is **5**.

⑦ **`crates/*/tests/*.rs` is 15, not 16.** The rule held — all fifteen are differential
or corpus — only the count moved.

⑧ **The skill files changed twice *during* this run** (`NODES.md` grew 42 741 → 45 572
bytes between two measurements minutes apart). The stamp above is a point-in-time
measurement, and a mismatch on the next run is the expected case rather than evidence this
build was wrong. It is a **warn**, never a rebuild trigger.

**Re-measured and unchanged, so not re-asked**: ADRs still 0001–0013 (the `search` list is
current) · 5 workflows, 4 of them gates · `gates.py` holds every command this file names ·
every sacred path still resolves to a real file · `crates/justrdp-codecs/src/rfx/mod.rs`
is still the single module-root spelling outlier, still a separate change · no `benches/`,
no `[[bench]]`, no `criterion`, so #250's bench-harness half stays deliberately open ·
nothing published, so `downstream` stays **absent** · the sub-issue relation is live
(#270 and #271 enrolled under #268).

---

## Node roster

| Node | Count | What decided it |
|---|---|---|
| `classify` | 1 | catalog |
| `spine` | 1 | catalog. The tracker **has** the relation — see *Tracker capability* |
| `map` | 1 | the bindings name a territory map: [`docs/map/README.md`](../map/README.md) |
| `reference` | **5** | 3 routing-table rows naming an external source, **+ the real VM** as its own class, **+ layout prior art** (`plat`'s confirmed peers) — all five below |
| `enumerate` | 1 | catalog. **Never delegated** |
| `boundary` | 1 | catalog. **Never delegated**. The seam is in-repo — see *Boundary rule* |
| `place` | **1** | catalog — **every repo has a tree**, so no input can zero this out. **Never delegated.** Tree rule below, compiled by `plat` against four confirmed peers |
| `implement` | **4** | one per claim class in Step 4's proof table |
| `proof` | **4** | one per claim class, each with its own method and its own blind spot |
| `verify` | **2** | 1 gap-hunting + 1 refuting, because the sacred-path list is **non-empty** |
| `sweep` | 1 | fanning out over **6** surfaces |
| `gate` | 1 | **8** gates / **10** commands, blind spots included |
| `search` | once per candidate | catalog |
| `batch` | 1 | catalog. **Never delegated, never bypassed** |
| `stop`, `decide` | edge-triggered | catalog |
| `promote` | 1 | a decision-record format exists and is named as the destination: `docs/adr/NNNN-<kebab>.md` |
| `downstream` | **0** | **Nothing is published to crates.io and there is no in-repo consumer seam.** Not skipped — absent. **Reversal event: the first crates.io publish.** At that moment derive the consumer list on the spot (grep the sibling manifests for the crate name) and never store it — here or anywhere |

**What the `downstream` absence takes with it**, all N/A on the same ground and
each recorded so no run goes looking: the SDK-floor / compatible-range constraint,
the two-consumer signal, the report-upstream duty, the after-merge downstream
migration, and Step 4's *"link into a real consumer"* proof (its fifth row). The
`boundary` node still exists — the seam is in-repo.

---

## Per-node data

### `reference` — 5 source classes, routed by `change_type`

| # | Class | How it is reached | Summarized? |
|---|---|---|---|
| 1 | **`[MS-*]` normative specs** — `[MS-RDPBCGR]`, `[MS-RDPRFX]`, `[MS-RDPEGDI]`, `[MS-RDPEGFX]`, … Governs **what we emit**: layout, flags, state transitions. Cite the section number | `curl -sL "<learn.microsoft.com/…>" > "$SCRATCH/spec.html"`, then `grep -n`. The WebFetch ban is on **summarization, not on the web** — same pattern as class 2 | **raw** — may reach `CONFIRMED`. If the fetch fails, **downgrade this run explicitly**; never a silent `CONFIRMED` |
| 2 | **FreeRDP (C) + IronRDP (Rust) real source** — hidden state, server tolerance, edges, the CVE points. Spec-unwritten tolerance exists **only** here | `gh api repos/<owner>/<repo>/contents/<path> --jq .content \| base64 -d > "$SCRATCH/x"`, then `grep -n` / `sed -n`. **`WebFetch` is banned** — it drops handler bodies from large files, so a decoder branch that *is* there reads as absent | **raw** |
| 3 | **Published / external state** — crates.io, the upstream repo's own state | a registry query / `gh api`, never a sentence about them | **raw** |
| 4 | **The real VM** — `192.168.136.136` (memory `test_environment`). The authority for **what we accept** | a **throwaway probe**: instrument, read the number, delete the probe, **record the number in the issue**. Reading the code is not observing what it does. **And a probe whose output is server-to-client bytes outlives the probe** — the number-in-the-issue form is the floor, not the ceiling. `JUSTRDP_CONNECT_CAPTURE_FILE` (`justrdp-tokio`, adapter-side) records the read path only, so a capture carries no credential and is **committable**; #252 captured the finalization leg, committed 156 bytes as a fixture and walks it with the shipped parsers, turning a one-run observation into a standing test. Prefer that whenever the fact is server-to-client. **What a fixture still cannot do**: a conforming server cannot redden a guard that only fires on non-conforming input, so its discriminating power is over *false positives* — name which assertion observes the change and mutate **both** ways before recording it (#252 ran both) | **raw observation**. Caveat carried on the node: it is **one WS2022 box** (memory `vm_advertised_graphics_caps`) — it proves the paths it advertises and says nothing about the ones it does not. *"The VM is happy"* is not *"servers are happy"* |
| 5 | **Layout prior art** — the maintainer-confirmed peer packages `quinn-proto` / `quinn` / `quinn-udp`, `ironrdp-pdu` / `ironrdp-graphics` / `ironrdp-tokio`, `rustls`, `h2` (hyperium). Governs **where a file goes** and nothing else. `place` **reads** this class; it never fetches it | `gh api repos/<owner>/<repo>/contents/<path>` against the **real tree**. A layout read off a documentation site, a blog post or a starter template is **summarized** and can never confirm anything; a repository's actual tree can | **raw**. **Their trees are never stored** — the rule is kept here, the peers are kept by name, and the contents are read again when acted on. A stored copy of somebody else's tree is a derivable fact that rots |

**Not a source class**, and recorded so no run re-derives it: *performance claims*
resolve to **our own measurement on a `--release` build** — that is the
tie-breaker, not prior art. And **"Concept ≠ mechanism"** is a *reading rule over
classes 1 and 2*, not a fifth class: a codec we newly own may be absent from
IronRDP while its components (bit reader, tile boundaries, colour conversion,
sub-band layout) exist in FreeRDP and in the spec. Read **both**. A feature being
"new" never justifies skipping the mechanism reference.

**Derive, don't copy** (ADR-0003) — re-derive from the spec and prove by
differential test, never by structural similarity. **Spec ≠ interop**: code
matching the spec can still not be byte-identical to a real server.

### `map` — [`docs/map/README.md`](../map/README.md)

Read **before `boundary`** — reaching for it at `verify` turns everything it would
have told you into rework. Per territory: `## Blast radius` (what else moves when
you touch this — opening one and finding nothing to do is a correct outcome),
`## Cross-cutting invariants`, `## Governing decisions`, `## Known holes / open`.
`ls docs/map/invariant/ docs/map/territory/` is the roster — this line carried the two
counts and they rotted the day #252 promoted a note, which is the failure
[`docs/map/README.md`](../map/README.md) already records against itself ("a count written
here is a copy that rots"). Add `docs/plan.md` §0 (traps already PROVEN
on the real VM — do not re-discover) and §1 (capability → feature coupling).

**If no territory matches, that is an exit this node owes an answer for — and the
hub already has it.** [`README.md` § *Coverage*](../map/README.md#coverage) settles
which of the two it is: an **unbuilt** protocol area correctly has no territory
(clipboard, audio, redirection, drawing orders, RD Gateway, H.264, multi-monitor —
their roster is the `epic`-labelled issues, and *"a territory appears when the
first slice lands"*), while code you are changing that nobody mapped is a
**finding**, and this change's rather than the backlog's, because you are the first
person standing there with the evidence. It does not block — coverage may lag
(`sweep` surface 3 ①) — so it is carried as a candidate to `batch`, never written
unasked. Two shapes to distrust before reading an empty result as clean: your
**search** may be what was empty (search by artifact — the PDU, the field, the
capability — never by feature name), and the **invariant** half does not lag at all
(`sweep` surface 3 ②, which blocks).

**Where the hidden-state list lives** (`enumerate` reads this): VM-observed traps
→ `docs/plan.md` §0. Per-territory state → the map's `## Design model`.
Cross-territory facts → an [`invariant/`](../map/invariant/) note, each carrying a
`## Where it will recur` test, which *is* the enumeration. Per-codec state the map
does not yet name (tile boundaries, quant tables, progressive pass state,
palette/run state) → into the issue **before** implementing.

### `place` — the tree rule, as concrete paths

Runs **before `implement`**: a directory boundary is where the seam is *physically*
expressed, so a file written to the wrong one breaks the seam while producing no
error, no failing test and no warning — and read *after* the code is green,
everything it would have said arrives as rework. **Decider AI, never delegated** —
choosing between the tree rule and what the peers do is adjudication.

Compiled 2026-08-31 by `plat` against four **maintainer-confirmed** peers (source
class 5). A declared rule outranks what the tree merely looks like — and here the
two never conflicted: the declared dependency boundary has **zero violators**, and
measurement is *stricter* than the declaration. `justrdp-codecs` has **no external
dependency at all**, and the four crates depend only downward. `CLAUDE.md`'s
"sspi·rustls live in the adapter" is a lossier statement of a rule the code already
keeps.

| Path | Owns | Grounds |
|---|---|---|
| `crates/justrdp-pdu/src/*.rs` | one file per `[MS-*]` protocol area — bytes↔types only. **Zero external dependencies** | ADR-0001 / ADR-0002, measured 0 violators |
| `crates/justrdp-pdu/src/<area>/` | a protocol area that outgrew one file. Module root is **`<area>.rs` beside it** | spelling rule below |
| `crates/justrdp-codecs/src/*.rs` | one codec per file — **pixel math only**. Depends on `justrdp-pdu` and nothing else | ADR-0003 / ADR-0007, measured |
| `crates/justrdp-codecs/src/<codec>/` | a codec that outgrew one file | spelling rule below |
| `crates/justrdp/src/*.rs` | the sans-IO state machines and the host-facing output types. **No `tokio`, no `rustls`, no `sspi`** | ADR-0001; measured: `x509-cert` + `tracing` only |
| `crates/justrdp-tokio/src/*.rs` | **the only place `tokio`, `rustls`, `sspi` or `ring` may appear.** Policy injection | ADR-0002, measured 0 violators |
| `crates/*/tests/*.rs` | **differential-oracle and real-corpus tests only.** Unit tests stay inline `#[cfg(test)]` | measured **15/15** (16/16 at the previous build; the rule held, the count moved) |
| `crates/*/tests/fixtures/<name>/` | captured real-server bytes plus a `README.md`. Appears **only** in a crate whose tests replay them | which is *why* `crates/justrdp/tests/` has none — both its tests are differential |
| `crates/*/proptest-regressions/` | generated. Never authored | — |
| `fuzz/fuzz_targets/*.rs` | fuzz targets, **out of the workspace** | matches 3/3 peers that run a fuzz lane |
| `.github/workflows/*.yml` · `.github/scripts/*.py` | things that **are** CI gates | — |
| `scripts/thegraph/*.py` | scripts this graph runs **locally**, never in CI | the split from `.github/scripts/` is deliberate |
| `.claude/agents/thegraph-*.md` | generated graph agents | extraction plan |
| `docs/adr/NNNN-<kebab>.md` · `docs/agents/*.md` · `docs/map/territory/<area>.md` · `docs/map/invariant/<claim>.md` | decision records · agent contracts · the wiring map | — |

**Module-root spelling: `<area>.rs` + `<area>/`** (the 2018 form), decided
2026-08-31 **because the evidence could not decide it**. The repo held exactly two
directory modules and one of each form; the peers disagree (IronRDP, rustls and h2
use `mod.rs`; **quinn mixes both** — `config/mod.rs` beside `congestion.rs` +
`congestion/`). Majority is evidence, not authority, and where neither it nor a
measured reason settles a difference the call is the maintainer's. The single
outlier is `crates/justrdp-codecs/src/rfx/mod.rs`; **the move is a separate change**,
because a move made before the rule is written drifts straight back.

**Three suspected splits dissolved under a content sort**, recorded so nobody
re-opens them by reading filenames. `pointer`/`cursor` across three crates sorts
**4/4** on role — wire fields (`justrdp-pdu/src/pointer.rs`), the byte reader
(`justrdp-pdu/src/cursor.rs`), pixel math (`justrdp-codecs/src/pointer.rs`), host
type (`justrdp/src/cursor.rs`). The two `cursor.rs` are a **name collision between
different roles**, which is the difference that bites and is not drift. `rfx` living
in both `justrdp-pdu` and `justrdp-codecs` sorts **2/2** — block framing versus
pixel math, exactly as ADR-0003 declares. And `crates/justrdp/tests/` lacking a
`fixtures/` directory is a *consequence* of the fixture rule, not an exception to it.

**Out-edge to `decide`. Guard: the change needs a new top-level area**, or the tree
rule and the peers disagree and no tie-breaker settles it. Both are structure calls.
**Writes `triggers`** when the same placement is argued twice — a tree rule being
re-decided is a record waiting to be written, and `promote` counts it.

**Guard mechanism**: `scripts/thegraph/place.py`, decider `code` — the tree rule is
a path list and a diff is a path list, so the check is a match, not a recollection.
Prose alone would make this node a bar with no firing mechanism, which is the exact
defect its own argument is against.

### `implement` / `proof` — 4 layers, each with its own blind spot

| Layer | Real proof | What this proof structurally cannot see (the tautological trap) |
|---|---|---|
| **`justrdp-pdu`** | `encode → decode` round-trip on hand-built PDUs **plus** the proptest no-panic / round-trip properties (ADR-0008, #98) | A decoder that only ever sees vectors *we* authored is untested against the input space a server spans — **narrowed but not closed since #203/#252**: `tests/fixtures/connect/` now holds real server bytes for the MCS/GCC leg *and* the finalization leg, obtained rather than synthesised, because every encoder in this crate writes client-to-server. And **a census can be blind to a whole class**: #241/#238 — the no-panic census's derivations were byte-scoped and path-scoped, so one could not see a parser in the core and neither could describe a consumption site at all. Both classes held live defects |
| **`justrdp-codecs`** | a **differential oracle** (ADR-0003/0007): same bitstream to *our* decoder **and** `ironrdp-graphics`, assert the output `Vec<u8>` is **byte-identical**. Stage-boundary verification applies **per pipeline stage**, not only end-to-end. 100% pass is the gate to drop the dependency (ADR-0011) | **The oracle shares our lineage** (memory `ironrdp_oracle_shares_lineage`, [the invariant](../map/invariant/oracle-agreement-is-not-independence.md)) — byte-identical agreement is **not** independence; cross-check FreeRDP before calling a match "proof". **A vector proves only what it contains**: a corpus can supply an axis and miss the *combination* (a codec exercised, but never at a tile boundary, never with a quant table that changes mid-frame) — measure what the fixture exercises, never infer coverage from what it was named for. **x64 cannot reach the 32-bit guards** (memory `wasm32_overflow_proof_via_i686`) |
| **`justrdp` (connect / session)** | a **real VM** round-trip — the full connect sequence to session-active, not a mock server | **One VM is one server.** It can prove the paths it exercises (#150/#91) and cannot speak about caps it does not advertise |
| **`justrdp-tokio`** | the same VM, driven end-to-end. Its integration tests are `#[ignore]`d in CI **by design** (they need the VM), which is why `coverage.yml` excludes this crate | **A demo or a fake is a smoke test, not proof** (DoD ④). Coverage silence here is expected, so it cannot be read as a signal either way |

Step 4's fifth row — *"strongest: a real consumer"* — is **N/A, no consumer
exists**, so it is not a layer. See the `downstream` roster row for the reversal.

**The `justrdp` row above answers a *conformance* claim and structurally cannot
answer a *refusal* claim** — a conforming server cannot produce non-conforming
input, so the VM is unable to exercise a guard that only fires on input it will
never send. Recorded because it recurred: **#263** substituted the codecs row's
32-bit rule by judgement, **#268** substituted a wire-format round-trip, and two
substitutions in a row is a re-grill request rather than a one-off. The layer count
stays **4** — like performance, this is a claim-class axis and not a fifth layer.

| Claim class on `justrdp` | Method | The trap it still carries |
|---|---|---|
| **conformance** — we speak the protocol a real server speaks | the **real VM** round-trip, full connect to session-active | **one VM is one server**: it proves the paths it advertises and nothing about the ones it does not |
| **refusal** — we reject what no conforming server can send | a **wire-format round-trip through the public entry point**: build the non-conforming PDU as bytes (`wrap_uncompressed` + header + body) and drive it through `GraphicsProcessor::process` / the public session API — **never a mock and never the private method**. **Plus mutate-and-re-run on `i686-pc-windows-msvc` wherever the guard is arithmetic** — the `gate` command already names `-p justrdp-codecs -p justrdp` for exactly this, so the layer row now knows what the gate row knew | **the PDU is a vector *we* authored** — the `justrdp-pdu` row's trap recurring one layer up. It bounds false positives, not false negatives: the VM capture (`reference` class 4) stays the only authority on what a server actually sends |
| **performance** | unchanged — the isolate-first table below | timing the whole system to detect a component |


**The table above answers a *correctness* claim. A performance claim is a different
class, and it cuts across all four layers rather than adding a fifth** — so the layer
count stays **4**. Recorded because #91 arrived at this node with no method at all,
and **#250** is the flush that says so.

| For a performance claim | Why — measured on #91 |
|---|---|
| **Isolate before you time.** A component's share of the pipeline is itself a measurement, and it comes **first** | RLGR is **4.6%** of a corpus decode, which caps a 2x win at 2.3% — the question can already be closed before a stopwatch comes out |
| **Measure the workload's shape, not only its duration** | The verdict came from a histogram, not a timer: real streams have a **mean run length of 1.0 bits** (66.7% of runs zero-length, 0.01% reaching 64) |
| **State the noise floor with the number** — repeat on the same build and report the spread | Four runs of the *same* build spanned 298 / 308 / 322 / 327 ms. A single before/after pair across a **9.6%** instrument is not evidence |
| **The probe is a throwaway**, `--release` only — instrument, read the number, delete the probe, record it in the issue | `reference` class 4's rule, which held once it was reached. Nothing *routed* a perf claim to it, and that was the gap |

**Its tautological trap, and it was not among the ones this build already named:**
**timing the whole system to detect a component.** 300 101 µs before against
298 099 µs after read as *"a wash"* and was noise — *a measurement that cannot
resolve its own effect is indistinguishable from one that found nothing.* The
synthetic micro-benchmark that followed resolved cleanly and still only *bracketed*
the answer (1.93x faster on long runs, 6–12% slower on dense symbols), because
neither shape was known to be the real one. Only isolation plus the distribution
decided it.

**No bench harness exists** — no `benches/`, no `[[bench]]`, no `criterion` — and
that stays **deliberately open in #250**, not answered here. `plat` measured that
**all four confirmed peers have a dedicated bench location** (`quinn/bench` +
`perf`, `rustls-bench`, `h2/benches`, `ironrdp-bench`), which is evidence for one and
does not outrank ADR-0002's argued dependency list. Until it is decided, `benches/`
is **not** in the tree rule, and a performance claim is proved by throwaway probe.

**Test-trust gate** (`implement`'s self-loop, decider `code`) has three
justrdp-shaped traps for the discriminating-power bar: a **differential-oracle test
can be green for the wrong reason** (a vector both implementations decode
identically proves agreement, not correctness); **a guard only 32-bit reaches
cannot go red on x64** — mutate and re-run on `i686-pc-windows-msvc` (#151/#155),
or the RED you never saw is on a target the gate never ran; and — found by **#252** —
**adding an exact-match gate to a parser silently kills its own no-panic property's
reachability**. `messageType == SYNCMSGTYPE_SYNC` put the read behind it at **1/65536**
under `vec(any::<u8>(), 0..=512)`, ~0.03 hits per 2048-case run, so an out-of-bounds read
there would have shipped green. [untrusted decode never panics](../map/invariant/untrusted-decode-never-panics.md)
states the rule and calls four instances *"a rule rather than a story"*; this was the
fifth, added in the module whose own comment enumerates *"a `messageType` dispatch"* among
the four. **Adding a guard is a generator change**, and the mutation has to be *watched* to
redden rather than asserted — weight the generator, never substitute it.

### `verify` — sacred paths, as concrete paths

The inbound guard is a **script over the diff** (`scripts/thegraph/triggers.py`),
decider `code`. It **overrides judgement**: you do not reason your way out of it
because the diff looks small. Absent a path hit, the guard is enumeration risk
(`AI`) — many edges, domain semantics, cross-feature interaction. justrdp has **no
money path, no production mutation and nothing destructive**; here a path is
sacred when it is **silent** (wrong, and nothing crashes) or **irreversible**.

**The guard has a third answer, and it exists because a run needed it.** `classify`'s
**open-decision** route runs `verify` on the *options*, before any code exists — so the
diff is empty **by construction**, and *"no sacred path in the diff"* is not what is true
there. `triggers.py` answers an empty diff with **`2` (cannot answer)**, not `0`, which is
the code it already reserves for *"the script could not answer"*. Exit `2` is what makes
the substitution visible: the run resolves the guard by **reading the sacred-path list
directly** — against the paths the change is *about to* touch — and says which slot it
substituted for. Measured on **#252** — the script returned `0`, both lenses were in fact
mandatory (`crates/justrdp/src/**` is surface 1), and only the run's own judgement caught
it. A `code` decider resolved by judgement is invariant ④ pointing at itself.

**Exit `2` on an empty diff is not a `build_gaps` entry.** This section used to say it
was — and #252's fix then made `2` the script's *designed, documented* answer for exactly
that case, its docstring included — so the build was prescribing a re-grill request for a
question it already answers, and **every open-decision run filed one**. #268 did. Write a
gap only where reading the list directly is itself ambiguous: the paths the change will
touch are not yet knowable, or they sit outside every group. Exit `2` from a **non-empty**
diff is untouched by this — that is a real *"the script could not answer"*, and it does
carry a gap.

| # | Sacred surface | Paths the script matches | Why |
|---|---|---|---|
| 1 | **Untrusted-input decoders, parsers, and consumption sites** | `crates/justrdp-pdu/src/**` · `crates/justrdp-codecs/src/**` · `crates/justrdp/src/**` — **crate-level globs, deliberately over-broad** | Every byte comes from a server we do not control; a wrong bound yields plausible pixels or a panic (DoS), not an error. The derivation lives once, with [untrusted decode never panics](../map/invariant/untrusted-decode-never-panics.md) — **four commands since #262, having been three since #241/#238 and two before that** — each widening was bought by a class the previous set went blind on, ④ being the one ③ could not see because both halves ask about the same signature. The globs are broad **on purpose**: over-triggering costs one lens run, and every narrower derivation went blind on a real class. The continuous half of this axis is proptest (#98) + cargo-fuzz (#99), and the **fuzz lane is nightly-only**, so a *new* target is not covered by the PR gate on the day it lands |
| 2 | **The TLS trust decision** | `crates/justrdp-tokio/src/trust.rs` · `crates/justrdp/src/tls.rs` | ADR-0005, #36. Silent by construction: a wrongly-accepted chain produces a perfectly working session, and the host's whole security posture is this one decision |
| 3 | **The NLA credential path** | `crates/justrdp-tokio/src/lib.rs` (the CredSSP token loop) · `crates/justrdp/src/tls.rs` · `crates/justrdp/src/connect.rs` (the SPKI public-key binding it authenticates against, `x509-cert`) · **plus every `sspi` version bump** | ADR-0004 requires the real-VM suite for a bump. A wrong binding or token order can still complete a handshake |

**The second lens exists** because that list is non-empty, and it is bought with
**opposing stance over the same corpus** — not by splitting the material
(invariant ①). Both corpora go into **both** briefs: ① this repo's siblings, from
[`docs/map/`](../map/README.md) — the touched territory's `## Blast radius` *is*
the sibling set and its `## Cross-cutting invariants` carry the recurrence tests,
plus `docs/plan.md` §0; and ② the reference — FreeRDP and IronRDP real source at
the known CVE points (memory `rdp_decoder_robustness_refs`) and the `[MS-*]`
section governing the field. **A hand-kept sibling list is deliberately absent
from this file** — that is the thing that goes stale and disagrees.

### `sweep` — 6 surfaces

| # | Surface | How it is read / written |
|---|---|---|
| 1 | **`CONTEXT.md` glossary + `docs/adr/`** | The domain SoT, and a **write** surface: a change that falsifies a record's premise amends *that record* — a status note, a superseded-by line — in the same change. An ADR's Consequences must be **currently true** |
| 2 | **`docs/plan.md`** | Keep the slice's entry (§2–§23) honest; add to **§0** any trap the VM just proved |
| 3 | **[`docs/map/`](../map/README.md)** | Two obligations. ① **Coverage** — is the touched territory present, is its `## Blast radius` still right? (**May lag.**) ② **Promotion** — *is the fact this fix revealed also true outside this territory?* Answer by grep in this repo's terms: does it hold at any site that sizes a buffer from server-declared dimensions, parses an untrusted length, or forwards pixel data? If yes, **the change does not land until an `invariant/` note exists** (**may not lag** — #151→#155, #85→#162→#163) |
| 4 | **`Cargo.toml` dependency comments** | Each states *why* a crate is here and, where temporary, what ends it. Load-bearing and unchecked: the `sspi` fork-bridge comment outlived its condition by six weeks (ADR-0004 Amendment 2026-08-10) |
| 5 | **Rustdoc on the public surface** | Ships as the crate's API docs — the surface most likely to still describe the old behaviour, and often the last thing describing a fixed bug as a contract |
| 6 | **Recent rationale** — PR bodies, issues, ADR prose | **Reclaim what is now false.** A justification written earlier can be made false by a later change and nobody re-reads it. The surviving reasons are usually the transitive ones |

**Changelog: none.** No `CHANGELOG.md` and nothing published, so there is no
snapshotted release note that could disagree with a registry. **Revisit at the
first crates.io publish** — the same event that creates `downstream`.

**The cluster anchor is not on this list** — it is `spine`'s flush, not a separate
obligation. What lands there: the root **confirmed or falsified**, the numbers
measured, any new sibling **enrolled into the tree** (never announced in prose),
what is still open. The roster itself never goes in the body.

### `gate` — 8 gates, 10 commands, each run bare

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check --manifest-path fuzz/Cargo.toml           # out-of-workspace blind spot
python .github/scripts/check_map.py --selftest        # the gate's own defect kinds, first
python .github/scripts/check_map.py                   # docs/map: links, anchors, symbols, reciprocity
just-shield scan . --strict                           # ADR-0006; CI passes strict: true
rustup target add i686-pc-windows-msvc                # prerequisite, not ceremony (see below)
cargo test -p justrdp-codecs -p justrdp --target i686-pc-windows-msvc
python scripts/thegraph/grants.py                     # invariant ① over .claude/agents
```

**The runnable copy is `scripts/thegraph/gates.py`, and it is the one that
decides.** This block describes it. There were three copies until 2026-08-31 —
`theflow.md` Step 7 held the same list under the old structure — and that file's
retirement dropped the count to **two**, which is the safe number: a command change
touches the script **and** this block, and nothing else.

**Each gate bare, never piped** — a pipeline's exit status is the last command's,
so `test … | tail -1 && commit` always commits. **A gate you cannot fail is not a
gate.** That is why this node is a script. And **never move a threshold to turn a
build green**: real regressions come to rest just under the threshold.

Blind spots, each an answer rather than an omission:

- **`fuzz` is out of the workspace** (own `[workspace]`), so `cargo test
  --workspace` does not even *build* it — a public-API change needs its own
  `cargo check --manifest-path fuzz/Cargo.toml`.
- **Host vs target.** On x86-64 a wrapping `width * height * bpp` is merely a large
  number, so every other gate is green over the [dimension-overflow
  class](../map/invariant/decoder-dimension-overflow-32bit.md). The i686 command
  names **`-p justrdp-codecs -p justrdp`**, not codecs alone — two of the five
  territories the invariant names (EGFX surface allocation, the framebuffer) live
  in `justrdp`.
- **The `rustup target add` is a prerequisite, not ceremony.** A rustup target is
  per-toolchain, so ADR-0013's pin means a target added under the old default is
  absent under the pinned one — it had silently gone missing within a day of #235.
  `targets` is deliberately kept out of `rust-toolchain.toml` (the file is shared
  with the ubuntu runners).
- **The local gates mirror CI, and only because the compiler is pinned**
  (ADR-0013, #235): `rust-toolchain.toml` fixes an exact three-part version and CI
  installs it by naming no toolchain. Before #235 the host was three months behind
  the runner and a lint that failed the gate could not fire locally at all. **The
  residue this does not cover is OS** — the runner is `ubuntu-latest`, the host is
  Windows MSVC, so a platform-conditional path is uncovered.
- **The formatter and the linter are pinned with the compiler**, not separately:
  `rust-toolchain.toml` names `components = ["clippy", "rustfmt"]` at the exact
  channel, so `cargo fmt --all --check` means the same thing here and on the
  runner. There is no independent formatter pin to drift — the compiler pin is it,
  and it is Dependabot's `rust-toolchain` ecosystem that raises it.
- **The fuzz lane is nightly-only**, so a *new* fuzz target is not covered by the
  PR gate on the day it lands.
- **The grant check is a gate because nothing else could be.** A generated agent's
  tool grant is derived from its brief, and a grant wider than the brief is invisible
  to every other gate here — it compiles, it tests green, it lints clean. Invariant ①
  is enforced by `scripts/thegraph/grants.py` or by nothing. It runs offline over
  `.claude/agents/thegraph-*.md` and is the one gate that needs no toolchain.
- **`coverage.yml` is deliberately not a gate** — a cargo-llvm-cov discovery tool
  (#102), post-merge/dispatch, **no threshold**, scoped to the sans-IO core and
  excluding `justrdp-tokio` (its tests need the VM).

**CI confirmation**: 5 workflows, 4 of them gates — `test.yml` (jobs `test` and
`map`), `fuzz.yml`, `supply-chain.yml`, `overflow-32bit.yml` (**path-filtered** to
the three crates that hold the sites; a Windows runner bills at 2x and the class
only moves when the arithmetic does). Do **not** sit watching CI during
implementation — the local gates mirror it. Then: branch → commit
`feat(<scope>): … (#issue)` (**no `Co-Authored-By` / AI-attribution trailer** —
memory `feedback_no_ai_attribution_external`) → squash PR (`Closes #issue`) →
confirm CI green.

### `search` — areas that already carry a decision record

Checked **before** proposing an anchor, so a cluster with a home never gets a
second one. All **Accepted; none Proposed** (a *proposed* record does an anchor's
job by construction, so one would pre-empt an anchor — none does here).

| # | Area |
|---|---|
| 0001 | sans-IO state-machine core / crate split |
| 0002 | dependency boundary (+ codec-ownership amendment, #100) |
| 0003 | phased codecs & the differential oracle |
| 0004 | `sspi` contribute-and-bridge (#61) |
| 0005 | TLS trust policy (#36) |
| 0006 | supply-chain action pinning |
| 0007 | stage-boundary codec verification (+ assembly-layer amendment, #118) |
| 0008 | robustness testing — fuzz & property (#97/#98/#99) |
| 0009 | tolerant negotiation posture (#101) |
| 0010 | `FrameUpdate` dirty-rect contract (#85) |
| 0011 | zero `ironrdp` as the terminal state; the oracle retires per codec (#194) |
| 0012 | consumption-site totality — a parser's guarantee is not held at the point of use (#211/#233) |
| 0013 | pinned build inputs — every pin names its bumper; the compiler pin (#235) |

**Search by the artifact** — the module, the wire field, the predicate, the config
key — **never by the feature name**: a related issue almost never shares your
vocabulary. Always label a new issue **triage + type** on creation (memory
`feedback_label_issues_on_creation`, `docs/agents/triage-labels.md`).

### `promote` — destination and format

A promoted rule becomes an **ADR** at `docs/adr/NNNN-<kebab-title>.md`, house
shape: `Status` (amendment history **inline**), `Context`, `Decision`,
`Consequences`, and **`Rejected alternatives` with reasons**. ADR-0002 and ADR-0007
are the models — both carry later Amendments rather than being rewritten. A record
earns its place by **deriving** decisions already taken, not by listing them.

### `spine` — tracker capability

**GitHub sub-issues exist and are in use.** Measured 2026-08-13, not inferred:

| Epic | `sub_issues` |
|---|---|
| **#158** (Progressive) | **7** — slices #167–#172 plus #194; #194 in turn carries #200 |
| #132, #45, #29, #21, #28, … | **0** |

So the roster is a **relation**, not a prose fallback — the follow-up tree and the
anchor's roster both render from the tracker, and nothing needs reconciling at
flush. **A `- [ ] #NNN` task list in the body does not create the relation**:
#132's body lists `#137`–`#141` in exactly #158's format and has zero sub-issues.
Enrolling an epic's slices is real work with a real result. **Use the relation**
for new follow-ups and spines rather than adding another prose convention; the
legacy convention (`epic #158, slice 3` in the title) is what it replaces.

Two API traps, each a few minutes to rediscover:

- `sub_issue_id` is the issue's **database id**, not its number, and `gh api` needs
  **`-F`** rather than `-f` — with `-f` it sends a string and the API answers
  **422**.
- Re-adding an existing child *also* answers **422**, with a message reading as if
  the child belonged to another parent. It usually means the edge is already there.
  **List the parent's `sub_issues` before believing it** — `.parent` is absent from
  the REST issue payload, so a child's own record cannot answer it.

```sh
gh api repos/kihyun1998/justrdp/issues/<parent>/sub_issues --jq '.[].number'   # check first
ID=$(gh api repos/kihyun1998/justrdp/issues/<child> --jq .id)
gh api --method POST repos/kihyun1998/justrdp/issues/<parent>/sub_issues -F sub_issue_id=$ID
```

---

## Boundary rule (ADR-0001)

- **The core is a pure state machine** — `bytes in → (Action, bytes) out`. **No
  I/O, no runtime embed, policy-agnostic.** It never reads a socket, never knows
  `tokio`, never sees a `TSRequest`.
- **Mechanism → core**: wire parsing, state transitions, codecs,
  surface/framebuffer composition. The core owns **every RDP-native protocol
  layer** itself (X.224 · MCS · GCC · capability · session loop · virtual channel ·
  codec · surface).
- **Policy → adapter**: TLS trust (ADR-0005), credential source, frame-sink
  behaviour are **injected** by the host adapter.
- **`sspi` and `rustls` live in the adapter** — security-critical, non-RDP leaf deps
  (ADR-0002).
- **The consumer seam is in-repo**: `justrdp-tokio` (~1 000 lines — the `Action`
  drive loop plus the TLS handshake, the CredSSP token loop, per-stage timeouts and
  the session runner: the things deliberately *not* in the core). There are **no
  published consumers**, which is why `downstream` does not exist while `boundary`
  does.
- **The host owns by definition** (not a workaround): the socket and runtime, the
  TLS trust decision, credentials, the frame sink / presentation, input device
  semantics, clipboard and redirection policy, reconnect strategy, and **every RDP
  feature flag**.
- **Payoff**: the core is independently, deterministically testable with no socket
  and no runtime — oracle round-trip + real VM.

**Do not misdiagnose a contract as a defect.** Policy-agnosticism and the
dirty-rect `FrameUpdate` (ADR-0010) are contracts justrdp **deliberately holds** —
*"the core should resolve this for me"* is a host standing on nothing valid, and
treating the report as a defect would delete a contract instead of a workaround.

**No consumer workaround for an upstream defect.** The worked instance is the
`sspi` CredSSP defect (ADR-0004): reported and fixed **upstream**, bridged
meanwhile with `[patch.crates-io]`, and the bridge **deleted once the fix shipped**
(2026-08-10) — never worked around locally. When the urge to compensate in a
shallower layer to make a test pass appears, that is the `stop` edge: **stop,
explain, ask.** Do not work around it alone and do not silently file an issue and
move on.

---

## Tie-breaker — what wins when prior art and justrdp's own evidence disagree

Not one value: the authority differs **by layer**, and flattening it breaks one of
them. The sharpest case is send vs. receive — writing to the spec and accepting
what a real server sends are opposite disciplines on the same protocol, so a single
tie-breaker is necessarily wrong on one side.

| Layer | Authority | Grounds |
|---|---|---|
| **What we emit** — wire layout, flags, state transitions | the **`[MS-*]` spec**, cited by section | Writing to spec is what makes us connect to servers nobody tested us against. ADR-0003 *derive, don't copy*: FreeRDP/IronRDP are cross-checks, never the source |
| **What we accept** — server tolerance, violated caps, absent/oversized fields, and **receive-side state transitions the spec phrases as server obligations** (#252) | the **real VM's observed behaviour**, then FreeRDP's tolerance code | ADR-0009 / #101: servers violate the spec and mstsc connects anyway, so strictness on the receive path is a defect, not rigor. **Caveat:** the VM is one WS2022 box (memory `vm_advertised_graphics_caps`) — a tolerance derived from it alone is a hypothesis until FreeRDP shows the same shape |
| **Codec byte-exactness** | an **owned basis** where one exists (real-server corpus + independently-derived expectations), else the **differential oracle** (`ironrdp-graphics`) — with **FreeRDP as the tie-break** when the oracle and we disagree | ADR-0003/0007, **narrowed by ADR-0011 §3** (#225): *"The oracle never outranks the owned basis"* — this row named the oracle as the authority outright until then, which is the pre-ADR-0011 answer. The oracle shares justrdp's own code lineage (memory `ironrdp_oracle_shares_lineage`), so agreement is weaker evidence than it looks and disagreement is not automatically ours |
| **Public API shape** — `FrameUpdate`, feature-flag exposure, host injection points | **this repo's own precedent + `CLAUDE.md` identity** | IronRDP's API is the thing being replaced. It is a design *input*, never a validator |
| **Performance claims** | **our own measurement on a `--release` build** | No precedent yet; stated so a debug-build number never becomes a claim |
| **Directory layout** — which path owns what | **this project's own measured rule**, then the confirmed layout peers (`reference` class 5) | `plat`, 2026-08-31. Four peers doing the same thing is a strong prior and still loses to a rule this repo already keeps: measured, the declared dependency boundary has **0 violators** and the tree is *stricter* than the declaration. Where neither settles it, it is the maintainer's call and **not a vote** — the module-root spelling was decided exactly that way |

A layer not in this table has **no recorded tie-breaker** — say so and ask, rather
than borrowing a neighbouring row.

## Deliberate divergences — where justrdp does *not* follow its prior art, on purpose

The table above says who wins an argument; this says **which arguments are already
over**. It is what `verify`'s reference-free restatement test is checked against: a
finding that lands here is `DELIBERATE` with the citation, never a defect, however
confidently a lens reports it.

| We do | The prior art does | Decided by |
|---|---|---|
| **The host holds every RDP feature flag** — the core hides no capability bit | `ironrdp-connector` 0.9.0 curates them internally and omits `SUPPORT_DYN_VC_GFX_PROTOCOL` (0x0100), so EGFX cannot be enabled | `CONTEXT.md` §Project intent — that single hidden flag is *why this project exists*. "Narrow the surface to a curated config" is not an open question |
| **ClearCodec tolerances** — RLEX runs that overflow the declared rect are clipped; the NSCodec subcodec path is skipped rather than rejected | FreeRDP treats both as errors | #127 + memory `clearcodec_corpus_required_tolerances` — the real-server corpus *requires* them. A lens reporting "FreeRDP rejects this" is `DELIBERATE`, cited to the corpus, not a defect |
| **`FrameUpdate` carries a dirty rect and no owned pixels**; surfaces blit straight into the host framebuffer | IronRDP's `DecodedImage` owns a full-frame copy the consumer reads out of | ADR-0010 (#85), realized in #162/#165 and #163/#166. "Let the core own the frame" reverses a measured performance decision |
| **Accept capability sets and negotiation responses that violate the letter of the spec** | a **strict reading of `[MS-RDPBCGR]`** — note the divergence here is from the *spec's strict interpretation*, **not** from FreeRDP/IronRDP, both of which are tolerant too | ADR-0009 (#101) |
| **Progressive: `quality = 0xFF` is a full-quality sentinel, and a region needs no preceding `WBT_CONTEXT` for its `codecContextId`** | `ironrdp-graphics` indexes its progressive-quant table by `quality` (0.9.0 `progressive.rs:1231`, `:1268`) and errors on an undeclared context id — note this diverges from **the oracle only**, not from FreeRDP, which special-cases the sentinel (`progressive.c:997`, `:1407`) and gates a region on `FLAG_WBT_FRAME_BEGIN` alone (`:2129`) | #194 + the corpus at `justrdp-codecs/tests/fixtures/progressive/`, where the real server needs both tolerances (2 of 52 payloads survive the oracle). Binds #169/#170: "require a context block" is not an open question |
| **Progressive upgrade: a refinement that cannot be represented in `i16` is a typed error** (whether from the accumulate, a too-wide raw read, or a shift that discards it) | **FreeRDP** truncates — `WINPR_ASSERTING_INT_CAST` is an assert in debug and a plain cast in release (`progressive.c:1223`, `:1252`), and `rawShift` (`:1192-1201`) uses a plain cast | #168. The receive-path row normally makes FreeRDP's tolerance the authority and this deliberately goes the other way: the coefficient store **survives across passes**, so a wrapped value corrupts every later refinement of that tile rather than one frame of it — the error is not local, so tolerating it is not tolerance. **Two caveats kept on the record rather than argued away:** reachability is *not* established — the corpus bounds the addend (`shift` 5..=11 against a magnitude ≤ 3) but says nothing about the accumulated coefficient it is added to, and no gate yet drives a pass against a non-zero store (#169); and because the pass refines in place, the error leaves a partially-refined store, so the caller's obligation is to **discard the tile's state**, not merely skip the tile |
| **Progressive first pass: the reduce-extrapolate inverse DWT saturates** its lifting taps | the **oracle** wraps (`dwt_extrapolate.rs:420-422`, `t(v) = v as i16`) | #169. FreeRDP's `clampi16` (`progressive.c:591-598`) is the tie-break, and the two differ by a full `u16` on an overflowing tap — a wrapped tap turns a clipped highlight into its photographic negative. Diverges from **the oracle only**; asserted by a test rather than left as a doc claim |
| **Progressive: a base quant band below 6 is decoded, not rejected** | **FreeRDP** rejects the whole region (`progressive_rfx_quant_lcmp_greater_equal(quantVal, 6)`, `progressive.c:2177`) | #169 + ADR-0009. The shift formula is total for `1 <= bitPos <= 16` and FreeRDP's floor sits inside that window, so the check buys no arithmetic safety on a receive path. **The oracle is not a second opinion here** — it has no such branch in any published version, and #167's "it defines a rounding right-shift for `q < 6`" described the *encoder* (`progressive.rs:315`). Unreachable on the corpus: no real region goes below 6 |
| **Progressive: an upgrade pass whose band layout disagrees with the layout its tile's store was written at is refused** | **FreeRDP** hardcodes the extrapolate walk and forwards the *current* region's flag to the DWT, so it refines one layout and reconstructs another | #169. Silent by construction — plausible pixels, no error, the shape #167 records. Stricter than the reference on a receive path, and **unreachable on the corpus** (52 of 52 regions set the flag), so it is a FreeRDP-derived hypothesis rather than a measured behaviour: guessing what such a server meant would be worse than refusing it |
| **Progressive: a first-pass dequantization shift of 16 or wider fails the tile** | **FreeRDP** refuses the same widths (`prim_shift.c:38-39`, generic and SSE3 alike) and then **discards the refusal** — the tile work callback is `void` (`progressive.c:1659-1684`), so the stale tile is blitted and the region reports success | #169. Reachable: `shift = quant + prog_quant - 1` runs to 29, not 15. Painting a stale tile from an already-overwritten sign store is the silent-corruption shape this territory refuses, so the divergence is from FreeRDP's *handling*, not from its threshold |
| **Progressive: the tile store is keyed by surface** | the **bootstrap oracle** keys by `codecContextId` alone with no cap (#83) | #169, and it is a **correctness** difference, not only a leak: `RFX_TILE_DIFFERENCE` adds a tile's coefficients to the store held for that grid position, and 1405 of 2943 real first passes carry it. Under context keying a rotated id starts from zeroes and the previous frame's contribution is dropped — measured, the two keyings paint differently. FreeRDP keys by `surfaceId` (`progressive.c:314`, `:471`). It also bounds the memory: 260 live stores against 2940 over one session |
| **Progressive: the tile store is freed by `DELETESURFACE` and by nothing else** — `DELETEENCODINGCONTEXT` and `RESETGRAPHICS` free nothing | the **bootstrap oracle path** frees on both (`justrdp/src/egfx.rs:319`, `:484`), which is #83's fix and is correct while contexts are keyed by `codecContextId` with no cap | #170. FreeRDP agrees with us on every row — its `DELETEENCODINGCONTEXT` handler is a literal no-op (`gdi/gfx.c:1239-1246`) and its `RESETGRAPHICS` reaches `progressive_context_reset`, a stub (`progressive.c:2635`) — so this diverges from *our own current call sites*, not from the reference. `RESETGRAPHICS` is the load-bearing one: the server's encoder keeps its reference frames across a reset and `RFX_TILE_DIFFERENCE` adds against them, so clearing desyncs while keeping cannot (an encoder that did reset cannot send a difference tile at all). **Landed in #172**: both call sites are retired and the passing test that pinned them was *inverted* rather than deleted (`reset_graphics_keeps_the_tile_stores_it_used_to_clear`), because a green test asserting the retired behaviour is the strongest possible "do not touch this" and deleting it would have thrown away the reason it was wrong |
| **Progressive: a tile index is bounded per axis, and a grid is replaced when the surface's grid dimensions change** | **FreeRDP** bounds the *linear* index only (`zIdx >= surface->tilesSize`, `progressive.c:473`) and its create is idempotent on the surface id alone (`:546-548`) | #170. Two different silences on the reference's side: a linear-only bound lets `(gridWidth + 5, 0)` alias onto `(5, 1)` and write the wrong tile, and an idempotent create lets a surface recreated at a new size keep the old `gridWidth` so every `zIdx` addresses the wrong tile. FreeRDP's grid is also **wider than ours for every surface** — it rounds up to the next multiple rather than `div_ceil` (`:447`) and 16-aligns the width first (`gdi/gfx.c:1284`) — so it accepts a column we reject. Unreachable on the corpus (widest index 19 on a 1280-wide surface), so the accept-side half is a hypothesis; the alias-side half is not |
| **Progressive assembly: a tile is clipped to its region's rects, and each region is clipped against its *own* rects** | **`ironrdp-graphics`** does not clip at all — `decode_bitmap` hands back whole 64 x 64 tiles — and **FreeRDP** clips the frame's accumulated dirty set against `progressive->region`, which after the parse loop holds the payload's *last* region (`update_tiles`, `progressive.c:2329-2412`) | #171. We follow FreeRDP on *whether* to clip and diverge on *which* region, and both halves are measured rather than argued: not clipping leaves **57 386 of 1 024 000** surface pixels different over the corpus (909 of 6193 tiles are genuinely cut), and **52 of 52 payloads carry exactly one region**, so the last-region rule and the per-region rule agree on every byte this server has sent. The oracle agreeing with the pre-#171 client here is [oracle-agreement-is-not-independence](../map/invariant/oracle-agreement-is-not-independence.md) again, not a second opinion |
| **Progressive assembly: overlapping region rects paint the overlap twice** | **FreeRDP** unions the rects into a `REGION16` first (`progressive.c:2331-2344`), so its copies are disjoint | #171. Both writes come from the same tile buffer at the same source offsets, so the *pixels* are identical and the cost is one redundant blit plus a doubled dirty area. Measured: **0 overlapping rect pairs** across the corpus' 52 regions, so a region-union implementation would be untested machinery guarding an unobserved case |
| **Progressive assembly: FreeRDP's deferred re-blit is not modelled** | **FreeRDP** re-blits the frame's whole accumulated dirty set on every payload of that frame (`frameId` / `updatedTileIndices`, `progressive.c:2437-2441`, `:2346`), which needs every tile's decoded *pixels* retained (+16 KiB on top of `TileState`'s 48 KiB) | #171, and the validity condition is recorded because the mechanism turned out to be **reachable**: probed live, **4 of 65** frames carried two WireToSurface2 payloads. Replaying that capture both ways, the carried-over set contributed **0 rectangles and 0 pixels** — inert *as long as a frame's successive regions do not overlap each other's tiles* |
| **Progressive assembly: the tile store has its own byte budget, and exceeding it skips the new tile** | **FreeRDP** allocates the whole grid up front per surface (`progressive_allocate_tile_cache`, `progressive.c:426`) and has no session-wide bound at all | #171. A `TileState` is 48 KiB per 16 KiB of RGBA, so `justrdp::egfx`'s 256 MiB surface cap admits ~768 MiB of store its accounting cannot see, against dimensions a *server* chose. Skipping the new tile rather than failing the payload is the direction that keeps every already-admitted tile refinable |
| **zgfx bounds what one compressed segment may expand to (65 536) and what a multipart may declare (64 MiB)** | **FreeRDP** caps the segment at the same number (a fixed `OutputBuffer[65536]`, `zgfx.c`) but bounds a multipart only by its own `u32` `uncompressedSize`, so ~400 KiB of input can demand 4 GiB; **`ironrdp-graphics`** has *no* output bound at all, and a ~20-byte segment can demand gigabytes (a match length is `2^(k+1) + v` for a unary-coded `k` the stream picks) | #189, and the requirement is older than the slice — `docs/plan.md` §V.3 wrote *"malformed sequences could cause OOM; use a max-decompressed-size limit"* before either decoder existed. The **uncompressed** segment path is deliberately left uncapped, diverging from FreeRDP the other way: those bytes are copied rather than expanded, so they are already bounded by the input the DVC layer capped, and refusing a long one would only kill a channel over wasted bandwidth |
| **zgfx refuses what no conforming encoder can emit** — a match distance past the 2.5 MB window, a bit pattern matching no token (`10000` and `101111111` name none), a compressed segment longer than the spec's own ceiling — **and tolerates what costs nothing**, an empty compressed segment | **FreeRDP** wraps an over-long distance modulo the window and emits whatever is there, silently skips an unknown token by consuming nine bits, and *refuses* the empty segment (`segmentSize < 2`); **`ironrdp-graphics`** panics on the first and errors on the second | #189. Refusing here is not strictness on a receive path: the referenced bytes have never existed, so there is no server intent to be tolerant *of* — where ADR-0009 applies (an empty segment, an over-long uncompressed one) this goes the tolerant way instead. The tell that the two halves are different questions: one is "what did the server mean", the other is "what could any encoder have meant" |
| **WireToSurface1: a dequantization shift of 16 or wider fails the component**, and an NSCodec colour-loss level that implies one fails the reconstruction | **FreeRDP** refuses the same width inside the shift primitive (`-1` from `general_lShiftC_16s_inplace`, `prim_shift.c:38-39`) and then **discards** the refusal — all ten `rfx_quantization_decode_block` calls drop the status and `rfx_quantization_decode` returns `TRUE` regardless (`rfx_quantization.c:73-83`), leaving the band unshifted and the tile decoding. `ironrdp-graphics`'s `quantization.rs` has no bound at all and carries the identical latent panic | #211 + [ADR-0012](../adr/0012-consumption-site-totality.md). Same split #169 already recorded for the Progressive first pass: the divergence is from FreeRDP's *handling*, not from its threshold. **Unreachable from the wire on both sites** — `Quant::decode` masks to nibbles (widest shift 14) and `parse_header` bounds the colour-loss level to `1..=7` — so this is a contract about what the `pub fn` admits, not a live guard; the priority (P2) follows the reachability and the contract does not. Note the threshold is on the **shift**, not on the nibble: an exponent of 16 shifts by 15 and is accepted |
| **`color::to_rgba` returns `Ok(Vec::new())` at a zero extent** rather than refusing, so a spec-legal empty rectangle converts to zero pixels | **FreeRDP** splits this on *who owns the destination*, not on decoder-versus-converter: everything writing into a **caller-supplied** buffer succeeds at a zero extent (`freerdp_image_copy` `color.c:1155`, `_no_overlap`, `_overlap`, `freerdp_image_fill`), and everything that **allocates and returns** refuses — `freerdp_glyph_convert_ex` (`color.c:265-267`, `if ((len == 0) || (width == 0) || (height == 0)) return nullptr;`) is a converter of exactly `to_rgba`'s shape. On that axis the reference puts us with the refusers | #262 + [ADR-0009](../adr/0009-tolerant-negotiation-posture.md), decided on what the one reachable consumer does with the error rather than on the axis: `justrdp::egfx`'s uncompressed WTS1 arm propagates a `ColorError` with `?`, which is **fatal for the channel** where every other codec arm there warn-and-skips, and `[MS-RDPEGFX]` 2.2.1.2 makes `RDPGFX_RECT16` **exclusive with no non-zero requirement** — so `right == left` is spec-legal and refusing would drop a healthy session over a legal empty rectangle. **Two things this row is not.** It is not an ADR-0012 §3 divergence against `rle`/`planar`, which refuse a zero extent (`EmptyImage`) as **policy** where this bounds a **loop** — different acts, no disagreement to record. And it is not the *reason* the guard exists: the guard exists because at `width == 0` every arithmetic check **passes** and `for out_row in 0..height` walks a bare `usize`, which hung CI for ~56.4 runner-hours; `Ok` versus `Err` is only what it returns once it is bounded. `pointer::decode_pointer` also returns empty and is **not** the precedent — its reason is a protocol semantic (*a zero-sized shape means "no shape"*) a bitmap has no counterpart for |
| **WireToSurface1: a quantization exponent of 0 fails the component** — and it is the first refusal in this family a server can actually reach, a `0x00` byte being two zero nibbles | the **oracle** treats `0` and `1` alike as no-ops (`quantization.rs` `decode_block`, `if factor > 0`), so it under-scales the subband and decodes on. **FreeRDP agrees with us** and in the same shape — validate all ten, then apply — refusing at `if (val < 1) return FALSE` (`rfx_quantization.c:66-71`) and propagating it through `rfx_decode.c:66-67` to `rfx.c:1082-1086`, though its threadpool path (`rfx.c:787-788`) logs and continues instead | #233 + [ADR-0012](../adr/0012-consumption-site-totality.md) §3, which is the reason rather than FreeRDP: `progressive::first_pass_shift` already refused the identically undefined `bitPos == 0`, and one quantity gets one answer across a family. Diverges from **the oracle only**, which is no second opinion here — it shares this decoder's lineage and carries #211's unbounded shift besides. The receive-path objection is removed by ADR-0009 §3(a) (tolerance scopes to *which features may appear*; typed errors hold over contents), not by a tolerance judgement: `shift = -1` is the absence of a value, not one we dislike — the line #189 drew for zgfx. **The VM cannot corroborate** (it never emits CAVIDEO), so this is a FreeRDP-derived position, not an observed one; `[MS-RDPRFX]` constrains the *encoder* to 6..=15, so no conforming encoder emits it |
| **A failed zgfx message poisons the decompressor** — every later call is a typed error | **both references** leave the object usable with a half-written history window | #189. Same reasoning as #168's Progressive store and for the same structural reason: the 2.5 MB window spans messages, so a half-written one silently mis-decodes every later match rather than failing locally. Unreachable in the client (`justrdp::egfx` already treats a zgfx error as fatal for the channel), so it is a contract assertion rather than a live guard — and it is what makes the ordering contract testable, which the issue asked for |
| **A Font Map whose body is shorter than its mandatory 8 bytes is a typed error, and the connect fails** | **FreeRDP** refuses to fail: `rdp_recv_font_map_pdu` (`libfreerdp/core/activation.c:552`) carries the comment *"Do not fail here, see https://github.com/FreeRDP/FreeRDP/issues/925"*, warns on a short payload, and still calls `rdp_finalize_set_flag(rdp, FINALIZE_SC_FONT_MAP_PDU)` — so finalization completes on a zero-byte body. **But that tolerance is bought, not free**: FreeRDP gates every finalization advance on `rdp_handle_sc_flags` (`libfreerdp/core/rdp.c:1867`) walking four states (`rdp.c:2176-2190`, Sync → Cooperate → GrantedControl → FontMap), so reaching `CONNECTION_STATE_ACTIVE` already proves all four replies arrived and parsed. It relaxes the **body** because it never relaxed the **place**. **Two corrections #252 measured, both to sentences this row used to carry.** It is a *completeness* gate, not an *ordered* one: `finalize_sc_pdus` is only ever OR-ed (`rdp.c:2714`) and cleared solely at reset (`:2699`/`:2701`), so out-of-order replies satisfy every rung one PDU behind and still reach ACTIVE. And it is the **transition** that is gated, not the handler — `rdp_recv_data_pdu`'s switch (`rdp.c:1235-1311`) consults no connection state, so `rdp_recv_font_map_pdu` runs at any rung. **And the gate never fails**: the else branch (`rdp.c:1884-1893`) warns and leaves `status` untouched, so a missing reply parks FreeRDP on the rung rather than dropping the session. It failed for one stretch of 2022 and was deliberately relaxed — `ff2509bbc4e9` (Armin Novak, 2022-11-29, *"[core,client] relax sc flags state checks"*) deleted `status = STATE_RUN_FAILED`, one day after FreeRDP#8458 reported an xrdp resolution change disconnecting on the reactivation leg (*"microsoft's clients seem to work"*). And the maintainer who landed it said so on the record (`bmiklautz`, #925, 2013-02-11): *"It's not really clean solution since it violates the protocol imho."* **IronRDP** rejects, like us, and goes further by rejecting unknown `SequenceFlags` bits — enforcing a spec `SHOULD` as a `MUST`, since `[MS-RDPBCGR]` 2.2.1.22.1 marks all four body fields `SHOULD` and only the Share Data header fields `MUST` | #237 + [ADR-0009](../adr/0009-tolerant-negotiation-posture.md) §3(a), which is the record and reads against the reference here: *"A tolerated order with a malformed body is still a typed error."* A missing mandatory body **is** a malformed body, and §2's tolerance is scoped to *rendering-feature self-inconsistency* — an unadvertised order, an over-advertised capability — which a truncated finalization PDU is not. **The open question is at the consumption site, not the parser**: `FontMap::decode` returning `NotEnoughBytes` is what §3(a) prescribes; whether `justrdp::connect::finalization_step` should tolerate that error the way FreeRDP does would widen §2 past rendering features, which is an ADR amendment rather than a fix. **Settled by #242 (2026-08-25): the row stands, and here is what the earlier version of it left out.** *"A real server produced it"* was true and incomplete — #925's server is **Oracle VirtualBox VRDP 4.2.6**, and the reporter adds *"i can connect to Ms RDP Windows"*. One modern Microsoft instance exists (winapps-org/winapps#244, 2024, FreeRDP 3.8.0, Windows 10 LTSC, `paylaod size is 0 instead of 8`) — but it is preceded 28 ms earlier by two `SSL_CERT_NOT_ON_SERVER` failures, and `nego.c`'s handler for that code disables nothing (unlike `SSL_REQUIRED_BY_SERVER`/`HYBRID_REQUIRED_BY_SERVER`), so the ladder steps down. With no server certificate every TLS-bearing rung fails for one reason, leaving **`PROTOCOL_RDP` as the only survivor** — Standard RDP Security, which `connect.rs:577` rejects (`selected.bits() != 0`) six stages before `finalization_step` exists. **So every published observation of this input arrives over a transport justrdp refuses.** That is not *"no server sends it"*: the search was FreeRDP's `paylaod` typo across public GitHub, which cannot see mstsc users, private trackers, or pre-3.x log text — unconfirmed ≠ absent. **Validity condition: this holds only while justrdp refuses `PROTOCOL_RDP`.** Supporting Standard RDP Security reopens #242 by itself. The larger finding #242 produced is not the body check — it is that justrdp has **no ladder at all** and reaches session-active on the Font Map alone. **Settled by #252 (2026-08-25): no ladder, deliberately, and now measured rather than argued.** A capture of the real VM (`JUSTRDP_CONNECT_CAPTURE_FILE`, four activations, connect leg *and* reactivation leg, pinned as `justrdp-pdu/tests/fixtures/connect/finalization-replies.bin`) shows it sends all four in spec order every time — the premise #242 asserted and nothing in the repo could check. ADR-0009 reaches the case from neither side: §1's predicate is *"where a violation is an attack vector"* and no scenario is constructible for a peer that has already completed CredSSP, MCS and licensing; §2's grant is scoped by enumeration to rendering-feature self-inconsistency, which a missing finalization PDU is not. So the record was extended, not the machine — with one exception, the orthogonal half: the **field values** the spec does fix are now checked on both legs (`Synchronize.messageType`, and a server `Control.action` restricted to Cooperate / Granted Control), where justrdp had been the sole outlier against both references. The completeness question stays open on purpose and its home is #252 |
| **`connect` and `session` live in one crate** — `crates/justrdp/src/connect.rs` and `session.rs` | **IronRDP** splits them into two crates, `ironrdp-connector` and `ironrdp-session` | ADR-0001 + `docs/plan.md` decision 6 (*"pragmatic 3+1"*). The two share one state machine and one capability set, so a crate boundary between them would run *through the middle of a state machine* rather than along a seam. `plat`, 2026-08-31 |
| **One adapter crate**, `justrdp-tokio` | **IronRDP** ships four — `ironrdp-async`, `ironrdp-tokio`, `ironrdp-blocking`, `ironrdp-futures` | ADR-0001. The adapter is ~1 000 lines and *which runtime* is a host policy, not a layer of ours — the core is runtime-agnostic precisely so a second runtime never needs a second crate here. `plat`, 2026-08-31 |
| **`justrdp-pdu/src/` is flat** — one file per `[MS-*]` protocol area, 25 of them | **IronRDP** nests by area: `basic_output/`, `gcc/`, `input/`, `rdp/`, `codecs/` | `docs/map/territory/` depends on a **1:1 area↔file correspondence**, and nesting breaks the thing the map is read for. The threshold is already in the tree rule rather than in judgement: nest when an area outgrows one file, which is what `rfx/` already is. `plat`, 2026-08-31 |
| **Unit tests are inline `#[cfg(test)]`; `crates/*/tests/` holds differential and corpus tests only** | **h2** and **quinn** put ordinary integration tests in a top-level `tests/` (quinn also `src/tests/`); **rustls** keeps a whole `rustls-test` crate | Measured **15/15** and **declared nowhere** until the 2026-08-31 build — so it is recorded here rather than discovered again. The peers disagree among themselves, so majority answers nothing and this project's own kept rule wins by the tie-breaker's layout row. `plat`, 2026-08-31 |

Add a row when a decision *chooses against* a reference or against a strict spec
reading — that is cheaper than re-defending it every time a lens finds it.

---

## Split coverage — **zero `unowned`** (all four resolved upstream)

Run once per build: every entry in thegraph's *"What the build must supply"* is
checked against its *"What is invariant, what the build decides"* split. This run
finds **no slot on neither side**.

The 2026-08-31 build reported **four** — the `proof` method per layer and its traps,
the areas already carrying a decision record, the tracker capability, and the
war-story index. All four are now placed, and by both mechanisms the split has:

| Slot | How it is now placed |
|---|---|
| tracker capability | **named explicitly** in *"Decided by the build"* |
| war-story index | **named explicitly** in *"Decided by the build"* |
| `proof` method per layer, and its tautological traps | covered by the generalised phrase — each node's data is *"everything it reads and everything it checks against … along with its **method**, its **traps**, and the policies it applies to a surface"* |
| areas already carrying a decision record | the same phrase — it is what `search` **checks against** |

**The generalisation is the load-bearing half, not the two new names.** The split now
states that the kinds it lists after *"data"* are examples and never the definition,
and that the coverage check asks *"is it something a node reads or checks against,
and is it not a bound?"* rather than *"is it one of the kinds listed?"* — which is
what closes the other two without naming them. Recorded rather than deleted: a
finding that was real and is now fixed upstream is the one thing an update run can
show that a first build cannot, and a section that simply vanished would read as
though the finding had been wrong.

**Nothing in this file changed as a result**, which is the shape the split predicts:
these slots were answerable all along, and *"placing them changes no build"*. Their
data was filled here before they were placed and is filled here now.

---

## Extraction plan

**Agents** — only nodes that **read without adjudicating** (invariant ①).
`implement`, `boundary`, `enumerate`, `proof`, `batch`, `stop`, `decide` and
`promote` are **never** generated: they adjudicate, and two subagents on one model
share every blind spot that matters.

**Scripts** — only `code` deciders (invariant ④). **Language: Python**, by repo
precedent (`.github/scripts/check_map.py`, `seed_fuzz_corpus.py`; the map gate is
toolchain-free by design). They live in **`scripts/thegraph/`**, kept distinct from
`.github/scripts/`, which holds scripts that *are* CI gates.

| File | Node | Data slots it carries |
|---|---|---|
| `.claude/agents/thegraph-reference.md` | `reference` (fetch only) | the **4 fetchable** classes of 5 — 1, 2, 3 and 5 · how each is reached · **which are summarized** (the flag the grade cap reads). **Class 4, the real VM, is not here**: it is a throwaway probe on the main thread, not a fetch, and an agent that cannot run one must not carry it as an instruction |
| `.claude/agents/thegraph-lens.md` | `verify` | both corpora paths (`docs/map/` + `docs/plan.md` §0; FreeRDP/IronRDP + the `[MS-*]` section) · the tie-breaker row for the layer · the deliberate-divergence pointer · the frontier |
| `.claude/agents/thegraph-refuter.md` | `verify` (2nd) | the same material, **opposing stance** in its brief |
| `.claude/agents/thegraph-sweep.md` | `sweep` | the 6 surfaces and how each is read |
| `scripts/thegraph/triggers.py` | `verify` inbound guard | the 3 sacred-path groups, matched against the diff · **the empty-diff answer (`2`, not `0`)** |
| `scripts/thegraph/place.py` | `place`, and `gate` again on the final diff | the tree rule as a path list, matched against the changed paths |
| `scripts/thegraph/gates.py` | `gate` | the 10 commands, each invoked **bare** |
| `scripts/thegraph/cluster.py` | `search` | the tracker query by artifact · the 13 record-carrying areas |
| `scripts/thegraph/grants.py` | `gate` (invariant ①) | the generated-agent roster · the write-capable tool list · the `Runs:` declaration form |

**Tool grants — derived from each brief, never defaulted, and checked.** Read-only is
the **default**; only an explicit `Runs:` declaration naming a tool moves one, and the
check asserts the default rather than the claim (*"is a write-capable tool granted, and
does the brief declare it?"* — never *"does the description say read-only?"*, which an
agent dodges by rephrasing).

| Agent | Grant | Why exactly this |
|---|---|---|
| `thegraph-reference` | `Read`, `Glob`, `Grep`, **`Bash`** | The **only** agent licensed to run a command, and it carries the declaration: classes 1/2/3/5 are `curl`, `gh api` and `base64 -d` into `$SCRATCH`, which `Read` cannot reach and `WebFetch` is banned from because it summarizes — the ban that exists so a handler body that *is* there stops reading as absent |
| `thegraph-lens` | `Read`, `Glob`, `Grep` | **`Bash` removed.** Its brief told it to `gh api … \| base64 -d`, which is the caller's job: `reference` has already fetched into `$SCRATCH` on the main thread by the time `verify` runs, so the brief carries the **paths**, not an instruction to go and get them |
| `thegraph-refuter` | `Read`, `Glob`, `Grep` | **`Bash` removed.** Its brief never asked for a command — the plainest case, and the one the invariant's war story turns on: the second lens is *the* node whose dissent has to be believed, and a shell it never needed is what cost it that |
| `thegraph-sweep` | `Read`, `Glob`, `Grep` | **`Bash` and `Edit` removed.** The `sweep` **node** writes surfaces; the **delegated instance** does not — one instance per surface, *"and it is read-only, so invariant ① permits it"*. The instance reports what each surface needs; the main thread applies it |

**Why this table exists at all.** The 2026-08-31 build granted `Bash` to all four and
`Edit` to the sweeper, **with no brief asking for a command and no declaration anywhere**
— and that build is the incident the method now records: one agent applied four mutations
to a live working tree nothing had asked for, while the refuting pass was reading that
same tree; the refuter then reported a failure it could not reproduce and graded the run
`UNADJUDICATED`, correctly, from inside evidence the first pass had manufactured. A
read-only claim asserted in three places and enforced in none is what this row replaces
with a check.

**Every file carries the build stamp** above. **No file carries the grade table,
the restatement test, the candidate envelope or the never-drop-a-corpus rule** —
those are method and live in `thegraph`. Thinness is the defence against
staleness: a thin artifact survives a change to the method, a thick one is stale
the moment the method gains a paragraph.

**Run state**: `.thegraph/` — append-only during the run, ignored by version
control, deletable at any time and rebuildable by re-reading the issue. The
durable record is the **issue**, flushed at each node's exit.

---

## War-story index

Per-incident and per-decision evidence lives in [`lessons.md`](lessons.md), indexed
by step and anchored to the ADRs and issues (#36, #61, #98, #99, #101, #127,
#151/#155, #162/#163). It is what keeps each guard here from reading as an
abstraction. Nothing in this file restates it.
