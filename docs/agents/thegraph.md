# thegraph build (justrdp)

The compiled graph for the `thegraph` skill: which nodes this repo has, how many,
what each one's guard and decider are, and which of them are extracted as agents
and scripts. `thegraph` holds the portable **method** (node-type catalog, four
invariants, reasoning habits); this file holds justrdp's **graph**. The method
defers every concrete value here.

**Build stamp** — built from `thegraph/SKILL.md`
`md5:f75be113416e647c1d0df2b841f092e1` (54 224 bytes, mtime 2026-08-10). Compiled
2026-08-24 by `/grill-the-graph` from [`theflow.md`](theflow.md) (the bindings),
`CLAUDE.md`, `CONTEXT.md`, `docs/adr/`, `docs/map/`, the manifests and the
workflows. Every generated artifact carries the same stamp. If the stamp is
behind, **warn and continue** — never rebuild on your own; a rebuild writes agents
and scripts, and those pass through the maintainer.

**Relationship to [`theflow.md`](theflow.md).** The bindings doc is this build's
**input**, and it stays live — `theflow` keeps working, and retirement is the
maintainer's call. Two tables are **co-owned rather than copied**: the
**tie-breaker** and the **deliberate-divergence list**. They are amended as issues
land (a row moved when #172 landed), so a second copy here would be the divergence
seed with a 23-row surface. Both are read by pointer, below. **Retiring
`theflow.md` means moving those two tables here, not deleting them.**

---

## Node roster

| Node | Count | What decided it |
|---|---|---|
| `classify` | 1 | catalog |
| `spine` | 1 | catalog. The tracker **has** the relation — see *Tracker capability* |
| `map` | 1 | the bindings name a territory map: [`docs/map/README.md`](../map/README.md) |
| `reference` | **4** | 3 routing-table rows naming an external source, **+ the real VM** as its own class (below) |
| `enumerate` | 1 | catalog. **Never delegated** |
| `boundary` | 1 | catalog. **Never delegated**. The seam is in-repo — see *Boundary rule* |
| `implement` | **4** | one per claim class in Step 4's proof table |
| `proof` | **4** | one per claim class, each with its own method and its own blind spot |
| `verify` | **2** | 1 gap-hunting + 1 refuting, because the sacred-path list is **non-empty** |
| `sweep` | 1 | fanning out over **6** surfaces |
| `gate` | 1 | **8** gates / 9 commands, blind spots included |
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

### `reference` — 4 source classes, routed by `change_type`

| # | Class | How it is reached | Summarized? |
|---|---|---|---|
| 1 | **`[MS-*]` normative specs** — `[MS-RDPBCGR]`, `[MS-RDPRFX]`, `[MS-RDPEGDI]`, `[MS-RDPEGFX]`, … Governs **what we emit**: layout, flags, state transitions. Cite the section number | `curl -sL "<learn.microsoft.com/…>" > "$SCRATCH/spec.html"`, then `grep -n`. The WebFetch ban is on **summarization, not on the web** — same pattern as class 2 | **raw** — may reach `CONFIRMED`. If the fetch fails, **downgrade this run explicitly**; never a silent `CONFIRMED` |
| 2 | **FreeRDP (C) + IronRDP (Rust) real source** — hidden state, server tolerance, edges, the CVE points. Spec-unwritten tolerance exists **only** here | `gh api repos/<owner>/<repo>/contents/<path> --jq .content \| base64 -d > "$SCRATCH/x"`, then `grep -n` / `sed -n`. **`WebFetch` is banned** — it drops handler bodies from large files, so a decoder branch that *is* there reads as absent | **raw** |
| 3 | **Published / external state** — crates.io, the upstream repo's own state | a registry query / `gh api`, never a sentence about them | **raw** |
| 4 | **The real VM** — `192.168.136.136` (memory `test_environment`). The authority for **what we accept** | a **throwaway probe**: instrument, read the number, delete the probe, **record the number in the issue**. Reading the code is not observing what it does | **raw observation**. Caveat carried on the node: it is **one WS2022 box** (memory `vm_advertised_graphics_caps`) — it proves the paths it advertises and says nothing about the ones it does not. *"The VM is happy"* is not *"servers are happy"* |

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
6 invariant notes, 18 territory notes. Add `docs/plan.md` §0 (traps already PROVEN
on the real VM — do not re-discover) and §1 (capability → feature coupling).

**Where the hidden-state list lives** (`enumerate` reads this): VM-observed traps
→ `docs/plan.md` §0. Per-territory state → the map's `## Design model`.
Cross-territory facts → an [`invariant/`](../map/invariant/) note, each carrying a
`## Where it will recur` test, which *is* the enumeration. Per-codec state the map
does not yet name (tile boundaries, quant tables, progressive pass state,
palette/run state) → into the issue **before** implementing.

### `implement` / `proof` — 4 layers, each with its own blind spot

| Layer | Real proof | What this proof structurally cannot see (the tautological trap) |
|---|---|---|
| **`justrdp-pdu`** | `encode → decode` round-trip on hand-built PDUs **plus** the proptest no-panic / round-trip properties (ADR-0008, #98) | A decoder that only ever sees vectors *we* authored is untested against the input space a server spans. And **a census can be blind to a whole class**: #241/#238 — the no-panic census's derivations were byte-scoped and path-scoped, so one could not see a parser in the core and neither could describe a consumption site at all. Both classes held live defects |
| **`justrdp-codecs`** | a **differential oracle** (ADR-0003/0007): same bitstream to *our* decoder **and** `ironrdp-graphics`, assert the output `Vec<u8>` is **byte-identical**. Stage-boundary verification applies **per pipeline stage**, not only end-to-end. 100% pass is the gate to drop the dependency (ADR-0011) | **The oracle shares our lineage** (memory `ironrdp_oracle_shares_lineage`, [the invariant](../map/invariant/oracle-agreement-is-not-independence.md)) — byte-identical agreement is **not** independence; cross-check FreeRDP before calling a match "proof". **A vector proves only what it contains**: a corpus can supply an axis and miss the *combination* (a codec exercised, but never at a tile boundary, never with a quant table that changes mid-frame) — measure what the fixture exercises, never infer coverage from what it was named for. **x64 cannot reach the 32-bit guards** (memory `wasm32_overflow_proof_via_i686`) |
| **`justrdp` (connect / session)** | a **real VM** round-trip — the full connect sequence to session-active, not a mock server | **One VM is one server.** It can prove the paths it exercises (#150/#91) and cannot speak about caps it does not advertise |
| **`justrdp-tokio`** | the same VM, driven end-to-end. Its integration tests are `#[ignore]`d in CI **by design** (they need the VM), which is why `coverage.yml` excludes this crate | **A demo or a fake is a smoke test, not proof** (DoD ④). Coverage silence here is expected, so it cannot be read as a signal either way |

Step 4's fifth row — *"strongest: a real consumer"* — is **N/A, no consumer
exists**, so it is not a layer. See the `downstream` roster row for the reversal.

**Test-trust gate** (`implement`'s self-loop, decider `code`) has two
justrdp-shaped traps for the discriminating-power bar: a **differential-oracle test
can be green for the wrong reason** (a vector both implementations decode
identically proves agreement, not correctness), and **a guard only 32-bit reaches
cannot go red on x64** — mutate and re-run on `i686-pc-windows-msvc` (#151/#155),
or the RED you never saw is on a target the gate never ran.

### `verify` — sacred paths, as concrete paths

The inbound guard is a **script over the diff** (`scripts/thegraph/triggers.py`),
decider `code`. It **overrides judgement**: you do not reason your way out of it
because the diff looks small. Absent a path hit, the guard is enumeration risk
(`AI`) — many edges, domain semantics, cross-feature interaction. justrdp has **no
money path, no production mutation and nothing destructive**; here a path is
sacred when it is **silent** (wrong, and nothing crashes) or **irreversible**.

| # | Sacred surface | Paths the script matches | Why |
|---|---|---|---|
| 1 | **Untrusted-input decoders, parsers, and consumption sites** | `crates/justrdp-pdu/src/**` · `crates/justrdp-codecs/src/**` · `crates/justrdp/src/**` — **crate-level globs, deliberately over-broad** | Every byte comes from a server we do not control; a wrong bound yields plausible pixels or a panic (DoS), not an error. The derivation lives once, with [untrusted decode never panics](../map/invariant/untrusted-decode-never-panics.md) — **three commands since #241/#238, not two**. The globs are broad **on purpose**: over-triggering costs one lens run, and every narrower derivation went blind on a real class. The continuous half of this axis is proptest (#98) + cargo-fuzz (#99), and the **fuzz lane is nightly-only**, so a *new* target is not covered by the PR gate on the day it lands |
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

### `gate` — 8 gates, 9 commands, each run bare

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
```

**The runnable copy is `scripts/thegraph/gates.py`, and it is the one that
decides.** This block describes it; `theflow.md` Step 7 holds the same list under
the old structure. Three copies is one more than is safe, so a command change
touches the script **and** both docs — or `theflow.md` retires and the count drops
to two.

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

## Tie-breaker — by pointer

**[`theflow.md` § Tie-breaker](theflow.md#tie-breaker--what-wins-when-prior-art-and-justrdps-own-evidence-disagree)**
— 5 rows. Not one value: the authority differs **by layer**, and flattening it
breaks one of them (the sharpest case is send vs. receive — writing to spec and
accepting what a real server sends are opposite disciplines on the same protocol).
`verify`'s brief carries **the row for the layer this change sits on**. A layer not
in that table has **no recorded tie-breaker** — say so and ask, rather than
borrowing a neighbouring row.

## Deliberate divergences — by pointer

**[`theflow.md` § Deliberate divergences](theflow.md#deliberate-divergences--where-justrdp-does-not-follow-its-prior-art-on-purpose)**
— 23 rows as of 2026-08-24. The tie-breaker says who wins an argument; this says
**which arguments are already over**. It is what the **reference-free restatement
test** is checked against: a finding that lands here is `DELIBERATE` with the
citation, never a defect, however confidently a lens reports it. Add a row when a
decision *chooses against* a reference or against a strict spec reading — cheaper
than re-defending it every time a lens finds it.

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
| `.claude/agents/thegraph-reference.md` | `reference` (fetch only) | the 4 source classes · how each is reached · **which are summarized** (the flag the grade cap reads) |
| `.claude/agents/thegraph-lens.md` | `verify` | both corpora paths (`docs/map/` + `docs/plan.md` §0; FreeRDP/IronRDP + the `[MS-*]` section) · the tie-breaker row for the layer · the deliberate-divergence pointer · the frontier |
| `.claude/agents/thegraph-refuter.md` | `verify` (2nd) | the same material, **opposing stance** in its brief |
| `.claude/agents/thegraph-sweep.md` | `sweep` | the 6 surfaces and how each is read |
| `scripts/thegraph/triggers.py` | `verify` inbound guard | the 3 sacred-path groups, matched against the diff |
| `scripts/thegraph/gates.py` | `gate` | the 9 commands, each invoked **bare** |
| `scripts/thegraph/cluster.py` | `search` | the tracker query by artifact · the 13 record-carrying areas |

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
