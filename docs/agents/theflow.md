# theflow bindings (justrdp)

Project-specific data for the `theflow` skill (the working discipline for a
substantive change to the sans-IO core / PDU / codecs / adapter). The skill holds
the portable *method* (seven steps + reasoning habits); this file holds justrdp's
*bindings* — which reference to read, what wins an argument, where the boundary
falls, how to prove behavior, which gates to run. The method defers every concrete
value here. (Authored/updated via `/grill-the-flow`.) Per-incident evidence:
[`lessons.md`](lessons.md).

Identity and the boundary invariant live in `CLAUDE.md`; the ubiquitous language in
**`CONTEXT.md`**; decisions in **`docs/adr/`** (0001–0010); the build plan in
**`docs/plan.md`** (§2–§23).

Prior art cross-checked throughout: **`[MS-*]` normative specs · FreeRDP (C) ·
IronRDP (Rust) · a real RDP VM** (`192.168.136.136`, memory `test_environment`).

## Tie-breaker — what wins when prior art and justrdp's own evidence disagree

Not one value: the authority differs **by layer**, and flattening it breaks one of
them. The sharpest case is send vs. receive — writing to the spec and accepting
what a real server sends are opposite disciplines on the same protocol, so a single
tie-breaker is necessarily wrong on one side.

| Layer | Authority | Grounds |
|---|---|---|
| **What we emit** — wire layout, flags, state transitions | the **`[MS-*]` spec**, cited by section | Writing to spec is what makes us connect to servers nobody tested us against. ADR-0003 *derive, don't copy*: FreeRDP/IronRDP are cross-checks, never the source |
| **What we accept** — server tolerance, violated caps, absent/oversized fields | the **real VM's observed behaviour**, then FreeRDP's tolerance code | ADR-0009 / #101: servers violate the spec and mstsc connects anyway, so strictness on the receive path is a defect, not rigor. **Caveat:** the VM is one WS2022 box (memory `vm_advertised_graphics_caps`) — a tolerance derived from it alone is a hypothesis until FreeRDP shows the same shape |
| **Codec byte-exactness** | the **differential oracle** (`ironrdp-graphics`) — with **FreeRDP as the tie-break** when the oracle and we disagree | ADR-0003/0007. The oracle shares justrdp's own code lineage (memory `ironrdp_oracle_shares_lineage`), so agreement is weaker evidence than it looks and disagreement is not automatically ours |
| **Public API shape** — `FrameUpdate`, feature-flag exposure, host injection points | **this repo's own precedent + `CLAUDE.md` identity** | IronRDP's API is the thing being replaced. It is a design *input*, never a validator |
| **Performance claims** | **our own measurement on a `--release` build** | No precedent yet; stated so a debug-build number never becomes a claim |

A layer not in this table has **no recorded tie-breaker** — say so and ask, rather
than borrowing a neighbouring row.

## Deliberate divergences — where justrdp does *not* follow its prior art, on purpose

The table above says who wins an argument; this says **which arguments are already
over**. It is what Step 5's reference-free restatement test is checked against: a
finding that lands here is `DELIBERATE` with the citation, never a defect, however
confidently a lens reports it.

| We do | The prior art does | Decided by |
|---|---|---|
| **The host holds every RDP feature flag** — the core hides no capability bit | `ironrdp-connector` 0.9.0 curates them internally and omits `SUPPORT_DYN_VC_GFX_PROTOCOL` (0x0100), so EGFX cannot be enabled | `CONTEXT.md` §Project intent — that single hidden flag is *why this project exists*. "Narrow the surface to a curated config" is not an open question |
| **ClearCodec tolerances** — RLEX runs that overflow the declared rect are clipped; the NSCodec subcodec path is skipped rather than rejected | FreeRDP treats both as errors | #127 + memory `clearcodec_corpus_required_tolerances` — the real-server corpus *requires* them. A lens reporting "FreeRDP rejects this" is `DELIBERATE`, cited to the corpus, not a defect |
| **`FrameUpdate` carries a dirty rect and no owned pixels**; surfaces blit straight into the host framebuffer | IronRDP's `DecodedImage` owns a full-frame copy the consumer reads out of | ADR-0010 (#85), realized in #162/#165 and #163/#166. "Let the core own the frame" reverses a measured performance decision |
| **Accept capability sets and negotiation responses that violate the letter of the spec** | a **strict reading of `[MS-RDPBCGR]`** — note the divergence here is from the *spec's strict interpretation*, **not** from FreeRDP/IronRDP, both of which are tolerant too | ADR-0009 (#101) |
| **Progressive: `quality = 0xFF` is a full-quality sentinel, and a region needs no preceding `WBT_CONTEXT` for its `codecContextId`** | `ironrdp-graphics` indexes its progressive-quant table by `quality` (0.9.0 `progressive.rs:1231`, `:1268`) and errors on an undeclared context id — note this diverges from **the oracle only**, not from FreeRDP, which special-cases the sentinel (`progressive.c:997`, `:1407`) and gates a region on `FLAG_WBT_FRAME_BEGIN` alone (`:2129`) | #194 + the corpus at `justrdp-codecs/tests/fixtures/progressive/`, where the real server needs both tolerances (2 of 52 payloads survive the oracle). Binds #169/#170: "require a context block" is not an open question |

Add a row when a decision *chooses against* a reference or against a strict spec
reading — that is cheaper than re-defending it every time a lens finds it.

## Crate / module map

Virtual workspace (no root `[package]`, edition 2024). `--workspace` is required at
the root and **does not build** the out-of-workspace `fuzz`.

| Member | In `--workspace`? | Role |
|---|---|---|
| `justrdp-pdu` | yes | **dependency-free** PDU encode/decode (0 external crates) — `x224` · `mcs` · `gcc` · `capability` · `fastpath` · `egfx` · `dvc` · `rfx` · … |
| `justrdp` | yes | sans-IO core (`connect` / `session` state machines, `framebuffer`, `egfx`, `dvc`) + leaf deps (`rustls`, `x509-cert`) |
| `justrdp-codecs` | yes | codecs (`rle` · `planar` · `nscodec` · `clearcodec` · `rfx/` · `pointer`); owns them via phased-c2 with `ironrdp-graphics` as a **dev-dependency oracle** (ADR-0003) |
| `justrdp-tokio` | yes | ~30-line I/O adapter — `tokio` / `sspi` / `tokio-rustls` and the TLS trust policy (`trust.rs`) live **only** here |
| `fuzz` | **no** (own `[workspace]`) | cargo-fuzz, nightly CI only (#99) — the `--workspace` blind spot |

**`--workspace` blind spot:** `fuzz` is out of the workspace, so the top-level gate
does not even *build* it — a public-API change needs a separate `cargo check
--manifest-path fuzz/Cargo.toml`.

**Consumers: none.** Nothing is published to crates.io yet and there is no in-repo
consumer seam. Everything the method marks *cross-repo only* — the SDK-floor
constraint, the two-consumer signal, the report-upstream duty, the after-merge
downstream migration, the Step 4 "link into a real consumer" proof — is **N/A on
that ground**, not skipped. When a consumer appears, derive the list on the spot
(`grep` the sibling manifests for the crate name); never store it here.

## Step 1 — verify against real source, before guessing

Read real source with `gh api repos/<owner>/<repo>/contents/<path> --jq .content |
base64 -d > "$SCRATCH/x"`, then `grep -n` / `sed -n`. **WebFetch is banned** — it
summarizes and silently drops handler bodies from large files, so a decoder branch
that *is* there reads as absent. **Derive, don't copy** — re-derive from the spec
and prove by differential test, not structural similarity (ADR-0003).

### Three ledgers to open before Step 2 — none of them is the issue body

1. **The cluster (decision side).** Read the worked issue's **spine**, or its
   epic where one exists (`gh issue view <n> --comments`), and treat the suspected
   root as a *hypothesis to test*. justrdp currently groups by **epic issues** whose
   slices name them in the title (`epic #158, slice 3`) — see the tracker note in
   Step 6 for the parent/child mechanism this should use instead.
2. **The map (blast-radius side) — [`docs/map/`](../map/README.md).** Open the
   territory notes the change touches. Their `## Blast radius` is *what else moves
   when you touch this* (a checklist — opening one and finding nothing to do is a
   correct outcome), their `## Cross-cutting invariants` are the facts that hold
   beyond the territory you are standing in, and `## Governing decisions` /
   `## Known holes / open` say what is already decided and what is deliberately
   absent. Read it **here**, before the boundary is drawn — reaching for it at
   Step 5 turns everything it would have told you into rework.
3. **The plan and the glossary.** `docs/plan.md` §0 (*traps already PROVEN on the
   real VM — do not re-discover*), §1 (capability → feature coupling table, the
   closest thing to a blast-radius list today), and §2–§23 for the layer the change
   sits in; `CONTEXT.md` for the term you are about to reuse or redefine.

### Reference routing table

| Change type | Real source to read |
|---|---|
| **Wire / PDU / codec layout** | the **normative spec first** — `[MS-RDPBCGR]`, `[MS-RDPRFX]`, `[MS-RDPEGDI]`, `[MS-RDPEGFX]`, … — for layout, flags, state transitions (cite the section number). The spec is the "first principles" source RDP has that a terminal does not |
| **Hidden state · server tolerance · edges** | **FreeRDP** (C, the CVE knowledge source) + **IronRDP** (Rust) real source. Spec-unwritten tolerance (caps servers violate — #101, ADR-0009) exists only here |
| **Concept ≠ mechanism** | a codec we newly own may be absent from IronRDP, but its *components* (bit reader, tile boundaries, colour conversion, sub-band layout) exist in FreeRDP and in the spec — read **both**. A feature being "new" never justifies skipping the mechanism reference |
| **Published / external state** | crates.io / the upstream repo, never a sentence about them. Worked example: three artifacts said *"remove the `sspi` fork when #689 ships"*; it had shipped six weeks earlier (0.21.1, 2026-06-26) and nobody re-read them. One registry query settled it — see ADR-0004's 2026-08-10 Amendment and [`docs/map/`](../map/territory/nla-credssp.md) |

**Spec ≠ interop.** Code that matches the spec can still not be byte-identical to a
real server — *derive from spec, prove against oracle/VM* (Step 4).

### Where the hidden-state list lives

- **VM-observed traps → `docs/plan.md` §0.** Anything the real server forced on us
  (an ordering, a field a server insists on, a cap it violates) is recorded there so
  it is not re-discovered a third time.
- **Per-territory hidden state → the map's `## Design model`**, and anything that
  holds across territories → an [`invariant/`](../map/invariant/) note. The four
  that exist today — 32-bit dimension overflow, no-owned-pixels, never-panic decode,
  oracle-agreement-is-not-independence — each carry a `## Where it will recur` test,
  which is the enumeration this bullet used to ask you to redo by hand.
- **Per-codec state the map does not yet name** (tile boundaries, quant tables,
  progressive pass state, palette/run state) goes into the issue *before*
  implementing — and if it turns out to hold outside its territory, Step 6's
  promotion obligation says it does not land until an invariant note exists.
- **Removing a field is the mirror image.** A value read *incidentally* elsewhere
  (feeding a boolean, gating a branch) is unpinned the moment you delete it — grep
  every read site, including ones that only compute something from it.

**To pin a runtime fact, instrument a throwaway probe** against the VM (a real
coordinate, an actual cap byte, the order a server sends surface commands), read the
number, delete the probe, and record the number in the issue. Reading the code is not
observing what it does.

**"Unconfirmed ≠ absent"** — a search not showing a server behaviour does not make it
absent; that is a gap to surface, never a silent load-bearing assumption. Its inverse:
**a cleared concern is recorded with its validity condition** ("this path is fine *as
long as the server advertises X*"), in the issue.

## Step 2 — boundary rule (sans-IO core vs adapter, ADR-0001)

- **The core is a pure state machine** — `bytes in → (Action, bytes) out`. **No I/O,
  no runtime embed, policy-agnostic.** It never reads a socket, never knows `tokio`,
  never sees a `TSRequest`.
- **Mechanism → core** (wire parsing, state transitions, codecs, surface/framebuffer
  composition). **Policy → adapter**: TLS trust (ADR-0005), credential source, frame-sink
  behaviour are *injected* by the host adapter (`justrdp-tokio`).
- **`sspi` (NLA CredSSP token loop) and `rustls` live in the adapter** — security-critical,
  non-RDP leaf deps (ADR-0002). The core owns every RDP-native protocol layer itself
  (X.224 · MCS · GCC · capability · session loop · virtual channel · codec · surface).
- **The host owns by definition** (not a workaround): the socket and runtime, the TLS
  trust decision, credentials, the frame sink / presentation, input device semantics,
  clipboard and redirection policy, reconnect strategy, and **every RDP feature flag**.
- The payoff: the core is **independently, deterministically testable** with no socket
  and no runtime (oracle round-trip + real VM).

**Do not misdiagnose a contract as a defect.** When something reads as a bug, first ask
*whose invariant broke*. Policy-agnosticism and the dirty-rect `FrameUpdate` (ADR-0010)
are contracts justrdp deliberately holds — "the core should resolve this for me" is a
host standing on nothing valid.

**No consumer workaround for an upstream defect.** The worked instance is the `sspi`
CredSSP defect (ADR-0004): it was reported and fixed *upstream*, bridged meanwhile with
`[patch.crates-io]`, and the bridge was deleted once the fix shipped (2026-08-10) — not
worked around locally at any point. When you feel the urge to compensate in a shallower layer to
make a test pass — **stop, explain, ask** — do not work around it alone and do not
silently file an issue and move on.

## Step 3 — the test-trust gate

Beyond `/tdd` RED → GREEN, a passing test earns trust only after two bars:
**discriminating power** (turn the fix off, confirm it goes red — a green from a test you
never saw fail is not evidence) and **right reason** (assert the side conditions: the
exact byte count, the state after, the branch that must *not* be taken).

Two justrdp-shaped traps for the first bar:

- **A differential-oracle test can be green for the wrong reason** — see the Step 4
  traps below; a vector both implementations decode identically proves agreement, not
  correctness.
- **A guard that only 32-bit reaches cannot go red on x64.** Dimension/offset overflow
  guards must be mutated and re-run on `i686-pc-windows-msvc` (memory
  `wasm32_overflow_proof_via_i686`, #151/#155), or the RED you never saw is on a target
  the gate never ran.

Where compilation itself enforces completeness (a new wire field every layer must
thread), strict RED is awkward — a round-trip test takes its place, but still write it
*before* the implementation.

## Step 4 — proof method per layer (real round-trip, not a fake)

| Layer | Real proof |
|---|---|
| **`justrdp-pdu`** | `encode → decode` round-trip on hand-built PDUs **plus** the proptest no-panic / round-trip properties (ADR-0008, #98). A decoder that only ever sees vectors we authored is untested against the input space a server actually spans |
| **`justrdp-codecs`** | a **differential oracle** (ADR-0003/0007): feed the same bitstream to *our* decoder **and** `ironrdp-graphics`, assert the output `Vec<u8>` is **byte-identical**. 100% pass is the gate to drop the dependency. Stage-boundary verification (ADR-0007) applies per pipeline stage, not only end-to-end |
| **`justrdp` (connect / session)** | a **real RDP VM** round-trip (`192.168.136.136`; memory `test_environment`) — the full connect sequence to session-active, not a mock server |
| **`justrdp-tokio`** | the same VM, driven end-to-end (its integration tests are `#[ignore]`d in CI by design — they need the VM, which is why `coverage.yml` excludes this crate) |
| **strongest — a real consumer** | **N/A: no consumer exists.** When one does, link a local build in via `[patch.crates-io]` / a path override in the consumer's manifest, run its **full** suite, and the strongest evidence is a consumer test that pinned the old bug as expected now *breaking* |

Traps this project must respect:

- **The oracle shares our lineage.** `ironrdp-graphics` and justrdp descend from the same
  reading of the same spec (memory `ironrdp_oracle_shares_lineage`), so byte-identical
  agreement is *not* independence — for ClearCodec and RemoteFX compositing in particular,
  cross-check FreeRDP before calling a match "proof".
- **A vector proves only what it contains.** A corpus can supply an axis and still miss the
  *combination* (a codec exercised, but never at a tile boundary, never with a quant table
  that changes mid-frame). Measure what the fixture actually exercises; do not infer
  coverage from the feature the fixture was named for.
- **One VM is one server.** The WS2022 box advertises a specific cap set
  (memory `vm_advertised_graphics_caps`) — it can *prove* the paths it exercises (#150/#91)
  and cannot say anything about the ones it does not advertise. "The VM is happy" is not
  "servers are happy".
- **x64 cannot reach the 32-bit guards** (memory `wasm32_overflow_proof_via_i686`).
- **A demo or a fake is a smoke test, not proof** (DoD ④).

## Step 5 — adversarial completeness pass (one lens, both corpora)

Gate on **enumeration risk**, not diff size: any change where *your own hidden-state
enumeration could be incomplete* (a decoder, a parser, a state machine with many edges,
cross-feature interaction) makes this mandatory. A genuinely closed surface may skip it —
**record that judgement explicitly**.

**One lens, briefed on both corpora — not one lens per corpus.** A lens holding half the
material can see that two things disagree but not which one is wrong, so every divergence
comes back to the main thread to be adjudicated from cold.

- **① this repo's siblings — from [`docs/map/`](../map/README.md), not from a list
  here.** The touched territory's `## Blast radius` *is* the sibling set, and its
  `## Cross-cutting invariants` carry the recurrence tests that derive the affected
  sites. A hand-kept copy in this file is what goes stale and disagrees, so there is
  deliberately none. Add `docs/plan.md` §0 for VM-proven traps.
- **② the reference** — FreeRDP and IronRDP real source at the known CVE points
  (rle/planar/clearcodec/nsc OOB; memory `rdp_decoder_robustness_refs`) and the `[MS-*]`
  section that governs the field.

**Carry into the brief, or the lens cannot grade its own findings:** the frontier (the
functions the diff touches + one hop), the open-issue list, **the tie-breaker row for this
layer**, **the deliberate-divergence table above**, and the four output grades
(`CONFIRMED` / `UNADJUDICATED` / `INERT` / `DELIBERATE`). A brief missing the last two
produces reference-shaped proposals that read as urgent defects.

**Direction, not just difference.** Only this layer diverges → move toward the reference.
This layer *and* its sibling decoders agree against the reference → a **family** decision:
hold the current behaviour and track the parity fix as one coordinated change.

**Unconditional triggers — three paths that run the pass regardless of the judgement
above, and the only places the second, *refuting* lens is worth its cost.** justrdp has no
money path, no production mutation and nothing destructive; here a path is sacred when it
is **silent** (wrong, and nothing crashes) or **irreversible**:

1. **Untrusted-input decoders and parsers.** Every byte comes from a server we do not
   control; a wrong bound yields plausible pixels or a panic (DoS), not an error. **Do
   not enumerate the surfaces here** — the derivation lives once, with the invariant:
   [untrusted decode never panics](../map/invariant/untrusted-decode-never-panics.md)
   carries the two commands that produce *what is parsed* and *what is fuzzed*, and the
   gap between them. The continuous half of this axis is **proptest (#98) + cargo-fuzz
   (#99)** (ADR-0008) — the fuzz lane is **nightly-only**, so a *new* target is not
   covered by the PR gate on the day it lands.
2. **The TLS trust decision** — `crates/justrdp-tokio/src/trust.rs` and
   `crates/justrdp/src/tls.rs` (ADR-0005, #36). Silent by construction: a wrongly-accepted
   chain produces a perfectly working session, and the host's whole security posture is
   this one decision.
3. **The NLA credential path** — the CredSSP token loop in `crates/justrdp-tokio/src/lib.rs`
   plus the SPKI public-key binding it authenticates against (`x509-cert`, in
   `crates/justrdp/src/{tls,connect}.rs`), and every `sspi` version bump (ADR-0004
   requires the real-VM suite for one). A wrong binding or token order can still
   complete a handshake.

A gap sends you back to Step 3. **Never drop a corpus because the fix looks small.**

## Step 6 — behavior-describing surfaces (sweep by hand)

- **`CONTEXT.md` glossary + `docs/adr/`** — the domain SoT, and a **write** surface, not
  only a read one: a change that falsifies a record's premise amends *that record* (a
  status note, a superseded-by line) in the same change. An ADR's Consequences must be
  *currently true*.
- **`docs/plan.md`** (§2–§23) — the build plan; keep the slice's entry honest, and add to
  §0 any trap the VM just proved.
- **[`docs/map/`](../map/README.md) — two obligations, and the second is what makes
  the map preventive rather than archival.** ① **Coverage**: is the touched territory
  present, and is its `## Blast radius` still right? (May lag.) ② **Promotion**: *is
  the fact this fix revealed also true outside this territory?* Answer by grep, in
  this repo's terms — *does it hold at any site that sizes a buffer from
  server-declared dimensions, parses an untrusted length, or forwards pixel data?* If
  yes, the change **does not land** until an `invariant/` note exists. (May **not**
  lag: the first site to hit a fact is where it is discovered, and at that moment no
  node exists — which is exactly how #151→#155 and #85→#162→#163 happened.)
- **`Cargo.toml`'s dependency comments** — each one states *why* a crate is here and,
  where it is temporary, what ends it. Those sentences are load-bearing and unchecked:
  the `sspi` fork-bridge comment outlived its condition by six weeks (ADR-0004
  Amendment 2026-08-10). When a dependency's rationale changes, the comment is part of
  the change.
- **Rustdoc on the public surface** ships as the crate's API docs — the surface most likely
  to still describe the old behavior.
- **Changelog: none.** No `CHANGELOG.md` and nothing published, so there is no snapshotted
  release note to keep consistent. Revisit at the first crates.io publish.
- **Reclaim now-false rationale** — a justification written in an earlier PR, issue, or ADR
  can be made false by a later one, and nobody re-reads it.

**Promotion destination and format.** A promoted rule becomes an **ADR** under
`docs/adr/NNNN-<kebab-title>.md`, following the house shape: `Status` (with amendment
history inline), `Context`, `Decision`, `Consequences`, and **`Rejected alternatives` with
reasons** — ADR-0002 and ADR-0007 are the models, both carrying later Amendments rather
than being rewritten. A record earns its place by **deriving** decisions already taken,
not by listing them.

**Areas that already carry a record** (the list the filing step checks *before* proposing
a spine — a cluster with a home never gets a second one). All **Accepted**; none Proposed:

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

**Tracker parent/child: GitHub sub-issues are in use on one cluster and nowhere else.**
Measured 2026-08-13, not inferred — an earlier revision of this paragraph asserted the
relation was unused because it said so, and the one command that checks it disagreed:

| Epic | `sub_issues` |
|---|---|
| **#158** (Progressive) | **7** — slices #167–#172, plus #194; #194 in turn carries #200 |
| #132, #45, #29, #21, #28, … | **0** |

**A `- [ ] #NNN` task list in the body does not create the relation.** #132's body lists
`#137`–`#141` in exactly the format #158's uses and has zero sub-issues, so #158's tree is
a deliberate act someone performed, not a side effect of the checklist. Enrolling an epic's
slices is therefore real work with a real result, and it is worth doing when you next touch
one. **Use the relation** for new follow-ups and spines rather than adding another prose
convention.

The API has two traps, both cost a few minutes to rediscover:

- `sub_issue_id` is the issue's **database id**, not its number, and `gh api` needs `-F`
  rather than `-f` — with `-f` it sends a string and the API answers **422**.
- Re-adding an existing child *also* answers **422**, with a message that reads as if the
  child belongs to some other parent: *"Issue may not contain duplicate sub-issues and Sub
  issue may only have one parent."* It usually means the edge is already there. **List the
  parent's `sub_issues` before believing it** — `.parent` is absent from the REST issue
  payload, so a child's own record cannot answer the question.

```sh
gh api repos/kihyun1998/justrdp/issues/<parent>/sub_issues --jq '.[].number'   # check first
ID=$(gh api repos/kihyun1998/justrdp/issues/<child> --jq .id)
gh api --method POST repos/kihyun1998/justrdp/issues/<parent>/sub_issues -F sub_issue_id=$ID
```

## Step 7 — gate matrix + PR

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check --manifest-path fuzz/Cargo.toml     # out-of-workspace blind spot
python .github/scripts/check_map.py             # docs/map: links, anchors, symbols, reciprocity
# + just-shield supply-chain scan (ADR-0006): SHA-pinned actions
# + 32-bit guards, when the change touches dimension/offset arithmetic:
#   cargo test -p justrdp-codecs --target i686-pc-windows-msvc
```

Run each gate **bare, never piped** (a pipeline's exit status is `tail`'s, so the gate
cannot fail), and **never move a threshold to turn a build green**.

**CI jobs — four workflows, three of them gates:**

| Workflow | Gate? | Notes |
|---|---|---|
| `test.yml` → job `test` | **yes** | fmt → clippy `-D warnings` → `cargo test --workspace`, stable, on PR + master |
| `test.yml` → job `map` | **yes** | `.github/scripts/check_map.py` — [`docs/map/`](../map/README.md) links, `#anchors`, `## Code` symbols, section sets, invariant↔territory reciprocity. Toolchain-free, so a docs-only PR answers without waiting for cargo |
| `fuzz.yml` | **yes** | nightly cargo-fuzz lane (#99) — a *new* target is not covered on the day it lands |
| `supply-chain.yml` | **yes** | just-shield, SHA-pinned actions (ADR-0006); pins auto-managed by `just-shield fix` + Dependabot |
| `coverage.yml` | **no** | cargo-llvm-cov discovery tool (#102), post-merge/dispatch, **no threshold**; scopes to the sans-IO core and excludes `justrdp-tokio` (its tests need the VM) |

- Branch → commit `feat(<scope>): … (#issue)` (**no `Co-Authored-By` / AI-attribution
  trailer** — memory `feedback_no_ai_attribution_external`) → squash PR (`Closes #issue`)
  → confirm CI green.
- Always label a new issue **triage + type** on creation (memory
  `feedback_label_issues_on_creation`); see `docs/agents/triage-labels.md`.
- Do **not** ask "shall I stop?" at a phase boundary of an agreed multi-step plan (memory
  `feedback_no_stop_prompts`).
- **After merge — downstream loop: N/A, nothing is published and there is no consumer**
  (see the crate map). Re-derive, never store, once that changes.

## War-story index

Per-incident and per-decision evidence lives in [`lessons.md`](lessons.md), indexed by step
and anchored to the ADRs and issues (#36, #61, #98, #99, #101, #127, #151/#155, #162/#163).
