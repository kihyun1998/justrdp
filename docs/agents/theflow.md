# theflow bindings (justrdp)

Project-specific data for the `theflow` skill (the working discipline for a
substantive change to the sans-IO core / codecs / adapter). The skill holds the
portable *method*; this file holds justrdp's *bindings* — which reference to
read, where the boundary falls, how to prove behavior, which gates to run. The
method defers every concrete value here. Per-incident evidence: [`lessons.md`](lessons.md).

Identity, the ubiquitous language, and the boundary invariant live in `CLAUDE.md`
and **`CONTEXT.md`**; decisions in **`docs/adr/`** (0001–0010); the build plan in
**`docs/plan.md`** (§2–§23). Prior art cross-checked throughout: **[MS-*] normative
specs · FreeRDP (C) · IronRDP (Rust) · a real RDP VM.**

## Crate / module map

Virtual workspace (no root `[package]`, edition 2024). `--workspace` is required
at the root and **does not build** the out-of-workspace `fuzz`.

| Member | In `--workspace`? | Role |
|---|---|---|
| `justrdp-pdu` | yes | **dependency-free** PDU encode/decode (0 external crates) |
| `justrdp` | yes | sans-IO core (connect/session state machine) + leaf deps (`rustls`, `x509-cert`) |
| `justrdp-codecs` | yes | codecs; owns them via phased-c2 with `ironrdp-graphics` as a **dev-dependency oracle** (ADR-0003) |
| `justrdp-tokio` | yes | ~30-line I/O adapter — `tokio` / `sspi` / `tokio-rustls` live **only** here |
| `fuzz` | **no** (own `[workspace]`) | cargo-fuzz, nightly CI only (#99) — the `--workspace` blind spot |

**`--workspace` blind spot:** `fuzz` is out of the workspace, so the top-level
gate does not even build it — a public-API change needs a separate `cargo check
--manifest-path fuzz/Cargo.toml`.

## Step 1 — reference routing table

Read real source with `gh api repos/<owner>/<repo>/contents/<path> --jq .content
| base64 -d > /tmp/x`, then `grep -n` / `sed -n`. **WebFetch is banned** — it
summarizes and drops handler bodies from large files. **Derive, don't copy** —
re-derive from spec and prove by differential test, not structural similarity (ADR-0003).

| Change type | Real source to read |
|---|---|
| **Wire / PDU / codec layout** | the **normative spec first** — `[MS-RDPBCGR]`, `[MS-RDPRFX]`, `[MS-RDPEGDI]`, … — for layout, flags, state transitions (cite the section number). Spec is the "first principles" source RDP has that a terminal does not |
| **Hidden state · server tolerance · edges** | **FreeRDP** (C, the CVE knowledge source) + **IronRDP** (Rust) real source. Spec-unwritten tolerance (caps servers violate — #101, ADR-0009) comes from here |
| **Concept ≠ mechanism** | a codec we newly own may be absent from IronRDP, but its components (bit reader, tile boundaries, color space) exist in FreeRDP/spec — read both |
| **Published / external state** | crates.io for the `sspi` fork status (ADR-0004, #61 — remove the `[patch.crates-io]` once Devolutions/sspi-rs#689 lands) |

**Spec ≠ interop:** code that matches the spec can still not be byte-identical to
a real server — *derive from spec, prove against oracle/VM* (Step 4).

## Step 2 — boundary rule (sans-IO core vs adapter, ADR-0001)

- **The core is a pure state machine** — `bytes in → (Action, bytes) out`. **No
  I/O, no runtime embed, policy-agnostic.** It never reads a socket, never knows
  `tokio`, never sees a `TSRequest`.
- **Mechanism → core** (wire parsing, state transitions, codecs). **Policy →
  adapter** (TLS trust = ADR-0005, credential source, frame-sink behavior) is
  *injected* by the host adapter (`justrdp-tokio`).
- **`sspi` (NLA CredSSP token loop) and `rustls` live in the adapter** — they are
  security-critical, non-RDP leaf deps (ADR-0002); the core owns every RDP-native
  protocol layer itself (X.224 · MCS · GCC · capability · session loop · virtual
  channel · codec · surface).
- The payoff: the core is **independently, deterministically testable** with no
  socket and no runtime (oracle round-trip + real VM).

## Step 4 — proof method per layer (real round-trip, not a fake)

| Layer | Real proof |
|---|---|
| **codecs** | a **differential oracle** (ADR-0003/0007): feed the same bitstream to *our* decoder **and** `ironrdp-graphics`, assert the `Vec<u8>` is **byte-identical**. 100% pass is the gate to drop the dependency |
| **connect / session logic** | a **real RDP VM** round-trip (`192.168.136.136`; memory `test_environment`) |

A demo or a fake passing is **not** proof (DoD ④). The sans-IO design is what
makes deterministic core tests possible without a socket — that is its dividend.

## Step 5 — adversarial completeness (two lenses, via subagents)

Gate on **enumeration risk**: a decoder/parser change where your own hidden-state
enumeration could be incomplete (many edges/states, untrusted parsing) makes this
**mandatory**. Two lenses:
- **① this repo's siblings** — OOB / boundary diff across our sibling decoders
  (rle / planar / nsc).
- **② the reference source** — FreeRDP / IronRDP real source at the known CVE
  points (rle/planar/clearcodec/nsc OOB; memory `rdp_decoder_robustness_refs`).

The automation of this axis is **proptest no-panic (#98) + cargo-fuzz (#99)**
(ADR-0008). A closed surface (purely mechanical) may skip it — record that
judgement.

## Step 6 — behavior-describing surfaces

- **`CONTEXT.md` glossary + `docs/adr/`** — the domain SoT. A new concept is
  defined here first; a flipped decision flips the ADR (its Consequences must be
  *currently true*).
- **`docs/plan.md`** — the build plan (§2–§23); keep a slice's plan entry honest.
- **`[patch.crates-io]` in `Cargo.toml`** — the temporary `sspi` fork; remove it
  and bump `sspi` once #689 lands (ADR-0004, #61).
- Rustdoc on the public surface ships as the crate's API docs.

## Step 7 — gate matrix + PR

```
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all --check
cargo check --manifest-path fuzz/Cargo.toml     # out-of-workspace blind spot
# + just-shield supply-chain (ADR-0006): SHA-pinned-action scanner
```

- Branch → `feat(<scope>): … (#issue)` (**no `Co-Authored-By` / AI-attribution**
  trailer — memory `feedback_no_ai_attribution_external`) → squash PR
  (`Closes #issue`) → confirm CI green: **`test` / `fuzz` / `supply-chain`**
  (three jobs; memory `justrdp_ci_policy`).
- Always label a new issue with **triage + type** on creation (memory
  `feedback_label_issues_on_creation`).
- Do **not** ask "shall I stop?" at a phase boundary of an agreed multi-step plan
  (memory `feedback_no_stop_prompts`).
- **No consumers yet** (this is a library still building out) — theflow's
  downstream verification/migration steps are N/A until one exists; derive on the
  spot, never store a list.

## War-story index

Per-incident and per-decision evidence lives in [`lessons.md`](lessons.md),
indexed by step and anchored to the ADRs / issues (#36, #61, #98, #99, #101).
