# 0013 — A build input is pinned, and every pin names its bumper

- Status: Accepted (issue #235)
- Date: 2026-08-24

## Context

This repo already pins two of its inputs, and it decided each one separately.

- **GitHub Actions** are pinned to 40-character commit SHAs, because a mutable `@v4` ref is one the
  action's author can silently re-point after review (ADR-0006, the tj-actions/CVE-2025-30066
  class).
- **`sspi`** is pinned to an exact `=0.21.3` rather than a caret range, because ADR-0004's
  contribute-and-bridge rule requires the version-bump PR to be the thing that runs the real-VM
  suite.

The **compiler** was not pinned, and nothing had decided that it should not be — it was simply never
a participant. `test.yml` ran `rustup toolchain install stable`, so the PR gate compiled with
whatever `stable` resolved to on the day it ran.

**What that cost, measured in #235.** A PR touching only `justrdp-codecs` went red on `Clippy` for
`clippy::chunks_exact_to_as_chunks`, a lint that had become default-on and fired on 40 pre-existing
sites across all four crates, none of them touched by that change. The maintainer's host was on
`clippy 0.1.96 (2026-05-25)` and CI on `1.98.0 (2026-08-18)` — so the lint that failed the gate
**could not fire locally at all**. Three properties made that worse than a one-off:

1. **The local gate stopped answering its own question.** `docs/agents/theflow.md` Step 7 tells the
   agent not to sit watching CI during implementation, *"the local gates mirror it"*. While the
   compiler floats, that sentence is false.
2. **The failure was unbounded from the inside.** `clippy` stops per crate, so a red run names only
   the first crate to fail, and a host that cannot run the newer clippy cannot enumerate what else
   is behind it.
3. **The cost landed on unrelated work.** Drift surfaces on whichever PR happens to be open, so the
   change that pays is never the change that caused it.

**The premise that made this look like a hard trade was false.** #235 was filed weighing a pin
against *"Dependabot does not watch this file — so the pin needs its own reason to be raised, or it
becomes the next artifact that outlives its condition"*, and proposed a scheduled bump job as the
expensive third way. Checked against the source rather than the sentence: `rust_toolchain` has been
a first-class ecosystem in `dependabot-core` since **2025-06-18** (initial updater `71668c6f`),
GitHub documents `package-ecosystem: "rust-toolchain"` for both version and security updates, and
the updater's `filter_by_version_type` bumps a *version* channel while deliberately declining a bare
stability channel. So the automation already existed, and the third option was machinery for a job
something else was doing. That is the same failure ADR-0004's Amendment records — three artifacts
said *"remove the fork when #689 ships"* six weeks after it had shipped — and it is why this record
is about the rule rather than about the compiler.

**Measured before deciding, not after:** the workspace is clean on the current stable.
`cargo +1.98.0 clippy --workspace --all-targets -- -D warnings`, `cargo +1.98.0 fmt --all --check`
and `cargo +1.98.0 check --manifest-path fuzz/Cargo.toml` all exit 0 on the maintainer's host, and
CI's own log for the last `master` run shows it installed `stable = 1.98.0` and passed. Property 2
above is therefore closed by number rather than by argument: nothing was waiting behind
`chunks_exact`, so pinning at 1.98.0 costs no code change.

## Decision

**Every input that decides what a gate *means* is pinned to an exact version, and every pin names
the automation that raises it.** The two halves are one rule: a pin without a named bumper is not a
conservative choice, it is a deferred one, and ADR-0004's `[patch.crates-io]` bridge is this repo's
worked example of what that costs.

Concretely, for the compiler:

- `rust-toolchain.toml` at the repo root pins `channel = "1.98.0"` with `profile = "minimal"` and
  `components = ["clippy", "rustfmt"]`. **Three-part, not `"1.98"`** — a two-part channel resolves
  to the newest patch release, which reintroduces an unreviewed compiler by a smaller door.
- `.github/dependabot.yml` carries a `rust-toolchain` ecosystem. That entry is not an optimization;
  it is the condition the pin ships with, and removing it re-opens this decision.
- CI installs the pinned toolchain by **naming no toolchain**: argless `rustup toolchain install`
  reads the file. Naming `stable` would install a second, different compiler that the pin then
  overrides, leaving a job log that misreports what ran.
- **Nightly is not affected.** `fuzz.yml` says `cargo +nightly fuzz run`, and an explicit
  `+toolchain` outranks `rust-toolchain.toml` in rustup's override order. libFuzzer needs nightly by
  construction, so the pin must not reach it, and it does not.
- **The pin does not carry `targets`.** The file is shared with CI, which runs on `ubuntu-latest`;
  naming the 32-bit Windows target the overflow proofs use (`i686-pc-windows-msvc`, #151/#155)
  would make every Linux job fetch a cross-target std it never builds.

The rule generalizes past the compiler, which is the point of recording it rather than closing #235
with a file. A future input — a `cargo-fuzz`, a `just-shield`, a formatter — is in scope when a
gate's verdict changes with its version, and the question to answer at that moment is *"what raises
this pin?"*, not *"should this be pinned?"*.

## Consequences

- **The local gate mirrors CI again, so `theflow` Step 7's premise is true rather than
  aspirational.** Green locally now means green on the PR gate for the same reasons, and the
  maintainer's host and the runner disagree only about the operating system.
- **Toolchain drift arrives as its own reviewable change.** A new default-on lint lands in the
  Dependabot bump PR, where the sweep it requires is attributable to the bump. It never again lands
  on whichever unrelated PR happened to be open, which was #235's worst property.
- **The pin's freshness is now observable rather than remembered.** An un-merged bump PR sitting in
  the queue *is* the report that the compiler is behind; there is no state to check by hand and no
  date anyone has to recall. ADR-0004's Amendment failed on precisely the opposite shape — a
  tripwire that fired on a transition and so could not catch a state — and a weekly PR is a state,
  re-asserted every week.
- **New diagnostics arrive later than they would have.** Between a Rust release and the bump PR
  merging, a lint that would have found a real defect is not running. This is the genuine cost, and
  it is accepted with its bound rather than argued away: the window is at most one Dependabot cycle,
  the bump is a normal reviewable PR, and nothing prevents raising the pin by hand sooner.
- **A contributor's first build in this repo downloads a toolchain.** rustup installs the pinned
  channel on the first `cargo` invocation. One-time, and it is the same download CI performs.
- **`cargo install cargo-fuzz` in the fuzz lane now builds under the pin.** Intended — one
  reproducible compiler builds the tool — with the boundary condition that a pin left far enough
  behind cargo-fuzz's own MSRV would fail at install time rather than during fuzzing.

## Rejected alternatives

- **Keep floating and treat the periodic sweep as routine (#235's option (b)).** Rejected. Its only
  claimed advantage was zero maintenance cost, and that advantage does not exist once the bump is
  automated — both options cost one PR per drift event. What separates them is *which* PR pays: the
  floating one charges it to unrelated work and leaves the local gate unable to answer whether a
  branch is green.
- **Pin, plus a scheduled workflow that opens the bump PR (#235's option (c)).** Rejected as
  machinery for a job Dependabot already does, on a config file this repo already maintains for
  three other ecosystems. It was proposed only because the premise "Dependabot does not watch this
  file" went unchecked; with that corrected, (c) is (a) plus a workflow to maintain.
- **Pin the compiler without the Dependabot entry.** Rejected — this is the ADR-0004 shape stated in
  advance. A pin whose bump depends on someone remembering is an artifact that will outlive its
  condition, and the only question is by how many weeks.
- **A two-part channel (`"1.98"`), so patch releases arrive without a PR.** Rejected. A patch release
  is still a different compiler with different diagnostics, and the reason to pin is reviewability,
  not major-version stability. It also silently narrows what the Dependabot lane watches, since the
  updater preserves the format it finds.
- **Amend ADR-0006 instead of writing this record.** Rejected. ADR-0006's title, threat model (a
  re-pointed tag, CVE-2025-30066) and enforcement (just-shield R1/R5/R7) are all specific to GitHub
  Actions, and none of the three reaches a compiler. The shared thing is the *rule*, not the
  mechanism — so this record derives ADR-0006 and ADR-0004 rather than widening either.
- **Declare `rust-version` (MSRV) in the workspace manifest instead.** Rejected as a different
  control answering a different question. `rust-version` states the oldest compiler that may build
  this code, which is a promise to consumers; the pin states the one compiler the gate is defined
  against. Nothing is published yet (ADR-0011's crate map), so the promise has no audience, and even
  with one the two would coexist rather than substitute.
