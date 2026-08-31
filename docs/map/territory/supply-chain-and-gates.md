# Supply chain & CI gates

## What it is

What has to be true before a change lands, and what the project trusts to build it:
four GitHub Actions workflows (three gating, one discovery), SHA-pinned third-party
actions and an exactly-pinned compiler both kept current by Dependabot, and a small,
deliberately-chosen, registry-only dependency set (the one `[patch.crates-io]` fork bridge this repo ever carried was
exited on 2026-08-10). Shipping is something the system does, so this is a territory
like any other.

## Governing decisions

- [ADR-0006](../../adr/0006-supply-chain-action-pinning.md) — pin third-party
  actions to commit SHAs, least-privilege permissions; `just-shield` scans for it and
  Dependabot keeps the pins current.
- [ADR-0002](../../adr/0002-dependency-boundary.md) — which dependencies may exist at
  all: leaf, security-critical, non-RDP only.
- [ADR-0004](../../adr/0004-sspi-contribute-and-bridge.md) — the fork-bridge rule and
  its removal obligation.
- [ADR-0008](../../adr/0008-robustness-testing-fuzz-and-property.md) — why fuzzing is
  a nightly lane rather than a PR gate.
- [ADR-0013](../../adr/0013-pinned-build-inputs.md) — a build input is pinned to an exact
  version and every pin names its bumper; the compiler is the third participant, after
  actions (0006) and `sspi` (0004).

## Design model

- **Four gating workflows and one report.** `test.yml` — two jobs: `test`
  (fmt → clippy `-D warnings` → `cargo test --workspace`) and `map`
  (`.github/scripts/check_map.py`, toolchain-free so a docs-only PR answers without
  waiting for cargo); `fuzz.yml` (nightly libFuzzer); `supply-chain.yml`
  (`just-shield`); `overflow-32bit.yml` (the 32-bit target, below). `coverage.yml`
  reports with no threshold and does not fail a build.
- **One gate exists because the others structurally cannot fail.** On x86-64 a wrapping
  `width * height * bytes_per_pixel` is merely a large number, so the dimension-overflow
  guards ([the invariant](../invariant/decoder-dimension-overflow-32bit.md)) are green
  everywhere the other gates run. `overflow-32bit.yml` builds
  `justrdp-codecs` + `justrdp` for `i686-pc-windows-msvc` on a Windows runner, path-filtered
  to the three crates that hold the sites because that runner bills at 2x. Two scoping notes
  that were measured rather than assumed: the pre-existing local command named
  `-p justrdp-codecs` **alone**, which does not reach the EGFX and framebuffer sites the
  invariant lists in `justrdp`; and `i686-unknown-linux-gnu` on ubuntu would give the same
  32-bit `usize` at 1x, but nothing here has run it, so the cheaper shape is a measurement
  away rather than an argument away.
- **Every job is bounded, and the number that justifies it lives in exactly one place.** A job
  with no `timeout-minutes` gets GitHub's default of **360**, so a hang costs six runner-hours
  and is indistinguishable from a slow queue. Measured on 2026-08-31 (#262), when a hanging
  `justrdp-codecs` property ran to the kill: **10 cancelled jobs, ~56.4 runner-hours in one
  day** — `test` 6 jobs (140/360/360/360/360/361 min) and `coverage` 4 jobs at 360 each. Every
  job in all five workflows now carries a bound (test 20, map 10, coverage 30, overflow-32bit
  30, just-shield 10, fuzz `targets` 10, fuzz `fuzz` 30), each sized against its own measured
  healthy maximum, and **`test.yml`'s block is the one that carries the incident numbers** —
  the others point at it rather than copying them, for the same reason the fuzz matrix is
  derived rather than transcribed. Two scoping notes: `coverage.yml` is in that table because
  it runs `cargo llvm-cov --workspace --exclude justrdp-tokio`, i.e. the *same* property, so
  bounding only the gating file would have left 24 of those 56 hours unbounded on the
  post-merge lane nobody watches a PR check for; and `overflow-32bit.yml` was never killed but
  runs the same property on a Windows runner that bills at **2x**, which makes an unbounded
  hang there the most expensive one available.
- **A gate is only as good as its failure directions, and that is now a command
  rather than a memory** — `python3 .github/scripts/check_map.py --selftest`, run in
  CI ahead of the gate itself. It builds a throwaway mini-map in a temp directory,
  breaks one thing at a time, and requires the gate to notice: **eight defect kinds**
  (broken link, broken anchor, missing section, symbol absent from the tree, symbol
  absent from *the file the bullet names*, symbol outside *the directory the bullet
  names*, path that does not exist, one-way invariant edge) plus a **baseline** case
  requiring a known-good map to pass clean. The baseline is not ceremony: a gate with
  false positives gets ignored, and an ignored gate returns its defect class to being
  silent, so "does not fire on good input" is a failure direction like the others —
  and it is the case that caught two of the five mutations run against #224's change.
  This bullet used to say "was verified … fail on each of five defect kinds", which was
  true, unrepeatable, and had already drifted: the fifth kind was checked tree-wide, so
  a bullet could name a symbol at a path it had moved out of and pass (#221, fixed in
  #224).
- **`--workspace` is not "everything".** `fuzz` has its own `[workspace]`, so the top
  gate does not even *build* it; a public-API change needs
  `cargo check --manifest-path fuzz/Cargo.toml`. Note what that command still does not
  reach: it builds the `[[bin]]` targets the manifest declares, so a `fuzz_targets/*.rs`
  with no `[[bin]]` entry is invisible to it too.
- **A workflow may not keep its own copy of a list the repo already answers** (#200).
  `fuzz.yml`'s matrix was a hand-kept transcription of `ls fuzz/fuzz_targets/` and
  drifted twice in silence — `nscodec` (#143) and `progressive` (#192) each shipped a
  compiling target that CI never ran. It now derives the matrix in a `targets` job and
  fails when `fuzz/Cargo.toml` disagrees with the directory. **Derived from the
  directory, not the manifest**, because the manifest is the copy that can be wrong
  quietly: a missing `[[bin]]` compiles nothing and reports nothing.
- **Pinning is cheap only because it is automated** — `just-shield fix` writes the
  SHA, Dependabot bumps it with a version comment. That pairing is the whole reason
  the earlier "pinning is unmaintainable" objection was resolved.
- **The compiler is a pinned input too, and the gate only means something because of it**
  (ADR-0013). `rust-toolchain.toml` pins `channel = "1.98.0"` exactly; the `rust-toolchain`
  Dependabot ecosystem raises it. Before the pin, `test.yml` installed whatever `stable`
  resolved to that day while the maintainer's host sat three months back, so a green local
  `clippy` said nothing about the PR gate — #235, where a `justrdp-codecs` change went red
  on 40 pre-existing sites in four crates it never touched, and the lint that failed it
  **could not fire locally at all**. Three properties of the pin are load-bearing rather
  than incidental: it is **three-part** (a two-part channel resolves to the newest patch,
  which is an unreviewed compiler by a smaller door); CI installs it by **naming no
  toolchain** (argless `rustup toolchain install` reads the file, where naming `stable`
  would install a second compiler the pin then overrides and leave the log misreporting
  what ran); and it carries **no `targets`**, because this file is shared with
  `ubuntu-latest` runners that would fetch the i686 Windows std they never build.
- **The pin does not reach the fuzz lane, by rustup's own ordering.** An explicit
  `+toolchain` outranks `rust-toolchain.toml`, so `cargo +nightly fuzz run` keeps nightly —
  which libFuzzer needs by construction. It *does* reach `cargo install cargo-fuzz`, which
  is intended, with the boundary condition that a pin far enough behind cargo-fuzz's MSRV
  fails at install time rather than during fuzzing.
- **A fork bridge is temporary by construction**: it may contain only commits already
  PR'd upstream, and it carries a removal obligation.
- **The Dependabot cargo job is a tripwire, not just an updater** — its `sspi` bump
  PR is the designated signal to run ADR-0004's removal checklist.

## Code

- `.github/workflows/` — `test.yml` (jobs `test` + `map`), `fuzz.yml`,
  `supply-chain.yml`, `overflow-32bit.yml`, `coverage.yml`
- `.github/scripts/check_map.py` — the map gate (`selftest`, `scope_text`,
  `check_code`, `check_links`, `check_reciprocity`); its scope is declared in its own
  docstring rather than inferred
- `.github/dependabot.yml` — weekly cargo, rust-toolchain and github-actions ecosystems
- `rust-toolchain.toml` — the exact compiler pin (ADR-0013); read by every `cargo`
  invocation in the tree, `fuzz/` included, since rustup discovers it by walking up
- `Cargo.toml` — `[workspace.dependencies]` (exact pin `sspi = "=0.21.3"` per ADR-0004)
- `fuzz/Cargo.toml` — the out-of-workspace member

## Reference behaviour

**None.** No verified external-fact store, and this territory is the one that keeps paying
for that. Two external facts it depends on continuously are checked ad hoc rather than
recorded, and **both have now been wrong in an artifact**:

- *Which `sspi` version on crates.io contains the fix.* Three artifacts said "remove the
  fork when #689 ships"; it had shipped six weeks earlier (ADR-0004 Amendment).
- *What Dependabot can watch.* #235 weighed its whole decision against "Dependabot does not
  watch `rust-toolchain.toml`". `rust_toolchain` had been a first-class ecosystem in
  `dependabot-core` since 2025-06-18 and is documented by GitHub as
  `package-ecosystem: "rust-toolchain"`. One query settled it, and it collapsed the issue's
  three options into one.

The shape is identical both times: a sentence about an external system, written once, load-bearing,
and never re-read. Verify at the source before a decision rests on it.

## Cross-cutting invariants

**None.**

## Blast radius

- [Verification harness](verification-harness.md) — the gates decide which proofs
  actually run, and when.
- [NLA / CredSSP authentication](nla-credssp.md) — the fork bridge is that
  territory's dependency.
- [TLS transport security & trust](tls-transport-security.md) — the `ring` provider
  choice is a build-time constraint on Windows.
- [Bitmap codecs](bitmap-codecs.md) — the nightly-only fuzz lane is the gap between
  a new decoder landing and being fuzzed.

## Known holes / open

- **A git dependency outlived its reason by six weeks, and the tripwire meant to catch
  that could not fire.** The `[patch.crates-io]` fork pin was removed on 2026-08-10
  (see [NLA / CredSSP](nla-credssp.md)), but it should have gone when
  Devolutions/sspi-rs#689 shipped in `sspi` 0.21.1 on **2026-06-26**. Dependabot's
  comment frames *a new sspi release* as the signal to run the removal checklist —
  three releases shipped and nothing happened, because the condition was already met
  by the first one. **A tripwire that fires on a transition cannot catch a state.**
- **The dependency graph is now registry-only again** — no `git` sources in
  `Cargo.lock`, so every dependency carries a checksum. Worth keeping true: a git
  dependency is the one supply-chain hole `just-shield` does not scan for.
- ~~**No i686 / 32-bit job exists.**~~ **Closed** by `overflow-32bit.yml` (see the design
  model above). What remains is a smaller, named gap: `targets` is still deliberately out of
  `rust-toolchain.toml` because that file is shared with the ubuntu runners, so the **local**
  i686 run needs its own `rustup target add` after every toolchain bump — which is exactly how
  it silently stopped working a day after ADR-0013 landed. The gate matrix carries the line;
  nothing enforces it locally.
- **The bump lane's *timing* is upstream's, and upstream has an open defect in it.**
  dependabot-core#15596 (*"Fix cooldown filtering for Rust toolchains"*) is open, so a
  toolchain bump PR may arrive later than the weekly schedule implies. The lane's existence
  is what ADR-0013 requires and that is verified at source; its punctuality is not, and a
  pin that stays behind is a quiet loss of new diagnostics rather than a red gate.
- **Documentation is only half-gated.** `docs/map/` now has a link/anchor/symbol/
  section/reciprocity gate, but **rustdoc is still unbuilt in CI** — no
  `cargo doc --no-deps` with `-D warnings`, so a public doc-comment can link a private
  item, or describe behaviour that no longer exists, and every gate stays green. That
  is exactly how the adapter's "~30 lines" sentence shipped to docs.rs.
- **A timeout bounds the *gate*, not the loop, and the local run is still unbounded.**
  `timeout-minutes` is a GitHub-Actions key; a maintainer running `cargo test --workspace` on
  the pinned toolchain has no equivalent and a hanging property still hangs forever there. This
  does not falsify ADR-0013's *"the local gate mirrors CI"* consequence — that claim is about
  the **compiler**, and it holds — but it is the one axis on which local and CI now genuinely
  differ, and it is worth naming rather than discovering. The in-repo mitigation is per-test and
  belongs to whoever writes the test: drive the call on a worker thread and fail at a deadline,
  which is what `to_rgba_returns_promptly_for_a_zero_extent_of_any_height` does.
- No release/publish workflow exists yet; nothing is on crates.io, so the whole
  cross-repo half of the discipline is inert by construction.
