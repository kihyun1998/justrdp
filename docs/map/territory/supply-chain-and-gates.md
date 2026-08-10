# Supply chain & CI gates

## What it is

What has to be true before a change lands, and what the project trusts to build it:
four GitHub Actions workflows (three gating, one discovery), SHA-pinned third-party
actions kept current by Dependabot, and a small, deliberately-chosen, registry-only
dependency set (the one `[patch.crates-io]` fork bridge this repo ever carried was
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

## Design model

- **Three gating workflows and one report.** `test.yml` — two jobs: `test`
  (fmt → clippy `-D warnings` → `cargo test --workspace`) and `map`
  (`.github/scripts/check_map.py`, toolchain-free so a docs-only PR answers without
  waiting for cargo); `fuzz.yml` (nightly libFuzzer); `supply-chain.yml`
  (`just-shield`). `coverage.yml` reports with no threshold and does not fail a build.
- **A gate is only as good as its failure directions.** The map gate was verified to
  pass on known-good notes, fail on each of five defect kinds (broken link, broken
  anchor, missing section, unresolvable symbol, one-way invariant edge), and ignore
  link-shaped text inside code spans — because a gate with false positives gets
  ignored, and an ignored gate returns its defect class to being silent.
- **`--workspace` is not "everything".** `fuzz` has its own `[workspace]`, so the top
  gate does not even *build* it; a public-API change needs
  `cargo check --manifest-path fuzz/Cargo.toml`.
- **Pinning is cheap only because it is automated** — `just-shield fix` writes the
  SHA, Dependabot bumps it with a version comment. That pairing is the whole reason
  the earlier "pinning is unmaintainable" objection was resolved.
- **A fork bridge is temporary by construction**: it may contain only commits already
  PR'd upstream, and it carries a removal obligation.
- **The Dependabot cargo job is a tripwire, not just an updater** — its `sspi` bump
  PR is the designated signal to run ADR-0004's removal checklist.

## Code

- `.github/workflows/` — `test.yml` (jobs `test` + `map`), `fuzz.yml`,
  `supply-chain.yml`, `coverage.yml`
- `.github/scripts/check_map.py` — the map gate; its scope is declared in its own
  docstring rather than inferred
- `.github/dependabot.yml` — weekly cargo + github-actions ecosystems
- `Cargo.toml` — `[workspace.dependencies]` (exact pin `sspi = "=0.21.3"` per ADR-0004)
- `fuzz/Cargo.toml` — the out-of-workspace member

## Reference behaviour

**None.** No verified external-fact store. The one external fact this territory
depends on continuously — *which `sspi` version on crates.io contains the fix* — is
checked ad hoc rather than recorded.

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
- **No i686 / 32-bit job exists**, so the dimension-overflow class is unguarded in CI
  (see [the invariant](../invariant/decoder-dimension-overflow-32bit.md)).
- **Documentation is only half-gated.** `docs/map/` now has a link/anchor/symbol/
  section/reciprocity gate, but **rustdoc is still unbuilt in CI** — no
  `cargo doc --no-deps` with `-D warnings`, so a public doc-comment can link a private
  item, or describe behaviour that no longer exists, and every gate stays green. That
  is exactly how the adapter's "~30 lines" sentence shipped to docs.rs.
- No release/publish workflow exists yet; nothing is on crates.io, so the whole
  cross-repo half of the discipline is inert by construction.
