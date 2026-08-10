# Supply chain & CI gates

## What it is

What has to be true before a change lands, and what the project trusts to build it:
four GitHub Actions workflows (three gating, one discovery), SHA-pinned third-party
actions kept current by Dependabot, a small and deliberately-chosen dependency set,
and one temporary `[patch.crates-io]` fork bridge. Shipping is something the system
does, so this is a territory like any other.

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

- **Three gates and one report.** `test.yml` (fmt → clippy `-D warnings` → `cargo
  test --workspace`), `fuzz.yml` (nightly libFuzzer), `supply-chain.yml`
  (`just-shield`) gate; `coverage.yml` reports with no threshold and does not fail a
  build.
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

- `.github/workflows/` — `test.yml`, `fuzz.yml`, `supply-chain.yml`, `coverage.yml`
- `.github/dependabot.yml` — weekly cargo + github-actions ecosystems
- `Cargo.toml` — `[workspace.dependencies]`, `[patch.crates-io]`
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

- **A git dependency outlived its reason, and its tracker is closed.** The
  `[patch.crates-io]` fork pin is still here although Devolutions/sspi-rs#689 shipped
  in `sspi` 0.21.1 on **2026-06-26**; the three artifacts naming **#61** — `Cargo.toml`,
  `.github/dependabot.yml`, ADR-0004 — point at a closed issue. See
  [NLA / CredSSP](nla-credssp.md) `## Known holes / open` for the measured removal
  attempt and what blocks it (the VM's credentials, not the bump).
- **Dependabot's tripwire cannot fire for a condition already met.** Its comment
  frames a *new* sspi release as the signal to run the removal checklist — but three
  releases (0.21.1/.2/.3) have shipped since the fix and the patch is still here, so
  the mechanism the ADR relies on has already been observed not to work.
- **No i686 / 32-bit job exists**, so the dimension-overflow class is unguarded in CI
  (see [the invariant](../invariant/decoder-dimension-overflow-32bit.md)).
- Nothing gates documentation: no rustdoc build, no link check — which is how a
  docs.rs sentence like the adapter's "~30 lines" stays wrong.
- No release/publish workflow exists yet; nothing is on crates.io, so the whole
  cross-repo half of the discipline is inert by construction.
