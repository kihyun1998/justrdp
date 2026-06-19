# 0006 — Supply-chain hardening for GitHub Actions: pin third-party actions, least privilege

- Status: Accepted (issue #99 — reintroducing CI for the fuzz lane; formalizes the "supply-chain gate (ADR-0006)" referenced by issues #99 and #101)
- Date: 2026-06-19

## Context

The per-PR build/test/clippy workflow was dropped (commit `2ca6c87`, "No longer running CI in this repo") because a blocking gate was too much friction for a solo, fast-moving repo. Issue #99 brings CI **back**, but deliberately not as that gate: a weekly, non-blocking **fuzz** lane (ADR-0008 §2) plus a **supply-chain** check. Reintroducing any workflow reopens a supply-chain question that the dangling "ADR-0006" references in issues #99 and #101 never actually wrote down.

A GitHub Actions workflow runs third-party code with access to the repo token and any secrets in scope. A `uses:` reference to a **mutable** ref — a tag (`@v4`) or branch (`@master`) — is a reference the action's author (or anyone who compromises the action's repo) can silently re-point to different code after review. This is not hypothetical: in the **tj-actions/changed-files** compromise (CVE-2025-30066, March 2025) an attacker retroactively moved version tags to a commit that dumped CI secrets; repositories pinning by tag were hit, those pinning by commit SHA were not. For a library whose entire thesis is a hardened trust boundary ("zero C in the trust boundary", ADR-0002), letting CI trust mutable references is incoherent.

We also already own a tool for exactly this: **just-shield** (`kihyun1998/just-shield`), a dependency-free scanner of GitHub Actions supply-chain posture. Because it shares this repo's owner it is first-party here — adopting it adds no new third-party trust.

## Decision

Every GitHub Actions workflow in this repo is bound by the following policy, **mechanically enforced by just-shield in CI**.

### 1. Action pinning (just-shield R1)

- **Third-party actions** (any owner that is not this repo's owner and not GitHub itself) **must** be pinned to a full 40-character commit SHA, with the human-readable version in a trailing comment (`# v1.2.3`).
- **GitHub-owned actions** (`actions/*`, `github/*`) **may** use a version tag — GitHub is a higher-trust publisher and the tj-actions class was a third-party action. Pinning them to SHA is encouraged but not required. (In practice we pin these too, because `just-shield fix` makes it free — see §3.)
- A reference may be pinned to a SHA only if that SHA is reachable from the action repo's canonical history (just-shield R5 rejects imposter commits, and the commit a SHA resolves to — never the annotated-tag object — is what gets pinned).

### 2. Least privilege (just-shield R7)

Every workflow declares an explicit `permissions:` block; the default is `contents: read`. No workflow uses `write-all` or leaves permissions undeclared. A job needs broader scope only for a stated reason (e.g. `security-events: write` to upload SARIF).

### 3. Enforcement and why it is cheap

- `.github/workflows/supply-chain.yml` runs `just-shield scan --strict` on any change under `.github/workflows/**`. A 🔴 (or, under `--strict`, 🟡) finding fails the job; the workflow's actions are themselves SHA-pinned.
- `just-shield fix` resolves mutable refs to SHAs automatically — so the one real cost of SHA-pinning (looking up and updating the hash by hand) does not exist here.
- The `github-actions` Dependabot ecosystem (`.github/dependabot.yml`) opens weekly bump PRs that advance the pinned SHA and its version comment together. Pins therefore stay **immutable and current** at once — the standard objection to SHA-pinning ("you freeze the action and stop getting updates") does not apply.

## Consequences

- **The CI we brought back cannot be turned against us through a moved tag.** The fuzz lane's own actions are pinned; a tag-hijack of any of them is a no-op against this repo, and a new mutable reference cannot land without failing the supply-chain job.
- **Policy, tool, and CI share one definition.** just-shield's R1/R5/R7 rules *are* this ADR's policy; there is no second prose spec to drift. The fuzz lane (ADR-0008 §2) said its actions "should be SHA-pinned and least-privilege" — this ADR is the concrete obligation that sentence pointed at.
- **No new third-party trust to add the guard.** just-shield is first-party here and offline/zero-dependency, so the supply-chain check does not itself enlarge the supply-chain surface — it is still pinned to a commit SHA per R1.
- **The relaxation for `actions/*` is a floor, not a ceiling.** Official actions *may* use tags so the policy is not onerous, but our committed workflows pin them too (via `fix`); the 🔵 advisories just-shield emits for an official-action tag are understood and acceptable, not failures.

## Alternatives considered

- **Pin nothing; trust tags (status quo before this ADR).** Rejected — it is the exact posture the tj-actions/CVE-2025-30066 victims had. Unacceptable for a security-boundary library.
- **Pin *everything*, including `actions/*`, as a hard requirement.** Rejected as the *floor* — it adds verbosity and Dependabot noise for the lowest-risk publisher (GitHub itself) with little marginal safety. We pin them in practice (free via `fix`) but do not gate on it, keeping the rule proportionate to the threat.
- **Drop or weaken the requirement because SHA-pinning "feels inefficient".** Rejected — the inefficiency is entirely a tooling-absence symptom. With `just-shield fix` (initial pin) and Dependabot (updates), the manual cost is zero, so there is nothing to trade security away for.
- **A third-party supply-chain scanner (e.g. StepSecurity Harden-Runner, zizmor).** Rejected in favor of the first-party `just-shield` — adopting an external scanner to defend the supply chain would itself add third-party CI trust, the very thing being defended against. Revisit only if just-shield's rule set proves insufficient.
- **No CI at all (keep the post-`2ca6c87` state).** Rejected for the fuzz lane specifically: libFuzzer cannot run on the maintainer's Windows host (ADR-0008 §Context), so "no CI" means "no fuzzing". The fuzz lane is non-blocking, so it does not reinstate the friction that retired the old gate.
