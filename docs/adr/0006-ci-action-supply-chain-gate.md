# 0006 — CI action supply-chain gate (just-shield)

- Status: Accepted (implemented in PR #76)
- Date: 2026-06-12

## Context

The CI workflow added to harden the build (fmt + clippy + test) ingests **third-party GitHub Actions** — at minimum `actions/checkout`. A GitHub Action is arbitrary code that runs inside CI with access to the workflow's `GITHUB_TOKEN`. That makes the set of actions a workflow uses a **supply chain**, exactly like the Cargo dependency graph [ADR-0002](0002-dependency-boundary.md) governs — but, until now, an unguarded one.

Two concrete risks:

1. **Mutable references.** Referencing an action by a floating tag or branch (`actions/checkout@v5`) pins a *name*, not *code*. The owner — or anyone who compromises the action's repo — can re-point that tag to a different commit, and CI will silently run it on the next build. This is not hypothetical: the 2025 `tj-actions/changed-files` compromise re-pointed existing version tags to a commit that exfiltrated CI secrets, hitting thousands of repos that pinned by tag.
2. **Over-broad token scope.** GitHub grants the default `GITHUB_TOKEN` write permissions across many scopes unless the workflow restricts them. A compromised action inherits that scope — enough to push commits, open releases, or tamper with the repo.

justrdp already takes a deliberate, documented stance on what it depends on at the *crate* level (ADR-0002: own the RDP protocol, depend only on leaf security libraries). CI actions are the same class of decision — code we did not write, executing with our credentials — and deserve the same discipline. plan.md §0's governing principle ("enforcement lives in the build, not in docs") applies directly: a rule that "actions must be pinned" only has teeth if CI fails when they are not.

## Decision

Every GitHub Action the CI ingests is **SHA-pinned, least-privilege, and scanned by a supply-chain gate before merge.**

### 1. Pin every action to a full commit SHA

Actions are referenced by their 40-character commit SHA with a trailing `# vX.Y.Z` comment for human readability, never by a tag or branch:

```yaml
- uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5
```

A SHA is immutable; it freezes exactly the code that runs. The trailing comment keeps the diff legible and lets Dependabot bump the pin deliberately (a visible SHA change), the same way `Cargo.lock` records the exact crate revision.

### 2. Least-privilege token by default

The workflow declares a read-only token at the top level, and any job that needs more requests it explicitly:

```yaml
permissions:
  contents: read
```

This caps the blast radius if an action is ever compromised — a malicious step cannot write to the repo with a read-only token.

### 3. A dedicated supply-chain gate enforces the above

A separate `supply-chain` CI job runs **[`just-shield`](https://github.com/kihyun1998/just-shield)** in strict mode on every push and PR:

```yaml
supply-chain:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5
    - uses: kihyun1998/just-shield@bfe605c359607bddb3fcbc04ee568e0ff4f60bf3 # v0.3.0
      with:
        strict: true
```

just-shield inspects every workflow in the repo and fails the build when an action is referenced by a mutable tag instead of a SHA, when a workflow grants more token scope than it declares a need for, or when a referenced action version is on the known-compromised list. just-shield is itself an action, so it is SHA-pinned too — the rule dogfoods itself.

### Rationale

1. **Tags are mutable; SHAs are not.** Pinning to a SHA is the only reference that cannot be changed out from under us after review. This is the single highest-leverage supply-chain control for GitHub Actions, and the direct mitigation for the tag-repointing attack class.
2. **Least privilege limits damage, not just probability.** Even a perfectly-pinned action can have a latent bug; a read-only token bounds what a bad step can do regardless of how it got there.
3. **Automated enforcement beats review vigilance.** A human reviewer will not reliably catch an unpinned action or an over-scoped token on every PR. A gate that fails the build catches it every time — the plan.md §0 principle that motivated justrdp's CI in the first place.
4. **Consistency with ADR-0002.** That ADR draws the line on *crate* dependencies (own RDP, depend on vetted leaf crypto). CI actions are an adjacent supply chain executing with repo credentials; leaving them unguarded would be an inconsistent security posture.

### Trade-offs accepted

- **just-shield is self-authored and young (v0.3.0).** Gating CI on the maintainer's own tooling is a dependency in its own right. Accepted because (a) it runs read-only — it inspects YAML and reports, it does not mutate the repo; (b) it is SHA-pinned like everything else; and (c) it is replaceable — the checks it performs (SHA-pinning, permissions, compromised-version lists) are also offered by drop-in tools such as `zizmor` and StepSecurity's Harden-Runner, so a stall in just-shield does not strand the project.
- **SHA pins are less readable than tags.** Mitigated by the mandatory `# vX.Y.Z` trailing comment, which carries the human-meaningful version alongside the immutable reference.
- **Updating an action becomes a deliberate SHA bump** rather than an automatic tag float. This is the point — visibility is the feature — and Dependabot automates the mechanical part.

## Consequences

- Any new action added to any workflow must be SHA-pinned and pass just-shield, or CI fails — a repeat of the "documented-but-unenforced" failure mode (plan.md §0) is structurally prevented for the CI supply chain.
- Action upgrades show up as explicit SHA changes in the diff, reviewable like a `Cargo.lock` bump.
- The default token is read-only; a future job that needs write access (e.g. publishing a release) must request the specific scope it needs, in the open.
- The project now has two enforced supply chains — Cargo crates (ADR-0002, via `Cargo.lock` + the zero-dep `justrdp-pdu` boundary) and CI actions (this ADR, via SHA pins + just-shield) — under one consistent "vet what executes with our credentials" posture.

## Alternatives considered

- **(A) Keep floating tags (`@v5`).** Rejected — this *is* the mutable-reference risk the decision exists to remove; the tj-actions incident is the worked example of why.
- **(B) Manual review only ("reviewers will check pins").** Rejected — does not scale and is exactly the docs-without-enforcement anti-pattern plan.md §0 calls out. Pins drift the moment attention lapses.
- **(C) A third-party scanner (`zizmor`, StepSecurity Harden-Runner) instead of just-shield.** Viable and noted as a fallback. just-shield was chosen as a lightweight, self-owned gate that does precisely the three checks this project cares about; if it stalls, (C) is a drop-in replacement and the SHA-pin + permissions conventions stand on their own regardless of the scanner.
- **(D) Use zero third-party actions (first-party `actions/*` only, everything else inline shell).** Partially adopted already — the Rust toolchain is installed via the runner's pre-installed `rustup` rather than a toolchain action, and no cache action is used (ADR-0002's dependency-minimalism spirit). But `actions/checkout` is still an ingested action, so pinning + scanning is needed regardless; eliminating actions entirely is neither practical nor a substitute for verifying the ones that remain.
