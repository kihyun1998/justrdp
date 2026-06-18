# 0004 — sspi strategy: contribute-and-bridge now, own the RDP-adjacent auth layers as the end state

- Status: Accepted (amended 2026-06-18 — #687 resolved upstream by the maintainer's own rework, not our PR; see Amendment)
- Date: 2026-06-11
- Refines: [ADR-0002](0002-dependency-boundary.md) (the `sspi` half; the `rustls` half and the "protocol omissions, not crypto complexity, are the bottleneck" insight stand unchanged)

## Context

ADR-0002 drew the dependency boundary at "own all RDP protocol, depend on `sspi` for NLA verbatim", with a single re-evaluation trigger ("if sspi Kerberos support becomes a blocker"). Three facts have since landed that the trigger did not anticipate:

1. **Measured dependency weight**: 223 of the workspace's 310 crates (~72%) are the `sspi` subtree — it is not a leaf dependency; it is most of the dependency graph.
2. **Upstream quality signal on our exact path**: sspi 0.21.0's `CredSspServer` cannot complete a handshake with its own `CredSspClient` in Negotiate-NTLM mode (the mode RDP requires — bare NTLM makes Windows servers abort TLS). Reported with a self-contained repro as [Devolutions/sspi-rs#687](https://github.com/Devolutions/sspi-rs/issues/687). The in-repo upstream tests never pair Negotiate↔Negotiate for NTLM, so our production path is under-tested upstream.
3. **The pain is layer-local**: every problem we have hit lives in CredSSP / SPNEGO / NTLM (the RDP-adjacent assembly layers). None has come from the Kerberos mechanism itself — and the enterprise-grade Kerberos features (SSO from the OS ticket cache, Credential Guard, smart cards) are *only* reachable by delegating to the OS SSPI, never by a userland reimplementation (ours or sspi's).

The maintainer goal is a production, enterprise-grade RDP package — which requires breadth of auth (NTLM, Kerberos/AD, eventually IAKerb as Microsoft retires NTLM), not a hand-rolled Kerberos.

## Decision

**Now — contribute-and-bridge.** For upstream sspi bugs that block us, we fix them ourselves and send the PR upstream; until the fix is released on crates.io we run our fork via `[patch.crates-io]`. The fork is a **bridge, not a residence**: it may contain *only* commits that have been submitted upstream as PRs, and the `[patch]` entry is deleted the moment upstream releases. `sspi` stays pinned exactly (`=x.y.z`); version bumps must pass the real-VM acceptance suite before landing.

**End state — own the RDP-adjacent auth layers.** The long-term direction (not yet scheduled) moves the ADR-0002 boundary one layer down:

- justrdp owns **CredSSP + SPNEGO + NTLM** (the layers where all observed pain lives, ~2–4k LOC, client-side, NTLMv2-only).
- **Kerberos remains a pluggable mechanism** behind a GSS-style mechanism boundary — backed by a userland implementation or by the OS SSPI (the only road to enterprise SSO / Credential Guard / smart cards).
- **Cryptographic primitives are never self-implemented** (MD4/MD5/HMAC/RC4/AES/SHA-256 come from RustCrypto-style leaf crates); we own protocol assembly only.
- Migration follows the ADR-0003 phased-oracle methodology: develop against `sspi` as a **differential oracle (dev-dependency only)**, byte-compare messages and key derivations, then drop it. Leaning: no runtime fallback feature — a feature-gated sspi path doubles the test matrix and reinstates the dependency tree for whoever enables it. (Re-decidable when the slice actually starts.)

**Deferred on purpose — the mechanism trait.** No `GssMechanism` abstraction is cut today: with a single implementation it would be speculative and would fossilize sspi's API shape into the trait. The seam is cut the day a **second** implementation exists (the self-owned NTLM slice, or Kerberos/OS-SSPI work). Until then, the swap-safety net is the wire-level `connect()` test suite (issue #59 / PR #60), which pins behavior independently of what implements NLA underneath.

## Re-evaluation triggers (whichever fires first)

Escalate from bridge to the self-ownership slice when any of:

- **Cost trigger**: ≥3 distinct fork-patches needed within 12 months (the bridge's repeat cost exceeds ownership).
- **Upstream-health trigger**: an upstream PR of ours is rejected or sits unreviewed for 60 days.
- **Regression trigger**: an sspi version bump breaks the real-VM suite.
- **Capability trigger**: a host requires OS-SSO / Credential Guard / smart cards. Note this trigger's answer is *different*: it is satisfied by the mechanism boundary delegating to OS SSPI, **not** by self-owned NTLM — record this so the trigger is not misread as "write more Rust".

Tracked in: the checklist of every sspi version-bump PR, and slice retrospectives.

## Consequences

- #687-class bugs are fixed on our schedule (fork-bridge) without acquiring a permanent fork's maintenance burden.
- The dependency-weight problem (223 crates) is acknowledged as **unsolved until the end state ships** — the bridge does not reduce it, and this ADR says so honestly rather than pretending the fork is independence.
- ADR-0002's narrative changes from "depend on sspi verbatim, forever" to "depend deliberately, contribute upstream, with a written exit and tripwires" — the original insight (own protocol, not crypto) survives with the line moved one layer down.

## Amendment (2026-06-18) — #687 resolved upstream by the maintainer; contribution conventions learned

The first real exercise of the contribute-and-bridge loop closed out, and it did **not** follow the path the Decision assumed ("we fix it, send the PR, run our fork via `[patch.crates-io]` until release"). Recording what actually happened, because it adjusts both the bridge mechanics and how the re-evaluation triggers should be read.

### What happened

- Our fix went up as [#688](https://github.com/Devolutions/sspi-rs/pull/688) — the `CredSspServer` Negotiate-NTLM `mechListMIC` completion, plus a `credssp_negotiate_ntlm` regression test, plus a CI-matrix commit adding `__test-data` so the `client_server` suite actually runs.
- The maintainer (Pavlo Myroniuk / `TheBestTvarynka`) accepted the **diagnosis and the test** but rejected the **shape of the fix**: our patch added a `bool` flag (`awaiting_pub_key_auth`) to defer `pubKeyAuth` by one leg, and he read that as papering over a bad state machine rather than fixing it. He reworked it as [#689](https://github.com/Devolutions/sspi-rs/pull/689) — fixing the server-side state transition itself (the machine demanded the encrypted public key immediately after the inner NTLM completed; correct behavior is to carry the final SPNEGO accept-completed token first) — and **merged #689 on 2026-06-17**, keeping our regression test. #688 was closed in favor of it. He confirmed this is a regression: "it worked in the past, before the big SPNEGO refactoring."

### Consequences for this ADR

1. **No fork-bridge was needed for #687.** Because upstream fixed it directly, we never carried a `[patch.crates-io]` commit. The bridge mechanism stays unused for now; the exit discipline ("patch deleted the moment upstream releases") is moot for this bug — we simply pin the released version that contains #689 once it ships to crates.io and run the real-VM acceptance suite against it (the existing version-bump gate).

2. **A PR closed in favor of the maintainer's own rework does NOT fire the upstream-health trigger.** That trigger reads "an upstream PR of ours is rejected or sits unreviewed for 60 days → escalate to self-ownership." Read literally, "#688 was closed" looks like a hit. It is the opposite signal: the maintainer engaged within days, validated the bug, kept our test, and shipped a *better* fix. The trigger is about **upstream neglect or hostility**, not about our specific patch being superseded by a cleaner one. Escalation is warranted when upstream won't move; here it moved fast and well. Do not misread this event as a tripwire.

3. **The rework validates ADR-0001, and previews our end-state obligation.** The maintainer's objection — fix the state machine, don't bolt on a flag — is exactly the [ADR-0001](0001-sans-io-state-machine-core.md) sans-IO state-machine discipline, confirmed from outside. When the ADR-0004 end-state has us *own* CredSSP + SPNEGO + NTLM, #689's transition (carry the accept-completed `mechListMIC` token, then accept `pubKeyAuth` on the following leg — no side flag) is the reference shape for our server-side machine. Worth keeping the #689 diff as a model when that slice starts.

4. **The CI-gate PR ([#691](https://github.com/Devolutions/sspi-rs/pull/691)) surfaced a second instance of the same rot mechanism as #687.** Enabling `__test-data` immediately failed to compile: five `ServerProperties` test initializers had drifted from the struct (a new `additional_service_keys` field, never filled in). Same root cause as #687 — code that never runs in CI rots silently — which confirms the CI gate is itself a fix, not housekeeping. Take-away for our own suite: any test path gated behind a feature that no CI row enables is effectively dead, and dead tests rot; keep every gate represented in the matrix.

### Conventions observed for future upstream PRs

- **One concern per PR.** The maintainer asked that the CI-matrix change be split out: "We try not to mix CI and library code changes." Our coming `__test-data` CI PR is therefore correctly a separate PR, not a rider on a fix. Apply this by default to all contribute-and-bridge PRs — library fix, test, and CI/tooling each stand alone.
- **Lead with a self-contained repro and a failing test.** Both #687 (issue) and #688 (PR) carried a hermetic repro / regression test, and that is what the maintainer kept even after discarding our fix. The test is the durable contribution; the patch is negotiable.
