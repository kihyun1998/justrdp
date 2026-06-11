# 0004 — sspi strategy: contribute-and-bridge now, own the RDP-adjacent auth layers as the end state

- Status: Accepted
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
