# 0002 — Dependency boundary: own RDP protocol, depend on crypto

- Status: Accepted — the `sspi` half refined by [ADR-0004](0004-sspi-contribute-and-bridge.md) (2026-06-11)
- Date: 2026-06-08

## Context

justrdp is a full from-scratch RDP client library written in Rust, built to replace the reliance on the `ironrdp` crates. The motivation is specific: `ironrdp-connector` 0.9 hardcodes the list of capability flags in GCC's `earlyCapabilityFlags` and omits `SUPPORT_DYN_VC_GFX_PROTOCOL` (0x0100), with no knob to override it. This single omission gates the server from opening the Graphics Pipeline dynamic virtual channel — the production codec path — leaving clients stuck with slow-path bitmap decompression. The bottleneck is not a subtle implementation bug but a **protocol-negotiation omission**: a flag the RDP spec allows was hardcoded off.

This motivates the question: what boundaries should justrdp maintain to ensure we are never gated by someone else's protocol omission again, while avoiding the trap of reimplementing security-critical crypto from scratch?

The core tension: **"own everything" is infeasible and reckless; "own nothing" repeats the bottleneck.** The decision pins the line.

## Decision

justrdp owns **all RDP-specific protocol** but depends on **leaf, non-RDP-specific security libraries**.

### What we own

- **X.224 negotiation and connection sequencing** (TPKT, X.224 TPDU, RDP_NEG_REQ/RSP, negotiate TLS/HYBRID/HYBRID_EX/RDSTLS/RDSAAD).
- **MCS (T.125) and GCC** (Conference Create, all client GCC blocks: Core, Security, Network; channel join).
- **Capability exchange and activation** (Demand Active, Confirm Active, DeactivateAll, finalization; deserialize all capset types; make every flag caller-settable so no future SUPPORT_DYN_VC_GFX_PROTOCOL-like omission can sneak in).
- **Session loop and virtual channel infrastructure** (both SVC and DVC; the `drdynvc` manager; channel PDU framing; surface model for EGFX).
- **Graphics codecs** (RemoteFX full, RemoteFX Progressive, ClearCodec, NSCodec, zgfx; initially via `ironrdp-graphics` as a differential-test oracle, then self-owned per the phased-c2 strategy).
- **Input event encoding** (fast-path and slow-path; keyboard scancode mapping OS→set-1; mouse, wheel, relative input).

### What we depend on

- **`rustls`** (TLS 1.2+): We use it verbatim. We do not reimplement or patch it. It is non-RDP-specific, security-critical, and has no hardcoded-flag negotiation bottleneck — RFC 5246/8446 defines the cipher suite negotiation, and `rustls` exposes the full set to the client, including the ability to extract the server's `subjectPublicKey` after handshake for CredSSP binding.
- **`sspi`** (Security Support Provider Interface, Windows; or a compatible userland SSPI wrapper): We depend on the `sspi` crate for NLA authentication — CredSSP, SPNEGO, NTLM (NTLMv2 + channel bindings + signing/sealing), Kerberos (AS/TGS/AP exchanges, KDC discovery, SPN resolution) — verbatim, without reimplementation. `sspi` is not RDP-specific (it is the Windows security stack abstraction); it is security-critical (every deviation from RFC 2478 / RFC 2104 / RFC 1964 is a potential authentication bypass); and it is free of hardcoded-flag omissions — it exposes the full SSPI API: acquire credentials, multi-step context initialization with caller-driven network I/O, per-direction encryption/signing, and channel-binding injection. Reimplementing it would be months of work for a codebase with the same attack surface; the payoff (independence) is illusory because a new NTLMv2 implementation is as security-critical as the original.

### Rationale for the boundary

1. **Protocol omissions are the bottleneck, not crypto complexity.** The EGFX gate was closed because a flag was hardcoded off, not because TLS or NTLM was too complicated to call. Owning RDP protocol ensures we can always advertise every capability the spec allows and let the server and caller decide.
2. **Crypto is not RDP-specific.** TLS and NLA (CredSSP/SPNEGO/NTLM/Kerberos) are used by thousands of applications and systems; they have been RFC-standardised and vetted for 20+ years. Their completeness is not a justrdp problem — it is a platform problem. If Windows' `sspi` or `rustls` is incomplete, that is a concern shared with all other TLS clients and Windows applications; it is not a justrdp-unique risk.
3. **"Don't roll your own crypto" is not paranoia.** Cryptographic implementations have a decades-long track record of subtle bugs with exploitable consequences (side-channel leaks, padding-oracle vulnerabilities, integer overflows in modular exponentiation). Silent exploits are the risk. By contrast, protocol bugs (e.g. a hardcoded flag) are visible — a feature simply does not work, and the cause surfaces during integration testing or customer debugging. The risk profile is inverted.
4. **`rustls` and `sspi` are API-complete for RDP.** `rustls` exposes cipher negotiation, server certificate inspection, and key material extraction; `sspi` exposes credential acquisition, multi-step context initialization with caller-driven I/O, and channel-binding injection. Neither is a thin wrapper — both are production stacks used by real applications. Depending on them does not cap our RDP feature set.
5. **Crypto is a moving target; RDP is stable.** RDP as a protocol has stabilized (Microsoft's last major version was RDP 10.x in Windows Server 2019; current is RDP 11 for Windows 11, with incremental additions). By contrast, cryptography standards evolve: TLS 1.2 → 1.3, and post-quantum key exchange is on the horizon. Owning crypto means committing to track that evolution forever; outsourcing it to `rustls` means we benefit from its maintenance automatically.

### Trade-offs accepted

- **Dependency on the Devolutions `sspi` crate ecosystem** (and on Devolutions' prioritization of NTLM/Kerberos bug fixes). This is acceptable because (a) the crate is actively maintained by the FreeRDP/Devolutions team, (b) NTLM/Kerberos are not RDP-specific (any Windows integrator benefits), and (c) the risk profile is different from ironrdp's protocol omissions — if `sspi` is incomplete, the symptom is "authentication fails on a niche setup" (visible, debuggable, discoverable before production), not "a feature silently does not work."
- **If hyperindependence is ever wanted,** the only tractable carve-out is NTLM-only (Kerberos can be deferred, and workgroup environments use NTLM). NTLM is still security-critical (NTLMv2 is a keyed hash and signature scheme), so this does not solve the "don't roll your own crypto" problem — it just reduces scope. Evaluate only if `sspi` Kerberos support becomes a blocker.

## Consequences

- justrdp's surface area is **RDP protocol negotiation and state machines**, not crypto. The codebase will be ~3–5k LOC (PDU codecs + connector/session state + channel processors) rather than ~50k (which would include NTLMv2, Kerberos, TLS, plus RDP).
- Every RDP capability flag is caller-settable by default, preventing a repeat of the EGFX gate incident.
- CI can run against real Windows VMs without needing to stub crypto or maintain a parallel mock authentication stack.
- Porting to non-Windows platforms (Linux/macOS SPNEGO via MIT Kerberos or Heimdal) is an `sspi` crate concern, not justrdp's.

## Alternatives considered

- **(A) Own all crypto too (TLS + NTLM + Kerberos).** Rejected. TLS alone is 50k+ LOC (`rustls` is a lean, carefully-scoped implementation); adding NTLM/Kerberos is +20k–40k LOC, a 6–12 month undertaking, with a security risk profile that makes this team uncomfortable. The payoff is "we are not dependent on Devolutions or Mozilla," but (i) both are actively maintained and reputable, (ii) the bottleneck that motivated justrdp (protocol omissions) is solved by owning RDP alone, and (iii) a homegrown crypto stack is more risky than the dependency.
- **(B) Pure minimal: depend on librdp or use a thin ironrdp wrapper.** Rejected. We evaluated `ironrdp` and found the capability-flag hardcoding is baked into the connector's API — forking would require maintaining a parallel `ironrdp-connector` with minimal deltas, accepting all of ironrdp's architecture decisions. The EGFX gate motivated a clean rethink of the connector's negotiation model; a thin wrapper would not solve it.
- **(C) Hybrid ownership: own TLS (re-export `rustls` codecs but wrap the handshake).** Rejected. Wrapping `rustls` adds no value — the RFC 5246/8246 handshake is standardised and complete in `rustls`. We gain no control over protocol omissions by inserting a wrapper layer.

## Open questions resolved

This decision resolves design question 13 from the plan: "Pure-Rust only, or allow the `sspi` crate?" **Answer: allow `sspi` (and `rustls`); they are non-RDP-specific, security-critical, and free of the negotiation bottleneck.** The outcome is a dependency graph of: `justrdp-pdu` (wire + PDUs) → `justrdp` (sans-IO core) → { `rustls`, `sspi`, `ironrdp-graphics` (temporary) } rather than `justrdp` → everything in `ironrdp` or nothing.
