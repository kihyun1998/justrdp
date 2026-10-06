# 0017 — Rebuild the RDP client so the host holds every policy flag

- Status: Accepted
- Date: 2026-06-08 (decided while grilling `docs/plan.md`); recorded 2026-10-06, moved out of
  `GLOSSARY.md` §Project intent
- Kind: **judgement**. This is the founding decision; the maintainer reopens it, not a better
  derivation.

## Context

`ironrdp-connector` 0.9.0 hardcodes the `earlyCapabilityFlags` it sends in GCC Client Core Data
and omits `SUPPORT_DYN_VC_GFX_PROTOCOL` (0x0100), with no knob to set it. That one bit gates the
Graphics Pipeline (EGFX) on modern Windows servers, so an `ironrdp` client is held to legacy
graphics. The defect is not the missing bit but the shape: the library decides a flag that is the
host's to decide.

## Decision

Write justrdp from scratch and own every RDP-native layer — X.224, MCS, GCC, capability exchange,
the session loop, virtual channels, codecs and surfaces — so that the host, not the library,
holds every policy flag. Delegate only security-critical, non-RDP work (`rustls`, `sspi`;
[ADR-0002](0002-dependency-boundary.md)). The sans-IO core ([ADR-0001](0001-sans-io-state-machine-core.md))
and the policy/implementation split ([ADR-0016](0016-policy-flags-are-the-hosts.md)) are how this
is kept.

## Rejected alternatives

- **Patch the one bit upstream and keep depending on `ironrdp`.** It fixes the symptom, not the
  shape: the next hardcoded field needs another upstream patch, and the project's behaviour waits
  on another project's release cadence. [ADR-0011](0011-zero-ironrdp-terminal-state.md) (B)
  rejects the same coupling for the codec oracle.

## Consequences

- Codec ownership does not follow from this record alone, since a connector defect argues only for
  owning the connector; [ADR-0002](0002-dependency-boundary.md)'s 2026-07-02 amendment gives it an
  independent rationale.
- `docs/plan.md` holds the scope this implies (§2–§23, the MVP cut in §9).
