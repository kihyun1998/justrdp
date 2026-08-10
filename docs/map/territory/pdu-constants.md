# PDU constants & flag tables

## What it is

The ~255 `pub const` values in `justrdp-pdu` that *are* the protocol's vocabulary:
capability type codes, early-capability flags, channel options, security-protocol
bits, input event types and sync flags, error-info codes, EGFX PDU types, license
message types. They are data, not logic — and they are the project's founding
subject matter: **the flag `ironrdp-connector` omitted (`0x0100`) is one row in one
of these tables.**

**This is a "nobody touches it, and it breaks silently" area.** A wrong bit does not
crash; it produces a server that quietly does not enable a feature, or a capability
the server answers differently than expected.

## Governing decisions

**None.** No ADR is about the constant tables.

Adjacent but not governing: `CLAUDE.md`'s identity claim ("the host holds every RDP
feature flag") is the reason these are `pub` rather than internal — the exposure is
the product, but no record decides it.

## Design model

- **Every constant is a spec citation, and the citation is the test.** These values
  cannot be derived or unit-tested into correctness: they either match `[MS-*]` or
  they do not, so the doc-comment naming the section is the only verification the
  value carries.
- **Exposure is deliberate and total.** Nothing is hidden behind a curated builder;
  a host may set any flag the wire allows, including combinations Microsoft's own
  client never sends.
- **Flag types are newtypes with associated constants** (`ClientEarlyCapabilityFlags`
  and friends) rather than bare integers, so a wrong *type* is a compile error even
  though a wrong *value* is not.

## Code

- `justrdp-pdu/src/gcc.rs` — `ClientEarlyCapabilityFlags` (14 consts, incl.
  `SUPPORT_DYN_VC_GFX_PROTOCOL = 0x0100`), channel-option flags
- `justrdp-pdu/src/egfx.rs` — 32 consts (PDU types, caps versions)
- `justrdp-pdu/src/capability.rs` — 23 consts (capability set type codes)
- `justrdp-pdu/src/share.rs` — 17 consts (share control/data PDU types)
- `justrdp-pdu/src/license.rs` — 16 consts; `justrdp-pdu/src/fastpath.rs` — 16;
  `justrdp-pdu/src/input.rs` — 15 (incl. `SYNC_CAPS_LOCK`, `SYNC_NUM_LOCK`,
  `SYNC_SCROLL_LOCK`); `justrdp-pdu/src/rfx.rs` — 12
- Derivation of the current counts:
  `grep -c "^pub const " crates/justrdp-pdu/src/*.rs`

## Reference behaviour

**None.** No verified external-fact store. For this territory the *spec section
number in each doc-comment* is the closest thing to a pin, and there is no recorded
cross-check against FreeRDP's headers — which is the artifact that would catch a
transcription error.

## Cross-cutting invariants

**None.**

## Blast radius

- [MCS / GCC channel setup](mcs-gcc-channel-setup.md) — the early-capability flags
  are set there and gate whole territories.
- [Capability exchange & activation](capability-exchange-activation.md) — capability
  type codes decide what parses at all.
- [EGFX graphics pipeline](egfx-graphics-pipeline.md) — PDU type codes and caps
  versions.
- [Input & platform scancode tables](input-scancodes.md) — event types and sync
  flags.
- [Session loop & PDU dispatch](session-loop-dispatch.md) — error-info codes feed
  disconnect classification.

## Known holes / open

- **No mechanical check exists that a constant matches its cited spec section.** A
  transcription error is invisible to every gate in the repo; the only signals are a
  feature that does not turn on, or a real server disagreeing.
- Unknown capability types decode into an `Unknown` variant carrying the raw type —
  which is the tolerant behaviour ADR-0009 wants, and also means a *missing* constant
  never announces itself. A live example sits in the adapter's own tests:
  `CAPSTYPE_SURFACE_COMMANDS` has no named constant, so a real server's cap lands in
  `CapabilitySet::Unknown`.
