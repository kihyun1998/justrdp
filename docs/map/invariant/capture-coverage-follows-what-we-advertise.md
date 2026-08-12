# Capture coverage follows what we advertise

## The fact

A real-server capture shows the paths the server chose to exercise, and **what the server
chooses is a function of what this client advertised**. A corpus is therefore evidence about a
*pair* — this server **and** that client config — never about the server alone.

The measured case (#194, 2026-08-13): the Client Core Data `connectionType`
([MS-RDPBCGR] 2.2.1.3.2) is only a hint, and the test VM takes it literally.

| advertised `connectionType` | payloads | TILE_FIRST | TILE_UPGRADE | quality values |
|---|---|---|---|---|
| `0x06` LAN | 1 | 1–8 | **0** | `{255}` |
| `0x01` MODEM | 52 | 2943 | **3250** | `{0, 255}` |

Same VM, same link, same 75-second window. On `LAN` the server has bandwidth to spare, sends
`TILE_FIRST` at the `0xFF` full-quality sentinel, and never refines — so **no SRL byte exists
anywhere on the wire**, and an entire entropy layer is invisible to the capture. One field in
the connect sequence decided whether a whole codec stage could be observed at all.

## Why it is cross-cutting

It is a property of *how this project gets evidence*, not of any codec. Every corpus, every
`#[ignore]`d VM test and every capability probe reaches the server through a connect sequence
this client controls, so each one inherits the limit. It also crosses from code into process:
it is the difference between "the server does not do X" (a claim about the server) and "we did
not see X" (a claim about the run), and only the second one is ever earned.

It is the sharper sibling of *"one VM is one server"*. That warns the cap set bounds coverage —
something the **server** decides. This says the **client's own advertised config** bounds it
too, which is the half a tester can change, and therefore the half that is worth checking before
concluding anything is absent.

## Territories it holds in

- [Verification harness](../territory/verification-harness.md) — every corpus and VM test is
  gathered this way; the limit bounds what all of them can claim.
- [Bitmap codecs](../territory/bitmap-codecs.md) — corpus-derived tolerances are only as broad
  as the traffic the capture provoked.
- [EGFX graphics pipeline](../territory/egfx-graphics-pipeline.md) — the Progressive quality
  ladder is the worked instance.
- [Capability exchange & activation](../territory/capability-exchange-activation.md) — where the
  advertised config is built, and therefore where the coverage is decided.

## What a violation looks like

A negative result promoted into a fact about the server, with no mention of the config that
produced it:

1. **"The VM never sends X."** Recorded from one capture, under one advertised config, and then
   built on. #194 came within one commit of concluding that this server never sends
   `TILE_UPGRADE` — and of hand-deriving an entropy layer that real traffic could in fact have
   supplied, had the client asked differently.
2. **A corpus README that lists what a fixture contains but not what was advertised to get it.**
   The fixture then cannot be reproduced, and the absences in it cannot be interpreted: a
   missing tile type reads identically whether the server cannot send it or was never given a
   reason to.

The tell for both is an absence with no config beside it. `docs/agents/theflow.md`'s
*"unconfirmed ≠ absent"* is the general rule; this is the specific mechanism by which the
confusion arises here.

## Discovery history

- **#193** — added the WireToSurface2 capture chokepoint. Its harness connected and waited under
  the default `LAN` config and captured a single payload per run; the thinness read as "the
  desktop was static", which was true and not the whole reason.
- **#194** — swept `connectionType` and found the ladder. The corpus that gates Progressive
  (`justrdp-codecs/tests/fixtures/progressive/`) exists because of this, and its README records
  the advertised config as provenance.
- Memory `vm_advertised_graphics_caps` records the server-side half of the same limit.

## Where it will recur

**Whenever a claim rests on something a capture did *not* contain.** The test is one question,
asked before recording an absence:

> What did the client advertise on the run that did not show it, and is there a value of that
> field which would have?

Concretely:

- A capture harness **records the advertised config in the fixture's provenance**, and prefers
  the setting that provokes the widest behaviour over the one that mirrors production. The
  Progressive harness takes `JUSTRDP_CAPTURE_CONNECTION_TYPE` for exactly that reason.
- Before concluding a server lacks a behaviour, **sweep the field that gates it** — connection
  type, performance flags, the advertised capability set, the early capability flags.
- A corpus README states **what it does not contain**, next to the config it was captured under,
  so a later reader can tell a real absence from an unprovoked one.
