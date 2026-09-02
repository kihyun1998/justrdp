# What we advertise, we must implement

## The fact

**An advertised capability is a promise, and the protocol lets the server hold us to it.**
Every capability this client sends — a graphics capability version, a Confirm Active capability
set, a virtual-channel capability flag — tells the server which messages it may now use. The
server then uses them, and a client that advertised something it does not handle does not get
an error: it gets traffic it silently drops.

The measured case (#271, 2026-09-02). `[MS-RDPEGFX]` 1.5.1 makes three graphics capability
versions a **MUST** to process `RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU`:

> Clients that advertise the RDPGFX_CAPSET_VERSION107 … capability set (sans the
> RDPGFX_CAPS_FLAG_SCALEDMAP_DISABLE (0x00000080) flag), the RDPGFX_CAPSET_VERSION105 …
> capability set, or the RDPGFX_CAPSET_VERSION106 … capability set MUST be capable of
> processing the following messages: RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU …

Advertised against the test VM, all of it looked healthy:

| advertised ladder | confirmed | frames painted |
|---|---|---|
| through `CAPVERSION_106` | `0x000A0600` (10.6) | **0** |
| stopping at `CAPVERSION_104` | `0x000A0400` (10.4) | 110 |

At 10.6 the server mapped the surface with the *scaled* command, the client skipped it as
unknown, the surface was therefore never mapped to an output, and **every tile decoded
correctly into a surface nobody could see**. The session stayed up, the channel stayed open,
`StartFrame`/`EndFrame` kept bracketing, and nothing anywhere returned an error. Two capability
sets were the whole difference between a desktop and a black screen.

## Why it is cross-cutting

It is a property of **every negotiation this client participates in**, not of the graphics
channel. The same shape exists wherever justrdp declares something to a server:

- the Client Core Data early capability flags, which decide whether a whole channel exists
- the Confirm Active capability sets, which decide which orders and surface commands may arrive
- the dynamic-channel capability flags — `VCCAPS_NO_COMPR` says *do not compress*, and the
  DVC layer rejects a compressed chunk on exactly that ground
- the graphics capability version ladder

And it is the **conformance** half of a coin whose evidence half is already recorded:
[capture coverage follows what we advertise](capture-coverage-follows-what-we-advertise.md)
says the advertised config bounds what a capture can *show* us. This says the same
advertisement bounds what we may *refuse to handle*. One is about what we can learn, the other
about what we owe; both start at the same bytes.

## Territories it holds in

- [EGFX graphics pipeline](../territory/egfx-graphics-pipeline.md) — the worked instance: the
  capability version ladder and the scaled map-surface obligation.
- [Capability exchange & activation](../territory/capability-exchange-activation.md) — where
  the Confirm Active capability sets are built, and the general form of the rule.
- [Virtual channels](../territory/virtual-channels.md) — `VCCAPS_NO_COMPR` and the dynamic
  channel capability exchange.
- [MCS / GCC channel setup](../territory/mcs-gcc-channel-setup.md) — the early capability
  flags, where advertising `SUPPORT_DYN_VC_GFX_PROTOCOL` is what makes EGFX exist at all.

## What a violation looks like

**A capability advertised because it is newer, higher, or "more complete", with no check that
the client handles what it gates.** The tell is an advertisement chosen by version ordering
rather than by capability:

1. **"Advertise up to whatever the server will confirm."** This is the phrasing #271 was filed
   with, and following it is what produced the black screen — the server confirms the highest
   thing offered, and the highest thing offered was the one we could not honour.
2. **An unknown-command branch that only logs.** Skipping a message a server was *told* it
   could send is not tolerance, it is a broken promise with the evidence discarded. The
   tolerant-receive posture ([ADR-0009](../../adr/0009-tolerant-negotiation-posture.md)) covers
   messages we never invited; it does not cover ones we advertised for.
3. **A capability flag set from a constant table with no consumer.** If nothing in the codebase
   reads the state a flag turns on, the flag is a promise with no implementation behind it —
   the sibling shape of
   [a decoded field with no reader](a-decoded-field-with-no-reader-is-an-unstated-decision.md),
   one direction out.

## Discovery history

- **#271** — the EGFX capability ladder. Filed as *"we are behind on caps versions"*; the
  measurement falsified that framing. Extending the ladder to what the server would confirm
  produced zero frames, and the fix was to choose the ladder by **which obligations the client
  can discharge**: 10.5 and 10.6 have no opt-out for the scaling obligation, 10.7 has one
  (`SCALEDMAP_DISABLE`), and everything at 10.4 and below has none to decline.
- **The references disagree on the same MUST**, which is what makes this a rule rather than a
  preference: FreeRDP compiles 10.5/10.6 out entirely without an image scaler, while
  `ironrdp-egfx` advertises them and discharges the obligation by accepting the command and
  recording the mapping. Both are conforming. What is *not* conforming is advertising them and
  skipping it.
- **#253** is the same fact one layer down and still open: a Share Data header field whose
  "must be 0" rests on our never advertising compression, unverified at the boundary, where
  the DVC layer rejects the identical violation.

## Where it will recur

**Whenever a capability, flag, version or feature bit is added to something this client
sends.** The test is one question, asked before the advertisement lands:

> Which messages does this let the server send that it could not send before, and does this
> client handle every one of them?

Concretely:

- Adding a capability set, a capability flag, or a version to any advertised list **names the
  messages it gates**, in the same change, and either implements them or does not advertise it.
- A branch that skips an unknown message **states whether the message was invited**. A skip on
  the receive path is tolerance; a skip on something we advertised for is a defect that
  produces no error.
- Proving it needs a **behavioural** assertion, not a handshake one. Every check on the
  capability exchange itself passed in the measured case above; what failed was the frame
  count. Assert what the negotiation was *for*.
