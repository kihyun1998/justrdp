# 0015 — The host chooses which EGFX versions and cache are advertised; the core refuses what it cannot honour

- Status: Accepted (issue #273) — amended 2026-09-17 (#296): 10.1 left the honoured set
- Date: 2026-09-17
- Kind: **judgement** — the maintainer chose between four shapes whose consequences were
  enumerated (below). A better derivation does not reopen it; the maintainer does.

## Context

`GraphicsProcessor` advertised a capability ladder fixed inside the core — 8, 8.1, 10, 10.1, 10.2,
10.3, 10.4, with no cache flag. `CONTEXT.md` gives the host every RDP feature flag, and this library
exists because a capability flag was curated inside `ironrdp-connector`. #271 chose the ladder by
measurement and left the host no way to narrow it or to ask for the small cache.

Only part of the ownership moves. Advertising 10.5 or 10.6 without processing
`RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU` breaks a MUST, and #271 measured the result as a black
screen with no error ([what we advertise, we must implement](../map/invariant/what-we-advertise-we-must-implement.md)).
Which versions *can* be honoured is known only to the core.

### What the enumeration found (lens pass, before the decision)

- **Which flag a version may carry is the axis that divides the options.** `[MS-RDPEGFX]` 2.2.3:
  THINCLIENT exists only on 8 and 8.1; SMALL_CACHE on 8, 8.1, 10, 10.2 and 10.4–10.7; 10.1 has
  sixteen reserved bytes; 10.3 has no cache flag, and choosing it implies the 16 MB cache
  (3.3.1.4); every 10.x needs AVC_DISABLED while no H.264 decoder exists.
- **Flags alone do nothing unless the host can also narrow the versions.** A thin-client flag
  cannot reach the wire at a confirmed 10.4, so a flags-only surface would silently not deliver
  what the host asked for.
- **Order carries no meaning.** 3.2.5.19: the server confirms *"the highest supported capability
  set"*.
- **3.3.5.18**: one or more capsets, and no capset type twice.
- **The cache budget ignored the confirm.** `MAX_CACHE_BYTES` was 100 MB whatever was confirmed,
  so a server that stops at 10.3 was already allowed six times its 16 MB.
- **Prior art converges on the same division, though not on the shape.** FreeRDP takes a
  subtractive version filter (a positional bitmask whose bit meanings shift with build flags)
  plus `GfxThinClient`/`GfxSmallCache`, and derives each version's flags itself — but sizes its
  cache from the setting rather than the confirm. `ironrdp-egfx` takes a host-supplied capset list
  and filters out the AVC versions it cannot decode.

## Decision

1. **`SessionConfig::egfx: EgfxConfig`** carries `versions: Option<Vec<u32>>` (`None` = the core's
   measured ladder) and `cache: EgfxCacheMode` (`Standard`, `Small`, `ThinClient`).
2. **The host names versions, never flags.** The core derives each version's flags: AVC_DISABLED
   on every 10.x; for `Small`, SMALL_CACHE wherever it is defined; for `ThinClient`, THINCLIENT on
   8/8.1 and SMALL_CACHE above them; nothing on 10.1 or 10.3. The wire order stays the ladder's.
3. **A version the core cannot honour is refused, not dropped**: `SessionStateMachine::new` returns
   `SessionError::EgfxConfig` for a version outside the honoured set, an empty list, or a repeated
   version.
4. **It is an allow-list**, so a host that pins its versions does not start advertising a version
   the core learns to honour later.
5. **The cache budget follows the confirmed capset** (3.3.1.4): 16 MB at 10.3 or when the confirm
   carries THINCLIENT or SMALL_CACHE, 100 MB otherwise.

### Options shown to the maintainer

- **(a) A host capset list, validated.** Rejected: every rule about which flag a version may carry
  becomes host-facing validation, and being able to set the order buys nothing.
- **(b) A min/max version range.** Rejected: it cannot express a set with gaps, though no measured
  need for one exists.
- **(c) Flags only.** Rejected: see the enumeration — a thin-client flag cannot take effect at 10.4.
- **(d) A subtractive filter.** Rejected in favour of the allow-list: under a filter, a host that
  has not moved starts advertising whatever the core's default ladder later gains.

### What this decision did not cover

- **A confirm naming a version the host did not advertise** is still adhered to, as before.
- **The cache slot count** (25 600 / 4 096, 3.3.1.4) was not enforced when this was written;
  the byte budget was. #297 closed it on 2026-09-18 — the slot maximum now reads the **same**
  `small_cache()` predicate as the budget, and an out-of-range slot is warned and skipped
  ([ADR-0009](0009-tolerant-negotiation-posture.md) row 4). So this decision's derivation of the
  cache size from the confirm is what the slot bound is built on.
- **AVC and 10.5+** stay out of the honoured set; this decision does not decide when they enter.

## Consequences

- The default config advertises exactly the bytes the fixed ladder did.
- The configured capsets survive a 3.3.5.19 reset and a channel close, because both rebuild the
  processor from `Default`.
- A host that set nothing is unaffected; a host with an invalid config learns before the session
  starts, not from a black screen.

## Amendment (2026-09-17, #296): 10.1 is not honoured

This record's Context and Decision list 10.1 in the ladder, and its not-covered list asked whether
`Small` should leave 10.1 out. Both premises were incomplete. `[MS-RDPEGFX]` 1.7 has
`RDPGFX_CAPSET_VERSION101` **imply AVC/H.264 in YUV444v2 mode**, and its reserved bytes have no
`AVC_DISABLED` to decline that — so advertising it breaks
[what we advertise, we must implement](../map/invariant/what-we-advertise-we-must-implement.md)
for as long as there is no H.264 decoder. Server implementations read it that way (FreeRDP shadow,
GNOME Remote Desktop, and `ironrdp-egfx`'s own confirm mapping all treat it as AVC444-enabled).

The removal is a **derivation** from that sentence, not a new judgement: Decision 2's rule
already says the core offers only what it can honour. `HONOURED_VERSIONS` is now 8, 8.1, 10, 10.2,
10.3 and 10.4; a host naming 10.1 gets `EgfxConfigError::NotAdvertisable`; the not-covered
question about `Small` at a confirmed 10.1 no longer arises. A confirm naming 10.1 is still
recognised (3.3.5.19), as 10.5+ are.
