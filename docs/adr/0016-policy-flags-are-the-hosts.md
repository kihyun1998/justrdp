# 0016 — The host owns policy flags; the core owns implementation flags and refuses what it cannot honour

- Status: Accepted (issue #352)
- Date: 2026-09-29
- Kind: **judgement**. The maintainer chose between the options below, each with its
  consequences listed. A better derivation does not reopen it; the maintainer does.

## Context

`CONTEXT.md` and `CLAUDE.md` said the host owns **every RDP feature flag**. The repo held three
models:

- The connect layer passes the host's early capability bits, `INFO_*` flags and Confirm Active
  sets to the wire verbatim.
- EGFX lets the host narrow the versions, and the core derives the flags and refuses what it
  cannot honour ([ADR-0015](0015-host-chosen-egfx-capabilities.md)).
- The channel helpers fix their flags in the core: cliprdr's `ADVERTISED_FLAGS`, and rdpdr's
  `ioCode1`, `extendedPDU` and `extraFlags1`.

An inventory (#352, 2026-09-29) classified every flag the client sends. Only one channel flag
carries policy: `CB_STREAM_FILECLIP_ENABLED`. A host can refuse file transfer by action, but the
server then still offers a paste that fails. The Monitor Layout's scale factor and orientation
are also fixed in the core, although only the host knows its display.

The verbatim connect layer lets a host advertise messages the core drops or rejects. At least
seven bits do this (STATUS_INFO, HEART_BEAT, `INFO_COMPRESSION` and others). The default Sound
set's `SOUND_BEEPS_FLAG` already did, since Play Sound PDUs were skipped. That breaks
[what we advertise, we must implement](../map/invariant/what-we-advertise-we-must-implement.md),
the class #271 measured as a black screen.

Prior art splits:

- FreeRDP hard-codes its cliprdr and rdpdr flags. It applies clipboard policy
  (`ClipboardFeatureMask`) by refusing requests, and leaves file transfer advertised.
- IronRDP lets the application choose cliprdr's four file flags (`CliprdrBackend::client_capabilities`)
  and hard-codes rdpdr's General set.

## Decision

1. **A policy flag is the host's**: a flag or value a host may legitimately want different for
   its own reasons, such as resources, security, display or whether a feature is on at all.
   **An implementation flag is the core's**: it only tells the server what the core handles, and
   a host honours it by doing nothing different. The host holds policy at the seam it already
   has, by what it announces and how it answers. Where only the flag can stop the server
   offering something that then fails, the flag itself is the host's.
2. **Of the channel flags, `CB_STREAM_FILECLIP_ENABLED` is a policy flag**, so the clipboard
   helper takes it from the host. So are the Monitor Layout's scale factor and orientation.
   `CB_HUGE_FILE_SUPPORT_ENABLED`, accepting Display Control, the EGFX queue depth and every
   rdpdr General bit (including `ENABLE_ASYNCIO`, #349) are implementation flags.
3. **The connect layer stays verbatim, and the core refuses what it cannot honour.** Before a
   connection starts, a bit, flag or capability set whose server traffic the core would drop or
   reject is a typed error. That includes a capability set the core cannot read, since it cannot
   judge that set. The honoured set is an allow-list that grows as the core implements more, as
   ADR-0015's does.
4. **The core implements what its defaults advertise.** `SOUND_BEEPS_FLAG` stays in the default,
   and the Play Sound PDU reaches the host as an event. Whether it sounds is the host's call.

### Options shown to the maintainer

- **Narrow the rule, and keep every channel flag in the core.** Rejected: file transfer would
  stay advertised when the host has turned it off, so the server offers a paste that fails.
- **Widen the practice: every channel flag host-chosen, ADR-0015's shape.** Rejected: it hands
  the host implementation facts it can only get wrong, and neither reference does it for rdpdr.
- **Connect layer: keep verbatim and document the honourable bits, or move it to ADR-0015's
  derived shape.** Rejected, the first because it leaves the black-screen class open and the
  second because it removes the anti-hardcode contract that motivated the rebuild.

Two points were not put to the maintainer, and are recorded as derivations. First, refusing a
capability set the core cannot read follows from Decision 3's rule, since an unread set cannot
be judged honourable. Second, the maintainer answered "choose the option that does it
properly" in place of a separate question.

### What this decision did not cover

- The API shape of each slice (the clipboard option, the monitor layout values, the refusal
  error type) is left to the slice, which derives it.
- A server's flags are still intersected with ours, as before. This decision governs only what
  the client offers.
