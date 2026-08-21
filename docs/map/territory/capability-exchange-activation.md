# Capability exchange & activation

## What it is

The negotiation that decides what the session can actually do: the server's Demand
Active carries its capability sets and the `shareID`; the client answers with
Confirm Active carrying its own; then the finalization round-trip (Synchronize →
Control Cooperate → Control Request Control → Font List → Font Map) reaches
`session-active`. The same exchange re-runs **in-session** as
Deactivation–Reactivation, which is how a resize actually happens.

## Governing decisions

- [ADR-0009](../../adr/0009-tolerant-negotiation-posture.md) — tolerant of server
  self-inconsistency in rendering capabilities, strict on security integrity. This
  is the record that says what to do when a server advertises something it then
  contradicts.
- [ADR-0010](../../adr/0010-frameupdate-dirty-rect-contract.md) — indirectly: the
  negotiated desktop size is what the framebuffer is allocated from.

## Design model

- **The negotiated desktop size is the server's, not the client's request.**
  `ActivationResult::desktop_size` comes from the server's Bitmap capability set;
  allocating the framebuffer from the GCC-requested size is the bug this field
  exists to prevent.
- **Activation hands over leftover bytes, and they must be processed before the
  next socket read.** Servers start streaming graphics immediately, so bytes after
  the Font Map routinely arrive in the same read. `ActivationResult::leftover`
  carries them; a session loop that reads the socket first loses a frame's worth of
  ordering.
- **Server capability sets are handed over verbatim**, because the session loop —
  not this phase — decides what order/codec support means.
- **Reactivation is the same exchange with session state alive.** `Phase::Reactivating`
  re-runs it; caches belong to the *connection*, not the share, so they survive.

## Code

- `justrdp-pdu/src/capability.rs` — `DemandActive`, `CapabilitySet`,
  `GeneralCapabilitySet`, `BitmapCapabilitySet`, `OrderCapabilitySet`,
  `PointerCapabilitySet`, `InputCapabilitySet`, `VirtualChannelCapabilitySet`,
  `BitmapCodec`, `BitmapCodecsCapabilitySet`
- `justrdp-pdu/src/share.rs` — `ShareControlHeader`, `ShareDataHeader`,
  `encode_share_control`, `encode_share_data`
- `justrdp-pdu/src/finalization.rs` — `Synchronize`, `Control`, `FontMap`,
  `encode_font_list`
- `justrdp/src/connect.rs` — `ActivationResult`, `Stage`
- `justrdp/src/session.rs` — `Phase::Reactivating`, `ResizeError`
- Stage strings: `capability-exchange`, `session-active`

## Reference behaviour

**None.** No verified external-fact store — and this is the territory where its
absence costs most: ADR-0009's tolerance rules were derived from real-server
behaviour that is now recorded only as prose in the ADR and in `docs/plan.md` §0,
with no pinned FreeRDP citation to check them against.

## Cross-cutting invariants

- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) — every PDU
  this territory parses is server-supplied: the Demand Active capability walk, the Share
  headers, and the three finalization replies. **Listed only from #237 onward, and the
  omission is the finding**: `finalization`'s three parsers had neither artifact and appeared
  in no uncovered list either, because this edge was the one place a reader would have been
  sent from. `check_map.py`'s reciprocity gate cannot catch that — it verifies that the edges
  which *exist* run both ways.
- [Capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md)
  — this territory builds the advertised config, so it is where a capture's coverage is
  decided, one connect sequence before anything is observed.

## Blast radius

- [Session loop & PDU dispatch](session-loop-dispatch.md) — receives `share_id`,
  the capability sets and the leftover bytes; every one of the three is a contract.
- [Framebuffer & frame delivery](framebuffer-frame-delivery.md) — allocated from
  the negotiated size, and reallocated on reactivation.
- [Bitmap codecs](bitmap-codecs.md) — `BitmapCodecsCapabilitySet` decides which
  decoders can be reached at all (the VM's advertised set bounds what is provable).
- [EGFX graphics pipeline](egfx-graphics-pipeline.md) — surface commands and frame
  acknowledgement are capability-gated here.
- [PDU constants & flag tables](pdu-constants.md) — capability type codes and their
  flags.

## Known holes / open

- **Client-initiated resize via Deactivation–Reactivation is only half-built** —
  plan.md §23 records the inbound request handler as missing ("ironrdp-displaycontrol
  does push, not pull").
- Order capabilities are parsed but drawing orders are not implemented (epic #22),
  so `OrderCapabilitySet` advertises a surface nothing consumes yet.
- ADR-0009's tolerance is **not yet exercised for drawing orders**, stated in the
  record itself.
