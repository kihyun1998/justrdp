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
- **The Font Map alone gates `session-active`, deliberately.** The server's Synchronize and
  Control replies are decoded and their values checked, then discarded — their *arrival* is
  recorded nowhere, so there is no completeness or ordering ladder. #252 decided this against
  a capture rather than by default; the grounds are in `## Reference behaviour`. The Font Map's
  own *body* is still strictly parsed — a separate question, settled by #237/#242.
- **Both legs answer the same question the same way.** `connect.rs`'s finalization arms and
  `session.rs`'s `Phase::Reactivating` arms call the same parsers and the same
  `Control::check_server_action`. Until #252 they did not: the reactivation leg dropped the
  `ReadCursor` unread, so a server `Control(Detach)` was fatal on connect and invisible on
  resize.

## Code

- `justrdp-pdu/src/capability.rs` — `DemandActive`, `CapabilitySet`,
  `GeneralCapabilitySet`, `BitmapCapabilitySet`, `OrderCapabilitySet`,
  `PointerCapabilitySet`, `InputCapabilitySet`, `VirtualChannelCapabilitySet`,
  `BitmapCodec`, `BitmapCodecsCapabilitySet`
- `justrdp-pdu/src/share.rs` — `ShareControlHeader`, `ShareDataHeader`,
  `encode_share_control`, `encode_share_data`
- `justrdp-pdu/src/finalization.rs` — `Synchronize`, `Control`, `FontMap`,
  `Control::check_server_action`, `encode_font_list`
- `justrdp/src/connect.rs` — `ActivationResult`, `Stage`
- `justrdp/src/session.rs` — `Phase::Reactivating`, `ResizeError`
- Stage strings: `capability-exchange`, `session-active`

## Reference behaviour

Opened by #252. It read **"None"** until then, with the note that this was the
territory where the absence cost most — and it did: #252 opened on the premise
*"the real VM sends all four finalization replies, in order"*, which nothing in
the repo could confirm or deny.

**What the real server sends** — captured 2026-08-25 via
`JUSTRDP_CONNECT_CAPTURE_FILE` (server-to-client only, hence commitable), four
activations across two tests, **identical on the connect leg and the
reactivation leg**:

```
DEMAND_ACTIVE
SYNCHRONIZE   messageType=1   targetUser=0
CONTROL       action=0x0004 (Cooperate)        grantId=0     controlId=0
CONTROL       action=0x0002 (Granted Control)  grantId=1007  controlId=0x03EA
FONT_MAP      mapFlags=0x0003  entrySize=4
```

`grantId` is the MCS user channel and `controlId` is the server channel — the two
values `[MS-RDPBCGR]` 2.2.1.21 marks MUST. Pinned as
`justrdp-pdu/tests/fixtures/connect/finalization-replies.bin`, walked by
`a_real_servers_finalization_replies_decode_in_order`. **One WS2022 box on one
advertised config**: it proves what *this* server sends, never what servers send
(see [capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md)).

**What the references require of the client.** The `[MS-*]` half is thinner than
it looks: 1.3.1.1 phrases every finalization rule as a *server* obligation
("is sent in response to", "is sent after transmitting"), and the client-side
processing sections 3.2.5.3.19–.22 are one sentence each plus a MUST-ignore
field list — **no ordering obligation, no arrival precondition**, and §3.2.1's
abstract data model has no finalization-arrival variable. So the spec does not
answer the question this territory kept asking.

FreeRDP does track arrival (`finalize_sc_pdus`, `rdp_handle_sc_flags` in
`libfreerdp/core/rdp.c`), and two things about it are routinely misread:

- **It is a completeness gate, not an ordering gate.** The flag word is only
  ever OR-ed and is cleared solely at reset, so out-of-order replies still
  satisfy every rung, one PDU behind.
- **It never fails.** The else branch warns and leaves `status` untouched, so a
  missing reply parks the client on the rung rather than dropping the session.
  It **did** fail once: `ff2509bbc4e9` (2022-11-29, *"relax sc flags state
  checks"*) deleted `status = STATE_RUN_FAILED` one day after FreeRDP#8458 — an
  xrdp resolution change disconnecting on the reactivation leg.

IronRDP tracks nothing: one flat wait state, `FontMap → Finished`.

**What justrdp does with that** (#252): no completeness gate — the Font Map alone
reaches session-active, deliberately — but the field values the spec does fix are
checked, identically on both legs.

## Cross-cutting invariants

- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md)
  — this territory builds the Confirm Active capability sets, which are the general form of
  the rule: every set sent here tells the server which orders and surface commands it may now
  use, and a set advertised past what the client handles produces dropped traffic rather than
  an error.
- [A decoded field with no reader is an unstated decision](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md)
  — the discovery site. `Synchronize.messageType` was discarded under a spec citation the
  spec does not make, and a server `Control.action` was decoded and dropped; both closed by
  #252, both rejected by both references.
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
  **And a fourth since #252**: it re-runs this territory's finalization parsers on the
  reactivation leg, `Control::check_server_action` included, so a change to what a server
  reply may contain moves `session.rs` too. That edge was silent before #252, and the
  silence is what let the two legs disagree.
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
