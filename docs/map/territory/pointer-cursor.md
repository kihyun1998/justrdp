# Pointer & cursor

## What it is

Everything about the mouse pointer *as an image*: the server sends colour, cached,
monochrome or large pointer updates with a hotspot; the client decodes the
XOR/AND masks into RGBA and hands the host a cursor event. The host draws it — the
library never composites a cursor into the framebuffer.

## Governing decisions

**None.** No ADR mentions the cursor at all (measured: 0 of 10 records).

Adjacent but not governing: [ADR-0001](../../adr/0001-sans-io-state-machine-core.md)
implies the host owns presentation, which is *why* a cursor is an event rather than
pixels in the frame — but nothing records that as a decision.

## Design model

- **A cursor is an event, not a frame.** `CursorEvent` carries a `CursorImage`
  (RGBA + hotspot) or a hide/show; compositing is the host's, so a cursor change
  never dirties the framebuffer.
- **Pointer caching is server-driven**: a cached pointer arrives once and is
  referenced by index later, so dropping a cache entry silently shows the wrong
  cursor rather than failing.
- **The XOR/AND mask arithmetic is the same shape as a bitmap decoder's**, which is
  precisely why the 32-bit overflow was found here first (#151) and only then in the
  bitmap decoders (#155).

## Code

- `justrdp/src/cursor.rs` — `CursorEvent`, `CursorImage`
- `justrdp-codecs/src/pointer.rs` — `decode_pointer`, `PointerError`
- `justrdp-pdu/src/pointer.rs` — `PointerUpdate`, `ColorPointerAttribute`
- `justrdp/src/session.rs` — `cursor_event_for`, `SessionOutput::Cursor`
- Spec sections cited inline: `[MS-RDPBCGR]` 2.2.9.1.1.4, 2.2.9.1.1.4.4

## Reference behaviour

**None.** No verified external-fact store; `differential_pointer_ironrdp` compares
behaviour as a test rather than recording it as a citable fact.

## Cross-cutting invariants

- [Decoder dimension overflow on 32-bit](../invariant/decoder-dimension-overflow-32bit.md)
  — this is the invariant's **first discovery site** (`decode_pointer`, #151).
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md)
- [Oracle agreement is not independence](../invariant/oracle-agreement-is-not-independence.md)
- [A later stage can hide an earlier defect](../invariant/a-later-stage-can-hide-an-earlier-defect.md)

## Blast radius

- [Session loop & PDU dispatch](session-loop-dispatch.md) — pointer updates are
  dispatched there and become one of the four session outputs.
- [Bitmap codecs](bitmap-codecs.md) — shares the mask/stride arithmetic and the
  colour conversion helpers.
- [Capability exchange & activation](capability-exchange-activation.md) —
  `PointerCapabilitySet` decides which pointer forms the server may send.

## Known holes / open

- **No governing record**, and the cursor is invisible in the decision trail — the
  0/10 measurement above is itself the finding.
- Nothing pins the *behavioural* contract on cache eviction: an out-of-range cache
  index has a defined decode result but no recorded intent.
