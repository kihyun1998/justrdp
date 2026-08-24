# Framebuffer & frame delivery

## What it is

The retained client-side picture and the contract by which the host reads it: an
RGBA8888, top-down buffer at the negotiated desktop size, into which every decoded
rectangle is blitted, plus the `FrameUpdate` (position and size only) that tells the
host *what changed*. This is the seam where the library stops and the host's
renderer begins.

## Governing decisions

- [ADR-0010](../../adr/0010-frameupdate-dirty-rect-contract.md) — `FrameUpdate`
  carries the dirty rectangle, **not** owned pixels; the host reads the retained
  framebuffer by borrow inside the synchronous frame sink (issue #85).
- [ADR-0001](../../adr/0001-sans-io-state-machine-core.md) — the frame sink is
  host-injected policy; the core neither renders nor schedules.

## Design model

- **The buffer is allocated from the *negotiated* desktop size**, not the requested
  one (see [capability exchange](capability-exchange-activation.md)).
- **Resize discards content on purpose** — after Deactivation–Reactivation the
  server repaints, so carrying stale pixels forward would only show a torn frame.
- **A fresh buffer is opaque black, not transparent black** — alpha is filled to
  255. A host compositing an RGBA surface would otherwise show through.
- **The borrow is bounded by the sink call.** `pixels()` + the rect, or
  `copy_rect_into`, are valid *inside* the synchronous frame sink; the host that
  wants to keep pixels copies them itself, which is what makes the zero-copy path
  possible at all.
- `full_frame()` exists for the cases where the whole surface changed (activation,
  resize) so the same contract covers them.

## Code

- `justrdp/src/framebuffer.rs` — `Framebuffer`, `FrameUpdate`, `Framebuffer::blit`,
  `copy_rect_into`, `pixels`, `full_frame`, `resize`
- `justrdp/src/session.rs` — `SessionOutput::Frame`
- Module doc: mirrors ironrdp-session's decode-complete image-buffer model
  (plan.md §7)

## Reference behaviour

**None.** No verified external-fact store. The module doc names ironrdp-session's
image buffer as the model it mirrors, in prose, with no pinned citation — which is
the exact shape the map's *reference behaviour* section exists to make visible.

## Cross-cutting invariants

- [The frame path carries no owned pixels](../invariant/frame-path-carries-no-owned-pixels.md)
  — this territory is where the invariant is stated; the others are where it is
  obeyed.
- [Decoder dimension overflow on 32-bit](../invariant/decoder-dimension-overflow-32bit.md)
  — `width × height × 4` is computed here too.

- **The framebuffer's own geometry is server-declared, and until #241/#238 nothing bounded
  it.** `resize` computed `width * height * 4` unguarded from `DemandActive`'s desktop size and
  from a Display Control `OutputResized`, neither clamped on the way in. On a 32-bit target that
  product passes `u32::MAX` at the type's own maximum (reproduced on `i686-pc-windows-msvc`:
  *"attempt to multiply with overflow"*; in release it wraps and leaves `width`/`height`
  describing a buffer that was never allocated). It is now capped at `MAX_DESKTOP_DIM = 16384` —
  **the same constant `justrdp::egfx` caps a surface at**, because an EGFX surface tracks the
  desktop and two ceilings would differ only by accident — and at the cap the product is exactly
  1 GiB, so it fits by construction rather than by a check.
- **`blit` and `copy_rect_into` are refusals, not clips, and neither is wire-reachable.** Both
  are `pub` and both had a total-arithmetic hole (`src_stride_px * 4` overflowing on *every*
  target; an out-of-range slice index on a rect outside the buffer). Their callers pass values
  a `FrameUpdate` produced, so reachability sets the priority and not the contract
  ([ADR-0012](../../adr/0012-consumption-site-totality.md) §1).

## Blast radius

- [Session loop & PDU dispatch](session-loop-dispatch.md) — emits the frame updates
  and owns their ordering.
- [EGFX graphics pipeline](egfx-graphics-pipeline.md) — surfaces blit straight into
  this buffer (#163); a change to the blit signature is a change there.
- [Bitmap codecs](bitmap-codecs.md) — decoders write into this buffer's stride and
  colour order; a codec that returns its own `Vec` reintroduces the copy ADR-0010
  removed.
- [Capability exchange & activation](capability-exchange-activation.md) — supplies
  the size, and re-supplies it on reactivation.
- [Adapter drive loop](adapter-drive-loop.md) — the frame sink is called from there,
  synchronously, which is what bounds the borrow.

## Known holes / open

- **Nothing enforces the borrow's bound** except the sink's signature — a host that
  stores the slice is a compile error today only because of lifetimes, and there is
  no test asserting the contract's *intent* (no copy occurs).
- Multi-monitor (epic #27) breaks the single-buffer assumption entirely; nothing
  here anticipates more than one output.
