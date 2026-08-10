# The frame path carries no owned pixels

## The fact

From decode to the host's frame sink, pixels are written **once**, into the retained
framebuffer, and everything downstream of that write moves a *rectangle*, never a
buffer. `FrameUpdate` is `(x, y, width, height)`; the host reads the pixels by
borrow inside the synchronous sink call. Any stage that returns an owned `Vec<u8>`
of pixels — a decoder handing back a bitmap, a surface extract step, a frame event
carrying its own copy — reintroduces a per-frame copy on the hottest path in the
library.

The rule is not "avoid copies where convenient". It is: **the frame path has exactly
one write of each pixel, and the host chooses whether a second one happens.**

## Why it is cross-cutting

The sites are a pipeline, not a module: a codec, a surface manager, a framebuffer
and a session output type. Each one is locally reasonable when it owns its output —
returning a `Vec` is the obvious Rust signature, and it is *correct*, just
expensive. Nothing in any single territory says otherwise, so the constraint has to
live above all four or it gets re-litigated at each new decoder.

## Territories it holds in

- [Framebuffer & frame delivery](../territory/framebuffer-frame-delivery.md) — where
  the contract is defined (`blit`, `copy_rect_into`, `pixels`).
- [Session loop & PDU dispatch](../territory/session-loop-dispatch.md) —
  `SessionOutput::Frame(FrameUpdate)` carries the rectangle.
- [EGFX graphics pipeline](../territory/egfx-graphics-pipeline.md) — surfaces blit
  straight into the framebuffer, with no extract step.
- [Bitmap codecs](../territory/bitmap-codecs.md) — decoders write into a
  caller-provided buffer wherever the path allows.
- [Adapter drive loop](../territory/adapter-drive-loop.md) — calls the sink
  synchronously, which is what makes the borrow sound.

## What a violation looks like

Nothing fails. The picture is correct, the tests pass, and the cost appears only as
frame-rate loss under load — proportional to desktop area, so it is worst exactly
where it matters (a full-screen 4K repaint) and invisible on a small test surface.
The tell in code review is a signature: a decode or surface function returning
`Vec<u8>`, or a frame event holding pixel data instead of coordinates.

The second failure form is a **lifetime workaround**: someone who needs the pixels
after the sink returns copies them inside the library "for safety". That is the
host's decision to make, and moving it inside is the same defect wearing a
correctness argument.

## Discovery history

- **#85** — the design finding: the frame pixel pipeline copied each frame 4–5
  times. This produced [ADR-0010](../../adr/0010-frameupdate-dirty-rect-contract.md).
- **#162 → PR #165** — `FrameUpdate` stops carrying owned pixels and carries the
  dirty rect instead.
- **#163 → PR #166** — EGFX surfaces blit straight into the framebuffer; the extract
  copy is removed.

Three encounters with one fact, at three layers, each found after the previous fix
— which is the signature of a constraint that had no home above the individual
change.

## Where it will recur

**If a function produces or forwards pixel data, it is subject to this.** The check
is a signature grep, not a judgement:

```sh
# pixel-producing signatures that own their output
rg -n 'fn .*-> *(Result<)?Vec<u8>' crates/justrdp-codecs/src crates/justrdp/src
```

Read each hit against the question *"could this write into a caller-provided
buffer?"* — a `Vec<u8>` that never reaches the framebuffer (a PDU encoder building
bytes to send) is **not** subject to this and should not be "fixed".

New graphics path ⇒ state, in the PR, where each pixel is written and how many times
it is copied before the host sees it. ADR-0010's answer is "once, then borrowed".
