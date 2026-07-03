# 0010 — FrameUpdate carries the dirty rectangle, not owned pixels: the host reads the retained framebuffer by borrow

- Status: Accepted
- Date: 2026-07-03
- Closes the design decision in issue #85; implementation sliced into #162 and #163

## Context

A decoded frame's pixels are copied 2× (legacy bitmap path) to 5× (EGFX surface path) between the codec and the host's frame sink. The root cause is the host-facing contract: `FrameUpdate` **owns** `pixels: Vec<u8>` (`framebuffer.rs:19`) — a duplicate of pixels that `Framebuffer::blit` has *already* written into the retained framebuffer one line earlier (`framebuffer.rs:97` writes the framebuffer, `:98` copies the same bytes again into the owned `FrameUpdate`).

Two facts make the owned copy pure redundancy:

- **justrdp already retains the authoritative framebuffer and exposes it** — `session.rs` `pub fn framebuffer(&self) -> &Framebuffer`, `framebuffer.rs:65` `pub fn pixels(&self) -> &[u8]`. The pixels the host needs already live in a retained buffer; the per-region `Vec` is a second residence of the same bytes.
- **The sink is already synchronous** — `on_frame: impl FnMut(&FrameUpdate)` (`justrdp-tokio lib.rs:642`). The host copies the region into its own texture inside the callback and drops the `FrameUpdate`. Owned buffers are only justified for *asynchronous* handoff (a `Sender<FrameUpdate>` channel); a synchronous borrowed callback needs no ownership.

The reference model agrees. IronRDP's session output is **coordinates only** — `ActiveStageOutput::GraphicsUpdate(InclusiveRectangle)`, with no pixel-buffer variant — and its `DecodedImage` retained framebuffer is read **by borrow** (`data(&self) -> &[u8]`, `data_for_rect(rect) -> &[u8]`); it never owns or moves per-rect pixels. justrdp's own `framebuffer.rs` docstring already claims to "mirror the decode-complete reference model of ironrdp-session's image buffer" — the owned `Vec` is a copy bolted on top that breaks the mirror.

One constraint rules out a middle option: a full-desktop framebuffer stores each row-major, so a `W×H` sub-rectangle is **not** a contiguous slice (it is `H` segments of `W×4` bytes separated by the framebuffer stride). A borrowed *flat* `&[u8]` therefore cannot represent a dirty rect without first copying it out contiguously — which is the copy we are trying to remove. The real choice is only **coordinates-only (host reads the retained framebuffer)** versus **owned `Vec`**; there is no zero-copy flat-borrow between them.

## Decision

**`FrameUpdate` carries the dirty rectangle only; the host reads those pixels from the retained framebuffer.** This is the orthodox retained-framebuffer + dirty-rectangle model, and it completes the ironrdp-session mirroring the code already aims at.

1. **`FrameUpdate` becomes `{ x, y, width, height }`** — the `pixels` field is removed.
2. **The sink gives the host framebuffer access in the callback** — `on_frame: impl FnMut(&FrameUpdate, &Framebuffer)`. The host reads the dirty rect through a stride-aware accessor (`Framebuffer::copy_rect_into(x, y, w, h, &mut dst)` / a `rows_for_rect` iterator) so it never hand-rolls stride math. This shape matches the host's real use: uploading the sub-rectangle to a GPU texture (`glTexSubImage2D` / `wgpu write_texture` both take a region + stride, not a flat buffer).
3. **`Framebuffer::blit` stops building the owned `FrameUpdate.pixels`** (removes the second copy, "d₂", on both paths); it still writes the region into the framebuffer (copy "d₁", structural — that *is* the retained buffer) and returns the rect.
4. **The EGFX DVC bridge carries coordinates, not owned pixels** — blit `surface → framebuffer` directly instead of extracting the region into an intermediate owned `FrameUpdate` (removes copy "c").
5. **A host that must defer a frame across threads copies the rect out itself** inside the synchronous callback (or takes a `full_frame()` snapshot) — an explicit, per-host opt-in, never a cost forced on the synchronous common case. (This is not a separate "hybrid" mechanism; it is what any borrow contract already permits.)

## Consequences

- **Public-API breaking for every host**: the `pixels` field is gone; hosts read from the framebuffer. Justified — the sink is synchronous (so the lifetime bound is already satisfied) and the host's real use wants a rect + stride, not a flat `Vec` it must re-unpack.
- **Removes 1 copy/region on the legacy path (d₂) and 2 copies/region on the EGFX path (c + d₂).** The remaining copies are structural and stay: **a** (the codec must decode *somewhere* — `color.rs:124`), **b** (the EGFX surface is a distinct buffer that gets composited before reaching the framebuffer — `egfx.rs:113`), **d₁** (writing the authoritative framebuffer — needed for reactivation re-emit and host snapshots).
- **Completes the ironrdp-session mirroring** `framebuffer.rs` already states as its model.
- **Implementation sliced**: #162 (contract change + d₂ removal + `copy_rect_into` helper + sink signature) and #163 (EGFX bridge coords + c removal). #162 is self-contained and lands first; #163 depends on it.
- **Out of scope**: fusing **a** + **d₁** by decoding straight into a `&mut` framebuffer slice (a `color::to_rgba`-into-borrowed-target change) is a larger codec-API refactor, tracked separately only if profiling justifies it after the copies above are gone.
