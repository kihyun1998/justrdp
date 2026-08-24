# Decoder dimension arithmetic overflows on 32-bit

## The fact

Any expression that multiplies server-declared dimensions into a byte count —
`width × height × bytes_per_pixel`, `stride × height`, `tile_count × tile_bytes` —
is computed in `usize`, and `usize` is **32 bits** on `i686` and `wasm32`. A server
may declare dimensions whose product exceeds `u32::MAX`; on a 64-bit host the
multiplication is merely large, on a 32-bit host it **wraps**, and the undersized
allocation that follows is then written past its end.

The check must be a checked/saturating multiplication *before* the allocation, not a
bounds check after it.

## Why it is cross-cutting

The sites do not call each other. Each decoder computes its own buffer size from its
own header fields, and the pointer decoder, the RLE/planar decoders, the colour
converter and the EGFX surface allocator arrived at the same expression
independently — because it is the natural way to size a pixel buffer, not because
one copied another. No territory-to-territory edge could carry this: the shared
thing is an *arithmetic assumption about the host*, not a dependency.

## Territories it holds in

- [Pointer & cursor](../territory/pointer-cursor.md) — `decode_pointer`'s
  `xor_stride × height` (the first site found).
- [Bitmap codecs](../territory/bitmap-codecs.md) — `rle`, `planar`, `color`, and any
  later decoder that sizes a buffer from header fields.
- [EGFX graphics pipeline](../territory/egfx-graphics-pipeline.md) — surface
  allocation is `width × height × 4`.
- [Framebuffer & frame delivery](../territory/framebuffer-frame-delivery.md) — the
  framebuffer itself is allocated the same way, from the negotiated desktop size.
- [Verification harness](../territory/verification-harness.md) — where the proof
  obligation lives, and where it is now **met**: `.github/workflows/overflow-32bit.yml`
  builds and tests `justrdp-codecs` + `justrdp` on `i686-pc-windows-msvc`. It used to
  say the class was "guarded by a command someone has to remember to run", and that
  premise failed in a measurable way before the job existed — ADR-0013's toolchain pin
  is exact and a rustup target is per-toolchain, so the locally-added target went
  missing under the new pin with no signal at all. The job's scope is deliberately
  wider than the command that preceded it: that command named `justrdp-codecs` alone,
  which does not reach the EGFX and framebuffer sites listed above.

## What a violation looks like

On x86-64: nothing. Every test passes, the fuzzer finds nothing, the VM is happy —
because the product fits. On `i686` or `wasm32` the same input allocates a small
buffer and the decode writes past it, which in Rust is a panic at best and a wrong
picture at worst. **The condition is the target, not the input**, which is why this
was found twice rather than fixed once: the reproduction requires a toolchain nobody
runs by default.

## Discovery history

- **#151** — `decode_pointer`: `xor_stride × height` can overflow `usize` on
  32-bit / wasm32. Found first, in the pointer decoder.
- **#155** — the *same* expression in the `rle`, `planar` and `color` decoders,
  filed explicitly as "#151 sibling". Two discoveries, four sites, one expression.
- Memory `wasm32_overflow_proof_via_i686` records the proof technique that closed
  both: build and run natively on `i686-pc-windows-msvc`, because x64 CI cannot
  reach the guard.

## Where it will recur

**If a function computes an allocation size from values a server sent, it is subject
to this.** Derive the current sites rather than trusting a list:

```sh
# multiplications that feed an allocation, in the decode paths
rg -n 'usize::from|as usize' crates/justrdp-codecs/src crates/justrdp/src/egfx.rs \
   crates/justrdp/src/framebuffer.rs | rg '\*'
```

Hand-written additions no tool can find:

- `justrdp-pdu/src/rfx/progressive.rs`, `decode_region` — sums the region's declared
  table sizes (`numRects * 8 + numQuant * 5 + numProgQuant * 16`) to check them
  against the block body before reserving. Satisfied **by construction**: the counts
  are a `u16` and two `u8`s and `numQuant` is rejected above 7 *before* the sum, so
  the total cannot exceed ~528 KB and cannot overflow a 32-bit `usize`. Outside the
  `rg` scope above, which covers `justrdp-codecs` and two `justrdp` files only —
  this is the first site in `justrdp-pdu` to size an allocation from a server count.

If a site satisfies the
invariant by *construction* (a dimension already clamped by a `u16` cap earlier in
the same function), say so in a comment at that site and add it here — a grep for
the checked-multiplication idiom will never surface it.

The proof obligation travels with the fix:
`cargo test -p justrdp-codecs --target i686-pc-windows-msvc`, with the guard
mutated off once to confirm the test can fail.
