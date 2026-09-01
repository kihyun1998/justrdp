# Decoder dimension arithmetic overflows on 32-bit

## The fact

Any expression that multiplies server-declared dimensions into a byte count —
`width × height × bytes_per_pixel`, `stride × height`, `tile_count × tile_bytes` —
is computed in `usize`, and `usize` is **32 bits** on `i686` and `wasm32`. A server
may declare dimensions whose product exceeds `u32::MAX`; on a 64-bit host the
multiplication is merely large, on a 32-bit host it **wraps**, and the undersized
allocation that follows is then written past its end.

The check must be *before* the allocation, not a bounds check after it — and **a
checked multiplication is not by itself the check.** That second clause is a
correction: this note said *"the check must be a checked/saturating multiplication
before the allocation"* until #263, and it is insufficient in a way that was measured
rather than argued. `Vec` refuses any request above **`isize::MAX`**, not above
`usize::MAX`, so on a 32-bit target there is a 2 GiB band where `checked_mul` returns
`Some` and the allocation then panics with *capacity overflow* inside `raw_vec`.
Measured on `i686-pc-windows-msvc`: `40000 x 20000 x 4` is 3_200_000_000, passes
`checked_mul`, and panicked. A guard whose threshold is not the allocator's converts
no panic into an error anywhere in that window.

**So the rule is about where the threshold comes from: the guard's ceiling must be the
one the operation that can fail actually enforces.** For an allocation that is
`isize::MAX`, or better a domain bound the caller can defend —
`justrdp::egfx`'s `GraphicsProcessor::process` refuses a `destRect` whose RGBA exceeds
`MAX_TOTAL_SURFACE_BYTES`, which is *derived* (no admissible surface exceeds it, so no
legitimate `destRect` does) rather than picked. `usize::MAX` is the **type's** ceiling
and belongs to no operation at all. This is
[ADR-0012](../../adr/0012-consumption-site-totality.md) §2 — *the threshold is written
on the quantity the arithmetic uses* — one level out, and it is amended there
(2026-08-31, #263): §2 fixes which **quantity** to guard, this fixes which **ceiling**
to guard it against, and both failures look identical from outside, a guard that is
present and off by an amount nobody computed.

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
  allocation is `width × height × 4`, and since #263 so is the **`destRect`** of a
  WireToSurface1 command: `[MS-RDPEGFX]` 2.2.2.1 makes the rectangle the bitmap's own
  dimensions and 2.2.1.2 bounds its fields at `u16` with no maximum, so for every codec
  that expands its input the rectangle alone sizes the decode. This is the territory
  that owns the *magnitude* half of the fact, because it is the only one holding a
  number (`MAX_TOTAL_SURFACE_BYTES`) that makes a magnitude bound principled.
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

On `i686` or `wasm32` the same input allocates a small buffer and the decode writes
past it, which in Rust is a panic at best and a wrong picture at worst. **The
condition is the target, not the input**, which is why this was found twice rather
than fixed once: the reproduction requires a toolchain nobody runs by default.

**"On x86-64: nothing" is what this section said, and #263 measured it false.** The
sentence held for the *arithmetic* half and was read as holding for the fact. Where
the multiplication fits, the number it produces is still a byte count somebody
allocates: a **93-byte** TS_RFX tileset with `destRect = (0,0,65535,65535)` returned
`Ok(Some(17_179_344_900))` on `x86_64-pc-windows-msvc` — **16 GiB allocated, 18.9 s,
no error** — while the same call panicked on `i686`. So on 64-bit the violation is not
silence, it is a successful decode that costs 16 GiB, and **it is host-conditional in
the direction that makes it worse**: it succeeded on a box with ~24.8 GiB of commit
available, and on a smaller one `alloc_zeroed` fails, which is `handle_alloc_error`
and therefore **`abort`** — not a `Result`, not catchable, and fatal to the host
process rather than to the RDP task.

The consequence for how this note is used: **no *overflow* check can reach the 64-bit
row**, because the product does not overflow. Closing it needs a **magnitude** bound,
which is a different guard with a different threshold, and the threshold has to come
from a layer that owns a defensible number. That is why the fix for #263 lives partly
in `justrdp::egfx` (`GraphicsProcessor::process`, against `MAX_TOTAL_SURFACE_BYTES`)
and not entirely in the codec that panicked.

## Discovery history

- **#151** — `decode_pointer`: `xor_stride × height` can overflow `usize` on
  32-bit / wasm32. Found first, in the pointer decoder.
- **#155** — the *same* expression in the `rle`, `planar` and `color` decoders,
  filed explicitly as "#151 sibling". Two discoveries, four sites, one expression.
- Memory `wasm32_overflow_proof_via_i686` records the proof technique that closed
  both: build and run natively on `i686-pc-windows-msvc`, because x64 CI cannot
  reach the guard.
- **#263 — the third discovery, and it corrected this note twice rather than adding a
  site.** `RemoteFx::decode_to_rgba` sized `opaque_black` from a WireToSurface1
  `destRect`; the numbers are in **What a violation looks like** above. Two things it
  changed about the note itself:
  - **The derivation could not see the class**, and the reason is mechanical rather
    than conceptual — see **Where it will recur** below, where the old command and the
    measurement that condemned it are both kept.
  - **`checked_mul` was the wrong threshold**, per **The fact** above. The i686 band
    between `isize::MAX` and `usize::MAX` was reached with a `checked_mul`-only guard
    already in place, which is the strongest available form of the claim: the guard
    this note asked for was written, and the panic survived it.

  The stated cause in #263's own body — that the derivation missed the site because *"a
  length comparison is not an allocation size"* — is **not** what the measurement shows.
  That describes this note's **prose**, not its command: `justrdp::framebuffer`'s
  `let needed = usize::from(width) * usize::from(height) * 4;` **is** a length
  comparison and the command **does** return it. The miss is line scope, below.

## Where it will recur

**If a function computes an allocation size from values a server sent, it is subject
to this.** Derive the current sites rather than trusting a list.

**The derivation was widened in #263, because the one below is *line*-scoped and the
class it misses is the class that panicked.** Kept rather than deleted, since what it
misses is the instruction for reading its replacement:

```sh
# (1) the original. Two patterns ANDed PER LINE, which is the defect.
rg -n 'usize::from|as usize' crates/justrdp-codecs/src crates/justrdp/src/egfx.rs \
   crates/justrdp/src/framebuffer.rs | rg '\*'
```

Measured against the pre-#263 tree: **32 hits, and neither of the two sites that
failed is among them.** `decode_wts1`'s `CODECID_UNCOMPRESSED` arm binds
`usize::from(w)` on one line and multiplies `uw * uh * 4` three lines down
(`egfx.rs:232` and `:235` on that tree), and `rfx`'s `opaque_black` was
`vec![0u8; w * h * 4]` with the `usize` conversion in its caller — so no single line
carries both patterns and neither grep can see the pair. The same run *does* return
`Surface::bytes` and `justrdp::framebuffer`'s `needed`, which is why the miss reads as
arbitrary until the line scope is named: a cast and its multiply landing on one line is
a formatting accident, not a property of the hazard.

```sh
# (2) the widened form (#263). Any identifier multiplied by any identifier, across the
#     three source crates, minus deref/pattern noise and comment prose. An
#     over-approximation ON PURPOSE — like derivations 3 and 4 in
#     untrusted-decode-never-panics.md, it lists candidates and the adjudication is the
#     judgement, not the grep.
rg -n --no-heading -g '*.rs' '\b[a-z_][a-z_0-9]*(\(\))? *\* *[a-z_][a-z_0-9]*' \
   crates/justrdp-codecs/src crates/justrdp/src crates/justrdp-pdu/src \
 | rg -v ':\s*(//|/\*|\*)' \
 | rg -v '\b(match|if|while|return) *\*'
```

Counts, measured on 2026-08-31 rather than estimated: **57** candidates on the pre-#263
tree against (1)'s **32**, and both missed sites are among the 57. On the tree as it
stands the two figures are **55** and **33** — (2) drops by two because the multiplies
it found are now `checked_mul` chains, and (1) *gains* one from a newly added comment,
which is a fair warning about what (1)'s number was ever counting. Without the comment
filter (2) returns ~286 lines, most of them prose containing `w * h`; the filter is
part of the command, not an optional tidy-up.

Hand-written additions no tool can find:

- `justrdp-pdu/src/rfx/progressive.rs`, `decode_region` — sums the region's declared
  table sizes (`numRects * 8 + numQuant * 5 + numProgQuant * 16`) to check them
  against the block body before reserving. Satisfied **by construction**: the counts
  are a `u16` and two `u8`s and `numQuant` is rejected above 7 *before* the sum, so
  the total cannot exceed ~528 KB and cannot overflow a 32-bit `usize`. Outside
  derivation (1)'s scope, which covers `justrdp-codecs` and two `justrdp` files only —
  this is the first site in `justrdp-pdu` to size an allocation from a server count.
  Derivation (2) does reach the crate.
- `justrdp/src/egfx.rs`, `Surface::bytes` and `Surface::extract` — both satisfied **by
  construction**, and both are *returned* by derivation (1) rather than hidden from it,
  which is why they now carry the comment: a reader running the command lands on a hit
  and needs something to adjudicate against. Every caller of `Surface::bytes` is
  downstream of `CREATE_SURFACE`'s `> MAX_SURFACE_DIM` refusal, so both factors are at
  most 16384 and the product is at most 1 GiB; `Surface::extract` clips `w`/`h` to the
  surface's own dimensions before any multiply, so its **reserve** is bounded by a buffer
  that already exists (#263).

  **Say what the by-construction argument is about, not just that there is one (#268).**
  `Surface::extract`'s entry above is exact and it is a claim about the multiply; the
  comment it asks for was written that way and was read as a claim about the function,
  which panicked on `&self.rgba[off..off]` because clipping `w` does not clip `x`. Nothing
  in this note was falsified — allocation sizing is its scope and the reserve was never
  the defect — but this is where the comment it mandates gets written, so the mandate
  carries the qualifier: **name the step**. A comment reading "total by construction" over
  a function that also indexes is an invitation to stop reading, and the wider claim is
  the one a reader takes away. The instance is in
  [untrusted decode never panics](untrusted-decode-never-panics.md)'s Discovery history.

If a site satisfies the
invariant by *construction* (a dimension already clamped by a `u16` cap earlier in
the same function), say so in a comment at that site and add it here — a grep for
the checked-multiplication idiom will never surface it.

### The threshold, and the one place it is written

**Every guard in the family now narrows through `justrdp_codecs::allocatable`**, a
crate-private helper whose whole body is `(bytes <= isize::MAX as usize).then_some(bytes)`.
One helper rather than one comparison per decoder, because this is a single quantity —
the largest buffer any of them may ask for — and
[ADR-0012](../../adr/0012-consumption-site-totality.md) §3 asks a family for one answer
to one quantity. It was six comparisons for about twenty minutes and that was already
one inconsistency too many: `rfx` was corrected first and the divergence it created
against its five siblings is what made the helper obviously right.

The table below is kept because the **reproductions** are the evidence, not the status.
All four were run on `i686-pc-windows-msvc` on 2026-08-31 and each panicked with
*capacity overflow* in `raw_vec` rather than returning its own `DimensionsOverflow`.
What separates the rows is not whether a guard was present — one was present at every
single site — but **how much memory a caller must already hold to get an
over-`isize::MAX` request issued**, and the answer is far less than it looks, because
every one of these functions *expands*.

| Site | Band reachable before #263 | Closed by |
|---|---|---|
| `justrdp_codecs::rle::decompress` | **yes, and it was the cheapest.** `decompress(&[0u8; 8], 40_000, 20_000, 24)` — `dst` is `vec![0; total]`, sized from the dimensions with **no source-length check above it**, so **8 bytes** of input requested 2_400_000_000 | `allocatable`, and it is the site the end-to-end assertion uses, precisely because 8 bytes make it cheap |
| `justrdp_codecs::pointer::decode_pointer` | **yes, and it is the one that matters most**, because both dimensions are `u16` — the purest form of the [ADR-0012](../../adr/0012-consumption-site-totality.md) §1 class. `decode_pointer(65535, 8500, 1, &[0u8; 69_632_000], &[], ..)`: the exact mask-length gate is satisfied by **66 MB** at 1 bpp and `out_len` is 2_228_190_000, a **32x** amplification. The gate did bound the request — just not below the allocator's ceiling | `allocatable` |
| `justrdp_codecs::color::to_rgba` | **yes.** `to_rgba(&vec![0u8; 558_000_000], 30_000, 18_600, 8, .., false)`: the source check wants `w * bpp * h` at 1 byte per pixel and the output is 4, so **558 MB** in bought a 2_232_000_000-byte reservation | `allocatable` |
| `justrdp_codecs::rfx::RemoteFx::decode_to_rgba` | **yes** — `40_000 x 20_000 x 4` is 3_200_000_000, and this one was reached *with a `checked_mul` guard already in place*, which is the strongest form of the claim in **The fact** | `allocatable` (corrected first, inline, then folded into the helper) |
| `justrdp_codecs::planar::decompress` | **derived, not measured** — the `full_size * 3` reservation can land in the band, but both probes hit an earlier guard (`TruncatedInput` on the raw path, `InvalidSegment` on the RLE path) and reaching it needs three ~720 MB plane allocations to succeed first, marginal in a 32-bit address space | `allocatable`, on the contract rather than on a reproduction |
| `justrdp_codecs::nscodec::decode` | no — the output reservation is capped against `y_plane.len()`, a buffer that exists (#262) | `allocatable` anyway, for the signature |
| `justrdp_codecs::clearcodec` | no — gated by `bitmap.len() < expected` | — |
| `justrdp::egfx`'s `decode_wts1` | no — its `needed` feeds a length comparison only; nothing is allocated from it in that arm | — |

**The lesson the `pointer` row carries, and the reason "is there a length check above
it" is the wrong way to sort a list like this:** a gate against a buffer the caller
already holds bounds the request only by the **amplification factor** between input and
output, and these decoders exist to amplify. 32x for a 1-bpp pointer, 4x for an 8-bpp
colour conversion, unbounded for `rle`. A sort by "has a gate" marks `pointer` closed;
a sort by amplification puts it first.

**What is pinned, and what is not.** The threshold is asserted once, on `allocatable`
itself (`isize::MAX` accepted, `+1` refused, and the measured 2_400_000_000 refused),
and the **wiring** is asserted end-to-end only at `rle`, where 8 bytes reach it. At
`color` the reserve sits below a source-length check, so any input that reaches it
carries ~536 MB — asserting it would mean allocating half a gigabyte inside a 32-bit
test process, and a cheaper input silently asserts `SourceTooShort` instead. That is
said out loud at the site, because a chain nobody reddens is exactly what these five
functions assumed about themselves until this was measured.

None of the four was reachable through `justrdp`'s own wire paths: `session`'s
`apply_bitmap` bounds a slow-path rectangle to the negotiated desktop, and
`decode_fastpath` caps a pointer at 96 pixels. That is reachability, which
[ADR-0012](../../adr/0012-consumption-site-totality.md) §1 says governs priority and
never the contract — and each of these is a `pub fn` whose own signature admits the
value.

The proof obligation travels with the fix:
`cargo test -p justrdp-codecs --target i686-pc-windows-msvc`, with the guard
mutated off once to confirm the test can fail. **`-p justrdp` too where the fix touches
`egfx` or `framebuffer`** — the workflow already covers both crates, and the older
one-crate command is what the note used to name.
