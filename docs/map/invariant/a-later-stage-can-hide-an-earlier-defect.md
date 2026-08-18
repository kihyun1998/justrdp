# A later stage can hide an earlier defect

## The fact

A test that asserts on a **pipeline's output** to verify an **earlier stage** is only
as discriminating as every stage in between. Where a later stage compresses the
value space — a clamp, a saturating cast, a constant field, a colour conversion
that pins most inputs to `0` or `255` — two different intermediate results arrive
at the same final bytes, and the assertion passes against an implementation that is
wrong.

This is not the same limit as [oracle agreement is not
independence](oracle-agreement-is-not-independence.md). That one is about the
*reference* being weak evidence. This one is about the *observation channel* being
lossy: the reference can be perfect, the expectation can be hand-derived, and the
comparison can still be blind, because the difference was destroyed after the stage
under test and before the assertion.

The consequence for method: **a test must demonstrate that it can tell the two
candidates apart, in the same run that asserts one of them.** An `assert_ne!`
against the alternative implementation, placed *before* the `assert_eq!` against
the expected one, converts "this passed" into "this passed and could have failed".

## Why it is cross-cutting

Every codec ends in a colour transform, every decoder ends in a buffer the caller
reads, and every acceptance gate ends in a count. The lossy stage is therefore
structural rather than incidental: it is the last stage of the pipeline, and the
last stage is where output-level assertions naturally attach. It also crosses out
of the codecs entirely — an acceptance corpus that counts successes cannot see a
value change, and a frame-path test that asserts a dirty rect cannot see wrong
pixels inside it.

It is a **verification** invariant, so it bounds what the harness can claim rather
than what any decoder does — which is exactly why it cannot be stated inside one
territory without being re-derived in the next.

## Territories it holds in

- [Bitmap codecs](../territory/bitmap-codecs.md) — every codec ends in
  `rfx_ycbcr_to_rgba` or `to_rgba`, both of which clamp to `0..=255`.
- [Verification harness](../territory/verification-harness.md) — where the limit
  bounds what a differential, a corpus replay or a proptest can assert.
- [Pointer & cursor](../territory/pointer-cursor.md) — the pointer differential
  compares final RGBA to check the plane split and the AND/XOR composition.
- [EGFX graphics pipeline](../territory/egfx-graphics-pipeline.md) — surface
  commands are verified through the blit, which clips before the assertion sees it.

## What a violation looks like

Three shapes, all of them green:

1. **The lossy stage swallows the difference.** A test decodes a tile with the
   wrong inverse transform and compares RGBA against the right one — and passes,
   because the coefficients were small enough that the colour step clamped both
   reconstructions onto the same flat tile. The tell is that the fixture was chosen
   for being *small and readable*, which is the same thing as *low dynamic range*.
2. **The measure is constant, so the comparison is between two constants.** An
   assertion like "both arrangements produce the same number of non-black tiles"
   reads as a pixel comparison and is not one, if the alpha channel is written
   unconditionally and "non-black" means "any non-zero byte". Every successful
   decode satisfies it, so the two sides are both just the success count.
3. **The stage under test is not on the path at all.** A unit test that calls the
   private helper directly proves the helper; it says nothing about the caller that
   selects the helper's arguments. Deleting the caller's branch then passes
   everything — the helper's own test still passes, because it never asked the
   caller anything.

## Discovery history

- **#169 (Progressive multi-pass decode), three times in one slice.** (a) Pointing
  the upgrade path at the classic inverse DWT instead of the reduce-extrapolate one
  survived the whole suite, including a test written specifically to pin the
  transform: the fixture's coefficients were small and the ICT clamped both
  reconstructions to the same tile. (b) A corpus test claiming the two store keys
  "paint identical pixels" compared `non_black_tiles`, a success count, because
  `rfx_ycbcr_to_rgba` writes `alpha = 255` unconditionally — hashing the tiles
  showed they paint *differently*, which reversed the conclusion the test was
  offered as evidence for. (c) Hardcoding the first pass's band layout survived,
  because the only test of the layout called the private dequantizer rather than
  `decode_first`.
- Each was found by **mutation**, not by review, and each of the three tests
  carried a doc comment asserting exactly the property it could not see.
- The corpus could not have caught any of them: it gates acceptance, and all three
  mutants decode every real payload without error.

## Where it will recur

At any site where a test observes a pipeline's **final** artifact to make a claim
about an **intermediate** one. Derive the list rather than storing it:

```sh
# assertions on final RGBA / pixel buffers, which every codec stage funnels through
grep -rn "to_rgba\|_rgba\b" crates/*/tests crates/*/src --include=*.rs | grep -i "assert\|expect"
# acceptance-shaped measures that cannot see a value change
grep -rn "is_ok()\|\.count()\|len(), \|non_black\|_tiles," crates/*/tests --include=*.rs
```

For each hit, ask the two questions that separate a gate from a green tick:

1. **Could this assertion have failed?** Turn the thing under test off and run it.
2. **Can this assertion distinguish the two candidates on *this* input?** Assert
   that it can, in the test, next to the assertion that relies on it.
