# 0007 — Stage-boundary differential verification for codecs without a high-level oracle

- Status: Accepted (first implemented in PR #81 / issue #58; amended same day — see Consequences); assembly-layer independence added in the Amendment below (#118, 2026-07-02)
- Date: 2026-06-12

## Context

[ADR-0003](0003-phased-codecs-differential-oracle.md) committed us to owning every RDP codec, with `ironrdp-graphics` as a **differential test oracle**: feed identical encoded bytes to our decoder and to ironrdp's, compare the decoded RGBA, assert byte-identity. That recipe has a hidden premise — **that ironrdp exposes a high-level decoder for the codec**. It holds for ClearCodec and zgfx (`ClearCodecDecoder`, `zgfx`), and #56 cleared ClearCodec on exactly that basis.

It does **not** hold for the RemoteFX family. `ironrdp-graphics` 0.8 ships no high-level RemoteFX decoder — only the transform *primitives* (`rlgr::decode`, `quantization::decode`, `dwt::decode`, `subband_reconstruction::decode`, color conversion) and an encode helper (`rfx_encode_component`). The assembled TS_RFX message-set decode lives in `ironrdp-session`, which we deliberately do not depend on. So for WireToSurface1 RemoteFX (#58) — and, by the same structure, the coming RemoteFX **Progressive** and **NSCodec** rewrites — there is no second decoder to feed. The ADR-0003 recipe, taken literally, has nothing to compare against.

Three compounding constraints make this worse for RemoteFX specifically:

1. **No high-level oracle.** As above — only primitives.
2. **The codec is lossy.** Quantization discards information, so an encode→decode round-trip cannot assert against the original pixels; `decode(encode(x)) != x`.
3. **No captured corpus.** The real test VM (192.168.136.136) never emits CAVIDEO — V8+ servers prefer Progressive — so a real-server bitstream corpus cannot be captured, and there is no real-VM acceptance path the way slice-3/slice-9 had.

The bit-exact failure mode ADR-0003 exists to catch (a rounding error in YCbCr→RGB that shifts hue on a fraction of tiles) is *more* likely here, not less — the math is the whole codec — yet the end-to-end oracle that would catch it is absent. We need a verification strategy that recovers ADR-0003's bit-exactness guarantee without a high-level decoder to diff against.

## Decision

For any codec we own that **lacks a high-level decoder oracle**, correctness is proven two complementary ways against the oracle's *primitives*, with synthesized inputs:

### 1. Stage-boundary differential (A)

Our decoder is structured as the spec's inverse stages (entropy decode → dequantize → inverse transform → color convert). At **each stage boundary**, the same intermediate buffer is fed to the corresponding `ironrdp-graphics` primitive and asserted byte-identical. This pins every math stage independently — the hue-shift class of bug surfaces at the exact stage that introduced it, not as an opaque end-to-end mismatch.

### 2. Composed full-pipeline reference (B)

The test harness glues the same `ironrdp-graphics` primitives in spec order to form a **reference decoder**, and asserts our full-tile RGBA is byte-identical to it. This catches stage-ordering and off-by-one assembly errors that (A) — which checks each stage in isolation — cannot. The glue is ours, but every unit of math is the oracle's, so the hard part stays externally verified. Because both sides decode the *same* stream, the codec's lossiness is irrelevant to the assertion.

### 3. Synthesized test vectors

Inputs are manufactured in the harness from the oracle's encoder family — for RemoteFX, `ironrdp-pdu`'s rfx message `Encode` impls (container) plus `ironrdp_graphics::rfx_encode_component` (tile payload) — driven by varied pixel patterns (flat / gradient / noise) to exercise the quantization and entropy code paths. The encoder is only an input *factory*; correctness is judged solely by the decode-side primitives, which are independent of it.

### 4. Coverage guard

Synthetic corpora test only the inputs we choose to generate, so a variant we forget to emit is a variant we never test. Each corpus therefore **asserts that every variant path was actually exercised** (e.g. RLGR1 and RLGR3 counts each `> 0`), mirroring the `oracle_rejections > 0` guard the ClearCodec corpus uses. A future change that silently stops covering a mode fails the build.

The oracle crates remain **dev-dependencies only** (ADR-0003); nothing here adds a runtime dependency.

## Consequences

- **ADR-0003's bit-exactness guarantee is preserved for oracle-less codecs.** The end-to-end byte-diff is replaced by (A)+(B), which together are strictly stronger at localizing the math bug ADR-0003 targets.
- **This is the standing pattern for the RemoteFX family.** Progressive and NSCodec face the same "primitives but no high-level decoder" situation; they follow this ADR rather than re-deriving a strategy. The reusable pure-math stages a self-owned RemoteFX decoder factors out (entropy / dequant / inverse transform, plus YCbCr→RGB in the shared color seam) are the same units the composed reference and the future Progressive rewrite consume.
- **Synthetic-only verification is an explicit ceiling for codecs the VM never emits.** Where no real-server bitstream can be captured (CAVIDEO today), the acceptance bar is the synthetic oracle and that limit is stated in the issue, not silently skipped. If such a server is later found, a real-VM smoke test is added then.
- **The harness trusts the oracle's encoder to produce spec-valid streams** — *amended 2026-06-12 (PR #81):* this premise failed on first contact. `ironrdp-graphics` 0.8's RLGR1 encoder adapts `kp` by `UP_GR` where MS-RDPRFX 3.1.8.1.7 (and FreeRDP's encoder *and* decoder, and the oracle's own decoder) use `UQ_GR`, so its RLGR1 streams desync every spec-correct decoder — including its own. The fallback that keeps point 3's *intent*: the forward transforms stay the oracle's, the entropy stage is a harness-local spec-correct RLGR encoder whose faithfulness is proven with the **oracle's decoder as the judge** (`harness_encoder_is_faithful_by_the_oracles_own_decoder`) — the input factory stays externally validated, not self-referential. A canary (`oracle_rlgr1_encoder_defect_still_present`) pins the upstream defect and fails loudly when an oracle upgrade fixes it, signalling the harness can be simplified back to the encoder-trusting form (the #56 pattern, mirrored to the encoder side).

## Alternatives considered

- **(A only) Stage-boundary diffs without a composed reference.** Rejected as insufficient alone — isolated stages can each match yet be wired together wrongly (stage ordering, an off-by-one at a boundary). (B) is cheap once the primitives are already glued for (A).
- **(B only) Composed reference without stage diffs.** Rejected as insufficient alone — an end-to-end mismatch gives no signal about *which* stage diverged, reintroducing the blind pixel-debugging loop ADR-0003 set out to eliminate.
- **Encode round-trip self-consistency** (`our_decode(synthetic_stream)` checked only for internal consistency). Rejected as a primary gate: with no independent decoder and a lossy codec, it asserts nothing about correctness against a reference. It survives only as the *input-generation* step feeding (A)/(B).
- **Wait for a captured real-server corpus.** Rejected — the VM never sends CAVIDEO, so this blocks the codec indefinitely on an event that may never occur.
- **Depend on `ironrdp-session`'s assembled RemoteFX decoder as the oracle.** Rejected — pulling in the session-level decoder is closer to vendoring the very assembly we are meant to own and prove independently (ADR-0003's "reference = copy = vendoring is explicitly avoided"); the primitive-level oracle keeps us honest about understanding the message set.

## Amendment (2026-07-02, #118): a same-lineage oracle does not prove the *assembly* layer

### Gap this closes

ADR-0003 and the Context above treat "ironrdp exposes a high-level decoder" (ClearCodec, zgfx) as sufficient for the byte-identical differential. A retrospective audit showed that is true for **availability** but false for **independence**, and the gap is specific to the codec's *assembly* layer (compositing / region / cache reconstruction) as opposed to its transform *primitives*:

1. **ClearCodec's high-level oracle shares our derivation.** `ironrdp-graphics`'s ClearCodec decoder is near line-for-line the same as ours (same V-bar reconstruction, same RLEX). A byte-identical diff cannot catch a bug both sides share by construction. **#116** is the demonstrated case: a cross-band V-bar corruption (a missing `band_height` clamp) was present in *both* our decoder and the oracle — only FreeRDP's `clear.c` (`if ((y + count) > vBarPixelCount) count = vBarPixelCount - y`) exposed it.
2. **The RemoteFX composed reference (B) glues *our* compositing logic.** (B) assembles the oracle's math primitives, but the region/tile blit/clip loop "is ours" (Decision §2). So the region-assembly layer is self-referential: **#117** — an empty `TS_RFX_REGION` (`numRects==0`) that must paint the full surface but painted nothing — would pass a reference that mirrors the same (wrong) region handling.
3. **The oracle *encoder* never emits the adversarial shapes** (cross-band cache hits, `numRects==0`), so those assembly paths have no differential coverage at all, independent of points 1–2.

### Decision (addition)

The oracle diff (ADR-0003) and the primitives-based (A)+(B) above remain the proof for the **transform/math stages** — entropy, dequantize, inverse DWT, subband, colour — which are genuinely the oracle's own independent math. But for the **assembly layer** — residual/band/V-bar/RLEX compositing and cache reconstruction (ClearCodec); region/tile blit and clipping (RemoteFX) — correctness MUST be proven by a conformance test whose expected output is derived **independently of our implementation**: hand-computed from the normative spec, or cross-checked against FreeRDP's `clear.c` / `rfx.c`. A green diff against a same-lineage oracle is *necessary but not sufficient* there.

The established pattern is the **#116 / #117 regression tests**: they assert against hand-derived expectations (FreeRDP clamp semantics; the opaque-black-init invariant), never against the shared-lineage oracle. New compositing / cache / region work follows this pattern.

### Consequence

- Verification is now explicitly two-tier: **primitives → oracle-diff (independent math); assembly → spec- or FreeRDP-independent conformance (the oracle is same-lineage).**
- The specific ClearCodec / RemoteFX behavioural divergences from FreeRDP that the shared oracle hides are tracked as their own issues (RLEX over-region clip #120, single-palette RLEX layout #121, and the remaining lenient divergences #127) rather than left implicit in a green differential.
