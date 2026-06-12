# 0007 — Stage-boundary differential verification for codecs without a high-level oracle

- Status: Accepted — governs #58 (not yet implemented)
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
- **The harness trusts the oracle's encoder to produce spec-valid streams.** Acceptable: the encoder is the same vetted crate family that supplies the decode primitives, and (A) independently checks the decode math regardless of how the bytes were produced.

## Alternatives considered

- **(A only) Stage-boundary diffs without a composed reference.** Rejected as insufficient alone — isolated stages can each match yet be wired together wrongly (stage ordering, an off-by-one at a boundary). (B) is cheap once the primitives are already glued for (A).
- **(B only) Composed reference without stage diffs.** Rejected as insufficient alone — an end-to-end mismatch gives no signal about *which* stage diverged, reintroducing the blind pixel-debugging loop ADR-0003 set out to eliminate.
- **Encode round-trip self-consistency** (`our_decode(synthetic_stream)` checked only for internal consistency). Rejected as a primary gate: with no independent decoder and a lossy codec, it asserts nothing about correctness against a reference. It survives only as the *input-generation* step feeding (A)/(B).
- **Wait for a captured real-server corpus.** Rejected — the VM never sends CAVIDEO, so this blocks the codec indefinitely on an event that may never occur.
- **Depend on `ironrdp-session`'s assembled RemoteFX decoder as the oracle.** Rejected — pulling in the session-level decoder is closer to vendoring the very assembly we are meant to own and prove independently (ADR-0003's "reference = copy = vendoring is explicitly avoided"); the primitive-level oracle keeps us honest about understanding the message set.
