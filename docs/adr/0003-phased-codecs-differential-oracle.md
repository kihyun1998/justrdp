# 0003 — Phased codec ownership via differential test oracle

- Status: Accepted
- Date: 2026-06-08

## Context

RDP codecs — RemoteFX, RemoteFX Progressive, ClearCodec, NSCodec, and zgfx — are RDP-specific protocols and belong in the "owned" category (Decision 2: we own all RDP-specific protocol). However, codec correctness is fundamentally about bit-exact math: DWT (Discrete Wavelet Transform), RLGR (Run-Length Golomb Rice), quantization, subband reconstruction, LZ77, and chroma subsampling. The hard part is not the algorithm design (the MS-RDP specs are public) but getting the implementation *interoperable* — decoding pixel-byte-identical output to what real servers and reference clients produce.

The `ironrdp-graphics` crate already decodes RemoteFX, ClearCodec, and zgfx (marked decode-complete), and the RemoteFX Progressive decoder is near-complete: `graphics/progressive.rs` exports `TileState` (cross-pass coefficient/sign store), `decode_first`/`decode_upgrade` (multi-pass state machine), and critically, `reconstruct_to_rgba` (full inverse DWT + YCbCr→RGB conversion). Confirmed on real VM this session: the server in use actually sends RemoteFX Progressive (`WireToSurface2`), not H.264 or uncompressed.

This creates a tempo tension: if we depend on `ironrdp-graphics` for codecs, we never own them (contradicts Decision 1). If we reimplement all codecs from spec on day one, we face weeks of blind "the output is corrupted pixels" debugging with no oracle to check against. Decision 1 commits us to a full rebuild; the question is how to do it without a cliff.

## Decision

**Phased ownership ("phased-c2"):** codecs are fully owned, but in three temporal phases with the oracle driving correctness.

1. **Bootstrap phase (day one):** Depend on `ironrdp-graphics` so rendering works immediately. Wire the server's codec streams (RemoteFX, Progressive, ClearCodec, zgfx) into `ironrdp-graphics` decoders and emit `FrameUpdate`s from the result. The application is fully functional and users see correct pixels.

2. **Rewrite phase (iterative):** Reimplement each codec ourselves (RemoteFX first, then Progressive, ClearCodec, zgfx). For each codec, the test harness feeds identical bitstreams to *both* our decoder *and* the `ironrdp-graphics` oracle, compares the decoded `Vec<u8>` pixel output, and asserts byte-identical results. The oracle runs as a dev-dependency.

3. **Drop phase (per codec):** Once our codec passes 100% of oracle comparisons (including edge cases, progressive tiles, quantization variants, server-emitted corpus), drop the `ironrdp-graphics` dependency for that codec and enable it in the feature gate. `rustls` (TLS) and `sspi` (NLA crypto — CredSSP, SPNEGO, NTLM, Kerberos, channel bindings) remain permanent dependencies; they are security-critical, not RDP-specific, and free of the hardcoded-flag negotiation bottleneck that motivated the justrdp rebuild.

## Consequences

- **Working pixels from day one.** No "image is garbage" debugging period; the application is usable while codec rewrites are in progress. Marketing sees a working demo during development.

- **Codec independence achieved without an upfront cliff.** Rewriting each codec is a 1–2 week task per codec in isolation, not a 4-week "get all decoders right before you can see anything" up-front commitment. Each codec becomes a discrete slice that can be reviewed, tested, and merged independently.

- **Correctness is automated, not debugged blind.** The oracle (ironrdp-* as dev-dependencies, pulled in only for tests) is the backbone of the §21 verification harness (plan.md). Feeding identical bytes to our codec and ironrdp's, comparing output, and asserting identity removes the manual pixel-inspection debugging loop that otherwise eats time in codec development.

- **"Reference = copy = vendoring" is explicitly avoided.** We re-derive the codec logic from the MS-RDP spec, not copy ironrdp's code, and we prove correctness via differential testing, not by structural similarity. This keeps us honest about understanding the protocol.

- **Workspace footprint.** `justrdp-codecs` depends on `ironrdp-graphics` initially; the dependency is feature-gated and removed once all codecs are self-owned. Downstream applications can pin `ironrdp-graphics` to zero if they use a version of justrdp with no ironrdp-graphics dependency.

- **No "forever fork" of ironrdp.** We are not maintaining a parallel codec implementation alongside theirs; we own ours completely and move on once it works.

## Alternatives considered

- **(A) Depend on `ironrdp-graphics` forever.** Rejected: contradicts Decision 1 (own all RDP-specific protocol). The goal is independence from ironrdp; a permanent codec dependency blocks that, even if the codecs are non-negotiable. Acceptable only if the goal were "minimal-scope client library" rather than "replace ironrdp," but that was not chosen.

- **(B) Hand-write all codecs from spec on day one with no oracle.** Rejected: weeks of "image is corrupted" debugging with no reference to check against. Leads to abandoned half-finished codecs, context-switch cost, and risk of shipping incorrect output. No clear incentive to do this phase upfront when the oracle makes the work risk-free later.

- **(C) Use a separate "oracle" repository.** Rejected: complicates the test harness. The oracle is the `ironrdp-*` crates themselves, pulled as dev-dependencies in `justrdp-codecs/Cargo.toml`. No separate repo needed; the test lives in `justrdp-codecs/tests/oracle.rs` and is the backbone of the verification harness (plan.md §21).

- **(D) Rely only on manual interop testing (servers + mstsc/FreeRDP capture).** Rejected: catches feature-level bugs but misses bit-exact alignment. If our YCbCr→RGB has a rounding error that manifests as a 1-pixel hue shift only on 10% of tiles, manual testing will not catch it; the oracle will.
