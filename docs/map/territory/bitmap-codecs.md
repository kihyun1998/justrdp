# Bitmap codecs

## What it is

Turning compressed pixel payloads into RGBA: interleaved RLE and RDP6 planar (the
slow path), NSCodec, ClearCodec, RemoteFX (WireToSurface1) with its RLGR entropy
coder, DWT and quantization stages, and the colour-space conversions every one of
them ends in. This is the largest concentration of hand-written parsing over
attacker-controlled bytes in the repo.

## Governing decisions

- [ADR-0003](../../adr/0003-phased-codecs-differential-oracle.md) — phased ownership
  with `ironrdp-graphics` as a differential test oracle; derive from spec, prove by
  byte-identical output, then drop the dependency.
- [ADR-0007](../../adr/0007-stage-boundary-codec-verification.md) — where no
  high-level oracle exists, verify **stage boundaries** (entropy → dequantize → DWT →
  colour) against the oracle's primitives; the amendment (#118) adds assembly-layer
  independence.
- [ADR-0008](../../adr/0008-robustness-testing-fuzz-and-property.md) — property
  tests and fuzzing for untrusted-input parsers.

## Design model

- **Derive from the spec, prove against the oracle.** Structural similarity to
  IronRDP is explicitly *not* the goal, and byte-identical output is the only
  accepted evidence.
- **Tolerances are corpus-driven, not spec-driven.** ClearCodec accepts RLEX runs
  that overflow the declared rect (clipping them) and skips the NSCodec subcodec
  path where FreeRDP rejects — both are required by real Server 2022 streams (#127).
  These are recorded as deliberate divergences in
  [`docs/agents/theflow.md`](../../agents/theflow.md).
- **Stage boundaries are the unit of verification** where the assembled decoder has
  no counterpart to compare against (RemoteFX, ADR-0007).
- **Decoders write into a caller-provided buffer** wherever the frame path allows
  it, rather than returning an owned `Vec` — the copy ADR-0010 removed.
- **RemoteFX has two block namespaces that collide by value.** WireToSurface1's
  `TS_RFX_*` and WireToSurface2's `RFX_PROGRESSIVE_*` both number their blocks
  `0xCCCx`, and only **two of the eight agree** — `0xCCC0` Sync and `0xCCC3` Context.
  The other six differ: `0xCCC1` CodecVersions vs FrameBegin, `0xCCC2` Channels vs
  FrameEnd, `0xCCC4` FrameBegin vs Region, `0xCCC5` FrameEnd vs TileSimple, `0xCCC6`
  Region vs TileFirst, `0xCCC7` TileSet vs TileUpgrade (WireToSurface1 first in each
  pair). So no block constant crosses between the two parsers. The same trap repeats
  one level down: progressive's `RFX_COMPONENT_CODEC_QUANT` swaps HL and LH at every
  DWT level relative to classic `TS_RFX_CODEC_QUANT`, so a quant read with the wrong
  decoder yields plausible values with two bands transposed rather than an error
  (#167). What makes both silent is that the wrong reading still *parses*: `0xCCC2`
  routed to the WireToSurface1 walker decodes as a channel list.
- **A region's tiles are bounded by its declared `tileDataSize` window, and the
  `numTiles` count is not policed against it.** This is **laxer than both
  references**, not a copy of either: FreeRDP drives by the window and then rejects a
  `numTiles` mismatch (`progressive_process_tiles` returns -1044; its `WLOG_WARN`
  there is the log level, not the outcome) and also rejects unless the window is
  consumed exactly; IronRDP drives by the count and discards the window. Tolerance is
  the permitted direction on a receive path (#167).

## Code

- `justrdp-codecs/src/rle.rs` — `decompress`, `RleError`
- `justrdp-codecs/src/planar.rs` — `decompress`, `PlanarError`
- `justrdp-codecs/src/nscodec.rs` — `decode`, `parse_header`, `split_planes`,
  `decode_plane`, `reconstruct`, `plane_sizes`, `NscHeader`, `NscError`
- `justrdp-codecs/src/clearcodec.rs` — `Clear`, `ClearDecoder`, `ClearError`
- `justrdp-codecs/src/rfx/` — `mod.rs` (`RemoteFx`, `RfxError`), `rlgr.rs`
  (`decode`), `dwt.rs` (`decode`), `quant.rs` (`dequantize`, `ll3_delta_decode`)
- `justrdp-codecs/src/color.rs` — `to_rgba`, `rfx_ycbcr_to_rgba`, `bytes_per_pixel`,
  `Palette`
- `justrdp-pdu/src/rfx.rs` — `RfxMessage`, `TileSet`, `Tile`, `Quant`, `RfxRect`,
  `EntropyAlgorithm`, `decode_all`
- `justrdp-pdu/src/rfx/progressive.rs` — `ProgressiveMessage`, `ProgressiveRegion`,
  `ProgressiveTile`, `FirstPassTile`, `UpgradeTile`, `ProgressiveQuant`,
  `ProgressiveCodecQuant`, `decode_all`
- Spec sections cited inline: `[MS-RDPBCGR]` 3.1.9, 2.2.9.1.1.3.1.2.4;
  `[MS-RDPEGDI]` 2.2.2.5.1, 3.1.9.1.2; `[MS-RDPRFX]` 3.1.8.1.3/.4/.7;
  `[MS-RDPEGFX]` 2.2.4.1.x

## Reference behaviour

**None.** No verified external-fact store — despite this being the territory with
the *most* reference-derived behaviour in the repo (FreeRDP's OOB fixes, IronRDP's
decoders). What exists instead: the differential tests themselves, and the
`clearcodec_corpus` fixtures, which encode reference behaviour as data rather than
as citations.

## Cross-cutting invariants

- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md)
- [Decoder dimension overflow on 32-bit](../invariant/decoder-dimension-overflow-32bit.md)
- [Oracle agreement is not independence](../invariant/oracle-agreement-is-not-independence.md)
- [The frame path carries no owned pixels](../invariant/frame-path-carries-no-owned-pixels.md)

## Blast radius

- [EGFX graphics pipeline](egfx-graphics-pipeline.md) — the consumer of most codec
  output, and the home of the two decoders still on bootstrap wrappers.
- [Framebuffer & frame delivery](framebuffer-frame-delivery.md) — stride, colour
  order and the blit target.
- [Pointer & cursor](pointer-cursor.md) — `decode_pointer` shares this territory's
  dimension arithmetic and was where the 32-bit overflow was first found.
- [Verification harness](verification-harness.md) — every claim in this territory is
  only as good as the oracle, corpus and property lanes.
- [Capability exchange & activation](capability-exchange-activation.md) —
  `BitmapCodecsCapabilitySet` decides which of these can be reached at all.

## Known holes / open

- **Standalone NSCodec (surface bits / bitmap cache) is not built** — #150; today's
  NSCodec exists as the ClearCodec subcodec only.
- **RemoteFX Progressive is not self-owned** — epic #158. Slice 1 (#167) landed the
  wire parser above; the decode half (SRL entropy #168, multi-pass tile state #169,
  context lifecycle #170, oracle + real-VM proof #171) and the bootstrap drop (#172)
  are open, so `egfx.rs` still delegates Progressive to `ironrdp-graphics`. #91 is
  the RLGR bit-reader performance work.
- H.264 (epic #21) has neither an implementation nor an oracle.
- The fuzz lane is nightly-only, so a newly added target is unguarded on the day it
  lands (ADR-0008).
