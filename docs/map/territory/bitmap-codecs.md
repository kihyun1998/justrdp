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
- **Progressive's upgrade entropy state starts at `kp = 8`, and that constant is not
  where the algorithm is.** FreeRDP sets it in `progressive_rfx_upgrade_component`
  (`progressive.c:1272`), the sole caller of the SRL reader — so a transcription that
  reads only `progressive_rfx_srl_read` gets a decoder that is correct symbol-by-symbol
  and desynchronised from the first symbol of every component, because `k = kp / 8` is
  1 rather than 0 and the zero-encoding phase reads a run-length bit the other decoder
  never reads. Both references make the mistake easy: `ironrdp-graphics` starts at 0
  (`srl.rs:26`), and FreeRDP declares the state `WINPR_C_ARRAY_INIT` before assigning
  `kp`, so stopping at the declaration also lands on 0. That is how it survived into
  #194's owned basis and out again in #168 (see
  [oracle agreement is not independence](../invariant/oracle-agreement-is-not-independence.md)).
  This is the same silence as the block-namespace collision above: the wrong reading
  still decodes.
- **A band's `num_bits` and `shift` are not 4-bit nibbles — they reach 30 and 29.** A
  bit position is `quant + prog_quant`, the *sum* of two nibbles; `num_bits` is the
  difference of two such positions and `shift` is one minus one. Sizing anything on
  "it's a nibble, so ≤ 15" is wrong in the direction that does not announce itself:
  #168 capped the truncated-unary magnitude loop at `i16::MAX` on that premise, which
  is correct for every `num_bits ≤ 15` and silently desynchronises the shared SRL
  cursor above it. Exported as `rfx::srl::MAX_BIT_POS` so #169 inherits the derivation
  rather than the conclusion.
- **Reduce-extrapolate is a second inverse DWT, not the classic one with different
  offsets.** An `n`-sample line splits `low = (n + 2) / 2`, `high = n - low` rather
  than in half, so 64 → 33/31, 33 → 17/16, 17 → 9/8. Three things change together:
  every subband offset *and length* (not only `LL3`, which is the half the epic
  originally recorded), the lifting tail (two shapes instead of a mirror), and the
  narrowing — FreeRDP `clampi16` saturates where the classic `trunc16` deliberately
  wraps, and the two differ by a full `u16` on an overflowing tap. Every region in
  the real capture asks for it, so it is the live path and the classic transform is
  the exotic one here.
- **A tile's store has a history, and the history is state.** Progressive's
  cross-pass store holds coefficients, signs and bit positions — and, less
  obviously, *the band layout it was written at* and *whether it is completely
  written*. Both were missing in #169's first revision and both produced silent
  wrong pixels: region flags are per-`WBT_REGION`, so reading the current region's
  extrapolate flag to judge a refinement answers a question about the wrong pass;
  and a first pass that fails at its second component leaves one component from
  this pass and two from the last, which a later upgrade refines with `Ok(())`.
  The general form is the rule #168 already paid for — **state that describes a
  buffer belongs with the buffer, not in whoever last touched it.**
- **The DAS sign array is the *quantized* coefficient, captured off the raw entropy
  output** (`progressive.c:876`) — before the LL3 delta and before the
  dequantization shifts. The oracle captures it after both (`progressive.rs:84`),
  and the two disagree on 8369 of 8829 real components, because the LL3 delta is a
  prefix sum that runs between the two points. The error is permanent rather than
  per-frame: the sign array routes every later refinement of that coefficient
  between the SRL and raw streams.
- **`RFX_TILE_DIFFERENCE` is an inter-frame delta against the persistent store, and
  it is a different mechanism from the LL3 delta.** The LL3 reconstruction is
  unconditional (`progressive.c:879`, `:921`); the flag selects
  `buffer += current` (saturating, both operands written) over `current = buffer`
  in the DWT entry (`:821-826`). Conflating them is easy — #169's own handover
  notes did — and it decides what the tile store must be keyed by: 1405 of 2943
  real first passes carry the flag, so a store keyed by anything other than the
  surface grid position adds the difference to the wrong thing.

- **The block-ordering rules are per payload, and the mask that holds them is not decoder
  state.** FreeRDP keeps them in `WBT_STATE_FLAG` (`progressive.h:204-210`), which reads like
  decoder state and is zeroed at the top of every `progressive_decompress` call
  (`progressive.c:2463`) — one call per surface command (`gdi/gfx.c:1116`). Scope is the whole
  design here: per-payload makes ordering a pure function over one parsed message list,
  per-stream makes it a field someone has to reset. Measured over the capture, the wrong
  reading rejects **51 of 52** payloads, because 51 carry `FRAME_BEGIN` with no `SYNC` and no
  `CONTEXT` and a carried mask sees each as a duplicate. Six conditions, **three** outcomes —
  two fatal, two skip one region and continue, the rest logged — so a single "validate the
  ordering" pass is wrong on four of the six rows (#170).
- **The tile store's free paths are not the PDUs named after them.** `DELETEENCODINGCONTEXT`
  frees nothing (FreeRDP's handler is a literal no-op, `gdi/gfx.c:1239-1246`) and
  `RESETGRAPHICS` frees nothing (it reaches `progressive_context_reset`, which is a stub —
  `progressive.c:2635`); `DELETESURFACE` is the only free (`gdi/gfx.c:1366`), and creation is
  lazy and idempotent per surface (`progressive.c:543-563`). Keeping the store across a reset
  is not merely FreeRDP-shaped: the server's *encoder* holds its reference frames across one,
  and `RFX_TILE_DIFFERENCE` adds against that shared reference, so a client that cleared while
  the server did not would decode every later difference tile against zeroes. An encoder that
  *did* reset cannot send a difference tile at all, so keeping is weakly dominant (#170).
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
  (`decode`), `dwt.rs` (`decode`), `dwt_extrapolate.rs` (`decode`), `quant.rs`
  (`dequantize`, `ll3_delta_decode`, `BANDS_STANDARD`, `BANDS_EXTRAPOLATE`),
  `srl.rs` (`upgrade_component`, `SrlError`), `progressive.rs` (`TileGrid`,
  `TileState`, `Scratch`, `ProgressiveError`, `SurfaceStore`, `order_payload`,
  `PayloadOrder`, `OrderAnomaly`)
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
- [Capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md)
- [A later stage can hide an earlier defect](../invariant/a-later-stage-can-hide-an-earlier-defect.md)

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
  wire parser above, slice 2 (#168) the upgrade-pass entropy layer (`rfx/srl.rs`)
  and slice 3 (#169) the multi-pass tile decode plus the reduce-extrapolate inverse
  DWT (`rfx/progressive.rs`, `rfx/dwt_extrapolate.rs`) and slice 4 (#170) the store's
  lifecycle plus the per-payload block ordering (`SurfaceStore`, `order_payload`); the
  assembly and real-VM proof (#171) and the bootstrap drop (#172) are open, so `egfx.rs`
  still delegates Progressive to `ironrdp-graphics`. **Two consequences of that ordering are
  live right now:** nothing composes `order_payload` with `SurfaceStore` and the tile decode
  outside the corpus test, and `justrdp::egfx` still frees on `RESETGRAPHICS`
  (`justrdp/src/egfx.rs:319`) and on `DELETEENCODINGCONTEXT` (`:484`) — correct for the
  id-keyed bootstrap oracle (#83), wrong once the surface-keyed store is wired, and pinned by
  a passing test (`:1206`) that #172 has to retire. FreeRDP also carries **per-surface,
  per-frame blit state** — `frameId`, `numUpdatedTiles`, `updatedTileIndices`, a per-tile
  `dirty` flag (`progressive.h:190-201`), reset by the frame id changing
  (`progressive.c:2437-2441`) and driving a deferred re-blit of the whole frame's dirty set
  (`:2346`) — which `TileGrid` models not at all; that is #171's. #91 is the RLGR bit-reader performance
  work. **Its verification basis is owned as of #194** — a real-server corpus plus
  FreeRDP-derived SRL expectations, not an oracle diff, because the oracle decodes 2 of
  52 real payloads (ADR-0011). The SRL half of that basis was **re-derived in #168**:
  five of its eight vectors had been computed at the oracle's initial `kp`.
- **The upgrade path's band walk has no non-extrapolate variant**, matching FreeRDP
  (`progressive.c:1281-1322`) and the capture, where all 52 payloads set
  `RFX_DWT_REDUCE_EXTRAPOLATE`. The first-pass decoder does branch on it, so #169 needs
  both layouts where #168 needed one — and `quant.rs`'s `LL3_OFFSET` is the
  **non**-extrapolate constant.
- H.264 (epic #21) has neither an implementation nor an oracle.
- The fuzz lane is nightly-only, so a newly added target is unguarded on the day it
  lands (ADR-0008).
