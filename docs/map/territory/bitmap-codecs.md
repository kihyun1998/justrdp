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
- [ADR-0012](../../adr/0012-consumption-site-totality.md) — a value the parser
  constrained is consumed here as arithmetic across a crate boundary, so the
  refusal lives at the consumption site and the threshold is written on the
  quantity the arithmetic uses. Where ADR-0008 governs *whether* a path may panic,
  this governs *which module owns the guarantee* once validation and use are apart.

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
- **A guarantee the parser proves is not held where the value is used, and this
  territory is where that bites** ([ADR-0012](../../adr/0012-consumption-site-totality.md)).
  `justrdp-pdu` masks quant nibbles to `0..=15` and rejects an NSCodec colour-loss
  level outside `1..=7`; `justrdp-codecs` then shifts by those values across a crate
  boundary, through plain `pub` fields and bare `u8` parameters that carry none of it.
  Three sites, and the census kept mis-sizing itself because each is safe for a
  *different* reason: `planar.rs`'s `cll` is safe **by construction** (`header & 0x07`),
  `progressive::dequantize_first_pass` **by a validating caller** (`first_pass_shift`),
  and `quant::dequantize` / `nscodec::reconstruct` were safe **only by the parser's
  word** — the one reason that does not survive either function being `pub`. Both
  panicked at a shift of 16 or wider, reproduced. The threshold is on the **shift**:
  an exponent of 16 shifts by 15 and is fine, so a guard written as "the nibble
  exceeds 15" is off by one and would make the two dequantizers refuse different
  inputs for the same stated reason.
- **The two RemoteFX dequantizers give one quantity one answer, and the one that
  cost a decision was `exponent == 0`** (#233, [ADR-0012](../../adr/0012-consumption-site-totality.md) §3).
  `progressive::first_pass_shift` refused it from the start (`ZeroBitPosition`);
  `quant::shifts` skipped the band, because `saturating_sub(1)` cannot tell an
  exponent of 0 — which names no shift — from an exponent of 1, which names a shift
  of zero and must stay untouched. Both behaviours were pinned by green tests that
  did not cite each other. It is now `checked_sub` on both sides. Two things this
  leaves that the width refusal does not: it is the family's **first refusal a server
  can reach** (a `0x00` byte is two zero nibbles), and it is **not corroborated by the
  VM**, which never emits CAVIDEO — the safety of refusing rests on FreeRDP agreeing,
  so it is recorded as a FreeRDP-derived position rather than an observed one. The
  differential oracle disagrees and stays green only because no harness quant table
  carries a zero: `Quant::default()` is the MS server's own table (6..7) and the
  harness's second table is 8..12. **If one ever carries a zero the differential goes
  red, and that is the correct signal, not a false one.**
- **A property can be green on every seed it finishes and still be the most expensive artifact
  in the repo** (#262). `color::to_rgba`'s no-panic property — added by #238/#241, mutation-
  checked, three tests red with the guard off — hung on ~43% of seeds, because a **hang is not
  a red**: the property does not fail, it runs, and a hang never shrinks so nothing lands in
  `proptest-regressions/`. Cost before anyone read a cancelled log: **10 jobs, ~56.4
  runner-hours**. This is the third distinct way a green property in this territory has meant
  nothing — after a generator *bounded* to the parser's range (#211) and one too *wide* to
  satisfy the parser (#230) — and it is the first that no mutation can detect, because the
  missing guard turns the property silent rather than red.
- **Two more members of ADR-0012's class were found by enumerating it, and both were live**
  (#238). `color::to_rgba` sizes two buffers from wire dimensions and had neither artifact — the
  member the issue named. `nscodec::plane_sizes` multiplied `tw * height` unguarded, and
  `temp_dims` rounds a declared 65535 up to 65536, so `decode`'s own `u16` parameters reach an
  overflow on a 32-bit target. **`plane_sizes` refuses rather than saturates**, and the reason is
  worth keeping: its four numbers are *bounds* `decode_plane` trusts, whose empty-input branch is
  `vec![0xFF; original_size]` — a saturated `usize::MAX` would have turned an arithmetic overflow
  into an allocation of the address space. "Total" and "does not panic" are not the same
  requirement.
- **A zero extent passes every guard and bounds no loop, and `to_rgba` is where that cost
  something** (#262, [ADR-0012](../../adr/0012-consumption-site-totality.md) §5). At
  `width == 0` the checks that exist all *succeed* rather than refusing — `0 * bpp` is 0,
  `0 * height` is 0, and `src.len() < 0` is false, so the source-length check reports a
  satisfied source — and `for out_row in 0..height` then walks a bare `usize`. **The arithmetic
  was never the undefined part; the trip count was.** The guard is `Ok(Vec::new())`, placed
  *after* the depth check (`rle::decompress`'s order, so an unsupported depth stays
  `UnsupportedBitsPerPixel` at any extent).
  **`Ok` is a deliberate divergence from FreeRDP, not agreement with it**, and the axis is the
  part to remember: the reference splits on **who owns the destination**, not on
  decoder-versus-converter. Everything writing into a caller-supplied buffer succeeds at a zero
  extent (`freerdp_image_copy` `color.c:1155`, `_no_overlap`, `_overlap`, `freerdp_image_fill`);
  everything that *allocates and returns* refuses, including `freerdp_glyph_convert_ex`
  (`color.c:265-267`, `return nullptr`), which is `to_rgba`'s exact shape. We go the other way
  on what the one reachable consumer does with the error: `justrdp::egfx`'s uncompressed WTS1
  arm propagates a `ColorError` with `?`, **fatal for the channel** where every other codec arm
  there warn-and-skips, and `[MS-RDPEGFX]` 2.2.1.2 makes `RDPGFX_RECT16` exclusive with no
  non-zero requirement — so `right == left` is spec-legal and refusing would drop a healthy
  session over a legal empty rectangle ([ADR-0009](../../adr/0009-tolerant-negotiation-posture.md)
  receive-path posture). `pointer::decode_pointer` also returns empty and is **not** the
  precedent: its reason is a protocol semantic (*a zero-sized shape means "no shape"*) that a
  bitmap has no counterpart for. **The `rle`/`planar` refusal is not a divergence row against
  this** — they refuse a zero extent as *policy*, which is a different act from bounding a loop,
  so ADR-0012 §3 is not the section in play.
- **The same hole was open one module over, and closed in the same change.**
  `nscodec::reconstruct` is `pub`, took `height` as a bare `usize`, and looped
  `for y in 0..height` with no zero guard — the second and only other member of the class, per
  derivation ④ in
  [untrusted decode never panics](../invariant/untrusted-decode-never-panics.md). Probing it at
  `usize::MAX` alone reports "returns promptly" and is misleading: an unchecked multiply in
  `temp_dims` panics before the loop is reached, so **the extreme masks the hang that lives one
  bit down**. Everything else in this territory is bounded by construction (`clearcodec`'s
  region walks and `pointer::decode_pointer` are `usize::from(<u16>)`) or guarded above the
  loop.
- **A no-panic property whose generator is bounded to the parser's range asserts the
  parser, not the function.** `nscodec`'s `reconstruct_never_panics_on_arbitrary_input`
  documented itself as covering *"any colour-loss level"* and generated `1u8..=7`.
  Measured: with the guard removed and that generator restored — master's exact state —
  the property passes **green over a live panic**, while the unit test beside it goes
  red. Same shape as
  [a later stage can hide an earlier defect](../invariant/a-later-stage-can-hide-an-earlier-defect.md),
  one layer out into the harness. The opposite convention was already written twice,
  in `fuzz/fuzz_targets/progressive_srl.rs` and `progressive_multipass.rs`, both of
  which hand quant nibbles over unmasked on purpose and say why.
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
  **The guard for that is the absence of a method, not a comment:** `SurfaceStore` offers only
  `delete_surface(surface_id)`, and `RDPGFX_CMDID_RESETGRAPHICS` carries no surface id, so the
  wrong call cannot be written. Clearing everything at once is already `close()`'s whole-object
  replacement (`justrdp/src/egfx.rs:725`), which is safe precisely because it is *obviously* too
  broad to reach for in a `RESETGRAPHICS` handler.
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
  (`shifts`, `dequantize`, `ll3_delta_decode`, `BANDS_STANDARD`,
  `BANDS_EXTRAPOLATE`),
  `srl.rs` (`upgrade_component`, `SrlError`), `progressive.rs` (`Progressive`,
  `PaintedRect`, `PayloadOutcome`, `TileGrid`, `TileState`, `Scratch`,
  `ProgressiveError`, `SurfaceStore`, `order_payload`, `PayloadOrder`,
  `OrderAnomaly`, `TILE_STATE_BYTES`, `MAX_STORE_BYTES`)
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
- [Supply chain & gates](supply-chain-and-gates.md) — this territory's properties are what the
  gates actually spend their minutes on, in **four** workflows (`test`, `coverage`,
  `overflow-32bit`, and `fuzz` for the targeted decoders). #262 is the measurement that made
  this edge worth drawing rather than assuming: a test-only change here ran three of those
  lanes to their kill. That territory already listed this one.

## Known holes / open

- **Standalone NSCodec (surface bits / bitmap cache) is not built** — #150; today's
  NSCodec exists as the ClearCodec subcodec only.
- **RemoteFX Progressive is self-owned and live** — epic #158, closed by #172. Slices 1–5
  landed the wire parser (#167), the upgrade-pass entropy layer (#168, `rfx/srl.rs`), the
  multi-pass tile decode plus the reduce-extrapolate inverse DWT (#169), the store's lifecycle
  plus the per-payload block ordering (#170) and the full-pipeline assembly (#171,
  `Progressive`); slice 6 (#172) wired it into `justrdp::egfx` and retired the bootstrap
  delegation. What the wiring inverted, and why a green test had to be inverted with it:
  `justrdp::egfx` used to free Progressive state on `RESETGRAPHICS` and on
  `DELETEENCODINGCONTEXT`, which is correct for the id-keyed bootstrap oracle (#83) and a
  **desync** once the store is keyed by surface — the server's encoder keeps its reference
  frames across a reset and `RFX_TILE_DIFFERENCE` adds against them. Both frees are gone;
  `DELETESURFACE` and the `CREATESURFACE` replace path are the only things that free now.
  #91 proposed a word-buffered RLGR bit reader and **the measurement rejected it**: `rlgr::decode`
  is **4.6%** of a real corpus decode, and real streams have a **mean run length of 1.0 bits**
  (66.7% of runs are zero-length, 0.01% reach 64 bits, none reaches 256), so leading-zero
  counting has nothing to count. Two implementations were measured — a peek-per-call reader at
  2.1× slower and FreeRDP's incremental-accumulator shape at 6–12% slower on the dominant path
  against 1.93× faster on long runs the server never sends. What landed instead is the reader's
  **contract tests**, which the ADR-0007 stage differential structurally cannot supply: it
  compares only streams *both* implementations accept, so truncation and end-of-stream behaviour
  are outside it. **Its verification basis is owned as of #194** — a real-server corpus plus
  FreeRDP-derived SRL expectations, not an oracle diff, because the oracle decodes 2 of 52 real
  payloads (ADR-0011); the *stage* differential remains valid and discriminating, which is a
  different layer from the whole-payload one. The SRL half of that basis was **re-derived in
  #168**: five of its eight vectors had been computed at the oracle's initial `kp`.
- **FreeRDP's deferred re-blit is not modelled, and that is measured rather than assumed.**
  Its per-surface frame state — `frameId`, `numUpdatedTiles`, `updatedTileIndices`, a per-tile
  `dirty` flag (`progressive.h:190-201`), reset by the frame id changing
  (`progressive.c:2437-2441`) — re-blits the frame's whole accumulated dirty set on every
  payload (`:2346`). Probed live on 2026-08-19 (#171): **4 of 65 frames carried two
  WireToSurface2 payloads**, so the mechanism is reachable — and replaying that capture both
  ways, the carried-over set contributed **0 rectangles and 0 pixels**, leaving the two
  surfaces byte-identical. Inert *as long as a frame's successive regions do not overlap each
  other's tiles*; a capture that breaks that is what would make it worth building.
- **The upgrade path's band walk has no non-extrapolate variant**, matching FreeRDP
  (`progressive.c:1281-1322`) and the capture, where all 52 payloads set
  `RFX_DWT_REDUCE_EXTRAPOLATE`. The first-pass decoder does branch on it, so #169 needs
  both layouts where #168 needed one — and `quant.rs`'s `LL3_OFFSET` is the
  **non**-extrapolate constant.
- **`nscodec::reconstruct` had `to_rgba`'s zero-extent hole; closed 2026-08-31 (#262).** `pub fn`, `height`
  a bare `usize`, `for y in 0..height` with no guard above it, and the inner `for x in 0..width`
  contributes nothing at `width == 0`. Not wire-reachable — `nscodec::decode`'s own parameters
  are `u16` — so it was the same priority `to_rgba`'s was, and the same contract question.
  Closed alongside it rather than filed, because the two are one quantity with one answer; the
  same change made `round_up` refuse instead of wrapping (its caller's doc-comment had named
  that multiply as *the* reachable overflow path while it stayed unchecked) and capped the
  output reservation against `y_plane`, which is what let the property's dimension generators be
  widened past `0..=32`. Derivation ④ of
  [untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) is the census
  that finds the next one.
- H.264 (epic #21) has neither an implementation nor an oracle.
- The fuzz lane is nightly-only, so a newly added target is unguarded on the day it
  lands (ADR-0008).
