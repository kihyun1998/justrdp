# RemoteFX Progressive corpus (issue #194)

`replay.bin` is one session's worth of genuine `WireToSurface2` block streams harvested from the
live test VM (192.168.136.136, Windows Server 2022) by the
`capture_progressive_corpus_against_real_vm` `#[ignore]` test in `justrdp-tokio`, **in arrival
order**. Each payload is one post-zgfx `RDPGFX_CODECID_CAPROGRESSIVE` stream exactly as it
reached `Progressive::decode` on the wire, with the `codecContextId` and surface dimensions it
was decoded against.

This corpus is Progressive's **primary verification gate** (ADR-0011): the `ironrdp-graphics`
oracle is scaffolding with a retirement condition, and Progressive is the first codec where the
oracle demonstrably cannot decode real traffic. See `tests/progressive_corpus.rs`.

## Why a single ordered file (not per-stream fixtures)

Progressive is **stateful twice over**: codec contexts live across PDUs, and an upgrade pass
refines coefficients that an *earlier* first pass wrote. A payload decoded in isolation is
therefore a different input from the same payload decoded in sequence — an upgrade pass with no
preceding first pass has nothing to refine. Same reason the ClearCodec corpus is one ordered
file, one layer up.

## `replay.bin` format

Little-endian, no padding:

```
u32   count
count × {
  u32  codec_context_id   // RFX_PROGRESSIVE context this stream belongs to
  u16  width              // surface width the stream was decoded against
  u16  height             // surface height
  u32  len                // payload byte length
  u8   payload[len]       // raw post-zgfx WireToSurface2 block stream
}
```

## Provenance

Captured **2026-08-13** from an interactive desktop session driven by the capture test itself
(mouse sweeps plus Start-menu open/close, with idle windows between rounds). 52 payloads,
913,862 bytes.

**The capture advertises `connectionType = 0x01` (MODEM), not `LAN`** — and that single field is
the difference between a corpus and an empty one. Measured, both against this VM:

| `connectionType` | payloads | TILE_FIRST | TILE_UPGRADE | quality values |
|---|---|---|---|---|
| `0x06` LAN (the old harness default) | 1 | 1–8 | **0** | `{255}` |
| `0x01` MODEM | 52 | 2943 | **3250** | `{0, 255}` |

On `LAN` the server has bandwidth to spare, so it sends `TILE_FIRST` at `quality = 0xFF` — full
quality, first pass, nothing left to refine. No upgrade passes means **no SRL bytes exist on the
wire at all**, which would have left slice 2 (#168) with no real-server vector to test against.
Telling the server the link is slow makes it run an actual quality ladder. Re-run with
`JUSTRDP_CAPTURE_CONNECTION_TYPE` to sweep the other rungs.

Which regions a server codes, and how it schedules refinement, is non-deterministic — re-running
the harness yields a different mix.

## What this corpus exercises

Asserted by `corpus_spans_the_axes_the_epic_needs`, so the list cannot rot silently:

- **Both pass kinds** — 2943 `TILE_FIRST`, 3250 `TILE_UPGRADE` (slices #168, #169).
- **Both quality forms** — the `0xFF` full-quality sentinel *and* table-indexed qualities, with
  regions that carry a progressive-quant table (`numProgQuant` ∈ {0, 1}).
- **Both wire flags this server sets** — `RFX_SUBBAND_DIFFING` on the context, and
  `RFX_DWT_REDUCE_EXTRAPOLATE` on every region, which makes the **extrapolate** band layout the
  live path rather than the exotic one.
- **SRL and raw refinement streams**, on real upgrade tiles.

## What it does *not* contain

- **No `TILE_SIMPLE` tiles.** This server never sent one in this capture.
- **No context teardown.** The server emits `WBT_CONTEXT` exactly **once** (payload 0) and then
  rotates `codecContextId` — **24 distinct ids across 52 payloads**, a fresh id per refinement
  group. Nothing in the capture frees one, which is the live shape of the #83 leak semantics
  #170 has to answer.
- **One server, one session.** The standing caveat: the WS2022 box advertises a fixed cap set,
  so this corpus can prove the paths it walks and says nothing about the ones it does not.

## What the oracle does with it

2 of 52 payloads decode. The rest fail for **two independent reasons**, each pinned by its own
canary in `tests/progressive_corpus.rs`:

1. **1 × `quant index 255 exceeds table length 0`** — the `0xFF` sentinel used as a table index
   (0.9.0 `progressive.rs:1231`, `:1268`), which FreeRDP special-cases (`progressive.c:997`,
   `:1407`).
2. **49 × `progressive stream missing CONTEXT block`** — the oracle demands a context block per
   `codecContextId`; this server sends one, ever. FreeRDP imposes no such requirement: it gates
   a region on `FLAG_WBT_FRAME_BEGIN` alone (`progressive.c:2129`), keys tile state by
   `surfaceId` (`:314`), and only warns when `ctxId != 0x00` (`:1999`).

The second is not a consequence of the first — skipping the payload that trips the sentinel does
not save the ones after it.
