# ClearCodec corpus (issue #56)

`replay.bin` is one full session's worth of genuine ClearCodec (`RDPGFX_CODECID_CLEARCODEC`)
bitmap streams harvested from the live test VM (192.168.136.136, Windows Server 2022) by the
`capture_clearcodec_corpus_against_real_vm` `#[ignore]` test in `justrdp-tokio`, **in arrival
order**. Each payload is one post-zgfx `CODECID_CLEARCODEC` stream exactly as it reached
`ClearDecoder::decode` on the wire, with the destination-rectangle dimensions it was decoded
against.

## Why a single ordered file (not per-stream fixtures)

ClearCodec is **stateful**: the V-bar cache and glyph cache persist across PDUs. A cache-hit
stream only resolves when the earlier streams that populated those cache entries are replayed
first. Decoding a captured payload in isolation would spuriously miss the cache (this is exactly
why one of the oracle's rejections, `vbarIndex` "V-bar cache miss on hit", is *transitive* — it
disappears once the preceding bands decode and store their columns). So the corpus is the whole
session in order, replayed through one decoder, the way the live session runs.

## `replay.bin` format

Little-endian, no padding:

```
u32   count
count × {
  u16  width        // destination rectangle width
  u16  height       // destination rectangle height
  u32  len          // payload byte length
  u8   payload[len] // raw post-zgfx CODECID_CLEARCODEC stream
}
```

## What the tests assert (`tests/clearcodec_corpus.rs`)

- The self-owned `ClearDecoder` replays the **entire** capture without error — matching the live
  session, which had 0 rejections under the fixed decoder.
- Where the bootstrap oracle (`ironrdp-graphics`) **succeeds**, the self-owned output is
  **byte-identical** (ADR-0003 phase-2 acceptance).
- Where the oracle **rejects** with one of its three defective validations
  (`shortVBarCacheMiss`, `rlex` suite, `vbarIndex`), the self-owned decoder produces pixels. The
  differential test asserts all three signatures appear in this corpus, so the #56 fix is
  genuinely exercised.

The oracle cannot supply a per-stream pixel reference for streams it rejects, so ground truth
for those is the full-desktop render in the slice-9 EGFX real-VM acceptance test (no Clear-region
holes).

## Provenance

Captured 2026-06-11 from a normal interactive desktop session (taskbar/tray + open windows).
Which regions a server Clear-codes is non-deterministic; re-running the capture harness yields a
different mix. This run produced 73 payloads.
