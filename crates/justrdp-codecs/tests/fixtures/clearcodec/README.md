# ClearCodec corpus (issue #56)

`replay.bin` is one full session's worth of genuine ClearCodec (`RDPGFX_CODECID_CLEARCODEC`)
bitmap streams harvested from the live test VM (192.168.136.136, Windows Server 2019) by the
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
- The `ironrdp-graphics` oracle accepts every entry too, and the self-owned output is
  **byte-identical** to it (ADR-0003 phase-2 acceptance).
- A parser in the test, independent of the decoder, counts the shapes #56 fixed: short V-bar
  cache misses the swapped field layout rejects, and full V-bar cache hits. It also asserts that
  every RLEX region and every residual layer fills its rectangle exactly.

## `replay-text.bin`

Same format. Captured 2026-11-18 from the same VM (#587) by the
`capture_clearcodec_text_corpus_against_real_vm` `#[ignore]` test in `justrdp-tokio`: an EGFX
session that opens Notepad from the Start menu and types three lines of text four times. 781 payloads, 294
glyph stores and 368 glyph hits, all decoding. `replay.bin` holds no glyph hit, so this file is
what drives the glyph cache. The tests replay it through one decoder against the oracle and
assert that it holds glyph hits, each drawn into the rectangle its slot was stored with and
equal to the pixels its store decoded to.

## `replay.bin` provenance

Captured 2026-06-11 from a normal interactive desktop session (taskbar/tray + open windows).
Which regions a server Clear-codes is non-deterministic; re-running the capture harness yields a
different mix. This run produced 73 payloads.
