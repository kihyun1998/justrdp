# Interleaved RLE corpora (#554)

| File | Records | Source |
|---|---|---|
| `ws2019-memblt-16bpp.bin` | 188 | the compressed Cache Bitmap (Revision 2) fills of `justrdp/tests/fixtures/session/memblt.bin`: the WS2019 VM, captured 2026-10-15 for #460 (provenance in that capture's README) |
| `ws2008r2-8bpp.bin` | the first 97 of 497 | the compressed bitmap-update rectangles of an 8 bpp session on the WS2008 R2 VM (192.168.136.167), captured 2026-10-26 by `bitmap_updates_at_8_bpp_paint_the_desktop_on_the_real_vm` |
| `ws2008r2-15bpp.bin` | 556 | the same at 15 bpp, by `bitmap_updates_at_15_bpp_paint_the_desktop_on_the_real_vm` |

For the two WS2008 R2 files the client advertised the defaults of `legacy_graphics_config` (no EGFX flag, no drdynvc) without the Surface
Commands and Bitmap Codecs sets, so the server paints in bitmap updates; `connectionType`
0x06 (LAN); `performanceFlags` 0x7 (no wallpaper, window drag or menu animation), with the Bitmap set's
`preferredBitsPerPixel` and `highColorDepth` at 8 or 15, and 15 added to `supportedColorDepths` for
the 15 bpp run. The session was driven by `corpus_session`: Notepad launched from the Start menu, the
pointer moved across a 19×15 grid of the desktop, Notepad closed. The 8 bpp file keeps only the records from the first that fit 512 KB (the
maintainer's call, 2026-10-26); the session's first rectangles are its largest.

## What no server here sends

**24 bpp.** Asked for 24, the WS2019 VM answers 32 (`../planar/`) and the WS2008 R2 VM answers 16.
FreeRDP 3.32.1 asking `/bpp:24` got the same depths from both (its `Remote framebuffer format` log
line, 2026-10-26), so the servers decide it, not this client's advertisement. WS2019 also answers 32
to 15 and 16 to 8; only WS2008 R2 honours 8 and 15.

## Format

The container every #554 corpus shares, little-endian: a `u32` record count, then per record
`u16 a, u16 b, u16 c, u32 len, payload[len]`. `a` and `b` are the bitmap's width and height; `c` is its bits per pixel.
`tests/real_server_corpus.rs` replays it.

## How to regenerate them

`ws2019-memblt-16bpp.bin` is carved from a committed capture:
`JUSTRDP_BLESS_CODEC_CORPUS=1 cargo test -p justrdp --test codec_corpus` writes it, and without the
variable that test fails when the file differs from a fresh carve.

For the WS2008 R2 files, the raw capture was not committed. Run

```
JUSTRDP_TEST_SERVER=ws2008r2 JUSTRDP_SESSION_CAPTURE_FILE=<file> cargo test -p justrdp-tokio --lib bitmap_updates_at_8_bpp_paint_the_desktop_on_the_real_vm -- --ignored
```

note the byte count it prints when its session ends (the harness's sign-out session appends to the
same file after it), then carve that many bytes and copy the codec's file here:

```
JUSTRDP_CARVE_CAPTURE=<file> JUSTRDP_CARVE_LEN=<count> JUSTRDP_CARVE_MAX_BYTES=524288 \
JUSTRDP_CARVE_OUT=<dir> cargo test -p justrdp --test codec_corpus carve_a_session_capture -- --ignored
```

Use the 15 bpp test for the 15 bpp file. The 8 bpp capture was 915 805 bytes, the 15 bpp one 412 559. A new capture differs: which regions a server repaints, and in which codec, varies run to
run.
