# RDP6 planar corpus (#554)

`ws2019-32bpp.bin`: the first 1016 of the 2639 compressed 32 bpp bitmap-update rectangles the
WS2019 VM (192.168.136.136) sent in one session on 2026-10-26, captured by
`bitmap_updates_at_32_bpp_paint_the_desktop_on_the_real_vm`. Only the records from the first that
fit 512 KB are kept (the maintainer's call, 2026-10-26).

The client advertised the defaults of `legacy_graphics_config` (no EGFX flag, no drdynvc) without the Surface
Commands and Bitmap Codecs sets, so the server paints in bitmap updates; `connectionType`
0x06 (LAN); `performanceFlags` 0x7 (no wallpaper, window drag or menu animation), with `preferredBitsPerPixel` 32, `highColorDepth` 24 and
`WANT_32BPP_SESSION`. The session was driven by `corpus_session`: Notepad launched from the Start menu, the
pointer moved across a 19×15 grid of the desktop, Notepad closed. The server answered 32 bpp; it answers a 24 bpp request with 32 as
well.

The Graphics Pipeline's `CODECID_PLANAR` reaches the same decoder, but the WS2019 VM sent none in
the two EGFX sessions captured for #554 (`../zgfx/`, `../remotefx/`).

## Format

The container every #554 corpus shares, little-endian: a `u32` record count, then per record
`u16 a, u16 b, u16 c, u32 len, payload[len]`. `a` and `b` are the bitmap's width and height; `c` is 32.
`tests/real_server_corpus.rs` replays it.

## How to regenerate it

The raw capture was not committed. Run

```
JUSTRDP_SESSION_CAPTURE_FILE=<file> cargo test -p justrdp-tokio --lib bitmap_updates_at_32_bpp_paint_the_desktop_on_the_real_vm -- --ignored
```

note the byte count it prints when its session ends (the harness's sign-out session appends to the
same file after it), then carve that many bytes and copy the codec's file here:

```
JUSTRDP_CARVE_CAPTURE=<file> JUSTRDP_CARVE_LEN=<count> JUSTRDP_CARVE_MAX_BYTES=524288 \
JUSTRDP_CARVE_OUT=<dir> cargo test -p justrdp --test codec_corpus carve_a_session_capture -- --ignored
```

This capture was 1 830 295 bytes. A new capture differs: which regions a server repaints, and in which codec, varies run to
run.
