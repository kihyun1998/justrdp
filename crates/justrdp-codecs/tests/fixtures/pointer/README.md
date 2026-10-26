# Pointer shape corpora (#554)

| File | Shapes | Source |
|---|---|---|
| `ws2019.bin` | 2, 32×32: one at 1 bpp, one at 32 bpp | the WS2019 VM (192.168.136.136), the 32 bpp session of `../planar/` |
| `ws2008r2.bin` | 9, all 1 bpp 32×32 | the WS2008 R2 VM (192.168.136.167), the 8 bpp session of `../rle/` |

Both captured 2026-10-26, with the advertisement and the driven session those READMEs give. They are
every Color and New Pointer update of the session. No 8 bpp shape arrived, so none resolves through
the session palette.

## Format

The container every #554 corpus shares, little-endian: a `u32` record count, then per record
`u16 a, u16 b, u16 c, u32 len, payload[len]`. `a` and `b` are the shape's width and height; `c` is its `xorBpp` (24 for a Color Pointer); the payload is a `u32` XOR-mask length, the XOR mask, then the AND mask.
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

For `ws2008r2.bin`, run `bitmap_updates_at_8_bpp_paint_the_desktop_on_the_real_vm` with `JUSTRDP_TEST_SERVER=ws2008r2`. A new capture differs: which regions a server repaints, and in which codec, varies run to
run.
