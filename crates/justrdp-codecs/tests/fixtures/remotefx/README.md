# RemoteFX corpus (#554)

`ws2019-thin-client.bin`: the first 41 of the 162 WireToSurface1 `CODECID_CAVIDEO` payloads the
WS2019 VM (192.168.136.136) sent in one session on 2026-10-26, in arrival order, captured by
`a_driven_thin_client_egfx_session_paints_the_desktop_on_the_real_vm`. Only the records from the
first that fit 512 KB are kept (the maintainer's call, 2026-10-26).

**The advertisement is what makes this server send RemoteFX.** The client advertised only EGFX
capability versions 8 and 8.1, with `CAPS_FLAG_THINCLIENT`, which asks for RemoteFX in place of
RemoteFX Progressive; the default advertisement (`../zgfx/`) got none. Otherwise `test_config`'s
defaults: `connectionType` 0x06 (LAN), `performanceFlags` 0x7. The session was driven by `corpus_session`: Notepad launched from the Start menu, the
pointer moved across a 19×15 grid of the desktop, Notepad closed.

Replay it in order through one decoder: the first payload carries the stream's context.

## Format

The container every #554 corpus shares, little-endian: a `u32` record count, then per record
`u16 a, u16 b, u16 c, u32 len, payload[len]`. `a` and `b` are the destination rectangle's width and height; `c` is 0.
`tests/real_server_corpus.rs` replays it.

## How to regenerate it

The raw capture was not committed. Run

```
JUSTRDP_SESSION_CAPTURE_FILE=<file> cargo test -p justrdp-tokio --lib a_driven_thin_client_egfx_session_paints_the_desktop_on_the_real_vm -- --ignored
```

note the byte count it prints when its session ends (the harness's sign-out session appends to the
same file after it), then carve that many bytes and copy the codec's file here:

```
JUSTRDP_CARVE_CAPTURE=<file> JUSTRDP_CARVE_LEN=<count> JUSTRDP_CARVE_MAX_BYTES=524288 \
JUSTRDP_CARVE_OUT=<dir> cargo test -p justrdp --test codec_corpus carve_a_session_capture -- --ignored
```

This capture was 758 285 bytes. A new capture differs: which regions a server repaints, and in which codec, varies run to
run.

## Expected pixels (#560)

`ws2019-thin-client.freerdp-tiles.bin`: what FreeRDP's RemoteFX decoder makes of each corpus
record, as digests. `tests/remotefx_freerdp_pixels.rs` decodes the corpus and compares.

**Format**, little-endian: a `u32` record count, then per corpus record, in order, `u16 width,
u16 height` (the record's own) and one `u64` per 64×64 tile of that rectangle, tiles in raster
order. A tile's `u64` is FNV-1a 64 (offset basis `0xcbf29ce484222325`, prime `0x100000001b3`)
over its RGBA rows, top to bottom, each row clipped to the rectangle. 3720 tiles in all. The raw
RGBA is 56,613,936 bytes; digests were the maintainer's call (2026-11-02) over committing it
compressed, which needs a decompressing dev-dependency.

**How it was made.** FreeRDP at tag 3.32.1 (commit `bf217a504e54cc719880c228e82353382cd7d4fa`),
built in WSL Ubuntu 24.04 with gcc and `-DWITH_SIMD=OFF`, linked by a short C harness that:

1. calls `primitives_set_hints(PRIMITIVES_PURE_SOFT)` before anything else, so every primitive is
   the generic C one;
2. makes one `rfx_context_new(FALSE)` with `PIXEL_FORMAT_RGBA32`, and feeds it every record in
   order;
3. per record, fills a `width × height` buffer with opaque black (`00 00 00 ff`), the value this
   decoder leaves outside the region, and calls
   `rfx_process_message(ctx, payload, len, 0, 0, buf, PIXEL_FORMAT_RGBA32, width * 4, height, &r)`.

A Python script turned the concatenated buffers into the digests. Neither is in the repository;
the file is their output.

**FreeRDP's SIMD build gives other pixels.** The same harness against Ubuntu's FreeRDP 3.32.1
package, SIMD on, matched these exactly with `PRIMITIVES_PURE_SOFT` (its SSE2 dequantization and
DWT agree with the C ones) and differed in 92,849 pixels with the primitives autodetected, every channel difference being one:
the margin FreeRDP's own `TestPrimitivesYCbCr.c` allows its optimized colour conversion. Which
primitive makes it was not measured. These digests are the generic C decoder's.
