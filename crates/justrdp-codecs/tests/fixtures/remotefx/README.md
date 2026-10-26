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
