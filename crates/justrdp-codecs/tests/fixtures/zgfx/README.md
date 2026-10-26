# zgfx corpus (#554)

`ws2019.bin`: the 65 Graphics Pipeline channel messages the WS2019 VM (192.168.136.136) sent in one
session on 2026-10-26, each reassembled from its dynamic-channel fragments, in arrival order, exactly
as the zgfx decompressor receives them. Captured by
`a_driven_egfx_session_paints_the_desktop_on_the_real_vm`.

The client advertised `test_config`'s defaults: `SUPPORT_DYN_VC_GFX_PROTOCOL` and drdynvc,
`connectionType` 0x06 (LAN), `performanceFlags` 0x7, and every EGFX capability version from 8 to
10.4 with the standard cache. The session was driven by `corpus_session`: Notepad launched from the Start menu, the
pointer moved across a 19×15 grid of the desktop, Notepad closed. The messages carried 125 ClearCodec and 16 RemoteFX
Progressive commands, and no planar or RemoteFX.

Replay it in order through one decompressor: the history spans messages.

## Format

The container every #554 corpus shares, little-endian: a `u32` record count, then per record
`u16 a, u16 b, u16 c, u32 len, payload[len]`. `a`, `b` and `c` are 0.
`tests/real_server_corpus.rs` replays it.

## How to regenerate it

The raw capture was not committed. Run

```
JUSTRDP_SESSION_CAPTURE_FILE=<file> cargo test -p justrdp-tokio --lib a_driven_egfx_session_paints_the_desktop_on_the_real_vm -- --ignored
```

note the byte count it prints when its session ends (the harness's sign-out session appends to the
same file after it), then carve that many bytes and copy the codec's file here:

```
JUSTRDP_CARVE_CAPTURE=<file> JUSTRDP_CARVE_LEN=<count> JUSTRDP_CARVE_MAX_BYTES=524288 \
JUSTRDP_CARVE_OUT=<dir> cargo test -p justrdp --test codec_corpus carve_a_session_capture -- --ignored
```

This capture was 141 056 bytes. A new capture differs: which regions a server repaints, and in which codec, varies run to
run.
