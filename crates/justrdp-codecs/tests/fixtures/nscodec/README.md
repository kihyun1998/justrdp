# NSCodec corpus (#554)

`ws2019-surface-bits.bin`: the 1432 NSCodec streams of the Set Surface Bits commands in
`justrdp/tests/fixtures/session/nscodec-surface-bits.bin`, in arrival order. That capture's README
(`crates/justrdp/tests/fixtures/session/README.md`) holds its provenance: the WS2019 VM
(192.168.136.136), captured 2026-10-01 for #150, the default capability sets with NSCodec at codec
ID 1, `connectionType` 0x06 (LAN), 32 bpp answered to a 24 bpp request. 1311 streams are 64×64 and
121 are 64×32.

## Format

The container every #554 corpus shares, little-endian: a `u32` record count, then per record
`u16 a, u16 b, u16 c, u32 len, payload[len]`. `a` and `b` are the bitmap's width and height; `c` is 0.
`tests/real_server_corpus.rs` replays it.

## How to regenerate it

It is carved from a committed capture, so it is regenerated from that capture, not from a VM:

```
JUSTRDP_BLESS_CODEC_CORPUS=1 cargo test -p justrdp --test codec_corpus
```

Without the variable, that test fails when this file differs from a fresh carve.
`justrdp/tests/codec_corpus.rs` holds the carve.
