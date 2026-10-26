# XCRUSH corpus (#554)

`ws2019.bin`: the 34 bulk-compressed fast-path update sections of
`justrdp/tests/fixtures/session/xcrush.bin`, in arrival order, all with `compressionFlags` 0x23 and
one of them a pointer update. The capture's README holds its provenance and the level-1 and level-2
flag mix: the WS2019 VM, captured 2026-10-15 for #456, the defaults plus Client Info `COMPRESSION`
with `CompressionTypeMask` 3, `connectionType` 0x06 (LAN).

Replay it in order through one decompressor: both levels' histories span sections.

## Format

The container every #554 corpus shares, little-endian: a `u32` record count, then per record
`u16 a, u16 b, u16 c, u32 len, payload[len]`. `a` is the section's `compressionFlags`; `b` and `c` are 0.
`tests/real_server_corpus.rs` replays it.

## How to regenerate it

It is carved from a committed capture, so it is regenerated from that capture, not from a VM:

```
JUSTRDP_BLESS_CODEC_CORPUS=1 cargo test -p justrdp --test codec_corpus
```

Without the variable, that test fails when this file differs from a fresh carve.
`justrdp/tests/codec_corpus.rs` holds the carve.
