# MPPC corpus (#554)

`ws2019-64k.bin`: the 38 bulk-compressed fast-path update sections of
`justrdp/tests/fixtures/session/mppc-64k.bin`, in arrival order: 32 with `compressionFlags` 0x21,
5 with 0x61 (`PACKET_AT_FRONT`), and 1 pointer update with 0x21. The 139 uncompressed sections are
left out, because the decompressor never sees them. The capture's README holds its provenance: the
WS2019 VM, captured 2026-10-15 for #454, the defaults plus Client Info `COMPRESSION` with
`CompressionTypeMask` 1 (64K), `connectionType` 0x06 (LAN).

MPPC-8K has no corpus: the server compresses nothing at type 0 (the same README).

Replay it in order through one decompressor: the history spans sections.

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
