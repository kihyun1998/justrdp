# `Encode` / `Decode` + `ReadCursor` / `WriteCursor` pattern

## Decision

Every PDU implements the `Encode` / `Decode` traits from `justrdp-core`
directly. Both traits operate over `ReadCursor<'de>` / `WriteCursor<'_>`. The
hard invariant is: **the byte count returned by `size()` MUST equal the bytes
actually written by `encode()`**. The `justrdp-derive` proc-macro generates
the boilerplate for straightforward PDUs.

## Why

- **Byte-precise control** — RDP wire formats mix length prefixes,
  fixed-offset fields, and variable-length cursors. Working at the byte-cursor
  level is the most natural fit.
- **Compatible with `no_std`** — uses borrowed slices only; `alloc` is
  optional.
- **Pre-encode buffer sizing** — the `size()` invariant makes
  `Vec::with_capacity` / `[u8; N]` pre-allocation safe.

## Considered options

- **`nom`** — a combinator parser. Good on the read side, but no symmetric
  write side, and computing `size()` ahead of encoding would need a separate
  implementation anyway.
- **`serde` + a binary backend** — mismatches RDP's length-prefix and
  context-dependent layouts. Every PDU would need a custom `Serializer`.
- **`binread` / `binrw`** — heavy proc-macro magic. For security-sensitive
  paths (capability negotiation, license PDUs) the reviewer would have to
  trust the macro to produce *exactly* the bytes we want — we'd rather see it
  spelled out.

## Consequences

- A `size()`/`encode()` mismatch is a silent bug. Enforced via the CLAUDE.md
  rules "roundtrip tests are mandatory" and "boundary-value tests are
  mandatory".
- The proc-macro derive only covers *simple* PDUs. Context-dependent or
  variant-tagged PDUs are written by hand.
