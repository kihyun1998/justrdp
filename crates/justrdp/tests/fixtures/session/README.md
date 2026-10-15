# `session/` — server bytes after session-active, replayed through the session machine

Server-to-client only, so no credential crosses into these files. Captured from the real VM
(`docs/agents/thegraph.md`'s third source; memory `test_environment`), one WS2019 box on one
advertised configuration — **they prove what this server sends, never what servers send.**

This directory sits in `justrdp` rather than beside `justrdp-pdu/tests/fixtures/session/` because
its test replays the bytes through `SessionStateMachine`, and a fixture lives in the crate whose
tests replay it (ADR-0001 Amendment).

## `nscodec-surface-bits.bin`

162 fast-path PDUs, 199 624 bytes: one logon's desktop painted in NSCodec Set Surface Bits.
Captured 2026-10-01 for **#150** by `nscodec_surface_bits_paint_the_desktop_on_the_real_vm`
through `JUSTRDP_SESSION_CAPTURE_FILE`, carved to the test's own session (the first 201 631 bytes;
the harness's sign-out session appends after it) and then to its **fast-path PDUs only**.

The five TPKT frames were dropped on purpose. They carry Save Session Info, and the default General
set advertises `AUTORECONNECT_SUPPORTED`, so one of them holds an auto-reconnect cookie — a live
session credential (see `justrdp-pdu/tests/fixtures/session/README.md`).

What the client advertised: the default capability sets (`SURFCMDS_SET_SURFACE_BITS`, Multifragment
Update at 1 114 112 bytes, NSCodec at codec ID 1 with dynamic fidelity, subsampling and colour-loss
level 3), no `SUPPORT_DYN_VC_GFX_PROTOCOL`, 24-bpp high colour without `WANT_32BPP_SESSION`. The server's
Demand Active answered 32 bpp anyway.

| What | Count |
|---|---|
| Surface Commands updates (`FP_UPDATE_SURFCMDS`) | 26 |
| Set Surface Bits, all codec 1 at 32 bpp | 1432 — 1311 at 64×64, 121 at 64×32 (the bottom row of an 800-high desktop) |
| NSCodec streams with chroma subsampling / without | 1409 / 23, all at colour-loss level 3, none with an alpha plane |
| Bitmap updates | 0 |

### What it pins that an argument could not

- **The planes are bottom-up.** Neither `[MS-RDPNSC]` nor `[MS-RDPEGDI]` says so; FreeRDP's encoder
  writes plane row 0 as the bottom image row and its client decodes with a vertical flip. The
  framebuffer hash in `real_server_surface_bits.rs` was taken after the replay was rendered and
  looked at — taskbar at the bottom, readable text, correct icon colours — and a top-down decode
  changes it.
- **Frame Markers follow the advertisement.** This capture, advertising Set Surface Bits alone,
  holds none; a probe on the same day that also advertised `SURFCMDS_FRAME_MARKER` received 37
  begin/end pairs around the same kind of desktop paint.
- **The server needs the Multifragment Update set.** Without it, the same server sent three
  Frame Markers and then Set Error Info `0x112F` and closed the session, before any surface bits.

### What it cannot see

Stream Surface Bits, `codecID` 0, a `TS_COMPRESSED_BITMAP_HEADER_EX` and Frame Markers: none
arrived, and the last is the advertised config's doing
(`docs/map/invariant/capture-coverage-follows-what-we-advertise.md`). All four rest on the unit
tests in `surface_commands.rs` and `session.rs`.

### What it depends on

**The VM's *Limit maximum color depth* policy at 32 bpp**, set on 2026-10-01. Until then the server
capped every non-EGFX session at 16 bpp and sent no Surface Bits at all, to justrdp or to FreeRDP
3.31 (`+nsc /bpp:32`). A VM rebuilt without the policy reproduces none of this.

## `mppc-64k.bin`

171 fast-path PDUs, 64 983 bytes: one logon's desktop sent MPPC-64K bulk-compressed. Captured
2026-10-15 for **#454** by `mppc_compressed_updates_paint_the_desktop_on_the_real_vm` through
`JUSTRDP_SESSION_CAPTURE_FILE`, carved to the test's own session (the first 66 990 bytes, the
count the test printed) and then to its **fast-path PDUs only**. The raw capture was deleted.

The five TPKT frames were dropped for the same reason as above: three Save Session Info PDUs, one
of which may hold an auto-reconnect cookie, and two TPKT frames that were not I/O-channel Share Data. Dropping them leaves
the bulk history intact only because none carries a `PACKET_*` flag: the carve asserted that every
dropped Share Data PDU had `compressedType` with no flag bit, since fast-path and slow-path share
one history.

What the client advertised: the defaults as for `nscodec-surface-bits.bin`, plus Client Info
`COMPRESSION` with `CompressionTypeMask` 1 (64K).

| `compressionFlags` | Updates |
|---|---|
| `0x00` (no flags) | 139 |
| `0x21` (`PACKET_COMPRESSED`, 64K) | 33 |
| `0x61` (plus `PACKET_AT_FRONT`) | 5 |

### What it pins that an argument could not

- **The decompression matches the server's history.** `real_server_mppc.rs` asserts that the
  replay's framebuffer equals the live session's, hashed from the dump that was rendered and looked
  at (icons, taskbar, clock). A wrong copy-offset range or a history that skips a PDU changes it.
- **`ActivationResult::leftover` held nothing the history needs.** The capture starts after it, and
  the replay still matches the live framebuffer.

### What it cannot see

`PACKET_FLUSHED` (none arrived), MPPC-8K (the server compresses nothing at type 0), compressed
slow-path Share Data (none arrived), and NCRUSH / XCRUSH. The first three rest on the unit tests in
`mppc.rs`, `bulk.rs` and `session.rs`.

## `xcrush.bin`

152 fast-path PDUs, 57 299 bytes: one logon's desktop sent XCRUSH (RDP 6.1) bulk-compressed.
Captured 2026-10-15 for **#456** by `xcrush_compressed_updates_paint_the_desktop_on_the_real_vm`,
carved like `mppc-64k.bin` (the first 59 306 bytes, fast-path PDUs only; the carve asserted that
the dropped Share Data, three Save Session Info PDUs, carried no `PACKET_*` flag). The raw capture
was deleted. What the client advertised: the defaults plus Client Info `COMPRESSION` with
`CompressionTypeMask` 3.

| Fast-path `compressionFlags` | Updates | | XCRUSH (L1, L2) flags | Updates |
|---|---|---|---|---|
| `0x00` | 124 | | `(0x11, 0x21)` `L1_INNER \| L1_COMPRESSED`, level-2 64K | 20 |
| `0x23` (`PACKET_COMPRESSED`, RDP 6.1) | 34 | | `(0x12, 0x21)` `L1_INNER \| L1_NO_COMPRESSION` | 6 |
| | | | `(0x11, 0x00)` level-2 ran but passed through | 5 |
| | | | `(0x11, 0x61)` level-2 `PACKET_AT_FRONT` | 2 |
| | | | `(0x11, 0xe1)` level-2 `PACKET_FLUSHED \| PACKET_AT_FRONT` | 1 |

### What it pins that an argument could not

- **Both levels match the server.** `real_server_xcrush.rs` asserts that the replay equals the live
  framebuffer that was dumped and looked at; a copy with memmove semantics instead of byte by byte
  breaks it.

### What it cannot see

`L1_PACKET_AT_FRONT` and a level-2 `PACKET_FLUSHED` without `PACKET_COMPRESSED` never arrived, so
the replay is identical under either reading of each (measured: zero-filling on
`L1_PACKET_AT_FRONT`, and FreeRDP's compressed-only level-2 gate, both still pass). Those two
rules rest on the unit tests in `xcrush.rs` alone.

## `ncrush.bin`

164 fast-path PDUs, 52 214 bytes: one logon's desktop sent NCRUSH (RDP 6.0) bulk-compressed.
Captured 2026-10-15 for **#455** by `ncrush_compressed_updates_paint_the_desktop_on_the_real_vm`,
carved like `xcrush.bin` (the first 54 221 bytes, fast-path PDUs only; the dropped Share Data, three
Save Session Info PDUs, carried no `PACKET_*` flag). The raw capture was deleted. What the client
advertised: the defaults plus Client Info `COMPRESSION` with `CompressionTypeMask` 2.

| `compressionFlags` | Updates |
|---|---|
| `0x00` | 136 |
| `0x22` (`PACKET_COMPRESSED`, RDP 6.0) | 27 |
| `0x62` (plus `PACKET_AT_FRONT`: the history slid back by half) | 6 |

### What it pins that an argument could not

- **The slide and the offset cache match the server.** `real_server_ncrush.rs` asserts that the
  replay equals the live framebuffer that was dumped and looked at. Sliding from the wrong half,
  not caching a new offset, or not swapping a cache hit to the front each break it.

### What it cannot see

`PACKET_FLUSHED` (none arrived), and whether the slid-back history's second half is zeroed: no copy
after a slide reached it, so leaving it unzeroed replays identically. Both rest on the unit tests in
`ncrush.rs`.
