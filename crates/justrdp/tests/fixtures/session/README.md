# `session/` — server bytes after session-active, replayed through the session machine

Server-to-client only, so no credential crosses into these files. Captured from the real VM
(`docs/agents/thegraph.md`'s third source; memory `test_environment`), one WS2022 box on one
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
