# Session loop & PDU dispatch

## What it is

The state machine that runs once the connection is active: bytes arrive, get framed
(fast-path or slow-path share PDUs), and are dispatched to whatever handles them —
bitmap updates, palette, pointer, dynamic-channel traffic, error info, server
disconnect. Its outputs are what the host actually consumes: frame updates, cursor
events, bytes to write, the signal that resize became possible, a refused shutdown, and
who logged on.

## Governing decisions

**None.** No ADR is about the session loop.

Adjacent but not governing: [ADR-0001](../../adr/0001-sans-io-state-machine-core.md)
makes it sans-IO (bytes in → outputs out);
[ADR-0010](../../adr/0010-frameupdate-dirty-rect-contract.md) decides the shape of
one of its outputs. Neither says what the loop dispatches or in what order.

## Design model

- **These outputs are the host's whole view of a live session**:
  `Frame(FrameUpdate)` · `Cursor(CursorEvent)` · `WriteBytes` · `Deactivated` ·
  `Reactivated` · `DisplayControlReady` ·
  `ShutdownDenied` · `SaveSessionInfo` · `KeyboardIndicators` · `PlaySound` · `ChannelData` ·
  `ChannelMessageDropped` · `DynamicChannelOpened` · `DynamicChannelData` ·
  `DynamicChannelClosed` (the live list is `SessionOutput` in `session.rs`). Anything the
  host cannot learn from one of these, it cannot learn at all
  — which is the argument #228 turned on: a `pduType2` that falls into the catch-all
  (**skipped, cursor unread** — the arm never decoded anything, whatever its comment said
  until #252) is not "handled quietly", it is **unlearnable**, and a host asking for a
  shutdown then looks exactly like a host that never asked.
- **The loop is fed, never reads.** It has no socket; the adapter feeds it bytes and
  drains the outputs, which is what makes a captured stream a complete test input.
- **`DisplayControlReady` is a capability gate, not an event of interest** — it is
  the point at which `request_resize` stops returning `ResizeError::NotReady`.
- **Reactivation is in-scope for this machine** (`Phase::Reactivating`): a resize
  round-trips through capability exchange while the session's caches survive,
  because caches belong to the connection rather than the share.
- **A reactivation replaces every server announcement the session acts on** (#438, #443): the
  share ID, the desktop size, and the `ServerAnnouncement`: the General set's
  `refreshRectSupport` / `suppressOutputSupport` and the Input set's `inputFlags`, which pick the
  input transport. One rule reads it on both legs (#450): `ServerAnnouncement::from_capabilities`,
  which the host calls at connect over `ActivationResult::server_capabilities` and the session
  calls at reactivation. A Demand Active without the set announces nothing: no Refresh Rect, no
  Suppress Output, `inputFlags` 0 (slow-path); a repeated set counts once, the first. The single
  constructor was the maintainer's call in #450's triage, over a free helper beside loose fields
  and over `SessionStateMachine::new` deriving them itself. FreeRDP re-derives its input settings from the Input set
  of every Demand Active it reads (`rdp_read_input_capability_set`, `libfreerdp/core/capabilities.c`).
  Measured on the WS2019 VM: `inputFlags` is `0x0375` at connect and after a Display Control
  resize reactivation (one run, #443's triage), so the transport switch is proven at unit level
  only (`reactivation_replaces_the_server_input_flags`).
- **Input the Server Announcement does not invite is dropped** (#449): `encode_input` drops, per
  event and against the current announcement, Unicode without `INPUT_FLAG_UNICODE`, MouseX
  without `INPUT_FLAG_MOUSEX` and a horizontal-wheel Mouse event without
  `INPUT_FLAG_MOUSE_HWHEEL`, with an `rdp_input_gate` record; the rest of the batch goes out. The
  host reads the announcement through `SessionStateMachine::server_announcement`, and
  `justrdp-tokio`'s `SessionEvent::Reactivated` carries the reactivation's, because the command
  runner holds the machine for the whole session. What the host does about a dropped event (say,
  scancodes in place of Unicode) is its own. `[MS-RDPBCGR]` 2.2.7.1.6 only says each flag
  *"indicates support"*; FreeRDP gates in its protocol layer all the same
  (`libfreerdp/core/input.c`: Unicode refused, MouseX and horizontal wheel skipped with a
  warning, against settings re-read from every Demand Active), as #438 refuses an unannounced
  Refresh Rect. Gating in the core with the host able to read the announcement was the
  maintainer's call in #449's triage, over surfacing only, gating only and wontfix; dropping
  rather than erroring and the event payload are derived. Relative mouse has no `InputEvent`
  yet. Measured: the WS2019 VM announces `0x0375`, all three flags, so nothing the VM suite
  sends is dropped.
- **One bulk decompression context per connection, fed before anything can skip a PDU** (#454).
  `[MS-RDPBCGR]` 3.1.8.1 keeps one history per direction; FreeRDP holds one `rdpBulk` and both
  `fastpath.c` and `rdp.c` decompress through it. So `Bulk` sits in the session, and every
  fast-path update and every Share Data PDU goes through it first, including those a Deactivation
  then drops, because their bytes are history the next copy may reach into. Fast-path passes
  every update's `compressionFlags`; slow-path decompresses `compressedLength - 18` bytes. Without
  `PACKET_COMPRESSED` the payload is plain whatever the type nibble says (#253), and
  `PACKET_FLUSHED` / `PACKET_AT_FRONT` still reach an existing history (3.1.8.3; FreeRDP's slow
  path skips them, the spec does not). MPPC 8K and 64K decompress; any other type is
  `BulkError::UnsupportedType`, and a type change within a connection is `TypeChanged`. The
  connect machine refuses a compressed finalization reply: the history lives in the session.
  No static channel is decompressed, because `VCCAPS_COMPR_SC` is never advertised.
  Proof follows ADR-0003's order with the oracle tier empty (`ironrdp-graphics` has no MPPC, and
  `ironrdp-bulk` would be a new ironrdp crate against ADR-0011): `[MS-RDPBCGR]` 3.1.8.2.3's
  example hand-encoded from the 3.1.8.4 bit tables at both levels, and a WS2019 capture
  (`tests/fixtures/session/mppc-64k.bin`) whose replay equals the live, looked-at framebuffer.
  Measured on that VM (FreeRDP `/dump:record`, #427): the server compresses fast-path output with
  exactly the advertised type, and at type 0 (8K) compresses nothing, so MPPC-8K has no
  real-server proof.
- **XCRUSH is the third type the bulk context dispatches** (#456): `[MS-RDPEGDI]` 3.1.8.2, a
  level-1 match decoder over a 2,000,000-byte history chained after its own MPPC 64K (level-2,
  separate from a type-1 context). Per packet: the outer `PACKET_FLUSHED` zeroes level 1, then
  level-2 runs over everything after the two flag bytes when `L1_INNER_COMPRESSION` is set, then
  level-1 copies matches by absolute history offset (byte by byte, so a match may read what the
  same packet just wrote) between literals. An outer `PACKET_FLUSHED` on an uncompressed payload
  reaches level 1 as well (`Xcrush::flush`). Two readings are derived, not decided, and fall to a
  real-server capture that tells them apart:
  - **`L1_PACKET_AT_FRONT` resets the offset and keeps the history.** The spec says both "a
    simple reset of the history offset" (3.1.8.2.2.2's prose) and "reinitialized (by filling it
    with zeros)" (its flag tables). FreeRDP resets the offset only and interoperates with
    Windows with XCRUSH as its default.
  - **`Level2ComprFlags` reach level-2 whenever `L1_INNER_COMPRESSION` is set,** a
    `PACKET_FLUSHED` without `PACKET_COMPRESSED` included (3.1.8.2.3). FreeRDP calls its level-2
    only when `PACKET_COMPRESSED` is set.
  Measured on the WS2019 VM (`tests/fixtures/session/xcrush.bin`): 34 type-3 updates, their
  (L1, L2) flags `(0x11, 0x21)` ×20, `(0x12, 0x21)` ×6, `(0x11, 0x00)` ×5, `(0x11, 0x61)` ×2,
  `(0x11, 0xe1)` ×1. No `L1_PACKET_AT_FRONT` and no level-2 flush without compression arrived, so
  the capture replays identically under either reading of both. Only the unit tests in
  `xcrush.rs` hold them. `CompressionTypeMask` is a value: `advertise.rs` honours it through
  `HONOURED_COMPRESSION_TYPES`, now 0 to 3.
- **NCRUSH completes the set** (#455): `[MS-RDPEGDI]` 3.1.8.1, Huffman-coded literals, end of
  stream, copy-offsets and lengths of match, read least significant bit first, over a 65,536-byte
  history with a four-entry offset cache. The tables are transcribed from the spec (Tables 1-6),
  and a test regenerates both codebooks from their lengths by the canonical Huffman algorithm the
  spec names: Table 2 and Table 5 are the canonical codes with their bits reversed, all 293 and
  32. The offset-cache rules are drawn only in the spec's flowcharts, so FreeRDP's `ncrush.c`
  gives them: a new copy-offset enters at slot 0 and shifts the rest, and a hit swaps its slot
  with slot 0. `PACKET_AT_FRONT` here slides the history back by half (3.1.8.1.3), unlike MPPC's
  and XCRUSH's offset reset. A slide with no more than half a history written is an error, as
  FreeRDP's `-1002`. Derived, not decided: `PACKET_FLUSHED` absorbs `PACKET_AT_FRONT` (FreeRDP
  slides then flushes, reaching the same state when its slide succeeds), and a slide keeps the
  offset cache (FreeRDP's behaviour; 3.1.8.1.1 empties it on (re)initialisation only).
  Measured on the WS2019 VM (`tests/fixtures/session/ncrush.bin`): 27 `0x22` and 6 `0x62`
  updates, so the server did slide. The replay catches a wrong slide source and a wrong cache
  rule, but not an unzeroed second half, which no copy after a slide reached. No
  `PACKET_FLUSHED` arrived.
- **A Deactivation stops input and the share-bound requests, not channels** (#442). `[MS-RDPBCGR]`
  3.2.5.5.1: after Deactivate All *"the client MUST disable its graphics and input protocol
  handlers"*. From the moment the session leaves the active phase (a Deactivate All, or a Demand
  Active that arrives while active) until the reactivation's Font Map, `encode_input` returns
  nothing, Shutdown Request returns nothing, and Refresh Rect / Suppress / Resume are refused with
  `OutputControlError::NotActive`; a refused suppress or resume leaves the remembered one alone.
  Input is dropped, not queued: the desktop it would reach may have a new size. Static and dynamic
  channel sends and the Display Control resize go on, being neither input nor share-bound. The host
  hears `Deactivated` once and `Reactivated` once per Deactivation, the second right after the
  full-screen re-emit; re-sending the keyboard Synchronize then is the host's. These were the
  maintainer's calls in #442's triage (drop rather than queue, refuse rather than send, the two
  outputs); the window's edges are derived. FreeRDP's input module does not gate on this
  (`libfreerdp/core/input.c` at `c722db9c` checks only that the session has not ended). Measured:
  a Shift tap sent on `Deactivated` during a Display Control resize is dropped
  (`display_control_resize_against_real_vm`).
- **Surface commands paint like bitmap updates** (#150): each Set Surface Bits command decodes
  into the framebuffer and emits one `Frame`, at the bitmap's own size (2.2.9.2.1 says
  `destRight`/`destBottom` SHOULD be ignored). Stream Surface Bits, which is never invited, is
  applied the same way. A codec ID the Confirm Active never
  assigned is skipped with an `rdp_interop` record (ADR-0009 §2); an NSCodec stream that does not
  decode is fatal, as a slow-path bitmap that does not decompress is. Frame Markers are decoded and
  dropped, which is why the connect layer refuses `SURFCMDS_FRAME_MARKER`; acknowledging them would
  need the Frame Acknowledge set, refused too. A command whose `cmdFlags` bit was not advertised is
  still applied, with an `rdp_surface_bits` record (ADR-0009 §3(b)).
- **A fast-path fragment sequence is FIRST (NEXT...) LAST, and any other order ends the
  session** (#368). `[MS-RDPBCGR]` 3.2.5.9.3.1 says a deviation "SHOULD trigger a disconnect", and
  FreeRDP fails on one. A NEXT or LAST without a FIRST, a continuation with another update code,
  and since #368 a FIRST or SINGLE arriving while a sequence is open are all the same
  `TS_FP_UPDATE.fragmentation` error. Until then the FIRST case replaced the open buffer
  silently and the SINGLE case left it behind for the next continuation to extend.
- **One graphics update buys at most `PAINT_BUDGET_FRAMEBUFFERS` desktops of decoding, 8**
  (#367, #494). Each paint is charged before it is made:
  - a bitmap update's rectangles, a Surface Commands update's surface bits and an Orders update's
    paints are charged their decoded size, not their clipped one;
  - past the budget, the rest of a bitmap or Surface Commands update is skipped with an
    `rdp_paint_budget` warning; an Orders update pauses between its orders instead (#498), and
    skips, with the same warning, only an order that alone costs more than the budget;
  - the session continues, on ADR-0009 row 3's ground: a resource ceiling that is ours, against
    well-formed traffic.
- **A call pauses once it has bought one update's budget** (#496, the maintainer's call,
  2026-10-20). `process_bytes` starts no further PDU, fast-path section or drawing order (#498)
  once the call's paint spending reaches `paint_budget()`, and keeps the rest:
  - **What it keeps:** the inbox, the next section of its first PDU, and the orders an Orders
    Update has not reached (`Orders` keeps those; a resumed call starts with them);
  - **How it resumes:** `has_pending_input()` says so, and `process_bytes(&[])` continues.
    Sections already handled are skipped, never decompressed twice;
  - **Progress is guaranteed:** a call always handles its first PDU, and a resumed call its
    first remaining section, even with a budget of nothing (an empty desktop). One call costs at
    most two updates' budgets. The one-byte OpaqueRect burst below, at 1280 × 800
    (`--release`), resumes over 2,520 calls:
    - **Before #506:** a median call of 112 ms and one call of 800 ms, and 296 s for the whole
      PDU. When #496 measured it, a call was 149 ms and the PDU 286 s;
    - **After #506**, whose fills paint in place: a median call of 0.72 to 0.86 ms, at most
      1.5 ms, and 1.8 to 2.2 s for the whole PDU, over three runs.
- **Work that paints nothing is charged to the call as painted bytes are** (#507, the
  maintainer's call, 2026-10-20). Only to the call's pause, never to an update's budget:
  - **What is charged:** a fast-path section's or a Share Data PDU's decompressed bytes, when it
    was sent compressed; a pointer's RGBA bytes, decoded from a Color or New Pointer or re-emitted
    from the cursor cache by a Cached Pointer;
  - **Why it never skips:** decompression keeps the bulk history the server's compressor mirrors,
    so a skipped section would desynchronise it;
  - **What it costs legitimate traffic:** a compressed bitmap update is charged its decompressed
    bytes and its paint, so a call of them pauses up to twice as early;
  - **What stays uncharged:** a section sent uncompressed, a slow-path frame that paints
    nothing, and drdynvc reassembly. Each copies at most the bytes the call was handed; that is
    derived, not measured;
  - **The Graphics Pipeline charges its own ZGFX decompression** (#509,
    [Graphics Pipeline](egfx-graphics-pipeline.md)).
- **Why it is charged.** #507 set the rule: above about 300 ms a call, charge it. Measured
  uncharged (`--release`), the cost does not depend on the desktop size. A 32 KB PDU fell under
  the line, and the 49 KB a call can be handed crossed it:
  - **MPPC 64K sections of about 7 bytes that each decompress to the 64 KB history**,
    Synchronize updates otherwise: 241 to 273 ms a 32 KB PDU, and 367 to 380 ms for the 49 KB a
    call can be handed;
  - **pointers:** 96 × 96 is the largest pointer accepted. A Large Pointer is never advertised,
    and one sent anyway is skipped. 1,213 compressed 96 × 96 New Pointers in 32 KB took 104 to 109 ms. 6,552
    uncompressed Cached Pointers of a 96 × 96 shape took 70 to 77 ms, and that one call's
    outputs held 236 MB of cursor images;
  - **slow path:** 840 Share Data PDUs that each decompress to 64 KB took 68 to 70 ms.

  Charged, at 1280 × 800, the worst call over three runs was 83 ms for the MPPC sections,
  110 ms for the New Pointers, 18 ms for the Cached Pointers and 48 ms on the slow path. NCRUSH
  and XCRUSH are charged by the same rule, but their worst case is unmeasured. Both are Huffman
  coded, so a worst-case input cannot be written by hand as MPPC's was, and no compressor exists
  here to build one.
- **Why it pauses rather than skips.** An update's budget is issued afresh per section, so
  without the pause one call was bounded only by the bytes it was handed (#494, `--release`,
  1280 × 800):
  - NSCodec, desktop-sized empty planes: one 32 KB PDU of 728 one-command sections cost 6.3 s;
  - orders: a 32 KB PDU of 2,520 sections of eight one-byte repeated OpaqueRects cost 361 s;
  - a call can be handed about 49 KB of complete PDUs, so up to about 540 s, with the adapter's
    cancellation, input and timers stalled meanwhile.

  Skipping past a per-call budget would lose paints of a legitimate burst; pausing keeps every
  pixel and only moves the work to the next call.
- **A Graphics Pipeline message pauses between its PDUs too** ([Graphics Pipeline](egfx-graphics-pipeline.md)).
  - **Why it needs its own point.** One EGFX message of tiny frames cost 0.62 s at 60 KB and
    16 s at 1 MiB (about 64 s at the 4 MiB DVC cap), measured for #496.
  - **The allowance.** The session hands the dynamic-channel manager what the call may still
    paint, and adds what the processors painted to the call.
  - **Ordering.** A processor stops only once the call's whole budget is spent, so the call
    starts no later PDU either: what follows the message, on any channel or transport, waits. The
    next call resumes the message first, and a resumed message is that call's first unit of
    work.
- **The value is headroom over the largest real update.** The values below are in desktops.
  - The 2 came from #367: the largest Surface Commands update in the #150 capture (WS2019)
    decoded 1 desktop.
  - That capture held no drawing orders. On WS2008 R2, Server Manager maximised sends an Orders
    update of 4.16, a double-buffered window paint: an offscreen bitmap the size of the desktop
    made (1.00), cleared (1.00) and filled (1.05), then copied to the screen (1.01), with 0.10 in
    smaller orders. 7 of the
    session's 64 Orders updates spent more than 2.
  - At 2 the session skipped 417 orders, and the screen stayed wrong. 8 is the same ratio over
    the measurement as #367's 2 over 1 (the maintainer's call, 2026-10-19).
  - The server sends one Orders section per PDU, so its PDUs spend the same.
- **Static-channel traffic goes three ways** (#307): `drdynvc` to the dynamic-channel
  manager, a granted host channel to its reassembler and out as `ChannelData`, and a channel
  ID that was never granted is skipped with an `rdp_svc` record. Inside `drdynvc`, a channel
  the host registered surfaces as the three `DynamicChannel*` outputs (#385, ADR-0018). See
  [Virtual channels](virtual-channels.md) for the reassembly rules and whose call each was.
- **The host can ask for a redraw or a pause; the server's General set says whether it may**
  (#438). Refresh Rect and Suppress Output are client-to-server only. `refreshRectSupport` and
  `suppressOutputSupport` are server-only fields (2.2.7.1.1; the client's own copy is ignored), so
  the gate is the server's Demand Active, carried in `SessionConfig` and replaced at every
  reactivation. Areas come in `FrameUpdate` coordinates and go out as inclusive rectangles; resume
  covers the whole current desktop. When to send either is the host's.
- **The machine remembers the last Suppress Output it sent, and a repeated suppress sends nothing**
  (#438, the maintainer's call). The spec makes `allowDisplayUpdates` a value, but this server
  treats a suppress that arrives while output is already suppressed as a resume (see Reference
  behaviour), so a host that suppresses twice would otherwise turn output back on. Resume always
  goes out: it is idempotent here, and suppress then resume is the full-refresh workaround the
  spec gives for RDP 8.0/8.1 servers whose Refresh Rect is broken (product note on 2.2.11.2).
  The remembered state is kept across a reactivation. On this server a resize cannot reactivate a
  suppressed session (see Reference behaviour); whether another server-initiated reactivation ends
  suppression is unmeasured.

## Code

- `justrdp/src/session.rs` — `SessionStateMachine`, `SessionConfig`, `ServerAnnouncement`, `SessionOutput`,
  `SessionError`, `Phase`, `ResizeError`, `cursor_event_for`, `request_shutdown`,
  `apply_surface_bits` (#150), `PAINT_BUDGET_FRAMEBUFFERS`, `apply_bitmap_update`,
  `note_paint_budget` (#367), `on_fastpath_pdu`, `on_data_pdu`, `on_pointer` and
  `set_cursor_shape`, which charge work that paints nothing (#507)
- `justrdp/src/disconnect.rs` — `classify`, `DisconnectClass`, `DisconnectReason`,
  `ServerDisconnectCause`
- `justrdp-pdu/src/fastpath.rs` — `is_fastpath`, `frame_len`, `decode_updates`, `FastPathUpdate`
- `justrdp/src/bulk.rs` — `Bulk`, `BulkError`, `PACKET_COMPR_TYPE_8K`, `PACKET_COMPR_TYPE_64K`,
  `PACKET_COMPR_TYPE_RDP6` (#455), `PACKET_COMPR_TYPE_RDP61` (#456)
  (#454)
- `justrdp-codecs/src/mppc.rs` — `Mppc`, `MppcLevel`, `MppcError` (#454)
- `justrdp-codecs/src/xcrush.rs` — `Xcrush`, `XcrushError`, `HISTORY_SIZE` (#456)
- `justrdp-codecs/src/ncrush.rs` — `Ncrush`, `NcrushError` (#455)
- `justrdp/src/advertise.rs` — `HONOURED_COMPRESSION_TYPES` (#456)
- `justrdp-pdu/src/surface_commands.rs` — `decode_all`, `SurfaceCommand`, `SurfaceBits`,
  `BitmapDataEx`, `FrameMarker` (#150)
- `justrdp-pdu/src/share.rs`, `justrdp-pdu/src/update.rs` — `ShareDataHeader`,
  `BitmapUpdate`, `BitmapData`, `PaletteUpdate`
- `justrdp-pdu/src/errinfo.rs` — `ErrorInfo`, `decode_set_error_info`
- `justrdp-pdu/src/share.rs` — `PDU_TYPE2_SHUTDOWN_REQUEST`, `PDU_TYPE2_SHUTDOWN_DENIED`,
  `PDU_TYPE2_SAVE_SESSION_INFO`, `PDU_TYPE2_SET_KEYBOARD_INDICATORS`, `PDU_TYPE2_PLAY_SOUND`
- `justrdp-pdu/src/session_info.rs` — `SaveSessionInfo`
- `justrdp-pdu/src/sound.rs` — `PlaySound` (#354)
- `justrdp-pdu/src/output_control.rs` — `InclusiveRect`, `encode_refresh_rect`,
  `encode_suppress_output` (#438)
- `justrdp/src/session.rs` — `request_refresh_rect`, `request_suppress_output`,
  `request_resume_output`, `OutputControlError` (#438)

## Reference behaviour

**Play Sound: this VM never sends it, by design** (#354, 2026-10-01). `[MS-RDPBCGR]` product
behaviour note <45> (on 3.2.5.9.4.1): from Windows 7 / Server 2008 R2 on, *"all system and
application-generated beeps are dispatched … by using the RDP audio redirection protocol
[MS-RDPEA]. If a client does not support RDP audio redirection, it will not receive any beep
notifications."* Measured against the WS2019 VM with the default Sound set (`SOUND_FLAG_BEEPS`)
and no `rdpsnd`: `[console]::beep(800,300)`, a console BEL, `SystemSounds.Beep` and
`SystemSounds.Asterisk`, with the script's run confirmed on the framebuffer, gave **0 Play Sound
PDUs in 3 runs** (`play_sound_probe_against_real_vm`). The decoder and `SessionOutput::PlaySound`
are proven by unit tests only; a server that sends the PDU (pre-Windows 7, or a non-Windows one
such as FreeRDP's, whose `update_send_play_sound` exists) is what they are for. A Windows beep
reaches a client through audio output (#11). Keeping `SOUND_FLAG_BEEPS` advertised on that
evidence was the maintainer's call, recorded in ADR-0016.

**Set Keyboard IME Status: skipped on purpose — the maintainer's call** (#439, 2026-10-13).
`pduType2` 0x2D stays in the catch-all, read by nothing. What it was decided on: `[MS-RDPBCGR]`
product behaviour note <35> (on 2.2.8.2.2), *"Only Microsoft RDP 5.0, 5.1, 5.2, 6.0, 6.1, 7.0, and
7.1 servers send the Set Keyboard IME Status PDU"*, so by the spec neither test VM (RDP 10.x)
sends one; 3.2.5.8.2.2, *"Non-IME aware clients MAY ignore this PDU"*; its stated purpose, the
input to *"a Fujitsu Oyayubi-specific IME control function"*; and that nothing the client
advertises invites it, unlike Play Sound. FreeRDP decodes it into a callback, active state only; IronRDP keeps the raw bytes. The
options shown were this, decoding it to a session output proven by unit tests alone, and that plus
standing up a server that sends one. Nothing was measured: a host on an RDP 7.1-or-older server is
what would reopen it.

**Shutdown Request: this VM refuses it, even on a clean desktop** (#198 probed, #228 built).
`PDUTYPE2_SHUTDOWN_REQUEST` (36) goes out and `PDUTYPE2_SHUTDOWN_DENIED` (37) comes back. Both
are bodyless: the Share Data header *is* the PDU. The refusal comes with no open application
and no unsaved work, and the session stays up for the full 30 s observation. So the PDU is not
a way to end a session; anything that needs the session *gone* signs out from inside it (see
[Verification harness](verification-harness.md) for `shutdown /l /f`). **FreeRDP's client never
sends one**: only its server side names the request, and `rdp_recv_server_shutdown_denied_pdu`
is a bare `return TRUE`. IronRDP's `ActiveStage::graceful_shutdown` is therefore the only
send-side reference. **The MCS Disconnect Provider Ultimatum that follows a grant is
deliberately not written**: this VM never grants, so it would be machinery with no server to
prove it against.

**Suppress Output and Refresh Rect: honoured, and a repeated suppress resumes** (#438,
2026-10-13, WS2019, legacy NSCodec and EGFX sessions). The server announces both in its General
set. With output suppressed a Start click draws nothing for 25 s. A second
`SUPPRESS_DISPLAY_UPDATES` turns output back on with a full repaint (274 frames, the count a resume
brings), and a third suppresses again; a resume while output runs changes nothing. A resume
repaints the whole desktop, in both session kinds. A Refresh Rect for 0,0–255,255 brings back
exactly the sixteen 64×64 tiles that cover it, in both session kinds, and it does so while output
is suppressed too (two runs). A Display Control resize sent while output is suppressed is not
carried out until output resumes: the desktop changed size 260 frames after the resume, and
until then nothing arrived, not even the frame the machine emits when a reactivation completes.
Measured with throwaway probes and by mutating the adapter's command handler
(`suppress_resume_and_refresh_rect_drive_*`).

## Cross-cutting invariants

- [A decoded field with no reader is an unstated decision](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md)
  — `ShareDataHeader.compressed_type` stated "must be 0 here" with no reader while `dvc.rs`
  rejected the identical class; #253 closed it in the decoder both this loop and the connect
  leg call. `stream_id` is the same header's remaining instance.
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) —
  every byte this loop dispatches came from the network. The Surface Bits path is driven whole by
  `surface_bits_through_the_session_never_panic` and the `session_surface_bits` fuzz target
  (#369), whose generators shape NSCodec planes to their decoded sizes: 76% of cases reach a
  frame, against ~130 in 300 000 for undirected bytes, and a panic injected after the NSCodec
  decode or before the blit turns the property red.
- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md)
  — a `pduType2` a capability we send invites needs its own arm, not the catch-all: Play Sound
  for the default Sound set (#354).
- [The frame path carries no owned pixels](../invariant/frame-path-carries-no-owned-pixels.md)
  — `SessionOutput::Frame` is a rectangle; the pixels stay in the framebuffer.

## Blast radius

- [Framebuffer & frame delivery](framebuffer-frame-delivery.md) — every bitmap
  update lands there, and the frame-sink contract is shared.
- [Bitmap codecs](bitmap-codecs.md) — slow-path bitmap updates route here by codec.
- [Drawing orders](drawing-orders.md) — Orders Updates on both transports go to
  `Orders::apply`, charged to the call and pausing between orders, and a reactivation resets
  their history.
- [EGFX graphics pipeline](egfx-graphics-pipeline.md) — EGFX traffic arrives as DVC
  data through this loop.
- [Virtual channels](virtual-channels.md) — `drdynvc` framing and display control
  are dispatched here.
- [Pointer & cursor](pointer-cursor.md) — pointer updates become `CursorEvent`.
- [Capability exchange & activation](capability-exchange-activation.md) — supplies
  `share_id`, the capability sets, and the leftover bytes this loop must consume
  **before** its first socket read.
- [Adapter drive loop](adapter-drive-loop.md) — owns the select loop, cancellation
  and the ordering between input writes and output drains.
- [Logon & Save Session Info](logon-session-info.md) — the sixth output, and the only
  `pduType2` this loop dispatches that the connect leg dispatches too.
- [Input & platform scancode tables](input-scancodes.md) — `KeyboardIndicators`, the
  server's lock state in the Synchronize event's bits; session leg only, by the maintainer's call.

## Known holes / open

- ~~**Static channel 1004 traffic is dropped**, with no record of what is being
  dropped or when that stops being acceptable.~~ **Closed in #307.**
- Drawing orders dispatch through here on both transports since #460, the bitmap cache path
  alone ([drawing orders](drawing-orders.md)); every other order is unbuilt (epic #22).
- Auto-reconnect on transient disconnect is unbuilt: `classify`
  distinguishes the cases, and nothing acts on the distinction. When to reconnect is the
  host's reconnect strategy; the cookie it needs shipped in #306.
- Status Info has no arm: its flag stays refused and the PDU belongs to server redirection (#24;
  [Capability exchange & activation](capability-exchange-activation.md)). Refresh Rect and Suppress
  Output are sent since #438.
  Set Keyboard IME Status is skipped on purpose (Reference behaviour).
