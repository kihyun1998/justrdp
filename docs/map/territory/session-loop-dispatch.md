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
- **One graphics update buys at most `PAINT_BUDGET_FRAMEBUFFERS` desktops of decoding** (#367).
  A bitmap update's rectangles and a Surface Commands update's surface bits are charged their
  decoded size, not their clipped one, before they decode; past the budget the rest of the update
  is skipped with an `rdp_paint_budget` warning and the session continues, on ADR-0009 row 3's
  ground (a resource ceiling that is ours, against well-formed traffic). The budget is per update,
  so it bounds how long one `process_bytes` holds the adapter's loop, and the host's cancellation
  with it; it does not bound what a stream of updates can cost, which no budget can without
  refusing real RLE and NSCodec traffic. The real server's largest update decodes exactly one
  desktop (4 of the 20 Surface Commands updates in the #150 capture), so 2 leaves it untouched.
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
  `note_paint_budget` (#367)
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
  `Orders::apply` within the update's paint budget, and a reactivation resets their history.
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
