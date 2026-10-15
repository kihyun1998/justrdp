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
  only (`reactivation_replaces_the_server_input_flags`). The other Input-set bits (Unicode,
  MouseX, horizontal wheel) are the host's to honour and stay unread by the core.
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
- `justrdp-pdu/src/fastpath.rs` — `is_fastpath`, `frame_len`, `decode_updates`
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
- Drawing orders (epic #22), clipboard (#10), audio (#11/#12), device redirection
  (#13) all dispatch through here and none exist — the dispatch table is a small
  fraction of the protocol's surface.
- Auto-reconnect on transient disconnect is unbuilt: `classify`
  distinguishes the cases, and nothing acts on the distinction. When to reconnect is the
  host's reconnect strategy; the cookie it needs shipped in #306.
- Status Info has no arm: its flag stays refused and the PDU belongs to server redirection (#24;
  [Capability exchange & activation](capability-exchange-activation.md)). Refresh Rect and Suppress
  Output are sent since #438.
  Set Keyboard IME Status is skipped on purpose (Reference behaviour).
