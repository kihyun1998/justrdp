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
  `Frame(FrameUpdate)` · `Cursor(CursorEvent)` · `WriteBytes` · `DisplayControlReady` ·
  `ShutdownDenied` · `SaveSessionInfo` · `KeyboardIndicators` · `PlaySound` · `ChannelData` ·
  `ChannelMessageDropped` (the live list is `SessionOutput` in `session.rs`). Anything the
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
- **Surface commands paint like bitmap updates** (#150): each Set Surface Bits command decodes
  into the framebuffer and emits one `Frame`, at the bitmap's own size (2.2.9.2.1 says
  `destRight`/`destBottom` SHOULD be ignored). Stream Surface Bits, which is never invited, is
  applied the same way. A codec ID the Confirm Active never
  assigned is skipped with an `rdp_interop` record (ADR-0009 §2); an NSCodec stream that does not
  decode is fatal, as a slow-path bitmap that does not decompress is. Frame Markers are decoded and
  dropped, which is why the connect layer refuses `SURFCMDS_FRAME_MARKER`; acknowledging them would
  need the Frame Acknowledge set, refused too. A command whose `cmdFlags` bit was not advertised is
  still applied, with an `rdp_surface_bits` record (ADR-0009 §3(b)).
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
  ID that was never granted is skipped with an `rdp_svc` record. See
  [Virtual channels](virtual-channels.md) for the reassembly rules and whose call each was.

## Code

- `justrdp/src/session.rs` — `SessionStateMachine`, `SessionConfig`, `SessionOutput`,
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

## Reference behaviour

**Play Sound: this VM never sends it, by design** (#354, 2026-10-01). `[MS-RDPBCGR]` product
behaviour note <45> (on 3.2.5.9.4.1): from Windows 7 / Server 2008 R2 on, *"all system and
application-generated beeps are dispatched … by using the RDP audio redirection protocol
[MS-RDPEA]. If a client does not support RDP audio redirection, it will not receive any beep
notifications."* Measured against the WS2022 VM with the default Sound set (`SOUND_FLAG_BEEPS`)
and no `rdpsnd`: `[console]::beep(800,300)`, a console BEL, `SystemSounds.Beep` and
`SystemSounds.Asterisk`, with the script's run confirmed on the framebuffer, gave **0 Play Sound
PDUs in 3 runs** (`play_sound_probe_against_real_vm`). The decoder and `SessionOutput::PlaySound`
are proven by unit tests only; a server that sends the PDU (pre-Windows 7, or a non-Windows one
such as FreeRDP's, whose `update_send_play_sound` exists) is what they are for. A Windows beep
reaches a client through audio output (#11). Keeping `SOUND_FLAG_BEEPS` advertised on that
evidence was the maintainer's call, recorded in ADR-0016.

## Cross-cutting invariants

- [A decoded field with no reader is an unstated decision](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md)
  — `ShareDataHeader.compressed_type` stated "must be 0 here" with no reader while `dvc.rs`
  rejected the identical class; #253 closed it in the decoder both this loop and the connect
  leg call. `stream_id` is the same header's remaining instance.
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) —
  every byte this loop dispatches came from the network.
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
- Auto-reconnect on transient disconnect (plan.md §23) is unbuilt: `classify`
  distinguishes the cases, and nothing acts on the distinction.
