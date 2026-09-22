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

- **Eight outputs, and the host's whole view of a live session is these**:
  `Frame(FrameUpdate)` · `Cursor(CursorEvent)` · `WriteBytes` · `DisplayControlReady` ·
  `ShutdownDenied` · `SaveSessionInfo` · `KeyboardIndicators` · `ChannelData`. Anything the host cannot learn from one of these,
  it cannot learn at all
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
- **Static-channel traffic goes three ways** (#307): `drdynvc` to the dynamic-channel
  manager, a granted host channel to its reassembler and out as `ChannelData`, and a channel
  ID that was never granted is skipped with an `rdp_svc` record. See
  [Virtual channels](virtual-channels.md) for the reassembly rules and whose call each was.

## Code

- `justrdp/src/session.rs` — `SessionStateMachine`, `SessionConfig`, `SessionOutput`,
  `SessionError`, `Phase`, `ResizeError`, `cursor_event_for`, `request_shutdown`
- `justrdp/src/disconnect.rs` — `classify`, `DisconnectClass`, `DisconnectReason`,
  `ServerDisconnectCause`
- `justrdp-pdu/src/fastpath.rs` — `is_fastpath`, `frame_len`, `decode_updates`
- `justrdp-pdu/src/share.rs`, `justrdp-pdu/src/update.rs` — `ShareDataHeader`,
  `BitmapUpdate`, `BitmapData`, `PaletteUpdate`
- `justrdp-pdu/src/errinfo.rs` — `ErrorInfo`, `decode_set_error_info`
- `justrdp-pdu/src/share.rs` — `PDU_TYPE2_SHUTDOWN_REQUEST`, `PDU_TYPE2_SHUTDOWN_DENIED`,
  `PDU_TYPE2_SAVE_SESSION_INFO`, `PDU_TYPE2_SET_KEYBOARD_INDICATORS`
- `justrdp-pdu/src/session_info.rs` — `SaveSessionInfo`

## Reference behaviour

**None.** No verified external-fact store.

## Cross-cutting invariants

- [A decoded field with no reader is an unstated decision](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md)
  — `ShareDataHeader.compressed_type` stated "must be 0 here" with no reader while `dvc.rs`
  rejected the identical class; #253 closed it in the decoder both this loop and the connect
  leg call. `stream_id` is the same header's remaining instance.
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) —
  every byte this loop dispatches came from the network.
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
