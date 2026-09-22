# Input & platform scancode tables

## What it is

Turning host input into RDP input PDUs: mouse movement and buttons, and — the hard
half — keyboard events, which RDP expresses as **PC/AT scancodes with an extended
flag**, not as characters or platform key codes. So the library carries three
translation tables (Windows virtual-key, macOS keycode, Linux evdev), the multi-event
Pause sequence, and the toggle-key state a session must synchronise on — sent as the
Synchronize event, and heard back as the server's Set Keyboard Indicators PDU (0x29).

**This is a "nobody touches it, and it breaks silently" area.** A wrong row shows up
as *one key that does nothing* on *one platform*, and neither the test suite nor the
VM suite can see it.

## Governing decisions

**None.** No ADR is about input.

Adjacent but not governing: [ADR-0001](../../adr/0001-sans-io-state-machine-core.md)
puts the mapping in the core (it is a pure function, no I/O), and
[ADR-0002](../../adr/0002-dependency-boundary.md) explains why no platform keyboard
crate is pulled in — neither decides the mapping itself.

## Design model

- **The tables are the contract.** `scancode_from_windows_vk`,
  `scancode_from_macos_keycode` and `scancode_from_linux_evdev` are total functions
  returning `Option<Scancode>`; an unmapped key is `None`, never a guess.
- **Extended keys are a flag, not a different code** — the same scancode with
  `extended` set is a different physical key, and dropping the flag produces a key
  that "works but does the wrong thing".
- **Pause is not a key.** `pause_sequence()` returns four events; anything modelling
  it as one is wrong by construction.
- **Toggle state is synchronised, not inferred.** `keyboard_toggle_flags()` is
  `cfg`-split per platform in the adapter — it reads real OS state, which is why it
  lives outside the core.
- **The server's lock state comes back as data, not as action** (#305). Set Keyboard
  Indicators decodes to `KeyboardIndicators` and surfaces as
  `SessionOutput::KeyboardIndicators` / `SessionEvent::KeyboardIndicators`; driving an LED,
  or showing a lock where the OS has none, is the host's. `ledFlags` stays a raw `u16`
  with the four `SYNC_*` accessors, because 2.2.8.2.1.1 says its bits are the Synchronize
  event's, and an undefined bit is passed through rather than dropped.
- **`unitId` is not decoded.** 2.2.8.2.1.1: *"This field SHOULD be ignored by the client"*.
  That is way #3 of [a decoded field with no reader](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md),
  taken on the spec's word. FreeRDP warns on a non-zero one and IronRDP never parses the
  body; neither acts on it. A truncated body (under 4 bytes) is a typed error, as in FreeRDP.
  **Not logged either — the maintainer's call** (#305): the plan first shown logged a
  non-zero `unitId` as FreeRDP does, which would have needed a field whose only reader is
  that record; the maintainer kept the skip. No real `unitId` has ever been observed.
- **Session leg only — the maintainer's call, not a derivation** (#305, 2026-09-22). The
  connect leg's finalization catch-all still skips 0x29. The alternative shown was carrying
  it across in `ActivationResult` the way #304 carries Save Session Info. What it was decided
  on: FreeRDP's handler returns `FALSE` below `CONNECTION_STATE_ACTIVE` and its finalization
  states route data PDUs into it, so a pre-Font-Map 0x29 fails FreeRDP's connect, which
  suggests servers do not send one. That was prior art, not a measurement: the VM has never
  sent 0x29 on either leg (`## Reference behaviour`), so the decision is **untested** against
  a server that does.

## Code

- `justrdp/src/input.rs` — `Scancode`, `scancode_from_windows_vk`,
  `scancode_from_macos_keycode`, `scancode_from_linux_evdev`, `pause_sequence`
- `justrdp-pdu/src/input.rs` — `InputEvent`, `encode_fastpath_input`,
  `encode_slowpath_input_body`, `KeyboardIndicators`, `SYNC_*`
- `justrdp-pdu/src/share.rs` — `PDU_TYPE2_SET_KEYBOARD_INDICATORS`
- `justrdp/src/session.rs` — `SessionOutput::KeyboardIndicators`
- `justrdp-tokio/src/lib.rs` — `keyboard_toggle_flags` (two `cfg` variants),
  `run_session_with_input`, `SessionCommand`, `SessionEvent::KeyboardIndicators`,
  `keyboard_indicators_probe_against_real_vm`
- Spec sections cited inline: `[MS-RDPBCGR]` 2.2.8.1.2.2.1, 2.2.8.2.1.1

## Reference behaviour

**The scancode tables: none.** No verified external-fact store — and for this territory
that is the single largest gap in the map: the three tables were derived once, and there
is no recorded comparison against FreeRDP's keyboard maps, which is the only artifact that
could settle a disputed row.

**Set Keyboard Indicators: this WS2022 VM never sends it** (#305, 2026-09-22). Four runs,
raw session and connect captures scanned for every `pduType2`: 0x26, 0x2F and the
finalization replies are there, 0x29 never. The stimuli covered a client Synchronize of none,
Caps, and Scroll+Num+Caps, and Caps, Num and Scroll Lock each pressed twice, with and without
a focusing click first. So #305's premise that *"the server answers 0x29 when its own view
differs"* is **false for this server**, and what makes a Windows server send one is not
established. The layout rests on the spec and FreeRDP's handler agreeing (`unitId` u16 LE,
then `ledFlags` u16 LE), plus hand-built bodies. `keyboard_indicators_probe_against_real_vm`
re-runs the stimuli, prints any 0x29 it sees, and asserts only that the session survives —
advisory by the maintainer's call, because no assertion about the arm can fail on this VM.

## Cross-cutting invariants

- [A decoded field with no reader is an unstated decision](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md)
  — `unitId`, taken the third way out.

## Blast radius

- [Session loop & PDU dispatch](session-loop-dispatch.md) — input is written through
  the session's byte output, interleaved with graphics traffic; and the Set Keyboard
  Indicators arm and its output live there.
- [Adapter drive loop](adapter-drive-loop.md) — owns `SessionCommand`, the input
  channel, and the platform toggle-flag read.
- [Capability exchange & activation](capability-exchange-activation.md) —
  `InputCapabilitySet` and the keyboard layout advertised at GCC decide how the
  server interprets what is sent.
- [PDU constants & flag tables](pdu-constants.md) — input event type codes and
  keyboard flags.

## Known holes / open

- **No table has ever been verified against a reference implementation.** They are
  the repo's clearest instance of "derived once, never checked".
- IME / dead keys / Unicode input are unbuilt (plan.md §18); the Unicode path is a
  different PDU shape, not a table row.
- Multitouch and pen (epic #15), relative-mouse mode (a GCC early flag exists,
  `RELATIVE_MOUSE_INPUT`) are not implemented.
- Nothing tests the macOS or Linux tables on their own platform — the CI runner is
  Ubuntu and the maintainer's box is Windows.
- **`keyboard_toggle_flags()` is a stub off Windows.** The `#[cfg(windows)]` arm
  reads `GetKeyState`; the `#[cfg(not(windows))]` arm returns `0`, so on Linux/macOS
  hosts the initial Caps/Num/Scroll sync silently reports "no toggles set" and the
  server's modifier state starts out disagreeing with the host's. The doc-comment
  says a X11/evdev reader can replace it; nothing tracks that as work.
