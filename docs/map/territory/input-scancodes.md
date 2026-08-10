# Input & platform scancode tables

## What it is

Turning host input into RDP input PDUs: mouse movement and buttons, and — the hard
half — keyboard events, which RDP expresses as **PC/AT scancodes with an extended
flag**, not as characters or platform key codes. So the library carries three
translation tables (Windows virtual-key, macOS keycode, Linux evdev), the multi-event
Pause sequence, and the toggle-key state a session must synchronise on.

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

## Code

- `justrdp/src/input.rs` — `Scancode`, `scancode_from_windows_vk`,
  `scancode_from_macos_keycode`, `scancode_from_linux_evdev`, `pause_sequence`
- `justrdp-pdu/src/input.rs` — `InputEvent`, `encode_fastpath_input`,
  `encode_slowpath_input_body`
- `justrdp-tokio/src/lib.rs` — `keyboard_toggle_flags` (two `cfg` variants),
  `run_session_with_input`, `SessionCommand`
- Spec section cited inline: `[MS-RDPBCGR]` 2.2.8.1.2.2.1

## Reference behaviour

**None.** No verified external-fact store — and for this territory that is the
single largest gap in the map: the three tables were derived once, and there is no
recorded comparison against FreeRDP's keyboard maps, which is the only artifact that
could settle a disputed row.

## Cross-cutting invariants

**None.**

## Blast radius

- [Session loop & PDU dispatch](session-loop-dispatch.md) — input is written through
  the session's byte output, interleaved with graphics traffic.
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
