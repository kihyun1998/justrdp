// US-English KeyboardEvent.code → PS/2 set-1 scancode map.
//
// Hand-written subset: typewriter rows, modifiers, function keys,
// arrows, navigation cluster, common punctuation. Matches the wire
// values mstsc emits on a US-English layout (MS-RDPBCGR 2.2.8.1.2.2.1
// references the standard PS/2 set-1 scancodes).
//
// Each entry is `[scancode, extended]`; extended=true means the
// keystroke has the 0xE0 prefix on PS/2 set-1, which we translate to
// KBDFLAGS_EXTENDED on the wire. Keys not listed here fall through
// silently — the demo is meant for visible input testing, not full
// keyboard fidelity. Consumers needing complete coverage should ship
// their own map.

export const SCANCODES = Object.freeze({
  // Letters.
  KeyA: [0x1E, false], KeyB: [0x30, false], KeyC: [0x2E, false], KeyD: [0x20, false],
  KeyE: [0x12, false], KeyF: [0x21, false], KeyG: [0x22, false], KeyH: [0x23, false],
  KeyI: [0x17, false], KeyJ: [0x24, false], KeyK: [0x25, false], KeyL: [0x26, false],
  KeyM: [0x32, false], KeyN: [0x31, false], KeyO: [0x18, false], KeyP: [0x19, false],
  KeyQ: [0x10, false], KeyR: [0x13, false], KeyS: [0x1F, false], KeyT: [0x14, false],
  KeyU: [0x16, false], KeyV: [0x2F, false], KeyW: [0x11, false], KeyX: [0x2D, false],
  KeyY: [0x15, false], KeyZ: [0x2C, false],

  // Top-row digits.
  Digit1: [0x02, false], Digit2: [0x03, false], Digit3: [0x04, false], Digit4: [0x05, false],
  Digit5: [0x06, false], Digit6: [0x07, false], Digit7: [0x08, false], Digit8: [0x09, false],
  Digit9: [0x0A, false], Digit0: [0x0B, false],

  // Punctuation (US layout).
  Minus: [0x0C, false],         // -
  Equal: [0x0D, false],         // =
  BracketLeft: [0x1A, false],   // [
  BracketRight: [0x1B, false],  // ]
  Backslash: [0x2B, false],     // \
  Semicolon: [0x27, false],     // ;
  Quote: [0x28, false],         // '
  Backquote: [0x29, false],     // `
  Comma: [0x33, false],         // ,
  Period: [0x34, false],        // .
  Slash: [0x35, false],         // /

  // Whitespace + edit.
  Space: [0x39, false], Tab: [0x0F, false], Enter: [0x1C, false], Backspace: [0x0E, false],
  Escape: [0x01, false], CapsLock: [0x3A, false],

  // Modifiers.
  ShiftLeft: [0x2A, false], ShiftRight: [0x36, false],
  ControlLeft: [0x1D, false], ControlRight: [0x1D, true],
  AltLeft: [0x38, false], AltRight: [0x38, true],
  MetaLeft: [0x5B, true], MetaRight: [0x5C, true],   // Win keys

  // Function keys (F1..F12).
  F1: [0x3B, false], F2: [0x3C, false], F3: [0x3D, false], F4: [0x3E, false],
  F5: [0x3F, false], F6: [0x40, false], F7: [0x41, false], F8: [0x42, false],
  F9: [0x43, false], F10: [0x44, false], F11: [0x57, false], F12: [0x58, false],

  // Arrow + navigation cluster (extended scancodes).
  ArrowUp: [0x48, true], ArrowDown: [0x50, true],
  ArrowLeft: [0x4B, true], ArrowRight: [0x4D, true],
  Home: [0x47, true], End: [0x4F, true],
  PageUp: [0x49, true], PageDown: [0x51, true],
  Insert: [0x52, true], Delete: [0x53, true],
});

/// Look up a `KeyboardEvent.code`. Returns `null` if the key isn't
/// mapped — caller should ignore those keystrokes rather than guessing.
export function lookup(code) {
  return SCANCODES[code] ?? null;
}
