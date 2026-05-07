/**
 * Browser `KeyboardEvent.code` → RDP scancode + extended-bit pair.
 *
 * The RDP wire encodes a key as an 8-bit AT/PS-2 scancode plus an
 * E0-prefix flag (`extended`). The scancode tables are in
 * MS-RDPBCGR §2.2.8.1.2.2 and the AT scancode set 1 reference.
 *
 * `keyEventToScancode` is a pure function — no DOM, no state. The
 * embedder calls it from a `keydown` / `keyup` handler:
 *
 * ```ts
 * const sc = keyEventToScancode(e.code);
 * if (sc) invoke("rdp_send_input", {
 *   id, event: { kind: "key", code: sc.code, extended: sc.extended, pressed: true }
 * });
 * ```
 *
 * Unknown codes return `null` so the embedder can choose to drop or
 * fall back to Unicode dispatch.
 *
 * Korean Hangul keys (한자 / 한영) are typically reported by browsers
 * as `Lang1` / `Lang2` but Chromium has historically been inconsistent
 * here — see notes inline. Defer full Korean IME hooking to a
 * follow-up slice (per PRD #1 out-of-scope).
 */

export interface Scancode {
  /** 8-bit scancode value. */
  code: number;
  /** Whether the E0 prefix is set. */
  extended: boolean;
}

/**
 * Lookup table for `KeyboardEvent.code` → scancode.
 *
 * Same scancode value with different `extended` bit is intentional
 * for navigation-cluster keys (Home/Insert/etc. share scancode with
 * Numpad7/Numpad0/etc. but with E0 prefix to disambiguate).
 */
const SCANCODES: Record<string, Scancode> = {
  // ── Letters (top row & home row, AT set 1) ──
  KeyA: { code: 0x1e, extended: false },
  KeyB: { code: 0x30, extended: false },
  KeyC: { code: 0x2e, extended: false },
  KeyD: { code: 0x20, extended: false },
  KeyE: { code: 0x12, extended: false },
  KeyF: { code: 0x21, extended: false },
  KeyG: { code: 0x22, extended: false },
  KeyH: { code: 0x23, extended: false },
  KeyI: { code: 0x17, extended: false },
  KeyJ: { code: 0x24, extended: false },
  KeyK: { code: 0x25, extended: false },
  KeyL: { code: 0x26, extended: false },
  KeyM: { code: 0x32, extended: false },
  KeyN: { code: 0x31, extended: false },
  KeyO: { code: 0x18, extended: false },
  KeyP: { code: 0x19, extended: false },
  KeyQ: { code: 0x10, extended: false },
  KeyR: { code: 0x13, extended: false },
  KeyS: { code: 0x1f, extended: false },
  KeyT: { code: 0x14, extended: false },
  KeyU: { code: 0x16, extended: false },
  KeyV: { code: 0x2f, extended: false },
  KeyW: { code: 0x11, extended: false },
  KeyX: { code: 0x2d, extended: false },
  KeyY: { code: 0x15, extended: false },
  KeyZ: { code: 0x2c, extended: false },

  // ── Top-row digits ──
  Digit1: { code: 0x02, extended: false },
  Digit2: { code: 0x03, extended: false },
  Digit3: { code: 0x04, extended: false },
  Digit4: { code: 0x05, extended: false },
  Digit5: { code: 0x06, extended: false },
  Digit6: { code: 0x07, extended: false },
  Digit7: { code: 0x08, extended: false },
  Digit8: { code: 0x09, extended: false },
  Digit9: { code: 0x0a, extended: false },
  Digit0: { code: 0x0b, extended: false },

  // ── Function keys F1–F12 ──
  // F13-F24 omitted — rarely emitted by browsers, defer to follow-up.
  F1: { code: 0x3b, extended: false },
  F2: { code: 0x3c, extended: false },
  F3: { code: 0x3d, extended: false },
  F4: { code: 0x3e, extended: false },
  F5: { code: 0x3f, extended: false },
  F6: { code: 0x40, extended: false },
  F7: { code: 0x41, extended: false },
  F8: { code: 0x42, extended: false },
  F9: { code: 0x43, extended: false },
  F10: { code: 0x44, extended: false },
  F11: { code: 0x57, extended: false },
  F12: { code: 0x58, extended: false },

  // ── Punctuation / symbols (US layout — server side does layout
  //    translation, so what matters is the *position*) ──
  Backquote: { code: 0x29, extended: false },
  Minus: { code: 0x0c, extended: false },
  Equal: { code: 0x0d, extended: false },
  BracketLeft: { code: 0x1a, extended: false },
  BracketRight: { code: 0x1b, extended: false },
  Backslash: { code: 0x2b, extended: false },
  Semicolon: { code: 0x27, extended: false },
  Quote: { code: 0x28, extended: false },
  Comma: { code: 0x33, extended: false },
  Period: { code: 0x34, extended: false },
  Slash: { code: 0x35, extended: false },
  IntlBackslash: { code: 0x56, extended: false },

  // ── Whitespace / typing controls ──
  Space: { code: 0x39, extended: false },
  Tab: { code: 0x0f, extended: false },
  Enter: { code: 0x1c, extended: false },
  Backspace: { code: 0x0e, extended: false },
  Escape: { code: 0x01, extended: false },

  // ── Modifiers (L+R distinguished by E0 prefix on the right side
  //    for Ctrl / Alt / Meta; Shift uses different scancodes) ──
  ShiftLeft: { code: 0x2a, extended: false },
  ShiftRight: { code: 0x36, extended: false },
  ControlLeft: { code: 0x1d, extended: false },
  ControlRight: { code: 0x1d, extended: true },
  AltLeft: { code: 0x38, extended: false },
  AltRight: { code: 0x38, extended: true },
  MetaLeft: { code: 0x5b, extended: true },
  MetaRight: { code: 0x5c, extended: true },
  ContextMenu: { code: 0x5d, extended: true },

  // ── Lock keys ──
  CapsLock: { code: 0x3a, extended: false },
  NumLock: { code: 0x45, extended: false },
  ScrollLock: { code: 0x46, extended: false },

  // ── Arrow keys (extended — same scancodes as Numpad nav) ──
  ArrowUp: { code: 0x48, extended: true },
  ArrowDown: { code: 0x50, extended: true },
  ArrowLeft: { code: 0x4b, extended: true },
  ArrowRight: { code: 0x4d, extended: true },

  // ── Navigation cluster (extended — share scancodes with Numpad) ──
  Insert: { code: 0x52, extended: true },
  Home: { code: 0x47, extended: true },
  PageUp: { code: 0x49, extended: true },
  Delete: { code: 0x53, extended: true },
  End: { code: 0x4f, extended: true },
  PageDown: { code: 0x51, extended: true },

  // ── Numpad (NOT extended; same scancodes as nav cluster but no E0) ──
  Numpad0: { code: 0x52, extended: false },
  Numpad1: { code: 0x4f, extended: false },
  Numpad2: { code: 0x50, extended: false },
  Numpad3: { code: 0x51, extended: false },
  Numpad4: { code: 0x4b, extended: false },
  Numpad5: { code: 0x4c, extended: false },
  Numpad6: { code: 0x4d, extended: false },
  Numpad7: { code: 0x47, extended: false },
  Numpad8: { code: 0x48, extended: false },
  Numpad9: { code: 0x49, extended: false },
  NumpadDecimal: { code: 0x53, extended: false },
  NumpadAdd: { code: 0x4e, extended: false },
  NumpadSubtract: { code: 0x4a, extended: false },
  NumpadMultiply: { code: 0x37, extended: false },
  NumpadDivide: { code: 0x35, extended: true },
  NumpadEnter: { code: 0x1c, extended: true },
};

/**
 * Translate a `KeyboardEvent.code` string to an RDP scancode pair,
 * or `null` if the code is not recognised.
 */
export function keyEventToScancode(code: string): Scancode | null {
  return SCANCODES[code] ?? null;
}
