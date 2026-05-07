import { describe, expect, it } from "vitest";
import { keyEventToScancode } from "./keymap";

/**
 * keymap behavior tests.
 *
 * Each `describe` block corresponds to one TDD cycle from PRD #1
 * issue #2 — they are grouped by *behavior* (extended-bit handling,
 * modifier left/right disambiguation, etc.) rather than by alphabetic
 * `KeyboardEvent.code` group, so a regression in any cycle surfaces
 * as a focused failure.
 *
 * The scancode reference is MS-RDPBCGR §2.2.8.1.2.2 + AT scancode
 * set 1. Tests assert against the wire-level pair, not the lookup
 * table shape — `keymap.ts` could store the mapping any way it likes
 * as long as the externally observable pair is right.
 */

// ─────────────────────────────────────────────────────────────────
// Cycle 7 — letters (tracer bullet, extended bit always false)
// ─────────────────────────────────────────────────────────────────
describe("letters", () => {
  it("KeyA → 0x1E (no E0)", () => {
    expect(keyEventToScancode("KeyA")).toEqual({ code: 0x1e, extended: false });
  });

  it("KeyZ → 0x2C (no E0)", () => {
    expect(keyEventToScancode("KeyZ")).toEqual({ code: 0x2c, extended: false });
  });
});

// ─────────────────────────────────────────────────────────────────
// Cycle 8 — arrows: same name, *always* extended
// ─────────────────────────────────────────────────────────────────
describe("arrow keys carry the E0 prefix", () => {
  it.each([
    ["ArrowUp", 0x48],
    ["ArrowDown", 0x50],
    ["ArrowLeft", 0x4b],
    ["ArrowRight", 0x4d],
  ])("%s → 0x%s with extended=true", (code, scancode) => {
    expect(keyEventToScancode(code)).toEqual({ code: scancode, extended: true });
  });
});

// ─────────────────────────────────────────────────────────────────
// Cycle 9 — numpad vs nav cluster share scancodes; only extended bit
//           disambiguates. Critical because typing "Home" vs Numpad7
//           with NumLock off feels identical to the user but the
//           remote must distinguish them.
// ─────────────────────────────────────────────────────────────────
describe("numpad and nav-cluster share scancodes — disambiguated by E0", () => {
  it.each([
    // [numpad code, nav code, shared scancode]
    ["Numpad7", "Home", 0x47],
    ["Numpad8", "ArrowUp", 0x48],
    ["Numpad9", "PageUp", 0x49],
    ["Numpad4", "ArrowLeft", 0x4b],
    ["Numpad6", "ArrowRight", 0x4d],
    ["Numpad1", "End", 0x4f],
    ["Numpad2", "ArrowDown", 0x50],
    ["Numpad3", "PageDown", 0x51],
    ["Numpad0", "Insert", 0x52],
    ["NumpadDecimal", "Delete", 0x53],
  ])("%s and %s both encode 0x%s but differ in extended bit", (numpad, nav, scancode) => {
    const np = keyEventToScancode(numpad);
    const navResult = keyEventToScancode(nav);
    expect(np).toEqual({ code: scancode, extended: false });
    expect(navResult).toEqual({ code: scancode, extended: true });
  });
});

// ─────────────────────────────────────────────────────────────────
// Cycle 10 — modifier L+R disambiguation
//   Shift uses *different* scancodes (0x2A vs 0x36).
//   Ctrl/Alt use the *same* scancode with E0 on the right.
//   Meta (Win) uses different scancodes, both with E0.
// ─────────────────────────────────────────────────────────────────
describe("modifiers: left and right are distinguishable", () => {
  it("ShiftLeft and ShiftRight have different scancodes (0x2A vs 0x36)", () => {
    expect(keyEventToScancode("ShiftLeft")).toEqual({ code: 0x2a, extended: false });
    expect(keyEventToScancode("ShiftRight")).toEqual({ code: 0x36, extended: false });
  });

  it("ControlLeft and ControlRight share scancode 0x1D, distinguished by E0", () => {
    expect(keyEventToScancode("ControlLeft")).toEqual({ code: 0x1d, extended: false });
    expect(keyEventToScancode("ControlRight")).toEqual({ code: 0x1d, extended: true });
  });

  it("AltLeft and AltRight share scancode 0x38, distinguished by E0", () => {
    expect(keyEventToScancode("AltLeft")).toEqual({ code: 0x38, extended: false });
    expect(keyEventToScancode("AltRight")).toEqual({ code: 0x38, extended: true });
  });

  it("MetaLeft (Win) is 0x5B+E0, MetaRight is 0x5C+E0", () => {
    expect(keyEventToScancode("MetaLeft")).toEqual({ code: 0x5b, extended: true });
    expect(keyEventToScancode("MetaRight")).toEqual({ code: 0x5c, extended: true });
  });
});

// ─────────────────────────────────────────────────────────────────
// Cycle 11 — function keys F1–F12
//   F1–F10 occupy 0x3B–0x44 contiguously; F11/F12 jump to 0x57/0x58.
// ─────────────────────────────────────────────────────────────────
describe("function keys F1–F12", () => {
  it("F1–F10 occupy 0x3B–0x44 contiguously", () => {
    const fnRow = ["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10"];
    fnRow.forEach((code, i) => {
      expect(keyEventToScancode(code)).toEqual({ code: 0x3b + i, extended: false });
    });
  });

  it("F11 → 0x57 and F12 → 0x58 (jump from F10's 0x44)", () => {
    expect(keyEventToScancode("F11")).toEqual({ code: 0x57, extended: false });
    expect(keyEventToScancode("F12")).toEqual({ code: 0x58, extended: false });
  });
});

// ─────────────────────────────────────────────────────────────────
// Cycle 12 — unknown codes return null (the embedder may then fall
//            back to Unicode dispatch or silently drop)
// ─────────────────────────────────────────────────────────────────
describe("unknown KeyboardEvent.code values", () => {
  it("returns null for an unrecognised code", () => {
    expect(keyEventToScancode("MadeUpCodeThatDoesNotExist")).toBeNull();
  });

  it("returns null for the empty string", () => {
    expect(keyEventToScancode("")).toBeNull();
  });

  it("is case-sensitive — 'keya' (lowercase) is not 'KeyA'", () => {
    // The browser always emits CamelCase for letter codes; we should
    // NOT silently coerce, because doing so would mask a real bug
    // (e.g. an embedder lowercasing somewhere upstream).
    expect(keyEventToScancode("keya")).toBeNull();
  });
});
