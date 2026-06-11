//! Host input helpers: OS key identifiers → RDP **set-1 scancodes** (plan.md §6a bullet 6 —
//! this mapping is owned here, not borrowed from another stack).
//!
//! RDP keyboard events carry IBM PC/AT *set-1 make codes* plus an `E0`/`E1` prefix flag —
//! key **positions**, not characters. Shift does not change a scancode; the server's own
//! keyboard layout turns positions into text. Each host OS reports key positions in its own
//! vocabulary, so there is one table per OS:
//!
//! - Windows: virtual-key codes (`VK_*`, the `wParam` of `WM_KEYDOWN`) via
//!   [`scancode_from_windows_vk`].
//! - macOS: Carbon virtual keycodes (`kVK_*`, `NSEvent.keyCode`) via
//!   [`scancode_from_macos_keycode`].
//! - Linux: evdev key codes (`KEY_*` from `<linux/input-event-codes.h>`; subtract 8 from an
//!   X11 keycode first) via [`scancode_from_linux_evdev`].
//!
//! The Pause key is the one position these tables do not map: its set-1 form is the
//! multi-code `E1 1D 45` sequence, which needs two events ([`pause_sequence`]).

use justrdp_pdu::input::InputEvent;

/// A set-1 scancode: the make code plus whether it needs the `E0` extended prefix
/// (navigation cluster, right-side modifiers, numpad Enter / divide, Windows keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scancode {
    /// The set-1 make code.
    pub code: u8,
    /// The key is in the `E0`-prefixed extended range.
    pub extended: bool,
}

impl Scancode {
    const fn plain(code: u8) -> Self {
        Self {
            code,
            extended: false,
        }
    }

    const fn ext(code: u8) -> Self {
        Self {
            code,
            extended: true,
        }
    }

    /// The key-down [`InputEvent`] for this scancode.
    pub fn press(self) -> InputEvent {
        InputEvent::ScanCode {
            code: self.code,
            release: false,
            extended: self.extended,
            extended1: false,
        }
    }

    /// The key-up [`InputEvent`] for this scancode.
    pub fn release(self) -> InputEvent {
        InputEvent::ScanCode {
            code: self.code,
            release: true,
            extended: self.extended,
            extended1: false,
        }
    }
}

/// The Pause key's events for one press-and-release: set-1 encodes Pause as the `E1 1D 45`
/// sequence, which RDP carries as an `EXTENDED1`-flagged `0x1D` followed by a plain `0x45`
/// (MS-RDPBCGR 2.2.8.1.2.2.1's stated purpose for the `EXTENDED1` flag).
pub fn pause_sequence() -> [InputEvent; 4] {
    let ctrl = |release| InputEvent::ScanCode {
        code: 0x1D,
        release,
        extended: false,
        extended1: true,
    };
    let numlock = |release| InputEvent::ScanCode {
        code: 0x45,
        release,
        extended: false,
        extended1: false,
    };
    [ctrl(false), numlock(false), ctrl(true), numlock(true)]
}

/// Set-1 scancodes for the letter keys in QWERTY position order A–Z (the position names are
/// layout-independent — a French host pressing the key labelled "A" reports VK/keycode "Q"'s
/// position and the server applies its own layout).
const LETTERS: [u8; 26] = [
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19,
    0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
];

/// Set-1 scancodes for the top-row digits 0–9 (0 maps to `0x0B`, 1–9 to `0x02`–`0x0A`).
const DIGITS: [u8; 10] = [0x0B, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];

/// Map a Windows virtual-key code (`VK_*`) to its set-1 scancode on the standard (IBM
/// enhanced) keyboard. Returns `None` for keys with no set-1 position (browser/media keys,
/// IME keys, `VK_PAUSE` — see [`pause_sequence`]).
///
/// Left/right-agnostic modifier VKs (`VK_SHIFT`/`VK_CONTROL`/`VK_MENU`) map to the left-side
/// position; pass the `VK_L*`/`VK_R*` forms when the host distinguishes sides.
pub fn scancode_from_windows_vk(vk: u16) -> Option<Scancode> {
    Some(match vk {
        0x08 => Scancode::plain(0x0E),        // VK_BACK
        0x09 => Scancode::plain(0x0F),        // VK_TAB
        0x0D => Scancode::plain(0x1C),        // VK_RETURN (numpad Enter: use ext(0x1C))
        0x10 | 0xA0 => Scancode::plain(0x2A), // VK_SHIFT / VK_LSHIFT
        0xA1 => Scancode::plain(0x36),        // VK_RSHIFT
        0x11 | 0xA2 => Scancode::plain(0x1D), // VK_CONTROL / VK_LCONTROL
        0xA3 => Scancode::ext(0x1D),          // VK_RCONTROL
        0x12 | 0xA4 => Scancode::plain(0x38), // VK_MENU / VK_LMENU
        0xA5 => Scancode::ext(0x38),          // VK_RMENU (AltGr)
        0x14 => Scancode::plain(0x3A),        // VK_CAPITAL
        0x1B => Scancode::plain(0x01),        // VK_ESCAPE
        0x20 => Scancode::plain(0x39),        // VK_SPACE
        0x21 => Scancode::ext(0x49),          // VK_PRIOR (Page Up)
        0x22 => Scancode::ext(0x51),          // VK_NEXT (Page Down)
        0x23 => Scancode::ext(0x4F),          // VK_END
        0x24 => Scancode::ext(0x47),          // VK_HOME
        0x25 => Scancode::ext(0x4B),          // VK_LEFT
        0x26 => Scancode::ext(0x48),          // VK_UP
        0x27 => Scancode::ext(0x4D),          // VK_RIGHT
        0x28 => Scancode::ext(0x50),          // VK_DOWN
        0x2C => Scancode::ext(0x37),          // VK_SNAPSHOT (Print Screen)
        0x2D => Scancode::ext(0x52),          // VK_INSERT
        0x2E => Scancode::ext(0x53),          // VK_DELETE
        0x30..=0x39 => Scancode::plain(DIGITS[usize::from(vk - 0x30)]),
        0x41..=0x5A => Scancode::plain(LETTERS[usize::from(vk - 0x41)]),
        0x5B => Scancode::ext(0x5B), // VK_LWIN
        0x5C => Scancode::ext(0x5C), // VK_RWIN
        0x5D => Scancode::ext(0x5D), // VK_APPS (menu key)
        // Numpad digits (NumLock-on meanings; the positions are the non-extended nav codes).
        0x60 => Scancode::plain(0x52),
        0x61 => Scancode::plain(0x4F),
        0x62 => Scancode::plain(0x50),
        0x63 => Scancode::plain(0x51),
        0x64 => Scancode::plain(0x4B),
        0x65 => Scancode::plain(0x4C),
        0x66 => Scancode::plain(0x4D),
        0x67 => Scancode::plain(0x47),
        0x68 => Scancode::plain(0x48),
        0x69 => Scancode::plain(0x49),
        0x6A => Scancode::plain(0x37), // VK_MULTIPLY
        0x6B => Scancode::plain(0x4E), // VK_ADD
        0x6D => Scancode::plain(0x4A), // VK_SUBTRACT
        0x6E => Scancode::plain(0x53), // VK_DECIMAL
        0x6F => Scancode::ext(0x35),   // VK_DIVIDE
        // F1–F12 (F13+ have no universal set-1 position).
        0x70..=0x79 => Scancode::plain(0x3B + (vk - 0x70) as u8),
        0x7A => Scancode::plain(0x57), // VK_F11
        0x7B => Scancode::plain(0x58), // VK_F12
        0x90 => Scancode::plain(0x45), // VK_NUMLOCK
        0x91 => Scancode::plain(0x46), // VK_SCROLL
        0xBA => Scancode::plain(0x27), // VK_OEM_1      ;:
        0xBB => Scancode::plain(0x0D), // VK_OEM_PLUS   =+
        0xBC => Scancode::plain(0x33), // VK_OEM_COMMA  ,<
        0xBD => Scancode::plain(0x0C), // VK_OEM_MINUS  -_
        0xBE => Scancode::plain(0x34), // VK_OEM_PERIOD .>
        0xBF => Scancode::plain(0x35), // VK_OEM_2      /?
        0xC0 => Scancode::plain(0x29), // VK_OEM_3      `~
        0xDB => Scancode::plain(0x1A), // VK_OEM_4      [{
        0xDC => Scancode::plain(0x2B), // VK_OEM_5      \|
        0xDD => Scancode::plain(0x1B), // VK_OEM_6      ]}
        0xDE => Scancode::plain(0x28), // VK_OEM_7      '"
        0xE2 => Scancode::plain(0x56), // VK_OEM_102 (ISO <> key)
        _ => return None,
    })
}

/// Map a macOS Carbon virtual keycode (`kVK_*`, `NSEvent.keyCode`) to its set-1 scancode.
/// Returns `None` for keys with no PC position (`kVK_Function`, media keys) — and for
/// `kVK_ANSI_KeypadEquals`, which PC keyboards lack.
pub fn scancode_from_macos_keycode(keycode: u16) -> Option<Scancode> {
    Some(match keycode {
        0x00 => Scancode::plain(0x1E), // A
        0x01 => Scancode::plain(0x1F), // S
        0x02 => Scancode::plain(0x20), // D
        0x03 => Scancode::plain(0x21), // F
        0x04 => Scancode::plain(0x23), // H
        0x05 => Scancode::plain(0x22), // G
        0x06 => Scancode::plain(0x2C), // Z
        0x07 => Scancode::plain(0x2D), // X
        0x08 => Scancode::plain(0x2E), // C
        0x09 => Scancode::plain(0x2F), // V
        0x0A => Scancode::plain(0x56), // ISO section key (<> on ISO boards)
        0x0B => Scancode::plain(0x30), // B
        0x0C => Scancode::plain(0x10), // Q
        0x0D => Scancode::plain(0x11), // W
        0x0E => Scancode::plain(0x12), // E
        0x0F => Scancode::plain(0x13), // R
        0x10 => Scancode::plain(0x15), // Y
        0x11 => Scancode::plain(0x14), // T
        0x12 => Scancode::plain(0x02), // 1
        0x13 => Scancode::plain(0x03), // 2
        0x14 => Scancode::plain(0x04), // 3
        0x15 => Scancode::plain(0x05), // 4
        0x16 => Scancode::plain(0x07), // 6
        0x17 => Scancode::plain(0x06), // 5
        0x18 => Scancode::plain(0x0D), // =
        0x19 => Scancode::plain(0x0A), // 9
        0x1A => Scancode::plain(0x08), // 7
        0x1B => Scancode::plain(0x0C), // -
        0x1C => Scancode::plain(0x09), // 8
        0x1D => Scancode::plain(0x0B), // 0
        0x1E => Scancode::plain(0x1B), // ]
        0x1F => Scancode::plain(0x18), // O
        0x20 => Scancode::plain(0x16), // U
        0x21 => Scancode::plain(0x1A), // [
        0x22 => Scancode::plain(0x17), // I
        0x23 => Scancode::plain(0x19), // P
        0x24 => Scancode::plain(0x1C), // Return
        0x25 => Scancode::plain(0x26), // L
        0x26 => Scancode::plain(0x24), // J
        0x27 => Scancode::plain(0x28), // '
        0x28 => Scancode::plain(0x25), // K
        0x29 => Scancode::plain(0x27), // ;
        0x2A => Scancode::plain(0x2B), // \
        0x2B => Scancode::plain(0x33), // ,
        0x2C => Scancode::plain(0x35), // /
        0x2D => Scancode::plain(0x31), // N
        0x2E => Scancode::plain(0x32), // M
        0x2F => Scancode::plain(0x34), // .
        0x30 => Scancode::plain(0x0F), // Tab
        0x31 => Scancode::plain(0x39), // Space
        0x32 => Scancode::plain(0x29), // `
        0x33 => Scancode::plain(0x0E), // Delete (backspace)
        0x35 => Scancode::plain(0x01), // Escape
        0x36 => Scancode::ext(0x5C),   // Right Command → Right Win
        0x37 => Scancode::ext(0x5B),   // Command → Left Win
        0x38 => Scancode::plain(0x2A), // Shift
        0x39 => Scancode::plain(0x3A), // Caps Lock
        0x3A => Scancode::plain(0x38), // Option → Left Alt
        0x3B => Scancode::plain(0x1D), // Control
        0x3C => Scancode::plain(0x36), // Right Shift
        0x3D => Scancode::ext(0x38),   // Right Option → Right Alt
        0x3E => Scancode::ext(0x1D),   // Right Control
        0x41 => Scancode::plain(0x53), // Keypad .
        0x43 => Scancode::plain(0x37), // Keypad *
        0x45 => Scancode::plain(0x4E), // Keypad +
        0x47 => Scancode::plain(0x45), // Keypad Clear → Num Lock
        0x4B => Scancode::ext(0x35),   // Keypad /
        0x4C => Scancode::ext(0x1C),   // Keypad Enter
        0x4E => Scancode::plain(0x4A), // Keypad -
        0x52 => Scancode::plain(0x52), // Keypad 0
        0x53 => Scancode::plain(0x4F), // Keypad 1
        0x54 => Scancode::plain(0x50), // Keypad 2
        0x55 => Scancode::plain(0x51), // Keypad 3
        0x56 => Scancode::plain(0x4B), // Keypad 4
        0x57 => Scancode::plain(0x4C), // Keypad 5
        0x58 => Scancode::plain(0x4D), // Keypad 6
        0x59 => Scancode::plain(0x47), // Keypad 7
        0x5B => Scancode::plain(0x48), // Keypad 8
        0x5C => Scancode::plain(0x49), // Keypad 9
        0x60 => Scancode::plain(0x3F), // F5
        0x61 => Scancode::plain(0x40), // F6
        0x62 => Scancode::plain(0x41), // F7
        0x63 => Scancode::plain(0x3D), // F3
        0x64 => Scancode::plain(0x42), // F8
        0x65 => Scancode::plain(0x43), // F9
        0x67 => Scancode::plain(0x57), // F11
        0x6D => Scancode::plain(0x44), // F10
        0x6F => Scancode::plain(0x58), // F12
        0x72 => Scancode::ext(0x52),   // Help → Insert
        0x73 => Scancode::ext(0x47),   // Home
        0x74 => Scancode::ext(0x49),   // Page Up
        0x75 => Scancode::ext(0x53),   // Forward Delete
        0x76 => Scancode::plain(0x3E), // F4
        0x77 => Scancode::ext(0x4F),   // End
        0x78 => Scancode::plain(0x3C), // F2
        0x79 => Scancode::ext(0x51),   // Page Down
        0x7A => Scancode::plain(0x3B), // F1
        0x7B => Scancode::ext(0x4B),   // Left
        0x7C => Scancode::ext(0x4D),   // Right
        0x7D => Scancode::ext(0x50),   // Down
        0x7E => Scancode::ext(0x48),   // Up
        _ => return None,
    })
}

/// Map a Linux evdev key code (`KEY_*`; subtract 8 from an X11/XKB keycode first) to its
/// set-1 scancode. The main block (`KEY_ESC`=1 … `KEY_F12`=88) **is** set-1 — Linux inherited
/// the AT set-1 numbering — so only the post-88 extended keys need a table. Returns `None`
/// for keys with no PC position (media keys, `KEY_PAUSE` — see [`pause_sequence`]).
pub fn scancode_from_linux_evdev(key: u16) -> Option<Scancode> {
    Some(match key {
        1..=88 => Scancode::plain(key as u8),
        96 => Scancode::ext(0x1C),  // KEY_KPENTER
        97 => Scancode::ext(0x1D),  // KEY_RIGHTCTRL
        98 => Scancode::ext(0x35),  // KEY_KPSLASH
        99 => Scancode::ext(0x37),  // KEY_SYSRQ (Print Screen)
        100 => Scancode::ext(0x38), // KEY_RIGHTALT
        102 => Scancode::ext(0x47), // KEY_HOME
        103 => Scancode::ext(0x48), // KEY_UP
        104 => Scancode::ext(0x49), // KEY_PAGEUP
        105 => Scancode::ext(0x4B), // KEY_LEFT
        106 => Scancode::ext(0x4D), // KEY_RIGHT
        107 => Scancode::ext(0x4F), // KEY_END
        108 => Scancode::ext(0x50), // KEY_DOWN
        109 => Scancode::ext(0x51), // KEY_PAGEDOWN
        110 => Scancode::ext(0x52), // KEY_INSERT
        111 => Scancode::ext(0x53), // KEY_DELETE
        125 => Scancode::ext(0x5B), // KEY_LEFTMETA
        126 => Scancode::ext(0x5C), // KEY_RIGHTMETA
        127 => Scancode::ext(0x5D), // KEY_COMPOSE (menu)
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letter_and_digit_positions_agree_across_all_three_tables() {
        // 'A' (QWERTY position) is 0x1E everywhere: VK_A = 0x41, kVK_ANSI_A = 0x00,
        // KEY_A = 30.
        for sc in [
            scancode_from_windows_vk(0x41),
            scancode_from_macos_keycode(0x00),
            scancode_from_linux_evdev(30),
        ] {
            assert_eq!(sc, Some(Scancode::plain(0x1E)));
        }
        // '1': VK 0x31, kVK 0x12, KEY_1 = 2.
        for sc in [
            scancode_from_windows_vk(0x31),
            scancode_from_macos_keycode(0x12),
            scancode_from_linux_evdev(2),
        ] {
            assert_eq!(sc, Some(Scancode::plain(0x02)));
        }
    }

    #[test]
    fn navigation_keys_are_extended_in_every_table() {
        // Left arrow: VK_LEFT 0x25, kVK_LeftArrow 0x7B, KEY_LEFT 105 — all E0 4B.
        for sc in [
            scancode_from_windows_vk(0x25),
            scancode_from_macos_keycode(0x7B),
            scancode_from_linux_evdev(105),
        ] {
            assert_eq!(sc, Some(Scancode::ext(0x4B)));
        }
        for (vk, code) in [
            (0x2Du16, 0x52u8), // Insert
            (0x2E, 0x53),      // Delete
            (0x24, 0x47),      // Home
            (0x23, 0x4F),      // End
            (0x21, 0x49),      // Page Up
            (0x22, 0x51),      // Page Down
            (0x26, 0x48),      // Up
            (0x28, 0x50),      // Down
        ] {
            assert_eq!(scancode_from_windows_vk(vk), Some(Scancode::ext(code)));
        }
    }

    #[test]
    fn function_keys_are_not_extended() {
        assert_eq!(scancode_from_windows_vk(0x70), Some(Scancode::plain(0x3B))); // F1
        assert_eq!(scancode_from_windows_vk(0x7B), Some(Scancode::plain(0x58))); // F12
        assert_eq!(
            scancode_from_macos_keycode(0x7A),
            Some(Scancode::plain(0x3B))
        );
        assert_eq!(scancode_from_linux_evdev(59), Some(Scancode::plain(0x3B)));
    }

    #[test]
    fn unmapped_keys_return_none() {
        assert_eq!(scancode_from_windows_vk(0x13), None); // VK_PAUSE → pause_sequence
        assert_eq!(scancode_from_windows_vk(0xAD), None); // VK_VOLUME_MUTE
        assert_eq!(scancode_from_macos_keycode(0x3F), None); // kVK_Function
        assert_eq!(scancode_from_linux_evdev(119), None); // KEY_PAUSE
        assert_eq!(scancode_from_linux_evdev(113), None); // KEY_MUTE
    }

    #[test]
    fn press_release_and_pause_produce_the_right_events() {
        let a = Scancode::plain(0x1E);
        assert_eq!(
            a.press(),
            InputEvent::ScanCode {
                code: 0x1E,
                release: false,
                extended: false,
                extended1: false
            }
        );
        assert_eq!(
            Scancode::ext(0x4B).release(),
            InputEvent::ScanCode {
                code: 0x4B,
                release: true,
                extended: true,
                extended1: false
            }
        );
        let pause = pause_sequence();
        assert!(matches!(
            pause[0],
            InputEvent::ScanCode {
                code: 0x1D,
                extended1: true,
                release: false,
                ..
            }
        ));
        assert!(matches!(
            pause[1],
            InputEvent::ScanCode {
                code: 0x45,
                extended1: false,
                release: false,
                ..
            }
        ));
    }
}
