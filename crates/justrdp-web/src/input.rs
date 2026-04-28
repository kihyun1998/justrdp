#![forbid(unsafe_code)]

//! Input event composition helpers.
//!
//! Pure functions that turn ergonomic browser-side semantics ("user
//! pressed scancode 0x1E", "mouse moved to (320, 240)", "wheel
//! scrolled −2 ticks") into the [`FastPathInputEvent`] variants RDP
//! servers expect (MS-RDPBCGR 2.2.8.1.2.2). Kept transport-agnostic
//! and side-effect-free so they can be unit-tested on native without
//! a session, then composed by [`JsClient`] for wasm-bindgen callers
//! and (eventually) by other embedders.
//!
//! [`JsClient`]: crate::js::JsClient

use justrdp_pdu::rdp::fast_path::{
    FastPathInputEvent, FastPathMouseEvent, FastPathScancodeEvent,
};

// ── Keyboard event flags (MS-RDPBCGR 2.2.8.1.2.2.1) ─────────────────

/// `KBDFLAGS_RELEASE` — set on key-up, clear on key-down.
pub const KBDFLAGS_RELEASE: u8 = 0x01;
/// `KBDFLAGS_EXTENDED` — second-half scancode (right-side modifiers,
/// arrows, numpad-not-numlock, etc.).
pub const KBDFLAGS_EXTENDED: u8 = 0x02;

// ── Mouse pointer flags (MS-RDPBCGR 2.2.8.1.2.2.3) ──────────────────

const PTRFLAGS_HWHEEL: u16 = 0x0400;
const PTRFLAGS_WHEEL: u16 = 0x0200;
const PTRFLAGS_WHEEL_NEGATIVE: u16 = 0x0100;
const PTRFLAGS_MOVE: u16 = 0x0800;
const PTRFLAGS_DOWN: u16 = 0x8000;
const PTRFLAGS_BUTTON1: u16 = 0x1000; // left
const PTRFLAGS_BUTTON2: u16 = 0x2000; // right
const PTRFLAGS_BUTTON3: u16 = 0x4000; // middle

/// Standard mouse button semantics that map cleanly across browser /
/// native input layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

impl MouseButton {
    fn pointer_flag(self) -> u16 {
        match self {
            Self::Left => PTRFLAGS_BUTTON1,
            Self::Right => PTRFLAGS_BUTTON2,
            Self::Middle => PTRFLAGS_BUTTON3,
        }
    }
}

/// Build a fast-path scancode event.
///
/// `key_code` is the PS/2 set-1 scancode; `pressed=false` flips
/// `KBDFLAGS_RELEASE` for key-up. `extended=true` is required for
/// keys that emit a 0xE0-prefixed second-half scancode (right-side
/// Alt/Ctrl, arrows, numpad on numlock-off, etc.).
pub fn scancode_event(key_code: u8, pressed: bool, extended: bool) -> FastPathInputEvent {
    let mut event_flags = 0u8;
    if !pressed {
        event_flags |= KBDFLAGS_RELEASE;
    }
    if extended {
        event_flags |= KBDFLAGS_EXTENDED;
    }
    FastPathInputEvent::Scancode(FastPathScancodeEvent {
        event_flags,
        key_code,
    })
}

/// Mouse move (no buttons changed). Per MS-RDPBCGR `PTRFLAGS_MOVE` is
/// the only flag set; coordinates are absolute desktop pixels.
pub fn mouse_move_event(x: u16, y: u16) -> FastPathInputEvent {
    FastPathInputEvent::Mouse(FastPathMouseEvent {
        event_flags: 0,
        pointer_flags: PTRFLAGS_MOVE,
        x_pos: x,
        y_pos: y,
    })
}

/// Mouse button press (`pressed=true`) or release (`pressed=false`)
/// at desktop pixel `(x, y)`. The matching `PTRFLAGS_BUTTONn` is set
/// in either case; `PTRFLAGS_DOWN` distinguishes press from release.
pub fn mouse_button_event(
    x: u16,
    y: u16,
    button: MouseButton,
    pressed: bool,
) -> FastPathInputEvent {
    let mut pointer_flags = button.pointer_flag();
    if pressed {
        pointer_flags |= PTRFLAGS_DOWN;
    }
    FastPathInputEvent::Mouse(FastPathMouseEvent {
        event_flags: 0,
        pointer_flags,
        x_pos: x,
        y_pos: y,
    })
}

/// Mouse wheel rotation event.
///
/// `delta` is the rotation step count (Windows convention: ±120 per
/// notch). The encoding stores the magnitude in the low byte of
/// `pointer_flags` and `PTRFLAGS_WHEEL_NEGATIVE` for sign. We clamp
/// to the i8 range because the wire encoding is 8-bit.
///
/// `horizontal=true` switches the master flag to `PTRFLAGS_HWHEEL`.
pub fn mouse_wheel_event(x: u16, y: u16, delta: i32, horizontal: bool) -> FastPathInputEvent {
    let clamped = delta.clamp(-127, 127);
    let mut pointer_flags = if horizontal {
        PTRFLAGS_HWHEEL
    } else {
        PTRFLAGS_WHEEL
    };
    if clamped < 0 {
        pointer_flags |= PTRFLAGS_WHEEL_NEGATIVE;
        pointer_flags |= ((-clamped) as u16) & 0x00FF;
    } else {
        pointer_flags |= (clamped as u16) & 0x00FF;
    }
    FastPathInputEvent::Mouse(FastPathMouseEvent {
        event_flags: 0,
        pointer_flags,
        x_pos: x,
        y_pos: y,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unwrap_scancode(e: FastPathInputEvent) -> FastPathScancodeEvent {
        match e {
            FastPathInputEvent::Scancode(s) => s,
            other => panic!("expected Scancode, got {other:?}"),
        }
    }

    fn unwrap_mouse(e: FastPathInputEvent) -> FastPathMouseEvent {
        match e {
            FastPathInputEvent::Mouse(m) => m,
            other => panic!("expected Mouse, got {other:?}"),
        }
    }

    #[test]
    fn scancode_press_has_no_release_flag() {
        let s = unwrap_scancode(scancode_event(0x1E, true, false));
        assert_eq!(s.key_code, 0x1E);
        assert_eq!(s.event_flags, 0);
    }

    #[test]
    fn scancode_release_sets_release_flag() {
        let s = unwrap_scancode(scancode_event(0x1E, false, false));
        assert_eq!(s.event_flags & KBDFLAGS_RELEASE, KBDFLAGS_RELEASE);
    }

    #[test]
    fn scancode_extended_combines_with_release() {
        let s = unwrap_scancode(scancode_event(0x4D, false, true));
        assert_eq!(s.event_flags, KBDFLAGS_RELEASE | KBDFLAGS_EXTENDED);
    }

    #[test]
    fn mouse_move_only_sets_move_flag() {
        let m = unwrap_mouse(mouse_move_event(320, 240));
        assert_eq!(m.pointer_flags, PTRFLAGS_MOVE);
        assert_eq!((m.x_pos, m.y_pos), (320, 240));
    }

    #[test]
    fn mouse_press_sets_button_and_down() {
        let m = unwrap_mouse(mouse_button_event(10, 20, MouseButton::Left, true));
        assert_eq!(m.pointer_flags, PTRFLAGS_BUTTON1 | PTRFLAGS_DOWN);
    }

    #[test]
    fn mouse_release_sets_button_only() {
        let m = unwrap_mouse(mouse_button_event(10, 20, MouseButton::Right, false));
        assert_eq!(m.pointer_flags, PTRFLAGS_BUTTON2);
    }

    #[test]
    fn middle_button_maps_to_button3() {
        let m = unwrap_mouse(mouse_button_event(0, 0, MouseButton::Middle, true));
        assert_eq!(m.pointer_flags, PTRFLAGS_BUTTON3 | PTRFLAGS_DOWN);
    }

    #[test]
    fn vertical_wheel_positive_delta() {
        let m = unwrap_mouse(mouse_wheel_event(0, 0, 120, false));
        // Magnitude clamped to 127.
        assert_eq!(m.pointer_flags, PTRFLAGS_WHEEL | 120);
        assert_eq!(m.pointer_flags & PTRFLAGS_WHEEL_NEGATIVE, 0);
    }

    #[test]
    fn vertical_wheel_negative_delta() {
        let m = unwrap_mouse(mouse_wheel_event(0, 0, -120, false));
        assert_eq!(
            m.pointer_flags,
            PTRFLAGS_WHEEL | PTRFLAGS_WHEEL_NEGATIVE | 120
        );
    }

    #[test]
    fn horizontal_wheel_uses_hwheel_flag() {
        let m = unwrap_mouse(mouse_wheel_event(0, 0, 60, true));
        assert_eq!(m.pointer_flags, PTRFLAGS_HWHEEL | 60);
        assert_eq!(m.pointer_flags & PTRFLAGS_WHEEL_NEGATIVE, 0);
    }

    #[test]
    fn wheel_clamps_oversized_delta() {
        let m = unwrap_mouse(mouse_wheel_event(0, 0, 1024, false));
        // 1024 → clamped to 127.
        assert_eq!(m.pointer_flags, PTRFLAGS_WHEEL | 127);
    }
}
