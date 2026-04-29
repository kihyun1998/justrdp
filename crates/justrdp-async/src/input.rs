#![forbid(unsafe_code)]

//! Pure helpers that turn an [`Operation`] (or a primitive `Scancode` /
//! `MouseButton` / `LockKeys`) into the [`FastPathInputEvent`] variant
//! the wire encoder expects.
//!
//! The conversion is mechanical — every op corresponds to one fast-path
//! event, with the wire-level flag bytes (KBDFLAGS_*, PTRFLAGS_*) baked
//! in here. Keeping this in its own module lets [`ActiveSession`]'s
//! state-tracked input API stay focused on diff-against-database logic.
//!
//! `MouseButton::X1` / `X2` are not yet wired — the wire format requires
//! a separate `MouseX` event the encoder doesn't currently emit, so
//! [`build_mouse_button_event`] returns `None` for those two and the
//! [`ActiveSession`] surface skips them rather than sending a bogus
//! Button1/2/3 substitute that would leave the server confused.
//!
//! [`ActiveSession`]: crate::session::ActiveSession
//! [`Operation`]: justrdp_input::Operation

use justrdp_input::{LockKeys, MouseButton, Scancode};
use justrdp_pdu::rdp::fast_path::{
    FastPathInputEvent, FastPathMouseEvent, FastPathScancodeEvent, FastPathSyncEvent,
    FastPathUnicodeEvent,
};

// ── Keyboard event flags (MS-RDPBCGR 2.2.8.1.2.2.1) ─────────────────

/// `KBDFLAGS_RELEASE` — set on key-up, clear on key-down.
pub(crate) const KBDFLAGS_RELEASE: u8 = 0x01;
/// `KBDFLAGS_EXTENDED` — second-half scancode (right-side modifiers,
/// arrows, numpad-not-numlock, etc.).
pub(crate) const KBDFLAGS_EXTENDED: u8 = 0x02;

// ── Mouse pointer flags (MS-RDPBCGR 2.2.8.1.2.2.3) ──────────────────

pub(crate) const PTRFLAGS_HWHEEL: u16 = 0x0400;
pub(crate) const PTRFLAGS_WHEEL: u16 = 0x0200;
pub(crate) const PTRFLAGS_WHEEL_NEGATIVE: u16 = 0x0100;
pub(crate) const PTRFLAGS_MOVE: u16 = 0x0800;
pub(crate) const PTRFLAGS_DOWN: u16 = 0x8000;
pub(crate) const PTRFLAGS_BUTTON1: u16 = 0x1000;
pub(crate) const PTRFLAGS_BUTTON2: u16 = 0x2000;
pub(crate) const PTRFLAGS_BUTTON3: u16 = 0x4000;

/// Build a fast-path scancode input event with appropriate
/// `KBDFLAGS_RELEASE` / `KBDFLAGS_EXTENDED` flags set.
pub(crate) fn build_scancode_event(scancode: Scancode, pressed: bool) -> FastPathInputEvent {
    let mut event_flags = 0u8;
    if !pressed {
        event_flags |= KBDFLAGS_RELEASE;
    }
    if scancode.extended {
        event_flags |= KBDFLAGS_EXTENDED;
    }
    FastPathInputEvent::Scancode(FastPathScancodeEvent {
        event_flags,
        key_code: scancode.code,
    })
}

/// Build a fast-path mouse-move event with `PTRFLAGS_MOVE`.
pub(crate) fn build_mouse_move_event(x: u16, y: u16) -> FastPathInputEvent {
    FastPathInputEvent::Mouse(FastPathMouseEvent {
        event_flags: 0,
        pointer_flags: PTRFLAGS_MOVE,
        x_pos: x,
        y_pos: y,
    })
}

/// Build a fast-path mouse button press/release event.
///
/// Returns `None` for `MouseButton::X1` / `X2`, which require a separate
/// `MouseX` event type that's not yet emitted by the encoder.
pub(crate) fn build_mouse_button_event(
    button: MouseButton,
    pressed: bool,
    x: u16,
    y: u16,
) -> Option<FastPathInputEvent> {
    let button_flag = match button {
        MouseButton::Left => PTRFLAGS_BUTTON1,
        MouseButton::Right => PTRFLAGS_BUTTON2,
        MouseButton::Middle => PTRFLAGS_BUTTON3,
        MouseButton::X1 | MouseButton::X2 => return None,
    };
    let down_flag = if pressed { PTRFLAGS_DOWN } else { 0 };
    Some(FastPathInputEvent::Mouse(FastPathMouseEvent {
        event_flags: 0,
        pointer_flags: button_flag | down_flag,
        x_pos: x,
        y_pos: y,
    }))
}

/// Build a fast-path mouse wheel event.
///
/// MS-RDPBCGR 2.2.8.1.1.3.1.1.3: low byte of `pointerFlags` carries the
/// magnitude (0..=255) and `PTRFLAGS_WHEEL_NEGATIVE` carries the sign.
/// Magnitude is clamped to 255.
pub(crate) fn build_mouse_wheel_event(
    delta: i16,
    horizontal: bool,
    x: u16,
    y: u16,
) -> FastPathInputEvent {
    let mut flags = if horizontal {
        PTRFLAGS_HWHEEL
    } else {
        PTRFLAGS_WHEEL
    };
    let magnitude = delta.unsigned_abs().min(255) as u16;
    flags |= magnitude;
    if delta < 0 {
        flags |= PTRFLAGS_WHEEL_NEGATIVE;
    }
    FastPathInputEvent::Mouse(FastPathMouseEvent {
        event_flags: 0,
        pointer_flags: flags,
        x_pos: x,
        y_pos: y,
    })
}

/// Build a fast-path Unicode key press/release event. Stateless — the
/// `InputDatabase` does not track unicode state, so this is invoked
/// directly from [`ActiveSession::send_unicode`] without any dedup.
pub(crate) fn build_unicode_event(unicode_code: u16, pressed: bool) -> FastPathInputEvent {
    let event_flags = if pressed { 0 } else { KBDFLAGS_RELEASE };
    FastPathInputEvent::Unicode(FastPathUnicodeEvent {
        event_flags,
        unicode_code,
    })
}

/// Build a fast-path synchronize event from lock-key state.
///
/// MS-RDPBCGR §2.2.8.1.2.2.5: `eventFlags` bits 0-3 carry the toggle
/// states (scroll, num, caps, kana). The high nibble is reserved.
pub(crate) fn build_sync_event(lock_keys: LockKeys) -> FastPathInputEvent {
    FastPathInputEvent::Sync(FastPathSyncEvent {
        event_flags: (lock_keys.to_flags() & 0x0F) as u8,
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

    fn unwrap_sync(e: FastPathInputEvent) -> FastPathSyncEvent {
        match e {
            FastPathInputEvent::Sync(s) => s,
            other => panic!("expected Sync, got {other:?}"),
        }
    }

    #[test]
    fn scancode_press_clears_release_flag() {
        let s = unwrap_scancode(build_scancode_event(Scancode::new(0x1E, false), true));
        assert_eq!(s.event_flags, 0);
        assert_eq!(s.key_code, 0x1E);
    }

    #[test]
    fn scancode_release_sets_release_flag() {
        let s = unwrap_scancode(build_scancode_event(Scancode::new(0x1E, false), false));
        assert_eq!(s.event_flags & KBDFLAGS_RELEASE, KBDFLAGS_RELEASE);
    }

    #[test]
    fn scancode_extended_combines_with_release() {
        let s = unwrap_scancode(build_scancode_event(Scancode::new(0x4D, true), false));
        assert_eq!(s.event_flags, KBDFLAGS_RELEASE | KBDFLAGS_EXTENDED);
    }

    #[test]
    fn mouse_move_only_sets_move_flag() {
        let m = unwrap_mouse(build_mouse_move_event(320, 240));
        assert_eq!(m.pointer_flags, PTRFLAGS_MOVE);
        assert_eq!((m.x_pos, m.y_pos), (320, 240));
    }

    #[test]
    fn mouse_button_left_press_sets_button1_and_down() {
        let m = unwrap_mouse(build_mouse_button_event(MouseButton::Left, true, 10, 20).unwrap());
        assert_eq!(m.pointer_flags, PTRFLAGS_BUTTON1 | PTRFLAGS_DOWN);
        assert_eq!((m.x_pos, m.y_pos), (10, 20));
    }

    #[test]
    fn mouse_button_right_release_sets_button2_only() {
        let m = unwrap_mouse(build_mouse_button_event(MouseButton::Right, false, 5, 5).unwrap());
        assert_eq!(m.pointer_flags, PTRFLAGS_BUTTON2);
    }

    #[test]
    fn mouse_button_middle_press_sets_button3_and_down() {
        let m = unwrap_mouse(build_mouse_button_event(MouseButton::Middle, true, 0, 0).unwrap());
        assert_eq!(m.pointer_flags, PTRFLAGS_BUTTON3 | PTRFLAGS_DOWN);
    }

    #[test]
    fn mouse_button_x1_returns_none() {
        assert!(build_mouse_button_event(MouseButton::X1, true, 0, 0).is_none());
        assert!(build_mouse_button_event(MouseButton::X2, false, 0, 0).is_none());
    }

    #[test]
    fn mouse_wheel_positive_delta_no_negative_flag() {
        let m = unwrap_mouse(build_mouse_wheel_event(120, false, 0, 0));
        assert_eq!(m.pointer_flags, PTRFLAGS_WHEEL | 120);
    }

    #[test]
    fn mouse_wheel_negative_delta_sets_negative_flag() {
        let m = unwrap_mouse(build_mouse_wheel_event(-120, false, 0, 0));
        assert_eq!(
            m.pointer_flags,
            PTRFLAGS_WHEEL | PTRFLAGS_WHEEL_NEGATIVE | 120
        );
    }

    #[test]
    fn mouse_wheel_horizontal_uses_hwheel_flag() {
        let m = unwrap_mouse(build_mouse_wheel_event(60, true, 0, 0));
        assert_eq!(m.pointer_flags, PTRFLAGS_HWHEEL | 60);
    }

    #[test]
    fn mouse_wheel_clamps_oversized_delta_magnitude() {
        // i16::MAX = 32767 → clamped to 255.
        let m = unwrap_mouse(build_mouse_wheel_event(i16::MAX, false, 0, 0));
        assert_eq!(m.pointer_flags, PTRFLAGS_WHEEL | 255);
    }

    #[test]
    fn unicode_press_no_release_flag() {
        if let FastPathInputEvent::Unicode(u) = build_unicode_event(0x0041, true) {
            assert_eq!(u.event_flags, 0);
            assert_eq!(u.unicode_code, 0x0041);
        } else {
            panic!("expected Unicode");
        }
    }

    #[test]
    fn unicode_release_sets_release_flag() {
        if let FastPathInputEvent::Unicode(u) = build_unicode_event(0x0041, false) {
            assert_eq!(u.event_flags, KBDFLAGS_RELEASE);
        } else {
            panic!("expected Unicode");
        }
    }

    #[test]
    fn sync_event_packs_lock_flags_low_nibble() {
        let s = unwrap_sync(build_sync_event(LockKeys {
            scroll_lock: true,
            num_lock: false,
            caps_lock: true,
            kana_lock: false,
        }));
        assert_eq!(s.event_flags, 0x05); // scroll | caps
    }

    #[test]
    fn sync_event_all_locks_set() {
        let s = unwrap_sync(build_sync_event(LockKeys {
            scroll_lock: true,
            num_lock: true,
            caps_lock: true,
            kana_lock: true,
        }));
        assert_eq!(s.event_flags, 0x0F);
    }
}
