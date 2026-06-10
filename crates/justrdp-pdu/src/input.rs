//! Input Event PDUs (MS-RDPBCGR 2.2.8) — keyboard and mouse events, client → server.
//!
//! One [`InputEvent`] value encodes into either transport:
//!
//! - **Fast-path** (`TS_FP_INPUT_PDU`, 2.2.8.1.2): the compact form servers prefer; sent when
//!   the server's Input capability set advertised `INPUT_FLAG_FASTPATH_INPUT` /
//!   `INPUT_FLAG_FASTPATH_INPUT2` ([`encode_fastpath_input`]).
//! - **Slow-path** (`TS_INPUT_PDU_DATA`, 2.2.8.1.1.3): the Share Data PDU body
//!   (`pduType2` = [`crate::share::PDU_TYPE2_INPUT`]) used as the fallback
//!   ([`encode_slowpath_input_body`]).

/// `pointerFlags`: the wheel rotation is negative (toward the user).
pub const PTRFLAGS_WHEEL_NEGATIVE: u16 = 0x0100;
/// `pointerFlags`: a vertical wheel rotation (the low 9 bits carry the amount).
pub const PTRFLAGS_WHEEL: u16 = 0x0200;
/// `pointerFlags`: a horizontal wheel rotation.
pub const PTRFLAGS_HWHEEL: u16 = 0x0400;
/// `pointerFlags`: pointer moved to (x, y).
pub const PTRFLAGS_MOVE: u16 = 0x0800;
/// `pointerFlags`: left button.
pub const PTRFLAGS_BUTTON1: u16 = 0x1000;
/// `pointerFlags`: right button.
pub const PTRFLAGS_BUTTON2: u16 = 0x2000;
/// `pointerFlags`: middle button / wheel button.
pub const PTRFLAGS_BUTTON3: u16 = 0x4000;
/// `pointerFlags`: button down (absent = button released).
pub const PTRFLAGS_DOWN: u16 = 0x8000;

/// `pointerFlags` (extended mouse event): first extended button (XBUTTON1).
pub const PTRXFLAGS_BUTTON1: u16 = 0x0001;
/// `pointerFlags` (extended mouse event): second extended button (XBUTTON2).
pub const PTRXFLAGS_BUTTON2: u16 = 0x0002;
/// `pointerFlags` (extended mouse event): button down.
pub const PTRXFLAGS_DOWN: u16 = 0x8000;

/// Sync toggle flag: Scroll Lock is on.
pub const SYNC_SCROLL_LOCK: u8 = 0x01;
/// Sync toggle flag: Num Lock is on.
pub const SYNC_NUM_LOCK: u8 = 0x02;
/// Sync toggle flag: Caps Lock is on.
pub const SYNC_CAPS_LOCK: u8 = 0x04;
/// Sync toggle flag: Kana Lock is on.
pub const SYNC_KANA_LOCK: u8 = 0x08;

// Fast-path eventCode values (the high 3 bits of the event header byte).
const FP_EVENT_SCANCODE: u8 = 0;
const FP_EVENT_MOUSE: u8 = 1;
const FP_EVENT_MOUSEX: u8 = 2;
const FP_EVENT_SYNC: u8 = 3;
const FP_EVENT_UNICODE: u8 = 4;

// Fast-path keyboard eventFlags (the low 5 bits of the event header byte).
const FP_KBDFLAGS_RELEASE: u8 = 0x01;
const FP_KBDFLAGS_EXTENDED: u8 = 0x02;
const FP_KBDFLAGS_EXTENDED1: u8 = 0x04;

// Slow-path messageType values (TS_INPUT_EVENT, 2.2.8.1.1.3.1.1).
const INPUT_EVENT_SYNC: u16 = 0x0000;
const INPUT_EVENT_SCANCODE: u16 = 0x0004;
const INPUT_EVENT_UNICODE: u16 = 0x0005;
const INPUT_EVENT_MOUSE: u16 = 0x8001;
const INPUT_EVENT_MOUSEX: u16 = 0x8002;

// Slow-path keyboardFlags (TS_KEYBOARD_EVENT). The fast-path flags are a compressed form of
// these; only the release/extended semantics exist in both.
const KBDFLAGS_EXTENDED: u16 = 0x0100;
const KBDFLAGS_EXTENDED1: u16 = 0x0200;
const KBDFLAGS_RELEASE: u16 = 0x8000;

/// One client input event, transport-agnostic. The same value encodes into the fast-path or
/// slow-path wire form; the session machine picks the transport from what the server's Input
/// capability set advertised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    /// A keyboard key transition, as a **set-1 scancode** (TS_FP_KEYBOARD_EVENT /
    /// TS_KEYBOARD_EVENT).
    ScanCode {
        /// The set-1 make code (the `E0`/`E1` prefix is carried by the flags, not the code).
        code: u8,
        /// Key released (`true`) or pressed (`false`).
        release: bool,
        /// The scancode carries the `E0` extended prefix (navigation cluster, right-side
        /// modifiers, numpad Enter / divide, Windows keys).
        extended: bool,
        /// The scancode carries the `E1` prefix (the Pause key sequence).
        extended1: bool,
    },
    /// A Unicode text event (TS_FP_UNICODE_KEYBOARD_EVENT) — one UTF-16 code unit, for hosts
    /// that deliver text rather than key positions. Requires `INPUT_FLAG_UNICODE` from the
    /// server.
    Unicode {
        /// The UTF-16 code unit.
        code_unit: u16,
        /// Key released (`true`) or pressed (`false`).
        release: bool,
    },
    /// Keyboard toggle-state synchronization (TS_FP_SYNC_EVENT / TS_SYNC_EVENT): sent on
    /// session start and whenever a lock LED changes host-side.
    Sync {
        /// `SYNC_*` bits for the locks currently on.
        toggle_flags: u8,
    },
    /// A mouse move / button / vertical-or-horizontal wheel event (TS_FP_POINTER_EVENT /
    /// TS_POINTER_EVENT), in absolute desktop coordinates.
    Mouse {
        /// `PTRFLAGS_*` bits (move/buttons/wheel selectors).
        flags: u16,
        /// Signed wheel rotation; folded into the low 9 bits of the wire flags exactly as
        /// MS-RDPBCGR specifies (magnitude truncated to a byte, sign as
        /// [`PTRFLAGS_WHEEL_NEGATIVE`]). Ignored unless a wheel flag is set.
        wheel_units: i16,
        /// Absolute x in desktop coordinates.
        x: u16,
        /// Absolute y in desktop coordinates.
        y: u16,
    },
    /// An extended mouse-button event (TS_FP_POINTERX_EVENT / TS_POINTERX_EVENT): the
    /// XBUTTON1/XBUTTON2 side buttons. Requires `INPUT_FLAG_MOUSEX` to have been negotiated.
    MouseX {
        /// `PTRXFLAGS_*` bits.
        flags: u16,
        /// Absolute x in desktop coordinates.
        x: u16,
        /// Absolute y in desktop coordinates.
        y: u16,
    },
}

impl InputEvent {
    /// The on-wire `pointerFlags` of a mouse event: caller flags plus the wheel rotation
    /// folded into the low 9 bits (magnitude truncated to a byte, sign bit separate).
    fn mouse_wire_flags(flags: u16, wheel_units: i16) -> u16 {
        let negative = if wheel_units < 0 {
            PTRFLAGS_WHEEL_NEGATIVE
        } else {
            0
        };
        flags | negative | u16::from(wheel_units as u8)
    }

    /// Append the fast-path form (event header byte + payload).
    fn encode_fastpath(&self, out: &mut Vec<u8>) {
        match *self {
            InputEvent::ScanCode {
                code,
                release,
                extended,
                extended1,
            } => {
                let mut flags = 0u8;
                if release {
                    flags |= FP_KBDFLAGS_RELEASE;
                }
                if extended {
                    flags |= FP_KBDFLAGS_EXTENDED;
                }
                if extended1 {
                    flags |= FP_KBDFLAGS_EXTENDED1;
                }
                out.push(flags | FP_EVENT_SCANCODE << 5);
                out.push(code);
            }
            InputEvent::Unicode { code_unit, release } => {
                let flags = if release { FP_KBDFLAGS_RELEASE } else { 0 };
                out.push(flags | FP_EVENT_UNICODE << 5);
                out.extend_from_slice(&code_unit.to_le_bytes());
            }
            InputEvent::Sync { toggle_flags } => {
                out.push(toggle_flags & 0x1F | FP_EVENT_SYNC << 5);
            }
            InputEvent::Mouse {
                flags,
                wheel_units,
                x,
                y,
            } => {
                out.push(FP_EVENT_MOUSE << 5);
                out.extend_from_slice(&Self::mouse_wire_flags(flags, wheel_units).to_le_bytes());
                out.extend_from_slice(&x.to_le_bytes());
                out.extend_from_slice(&y.to_le_bytes());
            }
            InputEvent::MouseX { flags, x, y } => {
                out.push(FP_EVENT_MOUSEX << 5);
                out.extend_from_slice(&flags.to_le_bytes());
                out.extend_from_slice(&x.to_le_bytes());
                out.extend_from_slice(&y.to_le_bytes());
            }
        }
    }

    /// Append the slow-path form (eventTime + messageType + body). `eventTime` is always 0 —
    /// the field is ignored by servers (MS-RDPBCGR 2.2.8.1.1.3.1.1).
    fn encode_slowpath(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&0u32.to_le_bytes()); // eventTime
        match *self {
            InputEvent::ScanCode {
                code,
                release,
                extended,
                extended1,
            } => {
                let mut flags = 0u16;
                if release {
                    flags |= KBDFLAGS_RELEASE;
                }
                if extended {
                    flags |= KBDFLAGS_EXTENDED;
                }
                if extended1 {
                    flags |= KBDFLAGS_EXTENDED1;
                }
                out.extend_from_slice(&INPUT_EVENT_SCANCODE.to_le_bytes());
                out.extend_from_slice(&flags.to_le_bytes());
                out.extend_from_slice(&u16::from(code).to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes()); // pad2Octets
            }
            InputEvent::Unicode { code_unit, release } => {
                let flags = if release { KBDFLAGS_RELEASE } else { 0 };
                out.extend_from_slice(&INPUT_EVENT_UNICODE.to_le_bytes());
                out.extend_from_slice(&flags.to_le_bytes());
                out.extend_from_slice(&code_unit.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes()); // pad2Octets
            }
            InputEvent::Sync { toggle_flags } => {
                out.extend_from_slice(&INPUT_EVENT_SYNC.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes()); // pad2Octets
                out.extend_from_slice(&u32::from(toggle_flags).to_le_bytes());
            }
            InputEvent::Mouse {
                flags,
                wheel_units,
                x,
                y,
            } => {
                out.extend_from_slice(&INPUT_EVENT_MOUSE.to_le_bytes());
                out.extend_from_slice(&Self::mouse_wire_flags(flags, wheel_units).to_le_bytes());
                out.extend_from_slice(&x.to_le_bytes());
                out.extend_from_slice(&y.to_le_bytes());
            }
            InputEvent::MouseX { flags, x, y } => {
                out.extend_from_slice(&INPUT_EVENT_MOUSEX.to_le_bytes());
                out.extend_from_slice(&flags.to_le_bytes());
                out.extend_from_slice(&x.to_le_bytes());
                out.extend_from_slice(&y.to_le_bytes());
            }
        }
    }
}

/// Encode one complete fast-path input PDU (`TS_FP_INPUT_PDU`) around 1–255 events.
///
/// The `fpInputHeader` byte packs `action` (low 2 bits, always 0), `numEvents` (4 bits — when
/// the count exceeds 15 the field is 0 and an explicit count byte follows the length), and
/// `flags` (high 2 bits — always 0 under TLS transport security; the encryption flags belong
/// to legacy RDP security). The length field covers the whole PDU and uses the same 7-bit /
/// high-bit-continuation form as fast-path output.
///
/// # Panics
///
/// If `events` is empty or holds more than 255 events — the per-PDU bounds of the wire format.
/// Callers batching larger streams split them first (the session machine does).
pub fn encode_fastpath_input(events: &[InputEvent]) -> Vec<u8> {
    assert!(
        (1..=255).contains(&events.len()),
        "a fast-path input PDU carries 1-255 events, got {}",
        events.len()
    );
    let mut body = Vec::new();
    for event in events {
        event.encode_fastpath(&mut body);
    }
    let (header_events, explicit_count) = if events.len() <= 15 {
        (events.len() as u8, None)
    } else {
        (0, Some(events.len() as u8))
    };
    let extra = usize::from(explicit_count.is_some());
    // The length field covers the entire PDU including itself; adding the second length byte
    // can only grow the total, never shrink it back under the one-byte boundary.
    let mut total = 2 + extra + body.len();
    let mut out = Vec::with_capacity(total + 1);
    out.push(header_events << 2); // action 0 | numEvents | flags 0
    if total <= 0x7F {
        out.push(total as u8);
    } else {
        total += 1;
        out.push(0x80 | (total >> 8) as u8);
        out.push(total as u8);
    }
    if let Some(count) = explicit_count {
        out.push(count);
    }
    out.extend_from_slice(&body);
    out
}

/// Encode the body of a slow-path Input Event PDU (`TS_INPUT_PDU_DATA` after its Share Data
/// header): `numEvents`, padding, then the events. Wrap it with
/// [`crate::share::encode_share_data`] under [`crate::share::PDU_TYPE2_INPUT`].
///
/// # Panics
///
/// If `events` is empty or holds more than 65535 events (the `numEvents` field width).
pub fn encode_slowpath_input_body(events: &[InputEvent]) -> Vec<u8> {
    assert!(
        (1..=usize::from(u16::MAX)).contains(&events.len()),
        "a slow-path input PDU carries 1-65535 events, got {}",
        events.len()
    );
    let mut out = Vec::new();
    out.extend_from_slice(&(events.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // pad2Octets
    for event in events {
        event.encode_slowpath(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fastpath_scancode_press_and_release() {
        let pdu = encode_fastpath_input(&[
            InputEvent::ScanCode {
                code: 0x1E,
                release: false,
                extended: false,
                extended1: false,
            },
            InputEvent::ScanCode {
                code: 0x1E,
                release: true,
                extended: false,
                extended1: false,
            },
        ]);
        // header: action 0, numEvents 2 → 0x08; length 6; events: (0x00,0x1E), (0x01,0x1E).
        assert_eq!(pdu, vec![0x08, 0x06, 0x00, 0x1E, 0x01, 0x1E]);
    }

    #[test]
    fn fastpath_extended_scancode_sets_the_e0_flag() {
        let pdu = encode_fastpath_input(&[InputEvent::ScanCode {
            code: 0x4B, // Left arrow
            release: false,
            extended: true,
            extended1: false,
        }]);
        assert_eq!(pdu[2], 0x02); // eventCode 0, EXTENDED flag
        assert_eq!(pdu[3], 0x4B);
    }

    #[test]
    fn fastpath_sync_event_carries_toggles_in_the_header() {
        let pdu = encode_fastpath_input(&[InputEvent::Sync {
            toggle_flags: SYNC_NUM_LOCK | SYNC_CAPS_LOCK,
        }]);
        // eventCode 3 << 5 | 0x06.
        assert_eq!(pdu, vec![0x04, 0x03, 0x66]);
    }

    #[test]
    fn fastpath_mouse_event_folds_wheel_units_into_the_flags() {
        let pdu = encode_fastpath_input(&[InputEvent::Mouse {
            flags: PTRFLAGS_WHEEL,
            wheel_units: -120,
            x: 10,
            y: 20,
        }]);
        assert_eq!(pdu[2], FP_EVENT_MOUSE << 5);
        let flags = u16::from_le_bytes([pdu[3], pdu[4]]);
        // WHEEL | WHEEL_NEGATIVE | (-120 truncated to a byte).
        assert_eq!(flags, PTRFLAGS_WHEEL | PTRFLAGS_WHEEL_NEGATIVE | 0x88);
        assert_eq!(u16::from_le_bytes([pdu[5], pdu[6]]), 10);
        assert_eq!(u16::from_le_bytes([pdu[7], pdu[8]]), 20);
    }

    #[test]
    fn fastpath_over_15_events_uses_the_explicit_count_byte() {
        let events = vec![
            InputEvent::ScanCode {
                code: 0x1E,
                release: false,
                extended: false,
                extended1: false,
            };
            16
        ];
        let pdu = encode_fastpath_input(&events);
        // numEvents field 0 → explicit byte after the length.
        assert_eq!(pdu[0], 0x00);
        assert_eq!(pdu[1] as usize, pdu.len());
        assert_eq!(pdu[2], 16);
        assert_eq!(pdu.len(), 3 + 16 * 2);
    }

    #[test]
    fn fastpath_long_pdu_uses_the_two_byte_length() {
        // 255 mouse events × 7 bytes ≈ 1788 bytes — over the 0x7F one-byte boundary.
        let events = vec![
            InputEvent::Mouse {
                flags: PTRFLAGS_MOVE,
                wheel_units: 0,
                x: 1,
                y: 2,
            };
            255
        ];
        let pdu = encode_fastpath_input(&events);
        assert_eq!(pdu[0], 0x00);
        assert!(pdu[1] & 0x80 != 0);
        let length = (usize::from(pdu[1] & 0x7F)) << 8 | usize::from(pdu[2]);
        assert_eq!(length, pdu.len());
        assert_eq!(pdu[3], 255);
        assert_eq!(pdu.len(), 4 + 255 * 7);
    }

    #[test]
    fn slowpath_body_layout() {
        let body = encode_slowpath_input_body(&[
            InputEvent::Sync {
                toggle_flags: SYNC_SCROLL_LOCK,
            },
            InputEvent::ScanCode {
                code: 0x10,
                release: true,
                extended: true,
                extended1: false,
            },
            InputEvent::Mouse {
                flags: PTRFLAGS_BUTTON1 | PTRFLAGS_DOWN,
                wheel_units: 0,
                x: 7,
                y: 9,
            },
        ]);
        // numEvents 3 + pad.
        assert_eq!(&body[..4], &[3, 0, 0, 0]);
        // Sync: time 0, type 0, pad, toggleFlags u32.
        assert_eq!(&body[4..16], &[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);
        // ScanCode: time 0, type 4, flags RELEASE|EXTENDED, key 0x10, pad.
        assert_eq!(
            &body[16..28],
            &[0, 0, 0, 0, 4, 0, 0x00, 0x81, 0x10, 0, 0, 0]
        );
        // Mouse: time 0, type 0x8001, flags, x, y.
        assert_eq!(
            &body[28..40],
            &[0, 0, 0, 0, 0x01, 0x80, 0x00, 0x90, 7, 0, 9, 0]
        );
    }

    #[test]
    #[should_panic(expected = "1-255 events")]
    fn fastpath_rejects_an_empty_batch() {
        encode_fastpath_input(&[]);
    }
}
