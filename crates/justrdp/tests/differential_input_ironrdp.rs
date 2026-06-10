//! Differential tests (ADR-0001): our input PDU **encoders** against ironrdp-pdu 0.8's as the
//! reference oracle. Input is encode-only for a client, so the differential is byte equality
//! of complete PDUs — any divergence in header packing, lengths, flags folding, or padding
//! shows up as a byte diff.

use justrdp_pdu::input::{
    self, InputEvent, PTRFLAGS_BUTTON1, PTRFLAGS_BUTTON2, PTRFLAGS_DOWN, PTRFLAGS_MOVE,
    PTRFLAGS_WHEEL, PTRXFLAGS_BUTTON1, PTRXFLAGS_DOWN, SYNC_CAPS_LOCK, SYNC_NUM_LOCK,
    SYNC_SCROLL_LOCK,
};

use ironrdp_pdu::encode_vec as iron_encode_vec;
use ironrdp_pdu::input::fast_path::{
    FastPathInput, FastPathInputEvent, KeyboardFlags as FpKeyboardFlags, SynchronizeFlags,
};
use ironrdp_pdu::input::mouse::PointerFlags;
use ironrdp_pdu::input::mouse_x::PointerXFlags;
use ironrdp_pdu::input::scan_code::KeyboardFlags as SpKeyboardFlags;
use ironrdp_pdu::input::sync::SyncToggleFlags;
use ironrdp_pdu::input::{
    InputEvent as IronInputEvent, InputEventPdu, MousePdu, MouseXPdu, ScanCodePdu, SyncPdu,
};

/// A representative event mix and its ironrdp twin: scancodes (plain / release / extended),
/// unicode, sync, mouse move / buttons / wheel in both directions, and extended buttons.
fn event_pairs() -> Vec<(InputEvent, FastPathInputEvent)> {
    vec![
        (
            InputEvent::ScanCode {
                code: 0x1E,
                release: false,
                extended: false,
                extended1: false,
            },
            FastPathInputEvent::KeyboardEvent(FpKeyboardFlags::empty(), 0x1E),
        ),
        (
            InputEvent::ScanCode {
                code: 0x1E,
                release: true,
                extended: false,
                extended1: false,
            },
            FastPathInputEvent::KeyboardEvent(FpKeyboardFlags::RELEASE, 0x1E),
        ),
        (
            InputEvent::ScanCode {
                code: 0x4B,
                release: false,
                extended: true,
                extended1: false,
            },
            FastPathInputEvent::KeyboardEvent(FpKeyboardFlags::EXTENDED, 0x4B),
        ),
        (
            InputEvent::ScanCode {
                code: 0x1D,
                release: true,
                extended: false,
                extended1: true,
            },
            FastPathInputEvent::KeyboardEvent(
                FpKeyboardFlags::RELEASE | FpKeyboardFlags::EXTENDED1,
                0x1D,
            ),
        ),
        (
            InputEvent::Unicode {
                code_unit: 0xAC00, // '가'
                release: false,
            },
            FastPathInputEvent::UnicodeKeyboardEvent(FpKeyboardFlags::empty(), 0xAC00),
        ),
        (
            InputEvent::Sync {
                toggle_flags: SYNC_NUM_LOCK | SYNC_CAPS_LOCK | SYNC_SCROLL_LOCK,
            },
            FastPathInputEvent::SyncEvent(
                SynchronizeFlags::NUM_LOCK
                    | SynchronizeFlags::CAPS_LOCK
                    | SynchronizeFlags::SCROLL_LOCK,
            ),
        ),
        (
            InputEvent::Mouse {
                flags: PTRFLAGS_MOVE,
                wheel_units: 0,
                x: 640,
                y: 400,
            },
            FastPathInputEvent::MouseEvent(MousePdu {
                flags: PointerFlags::MOVE,
                number_of_wheel_rotation_units: 0,
                x_position: 640,
                y_position: 400,
            }),
        ),
        (
            InputEvent::Mouse {
                flags: PTRFLAGS_DOWN | PTRFLAGS_BUTTON1,
                wheel_units: 0,
                x: 12,
                y: 34,
            },
            FastPathInputEvent::MouseEvent(MousePdu {
                flags: PointerFlags::DOWN | PointerFlags::LEFT_BUTTON,
                number_of_wheel_rotation_units: 0,
                x_position: 12,
                y_position: 34,
            }),
        ),
        (
            InputEvent::Mouse {
                flags: PTRFLAGS_BUTTON2,
                wheel_units: 0,
                x: 12,
                y: 34,
            },
            FastPathInputEvent::MouseEvent(MousePdu {
                flags: PointerFlags::RIGHT_BUTTON,
                number_of_wheel_rotation_units: 0,
                x_position: 12,
                y_position: 34,
            }),
        ),
        (
            InputEvent::Mouse {
                flags: PTRFLAGS_WHEEL,
                wheel_units: 120,
                x: 100,
                y: 200,
            },
            FastPathInputEvent::MouseEvent(MousePdu {
                flags: PointerFlags::VERTICAL_WHEEL,
                number_of_wheel_rotation_units: 120,
                x_position: 100,
                y_position: 200,
            }),
        ),
        (
            InputEvent::Mouse {
                flags: PTRFLAGS_WHEEL,
                wheel_units: -120,
                x: 100,
                y: 200,
            },
            FastPathInputEvent::MouseEvent(MousePdu {
                flags: PointerFlags::VERTICAL_WHEEL,
                number_of_wheel_rotation_units: -120,
                x_position: 100,
                y_position: 200,
            }),
        ),
        (
            InputEvent::MouseX {
                flags: PTRXFLAGS_DOWN | PTRXFLAGS_BUTTON1,
                x: 7,
                y: 9,
            },
            FastPathInputEvent::MouseEventEx(MouseXPdu {
                flags: PointerXFlags::DOWN | PointerXFlags::BUTTON1,
                x_position: 7,
                y_position: 9,
            }),
        ),
    ]
}

#[test]
fn fastpath_input_pdus_match_ironrdp_byte_for_byte() {
    let pairs = event_pairs();

    // Each event alone in a PDU…
    for (i, (ours, theirs)) in pairs.iter().enumerate() {
        let our_pdu = input::encode_fastpath_input(std::slice::from_ref(ours));
        let their_pdu =
            iron_encode_vec(&FastPathInput::new(vec![*theirs]).unwrap()).unwrap();
        assert_eq!(our_pdu, their_pdu, "event {i} diverged as a single-event PDU");
    }

    // …and the whole mix batched into one PDU (numEvents in the header).
    let ours: Vec<InputEvent> = pairs.iter().map(|(o, _)| *o).collect();
    let theirs: Vec<FastPathInputEvent> = pairs.iter().map(|(_, t)| *t).collect();
    let our_pdu = input::encode_fastpath_input(&ours);
    let their_pdu = iron_encode_vec(&FastPathInput::new(theirs).unwrap()).unwrap();
    assert_eq!(our_pdu, their_pdu, "batched PDU diverged");
}

#[test]
fn fastpath_explicit_count_and_long_length_match_ironrdp() {
    // 16 events forces the explicit numEvents byte; 200 forces the two-byte length too.
    for n in [16usize, 200] {
        let ours = vec![
            InputEvent::Mouse {
                flags: PTRFLAGS_MOVE,
                wheel_units: 0,
                x: 1,
                y: 2,
            };
            n
        ];
        let theirs = vec![
            FastPathInputEvent::MouseEvent(MousePdu {
                flags: PointerFlags::MOVE,
                number_of_wheel_rotation_units: 0,
                x_position: 1,
                y_position: 2,
            });
            n
        ];
        let our_pdu = input::encode_fastpath_input(&ours);
        let their_pdu = iron_encode_vec(&FastPathInput::new(theirs).unwrap()).unwrap();
        assert_eq!(our_pdu, their_pdu, "{n}-event PDU diverged");
    }
}

#[test]
fn slowpath_input_body_matches_ironrdp_byte_for_byte() {
    let ours = [
        InputEvent::Sync {
            toggle_flags: SYNC_NUM_LOCK,
        },
        InputEvent::ScanCode {
            code: 0x10,
            release: false,
            extended: false,
            extended1: false,
        },
        InputEvent::ScanCode {
            code: 0x10,
            release: true,
            extended: true,
            extended1: false,
        },
        InputEvent::Mouse {
            flags: PTRFLAGS_DOWN | PTRFLAGS_BUTTON1,
            wheel_units: 0,
            x: 320,
            y: 240,
        },
        InputEvent::Mouse {
            flags: PTRFLAGS_WHEEL,
            wheel_units: -120,
            x: 320,
            y: 240,
        },
        InputEvent::MouseX {
            flags: PTRXFLAGS_DOWN | PTRXFLAGS_BUTTON1,
            x: 3,
            y: 4,
        },
    ];
    let theirs = InputEventPdu(vec![
        IronInputEvent::Sync(SyncPdu {
            flags: SyncToggleFlags::NUM_LOCK,
        }),
        IronInputEvent::ScanCode(ScanCodePdu {
            flags: SpKeyboardFlags::empty(),
            key_code: 0x10,
        }),
        IronInputEvent::ScanCode(ScanCodePdu {
            flags: SpKeyboardFlags::RELEASE | SpKeyboardFlags::EXTENDED,
            key_code: 0x10,
        }),
        IronInputEvent::Mouse(MousePdu {
            flags: PointerFlags::DOWN | PointerFlags::LEFT_BUTTON,
            number_of_wheel_rotation_units: 0,
            x_position: 320,
            y_position: 240,
        }),
        IronInputEvent::Mouse(MousePdu {
            flags: PointerFlags::VERTICAL_WHEEL,
            number_of_wheel_rotation_units: -120,
            x_position: 320,
            y_position: 240,
        }),
        IronInputEvent::MouseX(MouseXPdu {
            flags: PointerXFlags::DOWN | PointerXFlags::BUTTON1,
            x_position: 3,
            y_position: 4,
        }),
    ]);
    assert_eq!(
        input::encode_slowpath_input_body(&ours),
        iron_encode_vec(&theirs).unwrap(),
        "slow-path TS_INPUT_PDU_DATA body diverged"
    );
}
