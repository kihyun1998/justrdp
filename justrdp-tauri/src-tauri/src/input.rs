//! Frontend input event normalisation.
//!
//! The webview ships JSON-shaped [`InputEvent`]s into the Tauri
//! command boundary. Before they reach `AsyncRdpClient`, they pass
//! through [`translate`] which validates them and converts the
//! frontend-flavoured shape (button-as-`u8`, code-as-raw-byte) into
//! a typed [`InputAction`] using `justrdp-input` enums.
//!
//! Keeping translation as a pure function makes it the single
//! testable seam — no tokio runtime, no `AsyncRdpClient` mock needed.

use justrdp_input::{MouseButton, Scancode};
use serde::Deserialize;

/// Frontend-shaped input event. One enum so we keep a single
/// `send_input` Tauri command instead of four overlapping ones.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InputEvent {
    /// `code` is the 8-bit AT/PS-2 scancode; `extended` carries the
    /// E0 prefix bit (arrow keys, right-side modifiers, etc.).
    Key { code: u8, extended: bool, pressed: bool },
    MouseMove { x: u16, y: u16 },
    /// `button`: 0=Left 1=Right 2=Middle 3=X1 4=X2.
    MouseButton { button: u8, pressed: bool, x: u16, y: u16 },
    Wheel { delta: i16, horizontal: bool, x: u16, y: u16 },
    /// Unicode keyboard event. `codepoint` is a UTF-32 code unit;
    /// values ≥ U+10000 (supplementary plane / surrogates) are
    /// rejected because the underlying RDP wire format is BMP-only.
    Unicode { codepoint: u32, pressed: bool },
}

/// Validated, RDP-shaped input action. Constructed only via
/// [`translate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputAction {
    Key { scancode: Scancode, pressed: bool },
    MouseMove { x: u16, y: u16 },
    MouseButton { button: MouseButton, pressed: bool, x: u16, y: u16 },
    Wheel { delta: i16, horizontal: bool, x: u16, y: u16 },
    Unicode { ch: char, pressed: bool },
}

/// Failures from [`translate`]. Reserved for inputs the frontend
/// should never have produced — these surface to the embedder as a
/// rejection rather than a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError {
    /// MouseButton index outside 0..=4. The five RDP buttons are
    /// Left / Right / Middle / X1 / X2.
    UnknownMouseButton(u8),
    /// Unicode codepoint that cannot be encoded as a single BMP
    /// `char`: ≥ U+10000 (supplementary plane), unpaired surrogate,
    /// or otherwise invalid.
    NonBmpUnicode(u32),
}

/// Normalise a frontend [`InputEvent`] into a typed [`InputAction`].
pub fn translate(event: InputEvent) -> Result<InputAction, InputError> {
    match event {
        InputEvent::Key { code, extended, pressed } => Ok(InputAction::Key {
            scancode: Scancode::new(code, extended),
            pressed,
        }),
        InputEvent::MouseMove { x, y } => Ok(InputAction::MouseMove { x, y }),
        InputEvent::MouseButton { button, pressed, x, y } => {
            let btn = match button {
                0 => MouseButton::Left,
                1 => MouseButton::Right,
                2 => MouseButton::Middle,
                3 => MouseButton::X1,
                4 => MouseButton::X2,
                other => return Err(InputError::UnknownMouseButton(other)),
            };
            Ok(InputAction::MouseButton { button: btn, pressed, x, y })
        }
        InputEvent::Wheel { delta, horizontal, x, y } => {
            Ok(InputAction::Wheel { delta, horizontal, x, y })
        }
        InputEvent::Unicode { codepoint, pressed } => {
            // BMP only — RDP Unicode keyboard PDU encodes a single
            // UTF-16 unit. Supplementary plane / surrogates rejected.
            if codepoint >= 0x10000 {
                return Err(InputError::NonBmpUnicode(codepoint));
            }
            char::from_u32(codepoint)
                .map(|ch| InputAction::Unicode { ch, pressed })
                .ok_or(InputError::NonBmpUnicode(codepoint))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_key_passes_through_scancode_extended_pressed() {
        let action = translate(InputEvent::Key {
            code: 0x1E,
            extended: false,
            pressed: true,
        })
        .expect("Key arm always Ok");
        assert_eq!(
            action,
            InputAction::Key {
                scancode: Scancode::new(0x1E, false),
                pressed: true,
            }
        );
    }

    #[test]
    fn translate_mouse_button_indices_zero_to_four_map_to_enum_variants() {
        let cases = [
            (0u8, MouseButton::Left),
            (1, MouseButton::Right),
            (2, MouseButton::Middle),
            (3, MouseButton::X1),
            (4, MouseButton::X2),
        ];
        for (button, expected) in cases {
            let action = translate(InputEvent::MouseButton {
                button,
                pressed: true,
                x: 100,
                y: 200,
            })
            .unwrap_or_else(|e| panic!("button {button} should be Ok, got {e:?}"));
            assert_eq!(
                action,
                InputAction::MouseButton {
                    button: expected,
                    pressed: true,
                    x: 100,
                    y: 200,
                },
                "button index {button} did not map to {expected:?}"
            );
        }
    }

    #[test]
    fn translate_mouse_button_index_five_or_more_returns_unknown_error() {
        for bad in [5u8, 6, 99, 255] {
            let result = translate(InputEvent::MouseButton {
                button: bad,
                pressed: true,
                x: 0,
                y: 0,
            });
            assert_eq!(
                result,
                Err(InputError::UnknownMouseButton(bad)),
                "button index {bad} should be UnknownMouseButton"
            );
        }
    }

    #[test]
    fn translate_mouse_move_passes_through_coordinates() {
        let action =
            translate(InputEvent::MouseMove { x: 1023, y: 767 }).expect("MouseMove always Ok");
        assert_eq!(action, InputAction::MouseMove { x: 1023, y: 767 });
    }

    #[test]
    fn translate_wheel_preserves_delta_sign_and_horizontal_flag() {
        let cases = [
            // (delta, horizontal): negative-vertical, positive-vertical, negative-horizontal, positive-horizontal
            (-120i16, false),
            (120, false),
            (-120, true),
            (120, true),
        ];
        for (delta, horizontal) in cases {
            let action = translate(InputEvent::Wheel {
                delta,
                horizontal,
                x: 50,
                y: 60,
            })
            .expect("Wheel always Ok");
            assert_eq!(
                action,
                InputAction::Wheel {
                    delta,
                    horizontal,
                    x: 50,
                    y: 60,
                },
                "wheel ({delta}, h={horizontal}) lost a field"
            );
        }
    }

    #[test]
    fn translate_unicode_bmp_codepoint_constructs_char() {
        // U+AC00 = '가' (Korean Hangul, BMP). Verifies non-ASCII BMP
        // codepoints round-trip — not just ASCII.
        let action = translate(InputEvent::Unicode {
            codepoint: 0xAC00,
            pressed: true,
        })
        .expect("BMP codepoint should be Ok");
        assert_eq!(
            action,
            InputAction::Unicode {
                ch: '가',
                pressed: true,
            }
        );
    }

    #[test]
    fn translate_unicode_supplementary_plane_returns_non_bmp_error() {
        // U+1F600 = '😀' (Emoticons block, supplementary plane).
        // The RDP Unicode keyboard PDU is BMP-only.
        let result = translate(InputEvent::Unicode {
            codepoint: 0x1F600,
            pressed: true,
        });
        assert_eq!(result, Err(InputError::NonBmpUnicode(0x1F600)));
    }

    #[test]
    fn translate_unicode_unpaired_surrogate_returns_non_bmp_error() {
        // U+D800 = high surrogate, never valid as a standalone char.
        // `char::from_u32` rejects it; we surface that as NonBmpUnicode.
        let result = translate(InputEvent::Unicode {
            codepoint: 0xD800,
            pressed: true,
        });
        assert_eq!(result, Err(InputError::NonBmpUnicode(0xD800)));
    }
}
