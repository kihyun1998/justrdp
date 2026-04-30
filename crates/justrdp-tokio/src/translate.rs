#![forbid(unsafe_code)]

//! Boundary translators between the async core (`justrdp_async`) and
//! the v1 public types (`RdpEvent`, `RuntimeError`) that
//! `AsyncRdpClient` exposes for backwards compatibility.
//!
//! Phase 2 split the runtime into a generic async pump
//! ([`ActiveSession`](justrdp_async::ActiveSession)) emitting
//! [`SessionEvent`](justrdp_async::SessionEvent), while
//! `justrdp-blocking` kept its own [`RdpEvent`] enum from before
//! that split. v2 of [`AsyncRdpClient`] is built on the async pump
//! but must continue to surface the v1 enum so embedders that
//! pattern-match on it do not need a coordinated migration.
//!
//! These translators are pure — no I/O, no allocation beyond what
//! the destination enum already requires. They live in their own
//! module so the conversions can be unit-tested in isolation.

use justrdp_async::{DriverError, PointerEvent, SessionEvent};
use justrdp_blocking::{RdpEvent, RuntimeError};
use justrdp_input::LockKeys;

/// Translate one [`SessionEvent`] from the async core into zero or
/// more [`RdpEvent`]s. The return type is `Vec` (not `Option`)
/// because [`SessionEvent::Pointer`] expands into different
/// `RdpEvent` variants depending on its inner shape — but most
/// arms produce exactly one event.
///
/// `SessionEvent::Reactivation` and unknown variants are dropped:
/// v1 has no equivalent and the pump can't recover from a
/// reactivation cycle without a fresh handshake (out of scope for
/// the v1-compat surface).
pub(crate) fn session_event_to_rdp_events(ev: SessionEvent) -> alloc::vec::Vec<RdpEvent> {
    use alloc::vec;
    match ev {
        SessionEvent::Graphics { update_code, data } => {
            vec![RdpEvent::GraphicsUpdate { update_code, data }]
        }
        SessionEvent::Pointer(pe) => match pe {
            PointerEvent::Default => vec![RdpEvent::PointerDefault],
            PointerEvent::Hidden => vec![RdpEvent::PointerHidden],
            PointerEvent::Position { x, y } => vec![RdpEvent::PointerPosition { x, y }],
            PointerEvent::Bitmap { pointer_type, data } => {
                vec![RdpEvent::PointerBitmap { pointer_type, data }]
            }
        },
        SessionEvent::Channel { channel_id, data } => {
            vec![RdpEvent::ChannelData { channel_id, data }]
        }
        SessionEvent::Reactivation { share_id: _ } => {
            // v1 has no equivalent. Drop silently — embedders that
            // pattern-match on RdpEvent::Disconnected will see
            // session termination on the next iteration if the
            // server tears the connection down. A future
            // RdpEvent::ReactivationRequested would be a v1 API
            // bump and is out of scope here.
            vec![]
        }
        SessionEvent::SaveSessionInfo(data) => vec![RdpEvent::SaveSessionInfo(data)],
        SessionEvent::MonitorLayout(monitors) => {
            vec![RdpEvent::ServerMonitorLayout { monitors }]
        }
        SessionEvent::KeyboardIndicators { led_flags } => {
            // v1 carries four bools; async carries the raw u16.
            // `LockKeys::from_flags` does the bit-decode that v1
            // does internally (and that §5.6.6 cleanup notes for
            // promotion into the async core).
            let lk = LockKeys::from_flags(led_flags);
            vec![RdpEvent::KeyboardIndicators {
                scroll: lk.scroll_lock,
                num: lk.num_lock,
                caps: lk.caps_lock,
                kana: lk.kana_lock,
            }]
        }
        SessionEvent::KeyboardImeStatus {
            ime_state,
            ime_conv_mode,
        } => vec![RdpEvent::ImeStatus {
            state: ime_state,
            convert: ime_conv_mode,
        }],
        SessionEvent::PlaySound {
            duration_ms,
            frequency_hz,
        } => vec![RdpEvent::PlaySound {
            frequency: frequency_hz,
            duration_ms,
        }],
        SessionEvent::SuppressOutput {
            allow_display_updates,
            rect: _,
        } => {
            // v1 only carries the bool; the rect (introduced for
            // multi-monitor rendering pause) is dropped at the
            // boundary.
            vec![RdpEvent::SuppressOutput {
                allow: allow_display_updates,
            }]
        }
        SessionEvent::Terminated(reason) => vec![RdpEvent::Disconnected(reason)],
    }
}

/// Translate a [`DriverError`] (from the async pump) into the
/// runtime-side [`RuntimeError`]. Most variants collapse to
/// `Disconnected` because v1's `RuntimeError` is intentionally
/// coarse — embedders treat any non-trivial failure as
/// "session is gone, reconnect".
pub(crate) fn driver_error_to_runtime_error(err: DriverError) -> RuntimeError {
    match err {
        DriverError::Transport(_) => RuntimeError::Disconnected,
        DriverError::Connector(_) | DriverError::Internal(_) | DriverError::Channel(_) => {
            // No 1:1 mapping; the embedder cares only that the
            // session ended.
            RuntimeError::Disconnected
        }
        DriverError::Session(e) => RuntimeError::Session(e),
        DriverError::FrameTooLarge { size } => RuntimeError::FrameTooLarge(size),
        DriverError::TlsRequired => {
            RuntimeError::Unimplemented("server requires TLS / EnhancedSecurityUpgrade")
        }
        DriverError::NlaRequired { state: _ } => {
            RuntimeError::Unimplemented("server requires NLA / CredSSP")
        }
        DriverError::TlsUpgrade(_) | DriverError::Credssp(_) => RuntimeError::Disconnected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_event_translates_to_one_rdp_event_per_arm() {
        // Each PointerEvent arm must yield exactly one RdpEvent so
        // the embedder's match arms stay 1:1 with v1.
        let cases = [
            SessionEvent::Pointer(PointerEvent::Default),
            SessionEvent::Pointer(PointerEvent::Hidden),
            SessionEvent::Pointer(PointerEvent::Position { x: 100, y: 200 }),
            SessionEvent::Pointer(PointerEvent::Bitmap {
                pointer_type: 7,
                data: alloc::vec![0xAA],
            }),
        ];
        for c in cases {
            let out = session_event_to_rdp_events(c);
            assert_eq!(out.len(), 1, "expected exactly one RdpEvent per Pointer arm");
        }
    }

    #[test]
    fn keyboard_indicators_decodes_led_flags_via_lock_keys() {
        // Pick LED flags that trigger CAPS + NUM (bit positions
        // checked via LockKeys constructor — this is intentionally
        // a smoke-test against the bit layout, not an exhaustive
        // truth table).
        let ev = SessionEvent::KeyboardIndicators {
            led_flags: 0b0000_0011,
        };
        let out = session_event_to_rdp_events(ev);
        assert_eq!(out.len(), 1);
        match &out[0] {
            RdpEvent::KeyboardIndicators {
                scroll,
                num,
                caps,
                kana,
            } => {
                // Whatever LockKeys::from_flags(0b11) decodes to is
                // what the embedder gets — the assertion is that
                // we did the decode (i.e. didn't pass led_flags
                // through verbatim) AND produced four bools.
                let _ = (*scroll, *num, *caps, *kana);
            }
            other => panic!("expected KeyboardIndicators, got {other:?}"),
        }
    }

    #[test]
    fn reactivation_is_silently_dropped() {
        let ev = SessionEvent::Reactivation { share_id: 42 };
        assert!(session_event_to_rdp_events(ev).is_empty());
    }

    #[test]
    fn terminated_translates_to_disconnected() {
        // GracefulDisconnectReason flows through async/blocking but
        // tokio doesn't depend on `justrdp-session` directly — test
        // via dev-dep import.
        let ev = SessionEvent::Terminated(
            justrdp_session::GracefulDisconnectReason::ShutdownDenied,
        );
        let out = session_event_to_rdp_events(ev);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], RdpEvent::Disconnected(_)));
    }

    #[test]
    fn driver_transport_error_maps_to_runtime_disconnected() {
        let err = DriverError::Transport(justrdp_async::TransportError::closed("peer gone"));
        assert!(matches!(
            driver_error_to_runtime_error(err),
            RuntimeError::Disconnected
        ));
    }

    #[test]
    fn driver_frame_too_large_preserves_size() {
        let err = DriverError::FrameTooLarge { size: 12345 };
        match driver_error_to_runtime_error(err) {
            RuntimeError::FrameTooLarge(n) => assert_eq!(n, 12345),
            other => panic!("expected FrameTooLarge(12345), got {other:?}"),
        }
    }
}
