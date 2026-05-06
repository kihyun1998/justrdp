#![forbid(unsafe_code)]

//! Pure translation: [`ActiveStageOutput`] → [`SessionEvent`] + response
//! frames.
//!
//! This module exists to lift the translation logic out of
//! [`ActiveSession::next_events`](crate::ActiveSession::next_events).  The
//! pump method previously did five things in one body — receive a frame,
//! drive the stage, translate outputs, dispatch SVC channels, write
//! response frames back over the transport.  By moving the
//! translate-and-dispatch step into a *pure* function (no I/O, only
//! `&mut SvcChannelSet` for channel state), unit tests can exercise:
//!
//! * the 1:1 mapping between every [`ActiveStageOutput`] variant and the
//!   [`SessionEvent`] / response-frame it produces,
//! * the SVC dispatch fork (claimed channel → frames absorbed; unclaimed
//!   → passthrough as [`SessionEvent::Channel`]),
//! * boundary cases like the post-§5.6.6 `LockKeys::from_flags` decode,
//!
//! all without spinning up a transport mock or building real wire frames.

use alloc::format;
use alloc::vec::Vec;

use justrdp_input::LockKeys;
use justrdp_session::{ActiveStageOutput, DeactivationReactivation};
use justrdp_svc::StaticChannelSet as SvcChannelSet;

use crate::driver::DriverError;
use crate::session::{PointerEvent, SessionEvent};

/// Result of translating a batch of [`ActiveStageOutput`].
///
/// `events` are the user-visible events the embedder receives from
/// [`ActiveSession::next_events`](crate::ActiveSession::next_events).
/// `response_frames` are MCS-wrapped bytes the wrapper must write back
/// over the transport before returning the events; the order across both
/// vecs reflects the order of the original outputs (response frames in
/// the order they were emitted, events in the order they were emitted).
#[derive(Debug, Default)]
pub(crate) struct Translation {
    pub events: Vec<SessionEvent>,
    pub response_frames: Vec<Vec<u8>>,
}

/// Translate a batch of [`ActiveStageOutput`] from the protocol state
/// machine into the events the embedder sees plus any wire frames that
/// must be written back over the transport.
///
/// `svc_set` carries channel-processor state (mutated in place when an
/// inbound `ChannelData` is dispatched to a registered SVC processor —
/// `process_incoming` advances each processor's reassembly buffers and
/// emits any reply frames).  `user_channel_id` is the local MCS user
/// channel id; SVC processors need it to address responses correctly.
/// `current_share_id` is the wrapper-tracked share id, surfaced as the
/// payload of [`SessionEvent::Reactivation`] when the stage emits
/// `ServerReactivation` (which does not carry the new id itself — see
/// the inline note below).
pub(crate) fn translate_outputs(
    outputs: Vec<ActiveStageOutput>,
    svc_set: &mut SvcChannelSet,
    user_channel_id: u16,
    current_share_id: u32,
) -> Result<Translation, DriverError> {
    let mut out = Translation::default();
    out.events.reserve(outputs.len());

    for output in outputs {
        match output {
            ActiveStageOutput::ResponseFrame(bytes) => {
                out.response_frames.push(bytes);
            }
            ActiveStageOutput::GraphicsUpdate { update_code, data } => {
                out.events.push(SessionEvent::Graphics { update_code, data });
            }
            ActiveStageOutput::PointerDefault => {
                out.events.push(SessionEvent::Pointer(PointerEvent::Default));
            }
            ActiveStageOutput::PointerHidden => {
                out.events.push(SessionEvent::Pointer(PointerEvent::Hidden));
            }
            ActiveStageOutput::PointerPosition { x, y } => {
                out.events
                    .push(SessionEvent::Pointer(PointerEvent::Position { x, y }));
            }
            ActiveStageOutput::PointerBitmap { pointer_type, data } => {
                out.events.push(SessionEvent::Pointer(PointerEvent::Bitmap {
                    pointer_type,
                    data,
                }));
            }
            ActiveStageOutput::DeactivateAll(DeactivationReactivation { share_id }) => {
                out.events.push(SessionEvent::Reactivation { share_id });
            }
            ActiveStageOutput::ServerReactivation { .. } => {
                // ServerReactivation does not carry the new share id
                // (it is read from the embedded DemandActive body that
                // the stage will process on the *next* frame).  We
                // surface the *current* (pre-reactivation) id so the
                // embedder can correlate before/after by tracking
                // changes across calls — passed in by the caller.
                out.events.push(SessionEvent::Reactivation {
                    share_id: current_share_id,
                });
            }
            ActiveStageOutput::Terminate(reason) => {
                out.events.push(SessionEvent::Terminated(reason));
            }
            ActiveStageOutput::SaveSessionInfo { data } => {
                out.events.push(SessionEvent::SaveSessionInfo(data));
            }
            ActiveStageOutput::ChannelData { channel_id, data } => {
                if svc_set.get_by_channel_id(channel_id).is_some() {
                    let frames = svc_set
                        .process_incoming(channel_id, &data, user_channel_id)
                        .map_err(|e| DriverError::Channel(format!("{e:?}")))?;
                    out.response_frames.extend(frames);
                } else {
                    out.events.push(SessionEvent::Channel { channel_id, data });
                }
            }
            ActiveStageOutput::ServerMonitorLayout { monitors } => {
                out.events.push(SessionEvent::MonitorLayout(monitors));
            }
            ActiveStageOutput::KeyboardIndicators { led_flags } => {
                // §5.6.6 cleanup: bit-decode happens here so embedders
                // see the four bools directly.
                out.events.push(SessionEvent::KeyboardIndicators(
                    LockKeys::from_flags(led_flags),
                ));
            }
            ActiveStageOutput::KeyboardImeStatus {
                ime_state,
                ime_conv_mode,
            } => {
                out.events.push(SessionEvent::KeyboardImeStatus {
                    ime_state,
                    ime_conv_mode,
                });
            }
            ActiveStageOutput::PlaySound {
                duration_ms,
                frequency_hz,
            } => {
                out.events.push(SessionEvent::PlaySound {
                    duration_ms,
                    frequency_hz,
                });
            }
            ActiveStageOutput::SuppressOutput {
                allow_display_updates,
                rect,
            } => {
                out.events.push(SessionEvent::SuppressOutput {
                    allow_display_updates,
                    rect,
                });
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::vec;

    use justrdp_pdu::rdp::fast_path::FastPathUpdateType;

    /// Helper: fresh empty SVC set for tests that don't exercise SVC dispatch.
    fn empty_svc() -> SvcChannelSet {
        SvcChannelSet::new()
    }

    // ── Pointer arms ───────────────────────────────────────────────────

    #[test]
    fn pointer_default_translates_to_pointer_default_event() {
        let outputs = vec![ActiveStageOutput::PointerDefault];
        let mut svc = empty_svc();
        let t = translate_outputs(outputs, &mut svc, 1001, 0x10ea).unwrap();
        assert!(t.response_frames.is_empty());
        assert_eq!(t.events, vec![SessionEvent::Pointer(PointerEvent::Default)]);
    }

    #[test]
    fn pointer_position_carries_coords() {
        let outputs = vec![ActiveStageOutput::PointerPosition { x: 42, y: 99 }];
        let mut svc = empty_svc();
        let t = translate_outputs(outputs, &mut svc, 1001, 0x10ea).unwrap();
        assert_eq!(
            t.events,
            vec![SessionEvent::Pointer(PointerEvent::Position { x: 42, y: 99 })],
        );
    }

    #[test]
    fn pointer_bitmap_carries_payload() {
        let outputs = vec![ActiveStageOutput::PointerBitmap {
            pointer_type: 7,
            data: vec![0xAA, 0xBB],
        }];
        let mut svc = empty_svc();
        let t = translate_outputs(outputs, &mut svc, 1001, 0x10ea).unwrap();
        match &t.events[0] {
            SessionEvent::Pointer(PointerEvent::Bitmap { pointer_type, data }) => {
                assert_eq!(*pointer_type, 7);
                assert_eq!(*data, vec![0xAA, 0xBB]);
            }
            other => panic!("expected Pointer(Bitmap), got {other:?}"),
        }
    }

    // ── Response frames ────────────────────────────────────────────────

    #[test]
    fn response_frame_goes_to_response_frames_not_events() {
        let outputs = vec![ActiveStageOutput::ResponseFrame(vec![0x01, 0x02, 0x03])];
        let mut svc = empty_svc();
        let t = translate_outputs(outputs, &mut svc, 1001, 0x10ea).unwrap();
        assert!(t.events.is_empty());
        assert_eq!(t.response_frames, vec![vec![0x01, 0x02, 0x03]]);
    }

    #[test]
    fn interleaved_outputs_preserve_per_kind_order() {
        let outputs = vec![
            ActiveStageOutput::ResponseFrame(vec![0x01]),
            ActiveStageOutput::PointerDefault,
            ActiveStageOutput::ResponseFrame(vec![0x02]),
            ActiveStageOutput::PointerHidden,
        ];
        let mut svc = empty_svc();
        let t = translate_outputs(outputs, &mut svc, 1001, 0x10ea).unwrap();
        assert_eq!(t.response_frames, vec![vec![0x01], vec![0x02]]);
        assert_eq!(
            t.events,
            vec![
                SessionEvent::Pointer(PointerEvent::Default),
                SessionEvent::Pointer(PointerEvent::Hidden),
            ],
        );
    }

    // ── ChannelData passthrough (no SVC processor registered) ──────────

    #[test]
    fn channel_data_with_no_svc_processor_passes_through_as_event() {
        let outputs = vec![ActiveStageOutput::ChannelData {
            channel_id: 1004,
            data: vec![0xDE, 0xAD],
        }];
        let mut svc = empty_svc();
        let t = translate_outputs(outputs, &mut svc, 1001, 0x10ea).unwrap();
        assert!(t.response_frames.is_empty());
        assert_eq!(
            t.events,
            vec![SessionEvent::Channel {
                channel_id: 1004,
                data: vec![0xDE, 0xAD],
            }],
        );
    }

    // ── KeyboardIndicators decode (§5.6.6) ─────────────────────────────

    #[test]
    fn keyboard_indicators_decodes_lock_keys_from_flags() {
        // Bits per MS-RDPBCGR §2.2.8.2.2.1: bit 0 = scroll, bit 1 = num,
        // bit 2 = caps, bit 3 = kana.  0b1010 = num + kana.
        let outputs = vec![ActiveStageOutput::KeyboardIndicators { led_flags: 0b1010 }];
        let mut svc = empty_svc();
        let t = translate_outputs(outputs, &mut svc, 1001, 0x10ea).unwrap();
        match &t.events[0] {
            SessionEvent::KeyboardIndicators(lk) => {
                assert!(!lk.scroll_lock);
                assert!(lk.num_lock);
                assert!(!lk.caps_lock);
                assert!(lk.kana_lock);
            }
            other => panic!("expected KeyboardIndicators, got {other:?}"),
        }
    }

    // ── Graphics ───────────────────────────────────────────────────────

    #[test]
    fn graphics_update_carries_update_code_and_data() {
        let outputs = vec![ActiveStageOutput::GraphicsUpdate {
            update_code: FastPathUpdateType::Bitmap,
            data: vec![0x01, 0x02],
        }];
        let mut svc = empty_svc();
        let t = translate_outputs(outputs, &mut svc, 1001, 0x10ea).unwrap();
        match &t.events[0] {
            SessionEvent::Graphics { update_code, data } => {
                assert_eq!(*update_code, FastPathUpdateType::Bitmap);
                assert_eq!(*data, vec![0x01, 0x02]);
            }
            other => panic!("expected Graphics, got {other:?}"),
        }
    }

    // ── Empty input ────────────────────────────────────────────────────

    #[test]
    fn empty_outputs_produce_empty_translation() {
        let outputs = vec![];
        let mut svc = empty_svc();
        let t = translate_outputs(outputs, &mut svc, 1001, 0x10ea).unwrap();
        assert!(t.events.is_empty());
        assert!(t.response_frames.is_empty());
    }

    // ── DeactivateAll vs ServerReactivation ────────────────────────────

    #[test]
    fn deactivate_all_carries_share_id_from_payload() {
        let outputs = vec![ActiveStageOutput::DeactivateAll(
            DeactivationReactivation { share_id: 0xCAFE },
        )];
        let mut svc = empty_svc();
        let t = translate_outputs(outputs, &mut svc, 1001, 0x10ea).unwrap();
        assert_eq!(t.events, vec![SessionEvent::Reactivation { share_id: 0xCAFE }]);
    }

    // ── SuppressOutput ─────────────────────────────────────────────────

    #[test]
    fn suppress_output_carries_rect_and_flag() {
        let outputs = vec![ActiveStageOutput::SuppressOutput {
            allow_display_updates: true,
            rect: Some((0, 0, 1024, 768)),
        }];
        let mut svc = empty_svc();
        let t = translate_outputs(outputs, &mut svc, 1001, 0x10ea).unwrap();
        match &t.events[0] {
            SessionEvent::SuppressOutput {
                allow_display_updates,
                rect,
            } => {
                assert!(*allow_display_updates);
                assert_eq!(*rect, Some((0, 0, 1024, 768)));
            }
            other => panic!("expected SuppressOutput, got {other:?}"),
        }
    }
}
