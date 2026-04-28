#![forbid(unsafe_code)]

//! Active-session pump.
//!
//! After [`WebClient::connect`] hands off a [`ConnectionResult`] +
//! [`WebTransport`], the caller wraps both in [`ActiveSession`] to drive
//! the post-handshake message loop. The pump:
//!
//! * reframes inbound bytes (TPKT slow-path **and** fast-path,
//!   discriminated by the first byte just like [`TpktHint`]),
//! * feeds each complete frame to [`ActiveStage::process`],
//! * auto-flushes any [`ActiveStageOutput::ResponseFrame`] back over the
//!   transport (the caller never sees these — they're protocol plumbing),
//! * surfaces user-visible state changes as [`SessionEvent`].
//!
//! This commit (S3a) only ships the pump + event surface. Bitmap decoding
//! and the [`FrameSink`] trait land in S3b together with the JS facade
//! evolution (a stateful `JsClient` handle).
//!
//! [`WebClient::connect`]: crate::driver::WebClient::connect
//! [`TpktHint`]: justrdp_pdu::tpkt::TpktHint
//! [`FrameSink`]: crate::FrameSink

use alloc::vec::Vec;

use justrdp_connector::ConnectionResult;
use justrdp_pdu::rdp::fast_path::{FastPathInputEvent, FastPathUpdateType};
use justrdp_pdu::rdp::finalization::{MonitorLayoutEntry, SaveSessionInfoData};
use justrdp_pdu::tpkt::TpktHint;
use justrdp_session::{
    ActiveStage, ActiveStageOutput, DeactivationReactivation, GracefulDisconnectReason,
    SessionConfig,
};

use crate::driver::{recv_until_pdu, DriverError};
use crate::transport::WebTransport;

static TPKT_HINT: TpktHint = TpktHint;

/// User-facing event surface of the active session.
///
/// Every variant maps to a non-trivial [`ActiveStageOutput`] that the
/// embedder may want to observe. Plumbing-only outputs (response frames
/// that we just bounce back to the server) are consumed inside the pump
/// and never reach the embedder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// Server pushed a graphics update for the screen surface. `data` is
    /// the raw fast-path update payload — embedders that want pixels
    /// must run a decoder (S3b will wire one).
    Graphics {
        update_code: FastPathUpdateType,
        data: Vec<u8>,
    },
    /// Pointer state change (default / hidden / position / new bitmap).
    Pointer(PointerEvent),
    /// Server sent a virtual-channel PDU (clipboard, drive, sound…).
    Channel { channel_id: u16, data: Vec<u8> },
    /// Server requested a deactivation–reactivation cycle. The active
    /// session is no longer valid until the caller drives a fresh
    /// capabilities exchange. **S3a does not auto-handle this** — it is
    /// surfaced for awareness so the embedder can show "reconnecting".
    Reactivation { share_id: u32 },
    /// Server sent Save Session Info (logon notification, ARC cookie,
    /// etc.). Forwarded verbatim so the embedder can feed it back into
    /// reconnect logic.
    SaveSessionInfo(SaveSessionInfoData),
    /// Server reported a new monitor layout (mid-session).
    MonitorLayout(Vec<MonitorLayoutEntry>),
    /// Server toggled keyboard indicator LEDs.
    KeyboardIndicators { led_flags: u16 },
    /// Server toggled IME state.
    KeyboardImeStatus { ime_state: u32, ime_conv_mode: u32 },
    /// Server asked the client to play a beep.
    PlaySound { duration_ms: u32, frequency_hz: u32 },
    /// Server asked the client to (un)pause display painting.
    SuppressOutput {
        allow_display_updates: bool,
        rect: Option<(u16, u16, u16, u16)>,
    },
    /// Session ended cleanly.
    Terminated(GracefulDisconnectReason),
}

/// Sub-type of [`SessionEvent::Pointer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerEvent {
    Default,
    Hidden,
    Position { x: u16, y: u16 },
    Bitmap { pointer_type: u16, data: Vec<u8> },
}

/// Active-session driver paired with a [`WebTransport`].
pub struct ActiveSession<T: WebTransport> {
    transport: T,
    stage: ActiveStage,
    /// Inbound byte accumulator. RDP framing is byte-stream, but the
    /// transport is message-oriented; the buffer absorbs message
    /// boundaries that don't align with PDU boundaries.
    scratch: Vec<u8>,
}

impl<T: WebTransport> ActiveSession<T> {
    /// Construct from a successful handshake result.
    ///
    /// `result` is the [`ConnectionResult`] returned by
    /// [`WebClient::connect`]. The session config (channel IDs, share id,
    /// I/O channel) is taken from there.
    ///
    /// [`WebClient::connect`]: crate::driver::WebClient::connect
    pub fn new(transport: T, result: &ConnectionResult) -> Self {
        let config = SessionConfig {
            io_channel_id: result.io_channel_id,
            user_channel_id: result.user_channel_id,
            share_id: result.share_id,
            channel_ids: result.channel_ids.clone(),
        };
        Self {
            transport,
            stage: ActiveStage::new(config),
            scratch: Vec::new(),
        }
    }

    /// Reborrow the underlying transport.
    pub fn transport(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Surrender the transport (e.g. to drop the session and reconnect).
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Read one frame from the transport, process it via [`ActiveStage`],
    /// auto-flush response frames, and return the user-facing events.
    ///
    /// One frame can yield zero or more events — a slow-path Demand
    /// Active during reactivation produces several outputs in a single
    /// call. The Vec preserves the order returned by [`ActiveStage`].
    pub async fn next_events(&mut self) -> Result<Vec<SessionEvent>, DriverError> {
        let n = recv_until_pdu(&mut self.transport, &TPKT_HINT, &mut self.scratch).await?;
        let frame: Vec<u8> = self.scratch[..n].to_vec();
        self.scratch.drain(..n);

        let outputs = self.stage.process(&frame)?;
        let mut events: Vec<SessionEvent> = Vec::with_capacity(outputs.len());
        for output in outputs {
            match output {
                ActiveStageOutput::ResponseFrame(bytes) => {
                    self.transport.send(&bytes).await?;
                }
                ActiveStageOutput::GraphicsUpdate { update_code, data } => {
                    events.push(SessionEvent::Graphics { update_code, data });
                }
                ActiveStageOutput::PointerDefault => {
                    events.push(SessionEvent::Pointer(PointerEvent::Default));
                }
                ActiveStageOutput::PointerHidden => {
                    events.push(SessionEvent::Pointer(PointerEvent::Hidden));
                }
                ActiveStageOutput::PointerPosition { x, y } => {
                    events.push(SessionEvent::Pointer(PointerEvent::Position { x, y }));
                }
                ActiveStageOutput::PointerBitmap { pointer_type, data } => {
                    events.push(SessionEvent::Pointer(PointerEvent::Bitmap {
                        pointer_type,
                        data,
                    }));
                }
                ActiveStageOutput::DeactivateAll(DeactivationReactivation { share_id }) => {
                    events.push(SessionEvent::Reactivation { share_id });
                }
                ActiveStageOutput::ServerReactivation { .. } => {
                    // ServerReactivation does not carry the new share_id
                    // (it is read from the embedded DemandActive body);
                    // we surface the *current* (pre-reactivation) id so
                    // the embedder can correlate before/after by tracking
                    // changes across calls.
                    events.push(SessionEvent::Reactivation {
                        share_id: self.stage.config().share_id,
                    });
                }
                ActiveStageOutput::Terminate(reason) => {
                    events.push(SessionEvent::Terminated(reason));
                }
                ActiveStageOutput::SaveSessionInfo { data } => {
                    events.push(SessionEvent::SaveSessionInfo(data));
                }
                ActiveStageOutput::ChannelData { channel_id, data } => {
                    events.push(SessionEvent::Channel { channel_id, data });
                }
                ActiveStageOutput::ServerMonitorLayout { monitors } => {
                    events.push(SessionEvent::MonitorLayout(monitors));
                }
                ActiveStageOutput::KeyboardIndicators { led_flags } => {
                    events.push(SessionEvent::KeyboardIndicators { led_flags });
                }
                ActiveStageOutput::KeyboardImeStatus {
                    ime_state,
                    ime_conv_mode,
                } => {
                    events.push(SessionEvent::KeyboardImeStatus {
                        ime_state,
                        ime_conv_mode,
                    });
                }
                ActiveStageOutput::PlaySound {
                    duration_ms,
                    frequency_hz,
                } => {
                    events.push(SessionEvent::PlaySound {
                        duration_ms,
                        frequency_hz,
                    });
                }
                ActiveStageOutput::SuppressOutput {
                    allow_display_updates,
                    rect,
                } => {
                    events.push(SessionEvent::SuppressOutput {
                        allow_display_updates,
                        rect,
                    });
                }
            }
        }
        Ok(events)
    }

    /// Encode and send a batch of fast-path input events (keyboard,
    /// mouse). The encoder lives in `justrdp-session`; we just frame and
    /// forward.
    pub async fn send_input(
        &mut self,
        events: &[FastPathInputEvent],
    ) -> Result<(), DriverError> {
        let frame = self.stage.encode_input_events(events)?;
        self.transport.send(&frame).await?;
        Ok(())
    }

    /// Send a graceful shutdown request (Shutdown Request Denied response
    /// from the server still surfaces as `Terminated(ShutdownDenied)`).
    pub async fn shutdown(&mut self) -> Result<(), DriverError> {
        let frame = self.stage.encode_shutdown_request()?;
        self.transport.send(&frame).await?;
        Ok(())
    }

    /// Send an MCS Disconnect Provider Ultimatum (immediate disconnect,
    /// no graceful handshake).
    pub async fn disconnect(&mut self) -> Result<(), DriverError> {
        let frame = self.stage.encode_disconnect()?;
        self.transport.send(&frame).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;
    use alloc::collections::VecDeque;
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::RefCell;

    use justrdp_connector::ConnectionResult;
    use justrdp_pdu::x224::SecurityProtocol;

    fn block_on<F: core::future::Future>(f: F) -> F::Output {
        pollster::block_on(f)
    }

    fn fake_result() -> ConnectionResult {
        ConnectionResult {
            io_channel_id: 1003,
            user_channel_id: 1001,
            share_id: 0x0001_03ea,
            server_capabilities: Vec::new(),
            channel_ids: vec![],
            selected_protocol: SecurityProtocol::RDP,
            session_id: 0,
            server_monitor_layout: None,
            server_arc_cookie: None,
            server_redirection: None,
        }
    }

    /// `TpktHint` looks at byte 0 to discriminate slow vs fast-path. A
    /// fast-path frame with the high length bit clear has total size
    /// equal to byte 1.
    fn build_fast_path_frame(payload: &[u8]) -> Vec<u8> {
        // action=0 (server output), num_events=0, flags=0 → byte 0 = 0x00
        // length1 = total size, MSB clear so it's the only length byte.
        let total = 2 + payload.len();
        assert!(total < 0x80, "test helper covers single-byte length only");
        let mut frame = Vec::with_capacity(total);
        frame.push(0x00);
        frame.push(total as u8);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn next_events_drains_scratch_after_processing() {
        // Smoke test: send a malformed fast-path frame and confirm the
        // session bubbles the SessionError up as DriverError::Session,
        // *and* that scratch is drained so subsequent calls don't loop
        // on the same bad bytes.
        block_on(async {
            let mut t = MockTransport::new();
            t.push_recv(build_fast_path_frame(&[0xFF, 0xFF])); // bogus payload
            let result = fake_result();
            let mut session = ActiveSession::new(t, &result);

            let outcome = session.next_events().await;
            // Either we get back a typed Session error (decode/protocol),
            // or we got a benign empty event list — both are acceptable
            // here; what we really want to verify is that the scratch
            // was drained (next call will read from the empty queue and
            // hit ConnectionClosed, not loop forever).
            let _ = outcome;
            let next = session.next_events().await.unwrap_err();
            match next {
                DriverError::Transport(e) => {
                    assert_eq!(e.kind(), crate::TransportErrorKind::ConnectionClosed);
                }
                other => panic!("expected Transport(ConnectionClosed), got {other:?}"),
            }
        });
    }

    /// `next_events` must propagate transport EOF as `Transport(...)`,
    /// not as a connector or session error.
    #[test]
    fn next_events_propagates_transport_eof() {
        block_on(async {
            let t = MockTransport::new();
            let result = fake_result();
            let mut session = ActiveSession::new(t, &result);
            let err = session.next_events().await.unwrap_err();
            match err {
                DriverError::Transport(e) => {
                    assert_eq!(e.kind(), crate::TransportErrorKind::ConnectionClosed);
                }
                other => panic!("expected Transport, got {other:?}"),
            }
        });
    }

    /// `into_transport` recovers ownership so the caller can reuse the
    /// socket (e.g. fold into a reconnect attempt).
    #[test]
    fn into_transport_returns_owned_transport() {
        let t = MockTransport::new();
        let result = fake_result();
        let session = ActiveSession::new(t, &result);
        let recovered = session.into_transport();
        // type-check only; no methods called — the recovered value's
        // type is the original generic T which is what the API contract
        // promises.
        let _: MockTransport = recovered;
    }

    /// Build a session whose transport observes both directions, push a
    /// minimal fast-path frame at it, and confirm:
    ///   * `next_events` consumes the input,
    ///   * any auto-flushed ResponseFrame ends up in `sent` (none here
    ///     because a 2-byte fast-path Synchronize emits no response),
    ///   * scratch is fully drained.
    #[test]
    fn next_events_handles_minimal_fast_path_frame() {
        block_on(async {
            // Smallest legal fast-path output update — Synchronize:
            //   fp_header   = 0x00 (action=0, numEvents=0, flags=0)
            //   fp_length1  = 0x05 (total frame size, MSB clear)
            //   updateCode  = 0x03 (FASTPATH_UPDATETYPE_SYNCHRONIZE,
            //                       MS-RDPBCGR 2.2.9.1.2.1.1)
            //   size        = 0x0000 (LE u16, no payload)
            // total = 5 bytes.
            let frame = vec![0x00, 0x05, 0x03, 0x00, 0x00];
            let shared = Rc::new(RefCell::new(SharedSink {
                sent: Vec::new(),
                recv: VecDeque::from([Ok(frame)]),
            }));
            let transport = SinkTransport {
                shared: Rc::clone(&shared),
            };
            let result = fake_result();
            let mut session = ActiveSession::new(transport, &result);

            let events = session.next_events().await.unwrap();
            // ActiveStage surfaces the Synchronize update as a Graphics
            // event with empty data and `Synchronize` updateCode — the
            // pump itself doesn't filter it (S3a leaves filtering to
            // the embedder, which usually wants a "kick the rendering
            // loop" hook on resync).
            assert_eq!(events.len(), 1, "expected one event, got {events:?}");
            match &events[0] {
                SessionEvent::Graphics { update_code, data } => {
                    assert_eq!(*update_code, FastPathUpdateType::Synchronize);
                    assert!(data.is_empty(), "synchronize carries no payload");
                }
                other => panic!("expected Graphics(Synchronize), got {other:?}"),
            }
            // No reply frame for synchronize.
            assert!(shared.borrow().sent.is_empty());
        });
    }

    // ── Test helpers ────────────────────────────────────────────────

    #[derive(Debug)]
    struct SinkTransport {
        shared: Rc<RefCell<SharedSink>>,
    }
    #[derive(Debug)]
    struct SharedSink {
        sent: Vec<Vec<u8>>,
        recv: VecDeque<Result<Vec<u8>, crate::TransportError>>,
    }

    impl WebTransport for SinkTransport {
        async fn send(&mut self, bytes: &[u8]) -> Result<(), crate::TransportError> {
            self.shared.borrow_mut().sent.push(bytes.to_vec());
            Ok(())
        }
        async fn recv(&mut self) -> Result<Vec<u8>, crate::TransportError> {
            match self.shared.borrow_mut().recv.pop_front() {
                Some(r) => r,
                None => Err(crate::TransportError::closed("empty")),
            }
        }
        async fn close(&mut self) -> Result<(), crate::TransportError> {
            Ok(())
        }
    }
}
