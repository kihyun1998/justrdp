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

use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;

use justrdp_connector::ConnectionResult;
use justrdp_input::{
    InputDatabase, LockKeys, MouseButton, Operation, Scancode, MAX_RELEASE_OPS,
};
use justrdp_pdu::rdp::fast_path::{FastPathInputEvent, FastPathUpdateType};
use justrdp_pdu::rdp::finalization::{InclusiveRect, MonitorLayoutEntry, SaveSessionInfoData};
use justrdp_pdu::tpkt::TpktHint;
use justrdp_session::{
    ActiveStage, ActiveStageOutput, DeactivationReactivation, GracefulDisconnectReason,
    SessionConfig,
};
use justrdp_svc::{StaticChannelSet as SvcChannelSet, SvcProcessor};

use crate::driver::{recv_until_pdu, DriverError};
use crate::input::{
    build_mouse_button_event, build_mouse_move_event, build_mouse_wheel_event,
    build_scancode_event, build_sync_event, build_unicode_event,
};
use crate::telemetry::{debug, info, trace};
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
    /// Tracks keyboard / mouse state so the high-level input API can
    /// suppress duplicate presses, replay every held key on focus loss,
    /// and report the cached mouse position. Bypassed by [`Self::send_input`]
    /// (raw fast-path) — that path is still available for callers who
    /// already track input state themselves.
    input_db: InputDatabase,
    /// Static virtual channel processors keyed by MCS channel id. Set
    /// up via [`Self::with_processors`]; otherwise empty and inert.
    /// `next_events` routes inbound `ChannelData` frames here first —
    /// frames a registered processor claims are consumed silently
    /// (with any processor-emitted response frames written back to the
    /// transport) instead of surfacing as [`SessionEvent::Channel`].
    svc_set: SvcChannelSet,
    /// Cached `user_channel_id` for the SVC dispatch path. Mirrors
    /// what `ActiveStage::config()` exposes; cached here so the channel
    /// dispatch loop in `next_events` doesn't have to reach back into
    /// the stage on every frame.
    user_channel_id: u16,
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
            input_db: InputDatabase::new(),
            svc_set: SvcChannelSet::new(),
            user_channel_id: result.user_channel_id,
        }
    }

    /// Build an active session with a pre-populated set of static
    /// virtual channel processors (clipboard, drive, sound, drdynvc,
    /// …). Mirrors `justrdp_blocking::RdpClient::connect_with_processors`.
    ///
    /// The processors must declare channel names that were advertised
    /// in the connector's `Config::static_channels` — otherwise the
    /// server never allocates an MCS id for them and they sit idle
    /// (no error; matches blocking semantics).
    ///
    /// This call drives `start_all` on every processor with an
    /// allocated id, encoding any initial frames they want to emit and
    /// flushing them through `transport.send` before returning. Errors
    /// at this stage surface as [`DriverError::Channel`] / [`DriverError::Transport`].
    ///
    /// To use Dynamic Virtual Channels, wrap your DvcProcessor instances
    /// in a `DrdynvcClient` and box that as the `drdynvc` SVC processor —
    /// same pattern as blocking.
    pub async fn with_processors(
        transport: T,
        result: &ConnectionResult,
        processors: Vec<Box<dyn SvcProcessor>>,
    ) -> Result<Self, DriverError> {
        let mut session = Self::new(transport, result);
        for processor in processors {
            session
                .svc_set
                .insert(processor)
                .map_err(|e| DriverError::Channel(format!("{e:?}")))?;
        }
        session.svc_set.assign_ids(&result.channel_ids);

        // Run start_all to collect any initial frames each processor
        // wants to send. The frames are already MCS+TPKT wrapped so
        // they go straight onto the wire.
        let start_results = session
            .svc_set
            .start_all(result.user_channel_id)
            .map_err(|e| DriverError::Channel(format!("{e:?}")))?;
        for (_chan_id, frames) in start_results {
            for frame in frames {
                session.transport.send(&frame).await?;
            }
        }
        Ok(session)
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
                    // Try to dispatch to a registered SVC processor
                    // first. If a processor claims the channel id its
                    // response frames are written back over the
                    // transport and the raw event is suppressed (the
                    // processor "owns" the channel). If no processor
                    // matches, fall through to a passthrough event so
                    // callers can still observe traffic on un-registered
                    // channels — matches blocking's behavior in
                    // `RdpClient::next_event`.
                    if self.svc_set.get_by_channel_id(channel_id).is_some() {
                        let frames = self
                            .svc_set
                            .process_incoming(channel_id, &data, self.user_channel_id)
                            .map_err(|e| DriverError::Channel(format!("{e:?}")))?;
                        for frame in frames {
                            self.transport.send(&frame).await?;
                        }
                    } else {
                        events.push(SessionEvent::Channel { channel_id, data });
                    }
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
    ///
    /// Bypasses the [`InputDatabase`] — the caller is responsible for
    /// any state tracking. Prefer [`Self::key_press`] / [`Self::move_mouse`]
    /// / etc. for the dedup + replay-on-focus-loss surface.
    pub async fn send_input(
        &mut self,
        events: &[FastPathInputEvent],
    ) -> Result<(), DriverError> {
        trace!(count = events.len(), "session.send_input");
        let frame = self.stage.encode_input_events(events)?;
        self.transport.send(&frame).await?;
        Ok(())
    }

    /// Send a single Unicode key event (MS-RDPBCGR §2.2.8.1.2.2.2).
    ///
    /// Stateless — the `InputDatabase` doesn't track Unicode key state,
    /// so callers must emit press/release pairs themselves. `pressed=true`
    /// emits a press; `false` emits a release. `unicode_code` is a UTF-16
    /// code unit; pass each surrogate of a non-BMP code point separately
    /// (the wire format is per-code-unit).
    pub async fn send_unicode(
        &mut self,
        unicode_code: u16,
        pressed: bool,
    ) -> Result<(), DriverError> {
        self.send_input(&[build_unicode_event(unicode_code, pressed)])
            .await
    }

    /// Convenience wrapper around [`Self::send_unicode`] that takes a
    /// Rust `char`. Returns `Ok(true)` if the character fit in a single
    /// UTF-16 code unit and a press+release pair was emitted; `Ok(false)`
    /// for non-BMP code points (which would need a UTF-16 surrogate pair
    /// — callers that need those should drive [`Self::send_unicode`]
    /// directly with each code unit).
    pub async fn send_unicode_char(&mut self, ch: char) -> Result<bool, DriverError> {
        let code = u32::from(ch);
        if code > u16::MAX as u32 {
            debug!(code, "session.send_unicode_char skipped (non-bmp)");
            return Ok(false);
        }
        let code = code as u16;
        self.send_unicode(code, true).await?;
        self.send_unicode(code, false).await?;
        Ok(true)
    }

    /// Raw fast-path Synchronize event (MS-RDPBCGR §2.2.8.1.2.2.5).
    /// Bypasses the `InputDatabase` — see [`Self::synchronize`] for the
    /// state-tracked variant. Useful when a higher layer already owns
    /// lock-key state and wants to push it without touching the cached
    /// value.
    pub async fn send_synchronize(&mut self, lock_keys: LockKeys) -> Result<(), DriverError> {
        self.send_input(&[build_sync_event(lock_keys)]).await
    }

    // ── State-tracked input API ──────────────────────────────────────
    //
    // These methods consult the internal `InputDatabase` and only fire a
    // wire event when state actually changes (e.g. a second key-press for
    // an already-held key produces nothing). They mirror the surface
    // exposed by `justrdp_blocking::RdpClient`. Use [`Self::send_input`]
    // for the raw, untracked path.

    /// Record a key press and send the event. Returns `Ok(true)` if the
    /// event was sent, `Ok(false)` if the key was already held
    /// (duplicate suppressed, nothing on the wire).
    pub async fn key_press(&mut self, scancode: Scancode) -> Result<bool, DriverError> {
        if self.input_db.key_press(scancode).is_some() {
            self.send_input(&[build_scancode_event(scancode, true)]).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Record a key release and send the event. Returns `Ok(true)` if the
    /// event was sent, `Ok(false)` if the key was not held.
    pub async fn key_release(&mut self, scancode: Scancode) -> Result<bool, DriverError> {
        if self.input_db.key_release(scancode).is_some() {
            self.send_input(&[build_scancode_event(scancode, false)]).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Record a mouse button press at `(x, y)` and send the event. Returns
    /// `Ok(true)` if the event was sent, `Ok(false)` if the button was
    /// already held or the button is `MouseButton::X1` / `X2` (which
    /// require a `MouseX` fast-path event the encoder does not yet emit;
    /// skipped before the database update so a paired `button_release`
    /// also no-ops, keeping client/server state in lockstep).
    pub async fn button_press(
        &mut self,
        button: MouseButton,
        x: u16,
        y: u16,
    ) -> Result<bool, DriverError> {
        let Some(event) = build_mouse_button_event(button, true, x, y) else {
            return Ok(false);
        };
        if self.input_db.mouse_button_press(button).is_none() {
            return Ok(false);
        }
        self.send_input(&[event]).await?;
        Ok(true)
    }

    /// Record a mouse button release at `(x, y)` and send the event.
    /// Same X1/X2 caveat as [`Self::button_press`].
    pub async fn button_release(
        &mut self,
        button: MouseButton,
        x: u16,
        y: u16,
    ) -> Result<bool, DriverError> {
        let Some(event) = build_mouse_button_event(button, false, x, y) else {
            return Ok(false);
        };
        if self.input_db.mouse_button_release(button).is_none() {
            return Ok(false);
        }
        self.send_input(&[event]).await?;
        Ok(true)
    }

    /// Record a mouse move and send the event. Returns `Ok(false)` if
    /// the position is unchanged.
    pub async fn move_mouse(&mut self, x: u16, y: u16) -> Result<bool, DriverError> {
        if self.input_db.mouse_move(x, y).is_some() {
            self.send_input(&[build_mouse_move_event(x, y)]).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Send a vertical mouse wheel rotation. `delta` follows the Windows
    /// convention (±120 per notch); positive scrolls up. Magnitude is
    /// clamped to 255 by the wire encoding. The wheel is stateless and
    /// does not consult the `InputDatabase`.
    pub async fn wheel_scroll(&mut self, delta: i16) -> Result<(), DriverError> {
        let (x, y) = self.input_db.mouse_position();
        self.send_input(&[build_mouse_wheel_event(delta, false, x, y)])
            .await
    }

    /// Send a horizontal mouse wheel rotation. Positive scrolls right.
    pub async fn horizontal_wheel_scroll(&mut self, delta: i16) -> Result<(), DriverError> {
        let (x, y) = self.input_db.mouse_position();
        self.send_input(&[build_mouse_wheel_event(delta, true, x, y)])
            .await
    }

    /// Update lock-key state and send a synchronize event. Always emits
    /// (per MS-RDPBCGR §2.2.8.1.1.3.1.1.5, synchronize is unconditional
    /// on focus gain regardless of whether the state actually changed).
    pub async fn synchronize(&mut self, lock_keys: LockKeys) -> Result<(), DriverError> {
        let _ = self.input_db.synchronize_event(lock_keys);
        self.send_input(&[build_sync_event(lock_keys)]).await
    }

    /// Release all held keys and mouse buttons (e.g. on focus loss),
    /// sending the appropriate release events in one batched frame.
    /// Returns the number of release events written to the wire (excludes
    /// X1/X2 which require an unsupported `MouseX` event type — those
    /// are dropped by [`build_mouse_button_event`] so the server never
    /// sees them held in the first place, keeping state consistent).
    pub async fn release_all_input(&mut self) -> Result<usize, DriverError> {
        let mut ops = [Operation::KeyPressed(Scancode::new(0, false)); MAX_RELEASE_OPS];
        let count = self.input_db.release_all(&mut ops);
        let (mx, my) = self.input_db.mouse_position();
        // Build all events first so a partial-send failure cannot leave
        // the database cleared while the server still sees keys held.
        let events: Vec<FastPathInputEvent> = ops[..count]
            .iter()
            .filter_map(|op| match *op {
                Operation::KeyReleased(sc) => Some(build_scancode_event(sc, false)),
                Operation::MouseButtonReleased(btn) => {
                    build_mouse_button_event(btn, false, mx, my)
                }
                _ => unreachable!("InputDatabase::release_all only emits release ops"),
            })
            .collect();
        let sent = events.len();
        if sent > 0 {
            self.send_input(&events).await?;
        }
        Ok(sent)
    }

    /// Whether a scancode is currently tracked as held by the database.
    /// Reflects sent-events only (raw [`Self::send_input`] calls bypass
    /// tracking).
    pub fn is_key_pressed(&self, scancode: Scancode) -> bool {
        self.input_db.is_key_pressed(scancode)
    }

    /// Whether a mouse button is currently tracked as held.
    pub fn is_button_pressed(&self, button: MouseButton) -> bool {
        self.input_db.is_mouse_button_pressed(button)
    }

    /// Last mouse position recorded by [`Self::move_mouse`].
    pub fn mouse_position(&self) -> (u16, u16) {
        self.input_db.mouse_position()
    }

    /// Last lock-key state recorded by [`Self::synchronize`].
    pub fn lock_keys(&self) -> LockKeys {
        self.input_db.lock_keys()
    }

    /// Send a Refresh Rect PDU asking the server to re-emit bitmap
    /// updates for the listed inclusive rectangles. Useful right after
    /// connect (or after a window restore) to force the first paint —
    /// servers don't push bitmap updates for an idle desktop until
    /// something triggers a redraw.
    pub async fn send_refresh_rect(
        &mut self,
        areas: &[InclusiveRect],
    ) -> Result<(), DriverError> {
        let frame = self.stage.encode_refresh_rect(areas)?;
        self.transport.send(&frame).await?;
        Ok(())
    }

    /// Send a Suppress Output PDU. `allow=false` tells the server to
    /// pause display updates (e.g. while the local window is minimised);
    /// `allow=true` resumes them, with `rect` passing the visible
    /// viewport. A typical client emits `(true, Some(viewport))` after
    /// restore, often paired with a `send_refresh_rect` to force a
    /// fresh full-screen paint.
    pub async fn send_suppress_output(
        &mut self,
        allow: bool,
        rect: Option<InclusiveRect>,
    ) -> Result<(), DriverError> {
        let frame = self.stage.encode_suppress_output(allow, rect)?;
        self.transport.send(&frame).await?;
        Ok(())
    }

    /// Send a graceful shutdown request (Shutdown Request Denied response
    /// from the server still surfaces as `Terminated(ShutdownDenied)`).
    pub async fn shutdown(&mut self) -> Result<(), DriverError> {
        info!("session.shutdown");
        let frame = self.stage.encode_shutdown_request()?;
        self.transport.send(&frame).await?;
        Ok(())
    }

    /// Send an MCS Disconnect Provider Ultimatum (immediate disconnect,
    /// no graceful handshake).
    pub async fn disconnect(&mut self) -> Result<(), DriverError> {
        info!("session.disconnect");
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

    /// Confirm `send_refresh_rect` produces a slow-path frame with
    /// `ShareDataPduType::RefreshRect` and the rectangle list intact.
    #[test]
    fn send_refresh_rect_produces_correct_wire_frame() {
        use justrdp_core::{Decode, ReadCursor};
        use justrdp_pdu::mcs::SendDataRequest;
        use justrdp_pdu::rdp::finalization::RefreshRectPdu;
        use justrdp_pdu::rdp::headers::{
            ShareControlHeader, ShareDataHeader, ShareDataPduType,
        };
        use justrdp_pdu::tpkt::TpktHeader;
        use justrdp_pdu::x224::DataTransfer;

        block_on(async {
            let shared = Rc::new(RefCell::new(SharedSink {
                sent: Vec::new(),
                recv: VecDeque::new(),
            }));
            let transport = SinkTransport { shared: Rc::clone(&shared) };
            let result = fake_result();
            let mut session = ActiveSession::new(transport, &result);

            let areas = alloc::vec![
                InclusiveRect { left: 0, top: 0, right: 1023, bottom: 767 },
            ];
            session.send_refresh_rect(&areas).await.unwrap();

            let sent = &shared.borrow().sent;
            assert_eq!(sent.len(), 1, "exactly one frame written to transport");
            let frame = &sent[0];

            let mut src = ReadCursor::new(frame);
            let _tpkt = TpktHeader::decode(&mut src).unwrap();
            let _dt = DataTransfer::decode(&mut src).unwrap();
            let sdr = SendDataRequest::decode(&mut src).unwrap();
            let mut inner = ReadCursor::new(sdr.user_data);
            let _sch = ShareControlHeader::decode(&mut inner).unwrap();
            let sdh = ShareDataHeader::decode(&mut inner).unwrap();
            assert_eq!(sdh.pdu_type2, ShareDataPduType::RefreshRect);
            let pdu = RefreshRectPdu::decode(&mut inner).unwrap();
            assert_eq!(pdu.areas, areas);
        });
    }

    /// Confirm `send_suppress_output(false, None)` writes a 4-byte body
    /// (no rect on wire) tagged `ShareDataPduType::SuppressOutput`.
    #[test]
    fn send_suppress_output_suppress_omits_rect() {
        use justrdp_core::{Decode, ReadCursor};
        use justrdp_pdu::mcs::SendDataRequest;
        use justrdp_pdu::rdp::finalization::SuppressOutputPdu;
        use justrdp_pdu::rdp::headers::{
            ShareControlHeader, ShareDataHeader, ShareDataPduType,
        };
        use justrdp_pdu::tpkt::TpktHeader;
        use justrdp_pdu::x224::DataTransfer;

        block_on(async {
            let shared = Rc::new(RefCell::new(SharedSink {
                sent: Vec::new(),
                recv: VecDeque::new(),
            }));
            let transport = SinkTransport { shared: Rc::clone(&shared) };
            let result = fake_result();
            let mut session = ActiveSession::new(transport, &result);

            session.send_suppress_output(false, None).await.unwrap();

            let sent = &shared.borrow().sent;
            assert_eq!(sent.len(), 1);
            let frame = &sent[0];

            let mut src = ReadCursor::new(frame);
            let _tpkt = TpktHeader::decode(&mut src).unwrap();
            let _dt = DataTransfer::decode(&mut src).unwrap();
            let sdr = SendDataRequest::decode(&mut src).unwrap();
            let mut inner = ReadCursor::new(sdr.user_data);
            let _sch = ShareControlHeader::decode(&mut inner).unwrap();
            let sdh = ShareDataHeader::decode(&mut inner).unwrap();
            assert_eq!(sdh.pdu_type2, ShareDataPduType::SuppressOutput);
            let pdu = SuppressOutputPdu::decode(&mut inner).unwrap();
            assert_eq!(pdu.allow_display_updates, 0);
            assert_eq!(pdu.left, None);
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

    // ── State-tracked input API tests ───────────────────────────────

    /// Decode a fast-path input frame back into the list of events the
    /// caller asked the session to send. Anchors the wire-level
    /// invariants for input round-trip tests: every event we emit must
    /// round-trip through the wire codec to the byte-identical event.
    fn decode_input_events(frame: &[u8]) -> Vec<FastPathInputEvent> {
        use justrdp_core::{Decode, ReadCursor};
        use justrdp_pdu::rdp::fast_path::FastPathInputHeader;

        let mut cursor = ReadCursor::new(frame);
        let hdr = FastPathInputHeader::decode(&mut cursor).unwrap();
        let mut events = Vec::with_capacity(hdr.num_events as usize);
        for _ in 0..hdr.num_events {
            events.push(FastPathInputEvent::decode(&mut cursor).unwrap());
        }
        events
    }

    fn build_session() -> (ActiveSession<SinkTransport>, Rc<RefCell<SharedSink>>) {
        let shared = Rc::new(RefCell::new(SharedSink {
            sent: Vec::new(),
            recv: VecDeque::new(),
        }));
        let transport = SinkTransport { shared: Rc::clone(&shared) };
        let result = fake_result();
        (ActiveSession::new(transport, &result), shared)
    }

    #[test]
    fn key_press_first_call_sends_event_and_marks_pressed() {
        block_on(async {
            let (mut session, shared) = build_session();
            let sc = Scancode::new(0x1E, false); // 'A'
            let sent = session.key_press(sc).await.unwrap();
            assert!(sent);
            assert!(session.is_key_pressed(sc));
            let events = decode_input_events(&shared.borrow().sent[0]);
            match &events[0] {
                FastPathInputEvent::Scancode(s) => {
                    assert_eq!(s.key_code, 0x1E);
                    assert_eq!(s.event_flags, 0); // no release, no extended
                }
                other => panic!("expected Scancode, got {other:?}"),
            }
        });
    }

    #[test]
    fn key_press_duplicate_suppressed_no_wire_traffic() {
        block_on(async {
            let (mut session, shared) = build_session();
            let sc = Scancode::new(0x1E, false);
            assert!(session.key_press(sc).await.unwrap());
            assert!(!session.key_press(sc).await.unwrap()); // dup → false
            assert_eq!(shared.borrow().sent.len(), 1, "dup must not write");
        });
    }

    #[test]
    fn key_release_without_press_suppressed() {
        block_on(async {
            let (mut session, shared) = build_session();
            let sc = Scancode::new(0x1E, false);
            assert!(!session.key_release(sc).await.unwrap());
            assert!(shared.borrow().sent.is_empty());
        });
    }

    #[test]
    fn key_release_after_press_sends_release_event() {
        block_on(async {
            let (mut session, shared) = build_session();
            let sc = Scancode::new(0x1D, true); // Right Ctrl (extended)
            session.key_press(sc).await.unwrap();
            assert!(session.is_key_pressed(sc));
            assert!(session.key_release(sc).await.unwrap());
            assert!(!session.is_key_pressed(sc));

            let events = decode_input_events(&shared.borrow().sent[1]);
            match &events[0] {
                FastPathInputEvent::Scancode(s) => {
                    assert_eq!(s.key_code, 0x1D);
                    // KBDFLAGS_RELEASE | KBDFLAGS_EXTENDED
                    assert_eq!(s.event_flags, 0x03);
                }
                other => panic!("expected Scancode, got {other:?}"),
            }
        });
    }

    #[test]
    fn button_press_x1_x2_dropped_silently() {
        // X1/X2 require a MouseX event the encoder doesn't emit. The
        // state-tracked API skips both the wire send AND the database
        // update, so a follow-up release also no-ops — the server never
        // sees a press, never sees a release, and the database never
        // claims X1/X2 is held.
        block_on(async {
            let (mut session, shared) = build_session();
            assert!(!session.button_press(MouseButton::X1, 0, 0).await.unwrap());
            assert!(!session.button_press(MouseButton::X2, 0, 0).await.unwrap());
            assert!(!session.is_button_pressed(MouseButton::X1));
            assert!(!session.is_button_pressed(MouseButton::X2));
            assert!(!session.button_release(MouseButton::X1, 0, 0).await.unwrap());
            assert!(shared.borrow().sent.is_empty());
        });
    }

    #[test]
    fn button_press_left_writes_button1_down() {
        block_on(async {
            let (mut session, shared) = build_session();
            assert!(session
                .button_press(MouseButton::Left, 100, 200)
                .await
                .unwrap());
            assert!(session.is_button_pressed(MouseButton::Left));
            let events = decode_input_events(&shared.borrow().sent[0]);
            match &events[0] {
                FastPathInputEvent::Mouse(m) => {
                    // PTRFLAGS_BUTTON1 | PTRFLAGS_DOWN
                    assert_eq!(m.pointer_flags, 0x9000);
                    assert_eq!((m.x_pos, m.y_pos), (100, 200));
                }
                other => panic!("expected Mouse, got {other:?}"),
            }
        });
    }

    #[test]
    fn move_mouse_same_position_suppressed() {
        block_on(async {
            let (mut session, shared) = build_session();
            assert!(session.move_mouse(50, 60).await.unwrap());
            assert!(!session.move_mouse(50, 60).await.unwrap()); // dup
            assert_eq!(session.mouse_position(), (50, 60));
            assert_eq!(shared.borrow().sent.len(), 1);
        });
    }

    #[test]
    fn synchronize_emits_unconditionally() {
        block_on(async {
            let (mut session, shared) = build_session();
            let locks = LockKeys {
                scroll_lock: false,
                num_lock: true,
                caps_lock: true,
                kana_lock: false,
            };
            session.synchronize(locks).await.unwrap();
            session.synchronize(locks).await.unwrap(); // same — must still emit
            assert_eq!(shared.borrow().sent.len(), 2);
            assert_eq!(session.lock_keys(), locks);

            // Verify the wire-level Sync event has the expected flag byte
            // (num | caps = 0x02 | 0x04 = 0x06).
            let events = decode_input_events(&shared.borrow().sent[0]);
            match &events[0] {
                FastPathInputEvent::Sync(s) => {
                    assert_eq!(s.event_flags, 0x06);
                }
                other => panic!("expected Sync, got {other:?}"),
            }
        });
    }

    #[test]
    fn release_all_input_clears_held_state_and_batches() {
        block_on(async {
            let (mut session, shared) = build_session();
            let sc_a = Scancode::new(0x1E, false);
            let sc_ctrl = Scancode::new(0x1D, true);
            session.key_press(sc_a).await.unwrap();
            session.key_press(sc_ctrl).await.unwrap();
            session
                .button_press(MouseButton::Left, 10, 20)
                .await
                .unwrap();
            // 3 frames so far (one per state-changing call).
            assert_eq!(shared.borrow().sent.len(), 3);

            let count = session.release_all_input().await.unwrap();
            // 2 keys + 1 button = 3 events, batched in a single frame.
            assert_eq!(count, 3);
            assert_eq!(shared.borrow().sent.len(), 4);
            assert!(!session.is_key_pressed(sc_a));
            assert!(!session.is_key_pressed(sc_ctrl));
            assert!(!session.is_button_pressed(MouseButton::Left));

            let events = decode_input_events(&shared.borrow().sent[3]);
            assert_eq!(events.len(), 3);
        });
    }

    #[test]
    fn release_all_input_with_no_state_writes_nothing() {
        block_on(async {
            let (mut session, shared) = build_session();
            let count = session.release_all_input().await.unwrap();
            assert_eq!(count, 0);
            assert!(shared.borrow().sent.is_empty());
        });
    }

    #[test]
    fn send_unicode_press_emits_unicode_event_no_release_flag() {
        block_on(async {
            let (mut session, shared) = build_session();
            session.send_unicode(0x0041, true).await.unwrap(); // 'A' press
            let events = decode_input_events(&shared.borrow().sent[0]);
            match &events[0] {
                FastPathInputEvent::Unicode(u) => {
                    assert_eq!(u.unicode_code, 0x0041);
                    assert_eq!(u.event_flags, 0); // no release flag
                }
                other => panic!("expected Unicode, got {other:?}"),
            }
        });
    }

    #[test]
    fn send_unicode_release_sets_release_flag() {
        block_on(async {
            let (mut session, shared) = build_session();
            session.send_unicode(0x0041, false).await.unwrap();
            let events = decode_input_events(&shared.borrow().sent[0]);
            match &events[0] {
                FastPathInputEvent::Unicode(u) => assert_eq!(u.event_flags, 0x01),
                other => panic!("expected Unicode, got {other:?}"),
            }
        });
    }

    #[test]
    fn send_unicode_char_bmp_emits_press_release_pair() {
        block_on(async {
            let (mut session, shared) = build_session();
            assert!(session.send_unicode_char('A').await.unwrap());
            assert_eq!(shared.borrow().sent.len(), 2);

            let press = decode_input_events(&shared.borrow().sent[0]);
            let release = decode_input_events(&shared.borrow().sent[1]);
            match (&press[0], &release[0]) {
                (FastPathInputEvent::Unicode(p), FastPathInputEvent::Unicode(r)) => {
                    assert_eq!(p.unicode_code, 0x0041);
                    assert_eq!(p.event_flags, 0);
                    assert_eq!(r.unicode_code, 0x0041);
                    assert_eq!(r.event_flags, 0x01);
                }
                _ => panic!("expected Unicode press+release"),
            }
        });
    }

    #[test]
    fn send_unicode_char_non_bmp_returns_false_and_writes_nothing() {
        block_on(async {
            let (mut session, shared) = build_session();
            // U+1F600 GRINNING FACE — outside BMP, needs surrogate pair.
            assert!(!session.send_unicode_char('\u{1F600}').await.unwrap());
            assert!(shared.borrow().sent.is_empty());
        });
    }

    #[test]
    fn send_synchronize_raw_does_not_update_database() {
        block_on(async {
            let (mut session, _shared) = build_session();
            let locks = LockKeys {
                scroll_lock: true,
                num_lock: false,
                caps_lock: false,
                kana_lock: false,
            };
            session.send_synchronize(locks).await.unwrap();
            // Cached lock-key state stays at the default — raw send does
            // not touch the InputDatabase.
            assert_eq!(session.lock_keys(), LockKeys::default());
        });
    }

    // ── SVC processor wiring tests ──────────────────────────────────

    use alloc::string::String as StdString;
    use justrdp_svc::{ChannelName, CompressionCondition, SvcMessage, SvcResult};

    /// Echo SVC processor — start() emits "hello"; process() records
    /// the inbound payload and replies "reply". Mirrors blocking's
    /// `RecordingProcessor`.
    #[derive(Debug, Default)]
    struct EchoProcessor;

    impl justrdp_core::AsAny for EchoProcessor {
        fn as_any(&self) -> &dyn core::any::Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
            self
        }
    }

    impl SvcProcessor for EchoProcessor {
        fn channel_name(&self) -> ChannelName {
            ChannelName::new(b"echo")
        }
        fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
            Ok(vec![SvcMessage::new(b"hello".to_vec())])
        }
        fn process(&mut self, _payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
            Ok(vec![SvcMessage::new(b"reply".to_vec())])
        }
        fn compression_condition(&self) -> CompressionCondition {
            CompressionCondition::Never
        }
    }

    /// `EmptyStartProcessor` — `start()` returns nothing. Used to
    /// confirm that with_processors() doesn't emit spurious frames
    /// for processors that have nothing to say at startup.
    #[derive(Debug, Default)]
    struct EmptyStartProcessor;

    impl justrdp_core::AsAny for EmptyStartProcessor {
        fn as_any(&self) -> &dyn core::any::Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
            self
        }
    }

    impl SvcProcessor for EmptyStartProcessor {
        fn channel_name(&self) -> ChannelName {
            ChannelName::new(b"silent")
        }
        fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
            Ok(Vec::new())
        }
        fn process(&mut self, _payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
            Ok(Vec::new())
        }
        fn compression_condition(&self) -> CompressionCondition {
            CompressionCondition::Never
        }
    }

    fn build_session_for_processors(
        channel_ids: Vec<(StdString, u16)>,
    ) -> (ConnectionResult, Rc<RefCell<SharedSink>>, SinkTransport) {
        let shared = Rc::new(RefCell::new(SharedSink {
            sent: Vec::new(),
            recv: VecDeque::new(),
        }));
        let transport = SinkTransport { shared: Rc::clone(&shared) };
        let mut result = fake_result();
        result.channel_ids = channel_ids;
        (result, shared, transport)
    }

    #[test]
    fn with_processors_empty_list_succeeds_no_traffic() {
        block_on(async {
            let (result, shared, transport) = build_session_for_processors(vec![]);
            let _session = ActiveSession::with_processors(transport, &result, vec![])
                .await
                .unwrap();
            assert!(shared.borrow().sent.is_empty());
        });
    }

    #[test]
    fn with_processors_writes_start_frames_for_assigned_channels() {
        // Echo processor's start() emits "hello"; the channel_ids list
        // contains a matching "echo" entry so the SVC set assigns it
        // an MCS id and the frames get encoded + flushed.
        block_on(async {
            let (result, shared, transport) =
                build_session_for_processors(vec![(StdString::from("echo"), 1004)]);
            let processors: Vec<Box<dyn SvcProcessor>> =
                vec![Box::new(EchoProcessor::default())];
            let _session = ActiveSession::with_processors(transport, &result, processors)
                .await
                .unwrap();
            // start_all produced one MCS-wrapped frame for the echo
            // channel — written through the transport.
            assert_eq!(shared.borrow().sent.len(), 1);
            // Sanity check: the frame is non-empty (the processor's
            // `b"hello"` payload + MCS/TPKT framing).
            assert!(!shared.borrow().sent[0].is_empty());
        });
    }

    #[test]
    fn with_processors_unassigned_channel_writes_nothing() {
        // Channel name does not appear in result.channel_ids, so
        // assign_ids leaves the entry without an MCS id and start_all
        // skips it. EmptyStartProcessor returns no frames anyway, so
        // the assertion is double-protected.
        block_on(async {
            let (result, shared, transport) =
                build_session_for_processors(vec![(StdString::from("unrelated"), 1004)]);
            let processors: Vec<Box<dyn SvcProcessor>> =
                vec![Box::new(EmptyStartProcessor::default())];
            let _session = ActiveSession::with_processors(transport, &result, processors)
                .await
                .unwrap();
            assert!(shared.borrow().sent.is_empty());
        });
    }

    #[test]
    fn with_processors_processor_with_empty_start_writes_nothing() {
        // Processor IS assigned a channel id, but start() returns no
        // messages — start_all should produce no frames for that entry.
        block_on(async {
            let (result, shared, transport) =
                build_session_for_processors(vec![(StdString::from("silent"), 1004)]);
            let processors: Vec<Box<dyn SvcProcessor>> =
                vec![Box::new(EmptyStartProcessor::default())];
            let _session = ActiveSession::with_processors(transport, &result, processors)
                .await
                .unwrap();
            assert!(shared.borrow().sent.is_empty());
        });
    }

    #[test]
    fn wheel_scroll_uses_cached_mouse_position() {
        block_on(async {
            let (mut session, shared) = build_session();
            session.move_mouse(123, 456).await.unwrap();
            session.wheel_scroll(120).await.unwrap();
            let events = decode_input_events(&shared.borrow().sent[1]);
            match &events[0] {
                FastPathInputEvent::Mouse(m) => {
                    // PTRFLAGS_WHEEL (0x0200) | magnitude (120)
                    assert_eq!(m.pointer_flags, 0x0200 | 120);
                    assert_eq!((m.x_pos, m.y_pos), (123, 456));
                }
                other => panic!("expected Mouse, got {other:?}"),
            }
        });
    }
}
