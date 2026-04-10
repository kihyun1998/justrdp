#![forbid(unsafe_code)]

//! [`RdpClient`] — high-level synchronous RDP client.
//!
//! As of M3, `connect()` runs the full connection sequence through to the
//! `Connected` state and constructs an [`ActiveStage`] from the resulting
//! channel IDs and share ID, so [`RdpClient::connect`] now returns `Ok`
//! on success. The active-session pump ([`RdpClient::next_event`] and
//! the input helpers) is still stubbed — see M4 in CHECKLIST.md.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;

use justrdp_connector::{ArcCookie, ClientConnector, ClientConnectorState, Config, Sequence};
use justrdp_core::WriteBuf;
use justrdp_input::{MouseButton, Scancode};
use justrdp_pdu::rdp::fast_path::{
    FastPathInputEvent, FastPathMouseEvent, FastPathScancodeEvent, FastPathUnicodeEvent,
};
use justrdp_pdu::tpkt::TpktHint;
use justrdp_session::{ActiveStage, ActiveStageOutput, GracefulDisconnectReason, SessionConfig};
use justrdp_svc::{StaticChannelSet as SvcChannelSet, SvcProcessor};
use justrdp_tls::{AcceptAll, ReadWrite, RustlsUpgrader, ServerCertVerifier, TlsUpgrader};

// MS-RDPBCGR 2.2.8.1.2.2.1 keyboard event flags (5-bit field).
const KBDFLAGS_RELEASE: u8 = 0x01;
const KBDFLAGS_EXTENDED: u8 = 0x02;

// MS-RDPBCGR 2.2.8.1.2.2.3 pointer flags (16-bit pointerFlags field).
const PTRFLAGS_MOVE: u16 = 0x0800;
const PTRFLAGS_DOWN: u16 = 0x8000;
const PTRFLAGS_BUTTON1: u16 = 0x1000; // left
const PTRFLAGS_BUTTON2: u16 = 0x2000; // right
const PTRFLAGS_BUTTON3: u16 = 0x4000; // middle

use crate::credssp::run_credssp_sequence;
use crate::error::{ConnectError, RuntimeError};
use crate::event::RdpEvent;
use crate::reconnect::ReconnectPolicy;
use crate::transport::{read_pdu, write_all};

/// Transport abstraction shared across the pre-TLS and post-TLS phases.
///
/// Before TLS upgrade the transport holds a raw [`TcpStream`]; after upgrade
/// it holds the boxed rustls stream. [`Read`] / [`Write`] dispatch to
/// whichever variant is active, so the pump code can read and write without
/// caring which phase it is in.
pub(crate) enum Transport {
    /// Raw TCP (pre-handshake or Standard RDP Security).
    Tcp(TcpStream),
    /// Post-TLS-upgrade stream (any backend that implements [`ReadWrite`]).
    ///
    /// Intentionally not `Send`: rustls's `StreamOwned` is not `Send` when
    /// boxed through `justrdp_tls::ReadWrite`, and blocking clients are
    /// single-threaded. Cross-thread ownership is an M7+ concern.
    Tls(Box<dyn ReadWrite>),
    /// Placeholder used while the transport is swapped during upgrade.
    Swapping,
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
            Self::Swapping => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "transport is being swapped",
            )),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
            Self::Swapping => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "transport is being swapped",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            Self::Tls(s) => s.flush(),
            Self::Swapping => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "transport is being swapped",
            )),
        }
    }
}

/// High-level synchronous RDP client.
pub struct RdpClient {
    transport: Option<Transport>,
    session: Option<ActiveStage>,
    reconnect_policy: ReconnectPolicy,
    scratch: Vec<u8>,
    /// Events produced by a single `session.process()` call that have
    /// not yet been returned via [`RdpClient::next_event`]. Drained in
    /// FIFO order before the next frame is read from the wire.
    pending_events: VecDeque<RdpEvent>,
    /// Set once the session has reached a terminal state. Further calls
    /// to [`next_event`] return `Ok(None)` without touching the network.
    disconnected: bool,
    /// Registered SVC processors. Populated at connect time from the
    /// `processors` argument and consulted in [`Self::read_one_frame`]
    /// when an MCS channel data PDU arrives. Empty if the caller did not
    /// register any processors — in which case `RdpEvent::ChannelData`
    /// is emitted as a raw passthrough.
    svc_set: SvcChannelSet,
    /// MCS user channel ID, captured from the connection result. Needed
    /// to wrap outgoing SVC frames with `SendDataRequest`.
    user_channel_id: u16,
    /// Server public key captured at TLS upgrade. Consumed by CredSSP and
    /// retained for M7 auto-reconnect (which may need to re-derive session
    /// keys against the same certificate).
    #[allow(dead_code)]
    server_public_key: Option<Vec<u8>>,
    /// Resolved server address from the initial connect, used by M7
    /// auto-reconnect to skip the DNS step on retry.
    last_server_addr: SocketAddr,
    /// SNI hostname captured at the initial connect, reused by M7
    /// auto-reconnect when re-running the TLS handshake.
    last_server_name: String,
    /// Config snapshot taken before the connector consumed the original.
    /// On reconnect, this is cloned and the latest ARC cookie is injected
    /// before being handed to a new `ClientConnector`.
    last_config: Config,
    /// Most recent Auto-Reconnect Cookie surfaced via SaveSessionInfo
    /// (MS-RDPBCGR 5.5). `None` until the server has logged the user in
    /// and emitted a logon-info PDU containing the ARC random bits.
    last_arc_cookie: Option<ArcCookie>,
}

impl RdpClient {
    /// Perform the full connection sequence using the default
    /// [`RustlsUpgrader`] with [`AcceptAll`] (mstsc.exe-like behavior)
    /// and no SVC processors.
    pub fn connect<A: ToSocketAddrs>(
        server: A,
        server_name: &str,
        config: Config,
    ) -> Result<Self, ConnectError> {
        Self::connect_with_verifier(server, server_name, config, Arc::new(AcceptAll))
    }

    /// Perform the connection sequence using a custom [`ServerCertVerifier`].
    ///
    /// Prefer this over [`connect`](Self::connect) for production deployments
    /// — pass [`PinnedSpki`](justrdp_tls::PinnedSpki) or a GUI-backed verifier
    /// so self-signed certificates are not accepted blindly.
    pub fn connect_with_verifier<A: ToSocketAddrs>(
        server: A,
        server_name: &str,
        config: Config,
        verifier: Arc<dyn ServerCertVerifier>,
    ) -> Result<Self, ConnectError> {
        let upgrader = RustlsUpgrader::with_verifier(verifier);
        Self::connect_with_upgrader(server, server_name, config, upgrader, Vec::new())
    }

    /// Perform the connection sequence with a list of SVC processors.
    ///
    /// Channel names declared by each processor must also be present in
    /// `config.static_channels` so the connector advertises them during
    /// the BasicSettingsExchange — otherwise the server will not allocate
    /// MCS channel IDs and the processors will be silently ignored.
    ///
    /// To use Dynamic Virtual Channels, wrap your `DvcProcessor` instances
    /// in a [`DrdynvcClient`](justrdp_dvc::DrdynvcClient) and box that as
    /// the `drdynvc` SVC processor.
    pub fn connect_with_processors<A: ToSocketAddrs>(
        server: A,
        server_name: &str,
        config: Config,
        processors: Vec<Box<dyn SvcProcessor>>,
    ) -> Result<Self, ConnectError> {
        let upgrader = RustlsUpgrader::with_verifier(Arc::new(AcceptAll));
        Self::connect_with_upgrader(server, server_name, config, upgrader, processors)
    }

    /// Perform the connection sequence using an arbitrary [`TlsUpgrader`]
    /// and a list of SVC processors. Used by tests and by callers who want
    /// full control over the TLS stack (e.g. `native-tls` backend).
    pub fn connect_with_upgrader<A, U>(
        server: A,
        server_name: &str,
        config: Config,
        upgrader: U,
        processors: Vec<Box<dyn SvcProcessor>>,
    ) -> Result<Self, ConnectError>
    where
        A: ToSocketAddrs,
        U: TlsUpgrader,
        U::Stream: 'static,
    {
        // Resolve the server address eagerly so M7 auto-reconnect can
        // skip DNS on retry. Multi-A-record DNS is collapsed to the first
        // resolved address — applications that need round-robin failover
        // should resolve themselves and pass a SocketAddr.
        let last_server_addr = server
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| {
                ConnectError::Tcp(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no socket addresses resolved from `server` argument",
                ))
            })?;
        let last_server_name = server_name.to_string();
        let last_config = config.clone();

        let tcp = TcpStream::connect(last_server_addr)?;
        let mut connector = ClientConnector::new(config);
        let mut transport = Transport::Tcp(tcp);

        // Phase 1: drive the connector until it hits the TLS upgrade point.
        drive_until_state_change(&mut connector, &mut transport, |s| {
            matches!(
                s,
                ClientConnectorState::EnhancedSecurityUpgrade
                    | ClientConnectorState::Connected { .. }
            )
        })?;

        // Phase 2: perform TLS upgrade if the connector asked for it.
        let server_public_key = if matches!(
            connector.state(),
            ClientConnectorState::EnhancedSecurityUpgrade
        ) {
            let tcp = match std::mem::replace(&mut transport, Transport::Swapping) {
                Transport::Tcp(s) => s,
                _ => {
                    return Err(ConnectError::Unimplemented(
                        "unexpected transport variant before TLS upgrade",
                    ));
                }
            };
            let upgraded = upgrader.upgrade(tcp, server_name)?;
            transport = Transport::Tls(Box::new(upgraded.stream));
            Some(upgraded.server_public_key)
        } else {
            None
        };

        // Phase 3 (M2): if the negotiated protocol is HYBRID/HYBRID_EX, the
        // connector now sits in `EnhancedSecurityUpgrade`. Step it once
        // (the connector's send-state for that phase is a pure transition)
        // so we can see whether it advances into a Credssp* state or skips
        // straight to BasicSettingsExchange.
        drive_until_state_change(&mut connector, &mut transport, |s| {
            !matches!(s, ClientConnectorState::EnhancedSecurityUpgrade)
        })?;

        if matches!(
            connector.state(),
            ClientConnectorState::CredsspNegoTokens
                | ClientConnectorState::CredsspPubKeyAuth
                | ClientConnectorState::CredsspCredentials
        ) {
            // Clone the SPKI for CredSSP; the original is retained on the
            // RdpClient for potential reuse during M7 auto-reconnect.
            let server_pub_key = server_public_key
                .as_ref()
                .cloned()
                .ok_or(ConnectError::Unimplemented(
                    "CredSSP requires a TLS upgrade to capture server_public_key",
                ))?;
            // run_credssp_sequence handles all token I/O over the TLS stream;
            // the connector's Credssp* states are just internal markers and
            // are advanced (no-op transitions) below.
            run_credssp_sequence(&connector, &mut transport, server_pub_key)?;
            drive_until_state_change(&mut connector, &mut transport, |s| {
                !matches!(
                    s,
                    ClientConnectorState::CredsspNegoTokens
                        | ClientConnectorState::CredsspPubKeyAuth
                        | ClientConnectorState::CredsspCredentials
                        | ClientConnectorState::CredsspEarlyUserAuth
                )
            })?;
        }

        // Phase 4 (M3): BasicSettingsExchange → ChannelConnection →
        // SecureSettings → Licensing → Capabilities → Finalization → Connected.
        // The connector owns all of this internally; we just pump bytes.
        drive_until_state_change(&mut connector, &mut transport, |s| s.is_connected())?;

        // The connector is now in `Connected { result }`. Convert the
        // resulting channel layout into a SessionConfig so the caller can
        // drive the active session via ActiveStage.
        let result = connector.result().ok_or_else(|| {
            ConnectError::Unimplemented("connector reached Connected but result() returned None")
        })?;
        let user_channel_id = result.user_channel_id;
        let session_config = SessionConfig {
            io_channel_id: result.io_channel_id,
            user_channel_id: result.user_channel_id,
            share_id: result.share_id,
            channel_ids: result.channel_ids.clone(),
        };
        let channel_ids = result.channel_ids.clone();
        let session = ActiveStage::new(session_config);

        // Wire SVC processors. Each processor declares a channel_name();
        // assign_ids matches that against the connector's negotiated MCS
        // channel IDs. Processors whose channel name was not advertised
        // in config.static_channels (and therefore not allocated by the
        // server) get no ID and are silently inert.
        let mut svc_set = SvcChannelSet::new();
        for processor in processors {
            svc_set
                .insert(processor)
                .map_err(|e| ConnectError::ChannelSetup(format!("{e:?}")))?;
        }
        svc_set.assign_ids(&channel_ids);

        // Run start_all to collect any initial frames each processor wants
        // to send (e.g. CLIPRDR Capability Request, RDPDR Server Announce
        // Reply). The frames are already MCS+TPKT wrapped so they go
        // straight onto the wire.
        let start_results = svc_set
            .start_all(user_channel_id)
            .map_err(|e| ConnectError::ChannelSetup(format!("{e:?}")))?;
        for (_chan_id, frames) in start_results {
            for frame in frames {
                transport.write_all(&frame).map_err(ConnectError::Tcp)?;
            }
        }
        transport.flush().map_err(ConnectError::Tcp)?;

        // If the connector captured an ARC cookie during the connection
        // sequence (rare — most servers send it later inside an active
        // SaveSessionInfo PDU), seed last_arc_cookie with it so a very
        // early disconnect can still trigger M7 auto-reconnect.
        let last_arc_cookie = result.server_arc_cookie.clone();

        Ok(Self {
            transport: Some(transport),
            session: Some(session),
            reconnect_policy: ReconnectPolicy::disabled(),
            scratch: Vec::new(),
            pending_events: VecDeque::new(),
            disconnected: false,
            svc_set,
            user_channel_id,
            server_public_key,
            last_server_addr,
            last_server_name,
            last_config,
            last_arc_cookie,
        })
    }

    /// Set the [`ReconnectPolicy`] to consult when the session drops.
    pub fn set_reconnect_policy(&mut self, policy: ReconnectPolicy) {
        self.reconnect_policy = policy;
    }

    /// Read the next session event from the active session loop.
    ///
    /// Drains pending events first; if the queue is empty, reads exactly one
    /// frame from the transport, runs it through [`ActiveStage::process`], and
    /// returns the first resulting event (queueing the rest).
    ///
    /// Returns `Ok(None)` once the session has terminated. After that point
    /// the transport has been dropped; call [`RdpClient::connect`] again to
    /// start a fresh session.
    ///
    /// `ResponseFrame` outputs are written back to the transport before any
    /// event is returned; they never surface to callers.
    ///
    /// If a [`ReconnectPolicy`] has been set via
    /// [`set_reconnect_policy`](Self::set_reconnect_policy) and the transport
    /// drops mid-session, this method will attempt automatic reconnection
    /// (using the captured ARC cookie) before surfacing the disconnect.
    /// Each attempt produces a [`RdpEvent::Reconnecting`] event; on success
    /// a final [`RdpEvent::Reconnected`] event is queued and the loop resumes.
    pub fn next_event(&mut self) -> Result<Option<RdpEvent>, RuntimeError> {
        loop {
            if let Some(event) = self.pending_events.pop_front() {
                return Ok(Some(event));
            }
            if self.disconnected {
                return Ok(None);
            }
            match self.read_one_frame() {
                Ok(()) => continue,
                Err(RuntimeError::Disconnected) | Err(RuntimeError::Io(_)) => {
                    // Transport-level error: attempt M7 auto-reconnect.
                    // try_reconnect pushes Reconnecting/Reconnected (or
                    // Disconnected on failure) into pending_events and
                    // updates self in place on success.
                    self.try_reconnect();
                    // Loop again to drain whatever try_reconnect queued.
                }
                Err(other) => return Err(other),
            }
        }
    }

    /// Read exactly one frame, run it through `ActiveStage::process`, and
    /// push every resulting event onto `pending_events`. Frames produced
    /// by `ActiveStageOutput::ResponseFrame` are written immediately and
    /// never queued.
    ///
    /// `ChannelData` PDUs are routed through the SVC processor set: if a
    /// registered processor handles the channel, its response frames are
    /// written immediately and no `RdpEvent::ChannelData` is emitted. If
    /// no processor matches, the raw bytes are surfaced as
    /// `RdpEvent::ChannelData` for the caller to handle directly.
    fn read_one_frame(&mut self) -> Result<(), RuntimeError> {
        // Local accumulators so the borrows on self.transport / self.session
        // can be released before we touch self.pending_events / self.disconnected.
        let mut local_events: Vec<RdpEvent> = Vec::new();
        let mut should_disconnect = false;
        let mut svc_responses: Vec<Vec<u8>> = Vec::new();
        let user_channel_id = self.user_channel_id;
        // Local mutable carry for the ARC cookie because the inner borrow
        // block holds a &mut on self.session and cannot also touch
        // self.last_arc_cookie. Flushed after the block ends.
        let mut captured_arc_cookie: Option<ArcCookie> = None;

        {
            let transport = self
                .transport
                .as_mut()
                .ok_or(RuntimeError::Disconnected)?;
            let session = self
                .session
                .as_mut()
                .ok_or(RuntimeError::Disconnected)?;

            let n = read_pdu(transport, &TpktHint, &mut self.scratch)
                .map_err(connect_error_to_runtime)?;
            let outputs = session.process(&self.scratch[..n])?;

            for output in outputs {
                match output {
                    ActiveStageOutput::ResponseFrame(bytes) => {
                        transport.write_all(&bytes).map_err(RuntimeError::Io)?;
                        transport.flush().map_err(RuntimeError::Io)?;
                    }
                    ActiveStageOutput::GraphicsUpdate { update_code, data } => {
                        local_events.push(RdpEvent::GraphicsUpdate { update_code, data });
                    }
                    ActiveStageOutput::PointerDefault => {
                        local_events.push(RdpEvent::PointerDefault);
                    }
                    ActiveStageOutput::PointerHidden => {
                        local_events.push(RdpEvent::PointerHidden);
                    }
                    ActiveStageOutput::PointerPosition { x, y } => {
                        local_events.push(RdpEvent::PointerPosition { x, y });
                    }
                    ActiveStageOutput::PointerBitmap { pointer_type, data } => {
                        local_events.push(RdpEvent::PointerBitmap { pointer_type, data });
                    }
                    ActiveStageOutput::SaveSessionInfo { data } => {
                        // M7: opportunistically capture the Auto-Reconnect
                        // Cookie if the server bundled one in this PDU.
                        // The cookie remains valid across the lifetime of
                        // the logon session, so we overwrite the previous
                        // value rather than ignoring updates.
                        if let Some((logon_id, arc_random_bits)) = data.arc_random() {
                            captured_arc_cookie = Some(ArcCookie::new(logon_id, arc_random_bits));
                        }
                        local_events.push(RdpEvent::SaveSessionInfo(data));
                    }
                    ActiveStageOutput::ServerMonitorLayout { monitors } => {
                        local_events.push(RdpEvent::ServerMonitorLayout { monitors });
                    }
                    ActiveStageOutput::ChannelData { channel_id, data } => {
                        // Try to dispatch to a registered SVC processor
                        // first. If one matches, capture its response
                        // frames for write-back below; the raw event is
                        // suppressed because the processor "owns" the
                        // channel. If no processor matches, fall through
                        // to a raw passthrough event so callers can still
                        // observe traffic on un-registered channels.
                        let handled = self.svc_set.get_by_channel_id(channel_id).is_some();
                        if handled {
                            let frames = self
                                .svc_set
                                .process_incoming(channel_id, &data, user_channel_id)
                                .map_err(|e| {
                                    RuntimeError::Io(io::Error::new(
                                        io::ErrorKind::Other,
                                        format!("SVC processor failed: {e:?}"),
                                    ))
                                })?;
                            svc_responses.extend(frames);
                        } else {
                            local_events.push(RdpEvent::ChannelData { channel_id, data });
                        }
                    }
                    ActiveStageOutput::KeyboardIndicators { led_flags } => {
                        local_events.push(RdpEvent::KeyboardIndicators {
                            scroll: led_flags & 0x0001 != 0,
                            num: led_flags & 0x0002 != 0,
                            caps: led_flags & 0x0004 != 0,
                            kana: led_flags & 0x0008 != 0,
                        });
                    }
                    ActiveStageOutput::KeyboardImeStatus {
                        ime_state,
                        ime_conv_mode,
                    } => {
                        local_events.push(RdpEvent::ImeStatus {
                            state: ime_state as u32,
                            convert: ime_conv_mode,
                        });
                    }
                    ActiveStageOutput::PlaySound {
                        duration_ms,
                        frequency_hz,
                    } => {
                        local_events.push(RdpEvent::PlaySound {
                            frequency: frequency_hz,
                            duration_ms,
                        });
                    }
                    ActiveStageOutput::SuppressOutput {
                        allow_display_updates,
                        rect: _,
                    } => {
                        // The dirty rectangle is currently dropped; the
                        // event signals only pause/resume. Future versions
                        // may extend RdpEvent::SuppressOutput with the rect
                        // for callers that want to invalidate a region.
                        local_events.push(RdpEvent::SuppressOutput {
                            allow: allow_display_updates,
                        });
                    }
                    ActiveStageOutput::Terminate(reason) => {
                        local_events.push(RdpEvent::Disconnected(reason));
                        should_disconnect = true;
                    }
                    // Deactivate-Reactivation requires the caller to re-run
                    // the capability exchange. The blocking runtime does not
                    // yet support this; for MVP we surface it as a graceful
                    // disconnect so callers do not loop forever waiting for
                    // events that will never come. A future milestone may
                    // implement true reactivation by re-running the
                    // connector's CapabilitiesExchange phase against the
                    // existing transport.
                    ActiveStageOutput::DeactivateAll(_)
                    | ActiveStageOutput::ServerReactivation { .. } => {
                        local_events.push(RdpEvent::Disconnected(
                            GracefulDisconnectReason::ShutdownDenied,
                        ));
                        should_disconnect = true;
                    }
                }
            }
        }

        // Flush any SVC processor responses produced by the loop above.
        // We do this *after* the local-borrow block so the borrow on
        // self.transport from read_pdu() has been released.
        if !svc_responses.is_empty() {
            let transport = self
                .transport
                .as_mut()
                .ok_or(RuntimeError::Disconnected)?;
            for frame in svc_responses {
                transport.write_all(&frame).map_err(RuntimeError::Io)?;
            }
            transport.flush().map_err(RuntimeError::Io)?;
        }

        // Persist ARC cookie outside the inner borrow block.
        if let Some(cookie) = captured_arc_cookie {
            self.last_arc_cookie = Some(cookie);
        }

        self.pending_events.extend(local_events);
        if should_disconnect {
            self.mark_disconnected();
        }
        Ok(())
    }

    fn mark_disconnected(&mut self) {
        self.disconnected = true;
        self.transport.take();
        self.session.take();
    }

    /// Attempt to reconnect after a transport-level failure.
    ///
    /// Pushes one [`RdpEvent::Reconnecting`] per attempt, then either
    /// [`RdpEvent::Reconnected`] on success or [`RdpEvent::Disconnected`]
    /// on terminal failure. The session is fully reset and ready for
    /// further [`next_event`] calls when this returns.
    ///
    /// Pre-conditions for reconnect to be attempted:
    /// - `reconnect_policy.max_attempts > 0`
    /// - `last_arc_cookie.is_some()` (the server requires the ARC cookie
    ///   to associate the new socket with the existing logon session)
    /// - `svc_set.is_empty()` — SVC processors carry per-session state
    ///   that cannot be revived from a stored Config alone, so reconnect
    ///   is mutually exclusive with channel registration in this MVP
    fn try_reconnect(&mut self) {
        if !self.can_reconnect() {
            self.pending_events.push_back(RdpEvent::Disconnected(
                GracefulDisconnectReason::ServerDisconnect(
                    justrdp_pdu::mcs::DisconnectReason::DomainDisconnected,
                ),
            ));
            self.mark_disconnected();
            return;
        }

        // Drop the dead transport eagerly so a flapping reconnect loop
        // doesn't accidentally reuse a half-closed socket.
        self.transport.take();
        self.session.take();

        let max_attempts = self.reconnect_policy.max_attempts;
        for attempt in 1..=max_attempts {
            let delay = self.reconnect_policy.delay_for_attempt(attempt);
            if delay > std::time::Duration::ZERO {
                std::thread::sleep(delay);
            }
            self.pending_events
                .push_back(RdpEvent::Reconnecting { attempt });

            match self.do_one_reconnect() {
                Ok(()) => {
                    self.pending_events.push_back(RdpEvent::Reconnected);
                    return;
                }
                Err(_e) => {
                    // Try again on the next iteration. Errors are
                    // intentionally swallowed here; if all attempts fail
                    // the loop falls through to the disconnect path.
                }
            }
        }

        // All attempts exhausted.
        self.pending_events.push_back(RdpEvent::Disconnected(
            GracefulDisconnectReason::ServerDisconnect(
                justrdp_pdu::mcs::DisconnectReason::DomainDisconnected,
            ),
        ));
        self.mark_disconnected();
    }

    fn can_reconnect(&self) -> bool {
        self.reconnect_policy.max_attempts > 0
            && self.last_arc_cookie.is_some()
            && self.svc_set.is_empty()
    }

    /// Perform one full reconnection attempt: TCP + TLS + CredSSP +
    /// connection finalization, using the saved server address, server
    /// name, and config (with the latest ARC cookie injected).
    ///
    /// On success, the session-related fields on `self` are replaced
    /// with the new connection's values; the "last_*" remembered fields
    /// stay intact for the next reconnect attempt.
    fn do_one_reconnect(&mut self) -> Result<(), ConnectError> {
        let mut config = self.last_config.clone();
        config.auto_reconnect_cookie = self.last_arc_cookie.clone();

        // Reuse the simple connect() path. This rebuilds a fresh
        // RustlsUpgrader with AcceptAll — applications that need a
        // pinned verifier across reconnects must use a custom verifier
        // factory (not yet exposed).
        let new_client =
            Self::connect(self.last_server_addr, &self.last_server_name, config)?;

        // Move the new client's "session" fields into self while keeping
        // the existing reconnect_policy, last_*, and pending_events.
        self.transport = new_client.transport;
        self.session = new_client.session;
        self.svc_set = new_client.svc_set;
        self.user_channel_id = new_client.user_channel_id;
        self.server_public_key = new_client.server_public_key;
        self.last_arc_cookie = new_client.last_arc_cookie.or_else(|| self.last_arc_cookie.clone());
        self.scratch.clear();
        self.disconnected = false;
        Ok(())
    }

    /// Send a single keyboard scancode press or release.
    ///
    /// Encodes a fast-path scancode input event with the appropriate
    /// `KBDFLAGS_RELEASE` / `KBDFLAGS_EXTENDED` flags and writes it to
    /// the active session transport.
    pub fn send_keyboard(
        &mut self,
        scancode: Scancode,
        pressed: bool,
    ) -> Result<(), RuntimeError> {
        self.send_input_events(&[build_scancode_event(scancode, pressed)])
    }

    /// Send a single Unicode key press or release (BMP code points only).
    ///
    /// Code points outside the Basic Multilingual Plane (i.e. above U+FFFF)
    /// require UTF-16 surrogate pairs and are not yet handled — calling this
    /// with such a `char` returns [`RuntimeError::Unimplemented`].
    pub fn send_unicode(&mut self, ch: char, pressed: bool) -> Result<(), RuntimeError> {
        let event = build_unicode_event(ch, pressed).ok_or(RuntimeError::Unimplemented(
            "send_unicode: surrogate pairs (code points > U+FFFF)",
        ))?;
        self.send_input_events(&[event])
    }

    /// Send an absolute mouse position update.
    ///
    /// Sends a fast-path mouse event with [`PTRFLAGS_MOVE`] and the new
    /// `(x, y)` coordinates. Coordinates are in the desktop coordinate
    /// space negotiated during the connection sequence (see
    /// [`ConnectionResult`](justrdp_connector::ConnectionResult)).
    pub fn send_mouse_move(&mut self, x: u16, y: u16) -> Result<(), RuntimeError> {
        self.send_input_events(&[build_mouse_move_event(x, y)])
    }

    /// Send a mouse button press or release at the given coordinates.
    ///
    /// `(x, y)` is included because the fast-path mouse event always
    /// carries a position; pass the cursor's current location.
    /// X1/X2 buttons are not yet supported by this helper (the wire
    /// format requires a separate `MouseX` event with different flag
    /// constants); calling with `MouseButton::X1` or `X2` returns
    /// [`RuntimeError::Unimplemented`].
    pub fn send_mouse_button(
        &mut self,
        button: MouseButton,
        pressed: bool,
        x: u16,
        y: u16,
    ) -> Result<(), RuntimeError> {
        let event = build_mouse_button_event(button, pressed, x, y).ok_or(
            RuntimeError::Unimplemented(
                "send_mouse_button: X1/X2 require a fast-path MouseX event",
            ),
        )?;
        self.send_input_events(&[event])
    }

    /// Encode and write a batch of fast-path input events to the transport.
    ///
    /// Pre-condition: the session must be active. After a disconnect this
    /// returns [`RuntimeError::Disconnected`] without touching the network.
    fn send_input_events(&mut self, events: &[FastPathInputEvent]) -> Result<(), RuntimeError> {
        let session = self
            .session
            .as_mut()
            .ok_or(RuntimeError::Disconnected)?;
        let transport = self
            .transport
            .as_mut()
            .ok_or(RuntimeError::Disconnected)?;
        let frame = session.encode_input_events(events)?;
        transport.write_all(&frame).map_err(RuntimeError::Io)?;
        transport.flush().map_err(RuntimeError::Io)?;
        Ok(())
    }

    /// Gracefully disconnect the session and consume the client.
    ///
    /// *Scaffold: drops the transport without sending an MCS Disconnect Provider
    /// Ultimatum. Polite shutdown via `ActiveStage::encode_disconnect()` will
    /// land in a follow-up.*
    pub fn disconnect(mut self) -> Result<(), RuntimeError> {
        self.transport.take();
        self.session.take();
        Ok(())
    }
}

// ── Pure event-building helpers (testable without a live session) ──

/// Build a fast-path scancode input event from an [`InputDatabase`]-style
/// scancode + press/release flag.
fn build_scancode_event(scancode: Scancode, pressed: bool) -> FastPathInputEvent {
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

/// Build a fast-path Unicode key event. Returns `None` for code points
/// outside the BMP (which would require a UTF-16 surrogate pair).
fn build_unicode_event(ch: char, pressed: bool) -> Option<FastPathInputEvent> {
    let code = u32::from(ch);
    if code > u16::MAX as u32 {
        return None;
    }
    let event_flags = if pressed { 0 } else { KBDFLAGS_RELEASE };
    Some(FastPathInputEvent::Unicode(FastPathUnicodeEvent {
        event_flags,
        unicode_code: code as u16,
    }))
}

/// Build a fast-path mouse-move event with [`PTRFLAGS_MOVE`].
fn build_mouse_move_event(x: u16, y: u16) -> FastPathInputEvent {
    FastPathInputEvent::Mouse(FastPathMouseEvent {
        event_flags: 0,
        pointer_flags: PTRFLAGS_MOVE,
        x_pos: x,
        y_pos: y,
    })
}

/// Build a fast-path mouse button press/release event. Returns `None` for
/// `MouseButton::X1` / `X2`, which require a separate `MouseX` event type.
fn build_mouse_button_event(
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

/// Translate a transport-level [`ConnectError`] (used during the handshake)
/// into a [`RuntimeError`] suitable for the active session loop.
fn connect_error_to_runtime(err: ConnectError) -> RuntimeError {
    match err {
        ConnectError::Tcp(io) => RuntimeError::Io(io),
        ConnectError::UnexpectedEof => RuntimeError::Disconnected,
        ConnectError::FrameTooLarge(n) => RuntimeError::FrameTooLarge(n),
        // Tls/Connector/Unimplemented should never originate from the
        // active-session pump path; map them to a generic I/O error so
        // they remain visible if invariants ever break.
        other => RuntimeError::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("unexpected error in active session pump: {other}"),
        )),
    }
}

/// Drive the connector step loop, forwarding bytes to/from `transport`,
/// until `stop_when(connector.state())` returns `true`.
fn drive_until_state_change<F>(
    connector: &mut ClientConnector,
    transport: &mut Transport,
    stop_when: F,
) -> Result<(), ConnectError>
where
    F: Fn(&ClientConnectorState) -> bool,
{
    let mut output = WriteBuf::new();
    let mut scratch: Vec<u8> = Vec::new();

    loop {
        if stop_when(connector.state()) {
            return Ok(());
        }

        let hint = connector.next_pdu_hint();
        if let Some(hint) = hint {
            let n = read_pdu(transport, hint, &mut scratch)?;
            let _written = connector.step(&scratch[..n], &mut output)?;
        } else {
            output.clear();
            let _written = connector.step(&[], &mut output)?;
        }

        if !output.is_empty() {
            write_all(transport, output.as_slice())?;
            output.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Transport::Swapping` must return an error on any I/O attempt so
    /// that a partially-swapped client never silently drops bytes.
    #[test]
    fn swapping_transport_errors_on_read_and_write() {
        let mut t = Transport::Swapping;
        let mut buf = [0u8; 4];
        assert!(t.read(&mut buf).is_err());
        assert!(t.write(b"hi").is_err());
        assert!(t.flush().is_err());
    }

    // ── Input helper unit tests ──

    #[test]
    fn scancode_event_press_basic() {
        let event = build_scancode_event(Scancode::new(0x1E, false), true);
        match event {
            FastPathInputEvent::Scancode(e) => {
                assert_eq!(e.event_flags, 0);
                assert_eq!(e.key_code, 0x1E);
            }
            _ => panic!("expected Scancode variant"),
        }
    }

    #[test]
    fn scancode_event_release_sets_release_flag() {
        let event = build_scancode_event(Scancode::new(0x1E, false), false);
        match event {
            FastPathInputEvent::Scancode(e) => {
                assert_eq!(e.event_flags, KBDFLAGS_RELEASE);
            }
            _ => panic!("expected Scancode variant"),
        }
    }

    #[test]
    fn scancode_event_extended_sets_extended_flag() {
        // Extended scancode (e.g. cursor keys) released
        let event = build_scancode_event(Scancode::new(0x4B, true), false);
        match event {
            FastPathInputEvent::Scancode(e) => {
                assert_eq!(e.event_flags, KBDFLAGS_RELEASE | KBDFLAGS_EXTENDED);
                assert_eq!(e.key_code, 0x4B);
            }
            _ => panic!("expected Scancode variant"),
        }
    }

    #[test]
    fn unicode_event_bmp_press_succeeds() {
        let event = build_unicode_event('가', true).expect("BMP code point");
        match event {
            FastPathInputEvent::Unicode(e) => {
                assert_eq!(e.event_flags, 0);
                assert_eq!(e.unicode_code, 0xAC00);
            }
            _ => panic!("expected Unicode variant"),
        }
    }

    #[test]
    fn unicode_event_release_sets_release_flag() {
        let event = build_unicode_event('A', false).unwrap();
        match event {
            FastPathInputEvent::Unicode(e) => {
                assert_eq!(e.event_flags, KBDFLAGS_RELEASE);
                assert_eq!(e.unicode_code, 0x41);
            }
            _ => panic!("expected Unicode variant"),
        }
    }

    #[test]
    fn unicode_event_supplementary_plane_returns_none() {
        // U+1F600 (😀) is outside the BMP and needs a surrogate pair.
        let event = build_unicode_event('😀', true);
        assert!(event.is_none(), "supplementary code points must return None");
    }

    #[test]
    fn mouse_move_event_sets_move_flag_and_position() {
        let event = build_mouse_move_event(1024, 768);
        match event {
            FastPathInputEvent::Mouse(e) => {
                assert_eq!(e.pointer_flags, PTRFLAGS_MOVE);
                assert_eq!(e.x_pos, 1024);
                assert_eq!(e.y_pos, 768);
                assert_eq!(e.event_flags, 0);
            }
            _ => panic!("expected Mouse variant"),
        }
    }

    #[test]
    fn mouse_button_press_left() {
        let event = build_mouse_button_event(MouseButton::Left, true, 100, 200).unwrap();
        match event {
            FastPathInputEvent::Mouse(e) => {
                assert_eq!(e.pointer_flags, PTRFLAGS_BUTTON1 | PTRFLAGS_DOWN);
                assert_eq!(e.x_pos, 100);
                assert_eq!(e.y_pos, 200);
            }
            _ => panic!("expected Mouse variant"),
        }
    }

    #[test]
    fn mouse_button_release_right_omits_down_flag() {
        let event = build_mouse_button_event(MouseButton::Right, false, 0, 0).unwrap();
        match event {
            FastPathInputEvent::Mouse(e) => {
                assert_eq!(e.pointer_flags, PTRFLAGS_BUTTON2);
            }
            _ => panic!("expected Mouse variant"),
        }
    }

    #[test]
    fn mouse_button_middle_uses_button3_flag() {
        let event = build_mouse_button_event(MouseButton::Middle, true, 50, 50).unwrap();
        match event {
            FastPathInputEvent::Mouse(e) => {
                assert_eq!(e.pointer_flags, PTRFLAGS_BUTTON3 | PTRFLAGS_DOWN);
            }
            _ => panic!("expected Mouse variant"),
        }
    }

    #[test]
    fn mouse_button_x1_x2_return_none() {
        assert!(build_mouse_button_event(MouseButton::X1, true, 0, 0).is_none());
        assert!(build_mouse_button_event(MouseButton::X2, false, 0, 0).is_none());
    }

    // ── SVC processor wiring ──

    use justrdp_svc::{ChannelName, CompressionCondition, SvcMessage, SvcResult};
    use std::string::String as StdString;

    /// Minimal SvcProcessor that records every payload it sees and echoes
    /// `b"reply"` back. Used to verify M6's dispatch contract without
    /// standing up a real connection.
    #[derive(Debug, Default)]
    struct RecordingProcessor {
        seen: Vec<Vec<u8>>,
    }

    impl justrdp_core::AsAny for RecordingProcessor {
        fn as_any(&self) -> &dyn core::any::Any { self }
        fn as_any_mut(&mut self) -> &mut dyn core::any::Any { self }
    }

    impl SvcProcessor for RecordingProcessor {
        fn channel_name(&self) -> ChannelName {
            ChannelName::new(b"echo")
        }
        fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
            Ok(Vec::new())
        }
        fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
            self.seen.push(payload.to_vec());
            Ok(vec![SvcMessage::new(b"reply".to_vec())])
        }
        fn compression_condition(&self) -> CompressionCondition {
            CompressionCondition::Never
        }
    }

    /// Build a single-chunk channel data payload that the SVC framework
    /// will hand to its processor as `b"hello"`.
    fn channel_data_payload(payload: &[u8]) -> Vec<u8> {
        use justrdp_pdu::rdp::svc::{CHANNEL_FLAG_FIRST, CHANNEL_FLAG_LAST};
        let total = payload.len() as u32;
        let flags = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
        let mut buf = Vec::with_capacity(8 + payload.len());
        buf.extend_from_slice(&total.to_le_bytes());
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn svc_set_dispatches_to_registered_processor() {
        // Replicate the M6 wiring path on a bare SvcChannelSet so we can
        // assert the contract without a live RdpClient.
        let mut set = SvcChannelSet::new();
        set.insert(Box::new(RecordingProcessor::default())).unwrap();
        set.assign_ids(&[(StdString::from("echo"), 1004)]);

        let raw = channel_data_payload(b"hello");
        let response_frames = set.process_incoming(1004, &raw, 1007).unwrap();
        // Recording processor returns one SvcMessage; framework wraps it
        // as a single MCS frame ready for the wire.
        assert_eq!(response_frames.len(), 1);
    }

    #[test]
    fn svc_set_unknown_channel_returns_no_frames() {
        // M6's read_one_frame path checks `get_by_channel_id().is_some()`
        // before calling process_incoming. This test guards the underlying
        // SvcChannelSet behavior we rely on: if the channel ID is not
        // registered, get_by_channel_id returns None and the raw passthrough
        // path triggers in client.rs.
        let mut set = SvcChannelSet::new();
        set.insert(Box::new(RecordingProcessor::default())).unwrap();
        set.assign_ids(&[(StdString::from("echo"), 1004)]);

        assert!(set.get_by_channel_id(9999).is_none());
        assert!(set.get_by_channel_id(1004).is_some());
    }

    // ── M7 auto-reconnect ──

    /// Build a `RdpClient` instance directly for predicate-only tests.
    /// `connect()` requires a real network so we hand-construct the
    /// fields here. The transport/session are `None` to mirror the
    /// "just disconnected, no live session" state where `try_reconnect`
    /// is actually called.
    fn synthetic_client(
        policy: ReconnectPolicy,
        cookie: Option<ArcCookie>,
        with_processor: bool,
    ) -> RdpClient {
        let mut svc_set = SvcChannelSet::new();
        if with_processor {
            svc_set
                .insert(Box::new(RecordingProcessor::default()))
                .unwrap();
        }
        RdpClient {
            transport: None,
            session: None,
            reconnect_policy: policy,
            scratch: Vec::new(),
            pending_events: VecDeque::new(),
            disconnected: false,
            svc_set,
            user_channel_id: 1007,
            server_public_key: None,
            last_server_addr: "127.0.0.1:3389".parse().unwrap(),
            last_server_name: StdString::from("localhost"),
            last_config: justrdp_connector::Config::builder("u", "p").build(),
            last_arc_cookie: cookie,
        }
    }

    fn dummy_cookie() -> ArcCookie {
        ArcCookie::new(0xDEAD_BEEF, [0xAAu8; 16])
    }

    #[test]
    fn can_reconnect_requires_enabled_policy() {
        let client = synthetic_client(ReconnectPolicy::disabled(), Some(dummy_cookie()), false);
        assert!(!client.can_reconnect(), "disabled policy must veto");
    }

    #[test]
    fn can_reconnect_requires_arc_cookie() {
        let client = synthetic_client(ReconnectPolicy::aggressive(), None, false);
        assert!(!client.can_reconnect(), "missing ARC cookie must veto");
    }

    #[test]
    fn can_reconnect_blocked_by_processors() {
        // SVC processors carry per-session state that cannot be revived
        // from a saved Config alone, so reconnect is mutually exclusive
        // with channel registration in the MVP.
        let client = synthetic_client(
            ReconnectPolicy::aggressive(),
            Some(dummy_cookie()),
            true,
        );
        assert!(
            !client.can_reconnect(),
            "presence of SVC processors must veto reconnect"
        );
    }

    #[test]
    fn can_reconnect_allowed_with_policy_and_cookie() {
        let client = synthetic_client(
            ReconnectPolicy::aggressive(),
            Some(dummy_cookie()),
            false,
        );
        assert!(client.can_reconnect());
    }

    #[test]
    fn try_reconnect_disabled_policy_emits_disconnect_and_marks_terminal() {
        let mut client = synthetic_client(ReconnectPolicy::disabled(), None, false);
        client.try_reconnect();

        assert!(client.disconnected);
        // Exactly one Disconnected event in the queue, no Reconnecting noise.
        assert_eq!(client.pending_events.len(), 1);
        assert!(matches!(
            client.pending_events.front(),
            Some(RdpEvent::Disconnected(_))
        ));
    }

    #[test]
    fn try_reconnect_with_processors_short_circuits_to_disconnect() {
        let mut client = synthetic_client(
            ReconnectPolicy::aggressive(),
            Some(dummy_cookie()),
            true,
        );
        client.try_reconnect();
        assert!(client.disconnected);
        assert_eq!(client.pending_events.len(), 1);
        assert!(matches!(
            client.pending_events.front(),
            Some(RdpEvent::Disconnected(_))
        ));
    }
}
