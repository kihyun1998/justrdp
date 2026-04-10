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
use justrdp_input::{InputDatabase, LockKeys, MouseButton, Operation, Scancode, MAX_RELEASE_OPS};
use justrdp_pdu::rdp::fast_path::{
    FastPathInputEvent, FastPathMouseEvent, FastPathScancodeEvent, FastPathSyncEvent,
    FastPathUnicodeEvent,
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
const PTRFLAGS_WHEEL: u16 = 0x0200; // vertical wheel rotation
const PTRFLAGS_HWHEEL: u16 = 0x0400; // horizontal wheel rotation
const PTRFLAGS_WHEEL_NEGATIVE: u16 = 0x0100; // wheel rotation is negative

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
    /// Active session processor.
    ///
    /// Boxed because `ActiveStage` carries two `BulkDecompressor` instances
    /// (slow-path and fast-path) and each one inlines a 64 KiB MPPC64K
    /// history buffer plus a 64 KiB NCRUSH history buffer plus an 8 KiB
    /// MPPC8K history. With both decompressors that's ~272 KiB inline; if
    /// it lived directly on `RdpClient`, the struct would blow Windows'
    /// default 1 MiB stack as soon as it crossed two nested method frames
    /// without NRVO. Heap-allocating it keeps `RdpClient` small.
    session: Option<Box<ActiveStage>>,
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
    /// Input state tracker. Deduplicates key/button presses, tracks mouse
    /// position, and supports batch release on focus loss.
    input_db: InputDatabase,
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
        let initial_addr = server
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| {
                ConnectError::Tcp(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no socket addresses resolved from `server` argument",
                ))
            })?;

        // 9.3 Session Redirection: the handshake may need to be re-run
        // against a different target if the broker sends a redirection
        // PDU. We loop here so the same `upgrader` instance can be
        // reused across redirects (its trait method takes &self).
        let mut current_addr = initial_addr;
        let current_name = server_name.to_string();
        let mut current_config = config;
        let mut redirect_depth: u32 = 0;
        const MAX_REDIRECTS: u32 = 5;

        // Outputs of one successful (non-redirected) handshake. Filled in
        // by the loop body once the connector reaches Connected without
        // server_redirection.
        let (mut transport, server_public_key, last_arc_cookie, result_for_session): (
            Transport,
            Option<Vec<u8>>,
            Option<ArcCookie>,
            ResultForSession,
        ) = loop {
            let tcp = TcpStream::connect(current_addr)?;
            // Clone the config so we can rebuild ClientConnector on the
            // next iteration if a redirect is detected.
            let mut connector = ClientConnector::new(current_config.clone());
            let mut transport = Transport::Tcp(tcp);

            // Phase 1: drive to TLS upgrade point.
            drive_until_state_change(&mut connector, &mut transport, |s| {
                matches!(
                    s,
                    ClientConnectorState::EnhancedSecurityUpgrade
                        | ClientConnectorState::Connected { .. }
                )
            })?;

            // Phase 2: TLS upgrade if needed.
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
                let upgraded = upgrader.upgrade(tcp, &current_name)?;
                transport = Transport::Tls(Box::new(upgraded.stream));
                Some(upgraded.server_public_key)
            } else {
                None
            };

            // Phase 3: Step past EnhancedSecurityUpgrade then run CredSSP if needed.
            drive_until_state_change(&mut connector, &mut transport, |s| {
                !matches!(s, ClientConnectorState::EnhancedSecurityUpgrade)
            })?;

            if matches!(
                connector.state(),
                ClientConnectorState::CredsspNegoTokens
                    | ClientConnectorState::CredsspPubKeyAuth
                    | ClientConnectorState::CredsspCredentials
            ) {
                let server_pub_key = server_public_key
                    .as_ref()
                    .cloned()
                    .ok_or(ConnectError::Unimplemented(
                        "CredSSP requires a TLS upgrade to capture server_public_key",
                    ))?;
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

            // Phase 4: BasicSettings → ... → Finalization → Connected.
            drive_until_state_change(&mut connector, &mut transport, |s| s.is_connected())?;

            let result = connector.result().ok_or_else(|| {
                ConnectError::Unimplemented(
                    "connector reached Connected but result() returned None",
                )
            })?;

            // 9.3 redirect dispatch: if the connector captured a Server
            // Redirection PDU, the current transport is unusable — drop
            // it, build a fresh Config from the redirect target, and
            // restart the handshake. Otherwise fall through with the
            // values needed to construct RdpClient.
            if let Some(redir) = result.server_redirection.clone() {
                redirect_depth += 1;
                if redirect_depth > MAX_REDIRECTS {
                    return Err(ConnectError::Tcp(io::Error::new(
                        io::ErrorKind::Other,
                        format!("too many redirects ({MAX_REDIRECTS} max) — aborting"),
                    )));
                }

                // Drop the current transport explicitly so the OS sends
                // FIN to the broker before we open the next socket.
                drop(transport);

                // Decide the next target. Priority:
                //   1. LB_TARGET_NET_ADDRESS (UTF-16LE host string)
                //   2. LB_TARGET_NET_ADDRESSES first entry
                //   3. fall through to current_addr (LB cookie only)
                let new_addr = parse_redirect_target(&redir, current_addr.port())
                    .unwrap_or(current_addr);

                // Build the next Config: clone the previous one, blow
                // away routing_token / cookie / arc_cookie so they don't
                // collide with the redirect-supplied LB info, and inject
                // the new routing token if the broker provided one.
                let mut next_config = current_config.clone();
                next_config.routing_token = redir.load_balance_info.clone();
                next_config.cookie = None;
                next_config.auto_reconnect_cookie = None;

                // When the broker sends a PK-encrypted password blob,
                // the redirected connection must use RDSTLS to pass it
                // through to the target RD Session Host.
                if redir.redir_flags & justrdp_pdu::rdp::redirection::LB_PASSWORD_IS_PK_ENCRYPTED != 0 {
                    // Only switch to RDSTLS when the password blob is
                    // actually present; if the flag is set but the field
                    // is absent, fall through to the normal auth path.
                    if let Some(pw) = &redir.password {
                        next_config.redirection_password_blob = Some(pw.clone());
                        next_config.security_protocol =
                            justrdp_pdu::x224::SecurityProtocol::RDSTLS;
                        if let Some(guid) = &redir.redirection_guid {
                            next_config.redirection_guid = Some(guid.clone());
                        }
                    }
                }

                // Override username/domain from the redirect PDU if provided.
                if let Some(ref u) = redir.username {
                    if let Some(name) = utf16le_to_string(u) {
                        next_config.credentials.username = name;
                    }
                }
                if let Some(ref d) = redir.domain {
                    if let Some(dom) = utf16le_to_string(d) {
                        next_config.domain = Some(dom);
                    }
                }

                current_addr = new_addr;
                current_config = next_config;
                continue;
            }

            // No redirect — break out with everything we need.
            let user_channel_id = result.user_channel_id;
            let session_config = SessionConfig {
                io_channel_id: result.io_channel_id,
                user_channel_id,
                share_id: result.share_id,
                channel_ids: result.channel_ids.clone(),
            };
            let server_arc_cookie = result.server_arc_cookie.clone();
            break (
                transport,
                server_public_key,
                server_arc_cookie,
                ResultForSession {
                    session_config,
                    user_channel_id,
                    channel_ids: result.channel_ids.clone(),
                    redirect_depth,
                },
            );
        };

        // From here on, the loop has exited with a usable transport
        // pointing at the (post-redirect) target. The remaining setup
        // (ActiveStage, SVC processors, RdpClient construction) is
        // identical to the pre-9.3 path.
        let last_server_addr = current_addr;
        let last_server_name = current_name;
        let last_config = current_config;

        let user_channel_id = result_for_session.user_channel_id;
        let channel_ids = result_for_session.channel_ids;
        let session = Box::new(ActiveStage::new(result_for_session.session_config));

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
        // to send. The frames are already MCS+TPKT wrapped so they go
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

        // If we followed one or more redirects to reach this target,
        // queue a single `Redirected` event so the caller can observe it
        // through the normal `next_event` loop. The target string is
        // best-effort: a "host:port" rendering of the final SocketAddr
        // we landed on.
        let mut pending_events = VecDeque::new();
        if result_for_session.redirect_depth > 0 {
            pending_events.push_back(RdpEvent::Redirected {
                target: format!("{}", last_server_addr),
            });
        }

        Ok(Self {
            transport: Some(transport),
            session: Some(session),
            reconnect_policy: ReconnectPolicy::disabled(),
            scratch: Vec::new(),
            pending_events,
            disconnected: false,
            svc_set,
            user_channel_id,
            server_public_key,
            last_server_addr,
            last_server_name,
            last_config,
            last_arc_cookie,
            input_db: InputDatabase::new(),
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
        // Local carry for a server-initiated termination. Processed
        // after the borrow block so we can route through try_reconnect
        // if the error code is retryable.
        let mut terminate_reason: Option<GracefulDisconnectReason> = None;

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
            self.scratch.drain(..n);

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
                        // Record whether this is a retryable error code
                        // so the outer loop can route through try_reconnect
                        // instead of tearing the session down.
                        //
                        // The check happens AFTER the borrow block
                        // because try_reconnect needs full mutable access
                        // to self; we carry the decision out via a local
                        // flag and the disconnect reason.
                        terminate_reason = Some(reason);
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

        // Server-initiated termination: decide whether to route through
        // try_reconnect (retryable error) or surface as Disconnected.
        if let Some(reason) = terminate_reason {
            let retryable = match &reason {
                // SetErrorInfo code recorded by ActiveStage.
                GracefulDisconnectReason::ServerError(code) => {
                    justrdp_pdu::rdp::finalization::is_error_info_retryable(*code)
                }
                // MCS DisconnectProviderUltimatum without a prior
                // SetErrorInfo — treat as non-retryable because we
                // don't have an error code to classify.
                GracefulDisconnectReason::ServerDisconnect(_) => false,
                // Explicit user/server/redirect intents — never retry.
                GracefulDisconnectReason::UserRequested
                | GracefulDisconnectReason::ShutdownDenied
                | GracefulDisconnectReason::ServerRedirect => false,
            };

            if retryable && self.can_reconnect() {
                // Caller will see Reconnecting/Reconnected events from
                // try_reconnect; do NOT queue a Disconnected event.
                self.try_reconnect();
            } else {
                self.pending_events.push_back(RdpEvent::Disconnected(reason));
                should_disconnect = true;
            }
        }

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

    /// Send a mouse wheel rotation event.
    ///
    /// `delta` is the signed rotation count in mouse-wheel "clicks".
    /// Positive values rotate the wheel away from the user (scroll up /
    /// right for horizontal), negative values rotate toward the user.
    /// The wire format carries the magnitude in the low byte of
    /// `pointerFlags` (0..=255) and uses `PTRFLAGS_WHEEL_NEGATIVE` as
    /// the sign bit, so the per-event magnitude is clamped to 255.
    /// Callers that need larger rotations should send multiple events.
    ///
    /// `horizontal` = `true` emits `PTRFLAGS_HWHEEL`; `false` (the
    /// common case) emits `PTRFLAGS_WHEEL`. `(x, y)` is the current
    /// cursor position, carried unchanged in the event.
    pub fn send_mouse_wheel(
        &mut self,
        delta: i16,
        horizontal: bool,
        x: u16,
        y: u16,
    ) -> Result<(), RuntimeError> {
        self.send_input_events(&[build_mouse_wheel_event(delta, horizontal, x, y)])
    }

    /// Send a synchronize event to inform the server of the current lock-key
    /// state (Scroll Lock, Num Lock, Caps Lock, Kana Lock).
    ///
    /// Per MS-RDPBCGR §2.2.8.1.2.2.5, this should be sent whenever the
    /// client window receives input focus.
    pub fn send_synchronize(&mut self, lock_keys: LockKeys) -> Result<(), RuntimeError> {
        self.send_input_events(&[build_sync_event(lock_keys)])
    }

    // ── State-tracked input API ──
    //
    // These methods go through the internal `InputDatabase` which deduplicates
    // events (e.g. suppresses a second key-press when the key is already held)
    // and tracks the current input state. Prefer these over the raw `send_*`
    // methods above when the caller cannot easily track input state itself.

    /// Record a key press and send the event. Returns `Ok(false)` if the
    /// key was already held (duplicate suppressed, nothing sent).
    pub fn key_press(&mut self, scancode: Scancode) -> Result<bool, RuntimeError> {
        if let Some(op) = self.input_db.key_press(scancode) {
            self.send_operation(op)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Record a key release and send the event. Returns `Ok(false)` if the
    /// key was not held (duplicate suppressed, nothing sent).
    pub fn key_release(&mut self, scancode: Scancode) -> Result<bool, RuntimeError> {
        if let Some(op) = self.input_db.key_release(scancode) {
            self.send_operation(op)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Record a mouse button press and send the event. Returns `Ok(false)`
    /// if the button was already held.
    ///
    /// `x` / `y` are the cursor coordinates at the time of the click;
    /// the `InputDatabase` does not track position for button events —
    /// the caller must supply it.
    pub fn button_press(
        &mut self,
        button: MouseButton,
        x: u16,
        y: u16,
    ) -> Result<bool, RuntimeError> {
        if self.input_db.mouse_button_press(button).is_some() {
            self.send_mouse_button(button, true, x, y)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Record a mouse button release and send the event. Returns `Ok(false)`
    /// if the button was not held.
    pub fn button_release(
        &mut self,
        button: MouseButton,
        x: u16,
        y: u16,
    ) -> Result<bool, RuntimeError> {
        if self.input_db.mouse_button_release(button).is_some() {
            self.send_mouse_button(button, false, x, y)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Record a mouse move and send the event. Returns `Ok(false)` if the
    /// position has not changed.
    pub fn move_mouse(&mut self, x: u16, y: u16) -> Result<bool, RuntimeError> {
        if self.input_db.mouse_move(x, y).is_some() {
            self.send_mouse_move(x, y)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Update lock-key state and send a synchronize event. This always
    /// sends an event (per RDP spec, synchronize is unconditional on
    /// focus gain).
    pub fn synchronize(&mut self, lock_keys: LockKeys) -> Result<(), RuntimeError> {
        let op = self.input_db.synchronize_event(lock_keys);
        self.send_operation(op)
    }

    /// Release all held keys and mouse buttons, sending the appropriate
    /// release events. Call this when the client window loses focus.
    /// Returns the number of release events sent.
    pub fn release_all_input(&mut self) -> Result<usize, RuntimeError> {
        let mut ops = [Operation::KeyPressed(Scancode::new(0, false)); MAX_RELEASE_OPS];
        let count = self.input_db.release_all(&mut ops);
        // Build all events before sending so a partial-send failure cannot
        // leave InputDatabase cleared while the server still sees keys held.
        let (mx, my) = self.input_db.mouse_position();
        let events: Vec<FastPathInputEvent> = ops[..count]
            .iter()
            .filter_map(|op| match *op {
                Operation::KeyReleased(sc) => Some(build_scancode_event(sc, false)),
                Operation::MouseButtonReleased(btn) => {
                    // X1/X2 require a MouseX fast-path event which is not
                    // yet implemented; skip them rather than sending a bogus
                    // substitute event that would leave the server confused.
                    build_mouse_button_event(btn, false, mx, my)
                }
                _ => unreachable!("release_all only emits release operations"),
            })
            .collect();
        let sent = events.len();
        self.send_input_events(&events)?;
        Ok(sent)
    }

    /// Check whether a key is currently held (per `InputDatabase` state).
    pub fn is_key_pressed(&self, scancode: Scancode) -> bool {
        self.input_db.is_key_pressed(scancode)
    }

    /// Check whether a mouse button is currently held.
    pub fn is_button_pressed(&self, button: MouseButton) -> bool {
        self.input_db.is_mouse_button_pressed(button)
    }

    /// Current mouse position as tracked by the `InputDatabase`.
    pub fn mouse_position(&self) -> (u16, u16) {
        self.input_db.mouse_position()
    }

    /// Current lock-key state as tracked by the `InputDatabase`.
    pub fn lock_keys(&self) -> LockKeys {
        self.input_db.lock_keys()
    }

    /// Convert an [`Operation`] from the `InputDatabase` into a fast-path
    /// event and send it over the wire.
    fn send_operation(&mut self, op: Operation) -> Result<(), RuntimeError> {
        let event = match op {
            Operation::KeyPressed(sc) => build_scancode_event(sc, true),
            Operation::KeyReleased(sc) => build_scancode_event(sc, false),
            Operation::UnicodeKeyPressed(code) => {
                FastPathInputEvent::Unicode(FastPathUnicodeEvent {
                    event_flags: 0,
                    unicode_code: code,
                })
            }
            Operation::UnicodeKeyReleased(code) => {
                FastPathInputEvent::Unicode(FastPathUnicodeEvent {
                    event_flags: KBDFLAGS_RELEASE,
                    unicode_code: code,
                })
            }
            Operation::MouseButtonPressed(btn) => {
                let (x, y) = self.input_db.mouse_position();
                return self.send_mouse_button(btn, true, x, y);
            }
            Operation::MouseButtonReleased(btn) => {
                let (x, y) = self.input_db.mouse_position();
                return self.send_mouse_button(btn, false, x, y);
            }
            Operation::MouseMove { x, y } => build_mouse_move_event(x, y),
            Operation::RelativeMouseMove { .. } => {
                return Err(RuntimeError::Unimplemented(
                    "RelativeMouseMove not yet wired to fast-path relative mouse event",
                ));
            }
            Operation::WheelRotations(delta) => {
                let (wx, wy) = self.input_db.mouse_position();
                build_mouse_wheel_event(delta, false, wx, wy)
            }
            Operation::HorizontalWheelRotations(delta) => {
                let (wx, wy) = self.input_db.mouse_position();
                build_mouse_wheel_event(delta, true, wx, wy)
            }
            Operation::SynchronizeEvent(locks) => build_sync_event(locks),
        };
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
    /// Builds an MCS Disconnect Provider Ultimatum frame via the
    /// session's built-in encoder and writes it to the transport before
    /// dropping both, so the server sees a clean shutdown instead of
    /// a TCP RST. If the session has already been torn down (because
    /// of an earlier Disconnected event, a failed reconnect, or a
    /// prior transport drop), this is a no-op and returns `Ok(())`.
    ///
    /// Write failures on the farewell frame are **ignored** — the
    /// caller is shutting the session down anyway and the socket might
    /// already be half-closed from the server side. The transport is
    /// still dropped so the local file descriptor is released.
    pub fn disconnect(mut self) -> Result<(), RuntimeError> {
        if let (Some(session), Some(transport)) =
            (self.session.as_mut(), self.transport.as_mut())
        {
            if let Ok(frame) = session.encode_disconnect() {
                let _ = transport.write_all(&frame);
                let _ = transport.flush();
            }
        }
        self.transport.take();
        self.session.take();
        Ok(())
    }

    /// **Test-only**: drop the underlying transport without telling the
    /// server. The next [`next_event`](Self::next_event) call will see
    /// [`RuntimeError::Disconnected`] and route through the auto-reconnect
    /// path (if a [`ReconnectPolicy`] is enabled). Used by examples and
    /// integration tests to simulate a network drop without involving
    /// real packet loss.
    #[doc(hidden)]
    pub fn test_drop_transport(&mut self) {
        self.transport.take();
        self.session.take();
    }

    /// **Test-only**: inject an Auto-Reconnect Cookie into the client.
    ///
    /// Required when validating M7 reconnect against an RDP server that
    /// does not advertise an ARC cookie in its `SaveSessionInfo` PDU
    /// (e.g. Windows RDS without the auto-reconnect Group Policy enabled).
    /// Without this, [`can_reconnect`](Self::can_reconnect) returns false
    /// and `try_reconnect` short-circuits to a synthetic Disconnected.
    #[doc(hidden)]
    pub fn test_set_arc_cookie(&mut self, cookie: ArcCookie) {
        self.last_arc_cookie = Some(cookie);
    }
}

/// Local helper struct used to thread session-tier outputs out of the
/// 9.3 redirect loop. The loop builds this on the final non-redirected
/// iteration and the surrounding code consumes it once to construct
/// the public `RdpClient` value.
struct ResultForSession {
    session_config: SessionConfig,
    user_channel_id: u16,
    channel_ids: Vec<(String, u16)>,
    /// Number of redirects we followed to reach this target. The
    /// surrounding `connect_with_upgrader` uses this to decide whether
    /// to emit a one-shot `RdpEvent::Redirected` after the handshake.
    redirect_depth: u32,
}

/// Parse a Server Redirection PDU's target address fields into a
/// concrete [`SocketAddr`].
///
/// Tries `LB_TARGET_NET_ADDRESS` first, then the first entry of
/// `LB_TARGET_NET_ADDRESSES`. The address bytes are UTF-16LE, possibly
/// null-terminated. The string may be a bare IPv4/IPv6 literal or
/// `host:port`; if no port is present in the string we use
/// `default_port`. Returns `None` on parse failure (caller falls back
/// to the previous target).
fn parse_redirect_target(
    redir: &justrdp_pdu::rdp::redirection::ServerRedirectionPdu,
    default_port: u16,
) -> Option<SocketAddr> {
    let bytes = redir
        .target_net_address
        .as_deref()
        .or_else(|| {
            redir
                .target_net_addresses
                .as_ref()
                .and_then(|tna| tna.addresses.first().map(|a| a.address.as_slice()))
        })?;
    let text = utf16le_to_string(bytes)?;
    parse_addr_with_default_port(text.trim_end_matches('\0'), default_port)
}

/// Decode a UTF-16LE byte slice into a `String`. Stops at the first
/// embedded NUL. Returns `None` on odd byte count or invalid surrogate.
fn utf16le_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let u = u16::from_le_bytes([chunk[0], chunk[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16(&units).ok()
}

/// Parse `host[:port]` into a `SocketAddr`, falling back to
/// `default_port` if no port is given. Accepts bare IPv4/IPv6 and
/// `host:port` forms.
fn parse_addr_with_default_port(text: &str, default_port: u16) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Ok(ip) = text.parse::<std::net::IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    let with_port = format!("{text}:{default_port}");
    with_port.to_socket_addrs().ok()?.next()
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

/// Build a fast-path mouse wheel event.
///
/// MS-RDPBCGR 2.2.8.1.1.3.1.1.3: the low byte of `pointerFlags` holds
/// the unsigned rotation magnitude (0..=255) and `PTRFLAGS_WHEEL_NEGATIVE`
/// signals the sign. `PTRFLAGS_WHEEL` marks a vertical wheel event;
/// `PTRFLAGS_HWHEEL` marks a horizontal wheel event. Callers pass a
/// signed `delta`; this helper handles sign extraction and magnitude
/// clamping.
fn build_mouse_wheel_event(
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
    // Magnitude bits occupy the low byte; clamp to 255.
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

/// Build a fast-path synchronize event from lock-key state.
///
/// MS-RDPBCGR §2.2.8.1.2.2.5: eventFlags bits 0-3 carry the toggle states
/// (scroll, num, caps, kana).
fn build_sync_event(lock_keys: LockKeys) -> FastPathInputEvent {
    FastPathInputEvent::Sync(FastPathSyncEvent {
        event_flags: (lock_keys.to_flags() & 0x0F) as u8,
    })
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
///
/// `scratch` is held across iterations because [`read_pdu`] may pull
/// more bytes off the socket than the current PDU consumes (Windows
/// servers regularly pipeline multiple finalization PDUs into a single
/// TCP frame). The leftover bytes are drained after each `step()` so
/// the next iteration sees the next PDU already buffered.
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
            scratch.drain(..n);
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
    /// that a partially-swapped client never silently drops bytes. The
    /// ErrorKind matters because callers may inspect it — pin to
    /// `NotConnected` so a future change to a different kind has to be
    /// deliberate.
    #[test]
    fn swapping_transport_errors_on_read_and_write() {
        let mut t = Transport::Swapping;
        let mut buf = [0u8; 4];
        let r = t.read(&mut buf).unwrap_err();
        assert_eq!(r.kind(), io::ErrorKind::NotConnected);
        let w = t.write(b"hi").unwrap_err();
        assert_eq!(w.kind(), io::ErrorKind::NotConnected);
        let f = t.flush().unwrap_err();
        assert_eq!(f.kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn connect_error_to_runtime_maps_each_variant() {
        // Tcp -> Io
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        match connect_error_to_runtime(ConnectError::Tcp(io_err)) {
            RuntimeError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
            other => panic!("expected Io, got {other:?}"),
        }
        // UnexpectedEof -> Disconnected
        assert!(matches!(
            connect_error_to_runtime(ConnectError::UnexpectedEof),
            RuntimeError::Disconnected
        ));
        // FrameTooLarge -> FrameTooLarge
        match connect_error_to_runtime(ConnectError::FrameTooLarge(42)) {
            RuntimeError::FrameTooLarge(n) => assert_eq!(n, 42),
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
        // Anything else falls into the catch-all Io with a descriptive
        // message — pinning the catch-all so future ConnectError variants
        // do not silently degrade to Io without us noticing.
        match connect_error_to_runtime(ConnectError::Unimplemented("xyz")) {
            RuntimeError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::Other);
                assert!(e.to_string().contains("xyz"));
            }
            other => panic!("expected Io fallback, got {other:?}"),
        }
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

    #[test]
    fn mouse_wheel_positive_vertical() {
        let event = build_mouse_wheel_event(3, false, 100, 200);
        match event {
            FastPathInputEvent::Mouse(e) => {
                // PTRFLAGS_WHEEL (0x0200) | magnitude(3) = 0x0203
                assert_eq!(e.pointer_flags, PTRFLAGS_WHEEL | 3);
                assert_eq!(e.x_pos, 100);
                assert_eq!(e.y_pos, 200);
                // Sign bit MUST be clear for positive delta.
                assert_eq!(e.pointer_flags & PTRFLAGS_WHEEL_NEGATIVE, 0);
            }
            _ => panic!("expected Mouse variant"),
        }
    }

    #[test]
    fn mouse_wheel_negative_vertical_sets_sign_flag() {
        let event = build_mouse_wheel_event(-5, false, 50, 60);
        match event {
            FastPathInputEvent::Mouse(e) => {
                // PTRFLAGS_WHEEL | PTRFLAGS_WHEEL_NEGATIVE | magnitude(5)
                assert_eq!(
                    e.pointer_flags,
                    PTRFLAGS_WHEEL | PTRFLAGS_WHEEL_NEGATIVE | 5
                );
            }
            _ => panic!("expected Mouse variant"),
        }
    }

    #[test]
    fn mouse_wheel_horizontal_uses_hwheel_flag() {
        let event = build_mouse_wheel_event(2, true, 0, 0);
        match event {
            FastPathInputEvent::Mouse(e) => {
                assert_eq!(e.pointer_flags, PTRFLAGS_HWHEEL | 2);
                // Must NOT set the vertical wheel bit simultaneously.
                assert_eq!(e.pointer_flags & PTRFLAGS_WHEEL, 0);
            }
            _ => panic!("expected Mouse variant"),
        }
    }

    #[test]
    fn mouse_wheel_clamps_oversized_magnitude() {
        // i16::MAX rotations in one event is nonsense but must not
        // overflow into the flag bits.
        let event = build_mouse_wheel_event(i16::MAX, false, 0, 0);
        match event {
            FastPathInputEvent::Mouse(e) => {
                // Magnitude must be clamped to the low byte (255) so it
                // does not collide with the flag bits in the high byte.
                assert_eq!(e.pointer_flags & 0x00FF, 255);
                assert_eq!(e.pointer_flags & PTRFLAGS_WHEEL, PTRFLAGS_WHEEL);
                assert_eq!(e.pointer_flags & PTRFLAGS_WHEEL_NEGATIVE, 0);
            }
            _ => panic!("expected Mouse variant"),
        }
    }

    #[test]
    fn mouse_wheel_clamps_oversized_negative_magnitude() {
        let event = build_mouse_wheel_event(i16::MIN, false, 0, 0);
        match event {
            FastPathInputEvent::Mouse(e) => {
                assert_eq!(e.pointer_flags & 0x00FF, 255);
                assert_eq!(
                    e.pointer_flags & PTRFLAGS_WHEEL_NEGATIVE,
                    PTRFLAGS_WHEEL_NEGATIVE
                );
            }
            _ => panic!("expected Mouse variant"),
        }
    }

    #[test]
    fn disconnect_without_live_session_is_noop() {
        // Disconnecting a client that has already torn down (e.g. after
        // a Terminate event) must not panic on the missing session.
        let client = synthetic_client(ReconnectPolicy::disabled(), None, false);
        assert!(client.transport.is_none());
        assert!(client.session.is_none());
        // Should succeed without touching the network.
        client.disconnect().unwrap();
    }

    #[test]
    fn disconnect_with_live_session_clears_fields() {
        // Build a synthetic client with a populated session and a
        // Transport::Swapping stand-in transport. disconnect() should
        // attempt the write (which will error on Swapping) but still
        // take both fields and return Ok.
        let mut client = synthetic_client(ReconnectPolicy::disabled(), None, false);
        client.transport = Some(Transport::Swapping);
        client.session = Some(Box::new(ActiveStage::new(SessionConfig {
            io_channel_id: 1003,
            user_channel_id: 1007,
            share_id: 0,
            channel_ids: Vec::new(),
        })));
        client.disconnect().unwrap();
        // Both fields must be None after disconnect regardless of
        // whether the write succeeded.
    }

    #[test]
    fn mouse_wheel_zero_delta_produces_bare_wheel_flag() {
        let event = build_mouse_wheel_event(0, false, 0, 0);
        match event {
            FastPathInputEvent::Mouse(e) => {
                assert_eq!(e.pointer_flags, PTRFLAGS_WHEEL);
            }
            _ => panic!("expected Mouse variant"),
        }
    }

    // ── Sync event helpers ──

    #[test]
    fn sync_event_all_off() {
        let event = build_sync_event(LockKeys::DEFAULT);
        match event {
            FastPathInputEvent::Sync(e) => assert_eq!(e.event_flags, 0x00),
            _ => panic!("expected Sync variant"),
        }
    }

    #[test]
    fn sync_event_all_on() {
        let lock_keys = LockKeys {
            scroll_lock: true,
            num_lock: true,
            caps_lock: true,
            kana_lock: true,
        };
        let event = build_sync_event(lock_keys);
        match event {
            FastPathInputEvent::Sync(e) => assert_eq!(e.event_flags, 0x0F),
            _ => panic!("expected Sync variant"),
        }
    }

    #[test]
    fn sync_event_caps_only() {
        let lock_keys = LockKeys {
            caps_lock: true,
            ..LockKeys::DEFAULT
        };
        let event = build_sync_event(lock_keys);
        match event {
            FastPathInputEvent::Sync(e) => assert_eq!(e.event_flags, 0x04),
            _ => panic!("expected Sync variant"),
        }
    }

    #[test]
    fn sync_event_num_and_scroll() {
        let lock_keys = LockKeys {
            scroll_lock: true,
            num_lock: true,
            ..LockKeys::DEFAULT
        };
        let event = build_sync_event(lock_keys);
        match event {
            FastPathInputEvent::Sync(e) => assert_eq!(e.event_flags, 0x03),
            _ => panic!("expected Sync variant"),
        }
    }

    // ── InputDatabase integration ──

    #[test]
    fn key_press_deduplication() {
        let mut db = InputDatabase::new();
        let a = Scancode::new(0x1E, false);
        // First press produces an event.
        assert!(db.key_press(a).is_some());
        // Second press is deduplicated.
        assert!(db.key_press(a).is_none());
    }

    #[test]
    fn key_release_deduplication() {
        let mut db = InputDatabase::new();
        let a = Scancode::new(0x1E, false);
        // Release without press is suppressed.
        assert!(db.key_release(a).is_none());
        db.key_press(a);
        assert!(db.key_release(a).is_some());
        // Double release is suppressed.
        assert!(db.key_release(a).is_none());
    }

    #[test]
    fn mouse_move_deduplication() {
        let mut db = InputDatabase::new();
        assert!(db.mouse_move(100, 200).is_some());
        // Same position is suppressed.
        assert!(db.mouse_move(100, 200).is_none());
        // Different position produces event.
        assert!(db.mouse_move(101, 200).is_some());
    }

    #[test]
    fn mouse_button_deduplication() {
        let mut db = InputDatabase::new();
        assert!(db.mouse_button_press(MouseButton::Left).is_some());
        assert!(db.mouse_button_press(MouseButton::Left).is_none());
        assert!(db.mouse_button_release(MouseButton::Left).is_some());
        assert!(db.mouse_button_release(MouseButton::Left).is_none());
    }

    #[test]
    fn synchronize_always_emits() {
        let mut db = InputDatabase::new();
        let locks = LockKeys::DEFAULT;
        // Even with default state, synchronize always produces an event.
        let op = db.synchronize_event(locks);
        assert!(matches!(op, Operation::SynchronizeEvent(_)));
        // Calling again still produces an event.
        let op2 = db.synchronize_event(locks);
        assert!(matches!(op2, Operation::SynchronizeEvent(_)));
    }

    #[test]
    fn release_all_releases_held_keys_and_buttons() {
        let mut db = InputDatabase::new();
        let a = Scancode::new(0x1E, false);
        let b = Scancode::new(0x30, false);
        db.key_press(a);
        db.key_press(b);
        db.mouse_button_press(MouseButton::Left);

        let mut ops = [Operation::KeyPressed(Scancode::new(0, false)); MAX_RELEASE_OPS];
        let count = db.release_all(&mut ops);
        assert_eq!(count, 3, "2 keys + 1 button = 3 releases");

        // After release, everything is clear.
        assert!(!db.is_key_pressed(a));
        assert!(!db.is_key_pressed(b));
        assert!(!db.is_mouse_button_pressed(MouseButton::Left));
    }

    #[test]
    fn send_operation_maps_scancode_press() {
        let op = Operation::KeyPressed(Scancode::new(0x1E, false));
        let event = match op {
            Operation::KeyPressed(sc) => build_scancode_event(sc, true),
            _ => unreachable!(),
        };
        match event {
            FastPathInputEvent::Scancode(e) => {
                assert_eq!(e.key_code, 0x1E);
                assert_eq!(e.event_flags & KBDFLAGS_RELEASE, 0);
            }
            _ => panic!("expected Scancode variant"),
        }
    }

    #[test]
    fn send_operation_maps_scancode_release() {
        let op = Operation::KeyReleased(Scancode::new(0x1E, true));
        let event = match op {
            Operation::KeyReleased(sc) => build_scancode_event(sc, false),
            _ => unreachable!(),
        };
        match event {
            FastPathInputEvent::Scancode(e) => {
                assert_eq!(e.key_code, 0x1E);
                assert_ne!(e.event_flags & KBDFLAGS_RELEASE, 0);
                assert_ne!(e.event_flags & KBDFLAGS_EXTENDED, 0);
            }
            _ => panic!("expected Scancode variant"),
        }
    }

    #[test]
    fn send_operation_maps_sync() {
        let locks = LockKeys {
            num_lock: true,
            caps_lock: true,
            ..LockKeys::DEFAULT
        };
        let event = build_sync_event(locks);
        match event {
            FastPathInputEvent::Sync(e) => assert_eq!(e.event_flags, 0x06),
            _ => panic!("expected Sync variant"),
        }
    }

    #[test]
    fn state_queries_track_input() {
        let mut db = InputDatabase::new();
        let a = Scancode::new(0x1E, false);
        assert!(!db.is_key_pressed(a));
        db.key_press(a);
        assert!(db.is_key_pressed(a));

        assert!(!db.is_mouse_button_pressed(MouseButton::Right));
        db.mouse_button_press(MouseButton::Right);
        assert!(db.is_mouse_button_pressed(MouseButton::Right));

        assert_eq!(db.mouse_position(), (0, 0));
        db.mouse_move(320, 240);
        assert_eq!(db.mouse_position(), (320, 240));
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
            input_db: InputDatabase::new(),
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

    #[test]
    fn mark_disconnected_takes_transport_and_session() {
        // Build a synthetic client whose transport/session are populated
        // (using Transport::Swapping as a stand-in — its only requirement
        // is that the Option be `Some`). After mark_disconnected we
        // expect both fields to be None and the disconnected flag set.
        let mut client = synthetic_client(ReconnectPolicy::disabled(), None, false);
        client.transport = Some(Transport::Swapping);
        // ActiveStage is heap-allocated; we can't easily fabricate one
        // without a real SessionConfig, but we can stub the field by
        // wrapping a fresh ActiveStage built from a dummy SessionConfig.
        let session_config = SessionConfig {
            io_channel_id: 1003,
            user_channel_id: 1007,
            share_id: 0,
            channel_ids: Vec::new(),
        };
        client.session = Some(Box::new(ActiveStage::new(session_config)));

        client.mark_disconnected();

        assert!(client.disconnected, "disconnected flag must be set");
        assert!(client.transport.is_none(), "transport must be taken");
        assert!(client.session.is_none(), "session must be taken");
    }

    #[test]
    fn next_event_after_disconnect_returns_none_without_io() {
        // Once disconnected == true, next_event must short-circuit to
        // Ok(None) without touching the (already-None) transport. This
        // guards against a regression where the loop tries to read from
        // a missing transport and panics on the unwrap.
        let mut client = synthetic_client(ReconnectPolicy::disabled(), None, false);
        client.disconnected = true;
        let event = client.next_event().expect("next_event must succeed");
        assert!(event.is_none(), "expected Ok(None) after disconnect");
    }

    // ── 9.3 Session Redirection helpers ──

    use justrdp_pdu::rdp::redirection::{
        ServerRedirectionPdu, TargetNetAddress, TargetNetAddresses, LB_TARGET_NET_ADDRESS,
        LB_TARGET_NET_ADDRESSES,
    };

    fn utf16le_bytes(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        // null terminator
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn utf16le_to_string_handles_null_terminator() {
        let bytes = utf16le_bytes("hello");
        assert_eq!(utf16le_to_string(&bytes).unwrap(), "hello");
    }

    #[test]
    fn utf16le_to_string_rejects_odd_length() {
        let bytes = vec![0x68, 0x00, 0x65];
        assert!(utf16le_to_string(&bytes).is_none());
    }

    #[test]
    fn parse_addr_default_port_for_bare_ipv4() {
        let addr = parse_addr_with_default_port("192.168.1.10", 3389).unwrap();
        assert_eq!(addr.port(), 3389);
        assert_eq!(addr.ip().to_string(), "192.168.1.10");
    }

    #[test]
    fn parse_addr_keeps_explicit_port() {
        let addr = parse_addr_with_default_port("10.0.0.5:9000", 3389).unwrap();
        assert_eq!(addr.port(), 9000);
    }

    #[test]
    fn parse_redirect_target_uses_target_net_address() {
        let mut redir = ServerRedirectionPdu::default();
        redir.redir_flags = LB_TARGET_NET_ADDRESS;
        redir.target_net_address = Some(utf16le_bytes("192.168.1.50"));
        let addr = parse_redirect_target(&redir, 3389).unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.50");
        assert_eq!(addr.port(), 3389);
    }

    #[test]
    fn parse_redirect_target_falls_back_to_target_net_addresses() {
        let mut redir = ServerRedirectionPdu::default();
        redir.redir_flags = LB_TARGET_NET_ADDRESSES;
        redir.target_net_addresses = Some(TargetNetAddresses {
            addresses: vec![TargetNetAddress {
                address: utf16le_bytes("10.0.0.99"),
            }],
        });
        let addr = parse_redirect_target(&redir, 3389).unwrap();
        assert_eq!(addr.ip().to_string(), "10.0.0.99");
    }

    #[test]
    fn parse_redirect_target_returns_none_when_no_address() {
        let redir = ServerRedirectionPdu::default();
        assert!(parse_redirect_target(&redir, 3389).is_none());
    }

    #[test]
    fn next_event_drains_pending_queue_before_disconnect_check() {
        // Even with disconnected == true, queued events should be
        // returned in FIFO order before the (terminal) None.
        let mut client = synthetic_client(ReconnectPolicy::disabled(), None, false);
        client.disconnected = true;
        client.pending_events.push_back(RdpEvent::Reconnected);
        client.pending_events.push_back(RdpEvent::PointerDefault);

        let first = client.next_event().unwrap();
        assert!(matches!(first, Some(RdpEvent::Reconnected)));
        let second = client.next_event().unwrap();
        assert!(matches!(second, Some(RdpEvent::PointerDefault)));
        let third = client.next_event().unwrap();
        assert!(third.is_none(), "queue empty + disconnected should yield None");
    }
}
