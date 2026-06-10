//! The sans-IO connection state machine (ADR-0001). It drives the RDP connect sequence by
//! consuming [`Event`]s (socket connected, bytes received) and emitting [`Action`]s (open the
//! socket, write bytes, fail) — never touching the socket itself. Implemented so far:
//! `tcp-connect` → `x224-negotiate` → `tls-handshake` → `nla-credssp` → the MCS/GCC half of
//! `capability-exchange` (Connect-Initial/Response, Erect Domain, Attach User, Channel Join),
//! closing with the Client Info PDU — the Secure Settings Exchange the server requires before
//! it will start licensing (slice-5's entry point).

use justrdp_pdu::client_info;
use justrdp_pdu::gcc::{
    ClientGccBlocks, ClientNetworkData, ServerEarlyCapabilityFlags,
};
use justrdp_pdu::nego::{NegFailureCode, NegRequest, NegResponse, SecurityProtocol};
use justrdp_pdu::{gcc, mcs, tpkt, x224};

/// Everything the connect sequence needs from the caller, fixed at construction. The GCC fields
/// — most critically `core.early_capability_flags`, the EGFX gate (plan.md §0) — reach the wire
/// **verbatim**: the machine fills in only `core.server_selected_protocol` (the negotiated
/// protocol, a wire fact, not policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectConfig {
    /// Protocols to advertise in the X.224 security negotiation.
    pub requested: SecurityProtocol,
    /// The Client Core Data exactly as it should appear in GCC. Nothing in this struct is
    /// defaulted, derived, or overridden by the machine (except `server_selected_protocol`).
    pub core: gcc::ClientCoreData,
    /// The Client Security Data (all-zero with TLS transport security).
    pub security: gcc::ClientSecurityData,
    /// Static virtual channels to request in the Client Network Data, in order. The server
    /// answers with one channel ID per entry.
    pub channels: Vec<gcc::ChannelDef>,
    /// The Client Info PDU settings (Secure Settings Exchange, MS-RDPBCGR 2.2.1.11) — sent on
    /// the I/O channel as soon as the channel join completes.
    pub client_info: ClientInfoConfig,
}

/// Caller-supplied fields of the Client Info PDU. Every field reaches the wire verbatim.
///
/// There is deliberately **no password field**: the sans-IO machine never holds secrets
/// (plan.md decision 10). Under NLA the session logs on with the CredSSP-delegated
/// credentials, so the wire's password field is sent empty; a future autologon-over-plain-SSL
/// feature would have to thread a password at the adapter boundary instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfoConfig {
    /// `INFO_*` flags (e.g. AUTOLOGON, MOUSE, LOGON_NOTIFY) — caller policy. The PDU encoder
    /// adds only `INFO_UNICODE`, which must match the UTF-16 strings it writes.
    pub flags: client_info::ClientInfoFlags,
    /// Logon domain (may be empty).
    pub domain: String,
    /// Logon user name (may be empty; under NLA the delegated identity wins).
    pub username: String,
    /// Program to run instead of the shell (usually empty).
    pub alternate_shell: String,
    /// Working directory for the alternate shell.
    pub work_dir: String,
    /// `clientAddressFamily` (see [`client_info::ADDRESS_FAMILY_INET`]).
    pub address_family: u16,
    /// The client's own address as text (informational).
    pub client_address: String,
    /// The client software directory (informational).
    pub client_dir: String,
    /// The client time zone.
    pub timezone: client_info::TimezoneInfo,
    /// `clientSessionId` (0 unless reconnecting).
    pub session_id: u32,
    /// `performanceFlags` (`PERF_*` bits).
    pub performance_flags: u32,
}

/// A static virtual channel the server granted: the requested name paired with the MCS channel
/// ID that now carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticChannel {
    /// The channel name as requested (e.g. `"cliprdr"`).
    pub name: String,
    /// The server-assigned MCS channel ID.
    pub id: u16,
}

/// The outcome of a completed MCS connect: everything downstream slices (Client Info,
/// licensing, capability exchange) need to address Share Data PDUs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McsConnectResult {
    /// The transport security protocol the server selected at X.224.
    pub selected: SecurityProtocol,
    /// The user channel ID from Attach User Confirm — the `initiator` for all later requests.
    pub user_channel_id: u16,
    /// The I/O (global) channel ID from the Server Network Data (conventionally 1003).
    pub io_channel_id: u16,
    /// The granted static channels (refused channels — ID 0 — are omitted).
    pub static_channels: Vec<StaticChannel>,
    /// The desktop size requested at GCC. The *final* size is settled at capability exchange
    /// (Demand Active, slice-5); until then this is the client's request.
    pub desktop_size: (u16, u16),
    /// True if the channel join sequence was skipped because both sides advertised
    /// skip-channel-join support.
    pub channel_join_skipped: bool,
}

/// A side effect the host adapter must perform on the machine's behalf. The machine is pure;
/// these are its only outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Open the TCP socket to the server.
    Connect,
    /// Write these bytes to the socket (the plaintext socket before [`Action::StartTls`], the
    /// TLS stream after).
    WriteBytes(Vec<u8>),
    /// The X.224 negotiation selected `selected`; the adapter must now upgrade the socket to TLS
    /// (rustls handshake) and hand the server's leaf certificate back via
    /// [`Event::TlsEstablished`]. The TLS records themselves never enter this machine (plan.md
    /// §3 — the handshake runs outside the connect state machine).
    StartTls { selected: SecurityProtocol },
    /// The TLS upgrade is complete and the server's `subjectPublicKey` has been extracted; the
    /// adapter must now run the CredSSP token exchange (NLA), binding `pubKeyAuth` to
    /// `server_public_key`, and signal completion via [`Event::NlaComplete`]. The CredSSP
    /// records (`TSRequest`s) never enter this machine — `sspi` owns CredSSP and the adapter
    /// drives the loop (plan.md decision 10), exactly as the TLS handshake stays in the adapter.
    StartNla {
        /// The protocol the server chose in the X.224 Connection Confirm.
        selected: SecurityProtocol,
        /// The server's `subjectPublicKey` (DER `SubjectPublicKeyInfo`) for CredSSP to bind to.
        server_public_key: Vec<u8>,
    },
    /// HYBRID_EX only: the CredSSP exchange finished and the server will now send the 4-byte
    /// Early User Authorization Result PDU. The adapter must read it and deliver it via
    /// [`Event::EarlyUserAuthResult`]. (Failing to consume it desyncs capability exchange —
    /// plan.md §0.)
    AwaitEarlyUserAuth,
    /// The MCS connect sequence completed: GCC settings exchanged, user attached, channels
    /// joined (or the join legitimately skipped). The connect sequence has reached the end of
    /// what this slice implements; the Client Info PDU (slice-4b) and licensing (slice-5) are
    /// next.
    McsConnected {
        /// The negotiated MCS/GCC results.
        result: McsConnectResult,
    },
    /// The connect attempt failed; surface this error and tear down.
    FailWith(ConnectError),
}

/// An input handed to the machine by the host adapter.
///
/// Events are ordered: each one is valid only in the stage that requested it (e.g.
/// [`Event::TlsEstablished`] answers [`Action::StartTls`], [`Event::NlaComplete`] answers
/// [`Action::StartNla`]). Feeding an event the current stage does not expect is never undefined
/// behavior and never panics — the machine fails the connect with
/// [`ConnectError::UnexpectedEvent`], naming the stage and the offending event kind. This is the
/// contract third-party adapters (blocking, wasm, …) are held to; `justrdp-tokio` upholds it by
/// construction.
///
/// [`Event::Received`] chunks need no framing by the adapter: the machine buffers partial TPKT
/// frames internally and processes as many complete frames as a chunk completes.
#[derive(Debug, Clone, Copy)]
pub enum Event<'a> {
    /// The TCP socket finished connecting.
    Connected,
    /// Bytes arrived from the socket (raw, unframed — any split is fine).
    Received(&'a [u8]),
    /// The TLS handshake the adapter ran (after [`Action::StartTls`]) completed; carries the
    /// server's leaf certificate (DER) so the machine can extract its `subjectPublicKey`.
    TlsEstablished(&'a [u8]),
    /// The CredSSP token exchange the adapter ran (after [`Action::StartNla`]) completed
    /// successfully. For HYBRID_EX, the Early User Authorization Result PDU still follows on
    /// the wire (delivered next via [`Event::EarlyUserAuthResult`]).
    NlaComplete,
    /// HYBRID_EX only: the 4-byte Early User Authorization Result PDU the adapter read (after
    /// [`Action::AwaitEarlyUserAuth`]). Little-endian; the machine decodes grant/deny.
    EarlyUserAuthResult(&'a [u8]),
}

impl Event<'_> {
    /// The payload-free discriminant of this event, for [`ConnectError::UnexpectedEvent`].
    pub fn kind(&self) -> EventKind {
        match self {
            Event::Connected => EventKind::Connected,
            Event::Received(_) => EventKind::Received,
            Event::TlsEstablished(_) => EventKind::TlsEstablished,
            Event::NlaComplete => EventKind::NlaComplete,
            Event::EarlyUserAuthResult(_) => EventKind::EarlyUserAuthResult,
        }
    }
}

/// The kind of an [`Event`], without its payload (which may borrow from the adapter's buffers).
/// Carried by [`ConnectError::UnexpectedEvent`] to name the event that violated the ordering
/// contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// [`Event::Connected`].
    Connected,
    /// [`Event::Received`].
    Received,
    /// [`Event::TlsEstablished`].
    TlsEstablished,
    /// [`Event::NlaComplete`].
    NlaComplete,
    /// [`Event::EarlyUserAuthResult`].
    EarlyUserAuthResult,
}

/// Why a connect attempt failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// The server refused every advertised protocol (`RDP_NEG_FAILURE`).
    NegotiationFailed(NegFailureCode),
    /// The server selected a protocol the client never advertised.
    UnsupportedProtocol(SecurityProtocol),
    /// A malformed PDU arrived from the server.
    Decode(justrdp_pdu::DecodeError),
    /// The TLS upgrade failed: the server's certificate could not be parsed or its public key
    /// extracted. (Handshake-level failures surface at the adapter boundary.)
    TlsHandshake(crate::tls::TlsCertError),
    /// HYBRID_EX only: the server's Early User Authorization Result PDU denied access
    /// (`AUTHZ_ACCESS_DENIED`) — user authorization failed, so the connection must be dropped.
    EarlyUserAuthDenied,
    /// The MCS Connect-Response carried a non-successful `result` code.
    McsConnectFailed {
        /// The T.125 `Result` value (1..=15; 0 is rt-successful).
        result: u8,
    },
    /// The Attach User Confirm carried a non-successful `result` code.
    AttachUserFailed {
        /// The T.125 `Result` value.
        result: u8,
    },
    /// A Channel Join Confirm refused a channel.
    ChannelJoinFailed {
        /// The channel that failed to join.
        channel_id: u16,
        /// The T.125 `Result` value.
        result: u8,
    },
    /// The adapter fed the machine an [`Event`] the current stage does not expect (the ordering
    /// contract on [`Event`]). Carries the stage label and the offending event kind. This is an
    /// adapter bug, not a server behavior — but it surfaces as a typed failure, never a panic.
    UnexpectedEvent {
        /// The connect-stage label the machine was in (as reported by
        /// [`ConnectStateMachine::stage`]).
        stage: &'static str,
        /// The kind of event that arrived.
        event: EventKind,
    },
}

/// The labeled connect sub-step the machine is in (CONTEXT.md "Connect Stage"). Stages that
/// follow the X.224 confirm carry the server-selected protocol, so a stage being reachable
/// proves the data it needs exists — no `Option` to unwrap, no panic path.
///
/// The three MCS sub-states all report the glossary's `capability-exchange` label: GCC *is* the
/// first half of capability negotiation ("client/server advertise and negotiate feature flags
/// and desktop size" — CONTEXT.md), with Demand/Confirm Active (slice-5) as the second half.
/// CONTEXT.md's seven stages remain the complete observable set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Before the socket is up — the machine has asked the adapter to `Connect`.
    TcpConnect,
    /// Socket is up; the X.224 security negotiation request has been sent, awaiting the confirm.
    X224Negotiate,
    /// X.224 selected a TLS-based protocol; the adapter is running the rustls handshake, after
    /// which it hands back the server certificate via [`Event::TlsEstablished`].
    TlsHandshake { selected: SecurityProtocol },
    /// TLS is up and the server's public key extracted; the adapter is running the CredSSP
    /// token exchange, completion signalled via [`Event::NlaComplete`].
    NlaCredssp { selected: SecurityProtocol },
    /// HYBRID_EX only: CredSSP finished and the adapter is reading the 4-byte Early User
    /// Authorization Result PDU. Still the `nla-credssp` stage to observers.
    EarlyUserAuth { selected: SecurityProtocol },
    /// The MCS Connect-Initial is on the wire, awaiting the Connect-Response with the server's
    /// GCC blocks.
    GccExchange { selected: SecurityProtocol },
    /// Erect Domain + Attach User are on the wire, awaiting the Attach User Confirm.
    McsAttach { selected: SecurityProtocol },
    /// Channel Join Requests are on the wire, awaiting the remaining confirms.
    ChannelJoin { selected: SecurityProtocol },
    /// Terminal: the machine emitted [`Action::McsConnected`] or [`Action::FailWith`] and will
    /// accept no further events (each yields [`ConnectError::UnexpectedEvent`]). Internal only —
    /// `last` is the label of the stage where the connect ended, and [`Stage::label`] keeps
    /// reporting it: CONTEXT.md's seven Connect Stages stay the complete observable set (no
    /// extra label leaks to the host's `on_stage`), and after a failure `stage()` still names
    /// the stage that failed, preserving error attribution.
    Done { last: &'static str },
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Stage::TcpConnect => "tcp-connect",
            Stage::X224Negotiate => "x224-negotiate",
            Stage::TlsHandshake { .. } => "tls-handshake",
            Stage::NlaCredssp { .. } | Stage::EarlyUserAuth { .. } => "nla-credssp",
            Stage::GccExchange { .. } | Stage::McsAttach { .. } | Stage::ChannelJoin { .. } => {
                "capability-exchange"
            }
            Stage::Done { last } => last,
        }
    }

    /// The terminal state, remembering this stage's label as the last observable one.
    fn done(self) -> Stage {
        Stage::Done { last: self.label() }
    }

    /// True for the stages that consume raw socket bytes ([`Event::Received`]).
    fn accepts_received(self) -> bool {
        matches!(
            self,
            Stage::X224Negotiate
                | Stage::GccExchange { .. }
                | Stage::McsAttach { .. }
                | Stage::ChannelJoin { .. }
        )
    }
}

/// The sans-IO RDP connect state machine. Construct it with [`ConnectStateMachine::new`], kick
/// it off with [`ConnectStateMachine::start`], then feed it [`Event`]s; each call returns the
/// [`Action`]s the adapter must perform.
#[derive(Debug)]
pub struct ConnectStateMachine {
    config: ConnectConfig,
    stage: Stage,
    /// Unprocessed socket bytes: TPKT frames are assembled here, so the adapter can deliver
    /// reads in arbitrary chunks.
    inbox: Vec<u8>,
    /// MCS results accumulated across the exchange (valid per the stage that filled them).
    user_channel_id: u16,
    io_channel_id: u16,
    static_channels: Vec<StaticChannel>,
    skip_channel_join: bool,
    pending_joins: Vec<u16>,
}

impl ConnectStateMachine {
    /// Create a machine that will drive the connect sequence with `config`. The GCC fields are
    /// used verbatim when the MCS Connect-Initial is built — nothing is added or stripped.
    pub fn new(config: ConnectConfig) -> Self {
        Self {
            config,
            stage: Stage::TcpConnect,
            inbox: Vec::new(),
            user_channel_id: 0,
            io_channel_id: 0,
            static_channels: Vec::new(),
            skip_channel_join: false,
            pending_joins: Vec::new(),
        }
    }

    /// The current connect stage label, for diagnostics / progress UI.
    pub fn stage(&self) -> &'static str {
        self.stage.label()
    }

    /// Begin the connect sequence: ask the adapter to open the socket.
    pub fn start(&mut self) -> Vec<Action> {
        vec![Action::Connect]
    }

    /// Advance the machine with an input event, returning the actions to perform.
    ///
    /// Dispatch is on the (stage, event) pair: each stage accepts exactly the event it asked
    /// the adapter for, and every other combination fails the connect with
    /// [`ConnectError::UnexpectedEvent`] — see the ordering contract on [`Event`].
    pub fn process(&mut self, event: Event) -> Vec<Action> {
        match (self.stage, event) {
            (Stage::TcpConnect, Event::Connected) => {
                self.stage = Stage::X224Negotiate;
                let neg = NegRequest::new(self.config.requested).encode();
                let tpdu = x224::encode_connection_request(&neg);
                vec![Action::WriteBytes(tpkt::encode(&tpdu))]
            }
            (stage, Event::Received(bytes)) if stage.accepts_received() => {
                self.inbox.extend_from_slice(bytes);
                self.drain_frames()
            }
            (Stage::TlsHandshake { selected }, Event::TlsEstablished(cert_der)) => {
                match crate::tls::extract_subject_public_key(cert_der) {
                    Ok(server_public_key) => {
                        // TLS is up: hand off into NLA. The adapter runs the CredSSP token
                        // exchange (binding to this key); the machine advances to `nla-credssp`
                        // and waits for the adapter to report completion.
                        self.stage = Stage::NlaCredssp { selected };
                        vec![Action::StartNla {
                            selected,
                            server_public_key,
                        }]
                    }
                    Err(e) => self.fail(ConnectError::TlsHandshake(e)),
                }
            }
            (Stage::NlaCredssp { selected }, Event::NlaComplete) => {
                // HYBRID_EX appends a 4-byte Early User Authorization Result PDU after CredSSP;
                // the machine must consume it before MCS. Plain HYBRID/SSL proceed directly.
                if selected.contains(SecurityProtocol::HYBRID_EX) {
                    self.stage = Stage::EarlyUserAuth { selected };
                    vec![Action::AwaitEarlyUserAuth]
                } else {
                    self.start_mcs(selected)
                }
            }
            (Stage::EarlyUserAuth { selected }, Event::EarlyUserAuthResult(bytes)) => {
                // 4 bytes little-endian (MS-RDPBCGR 2.2.10.2). Only AUTHZ_SUCCESS grants access;
                // any other value — or a truncated buffer — is a malformed PDU.
                match bytes.get(..4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])) {
                    Some(AUTHZ_SUCCESS) => self.start_mcs(selected),
                    Some(AUTHZ_ACCESS_DENIED) => self.fail(ConnectError::EarlyUserAuthDenied),
                    _ => self.fail(ConnectError::Decode(
                        justrdp_pdu::DecodeError::InvalidField {
                            field: "authorizationResult",
                            reason: "unrecognized or truncated Early User Authorization Result PDU",
                        },
                    )),
                }
            }
            // Every other (stage, event) combination violates the ordering contract on `Event`:
            // an adapter bug, surfaced as a typed failure — never a panic, never silent.
            (stage, event) => self.fail(ConnectError::UnexpectedEvent {
                stage: stage.label(),
                event: event.kind(),
            }),
        }
    }

    /// Authentication finished: enter the MCS/GCC half of capability exchange. Builds the
    /// Connect-Initial from the caller's config — the only field the machine touches is
    /// `serverSelectedProtocol`, which echoes the negotiated protocol (a wire fact). Every
    /// `earlyCapabilityFlags` bit is the caller's, verbatim (plan.md §0).
    fn start_mcs(&mut self, selected: SecurityProtocol) -> Vec<Action> {
        self.stage = Stage::GccExchange { selected };
        let mut core = self.config.core.clone();
        core.server_selected_protocol = selected;
        let blocks = ClientGccBlocks {
            core,
            security: self.config.security,
            network: ClientNetworkData {
                channels: self.config.channels.clone(),
            },
        };
        let body = mcs::encode_connect_initial(&blocks);
        vec![Action::WriteBytes(tpkt::encode(&x224::encode_data(&body)))]
    }

    /// Process as many complete TPKT frames as the inbox holds. Stops on the first failure or
    /// terminal action; any unconsumed bytes stay buffered for the next stage.
    fn drain_frames(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        loop {
            if matches!(self.stage, Stage::Done { .. }) {
                break;
            }
            let frame_len = match tpkt::frame_len(&self.inbox) {
                Ok(n) => n,
                // The 4-byte header is still incomplete: wait for more bytes.
                Err(justrdp_pdu::DecodeError::NotEnoughBytes { .. }) => break,
                Err(e) => {
                    actions.extend(self.fail(ConnectError::Decode(e)));
                    break;
                }
            };
            if self.inbox.len() < frame_len {
                break; // partial frame: wait for more bytes
            }
            let frame: Vec<u8> = self.inbox.drain(..frame_len).collect();
            actions.extend(self.on_frame(&frame));
        }
        actions
    }

    /// Handle one complete TPKT frame according to the current stage. The frame is complete, so
    /// any decode shortfall inside it is a malformed PDU, not a partial read.
    fn on_frame(&mut self, frame: &[u8]) -> Vec<Action> {
        match self.stage {
            Stage::X224Negotiate => match decode_confirm(frame) {
                Ok(NegResponse::Selected(selected))
                    if selected.bits() != 0 && self.config.requested.contains(selected) =>
                {
                    // The server picked a TLS-based protocol we advertised: remember it and ask
                    // the adapter to upgrade the socket.
                    self.stage = Stage::TlsHandshake { selected };
                    vec![Action::StartTls { selected }]
                }
                Ok(NegResponse::Selected(selected)) => {
                    self.fail(ConnectError::UnsupportedProtocol(selected))
                }
                Ok(NegResponse::Failure(code)) => {
                    self.fail(ConnectError::NegotiationFailed(code))
                }
                Err(e) => self.fail(ConnectError::Decode(e)),
            },
            Stage::GccExchange { selected } => match decode_mcs_frame(frame)
                .and_then(mcs::decode_connect_response)
            {
                Ok(response) => self.on_connect_response(selected, response),
                Err(e) => self.fail(ConnectError::Decode(e)),
            },
            Stage::McsAttach { selected } => match decode_mcs_frame(frame)
                .and_then(mcs::AttachUserConfirm::decode)
            {
                Ok(confirm) => self.on_attach_user_confirm(selected, confirm),
                Err(e) => self.fail(ConnectError::Decode(e)),
            },
            Stage::ChannelJoin { selected } => match decode_mcs_frame(frame)
                .and_then(mcs::ChannelJoinConfirm::decode)
            {
                Ok(confirm) => self.on_channel_join_confirm(selected, confirm),
                Err(e) => self.fail(ConnectError::Decode(e)),
            },
            // drain_frames only runs in receiving stages; anything else is unreachable by
            // construction, but fail typed rather than panic if that invariant ever breaks.
            stage => self.fail(ConnectError::UnexpectedEvent {
                stage: stage.label(),
                event: EventKind::Received,
            }),
        }
    }

    /// The server's Connect-Response arrived: validate it, record the channel topology, and
    /// move on to Erect Domain + Attach User.
    fn on_connect_response(
        &mut self,
        selected: SecurityProtocol,
        response: mcs::ConnectResponse,
    ) -> Vec<Action> {
        if response.result != 0 {
            return self.fail(ConnectError::McsConnectFailed {
                result: response.result,
            });
        }
        let blocks = &response.conference.blocks;

        // One server channel ID answers each requested channel, in order (ID 0 = refused).
        if blocks.network.channel_ids.len() != self.config.channels.len() {
            return self.fail(ConnectError::Decode(
                justrdp_pdu::DecodeError::InvalidField {
                    field: "channelIdArray",
                    reason: "server did not answer every requested static channel",
                },
            ));
        }
        self.io_channel_id = blocks.network.io_channel;
        self.static_channels = self
            .config
            .channels
            .iter()
            .zip(&blocks.network.channel_ids)
            .filter(|&(_, &id)| id != 0)
            .map(|(def, &id)| StaticChannel {
                name: def.name_str().to_string(),
                id,
            })
            .collect();

        // The join sequence is skipped only when *both* sides advertised it: the server in its
        // Core Data flags, the client in its caller-supplied earlyCapabilityFlags.
        let server_skips = blocks
            .core
            .early_capability_flags
            .is_some_and(|f| f.contains(ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED));
        let client_skips = self
            .config
            .core
            .early_capability_flags
            .contains(gcc::ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN);
        self.skip_channel_join = server_skips && client_skips;

        self.stage = Stage::McsAttach { selected };
        vec![
            Action::WriteBytes(tpkt::encode(&x224::encode_data(
                &mcs::encode_erect_domain_request(),
            ))),
            Action::WriteBytes(tpkt::encode(&x224::encode_data(
                &mcs::encode_attach_user_request(),
            ))),
        ]
    }

    /// The Attach User Confirm arrived: record the user channel and either join channels or
    /// finish (skip-channel-join).
    fn on_attach_user_confirm(
        &mut self,
        selected: SecurityProtocol,
        confirm: mcs::AttachUserConfirm,
    ) -> Vec<Action> {
        if confirm.result != 0 {
            return self.fail(ConnectError::AttachUserFailed {
                result: confirm.result,
            });
        }
        self.user_channel_id = confirm.initiator_id;

        if self.skip_channel_join {
            return self.finish(selected);
        }

        // Join the user channel, the I/O channel, and every granted static channel. All
        // requests go out in one batch (RDP 8.1+ behavior); confirms may arrive in any order.
        self.pending_joins = std::iter::once(self.user_channel_id)
            .chain(std::iter::once(self.io_channel_id))
            .chain(self.static_channels.iter().map(|c| c.id))
            .collect();
        let actions = self
            .pending_joins
            .iter()
            .map(|&channel_id| {
                Action::WriteBytes(tpkt::encode(&x224::encode_data(
                    &mcs::encode_channel_join_request(self.user_channel_id, channel_id),
                )))
            })
            .collect();
        self.stage = Stage::ChannelJoin { selected };
        actions
    }

    /// A Channel Join Confirm arrived: check it off; the exchange completes when every
    /// requested channel is confirmed.
    fn on_channel_join_confirm(
        &mut self,
        selected: SecurityProtocol,
        confirm: mcs::ChannelJoinConfirm,
    ) -> Vec<Action> {
        if confirm.result != 0 {
            return self.fail(ConnectError::ChannelJoinFailed {
                channel_id: confirm.requested_channel_id,
                result: confirm.result,
            });
        }
        let Some(pos) = self
            .pending_joins
            .iter()
            .position(|&id| id == confirm.requested_channel_id)
        else {
            return self.fail(ConnectError::Decode(
                justrdp_pdu::DecodeError::InvalidField {
                    field: "ChannelJoinConfirm.requested",
                    reason: "confirm for a channel that was never requested (or already confirmed)",
                },
            ));
        };
        self.pending_joins.swap_remove(pos);
        if self.pending_joins.is_empty() {
            self.finish(selected)
        } else {
            Vec::new()
        }
    }

    /// The MCS connect is complete: send the Client Info PDU, then emit the terminal result.
    ///
    /// The Client Info write is the Secure Settings Exchange (MS-RDPBCGR 2.2.1.11) — the server
    /// does not begin licensing until it arrives, so the connect machine owns the send rather
    /// than leaving a silent gap for the host to discover. It happens at the tail of the
    /// `capability-exchange` stage; per CONTEXT.md's seven-stage glossary no separate label
    /// exists for it (it is a single fire-and-forget write with no response of its own — the
    /// next inbound PDU is licensing, slice-5's entry point).
    fn finish(&mut self, selected: SecurityProtocol) -> Vec<Action> {
        let info = client_info::ClientInfo {
            code_page: 0,
            flags: self.config.client_info.flags,
            domain: self.config.client_info.domain.clone(),
            username: self.config.client_info.username.clone(),
            // Never a secret here: NLA delegates the real credentials via CredSSP
            // (plan.md decision 10 — no secrets in the sans-IO machine).
            password: String::new(),
            alternate_shell: self.config.client_info.alternate_shell.clone(),
            work_dir: self.config.client_info.work_dir.clone(),
            extra: client_info::ExtendedClientInfo {
                address_family: self.config.client_info.address_family,
                address: self.config.client_info.client_address.clone(),
                dir: self.config.client_info.client_dir.clone(),
                timezone: self.config.client_info.timezone.clone(),
                session_id: self.config.client_info.session_id,
                performance_flags: self.config.client_info.performance_flags,
                // Empty until epic #25 replays a Save Session Info cookie.
                reconnect_cookie: None,
            },
        };
        let payload = info.encode();
        let frame = tpkt::encode(&x224::encode_data(&mcs::encode_send_data_request(
            self.user_channel_id,
            self.io_channel_id,
            &payload,
        )));

        self.stage = self.stage.done();
        vec![
            Action::WriteBytes(frame),
            Action::McsConnected {
                result: McsConnectResult {
                    selected,
                    user_channel_id: self.user_channel_id,
                    io_channel_id: self.io_channel_id,
                    static_channels: std::mem::take(&mut self.static_channels),
                    desktop_size: (
                        self.config.core.desktop_width,
                        self.config.core.desktop_height,
                    ),
                    channel_join_skipped: self.skip_channel_join,
                },
            },
        ]
    }

    /// Fail the connect: emit [`Action::FailWith`] and move to the terminal [`Stage::Done`],
    /// where every further event is itself an [`ConnectError::UnexpectedEvent`]. The label of
    /// the stage that failed is kept, so `stage()` still attributes the error to it.
    fn fail(&mut self, e: ConnectError) -> Vec<Action> {
        self.stage = self.stage.done();
        vec![Action::FailWith(e)]
    }
}

/// `AUTHZ_SUCCESS` — the HYBRID_EX Early User Authorization Result PDU value that grants the
/// user access (MS-RDPBCGR 2.2.10.2). Any other `authorizationResult` denies or is malformed.
const AUTHZ_SUCCESS: u32 = 0x0000_0000;
/// `AUTHZ_ACCESS_DENIED` — the Early User Authorization Result PDU value that denies access;
/// the client must drop the connection (MS-RDPBCGR 2.2.10.2).
const AUTHZ_ACCESS_DENIED: u32 = 0x0000_0005;

/// Decode a server Connection Confirm frame into its RDP negotiation response, peeling TPKT →
/// X.224 CC → `RDP_NEG_RSP`/`RDP_NEG_FAILURE`.
fn decode_confirm(bytes: &[u8]) -> Result<NegResponse, justrdp_pdu::DecodeError> {
    let tpdu = tpkt::decode(bytes)?;
    let variable = x224::decode_connection_confirm(tpdu)?;
    NegResponse::decode(variable)
}

/// Peel TPKT → X.224 Data from a complete frame, returning the MCS payload.
fn decode_mcs_frame(frame: &[u8]) -> Result<&[u8], justrdp_pdu::DecodeError> {
    let tpdu = tpkt::decode(frame)?;
    x224::decode_data(tpdu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::gcc::{
        CHANNEL_OPTION_INITIALIZED, COLOR_DEPTH_8BPP, CONNECTION_TYPE_LAN, ChannelDef,
        ClientEarlyCapabilityFlags, HIGH_COLOR_DEPTH_24BPP, KEYBOARD_TYPE_IBM_ENHANCED,
        RDP_VERSION_10_12, SUPPORTED_COLOR_DEPTH_24BPP, SUPPORTED_COLOR_DEPTH_32BPP,
    };

    use ironrdp_pdu::encode_vec as iron_encode_vec;
    use ironrdp_pdu::gcc as iron_gcc;
    use ironrdp_pdu::mcs as iron_mcs;
    use ironrdp_pdu::nego::SecurityProtocol as IronProtocol;
    use ironrdp_pdu::x224::X224 as IronX224;

    fn requested() -> SecurityProtocol {
        SecurityProtocol::SSL | SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX
    }

    /// A full caller-supplied config: two static channels, explicit early-capability flags.
    fn config_with_flags(flags: ClientEarlyCapabilityFlags) -> ConnectConfig {
        ConnectConfig {
            requested: requested(),
            core: justrdp_pdu::gcc::ClientCoreData {
                version: RDP_VERSION_10_12,
                desktop_width: 1280,
                desktop_height: 800,
                keyboard_layout: 0x0409,
                client_build: 1,
                client_name: "sm-test".to_string(),
                keyboard_type: KEYBOARD_TYPE_IBM_ENHANCED,
                keyboard_subtype: 0,
                keyboard_functional_keys_count: 12,
                ime_file_name: String::new(),
                post_beta2_color_depth: COLOR_DEPTH_8BPP,
                client_product_id: 1,
                serial_number: 0,
                high_color_depth: HIGH_COLOR_DEPTH_24BPP,
                supported_color_depths: SUPPORTED_COLOR_DEPTH_24BPP
                    | SUPPORTED_COLOR_DEPTH_32BPP,
                early_capability_flags: flags,
                dig_product_id: String::new(),
                connection_type: CONNECTION_TYPE_LAN,
                // Placeholder; the machine overwrites it with the negotiated protocol.
                server_selected_protocol: SecurityProtocol::from_bits(0),
            },
            security: justrdp_pdu::gcc::ClientSecurityData::default(),
            channels: vec![
                ChannelDef::new("cliprdr", CHANNEL_OPTION_INITIALIZED).unwrap(),
                ChannelDef::new("drdynvc", CHANNEL_OPTION_INITIALIZED).unwrap(),
            ],
            client_info: ClientInfoConfig {
                flags: client_info::ClientInfoFlags::MOUSE
                    | client_info::ClientInfoFlags::AUTOLOGON
                    | client_info::ClientInfoFlags::LOGON_NOTIFY,
                domain: "WORKGROUP".to_string(),
                username: "sm-user".to_string(),
                alternate_shell: String::new(),
                work_dir: String::new(),
                address_family: client_info::ADDRESS_FAMILY_INET,
                client_address: "10.0.0.2".to_string(),
                client_dir: String::new(),
                timezone: client_info::TimezoneInfo {
                    bias: -540,
                    standard_name: "Korea Standard Time".to_string(),
                    standard_bias: 0,
                    daylight_name: String::new(),
                    daylight_bias: 0,
                },
                session_id: 0,
                performance_flags: 0x7,
            },
        }
    }

    fn config() -> ConnectConfig {
        config_with_flags(
            ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU
                | ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL,
        )
    }

    #[test]
    fn start_emits_connect_in_tcp_connect_stage() {
        let mut sm = ConnectStateMachine::new(config());
        let actions = sm.start();
        assert_eq!(actions, vec![Action::Connect]);
        assert_eq!(sm.stage(), "tcp-connect");
    }

    #[test]
    fn connected_writes_connection_request_and_enters_x224_stage() {
        let mut sm = ConnectStateMachine::new(config());
        sm.start();
        let actions = sm.process(Event::Connected);
        // The machine writes exactly one frame: TPKT( X.224 CR( RDP_NEG_REQ ) ) advertising
        // SSL|HYBRID|HYBRID_EX (0x0B). The wire format is fixed by MS-RDPBCGR, so the exact
        // bytes are the observable contract.
        assert_eq!(
            actions,
            vec![Action::WriteBytes(vec![
                0x03, 0x00, 0x00, 0x13, // TPKT: version, reserved, length = 19
                0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR: LI=14, code, refs, class
                0x01, 0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x00, // RDP_NEG_REQ: SSL|HYBRID|HYBRID_EX
            ])]
        );
        assert_eq!(sm.stage(), "x224-negotiate");
    }

    /// Wrap an 8-byte RDP negotiation structure in an X.224 Connection Confirm + TPKT, as a
    /// server would on the wire.
    fn wrap_confirm(nego: [u8; 8]) -> Vec<u8> {
        let mut cc = vec![0x0E, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00];
        cc.extend_from_slice(&nego);
        justrdp_pdu::tpkt::encode(&cc)
    }

    /// A Connection Confirm carrying an `RDP_NEG_RSP` selecting `selected`.
    fn connection_confirm(selected: SecurityProtocol) -> Vec<u8> {
        let [s0, s1, s2, s3] = selected.bits().to_le_bytes();
        wrap_confirm([0x02, 0x00, 0x08, 0x00, s0, s1, s2, s3])
    }

    /// A Connection Confirm carrying an `RDP_NEG_FAILURE` with `code`.
    fn connection_failure(code: NegFailureCode) -> Vec<u8> {
        let [c0, c1, c2, c3] = code.0.to_le_bytes();
        wrap_confirm([0x03, 0x00, 0x08, 0x00, c0, c1, c2, c3])
    }

    /// A machine driven to the `x224-negotiate` stage, ready to receive a confirm.
    fn negotiating() -> ConnectStateMachine {
        negotiating_with(config())
    }

    fn negotiating_with(config: ConnectConfig) -> ConnectStateMachine {
        let mut sm = ConnectStateMachine::new(config);
        sm.start();
        sm.process(Event::Connected);
        sm
    }

    #[test]
    fn received_confirm_emits_start_tls_and_enters_tls_handshake_stage() {
        let mut sm = negotiating();
        let confirm = connection_confirm(SecurityProtocol::HYBRID);
        let actions = sm.process(Event::Received(&confirm));
        assert_eq!(
            actions,
            vec![Action::StartTls {
                selected: SecurityProtocol::HYBRID
            }]
        );
        assert_eq!(sm.stage(), "tls-handshake");
    }

    /// Drive a machine through the X.224 confirm into the `tls-handshake` stage.
    fn awaiting_tls(selected: SecurityProtocol) -> ConnectStateMachine {
        awaiting_tls_with(config(), selected)
    }

    fn awaiting_tls_with(config: ConnectConfig, selected: SecurityProtocol) -> ConnectStateMachine {
        let mut sm = negotiating_with(config);
        sm.process(Event::Received(&connection_confirm(selected)));
        sm
    }

    /// Drive a machine through the TLS handshake into the `nla-credssp` stage. The certificate
    /// is a throwaway self-signed cert — only the stage transition matters here.
    fn awaiting_nla(selected: SecurityProtocol) -> ConnectStateMachine {
        awaiting_nla_with(config(), selected)
    }

    fn awaiting_nla_with(config: ConnectConfig, selected: SecurityProtocol) -> ConnectStateMachine {
        let mut sm = awaiting_tls_with(config, selected);
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        sm.process(Event::TlsEstablished(key.cert.der().as_ref()));
        sm
    }

    #[test]
    fn tls_established_emits_start_nla_and_enters_nla_credssp_stage() {
        let mut sm = awaiting_tls(SecurityProtocol::HYBRID);
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = key.cert.der();

        let actions = sm.process(Event::TlsEstablished(cert_der.as_ref()));

        let expected_key = crate::tls::extract_subject_public_key(cert_der.as_ref()).unwrap();
        assert_eq!(
            actions,
            vec![Action::StartNla {
                selected: SecurityProtocol::HYBRID,
                server_public_key: expected_key,
            }]
        );
        assert_eq!(sm.stage(), "nla-credssp");
    }

    #[test]
    fn nla_complete_without_hybrid_ex_writes_connect_initial() {
        // On a plain HYBRID connection, NLA completion flows straight into MCS: the machine
        // writes the Connect-Initial and enters the capability-exchange stage (the GCC half).
        let mut sm = awaiting_nla(SecurityProtocol::HYBRID);
        let actions = sm.process(Event::NlaComplete);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], Action::WriteBytes(_)));
        assert_eq!(sm.stage(), "capability-exchange");
    }

    /// Drive a HYBRID_EX machine to the point where it awaits the Early User Authorization
    /// Result PDU.
    fn awaiting_early_user_auth() -> ConnectStateMachine {
        let mut sm = awaiting_nla(SecurityProtocol::HYBRID_EX);
        sm.process(Event::NlaComplete);
        sm
    }

    #[test]
    fn early_user_auth_granted_writes_connect_initial() {
        let mut sm = awaiting_early_user_auth();
        let actions = sm.process(Event::EarlyUserAuthResult(&[0x00, 0x00, 0x00, 0x00]));
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], Action::WriteBytes(_)));
        assert_eq!(sm.stage(), "capability-exchange");
    }

    #[test]
    fn early_user_auth_denied_fails_with_early_user_auth_denied() {
        let mut sm = awaiting_early_user_auth();
        let actions = sm.process(Event::EarlyUserAuthResult(&[0x05, 0x00, 0x00, 0x00]));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::EarlyUserAuthDenied)]
        );
    }

    #[test]
    fn early_user_auth_unrecognized_code_fails_with_decode() {
        let mut sm = awaiting_early_user_auth();
        let actions = sm.process(Event::EarlyUserAuthResult(&[0x99, 0x00, 0x00, 0x00]));
        assert!(matches!(
            actions.as_slice(),
            [Action::FailWith(ConnectError::Decode(_))]
        ));
    }

    #[test]
    fn nla_complete_with_hybrid_ex_awaits_early_user_auth() {
        let mut sm = awaiting_nla(SecurityProtocol::HYBRID_EX);
        let actions = sm.process(Event::NlaComplete);
        assert_eq!(actions, vec![Action::AwaitEarlyUserAuth]);
        assert_eq!(sm.stage(), "nla-credssp");
    }

    #[test]
    fn tls_established_with_malformed_cert_fails_with_tls_handshake() {
        let mut sm = awaiting_tls(SecurityProtocol::HYBRID);
        let actions = sm.process(Event::TlsEstablished(&[0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::TlsHandshake(
                crate::tls::TlsCertError::MalformedCertificate
            ))]
        );
    }

    #[test]
    fn received_confirm_selecting_unadvertised_protocol_fails() {
        let mut sm = negotiating();
        // RDSTLS (0x04) was never in our advertised SSL|HYBRID|HYBRID_EX set.
        let rdstls = SecurityProtocol::from_bits(0x04);
        let confirm = connection_confirm(rdstls);
        let actions = sm.process(Event::Received(&confirm));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::UnsupportedProtocol(rdstls))]
        );
    }

    #[test]
    fn received_confirm_selecting_standard_security_is_rejected() {
        let mut sm = negotiating();
        // PROTOCOL_RDP (0x00) = legacy RC4 Standard Security. It is a (trivial) subset of any
        // advertised set, so it must be rejected explicitly — justrdp never accepts it.
        let standard = SecurityProtocol::from_bits(0x00);
        let confirm = connection_confirm(standard);
        let actions = sm.process(Event::Received(&confirm));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::UnsupportedProtocol(standard))]
        );
    }

    #[test]
    fn received_partial_frame_waits_for_more_bytes() {
        let mut sm = negotiating();
        let confirm = connection_confirm(SecurityProtocol::HYBRID);
        // Only the first 5 of 19 bytes have arrived — the machine buffers and waits...
        let actions = sm.process(Event::Received(&confirm[..5]));
        assert!(actions.is_empty());
        assert_eq!(sm.stage(), "x224-negotiate");
        // ...and completes once the rest arrives (the machine owns frame reassembly).
        let actions = sm.process(Event::Received(&confirm[5..]));
        assert_eq!(
            actions,
            vec![Action::StartTls {
                selected: SecurityProtocol::HYBRID
            }]
        );
    }

    #[test]
    fn received_malformed_confirm_emits_failwith_decode() {
        let mut sm = negotiating();
        // A complete TPKT frame, but the X.224 code is a Connection *Request* (0xE0), not a
        // Confirm — a malformed response, distinct from a partial read.
        let mut cc = vec![0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00];
        cc.extend_from_slice(&[0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]);
        let frame = justrdp_pdu::tpkt::encode(&cc);
        let actions = sm.process(Event::Received(&frame));
        assert!(matches!(
            actions.as_slice(),
            [Action::FailWith(ConnectError::Decode(_))]
        ));
    }

    #[test]
    fn received_failure_emits_failwith_negotiation_failed() {
        let mut sm = negotiating();
        let failure = connection_failure(NegFailureCode::HYBRID_REQUIRED_BY_SERVER);
        let actions = sm.process(Event::Received(&failure));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::NegotiationFailed(
                NegFailureCode::HYBRID_REQUIRED_BY_SERVER
            ))]
        );
    }

    // ---- MCS / GCC stage tests (server frames encoded by ironrdp — the differential oracle) --

    /// A TPKT + X.224 DT frame around an ironrdp-encoded MCS BER body.
    fn frame_mcs(body: &[u8]) -> Vec<u8> {
        justrdp_pdu::tpkt::encode(&justrdp_pdu::x224::encode_data(body))
    }

    /// An ironrdp-encoded server Connect-Response: io channel 1003, channel IDs answering the
    /// two requested channels, optional skip-channel-join flag.
    fn iron_connect_response(skip_join: bool, channel_ids: Vec<u16>) -> Vec<u8> {
        let flags = if skip_join {
            iron_gcc::ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED
        } else {
            iron_gcc::ServerEarlyCapabilityFlags::empty()
        };
        let blocks = iron_gcc::ServerGccBlocks {
            core: iron_gcc::ServerCoreData {
                version: iron_gcc::RdpVersion::V10_12,
                optional_data: iron_gcc::ServerCoreOptionalData {
                    client_requested_protocols: Some(IronProtocol::HYBRID_EX),
                    early_capability_flags: Some(flags),
                },
            },
            network: iron_gcc::ServerNetworkData {
                io_channel: 1003,
                channel_ids,
            },
            security: iron_gcc::ServerSecurityData::no_security(),
            message_channel: None,
            multi_transport_channel: None,
        };
        let response = iron_mcs::ConnectResponse {
            conference_create_response: iron_gcc::ConferenceCreateResponse::new(1002, blocks)
                .unwrap(),
            called_connect_id: 0,
            domain_parameters: iron_mcs::DomainParameters::target(),
        };
        frame_mcs(&iron_encode_vec(&response).unwrap())
    }

    /// An ironrdp-encoded Attach User Confirm (already TPKT-framed by ironrdp's X224 wrapper).
    fn iron_attach_user_confirm(initiator_id: u16) -> Vec<u8> {
        iron_encode_vec(&IronX224(iron_mcs::AttachUserConfirm {
            result: 0,
            initiator_id,
        }))
        .unwrap()
    }

    /// An ironrdp-encoded Channel Join Confirm.
    fn iron_channel_join_confirm(initiator_id: u16, channel_id: u16, result: u8) -> Vec<u8> {
        iron_encode_vec(&IronX224(iron_mcs::ChannelJoinConfirm {
            result,
            initiator_id,
            requested_channel_id: channel_id,
            channel_id,
        }))
        .unwrap()
    }

    /// Drive a machine to the GccExchange stage (Connect-Initial written).
    fn awaiting_connect_response(config: ConnectConfig) -> ConnectStateMachine {
        let mut sm = awaiting_nla_with(config, SecurityProtocol::HYBRID);
        let actions = sm.process(Event::NlaComplete);
        assert!(matches!(actions.as_slice(), [Action::WriteBytes(_)]));
        sm
    }

    /// Drive a machine through the Connect-Response + Attach User Confirm into ChannelJoin.
    fn joining_channels() -> ConnectStateMachine {
        let mut sm = awaiting_connect_response(config());
        sm.process(Event::Received(&iron_connect_response(
            false,
            vec![1004, 1005],
        )));
        let actions = sm.process(Event::Received(&iron_attach_user_confirm(1007)));
        assert_eq!(actions.len(), 4, "user + io + 2 static channel joins");
        sm
    }

    #[test]
    fn full_mcs_flow_reaches_mcs_connected_with_channel_topology() {
        let mut sm = awaiting_connect_response(config());

        // Connect-Response → Erect Domain + Attach User, both as complete TPKT frames.
        let actions = sm.process(Event::Received(&iron_connect_response(
            false,
            vec![1004, 1005],
        )));
        assert_eq!(
            actions,
            vec![
                Action::WriteBytes(frame_mcs(&mcs::encode_erect_domain_request())),
                Action::WriteBytes(frame_mcs(&mcs::encode_attach_user_request())),
            ]
        );
        assert_eq!(sm.stage(), "capability-exchange");

        // Attach User Confirm → batched join requests for user(1007), io(1003), 1004, 1005.
        let actions = sm.process(Event::Received(&iron_attach_user_confirm(1007)));
        let expected_joins: Vec<Action> = [1007u16, 1003, 1004, 1005]
            .iter()
            .map(|&id| {
                Action::WriteBytes(frame_mcs(&mcs::encode_channel_join_request(1007, id)))
            })
            .collect();
        assert_eq!(actions, expected_joins);

        // All four confirms arrive in ONE Received chunk (out of order) — the machine's frame
        // loop must process every TPKT frame in the buffer.
        let mut batch = Vec::new();
        for id in [1003u16, 1007, 1005, 1004] {
            batch.extend_from_slice(&iron_channel_join_confirm(1007, id, 0));
        }
        let actions = sm.process(Event::Received(&batch));
        // The machine closes the exchange by sending the Client Info PDU (Secure Settings
        // Exchange) before reporting completion — the server will not start licensing without
        // it (#40). Its content is verified field-by-field in
        // client_info_pdu_is_sent_on_the_io_channel_with_caller_fields.
        assert_eq!(actions.len(), 2);
        assert!(matches!(actions[0], Action::WriteBytes(_)));
        assert_eq!(
            actions[1],
            Action::McsConnected {
                result: McsConnectResult {
                    selected: SecurityProtocol::HYBRID,
                    user_channel_id: 1007,
                    io_channel_id: 1003,
                    static_channels: vec![
                        StaticChannel { name: "cliprdr".to_string(), id: 1004 },
                        StaticChannel { name: "drdynvc".to_string(), id: 1005 },
                    ],
                    desktop_size: (1280, 800),
                    channel_join_skipped: false,
                }
            }
        );
        assert_eq!(sm.stage(), "capability-exchange");
    }

    #[test]
    fn skip_channel_join_bypasses_joins_when_both_sides_advertise_it() {
        // Client advertises SUPPORT_SKIP_CHANNELJOIN, server answers SKIP_CHANNELJOIN_SUPPORTED:
        // after Attach User Confirm the machine finishes without a single join request.
        let cfg = config_with_flags(
            ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU
                | ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN,
        );
        let mut sm = awaiting_connect_response(cfg);
        sm.process(Event::Received(&iron_connect_response(true, vec![1004, 1005])));
        let actions = sm.process(Event::Received(&iron_attach_user_confirm(1009)));
        match actions.as_slice() {
            // Even on the skip path the Client Info PDU precedes completion.
            [Action::WriteBytes(_), Action::McsConnected { result }] => {
                assert!(result.channel_join_skipped);
                assert_eq!(result.user_channel_id, 1009);
                assert_eq!(result.io_channel_id, 1003);
                assert_eq!(result.static_channels.len(), 2);
            }
            other => panic!("expected immediate McsConnected, got {other:?}"),
        }
    }

    #[test]
    fn skip_channel_join_requires_the_client_flag_too() {
        // The server offers the skip but the caller did NOT advertise SUPPORT_SKIP_CHANNELJOIN:
        // the machine must join normally — honoring the caller's flags, never its own policy.
        let cfg = config_with_flags(ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU);
        let mut sm = awaiting_connect_response(cfg);
        sm.process(Event::Received(&iron_connect_response(true, vec![1004, 1005])));
        let actions = sm.process(Event::Received(&iron_attach_user_confirm(1009)));
        assert_eq!(actions.len(), 4, "must send all join requests");
        assert!(actions.iter().all(|a| matches!(a, Action::WriteBytes(_))));
    }

    #[test]
    fn refused_channels_are_omitted_from_the_result_and_joins() {
        // The server refuses "drdynvc" (ID 0): it must not be joined nor reported as granted.
        let mut sm = awaiting_connect_response(config());
        sm.process(Event::Received(&iron_connect_response(false, vec![1004, 0])));
        let actions = sm.process(Event::Received(&iron_attach_user_confirm(1007)));
        assert_eq!(actions.len(), 3, "user + io + 1 granted static channel");

        let mut batch = Vec::new();
        for id in [1007u16, 1003, 1004] {
            batch.extend_from_slice(&iron_channel_join_confirm(1007, id, 0));
        }
        let actions = sm.process(Event::Received(&batch));
        match actions.as_slice() {
            [Action::WriteBytes(_), Action::McsConnected { result }] => {
                assert_eq!(
                    result.static_channels,
                    vec![StaticChannel { name: "cliprdr".to_string(), id: 1004 }]
                );
            }
            other => panic!("expected McsConnected, got {other:?}"),
        }
    }

    #[test]
    fn mcs_connect_failure_result_is_typed() {
        let mut sm = awaiting_connect_response(config());
        // rt-resources-unavailable-ish: any non-zero result. Build via ironrdp then patch the
        // BER ENUMERATED result byte (offset: TPKT 4 + X224 3 + tag 2 + len 2..3 — easier to
        // patch by encoding result through ironrdp is not possible (it hardcodes 0), so flip
        // the enumerated content byte right after its 0x0A 0x01 header).
        let mut frame = iron_connect_response(false, vec![1004, 1005]);
        let pos = frame
            .windows(2)
            .position(|w| w == [0x0A, 0x01])
            .expect("BER ENUMERATED header present")
            + 2;
        frame[pos] = 14; // rt-unspecified-failure
        let actions = sm.process(Event::Received(&frame));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::McsConnectFailed { result: 14 })]
        );
    }

    #[test]
    fn channel_join_failure_is_typed() {
        let mut sm = joining_channels();
        let frame = iron_channel_join_confirm(1007, 1004, 3); // rt-no-such-channel
        let actions = sm.process(Event::Received(&frame));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::ChannelJoinFailed {
                channel_id: 1004,
                result: 3,
            })]
        );
    }

    #[test]
    fn unsolicited_channel_join_confirm_is_rejected() {
        let mut sm = joining_channels();
        // 1999 was never requested.
        let frame = iron_channel_join_confirm(1007, 1999, 0);
        let actions = sm.process(Event::Received(&frame));
        assert!(matches!(
            actions.as_slice(),
            [Action::FailWith(ConnectError::Decode(_))]
        ));
    }

    #[test]
    fn client_info_pdu_is_sent_on_the_io_channel_with_caller_fields() {
        // The Secure Settings Exchange write that closes the MCS stage: a SendDataRequest from
        // the user channel on the I/O channel, carrying SEC_INFO_PKT + the caller's Client Info
        // fields — parsed back by ironrdp, the independent reference.
        let mut sm = joining_channels();
        let mut batch = Vec::new();
        for id in [1007u16, 1003, 1004, 1005] {
            batch.extend_from_slice(&iron_channel_join_confirm(1007, id, 0));
        }
        let actions = sm.process(Event::Received(&batch));
        let Action::WriteBytes(frame) = &actions[0] else {
            panic!("expected the Client Info write, got {actions:?}");
        };

        let parsed: IronX224<iron_mcs::McsMessage<'_>> = ironrdp_pdu::decode(frame).unwrap();
        let iron_mcs::McsMessage::SendDataRequest(req) = parsed.0 else {
            panic!("expected a SendDataRequest");
        };
        assert_eq!(req.initiator_id, 1007, "sent as the attached user");
        assert_eq!(req.channel_id, 1003, "sent on the I/O channel");

        let pdu: ironrdp_pdu::rdp::ClientInfoPdu =
            ironrdp_pdu::decode(req.user_data.as_ref()).unwrap();
        let info = &pdu.client_info;
        assert_eq!(info.credentials.username, "sm-user");
        assert_eq!(info.credentials.domain.as_deref(), Some("WORKGROUP"));
        assert_eq!(
            info.credentials.password, "",
            "no secret enters the sans-IO machine (plan.md decision 10)"
        );
        let tz = info.extra_info.optional_data.timezone().expect("timezone present");
        assert_eq!(tz.bias, -540);
        assert_eq!(
            info.extra_info.optional_data.performance_flags().map(|f| f.bits()),
            Some(0x7)
        );
        assert_eq!(info.extra_info.optional_data.session_id(), Some(0));
        assert_eq!(
            info.extra_info.optional_data.reconnect_cookie(),
            None,
            "cbAutoReconnectCookie stays zero until epic #25"
        );
    }

    #[test]
    fn early_capability_flags_reach_the_connect_initial_verbatim() {
        // The anti-hardcode invariant, end to end through the machine: an arbitrary flag
        // pattern set by the caller appears bit-for-bit in the Connect-Initial the machine
        // writes — decoded back by ironrdp, the independent reference.
        for bits in [0x0000u16, 0x0FFF, 0x0123] {
            let cfg = config_with_flags(ClientEarlyCapabilityFlags::from_bits(bits));
            let mut sm = awaiting_nla_with(cfg, SecurityProtocol::HYBRID);
            let actions = sm.process(Event::NlaComplete);
            let Action::WriteBytes(frame) = &actions[0] else {
                panic!("expected the Connect-Initial write");
            };
            let body = decode_mcs_frame(frame).unwrap();
            let parsed: iron_mcs::ConnectInitial = ironrdp_pdu::decode(body).unwrap();
            let decoded_bits = parsed
                .conference_create_request
                .gcc_blocks()
                .core
                .optional_data
                .early_capability_flags
                .unwrap()
                .bits();
            assert_eq!(decoded_bits, bits, "flags must pass through unmodified");
            // And the machine echoed the negotiated protocol, not a hardcoded one.
            assert_eq!(
                parsed
                    .conference_create_request
                    .gcc_blocks()
                    .core
                    .optional_data
                    .server_selected_protocol
                    .unwrap()
                    .bits(),
                SecurityProtocol::HYBRID.bits()
            );
        }
    }

    // ---- ordering-contract (stage × event) tests ----

    /// All event kinds, for the stage × event mismatch matrix.
    const ALL_EVENT_KINDS: [EventKind; 5] = [
        EventKind::Connected,
        EventKind::Received,
        EventKind::TlsEstablished,
        EventKind::NlaComplete,
        EventKind::EarlyUserAuthResult,
    ];

    /// A representative event of `kind`. Payloads are minimal — for a mismatched (stage, event)
    /// pair the machine must reject on the pairing alone, before looking at any payload.
    fn sample_event(kind: EventKind) -> Event<'static> {
        match kind {
            EventKind::Connected => Event::Connected,
            EventKind::Received => Event::Received(&[]),
            EventKind::TlsEstablished => Event::TlsEstablished(&[]),
            EventKind::NlaComplete => Event::NlaComplete,
            EventKind::EarlyUserAuthResult => Event::EarlyUserAuthResult(&[0, 0, 0, 0]),
        }
    }

    /// A machine driven to the terminal stage via the success path (McsConnected emitted).
    fn done_connected() -> ConnectStateMachine {
        let mut sm = joining_channels();
        let mut batch = Vec::new();
        for id in [1007u16, 1003, 1004, 1005] {
            batch.extend_from_slice(&iron_channel_join_confirm(1007, id, 0));
        }
        let actions = sm.process(Event::Received(&batch));
        assert!(matches!(
            actions.as_slice(),
            [Action::WriteBytes(_), Action::McsConnected { .. }]
        ));
        sm
    }

    /// A machine driven to the terminal stage via the failure path (FailWith emitted).
    fn done_failed() -> ConnectStateMachine {
        let mut sm = negotiating();
        sm.process(Event::Received(&connection_failure(
            NegFailureCode::HYBRID_REQUIRED_BY_SERVER,
        )));
        sm
    }

    #[test]
    fn stage_mismatched_events_fail_with_unexpected_event() {
        // The full ordering-contract matrix: for every stage, every event the stage does not
        // expect yields FailWith(UnexpectedEvent { stage, event }) — never a panic, never a
        // silent misparse.
        type Make = fn() -> ConnectStateMachine;
        let stages: [(Make, &str, &[EventKind]); 10] = [
            (
                || ConnectStateMachine::new(config()),
                "tcp-connect",
                &[EventKind::Connected],
            ),
            (negotiating, "x224-negotiate", &[EventKind::Received]),
            (
                || awaiting_tls(SecurityProtocol::HYBRID),
                "tls-handshake",
                &[EventKind::TlsEstablished],
            ),
            (
                || awaiting_nla(SecurityProtocol::HYBRID),
                "nla-credssp",
                &[EventKind::NlaComplete],
            ),
            (
                awaiting_early_user_auth,
                "nla-credssp",
                &[EventKind::EarlyUserAuthResult],
            ),
            (
                || awaiting_connect_response(config()),
                "capability-exchange",
                &[EventKind::Received],
            ),
            (
                || {
                    let mut sm = awaiting_connect_response(config());
                    sm.process(Event::Received(&iron_connect_response(
                        false,
                        vec![1004, 1005],
                    )));
                    sm
                },
                "capability-exchange",
                &[EventKind::Received],
            ),
            (joining_channels, "capability-exchange", &[EventKind::Received]),
            // Terminal machines keep reporting the label of the stage where the connect ended.
            (done_connected, "capability-exchange", &[]),
            (done_failed, "x224-negotiate", &[]),
        ];

        for (make, label, expected) in stages {
            for kind in ALL_EVENT_KINDS {
                if expected.contains(&kind) {
                    continue;
                }
                let mut sm = make();
                assert_eq!(sm.stage(), label, "stage constructor drove to the wrong stage");
                let actions = sm.process(sample_event(kind));
                assert_eq!(
                    actions,
                    vec![Action::FailWith(ConnectError::UnexpectedEvent {
                        stage: label,
                        event: kind,
                    })],
                    "stage {label} fed {kind:?} must fail with UnexpectedEvent"
                );
                // The violation is terminal — but the label stays attributed to the stage where
                // the connect ended...
                assert_eq!(sm.stage(), label);
                // ...and any further event fails typed too.
                let replay = sm.process(sample_event(kind));
                assert_eq!(
                    replay,
                    vec![Action::FailWith(ConnectError::UnexpectedEvent {
                        stage: label,
                        event: kind,
                    })],
                    "terminal machine in {label} fed {kind:?} again must stay failed"
                );
            }
        }
    }

    #[test]
    fn nla_complete_in_early_user_auth_substage_is_unexpected() {
        // Regression pin: a duplicate NlaComplete while awaiting the early-auth PDU used to
        // re-emit AwaitEarlyUserAuth (double read). Covered by the matrix; documented here.
        let mut sm = awaiting_early_user_auth();
        let actions = sm.process(Event::NlaComplete);
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::UnexpectedEvent {
                stage: "nla-credssp",
                event: EventKind::NlaComplete,
            })]
        );
    }

    #[test]
    fn replay_after_completion_is_unexpected() {
        // The terminal state accepts nothing: replaying an event after McsConnected must fail
        // typed, attributed to the stage where the connect ended (capability-exchange).
        let mut sm = done_connected();
        let actions = sm.process(Event::NlaComplete);
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::UnexpectedEvent {
                stage: "capability-exchange",
                event: EventKind::NlaComplete,
            })]
        );
    }

    #[test]
    fn terminal_machine_keeps_the_last_canonical_stage_label() {
        // Termination is internal: stage() keeps attributing to the stage where the connect
        // ended. No non-glossary label is ever observable, so a host's on_stage sees only
        // CONTEXT.md's seven Connect Stage labels and error attribution survives.
        assert_eq!(done_failed().stage(), "x224-negotiate");
        assert_eq!(done_connected().stage(), "capability-exchange");
    }
}
