//! The sans-IO connection state machine (ADR-0001). It drives the RDP connect sequence by
//! consuming [`Event`]s (socket connected, bytes received) and emitting [`Action`]s (open the
//! socket, write bytes, fail) — never touching the socket itself. The full sequence:
//! `tcp-connect` → `x224-negotiate` → `tls-handshake` → `nla-credssp` → `capability-exchange`
//! (MCS/GCC, channel join, Client Info, licensing, Demand/Confirm Active) → `activation`
//! (Synchronize / Control / Font List ↔ Font Map) → `session-active`.

use crate::license_crypto;
use justrdp_pdu::capability::{self, CapabilitySet};
use justrdp_pdu::client_info;
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::gcc::{
    ClientGccBlocks, ClientNetworkData, ServerEarlyCapabilityFlags,
};
use justrdp_pdu::nego::{NegFailureCode, NegRequest, NegResponse, SecurityProtocol};
use justrdp_pdu::{finalization, gcc, license, mcs, share, tpkt, x224};

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
    /// The capability sets to send in Confirm Active, **verbatim** — the same anti-hardcode
    /// contract as `core.early_capability_flags` (plan.md §0). The machine touches exactly one
    /// thing: the Bitmap set's desktop size is overwritten with the server-negotiated size from
    /// Demand Active (a wire fact, like `serverSelectedProtocol`). Start from
    /// [`capability::default_client_capabilities`] and edit as needed.
    pub capabilities: Vec<CapabilitySet>,
    /// Licensing parameters for the full MS-RDPELE negotiation (most servers short-circuit it
    /// with `STATUS_VALID_CLIENT` and never consume these).
    pub license: LicenseConfig,
}

/// Caller-supplied licensing parameters (MS-RDPELE). Reaches the wire verbatim.
///
/// Decision-10 note: the entropy below is **connection-scoped protocol nonce material**, not a
/// user credential — it exists only to key the legacy licensing exchange, which itself rides
/// inside the already-authenticated TLS session. User secrets still never enter this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseConfig {
    /// Fresh per-connection randomness for the licensing key exchange. Generate with a real
    /// RNG at the adapter boundary (the sans-IO machine cannot produce randomness itself).
    pub entropy: LicenseEntropy,
    /// `PlatformId` for the New License Request (client OS / ISV identification, e.g.
    /// [`license::PLATFORM_ID_NT_POST_52_MICROSOFT`]).
    pub platform_id: u32,
    /// `ClientHardwareId` for the Platform Challenge Response — four caller-chosen words
    /// identifying this device to the license server (MS-RDPELE 2.2.2.5.1).
    pub hardware_id: [u32; 4],
}

/// Per-connection randomness for licensing: the client random and the premaster secret the
/// session keys derive from (MS-RDPELE 5.1.2–5.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseEntropy {
    /// `ClientRandom` (sent in the clear in the New License Request).
    pub client_random: [u8; license::RANDOM_SIZE],
    /// The premaster secret (sent RSA-encrypted to the server certificate's key).
    pub premaster_secret: [u8; license::PREMASTER_SECRET_SIZE],
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
        /// The server's `subjectPublicKey` for CredSSP to bind to — the inner BIT STRING
        /// contents of the `SubjectPublicKeyInfo` (for RSA, the DER `RSAPublicKey`), **not**
        /// the whole SPKI (see `tls::extract_subject_public_key`).
        server_public_key: Vec<u8>,
    },
    /// HYBRID_EX only: the CredSSP exchange finished and the server will now send the 4-byte
    /// Early User Authorization Result PDU. The adapter must read it and deliver it via
    /// [`Event::EarlyUserAuthResult`]. (Failing to consume it desyncs capability exchange —
    /// plan.md §0.)
    AwaitEarlyUserAuth,
    /// The MCS connect sequence completed: GCC settings exchanged, user attached, channels
    /// joined (or the join legitimately skipped). A **milestone, not the end**: the machine
    /// continues through licensing, capability exchange, and activation — keep feeding it
    /// [`Event::Received`] until [`Action::SessionActive`] or [`Action::FailWith`].
    McsConnected {
        /// The negotiated MCS/GCC results.
        result: McsConnectResult,
    },
    /// Terminal: the Font Map PDU arrived — the session is active and ready for live I/O.
    /// The connect machine is done; hand `result` (and the socket) to the session loop.
    SessionActive {
        /// The activation results the session loop starts from.
        result: ActivationResult,
    },
    /// The connect attempt failed; surface this error and tear down.
    FailWith(ConnectError),
}

/// What capability exchange + activation settled — everything the session loop needs beyond
/// the earlier [`McsConnectResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationResult {
    /// The server-assigned `shareID`, echoed in every Share Control PDU from here on.
    pub share_id: u32,
    /// The **negotiated** desktop size from the server's Bitmap capability set — allocate the
    /// framebuffer from this, not from the size requested at GCC.
    pub desktop_size: (u16, u16),
    /// The server's capability sets from Demand Active, verbatim (the session loop reads
    /// order/codec support from these).
    pub server_capabilities: Vec<CapabilitySet>,
    /// Socket bytes that arrived after the Font Map in the same read — already consumed from
    /// the transport, so the session loop must process these **before** reading the socket
    /// (servers start streaming graphics immediately).
    pub leftover: Vec<u8>,
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
    /// The server ended licensing with a License Error PDU whose code is not
    /// `STATUS_VALID_CLIENT` — no license, no session (MS-RDPELE 2.2.2.7).
    LicensingFailed {
        /// The `dwErrorCode` the server reported.
        error_code: u32,
    },
    /// A licensing message failed its MAC check — the decrypted content does not match the
    /// server's integrity data (MS-RDPELE 5.1.6).
    LicenseMacMismatch,
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
    /// The Client Info PDU is on the wire; awaiting the server's first licensing message
    /// (MS-RDPELE). Still `capability-exchange` to observers: licensing is a gatekeeping
    /// sub-step between the two halves of capability negotiation, and CONTEXT.md's seven
    /// stages remain the complete observable set (the same ruling as Client Info, gate #40).
    Licensing { selected: SecurityProtocol },
    /// Licensing completed; awaiting the server's Demand Active (tolerating DeactivateAll
    /// and stray data PDUs). Still `capability-exchange` — this is its second half.
    CapabilityExchange { selected: SecurityProtocol },
    /// Confirm Active + the finalization batch are on the wire; awaiting the server's
    /// Synchronize / Control / **Font Map** — the session-active gate. Label: `activation`.
    Finalization { selected: SecurityProtocol },
    /// Terminal: the machine emitted [`Action::SessionActive`] or [`Action::FailWith`] and will
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
            Stage::GccExchange { .. }
            | Stage::McsAttach { .. }
            | Stage::ChannelJoin { .. }
            | Stage::Licensing { .. }
            | Stage::CapabilityExchange { .. } => "capability-exchange",
            Stage::Finalization { .. } => "activation",
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
                | Stage::Licensing { .. }
                | Stage::CapabilityExchange { .. }
                | Stage::Finalization { .. }
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
    /// Licensing session keys, present only after a full negotiation ran (the
    /// `STATUS_VALID_CLIENT` short-circuit never derives them).
    license_keys: Option<license_crypto::LicenseKeys>,
    /// Capability-exchange results (valid from Demand Active onward).
    share_id: u32,
    negotiated_size: (u16, u16),
    server_capabilities: Vec<CapabilitySet>,
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
            license_keys: None,
            share_id: 0,
            negotiated_size: (0, 0),
            server_capabilities: Vec::new(),
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
            // Post-MCS stages: every inbound frame is a Send Data Indication on the I/O
            // channel; the per-stage step functions parse its payload.
            Stage::Licensing { selected } => match decode_mcs_frame(frame)
                .and_then(mcs::SendDataIndication::decode)
            {
                Ok(ind) => match self.license_step(selected, ind.user_data) {
                    Ok(actions) => actions,
                    Err(e) => self.fail(e),
                },
                Err(e) => self.fail(ConnectError::Decode(e)),
            },
            Stage::CapabilityExchange { selected } => match decode_mcs_frame(frame)
                .and_then(mcs::SendDataIndication::decode)
            {
                Ok(ind) => match self.capability_step(selected, ind.user_data) {
                    Ok(actions) => actions,
                    Err(e) => self.fail(e),
                },
                Err(e) => self.fail(ConnectError::Decode(e)),
            },
            Stage::Finalization { selected } => match decode_mcs_frame(frame)
                .and_then(mcs::SendDataIndication::decode)
            {
                Ok(ind) => match self.finalization_step(selected, ind.user_data) {
                    Ok(actions) => actions,
                    Err(e) => self.fail(e),
                },
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

    /// The MCS connect is complete: send the Client Info PDU, report the milestone, and enter
    /// the licensing wait.
    ///
    /// The Client Info write is the Secure Settings Exchange (MS-RDPBCGR 2.2.1.11) — the server
    /// does not begin licensing until it arrives, so the connect machine owns the send rather
    /// than leaving a silent gap for the host to discover. It happens at the tail of the
    /// `capability-exchange` stage; per CONTEXT.md's seven-stage glossary no separate label
    /// exists for it (it is a single fire-and-forget write with no response of its own — the
    /// next inbound PDU is licensing).
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

        self.stage = Stage::Licensing { selected };
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

    /// Wrap an I/O-channel payload (security header / share PDU and inward) into a complete
    /// outbound frame: MCS Send Data Request → X.224 Data → TPKT.
    fn send_io(&self, payload: &[u8]) -> Action {
        Action::WriteBytes(tpkt::encode(&x224::encode_data(
            &mcs::encode_send_data_request(self.user_channel_id, self.io_channel_id, payload),
        )))
    }

    /// One licensing message arrived (MS-RDPELE 3.2.5). Advances to capability exchange on
    /// `STATUS_VALID_CLIENT` (the common short-circuit) or a MAC-verified New/Upgrade License;
    /// answers License Request / Platform Challenge on the full path; stays in `Licensing`
    /// otherwise.
    fn license_step(
        &mut self,
        selected: SecurityProtocol,
        user_data: &[u8],
    ) -> Result<Vec<Action>, ConnectError> {
        let mut cur = ReadCursor::new(user_data, "licensing message");
        let flags =
            client_info::decode_basic_security_header(&mut cur).map_err(ConnectError::Decode)?;
        if flags & client_info::SEC_LICENSE_PKT == 0 {
            // Licensing is mandatory after Client Info (MS-RDPBCGR 1.3.1.1); anything else
            // here means the sequence desynced.
            return Err(ConnectError::Decode(justrdp_pdu::DecodeError::InvalidField {
                field: "securityHeader.flags",
                reason: "expected SEC_LICENSE_PKT while awaiting licensing",
            }));
        }
        let preamble = license::LicensePreamble::decode(&mut cur).map_err(ConnectError::Decode)?;
        match preamble.msg_type {
            license::MSG_ERROR_ALERT => {
                let alert = license::LicenseError::decode(&mut cur).map_err(ConnectError::Decode)?;
                // `dwStateTransition` pins the client's reaction (MS-RDPELE 2.2.2.7), not the
                // error code alone: ST_NO_TRANSITION means the licensing exchange is over and
                // the connect proceeds — true for the STATUS_VALID_CLIENT short-circuit (the
                // path most real servers take) and equally for a grace-period server that
                // reports an error code yet continues to Demand Active (FreeRDP-compatible).
                // Everything else (ST_TOTAL_ABORT, or the RESET/RESEND transitions this slice
                // does not negotiate) ends the connect with a typed failure.
                if alert.error_code == license::STATUS_VALID_CLIENT
                    || alert.state_transition == license::ST_NO_TRANSITION
                {
                    self.stage = Stage::CapabilityExchange { selected };
                    Ok(Vec::new())
                } else {
                    Err(ConnectError::LicensingFailed {
                        error_code: alert.error_code,
                    })
                }
            }
            license::MSG_LICENSE_REQUEST => {
                let request =
                    license::ServerLicenseRequest::decode(&mut cur).map_err(ConnectError::Decode)?;
                let key = self.server_license_key(request.certificate.as_ref())?;
                let entropy = &self.config.license.entropy;
                self.license_keys = Some(license_crypto::derive_license_keys(
                    &entropy.premaster_secret,
                    &entropy.client_random,
                    &request.server_random,
                ));
                let encrypted_premaster = license_crypto::encrypt_premaster_secret(
                    &entropy.premaster_secret,
                    &key.modulus,
                    key.exponent,
                );
                let msg = license::encode_new_license_request(
                    self.config.license.platform_id,
                    &entropy.client_random,
                    &encrypted_premaster,
                    &self.config.client_info.username,
                    &self.config.core.client_name,
                );
                Ok(vec![self.send_io(&msg)])
            }
            license::MSG_PLATFORM_CHALLENGE => {
                let challenge =
                    license::PlatformChallenge::decode(&mut cur).map_err(ConnectError::Decode)?;
                let keys = self.license_keys.as_ref().ok_or(ConnectError::Decode(
                    justrdp_pdu::DecodeError::InvalidField {
                        field: "PLATFORM_CHALLENGE",
                        reason: "platform challenge before a license request derived keys",
                    },
                ))?;
                let plain = license_crypto::rc4(&keys.license_key, &challenge.encrypted_challenge);
                if license_crypto::mac_data(&keys.mac_salt, &plain) != challenge.mac {
                    return Err(ConnectError::LicenseMacMismatch);
                }
                // PLATFORM_CHALLENGE_RESPONSE_DATA (MS-RDPELE 2.2.2.5.1): version 1.0, client
                // type "other", detail level "detail", then the decrypted challenge echoed.
                let mut response = Vec::with_capacity(8 + plain.len());
                response.extend_from_slice(&0x0100u16.to_le_bytes());
                response.extend_from_slice(&0xFF00u16.to_le_bytes());
                response.extend_from_slice(&0x0003u16.to_le_bytes());
                response.extend_from_slice(&(plain.len() as u16).to_le_bytes());
                response.extend_from_slice(&plain);
                // CLIENT_HARDWARE_ID (2.2.2.5.2): PlatformId + the caller's four words.
                let mut hwid = Vec::with_capacity(20);
                hwid.extend_from_slice(&self.config.license.platform_id.to_le_bytes());
                for word in self.config.license.hardware_id {
                    hwid.extend_from_slice(&word.to_le_bytes());
                }
                let mac =
                    license_crypto::mac_data(&keys.mac_salt, &[&response[..], &hwid].concat());
                let msg = license::encode_platform_challenge_response(
                    &license_crypto::rc4(&keys.license_key, &response),
                    &license_crypto::rc4(&keys.license_key, &hwid),
                    &mac,
                );
                Ok(vec![self.send_io(&msg)])
            }
            license::MSG_NEW_LICENSE | license::MSG_UPGRADE_LICENSE => {
                let new_license =
                    license::NewLicense::decode(&mut cur).map_err(ConnectError::Decode)?;
                let keys = self.license_keys.as_ref().ok_or(ConnectError::Decode(
                    justrdp_pdu::DecodeError::InvalidField {
                        field: "NEW_LICENSE",
                        reason: "license grant before a license request derived keys",
                    },
                ))?;
                let plain =
                    license_crypto::rc4(&keys.license_key, &new_license.encrypted_license_info);
                if license_crypto::mac_data(&keys.mac_salt, &plain) != new_license.mac {
                    return Err(ConnectError::LicenseMacMismatch);
                }
                // Persistent license caching is optional (MS-RDPELE) and backlog (plan.md §3):
                // the grant is integrity-verified and discarded.
                self.stage = Stage::CapabilityExchange { selected };
                Ok(Vec::new())
            }
            _ => Err(ConnectError::Decode(justrdp_pdu::DecodeError::InvalidField {
                field: "preamble.bMsgType",
                reason: "unknown licensing message type",
            })),
        }
    }

    /// Resolve the RSA key the premaster secret is encrypted to, from whichever certificate
    /// format the server sent.
    fn server_license_key(
        &self,
        certificate: Option<&license::ServerCertificate>,
    ) -> Result<license::RsaPublicKey, ConnectError> {
        match certificate {
            // A server may omit the certificate when it expects a cached license (LICENSE_INFO);
            // this client holds none (caching is backlog), so the exchange cannot proceed.
            None => Err(ConnectError::Decode(justrdp_pdu::DecodeError::InvalidField {
                field: "ServerCertificate",
                reason: "server sent no licensing certificate and no license is cached",
            })),
            Some(license::ServerCertificate::Proprietary(key)) => Ok(key.clone()),
            Some(license::ServerCertificate::X509Chain(chain)) => {
                // The leaf (last) certificate carries the licensing key. `x509-cert` extracts
                // the inner subjectPublicKey — the DER RSAPublicKey — exactly as the TLS
                // binding path does (ADR-0002 leaf dependency).
                let leaf = chain.last().expect("decode guarantees a non-empty chain");
                let inner = crate::tls::extract_subject_public_key(leaf).map_err(|_| {
                    ConnectError::Decode(justrdp_pdu::DecodeError::InvalidField {
                        field: "ServerCertificate.X509",
                        reason: "licensing X.509 leaf certificate could not be parsed",
                    })
                })?;
                license::RsaPublicKey::from_pkcs1_der(&inner).map_err(ConnectError::Decode)
            }
        }
    }

    /// One Share Control PDU arrived while awaiting Demand Active. DeactivateAll and stray
    /// data PDUs are decoded and discarded (MS-RDPBCGR 3.2.5.3.13: the server may reset);
    /// Demand Active triggers Confirm Active plus the pipelined finalization batch.
    fn capability_step(
        &mut self,
        selected: SecurityProtocol,
        user_data: &[u8],
    ) -> Result<Vec<Action>, ConnectError> {
        let mut cur = ReadCursor::new(user_data, "share control pdu");
        let header = share::ShareControlHeader::decode(&mut cur).map_err(ConnectError::Decode)?;
        match header.pdu_type {
            // The server is resetting the session: discard and keep waiting for the next
            // Demand Active.
            share::PDU_TYPE_DEACTIVATE_ALL => Ok(Vec::new()),
            // A data PDU before Demand Active (e.g. an early Set Error Info): skip, per the
            // robustness policy (plan.md §11c — unknown-but-well-formed input never kills the
            // connect; malformed input does).
            share::PDU_TYPE_DATA => Ok(Vec::new()),
            share::PDU_TYPE_DEMAND_ACTIVE => {
                let demand =
                    capability::DemandActive::decode(&mut cur).map_err(ConnectError::Decode)?;
                self.share_id = header.share_id;
                // The negotiated desktop size lives in the server's Bitmap set; a server that
                // omits it accepts the client's requested size.
                self.negotiated_size = demand
                    .bitmap()
                    .map(|b| (b.desktop_width, b.desktop_height))
                    .unwrap_or((
                        self.config.core.desktop_width,
                        self.config.core.desktop_height,
                    ));
                self.server_capabilities = demand.capability_sets;

                // Echo the negotiated size into our Bitmap set — the one wire fact the machine
                // writes into the caller's capability list (like `serverSelectedProtocol`).
                let mut caps = self.config.capabilities.clone();
                for set in &mut caps {
                    if let CapabilitySet::Bitmap(bitmap) = set {
                        bitmap.desktop_width = self.negotiated_size.0;
                        bitmap.desktop_height = self.negotiated_size.1;
                    }
                }
                let confirm = share::encode_share_control(
                    share::PDU_TYPE_CONFIRM_ACTIVE,
                    self.user_channel_id,
                    header.share_id,
                    &capability::encode_confirm_active(header.pdu_source, b"justrdp\0", &caps),
                );

                // Pipeline the whole finalization batch with the confirm (MS-RDPBCGR
                // 1.3.1.1 allows it; one round trip instead of four).
                let batch = [
                    (
                        share::PDU_TYPE2_SYNCHRONIZE,
                        finalization::Synchronize {
                            target_user: header.pdu_source,
                        }
                        .encode(),
                    ),
                    (
                        share::PDU_TYPE2_CONTROL,
                        finalization::Control::new(finalization::CTRLACTION_COOPERATE).encode(),
                    ),
                    (
                        share::PDU_TYPE2_CONTROL,
                        finalization::Control::new(finalization::CTRLACTION_REQUEST_CONTROL)
                            .encode(),
                    ),
                    (share::PDU_TYPE2_FONT_LIST, finalization::encode_font_list()),
                ];
                let mut actions = vec![self.send_io(&confirm)];
                for (pdu_type2, body) in batch {
                    actions.push(self.send_io(&share::encode_share_data(
                        self.user_channel_id,
                        header.share_id,
                        share::STREAM_MED,
                        pdu_type2,
                        &body,
                    )));
                }
                self.stage = Stage::Finalization { selected };
                Ok(actions)
            }
            _ => Err(ConnectError::Decode(justrdp_pdu::DecodeError::InvalidField {
                field: "ShareControlHeader.pduType",
                reason: "unexpected share control pdu during capability exchange",
            })),
        }
    }

    /// One Share PDU arrived during finalization. The Font Map is the session-active gate;
    /// the server's Synchronize / Control replies are decoded and noted; everything else is
    /// skipped. A DeactivateAll (or a fresh Demand Active) re-runs capability exchange.
    fn finalization_step(
        &mut self,
        selected: SecurityProtocol,
        user_data: &[u8],
    ) -> Result<Vec<Action>, ConnectError> {
        let mut cur = ReadCursor::new(user_data, "finalization pdu");
        let header = share::ShareControlHeader::decode(&mut cur).map_err(ConnectError::Decode)?;
        match header.pdu_type {
            share::PDU_TYPE_DATA => {
                let data = share::ShareDataHeader::decode(&mut cur).map_err(ConnectError::Decode)?;
                match data.pdu_type2 {
                    share::PDU_TYPE2_FONT_MAP => {
                        finalization::FontMap::decode(&mut cur).map_err(ConnectError::Decode)?;
                        // Session-active: the terminal stage keeps the glossary label so the
                        // host observes the `session-active` transition (CONTEXT.md stage 7).
                        self.stage = Stage::Done {
                            last: "session-active",
                        };
                        Ok(vec![Action::SessionActive {
                            result: ActivationResult {
                                share_id: self.share_id,
                                desktop_size: self.negotiated_size,
                                server_capabilities: std::mem::take(&mut self.server_capabilities),
                                leftover: std::mem::take(&mut self.inbox),
                            },
                        }])
                    }
                    share::PDU_TYPE2_SYNCHRONIZE => {
                        finalization::Synchronize::decode(&mut cur)
                            .map_err(ConnectError::Decode)?;
                        Ok(Vec::new())
                    }
                    share::PDU_TYPE2_CONTROL => {
                        finalization::Control::decode(&mut cur).map_err(ConnectError::Decode)?;
                        Ok(Vec::new())
                    }
                    // Anything else the server interleaves here (Save Session Info, Set Error
                    // Info, keyboard indicators, …) is session-loop material: skipped now,
                    // handled by the corresponding epics.
                    _ => Ok(Vec::new()),
                }
            }
            // The server reset mid-finalization: go back to waiting for Demand Active.
            share::PDU_TYPE_DEACTIVATE_ALL => {
                self.stage = Stage::CapabilityExchange { selected };
                Ok(Vec::new())
            }
            // A fresh Demand Active without an explicit deactivate: re-run the exchange.
            share::PDU_TYPE_DEMAND_ACTIVE => self.capability_step(selected, user_data),
            _ => Err(ConnectError::Decode(justrdp_pdu::DecodeError::InvalidField {
                field: "ShareControlHeader.pduType",
                reason: "unexpected share control pdu during finalization",
            })),
        }
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
            capabilities: capability::default_client_capabilities(&core_for_caps()),
            license: LicenseConfig {
                entropy: LicenseEntropy {
                    client_random: [0x11; license::RANDOM_SIZE],
                    premaster_secret: [0x22; license::PREMASTER_SECRET_SIZE],
                },
                platform_id: license::PLATFORM_ID_NT_POST_52_MICROSOFT,
                hardware_id: [1, 2, 3, 4],
            },
        }
    }

    /// The same core data `config_with_flags` builds, for deriving default capabilities.
    fn core_for_caps() -> justrdp_pdu::gcc::ClientCoreData {
        justrdp_pdu::gcc::ClientCoreData {
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
            supported_color_depths: SUPPORTED_COLOR_DEPTH_24BPP | SUPPORTED_COLOR_DEPTH_32BPP,
            early_capability_flags: ClientEarlyCapabilityFlags::empty(),
            dig_product_id: String::new(),
            connection_type: CONNECTION_TYPE_LAN,
            server_selected_protocol: SecurityProtocol::from_bits(0),
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

    /// A machine driven through the MCS connect (McsConnected emitted) into the licensing
    /// wait — no longer terminal since slice-5 continues to session-active.
    fn licensing() -> ConnectStateMachine {
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
        let stages: [(Make, &str, &[EventKind]); 12] = [
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
            // Licensing and the Demand Active wait keep consuming socket bytes under the
            // capability-exchange label; finalization does so under activation.
            (licensing, "capability-exchange", &[EventKind::Received]),
            (capability_waiting, "capability-exchange", &[EventKind::Received]),
            (finalizing, "activation", &[EventKind::Received]),
            // Terminal machines keep reporting the label of the stage where the connect ended.
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
        // The terminal state accepts nothing: replaying an event after SessionActive must
        // fail typed, attributed to the stage where the connect ended (session-active).
        let mut sm = session_active().0;
        let actions = sm.process(Event::NlaComplete);
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::UnexpectedEvent {
                stage: "session-active",
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
        assert_eq!(licensing().stage(), "capability-exchange");
        assert_eq!(session_active().0.stage(), "session-active");
    }

    // ───────────────────────── slice-5: licensing → capability → activation ──────────────────

    /// The server random every synthetic licensing exchange uses.
    const SERVER_RANDOM: [u8; 32] = [0x5A; 32];
    /// The 512-bit modulus of the synthetic proprietary licensing certificate (top bit set).
    const TEST_MODULUS: [u8; 64] = [0xC3; 64];
    /// The share ID the synthetic Demand Active assigns.
    const SHARE_ID: u32 = 0x0001_03EA;

    /// Wrap a server-side I/O channel payload as a complete inbound frame, with ironrdp's
    /// Send Data Indication encoder (their encoder, our decoder).
    fn server_io_frame(user_data: &[u8]) -> Vec<u8> {
        iron_encode_vec(&IronX224(iron_mcs::SendDataIndication {
            initiator_id: 1002,
            channel_id: 1003,
            user_data: std::borrow::Cow::Borrowed(user_data),
        }))
        .unwrap()
    }

    /// Security header + preamble + body, as the server frames licensing messages.
    fn license_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        client_info::encode_basic_security_header(&mut out, client_info::SEC_LICENSE_PKT);
        out.push(msg_type);
        out.push(0x03); // version 3.0
        out.extend_from_slice(&((4 + body.len()) as u16).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    /// A License Error (ERROR_ALERT) message with the given code and state transition.
    fn license_alert_with(error_code: u32, state_transition: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&error_code.to_le_bytes());
        body.extend_from_slice(&state_transition.to_le_bytes());
        body.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // empty error-info blob
        license_message(license::MSG_ERROR_ALERT, &body)
    }

    /// A License Error (ERROR_ALERT) message ending the exchange (`ST_NO_TRANSITION`).
    fn license_alert(error_code: u32) -> Vec<u8> {
        license_alert_with(error_code, license::ST_NO_TRANSITION)
    }

    /// A proprietary (CERT_CHAIN_VERSION_1) server certificate around [`TEST_MODULUS`].
    fn proprietary_cert() -> Vec<u8> {
        let keylen = TEST_MODULUS.len() + 8;
        let mut key = Vec::new();
        key.extend_from_slice(&0x3141_5352u32.to_le_bytes()); // "RSA1"
        key.extend_from_slice(&(keylen as u32).to_le_bytes());
        key.extend_from_slice(&((TEST_MODULUS.len() * 8) as u32).to_le_bytes());
        key.extend_from_slice(&((TEST_MODULUS.len() - 1) as u32).to_le_bytes());
        key.extend_from_slice(&65537u32.to_le_bytes());
        let mut le = TEST_MODULUS.to_vec();
        le.reverse();
        key.extend_from_slice(&le);
        key.extend_from_slice(&[0u8; 8]);

        let mut cert = Vec::new();
        cert.extend_from_slice(&1u32.to_le_bytes());
        cert.extend_from_slice(&1u32.to_le_bytes());
        cert.extend_from_slice(&1u32.to_le_bytes());
        cert.extend_from_slice(&0x0006u16.to_le_bytes());
        cert.extend_from_slice(&(key.len() as u16).to_le_bytes());
        cert.extend_from_slice(&key);
        cert
    }

    /// A Server License Request opening the full negotiation.
    fn server_license_request() -> Vec<u8> {
        let cert = proprietary_cert();
        let mut body = Vec::new();
        body.extend_from_slice(&SERVER_RANDOM);
        body.extend_from_slice(&0x0006_0000u32.to_le_bytes()); // ProductInfo.dwVersion
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(b"M\0S\0");
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(b"A\0");
        body.extend_from_slice(&0x000Du16.to_le_bytes()); // KeyExchangeList blob
        body.extend_from_slice(&4u16.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&0x0003u16.to_le_bytes()); // certificate blob
        body.extend_from_slice(&(cert.len() as u16).to_le_bytes());
        body.extend_from_slice(&cert);
        body.extend_from_slice(&0u32.to_le_bytes()); // ScopeCount 0
        license_message(license::MSG_LICENSE_REQUEST, &body)
    }

    /// The keys both sides derive in the synthetic full negotiation (the test plays server).
    fn test_license_keys() -> license_crypto::LicenseKeys {
        license_crypto::derive_license_keys(&[0x22; 48], &[0x11; 32], &SERVER_RANDOM)
    }

    /// A synthetic Demand Active: General + Bitmap (carrying `width`×`height`) + Input.
    fn server_demand_active(width: u16, height: u16) -> Vec<u8> {
        let sets = vec![
            CapabilitySet::General(capability::GeneralCapabilitySet {
                os_major_type: 1,
                os_minor_type: 3,
                extra_flags: capability::GENERAL_FASTPATH_OUTPUT_SUPPORTED,
                refresh_rect_support: 1,
                suppress_output_support: 1,
            }),
            CapabilitySet::Bitmap(capability::BitmapCapabilitySet {
                preferred_bits_per_pixel: 32,
                desktop_width: width,
                desktop_height: height,
                desktop_resize_flag: 1,
                drawing_flags: 0,
            }),
            CapabilitySet::Input(capability::InputCapabilitySet {
                input_flags: capability::INPUT_FLAG_SCANCODES,
                keyboard_layout: 0,
                keyboard_type: 4,
                keyboard_subtype: 0,
                keyboard_function_key: 12,
            }),
        ];
        let mut caps = Vec::new();
        for set in &sets {
            set.encode(&mut caps);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes());
        body.extend_from_slice(&((caps.len() + 4) as u16).to_le_bytes());
        body.extend_from_slice(b"RDP\0");
        body.extend_from_slice(&(sets.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&caps);
        body.extend_from_slice(&0u32.to_le_bytes()); // sessionId
        share::encode_share_control(share::PDU_TYPE_DEMAND_ACTIVE, 1002, SHARE_ID, &body)
    }

    /// The five outbound frames the machine must emit in response to Demand Active:
    /// Confirm Active (with the negotiated size echoed) + the pipelined finalization batch.
    fn expected_confirm_and_batch(width: u16, height: u16) -> Vec<Action> {
        let mut caps = config().capabilities;
        for set in &mut caps {
            if let CapabilitySet::Bitmap(bitmap) = set {
                bitmap.desktop_width = width;
                bitmap.desktop_height = height;
            }
        }
        let confirm = share::encode_share_control(
            share::PDU_TYPE_CONFIRM_ACTIVE,
            1007,
            SHARE_ID,
            &capability::encode_confirm_active(1002, b"justrdp\0", &caps),
        );
        let mut expected = vec![Action::WriteBytes(frame_io(&confirm))];
        let batch = [
            (
                share::PDU_TYPE2_SYNCHRONIZE,
                finalization::Synchronize { target_user: 1002 }.encode(),
            ),
            (
                share::PDU_TYPE2_CONTROL,
                finalization::Control::new(finalization::CTRLACTION_COOPERATE).encode(),
            ),
            (
                share::PDU_TYPE2_CONTROL,
                finalization::Control::new(finalization::CTRLACTION_REQUEST_CONTROL).encode(),
            ),
            (share::PDU_TYPE2_FONT_LIST, finalization::encode_font_list()),
        ];
        for (pdu_type2, body) in batch {
            expected.push(Action::WriteBytes(frame_io(&share::encode_share_data(
                1007,
                SHARE_ID,
                share::STREAM_MED,
                pdu_type2,
                &body,
            ))));
        }
        expected
    }

    /// Frame a client I/O payload the way the machine does (user 1007, I/O channel 1003).
    fn frame_io(payload: &[u8]) -> Vec<u8> {
        tpkt::encode(&x224::encode_data(&mcs::encode_send_data_request(
            1007, 1003, payload,
        )))
    }

    /// A server Share Data PDU on the synthetic share.
    fn server_share_data(pdu_type2: u8, body: &[u8]) -> Vec<u8> {
        share::encode_share_data(1002, SHARE_ID, share::STREAM_MED, pdu_type2, body)
    }

    /// Past licensing (short-circuit), awaiting Demand Active.
    fn capability_waiting() -> ConnectStateMachine {
        let mut sm = licensing();
        let actions = sm.process(Event::Received(&server_io_frame(&license_alert(
            license::STATUS_VALID_CLIENT,
        ))));
        assert!(actions.is_empty(), "the short-circuit produces no output");
        sm
    }

    /// Past Demand Active: Confirm Active + finalization batch sent, awaiting Font Map.
    fn finalizing() -> ConnectStateMachine {
        let mut sm = capability_waiting();
        let actions = sm.process(Event::Received(&server_io_frame(&server_demand_active(
            1920, 1080,
        ))));
        assert_eq!(actions, expected_confirm_and_batch(1920, 1080));
        sm
    }

    /// Through the Font Map into session-active; returns the machine and the result.
    fn session_active() -> (ConnectStateMachine, ActivationResult) {
        let mut sm = finalizing();
        // The server's own finalization replies, in the usual order.
        for (pdu_type2, body) in [
            (
                share::PDU_TYPE2_SYNCHRONIZE,
                finalization::Synchronize { target_user: 1007 }.encode(),
            ),
            (
                share::PDU_TYPE2_CONTROL,
                finalization::Control {
                    action: finalization::CTRLACTION_COOPERATE,
                    grant_id: 0,
                    control_id: 0,
                }
                .encode(),
            ),
            (
                share::PDU_TYPE2_CONTROL,
                finalization::Control {
                    action: finalization::CTRLACTION_GRANTED_CONTROL,
                    grant_id: 1007,
                    control_id: 1002,
                }
                .encode(),
            ),
        ] {
            let actions =
                sm.process(Event::Received(&server_io_frame(&server_share_data(
                    pdu_type2, &body,
                ))));
            assert!(actions.is_empty(), "server finalization replies produce no output");
        }
        let actions = sm.process(Event::Received(&server_io_frame(&server_share_data(
            share::PDU_TYPE2_FONT_MAP,
            &[0, 0, 0, 0, 3, 0, 4, 0],
        ))));
        match actions.as_slice() {
            [Action::SessionActive { result }] => (sm, result.clone()),
            other => panic!("expected SessionActive after Font Map, got {other:?}"),
        }
    }

    #[test]
    fn licensing_error_with_total_abort_fails_typed() {
        let mut sm = licensing();
        // ERR_NO_LICENSE (0x02) + ST_TOTAL_ABORT: the server refuses and aborts the exchange
        // (MS-RDPELE 2.2.2.7) — no license, no session.
        let actions = sm.process(Event::Received(&server_io_frame(&license_alert_with(
            0x02,
            license::ST_TOTAL_ABORT,
        ))));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::LicensingFailed { error_code: 0x02 })]
        );
    }

    #[test]
    fn licensing_error_with_no_transition_advances_like_a_grace_period_server() {
        // A grace-period server reports an error code yet declares the exchange over
        // (ST_NO_TRANSITION) and proceeds to Demand Active — the client must advance, not
        // fail (the spec's "terminal License Error" clause; FreeRDP-compatible).
        let mut sm = licensing();
        let actions = sm.process(Event::Received(&server_io_frame(&license_alert_with(
            0x02,
            license::ST_NO_TRANSITION,
        ))));
        assert!(actions.is_empty(), "exchange-ending alert produces no output");

        let actions = sm.process(Event::Received(&server_io_frame(&server_demand_active(
            1920, 1080,
        ))));
        assert_eq!(actions, expected_confirm_and_batch(1920, 1080));
    }

    #[test]
    fn licensing_requires_the_license_security_flag() {
        let mut sm = licensing();
        // A well-formed share PDU where a licensing message must be: sequence desync.
        let actions = sm.process(Event::Received(&server_io_frame(&server_demand_active(
            800, 600,
        ))));
        assert!(
            matches!(
                actions.as_slice(),
                [Action::FailWith(ConnectError::Decode(_))]
            ),
            "got {actions:?}"
        );
    }

    #[test]
    fn full_license_negotiation_answers_request_challenge_and_accepts_grant() {
        let mut sm = licensing();

        // 1. Server License Request → the machine answers with a New License Request built
        //    from the caller's entropy and the certificate's RSA key — byte-exact.
        let actions =
            sm.process(Event::Received(&server_io_frame(&server_license_request())));
        let encrypted_premaster =
            license_crypto::encrypt_premaster_secret(&[0x22; 48], &TEST_MODULUS, 65537);
        let expected = license::encode_new_license_request(
            license::PLATFORM_ID_NT_POST_52_MICROSOFT,
            &[0x11; 32],
            &encrypted_premaster,
            "sm-user",
            "sm-test",
        );
        assert_eq!(actions, vec![Action::WriteBytes(frame_io(&expected))]);

        // 2. Platform Challenge (RC4 + MAC under the derived keys) → byte-exact response.
        let keys = test_license_keys();
        let challenge_plain = b"TEST-CHALLENGE\0";
        let mut challenge_body = Vec::new();
        challenge_body.extend_from_slice(&0u32.to_le_bytes()); // ConnectFlags
        let encrypted = license_crypto::rc4(&keys.license_key, challenge_plain);
        challenge_body.extend_from_slice(&0x0009u16.to_le_bytes());
        challenge_body.extend_from_slice(&(encrypted.len() as u16).to_le_bytes());
        challenge_body.extend_from_slice(&encrypted);
        challenge_body.extend_from_slice(&license_crypto::mac_data(
            &keys.mac_salt,
            challenge_plain,
        ));
        let actions = sm.process(Event::Received(&server_io_frame(&license_message(
            license::MSG_PLATFORM_CHALLENGE,
            &challenge_body,
        ))));

        let mut response = Vec::new();
        response.extend_from_slice(&0x0100u16.to_le_bytes());
        response.extend_from_slice(&0xFF00u16.to_le_bytes());
        response.extend_from_slice(&0x0003u16.to_le_bytes());
        response.extend_from_slice(&(challenge_plain.len() as u16).to_le_bytes());
        response.extend_from_slice(challenge_plain);
        let mut hwid = Vec::new();
        hwid.extend_from_slice(&license::PLATFORM_ID_NT_POST_52_MICROSOFT.to_le_bytes());
        for word in [1u32, 2, 3, 4] {
            hwid.extend_from_slice(&word.to_le_bytes());
        }
        let expected = license::encode_platform_challenge_response(
            &license_crypto::rc4(&keys.license_key, &response),
            &license_crypto::rc4(&keys.license_key, &hwid),
            &license_crypto::mac_data(&keys.mac_salt, &[&response[..], &hwid].concat()),
        );
        assert_eq!(actions, vec![Action::WriteBytes(frame_io(&expected))]);

        // 3. New License (MAC-verified) ends the exchange; the machine is now waiting for
        //    Demand Active and handles it normally.
        let license_plain = b"LICENSE-BLOB";
        let mut grant = Vec::new();
        let encrypted = license_crypto::rc4(&keys.license_key, license_plain);
        grant.extend_from_slice(&0x0009u16.to_le_bytes());
        grant.extend_from_slice(&(encrypted.len() as u16).to_le_bytes());
        grant.extend_from_slice(&encrypted);
        grant.extend_from_slice(&license_crypto::mac_data(&keys.mac_salt, license_plain));
        let actions = sm.process(Event::Received(&server_io_frame(&license_message(
            license::MSG_NEW_LICENSE,
            &grant,
        ))));
        assert!(actions.is_empty());

        let actions = sm.process(Event::Received(&server_io_frame(&server_demand_active(
            1920, 1080,
        ))));
        assert_eq!(actions, expected_confirm_and_batch(1920, 1080));
    }

    #[test]
    fn platform_challenge_with_a_bad_mac_fails_typed() {
        let mut sm = licensing();
        sm.process(Event::Received(&server_io_frame(&server_license_request())));

        let keys = test_license_keys();
        let mut challenge_body = Vec::new();
        challenge_body.extend_from_slice(&0u32.to_le_bytes());
        let encrypted = license_crypto::rc4(&keys.license_key, b"TEST-CHALLENGE\0");
        challenge_body.extend_from_slice(&0x0009u16.to_le_bytes());
        challenge_body.extend_from_slice(&(encrypted.len() as u16).to_le_bytes());
        challenge_body.extend_from_slice(&encrypted);
        challenge_body.extend_from_slice(&[0xAA; 16]); // wrong MAC
        let actions = sm.process(Event::Received(&server_io_frame(&license_message(
            license::MSG_PLATFORM_CHALLENGE,
            &challenge_body,
        ))));
        assert_eq!(
            actions,
            vec![Action::FailWith(ConnectError::LicenseMacMismatch)]
        );
    }

    #[test]
    fn deactivate_all_before_demand_active_is_discarded() {
        let mut sm = capability_waiting();
        let deactivate =
            share::encode_share_control(share::PDU_TYPE_DEACTIVATE_ALL, 1002, SHARE_ID, &[]);
        let actions = sm.process(Event::Received(&server_io_frame(&deactivate)));
        assert!(actions.is_empty(), "DeactivateAll is decoded and discarded");
        assert_eq!(sm.stage(), "capability-exchange");

        // The next Demand Active proceeds normally.
        let actions = sm.process(Event::Received(&server_io_frame(&server_demand_active(
            1024, 768,
        ))));
        assert_eq!(actions, expected_confirm_and_batch(1024, 768));
    }

    #[test]
    fn demand_active_enters_the_activation_stage() {
        let sm = finalizing();
        assert_eq!(sm.stage(), "activation");
    }

    #[test]
    fn font_map_gates_session_active_with_negotiated_results() {
        let (sm, result) = session_active();
        assert_eq!(sm.stage(), "session-active");
        assert_eq!(result.share_id, SHARE_ID);
        // The negotiated size came from the server's Bitmap set, not the 1280×800 request.
        assert_eq!(result.desktop_size, (1920, 1080));
        assert_eq!(result.server_capabilities.len(), 3);
        assert!(result.leftover.is_empty());
    }

    #[test]
    fn bytes_after_the_font_map_are_returned_as_leftover() {
        let mut sm = finalizing();
        let mut chunk = server_io_frame(&server_share_data(
            share::PDU_TYPE2_FONT_MAP,
            &[0, 0, 0, 0, 3, 0, 4, 0],
        ));
        // The server's first graphics bytes ride in the same read.
        let trailing = [0x03, 0x00, 0x00, 0x20, 0xDE, 0xAD];
        chunk.extend_from_slice(&trailing);
        let actions = sm.process(Event::Received(&chunk));
        match actions.as_slice() {
            [Action::SessionActive { result }] => assert_eq!(result.leftover, trailing),
            other => panic!("expected SessionActive, got {other:?}"),
        }
    }

    #[test]
    fn unknown_data_pdus_during_finalization_are_skipped() {
        let mut sm = finalizing();
        // Save Session Info (logon notification) interleaves here on real servers.
        let actions = sm.process(Event::Received(&server_io_frame(&server_share_data(
            share::PDU_TYPE2_SAVE_SESSION_INFO,
            &[0u8; 12],
        ))));
        assert!(actions.is_empty());
        assert_eq!(sm.stage(), "activation");
    }

    #[test]
    fn deactivate_during_finalization_reruns_capability_exchange() {
        let mut sm = finalizing();
        let deactivate =
            share::encode_share_control(share::PDU_TYPE_DEACTIVATE_ALL, 1002, SHARE_ID, &[]);
        let actions = sm.process(Event::Received(&server_io_frame(&deactivate)));
        assert!(actions.is_empty());
        assert_eq!(sm.stage(), "capability-exchange");

        let actions = sm.process(Event::Received(&server_io_frame(&server_demand_active(
            800, 600,
        ))));
        assert_eq!(actions, expected_confirm_and_batch(800, 600));
    }

    #[test]
    fn malformed_demand_active_fails_typed_not_panics() {
        let mut sm = capability_waiting();
        // A Demand Active whose capability count points past the buffer.
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes());
        body.extend_from_slice(&8u16.to_le_bytes());
        body.extend_from_slice(b"RDP\0");
        body.extend_from_slice(&9u16.to_le_bytes()); // 9 capsets, none present
        body.extend_from_slice(&0u16.to_le_bytes());
        let frame = share::encode_share_control(
            share::PDU_TYPE_DEMAND_ACTIVE,
            1002,
            SHARE_ID,
            &body,
        );
        let actions = sm.process(Event::Received(&server_io_frame(&frame)));
        assert!(
            matches!(
                actions.as_slice(),
                [Action::FailWith(ConnectError::Decode(_))]
            ),
            "got {actions:?}"
        );
    }

    #[test]
    fn malformed_license_message_fails_typed_not_panics() {
        let mut sm = licensing();
        // Truncated License Request: the server random is cut short.
        let truncated = license_message(license::MSG_LICENSE_REQUEST, &[0x5A; 10]);
        let actions = sm.process(Event::Received(&server_io_frame(&truncated)));
        assert!(
            matches!(
                actions.as_slice(),
                [Action::FailWith(ConnectError::Decode(_))]
            ),
            "got {actions:?}"
        );
    }
}
