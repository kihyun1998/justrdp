//! The RD Gateway client sequence over the HTTP transport (MS-TSGU 3.7.5.2 to 3.7.5.4), as a
//! sans-IO state machine: handshake, tunnel create with a PAA cookie, the host's answer to a
//! consent message when the gateway sends one, tunnel authorize, channel create, then the
//! target's bytes inside data packets.
//!
//! [`GatewayStateMachine::receive`] takes the bytes the gateway sent, in any split, and frames
//! them into packets by `packetLength`. [`GatewayStateMachine::send`] wraps bytes for the target.
//! The transport under it (TLS, the WebSocket upgrade and framing) is the adapter's.

use justrdp_pdu::error::DecodeError;
use justrdp_pdu::tsgu::{
    self, ChannelCreate, HandshakeRequest, Packet, PacketHeader, TunnelAuth, TunnelCreate,
    UnicodeString,
};

pub use justrdp_pdu::tsgu::PaaCookie;

/// The protocol version the handshake request sends and the handshake response has to name, as
/// (`verMajor`, `verMinor`).
const VERSION: (u8, u8) = (1, 0);

/// The `ExtendedAuth` the handshake request sends, and the flag the handshake response has to
/// carry: PAA.
const EXTENDED_AUTH: u16 = tsgu::HTTP_EXTENDED_AUTH_PAA;

/// The `capsFlags` the tunnel create advertises (MS-TSGU 2.2.5.3.9): consent messaging.
pub const ADVERTISED_CAPS: u32 = tsgu::HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN;

/// The longest packet the gateway may send: an `HTTP_TUNNEL_RESPONSE` whose `serverCert` and
/// `consentMsg` are both 65,535 bytes.
pub const MAX_PACKET_LEN: usize = 131_116;

/// The most bytes one data packet carries: `cbDataLen` is a `u16` (MS-TSGU 2.2.10.6).
pub const MAX_DATA_LEN: usize = 65_535;

/// The stage label while the handshake response is awaited.
pub const STAGE_HANDSHAKE: &str = "gateway-handshake";
/// The stage label while the tunnel response is awaited.
pub const STAGE_TUNNEL_CREATE: &str = "gateway-tunnel-create";
/// The stage label while the tunnel authorization response is awaited.
pub const STAGE_TUNNEL_AUTH: &str = "gateway-tunnel-auth";
/// The stage label while the channel response is awaited.
pub const STAGE_CHANNEL_CREATE: &str = "gateway-channel-create";
/// The stage label once the Gateway Channel is open.
pub const STAGE_CHANNEL_OPEN: &str = "gateway-channel-open";

/// What the gateway sequence needs from the host. Its `Debug` prints the cookie's length and
/// never its bytes.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// The PAA cookie the host obtained for this gateway.
    pub paa_cookie: PaaCookie,
    /// The target server's name, as the gateway resolves it.
    pub target_host: String,
    /// The target server's port.
    pub target_port: u16,
    /// The client's name, sent in the tunnel authorization.
    pub client_name: String,
}

/// A [`GatewayConfig`] whose field does not fit its length prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfigError(tsgu::EncodeError);

impl core::fmt::Display for GatewayConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "the gateway config cannot be sent: {}", self.0)
    }
}

impl core::error::Error for GatewayConfigError {}

/// What the gateway granted with the Gateway Channel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayChannel {
    /// `tunnelId` of the tunnel response.
    pub tunnel_id: Option<u32>,
    /// `channelId` of the channel response.
    pub channel_id: Option<u32>,
    /// `capsFlags` of the tunnel response: the capabilities the gateway negotiated, as received,
    /// which can hold bits outside [`ADVERTISED_CAPS`].
    pub negotiated_caps: Option<u32>,
    /// `redirFlags` of the tunnel authorization response: the device redirections the gateway's
    /// policy allows, as `HTTP_TUNNEL_REDIR_*` flags (MS-TSGU 2.2.5.3.7).
    pub redir_flags: Option<u32>,
    /// `idleTimeout` of the tunnel authorization response, in minutes. `None` unless the gateway
    /// negotiated `HTTP_CAPABILITY_IDLE_TIMEOUT`. The timer is the client's (MS-TSGU 3.5.2.1) and
    /// nothing here runs it.
    pub idle_timeout_minutes: Option<u32>,
}

/// Why the gateway sequence failed, and the stage it was in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayError {
    /// The stage label, one of the `STAGE_*` constants.
    pub stage: &'static str,
    /// What went wrong.
    pub kind: GatewayErrorKind,
}

/// What went wrong in a gateway stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayErrorKind {
    /// The gateway answered the stage's request with a non-zero `errorCode` or `statusCode`.
    Refused {
        /// The code, an HRESULT.
        code: u32,
    },
    /// A packet declared a `packetLength` over [`MAX_PACKET_LEN`].
    PacketTooLong {
        /// The declared `packetLength`.
        packet_length: u32,
    },
    /// A packet arrived that the stage does not admit.
    UnexpectedPacket {
        /// Its `packetType`.
        packet_type: u16,
    },
    /// A packet did not decode.
    Decode(DecodeError),
    /// Bytes were handed to [`GatewayStateMachine::send`] while the Gateway Channel was not open.
    ChannelNotOpen,
    /// The host declined the gateway's consent message
    /// ([`GatewayStateMachine::decline_consent`]).
    ConsentDeclined,
    /// The handshake response named a version other than 1.0, the one this client sends.
    VersionMismatch {
        /// `verMajor` of the handshake response.
        major: u8,
        /// `verMinor` of the handshake response.
        minor: u8,
    },
    /// The handshake response's `ExtendedAuth` lacks `HTTP_EXTENDED_AUTH_PAA`, the one
    /// authentication this client asks for.
    PaaNotOffered {
        /// `ExtendedAuth` of the handshake response, `HTTP_EXTENDED_AUTH_*` flags.
        extended_auth: u16,
    },
}

impl core::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.stage, self.kind)
    }
}

impl core::fmt::Display for GatewayErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GatewayErrorKind::Refused { code } => {
                write!(f, "the gateway refused with code {code:#010x}")
            }
            GatewayErrorKind::PacketTooLong { packet_length } => write!(
                f,
                "a packet declares {packet_length} bytes, over the {MAX_PACKET_LEN}-byte limit"
            ),
            GatewayErrorKind::UnexpectedPacket { packet_type } => {
                write!(f, "unexpected packet type {packet_type:#x}")
            }
            GatewayErrorKind::Decode(e) => write!(f, "{e}"),
            GatewayErrorKind::ChannelNotOpen => f.write_str("the gateway channel is not open"),
            GatewayErrorKind::ConsentDeclined => {
                f.write_str("the gateway's consent message was declined")
            }
            GatewayErrorKind::VersionMismatch { major, minor } => write!(
                f,
                "the gateway answered version {major}.{minor}, not {}.{}",
                VERSION.0, VERSION.1
            ),
            GatewayErrorKind::PaaNotOffered { extended_auth } => write!(
                f,
                "the gateway's ExtendedAuth {extended_auth:#06x} does not offer PAA"
            ),
        }
    }
}

impl core::error::Error for GatewayError {}

/// What the adapter does next. Its `Debug` prints the length of bytes and of text, never their
/// content: the tunnel create among them carries the cookie.
#[derive(Clone, PartialEq, Eq)]
pub enum GatewayAction {
    /// Send these packets to the gateway.
    WriteBytes(Vec<u8>),
    /// The gateway's tunnel response carried a consent message (MS-TSGU 2.2.10.21). The
    /// sequence waits until the host answers with [`GatewayStateMachine::accept_consent`] or
    /// [`GatewayStateMachine::decline_consent`].
    ConsentRequested {
        /// The message the gateway's administrator set: the `consentMsg` text up to its first
        /// NUL, with an unpaired surrogate as U+FFFD. It may be empty, and it is otherwise
        /// unchecked: control characters are kept.
        message: String,
    },
    /// The Gateway Channel is open: bytes for the target go through
    /// [`GatewayStateMachine::send`] from here on.
    ChannelOpen(GatewayChannel),
    /// Bytes the target sent.
    Data(Vec<u8>),
    /// The Gateway Channel is closed. Nothing more arrives and nothing more may be sent.
    Closed {
        /// The `statusCode` of the gateway's close packet, an HRESULT.
        status_code: u32,
    },
    /// The sequence failed. Nothing more arrives and nothing more may be sent.
    FailWith(GatewayError),
}

impl core::fmt::Debug for GatewayAction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GatewayAction::WriteBytes(bytes) => f
                .debug_struct("WriteBytes")
                .field("len", &bytes.len())
                .finish(),
            GatewayAction::ConsentRequested { message } => f
                .debug_struct("ConsentRequested")
                .field("len", &message.len())
                .finish(),
            GatewayAction::ChannelOpen(channel) => {
                f.debug_tuple("ChannelOpen").field(channel).finish()
            }
            GatewayAction::Data(bytes) => {
                f.debug_struct("Data").field("len", &bytes.len()).finish()
            }
            GatewayAction::Closed { status_code } => f
                .debug_struct("Closed")
                .field("status_code", status_code)
                .finish(),
            GatewayAction::FailWith(error) => f.debug_tuple("FailWith").field(error).finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Handshake,
    TunnelCreate,
    /// The tunnel response carried a consent message and the host has not answered it.
    Consent,
    TunnelAuth,
    ChannelCreate,
    Open,
    /// The client sent its close packet and awaits the gateway's response.
    Closing,
    Closed,
    Failed,
}

/// The RD Gateway client sequence. Its `Debug` prints the stage only, since the requests it
/// holds carry the cookie.
pub struct GatewayStateMachine {
    state: State,
    stage: &'static str,
    tunnel_create: Vec<u8>,
    tunnel_auth: Vec<u8>,
    channel_create: Vec<u8>,
    /// Received bytes that do not yet make a whole packet.
    inbox: Vec<u8>,
    channel: GatewayChannel,
}

impl core::fmt::Debug for GatewayStateMachine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GatewayStateMachine")
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

impl GatewayStateMachine {
    /// A machine for `config`, or the field of it that does not fit its length prefix.
    pub fn new(config: GatewayConfig) -> Result<Self, GatewayConfigError> {
        let tunnel_create = Packet::TunnelCreate(TunnelCreate {
            caps_flags: ADVERTISED_CAPS,
            reauth_tunnel_context: None,
            paa_cookie: Some(config.paa_cookie),
        })
        .encode()
        .map_err(GatewayConfigError)?;
        let tunnel_auth = Packet::TunnelAuth(TunnelAuth {
            client_name: UnicodeString::from_str_nul(&config.client_name),
            statement_of_health: None,
        })
        .encode()
        .map_err(GatewayConfigError)?;
        let channel_create = Packet::ChannelCreate(ChannelCreate {
            resources: vec![UnicodeString::from_str_nul(&config.target_host)],
            alt_resources: Vec::new(),
            port: config.target_port,
            protocol: 3,
        })
        .encode()
        .map_err(GatewayConfigError)?;
        Ok(Self {
            state: State::Handshake,
            stage: STAGE_HANDSHAKE,
            tunnel_create,
            tunnel_auth,
            channel_create,
            inbox: Vec::new(),
            channel: GatewayChannel::default(),
        })
    }

    /// The current stage label. After a failure or a close it stays the stage that ended.
    pub fn stage(&self) -> &'static str {
        self.stage
    }

    /// Whether the Gateway Channel is open.
    pub fn is_open(&self) -> bool {
        self.state == State::Open
    }

    /// The handshake request that opens the sequence.
    pub fn start(&mut self) -> Vec<GatewayAction> {
        let request = Packet::HandshakeRequest(HandshakeRequest {
            ver_major: VERSION.0,
            ver_minor: VERSION.1,
            client_version: 0,
            extended_auth: EXTENDED_AUTH,
        });
        vec![GatewayAction::WriteBytes(encode_fixed(&request))]
    }

    /// Take bytes the gateway sent, in any split, and act on every whole packet in them.
    pub fn receive(&mut self, bytes: &[u8]) -> Vec<GatewayAction> {
        let mut actions = Vec::new();
        if self.is_finished() {
            return actions;
        }
        let mut inbox = core::mem::take(&mut self.inbox);
        inbox.extend_from_slice(bytes);
        let mut at = 0;
        while !self.is_finished() {
            let rest = &inbox[at..];
            if rest.len() < tsgu::HEADER_LEN {
                break;
            }
            let header = match PacketHeader::decode(rest) {
                Ok(header) => header,
                Err(e) => {
                    self.fail(GatewayErrorKind::Decode(e), &mut actions);
                    break;
                }
            };
            let Some(len) = usize::try_from(header.packet_length)
                .ok()
                .filter(|len| *len <= MAX_PACKET_LEN)
            else {
                self.fail(
                    GatewayErrorKind::PacketTooLong {
                        packet_length: header.packet_length,
                    },
                    &mut actions,
                );
                break;
            };
            if rest.len() < len {
                break;
            }
            match Packet::decode_with_unread(&rest[..len]) {
                Ok((packet, unread)) => {
                    if unread != 0 {
                        tracing::debug!(
                            target: "rdg_packet",
                            packet_type = packet.packet_type(),
                            unread,
                            "a gateway packet has body bytes after its last field"
                        );
                    }
                    self.on_packet(packet, &mut actions);
                }
                Err(e) => self.fail(GatewayErrorKind::Decode(e), &mut actions),
            }
            at += len;
        }
        if !self.is_finished() {
            inbox.drain(..at);
            self.inbox = inbox;
        }
        actions
    }

    /// Wrap `data` for the target in data packets of at most [`MAX_DATA_LEN`] bytes each.
    pub fn send(&self, data: &[u8]) -> Result<Vec<u8>, GatewayError> {
        if self.state != State::Open {
            return Err(GatewayError {
                stage: self.stage,
                kind: GatewayErrorKind::ChannelNotOpen,
            });
        }
        let mut out = Vec::with_capacity(data.len() + 10 * data.len().div_ceil(MAX_DATA_LEN));
        for chunk in data.chunks(MAX_DATA_LEN) {
            out.extend_from_slice(&encode_fixed(&Packet::Data(chunk)));
        }
        Ok(out)
    }

    /// Close the Gateway Channel from the client's side (MS-TSGU 3.7.5.4): the close packet to
    /// send, or nothing when the channel is not open. Data that arrives after it is discarded.
    pub fn close(&mut self) -> Vec<GatewayAction> {
        if self.state != State::Open {
            return Vec::new();
        }
        self.state = State::Closing;
        vec![GatewayAction::WriteBytes(encode_fixed(
            &Packet::CloseChannel { status_code: 0 },
        ))]
    }

    /// The host accepts the consent message [`GatewayAction::ConsentRequested`] handed it: the
    /// tunnel authorization to send (MS-TSGU 3.7.5.2 step 6), or nothing when no consent
    /// message awaits an answer.
    pub fn accept_consent(&mut self) -> Vec<GatewayAction> {
        if self.state != State::Consent {
            return Vec::new();
        }
        vec![self.authorize_tunnel()]
    }

    /// The host declines the consent message [`GatewayAction::ConsentRequested`] handed it: the
    /// sequence fails in the tunnel create stage with [`GatewayErrorKind::ConsentDeclined`], or
    /// nothing happens when no consent message awaits an answer. No Gateway Channel exists yet,
    /// so no packet is sent; the adapter closes the connection (MS-TSGU 3.7.5.4).
    pub fn decline_consent(&mut self) -> Vec<GatewayAction> {
        let mut actions = Vec::new();
        if self.state == State::Consent {
            self.fail(GatewayErrorKind::ConsentDeclined, &mut actions);
        }
        actions
    }

    /// Enter the tunnel authorization stage; the request to send.
    fn authorize_tunnel(&mut self) -> GatewayAction {
        self.enter(State::TunnelAuth, STAGE_TUNNEL_AUTH);
        GatewayAction::WriteBytes(core::mem::take(&mut self.tunnel_auth))
    }

    fn is_finished(&self) -> bool {
        matches!(self.state, State::Closed | State::Failed)
    }

    fn fail(&mut self, kind: GatewayErrorKind, actions: &mut Vec<GatewayAction>) {
        self.state = State::Failed;
        actions.push(GatewayAction::FailWith(GatewayError {
            stage: self.stage,
            kind,
        }));
    }

    fn enter(&mut self, state: State, stage: &'static str) {
        tracing::debug!(target: "rdg_stage", stage, "entering gateway stage");
        self.state = state;
        self.stage = stage;
    }

    fn on_packet(&mut self, packet: Packet<'_>, actions: &mut Vec<GatewayAction>) {
        match (self.state, packet) {
            (_, Packet::KeepAlive) => {
                actions.push(GatewayAction::WriteBytes(encode_fixed(&Packet::KeepAlive)));
            }
            (_, Packet::Other { packet_type, body }) => {
                tracing::debug!(
                    target: "rdg_packet",
                    packet_type,
                    len = body.len(),
                    "skipping a gateway packet"
                );
            }
            (State::Handshake, Packet::HandshakeResponse(response)) => {
                if response.error_code != 0 {
                    return self.refuse(response.error_code, actions);
                }
                if (response.ver_major, response.ver_minor) != VERSION {
                    let (major, minor) = (response.ver_major, response.ver_minor);
                    return self.fail(GatewayErrorKind::VersionMismatch { major, minor }, actions);
                }
                if response.extended_auth & EXTENDED_AUTH == 0 {
                    let extended_auth = response.extended_auth;
                    return self.fail(GatewayErrorKind::PaaNotOffered { extended_auth }, actions);
                }
                if response.server_version != 0 {
                    tracing::debug!(
                        target: "rdg_handshake",
                        server_version = response.server_version,
                        "accepting a handshake response with a non-zero serverVersion"
                    );
                }
                self.enter(State::TunnelCreate, STAGE_TUNNEL_CREATE);
                actions.push(GatewayAction::WriteBytes(core::mem::take(
                    &mut self.tunnel_create,
                )));
            }
            (State::TunnelCreate, Packet::TunnelResponse(response)) => {
                if response.status_code != 0 {
                    return self.refuse(response.status_code, actions);
                }
                self.channel.tunnel_id = response.tunnel_id;
                self.channel.negotiated_caps = response.caps_flags;
                let unadvertised = response.caps_flags.unwrap_or(0) & !ADVERTISED_CAPS;
                if unadvertised != 0 {
                    tracing::debug!(
                        target: "rdg_tunnel",
                        unadvertised,
                        negotiated = response.caps_flags,
                        "accepting negotiated capsFlags the client did not advertise"
                    );
                }
                match response.consent_msg {
                    Some(consent) => {
                        self.state = State::Consent;
                        actions.push(GatewayAction::ConsentRequested {
                            message: consent.to_string_lossy(),
                        });
                    }
                    None => {
                        let request = self.authorize_tunnel();
                        actions.push(request);
                    }
                }
            }
            (State::TunnelAuth, Packet::TunnelAuthResponse(response)) => {
                if response.error_code != 0 {
                    return self.refuse(response.error_code, actions);
                }
                self.channel.redir_flags = response.redir_flags;
                let idle_negotiated = self
                    .channel
                    .negotiated_caps
                    .is_some_and(|caps| caps & tsgu::HTTP_CAPABILITY_IDLE_TIMEOUT != 0);
                self.channel.idle_timeout_minutes =
                    response.idle_timeout.filter(|_| idle_negotiated);
                self.enter(State::ChannelCreate, STAGE_CHANNEL_CREATE);
                actions.push(GatewayAction::WriteBytes(core::mem::take(
                    &mut self.channel_create,
                )));
            }
            (State::ChannelCreate, Packet::ChannelResponse(response)) => {
                if response.error_code != 0 {
                    return self.refuse(response.error_code, actions);
                }
                self.channel.channel_id = response.channel_id;
                self.enter(State::Open, STAGE_CHANNEL_OPEN);
                actions.push(GatewayAction::ChannelOpen(self.channel.clone()));
            }
            (State::Open, Packet::Data(data)) => actions.push(GatewayAction::Data(data.to_vec())),
            (State::Open, Packet::CloseChannel { status_code }) => {
                actions.push(GatewayAction::WriteBytes(encode_fixed(
                    &Packet::CloseChannelResponse { status_code: 0 },
                )));
                self.state = State::Closed;
                actions.push(GatewayAction::Closed { status_code });
            }
            (State::Closing, Packet::CloseChannelResponse { status_code }) => {
                self.state = State::Closed;
                actions.push(GatewayAction::Closed { status_code });
            }
            (State::Open | State::Closing, packet) => {
                tracing::debug!(
                    target: "rdg_packet",
                    packet_type = packet.packet_type(),
                    "skipping a gateway packet"
                );
            }
            (_, packet) => {
                let packet_type = packet.packet_type();
                self.fail(GatewayErrorKind::UnexpectedPacket { packet_type }, actions);
            }
        }
    }

    fn refuse(&mut self, code: u32, actions: &mut Vec<GatewayAction>) {
        self.fail(GatewayErrorKind::Refused { code }, actions);
    }
}

/// Encode a packet whose fields all fit their length prefixes by construction.
fn encode_fixed(packet: &Packet<'_>) -> Vec<u8> {
    packet
        .encode()
        .expect("every field of this packet fits its length prefix")
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::tsgu::{
        ChannelResponse, HandshakeResponse, TunnelAuthResponse, TunnelResponse,
    };
    use proptest::prelude::*;

    const COOKIE: &str = "tok";

    fn config() -> GatewayConfig {
        GatewayConfig {
            paa_cookie: PaaCookie::from_token(COOKIE),
            target_host: "srv".to_string(),
            target_port: 3389,
            client_name: "pc".to_string(),
        }
    }

    /// The handshake request with the `extendedAuth` mstsc sends for PAA (#613).
    const HANDSHAKE_REQUEST: [u8; 14] = [
        0x01, 0x00, // packetType PKT_TYPE_HANDSHAKE_REQUEST
        0x00, 0x00, // reserved
        0x0E, 0x00, 0x00, 0x00, // packetLength 14
        0x01, // verMajor
        0x00, // verMinor
        0x00, 0x00, // clientVersion
        0x02, 0x00, // ExtendedAuth HTTP_EXTENDED_AUTH_PAA
    ];

    /// The tunnel create for the cookie "tok": what mstsc sends (#613) except `capsFlags`, which
    /// is `HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN` where mstsc sends 0x3f. `fieldsPresent` 0x1,
    /// the cookie as UTF-16LE with a NUL.
    const TUNNEL_CREATE: [u8; 26] = [
        0x04, 0x00, // packetType PKT_TYPE_TUNNEL_CREATE
        0x00, 0x00, // reserved
        0x1A, 0x00, 0x00, 0x00, // packetLength 26
        0x04, 0x00, 0x00, 0x00, // capsFlags HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN
        0x01, 0x00, // fieldsPresent HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE
        0x00, 0x00, // reserved
        0x08, 0x00, // cbLen
        b't', 0x00, b'o', 0x00, b'k', 0x00, 0x00, 0x00, // "tok\0"
    ];

    /// MS-TSGU 2.2.10.14 for the client name "pc", without a statement of health.
    const TUNNEL_AUTH: [u8; 18] = [
        0x06, 0x00, // packetType PKT_TYPE_TUNNEL_AUTH
        0x00, 0x00, // reserved
        0x12, 0x00, 0x00, 0x00, // packetLength 18
        0x00, 0x00, // fieldsPresent
        0x06, 0x00, // cbClientName
        b'p', 0x00, b'c', 0x00, 0x00, 0x00, // "pc\0"
    ];

    /// MS-TSGU 2.2.10.2 for the target "srv" on port 3389.
    const CHANNEL_CREATE: [u8; 24] = [
        0x08, 0x00, // packetType PKT_TYPE_CHANNEL_CREATE
        0x00, 0x00, // reserved
        0x18, 0x00, 0x00, 0x00, // packetLength 24
        0x01, // numResources
        0x00, // numAltResources
        0x3D, 0x0D, // port 3389
        0x03, 0x00, // protocol
        0x08, 0x00, // cbLen
        b's', 0x00, b'r', 0x00, b'v', 0x00, 0x00, 0x00, // "srv\0"
    ];

    fn handshake_response(error_code: u32) -> Vec<u8> {
        Packet::HandshakeResponse(HandshakeResponse {
            error_code,
            ver_major: 1,
            ver_minor: 0,
            server_version: 0,
            extended_auth: tsgu::HTTP_EXTENDED_AUTH_PAA,
        })
        .encode()
        .unwrap()
    }

    fn handshake_response_answering(ver_major: u8, ver_minor: u8, extended_auth: u16) -> Vec<u8> {
        Packet::HandshakeResponse(HandshakeResponse {
            error_code: 0,
            ver_major,
            ver_minor,
            server_version: 0,
            extended_auth,
        })
        .encode()
        .unwrap()
    }

    fn tunnel_response(status_code: u32) -> Vec<u8> {
        Packet::TunnelResponse(TunnelResponse {
            server_version: 0,
            status_code,
            tunnel_id: Some(7),
            caps_flags: Some(tsgu::HTTP_CAPABILITY_IDLE_TIMEOUT),
            soh_request: None,
            consent_msg: None,
        })
        .encode()
        .unwrap()
    }

    fn tunnel_auth_response(error_code: u32) -> Vec<u8> {
        Packet::TunnelAuthResponse(TunnelAuthResponse {
            error_code,
            redir_flags: Some(tsgu::HTTP_TUNNEL_REDIR_DISABLE_DRIVE),
            idle_timeout: Some(30),
            soh_response: None,
        })
        .encode()
        .unwrap()
    }

    fn channel_response(error_code: u32) -> Vec<u8> {
        Packet::ChannelResponse(ChannelResponse {
            error_code,
            channel_id: Some(9),
            udp_port: None,
            authn_cookie: None,
        })
        .encode()
        .unwrap()
    }

    fn data_packet(data: &[u8]) -> Vec<u8> {
        Packet::Data(data).encode().unwrap()
    }

    fn write(bytes: &[u8]) -> GatewayAction {
        GatewayAction::WriteBytes(bytes.to_vec())
    }

    fn granted() -> GatewayChannel {
        GatewayChannel {
            tunnel_id: Some(7),
            channel_id: Some(9),
            negotiated_caps: Some(tsgu::HTTP_CAPABILITY_IDLE_TIMEOUT),
            redir_flags: Some(tsgu::HTTP_TUNNEL_REDIR_DISABLE_DRIVE),
            idle_timeout_minutes: Some(30),
        }
    }

    /// A machine driven to an open Gateway Channel.
    fn open_machine() -> GatewayStateMachine {
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        machine.receive(&handshake_response(0));
        machine.receive(&tunnel_response(0));
        machine.receive(&tunnel_auth_response(0));
        let actions = machine.receive(&channel_response(0));
        assert_eq!(actions, [GatewayAction::ChannelOpen(granted())]);
        machine
    }

    #[test]
    fn the_sequence_sends_each_request_after_the_response_before_it() {
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        assert_eq!(machine.stage(), STAGE_HANDSHAKE);
        assert_eq!(machine.start(), [write(&HANDSHAKE_REQUEST)]);

        assert_eq!(
            machine.receive(&handshake_response(0)),
            [write(&TUNNEL_CREATE)]
        );
        assert_eq!(machine.stage(), STAGE_TUNNEL_CREATE);

        assert_eq!(machine.receive(&tunnel_response(0)), [write(&TUNNEL_AUTH)]);
        assert_eq!(machine.stage(), STAGE_TUNNEL_AUTH);

        assert_eq!(
            machine.receive(&tunnel_auth_response(0)),
            [write(&CHANNEL_CREATE)]
        );
        assert_eq!(machine.stage(), STAGE_CHANNEL_CREATE);
        assert!(!machine.is_open());

        assert_eq!(
            machine.receive(&channel_response(0)),
            [GatewayAction::ChannelOpen(granted())]
        );
        assert_eq!(machine.stage(), STAGE_CHANNEL_OPEN);
        assert!(machine.is_open());
    }

    /// ADR-0016: the tunnel create advertises what this client handles, not mstsc's 0x3f.
    #[test]
    fn consent_signing_is_the_one_capability_advertised() {
        assert_eq!(ADVERTISED_CAPS, 0x4);
    }

    /// A negotiated `capsFlags` bit outside `ADVERTISED_CAPS` is logged with the bits seen, and
    /// the sequence goes on to the tunnel authorization with the value stored as received; no
    /// field, zero and the advertised bit alone log nothing.
    #[test]
    #[tracing_test::traced_test]
    fn negotiated_caps_outside_the_advertised_ones_are_logged_and_not_refused() {
        let response = |caps_flags| {
            Packet::TunnelResponse(TunnelResponse {
                server_version: 0,
                status_code: 0,
                tunnel_id: Some(7),
                caps_flags,
                soh_request: None,
                consent_msg: None,
            })
            .encode()
            .unwrap()
        };
        let after_tunnel = |caps_flags| {
            let mut machine = GatewayStateMachine::new(config()).unwrap();
            machine.start();
            machine.receive(&handshake_response(0));
            assert_eq!(
                machine.receive(&response(caps_flags)),
                [write(&TUNNEL_AUTH)]
            );
            assert_eq!(machine.stage(), STAGE_TUNNEL_AUTH);
            assert_eq!(machine.channel.negotiated_caps, caps_flags);
        };
        for quiet in [None, Some(0), Some(ADVERTISED_CAPS)] {
            after_tunnel(quiet);
        }
        assert!(!logs_contain("rdg_tunnel"));

        let unadvertised = tsgu::HTTP_CAPABILITY_IDLE_TIMEOUT | tsgu::HTTP_CAPABILITY_UDP_TRANSPORT;
        after_tunnel(Some(ADVERTISED_CAPS | unadvertised));
        let expected = format!("unadvertised={unadvertised}");
        logs_assert(|lines: &[&str]| {
            match lines
                .iter()
                .filter(|l| l.contains("rdg_tunnel") && l.contains(&expected))
                .count()
            {
                1 => Ok(()),
                n => Err(format!("expected one rdg_tunnel record, found {n}")),
            }
        });
    }

    /// A tunnel response that carries `text` as its consent message.
    fn tunnel_response_with_consent(text: &str) -> Vec<u8> {
        Packet::TunnelResponse(TunnelResponse {
            server_version: 0,
            status_code: 0,
            tunnel_id: Some(7),
            caps_flags: Some(
                tsgu::HTTP_CAPABILITY_IDLE_TIMEOUT | tsgu::HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN,
            ),
            soh_request: None,
            consent_msg: Some(UnicodeString::from_str_nul(text)),
        })
        .encode()
        .unwrap()
    }

    /// A machine that received a consent message and awaits the host's answer.
    fn machine_awaiting_consent() -> GatewayStateMachine {
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        machine.receive(&handshake_response(0));
        assert_eq!(
            machine.receive(&tunnel_response_with_consent("Agree?")),
            [GatewayAction::ConsentRequested {
                message: "Agree?".to_string(),
            }]
        );
        machine
    }

    /// MS-TSGU 3.7.5.2 step 5: the consent message goes to the host, and the tunnel
    /// authorization is not sent until the host accepts.
    #[test]
    fn a_consent_message_holds_the_sequence_until_the_host_accepts() {
        let mut machine = machine_awaiting_consent();
        assert_eq!(machine.stage(), STAGE_TUNNEL_CREATE);
        assert_eq!(machine.receive(&[]), [], "nothing is sent while it waits");

        assert_eq!(machine.accept_consent(), [write(&TUNNEL_AUTH)]);
        assert_eq!(machine.stage(), STAGE_TUNNEL_AUTH);
        assert_eq!(machine.accept_consent(), [], "the answer is taken once");
        assert_eq!(machine.decline_consent(), []);

        assert_eq!(
            machine.receive(&tunnel_auth_response(0)),
            [write(&CHANNEL_CREATE)]
        );
        assert_eq!(
            machine.receive(&channel_response(0)),
            [GatewayAction::ChannelOpen(GatewayChannel {
                negotiated_caps: Some(
                    tsgu::HTTP_CAPABILITY_IDLE_TIMEOUT
                        | tsgu::HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN
                ),
                ..granted()
            })]
        );
    }

    #[test]
    fn declining_the_consent_message_fails_the_tunnel_create() {
        let mut machine = machine_awaiting_consent();
        assert_eq!(
            machine.decline_consent(),
            [GatewayAction::FailWith(GatewayError {
                stage: STAGE_TUNNEL_CREATE,
                kind: GatewayErrorKind::ConsentDeclined,
            })]
        );
        assert_eq!(machine.stage(), STAGE_TUNNEL_CREATE);
        assert_eq!(
            machine.accept_consent(),
            [],
            "a declined tunnel stays ended"
        );
        assert_eq!(machine.decline_consent(), []);
        assert_eq!(machine.receive(&tunnel_auth_response(0)), []);
    }

    /// An answer no consent message asked for does nothing, in every other state.
    #[test]
    fn a_consent_answer_nothing_asked_for_is_ignored() {
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        assert_eq!(machine.accept_consent(), []);
        assert_eq!(machine.decline_consent(), []);
        assert_eq!(machine.stage(), STAGE_HANDSHAKE);
        assert_eq!(
            machine.receive(&handshake_response(0)),
            [write(&TUNNEL_CREATE)],
            "the sequence carries on"
        );

        let mut machine = open_machine();
        assert_eq!(machine.accept_consent(), []);
        assert_eq!(machine.decline_consent(), []);
        assert!(machine.is_open());
    }

    #[test]
    fn a_keep_alive_is_answered_while_consent_is_awaited_and_a_response_is_not_admitted() {
        let keep_alive = Packet::KeepAlive.encode().unwrap();
        let mut machine = machine_awaiting_consent();
        assert_eq!(machine.receive(&keep_alive), [write(&keep_alive)]);
        assert_eq!(
            machine.receive(&tunnel_auth_response(0)),
            [GatewayAction::FailWith(GatewayError {
                stage: STAGE_TUNNEL_CREATE,
                kind: GatewayErrorKind::UnexpectedPacket {
                    packet_type: tsgu::PKT_TYPE_TUNNEL_AUTH_RESPONSE,
                },
            })]
        );
        assert_eq!(machine.accept_consent(), []);
    }

    /// A consent message that is present and empty is still the host's to answer.
    #[test]
    fn an_empty_consent_message_is_still_handed_to_the_host() {
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        machine.receive(&handshake_response(0));
        let empty = Packet::TunnelResponse(TunnelResponse {
            server_version: 0,
            status_code: 0,
            tunnel_id: Some(7),
            caps_flags: None,
            soh_request: None,
            consent_msg: Some(UnicodeString::from_bytes(Vec::new())),
        })
        .encode()
        .unwrap();
        assert_eq!(
            machine.receive(&empty),
            [GatewayAction::ConsentRequested {
                message: String::new(),
            }]
        );
    }

    /// A refused tunnel create has no consent message to answer, whatever its fields say.
    #[test]
    fn a_refused_tunnel_response_asks_for_no_consent() {
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        machine.receive(&handshake_response(0));
        let refused = Packet::TunnelResponse(TunnelResponse {
            server_version: 0,
            status_code: 0x8007_59E9,
            tunnel_id: None,
            caps_flags: None,
            soh_request: None,
            consent_msg: Some(UnicodeString::from_str_nul("Agree?")),
        })
        .encode()
        .unwrap();
        assert_eq!(
            machine.receive(&refused),
            [GatewayAction::FailWith(GatewayError {
                stage: STAGE_TUNNEL_CREATE,
                kind: GatewayErrorKind::Refused { code: 0x8007_59E9 },
            })]
        );
    }

    /// What the RD Gateway role of Windows Server 2019 sent a client whose tunnel create
    /// advertised no capability (#613): a handshake response with `ExtendedAuth` 0x7, then a
    /// tunnel response with `statusCode` `E_PROXY_CAPABILITYMISMATCH` and no optional field.
    const WS2019_REFUSAL_OF_NO_CAPABILITY: [u8; 36] = [
        0x02, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00,
        0x00, // PKT_TYPE_HANDSHAKE_RESPONSE, 18 bytes
        0x00, 0x00, 0x00, 0x00, // errorCode
        0x01, 0x00, 0x00, 0x00, // version 1.0, serverVersion 0
        0x07, 0x00, // ExtendedAuth
        0x05, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, // PKT_TYPE_TUNNEL_RESPONSE, 18 bytes
        0x00, 0x00, // serverVersion
        0xE9, 0x59, 0x07, 0x80, // statusCode 0x800759E9
        0x00, 0x00, // fieldsPresent
        0x00, 0x00, // reserved
    ];

    /// Each packet of the Windows Server 2019 refusal fills its `packetLength` exactly.
    #[test]
    fn the_windows_gateway_packets_leave_no_body_byte_unread() {
        let (handshake, tunnel) = WS2019_REFUSAL_OF_NO_CAPABILITY.split_at(18);
        for packet in [handshake, tunnel] {
            assert_eq!(Packet::decode_with_unread(packet).unwrap().1, 0);
        }
    }

    /// Body bytes after a packet's last field are logged with the packet type and their count,
    /// and the packet is acted on as without them; exact packets, the Windows gateway's among
    /// them, log nothing.
    #[test]
    #[tracing_test::traced_test]
    fn trailing_body_bytes_are_logged_and_not_refused() {
        let padded = |bytes: &[u8], n: usize| {
            let mut out = bytes.to_vec();
            out.resize(bytes.len() + n, 0);
            out[4..8].copy_from_slice(&u32::try_from(bytes.len() + n).unwrap().to_le_bytes());
            out
        };
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        machine.receive(&WS2019_REFUSAL_OF_NO_CAPABILITY);
        let mut machine = open_machine();
        assert_eq!(
            machine.receive(&data_packet(b"x")),
            [GatewayAction::Data(b"x".to_vec())]
        );
        assert!(!logs_contain("unread="));

        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        assert_eq!(
            machine.receive(&padded(&handshake_response(0), 3)),
            [write(&TUNNEL_CREATE)]
        );
        assert_eq!(machine.stage(), STAGE_TUNNEL_CREATE);
        let mut machine = open_machine();
        assert_eq!(
            machine.receive(&padded(&data_packet(b"x"), 2)),
            [GatewayAction::Data(b"x".to_vec())]
        );
        logs_assert(|lines: &[&str]| {
            let records: Vec<_> = lines
                .iter()
                .filter(|l| l.contains("rdg_packet") && l.contains("unread="))
                .collect();
            let expected = [
                format!("packet_type={} unread=3", tsgu::PKT_TYPE_HANDSHAKE_RESPONSE),
                format!("packet_type={} unread=2", tsgu::PKT_TYPE_DATA),
            ];
            match records.as_slice() {
                [first, second]
                    if first.contains(&expected[0]) && second.contains(&expected[1]) =>
                {
                    Ok(())
                }
                _ => Err(format!("expected {expected:?}, found {records:?}")),
            }
        });
    }

    #[test]
    fn the_refusal_a_windows_gateway_sent_names_the_tunnel_create_and_its_code() {
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        assert_eq!(
            machine.receive(&WS2019_REFUSAL_OF_NO_CAPABILITY),
            [
                write(&TUNNEL_CREATE),
                GatewayAction::FailWith(GatewayError {
                    stage: STAGE_TUNNEL_CREATE,
                    kind: GatewayErrorKind::Refused { code: 0x8007_59E9 },
                }),
            ]
        );
    }

    /// MS-TSGU 3.7.3: a gateway that answers another version gets no tunnel create, and so no
    /// cookie.
    #[test]
    fn a_handshake_response_with_another_version_fails_before_the_cookie_is_sent() {
        for (major, minor) in [(1, 1), (2, 0), (0, 0)] {
            let mut machine = GatewayStateMachine::new(config()).unwrap();
            machine.start();
            assert_eq!(
                machine.receive(&handshake_response_answering(
                    major,
                    minor,
                    tsgu::HTTP_EXTENDED_AUTH_PAA
                )),
                [GatewayAction::FailWith(GatewayError {
                    stage: STAGE_HANDSHAKE,
                    kind: GatewayErrorKind::VersionMismatch { major, minor },
                })],
                "version {major}.{minor}"
            );
            assert_eq!(machine.stage(), STAGE_HANDSHAKE);
            assert_eq!(machine.receive(&tunnel_response(0)), [], "nothing follows");
        }
    }

    /// The client asked for PAA alone; a gateway that does not offer it gets no cookie.
    #[test]
    fn a_handshake_response_without_paa_fails_before_the_cookie_is_sent() {
        let without_paa = [
            0,
            tsgu::HTTP_EXTENDED_AUTH_SC,
            tsgu::HTTP_EXTENDED_AUTH_SC | tsgu::HTTP_EXTENDED_AUTH_SSPI_NTLM,
            !tsgu::HTTP_EXTENDED_AUTH_PAA,
        ];
        for extended_auth in without_paa {
            let mut machine = GatewayStateMachine::new(config()).unwrap();
            machine.start();
            assert_eq!(
                machine.receive(&handshake_response_answering(1, 0, extended_auth)),
                [GatewayAction::FailWith(GatewayError {
                    stage: STAGE_HANDSHAKE,
                    kind: GatewayErrorKind::PaaNotOffered { extended_auth },
                })],
                "ExtendedAuth {extended_auth:#06x}"
            );
            assert_eq!(machine.stage(), STAGE_HANDSHAKE);
            assert_eq!(machine.receive(&tunnel_response(0)), [], "nothing follows");
        }
    }

    /// A refusal is reported as one whatever the version and `ExtendedAuth` beside it.
    #[test]
    fn a_refused_handshake_reports_its_code_before_any_mismatch() {
        let refused = Packet::HandshakeResponse(HandshakeResponse {
            error_code: 0x8007_59D8,
            ver_major: 0,
            ver_minor: 0,
            server_version: 0,
            extended_auth: 0,
        })
        .encode()
        .unwrap();
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        assert_eq!(
            machine.receive(&refused),
            [GatewayAction::FailWith(GatewayError {
                stage: STAGE_HANDSHAKE,
                kind: GatewayErrorKind::Refused { code: 0x8007_59D8 },
            })]
        );
    }

    /// A non-zero handshake `serverVersion` is logged with the value seen, and the sequence
    /// goes on to the tunnel create; a zero one logs nothing.
    #[test]
    #[tracing_test::traced_test]
    fn a_non_zero_handshake_server_version_is_logged_and_not_refused() {
        let response = |server_version| {
            Packet::HandshakeResponse(HandshakeResponse {
                error_code: 0,
                ver_major: 1,
                ver_minor: 0,
                server_version,
                extended_auth: tsgu::HTTP_EXTENDED_AUTH_PAA,
            })
            .encode()
            .unwrap()
        };
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        assert_eq!(machine.receive(&response(0)), [write(&TUNNEL_CREATE)]);
        assert!(!logs_contain("server_version="));

        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        assert_eq!(machine.receive(&response(0x0102)), [write(&TUNNEL_CREATE)]);
        assert_eq!(machine.stage(), STAGE_TUNNEL_CREATE);
        logs_assert(|lines: &[&str]| {
            match lines
                .iter()
                .filter(|l| l.contains("rdg_handshake") && l.contains("server_version=258"))
                .count()
            {
                1 => Ok(()),
                n => Err(format!("expected one rdg_handshake record, found {n}")),
            }
        });
    }

    /// PAA among other offers is a match: the Windows gateway of #613 answered 0x7.
    #[test]
    fn a_handshake_response_offering_paa_among_others_sends_the_cookie() {
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        assert_eq!(
            machine.receive(&handshake_response_answering(1, 0, 0x7)),
            [write(&TUNNEL_CREATE)]
        );
    }

    #[test]
    fn a_handshake_mismatch_is_displayed_with_what_the_gateway_answered() {
        let version = GatewayError {
            stage: STAGE_HANDSHAKE,
            kind: GatewayErrorKind::VersionMismatch { major: 2, minor: 0 },
        };
        assert_eq!(
            version.to_string(),
            "gateway-handshake: the gateway answered version 2.0, not 1.0"
        );
        let paa = GatewayError {
            stage: STAGE_HANDSHAKE,
            kind: GatewayErrorKind::PaaNotOffered { extended_auth: 0x5 },
        };
        assert_eq!(
            paa.to_string(),
            "gateway-handshake: the gateway's ExtendedAuth 0x0005 does not offer PAA"
        );
    }

    #[test]
    fn responses_split_at_every_byte_drive_the_same_sequence() {
        let mut stream = Vec::new();
        stream.extend(handshake_response(0));
        stream.extend(tunnel_response(0));
        stream.extend(tunnel_auth_response(0));
        stream.extend(channel_response(0));
        stream.extend(data_packet(b"hello"));

        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        let mut actions = Vec::new();
        for byte in stream {
            actions.extend(machine.receive(&[byte]));
        }
        assert_eq!(actions.len(), 5);
        assert_eq!(actions[2], write(&CHANNEL_CREATE));
        assert_eq!(actions[3], GatewayAction::ChannelOpen(granted()));
        assert_eq!(actions[4], GatewayAction::Data(b"hello".to_vec()));
    }

    #[test]
    fn several_packets_in_one_read_are_all_acted_on() {
        let mut machine = open_machine();
        let mut bytes = data_packet(b"one");
        bytes.extend(data_packet(b"two"));
        bytes.extend(&data_packet(b"three")[..5]);
        assert_eq!(
            machine.receive(&bytes),
            [
                GatewayAction::Data(b"one".to_vec()),
                GatewayAction::Data(b"two".to_vec()),
            ]
        );
        assert_eq!(
            machine.receive(&data_packet(b"three")[5..]),
            [GatewayAction::Data(b"three".to_vec())]
        );
    }

    /// Each stage's refusal names that stage and carries the gateway's code.
    #[test]
    fn a_refusal_names_the_stage_it_happened_in() {
        type Step = fn(u32) -> Vec<u8>;
        let steps: [(Step, &str); 4] = [
            (handshake_response, STAGE_HANDSHAKE),
            (tunnel_response, STAGE_TUNNEL_CREATE),
            (tunnel_auth_response, STAGE_TUNNEL_AUTH),
            (channel_response, STAGE_CHANNEL_CREATE),
        ];
        for refused_at in 0..steps.len() {
            let mut machine = GatewayStateMachine::new(config()).unwrap();
            machine.start();
            for (step, _) in &steps[..refused_at] {
                machine.receive(&step(0));
            }
            let (step, stage) = steps[refused_at];
            assert_eq!(
                machine.receive(&step(0x8007_59D8)),
                [GatewayAction::FailWith(GatewayError {
                    stage,
                    kind: GatewayErrorKind::Refused { code: 0x8007_59D8 },
                })]
            );
            assert_eq!(machine.stage(), stage);
            assert_eq!(machine.receive(&step(0)), [], "nothing follows a failure");
        }
    }

    #[test]
    fn a_response_out_of_order_fails_the_stage() {
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        assert_eq!(
            machine.receive(&tunnel_response(0)),
            [GatewayAction::FailWith(GatewayError {
                stage: STAGE_HANDSHAKE,
                kind: GatewayErrorKind::UnexpectedPacket {
                    packet_type: tsgu::PKT_TYPE_TUNNEL_RESPONSE,
                },
            })]
        );
    }

    /// The header alone refuses an over-long packet, so its body is never awaited.
    #[test]
    fn a_packet_length_over_the_limit_fails_on_its_header() {
        let mut machine = open_machine();
        let mut header = vec![0x0A, 0x00, 0x00, 0x00];
        header.extend((MAX_PACKET_LEN as u32 + 1).to_le_bytes());
        assert_eq!(
            machine.receive(&header),
            [GatewayAction::FailWith(GatewayError {
                stage: STAGE_CHANNEL_OPEN,
                kind: GatewayErrorKind::PacketTooLong {
                    packet_length: MAX_PACKET_LEN as u32 + 1,
                },
            })]
        );
    }

    /// The limit is the longest packet `tsgu` knows a layout for, and it is admitted.
    #[test]
    fn the_longest_tunnel_response_is_within_the_limit() {
        let longest = Packet::TunnelResponse(TunnelResponse {
            server_version: 0,
            status_code: 0,
            tunnel_id: Some(1),
            caps_flags: Some(0),
            soh_request: Some(tsgu::SohRequest {
                nonce: [0; 16],
                server_cert: UnicodeString::from_bytes(vec![0; 65_535]),
            }),
            consent_msg: Some(UnicodeString::from_bytes(vec![0; 65_535])),
        })
        .encode()
        .unwrap();
        assert_eq!(longest.len(), MAX_PACKET_LEN);

        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        machine.receive(&handshake_response(0));
        assert_eq!(
            machine.receive(&longest),
            [GatewayAction::ConsentRequested {
                message: String::new(),
            }]
        );
        assert_eq!(machine.accept_consent(), [write(&TUNNEL_AUTH)]);
    }

    #[test]
    fn a_packet_that_does_not_decode_fails_the_stage() {
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        // A handshake response whose packetLength covers the header alone.
        let truncated = [0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00];
        let actions = machine.receive(&truncated);
        assert!(matches!(
            actions.as_slice(),
            [GatewayAction::FailWith(GatewayError {
                stage: STAGE_HANDSHAKE,
                kind: GatewayErrorKind::Decode(DecodeError::InvalidField { .. }),
            })]
        ));
    }

    #[test]
    fn a_keep_alive_is_answered_in_every_stage() {
        let keep_alive = Packet::KeepAlive.encode().unwrap();
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        assert_eq!(machine.receive(&keep_alive), [write(&keep_alive)]);
        assert_eq!(machine.stage(), STAGE_HANDSHAKE);

        let mut machine = open_machine();
        assert_eq!(machine.receive(&keep_alive), [write(&keep_alive)]);
        assert!(machine.is_open());
    }

    /// Service messages, reauth and extended auth were not advertised; one that arrives anyway
    /// is skipped and the channel carries on.
    #[test]
    fn a_packet_type_this_client_does_not_read_is_skipped() {
        let service_message = Packet::Other {
            packet_type: tsgu::PKT_TYPE_SERVICE_MESSAGE,
            body: &[1, 2, 3],
        }
        .encode()
        .unwrap();
        let mut machine = open_machine();
        let mut bytes = service_message;
        bytes.extend(data_packet(b"after"));
        assert_eq!(
            machine.receive(&bytes),
            [GatewayAction::Data(b"after".to_vec())]
        );
    }

    #[test]
    fn data_for_the_target_is_wrapped_in_data_packets_of_at_most_65535_bytes() {
        let machine = open_machine();
        assert_eq!(machine.send(b"hi").unwrap(), data_packet(b"hi"));

        let big = vec![0xAB; MAX_DATA_LEN + 1];
        let mut expected = data_packet(&big[..MAX_DATA_LEN]);
        expected.extend(data_packet(&big[MAX_DATA_LEN..]));
        assert_eq!(machine.send(&big).unwrap(), expected);
    }

    #[test]
    fn data_is_refused_while_the_channel_is_not_open() {
        let machine = GatewayStateMachine::new(config()).unwrap();
        assert_eq!(
            machine.send(b"hi"),
            Err(GatewayError {
                stage: STAGE_HANDSHAKE,
                kind: GatewayErrorKind::ChannelNotOpen,
            })
        );
    }

    /// MS-TSGU 3.7.5.4, server-initiated: the response goes out and the channel ends.
    #[test]
    fn a_close_from_the_gateway_is_answered_and_ends_the_channel() {
        let mut machine = open_machine();
        let mut bytes = Packet::CloseChannel {
            status_code: 0x8007_59F8,
        }
        .encode()
        .unwrap();
        bytes.extend(data_packet(b"late"));
        assert_eq!(
            machine.receive(&bytes),
            [
                write(
                    &Packet::CloseChannelResponse { status_code: 0 }
                        .encode()
                        .unwrap()
                ),
                GatewayAction::Closed {
                    status_code: 0x8007_59F8
                },
            ]
        );
        assert!(!machine.is_open());
        assert!(machine.send(b"x").is_err());
        assert_eq!(machine.receive(&data_packet(b"more")), []);
    }

    /// MS-TSGU 3.7.5.4, client-initiated: data after the close is discarded until the response.
    #[test]
    fn a_close_from_the_client_discards_data_until_the_gateway_responds() {
        let mut machine = open_machine();
        assert_eq!(
            machine.close(),
            [write(
                &Packet::CloseChannel { status_code: 0 }.encode().unwrap()
            )]
        );
        assert!(machine.send(b"x").is_err());
        assert_eq!(machine.close(), [], "the close packet is sent once");
        assert_eq!(machine.receive(&data_packet(b"late")), []);
        assert_eq!(
            machine.receive(
                &Packet::CloseChannelResponse { status_code: 0 }
                    .encode()
                    .unwrap()
            ),
            [GatewayAction::Closed { status_code: 0 }]
        );
    }

    #[test]
    fn the_idle_timeout_is_reported_only_when_the_gateway_negotiated_it() {
        let mut machine = GatewayStateMachine::new(config()).unwrap();
        machine.start();
        machine.receive(&handshake_response(0));
        let without_idle = Packet::TunnelResponse(TunnelResponse {
            server_version: 0,
            status_code: 0,
            tunnel_id: Some(7),
            caps_flags: Some(0),
            soh_request: None,
            consent_msg: None,
        })
        .encode()
        .unwrap();
        machine.receive(&without_idle);
        machine.receive(&tunnel_auth_response(0));
        let actions = machine.receive(&channel_response(0));
        assert_eq!(
            actions,
            [GatewayAction::ChannelOpen(GatewayChannel {
                negotiated_caps: Some(0),
                idle_timeout_minutes: None,
                ..granted()
            })]
        );
    }

    #[test]
    fn a_cookie_longer_than_its_length_prefix_is_refused_before_anything_is_sent() {
        let error = GatewayStateMachine::new(GatewayConfig {
            paa_cookie: PaaCookie::from_bytes(vec![0; 65_536]),
            ..config()
        })
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "the gateway config cannot be sent: PAACookie is 65536 long, and its length prefix \
             admits 65535"
        );
    }

    /// The cookie's text and its UTF-16LE bytes, in the forms `Debug` could print them.
    fn assert_cookie_absent(text: &str) {
        assert!(!text.contains("secret-cookie"), "{text}");
        assert!(!text.contains("115, 0, 101, 0"), "{text}");
    }

    #[test]
    fn the_cookie_is_in_no_debug_output() {
        let config = GatewayConfig {
            paa_cookie: PaaCookie::from_token("secret-cookie"),
            ..config()
        };
        assert_cookie_absent(&format!("{config:?}"));
        let mut machine = GatewayStateMachine::new(config.clone()).unwrap();
        machine.start();
        assert_cookie_absent(&format!("{machine:?}"));
        let failed = machine.receive(&handshake_response(5));
        assert_cookie_absent(&format!("{failed:?} {machine:?}"));

        // The action that carries the tunnel create, cookie included.
        let mut machine = GatewayStateMachine::new(config).unwrap();
        machine.start();
        let tunnel_create = machine.receive(&handshake_response(0));
        assert_eq!(
            format!("{tunnel_create:?}"),
            "[WriteBytes { len: 46 }]",
            "the request is printed by its length"
        );
    }

    #[test]
    fn a_consent_message_is_printed_by_its_length() {
        let action = GatewayAction::ConsentRequested {
            message: "Agree?".to_string(),
        };
        assert_eq!(format!("{action:?}"), "ConsentRequested { len: 6 }");
    }

    /// One server packet a stage can receive, well formed.
    fn server_packet() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            any::<u32>().prop_map(|code| handshake_response(code & 1)),
            (any::<u8>(), any::<u8>(), any::<u16>()).prop_map(|(major, minor, auth)| {
                handshake_response_answering(major & 1, minor & 1, auth & 0x7)
            }),
            any::<u32>().prop_map(|code| tunnel_response(code & 1)),
            "[a-z]{0,8}".prop_map(|text| tunnel_response_with_consent(&text)),
            any::<u32>().prop_map(|code| tunnel_auth_response(code & 1)),
            any::<u32>().prop_map(|code| channel_response(code & 1)),
            proptest::collection::vec(any::<u8>(), 0..=64).prop_map(|data| data_packet(&data)),
            Just(Packet::KeepAlive.encode().unwrap()),
            any::<u32>()
                .prop_map(|status_code| { Packet::CloseChannel { status_code }.encode().unwrap() }),
            any::<u32>().prop_map(|status_code| {
                Packet::CloseChannelResponse { status_code }
                    .encode()
                    .unwrap()
            }),
        ]
    }

    /// What the gateway sends in one read: the four responses in order more often than not, then
    /// well-formed packets, some with a byte overwritten, some cut short, some arbitrary bytes.
    fn gateway_reads() -> impl Strategy<Value = Vec<Vec<u8>>> {
        let piece = prop_oneof![
            6 => server_packet(),
            2 => (server_packet(), any::<usize>(), any::<u8>()).prop_map(|(mut bytes, at, v)| {
                let at = at % bytes.len();
                bytes[at] = v;
                bytes
            }),
            1 => (server_packet(), any::<usize>()).prop_map(|(mut bytes, at)| {
                bytes.truncate(at % bytes.len());
                bytes
            }),
            1 => proptest::collection::vec(any::<u8>(), 0..=32),
        ];
        (
            any::<bool>(),
            proptest::collection::vec(piece, 0..=12),
            any::<bool>(),
        )
            .prop_map(|(opened, mut reads, split)| {
                if opened {
                    reads.splice(
                        0..0,
                        [
                            handshake_response(0),
                            tunnel_response(0),
                            tunnel_auth_response(0),
                            channel_response(0),
                        ],
                    );
                }
                if split {
                    reads = reads
                        .concat()
                        .chunks(3)
                        .map(<[u8]>::to_vec)
                        .collect::<Vec<_>>();
                }
                reads
            })
    }

    proptest! {
        // ADR-0008: every byte here is the gateway's, and so are packetLength and the order.
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// The machine never panics, never holds more than one packet's worth of bytes, and
        /// says nothing after it failed or closed. A consent answer is given after every read,
        /// asked for or not.
        #[test]
        fn receive_never_panics_and_never_buffers_past_the_limit(reads in gateway_reads()) {
            let mut machine = GatewayStateMachine::new(config()).unwrap();
            machine.start();
            let mut finished = false;
            for read in reads {
                let mut actions = machine.receive(&read);
                prop_assert!(machine.inbox.len() < MAX_PACKET_LEN);
                let asked = actions
                    .iter()
                    .any(|action| matches!(action, GatewayAction::ConsentRequested { .. }));
                let answer = if read.len() % 2 == 0 {
                    machine.accept_consent()
                } else {
                    machine.decline_consent()
                };
                prop_assert!(asked || answer.is_empty());
                actions.extend(answer);
                if finished {
                    prop_assert!(actions.is_empty());
                }
                finished |= actions.iter().any(|action| {
                    matches!(action, GatewayAction::FailWith(_) | GatewayAction::Closed { .. })
                });
                let _ = machine.send(&read);
            }
        }
    }
}
