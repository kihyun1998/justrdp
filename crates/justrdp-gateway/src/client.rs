#![forbid(unsafe_code)]

//! Sans-io `GatewayClient` state machine for MS-TSGU HTTP Transport.
//!
//! This module implements the protocol-level state machine for a
//! Remote Desktop Gateway client using the HTTP Transport variant
//! (§3.3.5 Normal Scenario). It is **transport-agnostic**: the caller
//! is responsible for the dual HTTP/TLS connections that carry the IN
//! and OUT channels, chunked transfer encoding, HTTP authentication,
//! and the 100-byte OUT channel preamble (§3.3.5.1). The state machine
//! produces and consumes MS-TSGU PDUs only.
//!
//! ## Usage
//!
//! 1. Build a [`GatewayClient`] from a [`GatewayClientConfig`].
//! 2. Drive the state machine in a loop:
//!    - If [`GatewayClient::is_send_state`] is `true`, call
//!      [`GatewayClient::step`] with an empty `input`. The encoded
//!      client PDU will be written to `output`; the caller sends it
//!      on the IN channel.
//!    - Otherwise, buffer bytes from the OUT channel until
//!      [`find_packet_size`] returns `Some(n)`, then pass the first
//!      `n` bytes to `step` as the server PDU.
//! 3. When [`GatewayClient::is_connected`] becomes `true`, the RDP
//!    payload path is open. Use [`GatewayClient::encode_data`] to
//!    wrap outbound RDP bytes and [`decode_data`] to unwrap inbound
//!    RDP bytes.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{Decode, DecodeError, Encode, EncodeError, ReadCursor, WriteBuf, WriteCursor};

use crate::pdu::{
    ChannelCreatePdu, ChannelResponsePdu, CloseChannelPdu, DataPdu, HandshakeRequestPdu,
    HandshakeResponsePdu, HttpByteBlob, TunnelAuthPdu, TunnelAuthResponsePdu, TunnelCreatePdu,
    TunnelResponsePdu, E_PROXY_QUARANTINE_ACCESSDENIED, ERROR_GRACEFUL_DISCONNECT,
    HTTP_CAPABILITY_IDLE_TIMEOUT, HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN,
    HTTP_CAPABILITY_MESSAGING_SERVICE_MSG, HTTP_CAPABILITY_REAUTH,
    HTTP_CAPABILITY_TYPE_QUAR_SOH, HTTP_CAPABILITY_UDP_TRANSPORT, HTTP_EXTENDED_AUTH_NONE,
    HTTP_EXTENDED_AUTH_PAA, PACKET_HEADER_SIZE, STATUS_SUCCESS,
};

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for a [`GatewayClient`].
#[derive(Debug, Clone)]
pub struct GatewayClientConfig {
    /// Hostname of the target RDP server (not the gateway). Used in
    /// the `HTTP_CHANNEL_PACKET.pResource` list. UTF-8.
    pub target_host: String,
    /// TCP port on the target RDP server. Typically `3389`.
    pub target_port: u16,
    /// Client machine name sent in `HTTP_TUNNEL_AUTH_PACKET.clientName`.
    /// UTF-8; will be encoded as UTF-16LE on the wire.
    pub client_name: String,
    /// Capability flags advertised in `HTTP_TUNNEL_PACKET.capsFlags`.
    /// Defaults to the six known caps (see [`Self::default_caps`]).
    pub client_caps: u32,
    /// Optional PAA cookie for pluggable authentication gateways.
    /// When present, the client sends `TunnelCreate` with
    /// `HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE` set.
    pub paa_cookie: Option<Vec<u8>>,
}

impl GatewayClientConfig {
    /// Full capability bitmask — all six caps defined in §2.2.5.3.
    pub const fn default_caps() -> u32 {
        HTTP_CAPABILITY_TYPE_QUAR_SOH
            | HTTP_CAPABILITY_IDLE_TIMEOUT
            | HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN
            | HTTP_CAPABILITY_MESSAGING_SERVICE_MSG
            | HTTP_CAPABILITY_REAUTH
            | HTTP_CAPABILITY_UDP_TRANSPORT
    }

    pub fn new(target_host: impl Into<String>, client_name: impl Into<String>) -> Self {
        Self {
            target_host: target_host.into(),
            target_port: 3389,
            client_name: client_name.into(),
            client_caps: Self::default_caps(),
            paa_cookie: None,
        }
    }
}

// =============================================================================
// State
// =============================================================================

/// State of the MS-TSGU HTTP Transport client session.
///
/// `Send*` states produce an outgoing PDU on the IN channel with an
/// empty `input`. `Wait*` states consume an incoming PDU from the OUT
/// channel. The state machine is strictly linear from `SendHandshake`
/// through `Connected` on the happy path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayClientState {
    /// Ready to send `HTTP_HANDSHAKE_REQUEST` on the IN channel.
    SendHandshake,
    /// Waiting for `HTTP_HANDSHAKE_RESPONSE` on the OUT channel.
    WaitHandshake,
    /// Ready to send `HTTP_TUNNEL_CREATE` on the IN channel.
    SendTunnelCreate,
    /// Waiting for `HTTP_TUNNEL_RESPONSE` on the OUT channel.
    WaitTunnelResponse,
    /// Ready to send `HTTP_TUNNEL_AUTH` on the IN channel.
    SendTunnelAuth,
    /// Waiting for `HTTP_TUNNEL_AUTH_RESPONSE` on the OUT channel.
    WaitTunnelAuthResponse,
    /// Ready to send `HTTP_CHANNEL_CREATE` on the IN channel.
    SendChannelCreate,
    /// Waiting for `HTTP_CHANNEL_RESPONSE` on the OUT channel.
    WaitChannelResponse,
    /// Tunnel is open and RDP traffic can flow through the DATA PDUs.
    Connected,
    /// Session is closed (clean shutdown or terminal error).
    Closed,
}

impl GatewayClientState {
    pub fn is_send(&self) -> bool {
        matches!(
            self,
            Self::SendHandshake
                | Self::SendTunnelCreate
                | Self::SendTunnelAuth
                | Self::SendChannelCreate
        )
    }

    pub fn is_wait(&self) -> bool {
        matches!(
            self,
            Self::WaitHandshake
                | Self::WaitTunnelResponse
                | Self::WaitTunnelAuthResponse
                | Self::WaitChannelResponse
        )
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::SendHandshake => "SendHandshake",
            Self::WaitHandshake => "WaitHandshake",
            Self::SendTunnelCreate => "SendTunnelCreate",
            Self::WaitTunnelResponse => "WaitTunnelResponse",
            Self::SendTunnelAuth => "SendTunnelAuth",
            Self::WaitTunnelAuthResponse => "WaitTunnelAuthResponse",
            Self::SendChannelCreate => "SendChannelCreate",
            Self::WaitChannelResponse => "WaitChannelResponse",
            Self::Connected => "Connected",
            Self::Closed => "Closed",
        }
    }
}

// =============================================================================
// Error / Result
// =============================================================================

/// Errors produced by [`GatewayClient`] while driving the state machine.
#[derive(Debug)]
pub enum GatewayError {
    /// `step` called with input/output in a way inconsistent with the
    /// current state (e.g. non-empty input for a `Send*` state).
    InvalidState(&'static str),
    /// Server sent a PDU with a `packetType` other than the one
    /// expected for the current state.
    UnexpectedPdu {
        expected: &'static str,
        got: u16,
    },
    /// Server returned a non-zero HRESULT at one of the negotiation
    /// stages. The session is terminal after this error.
    ServerStatus {
        stage: &'static str,
        code: u32,
    },
    /// The advertised `HTTP_TUNNEL_PACKET` capabilities required by
    /// the server were not granted (spec §3.3.5.2 step 8).
    CapabilityMismatch,
    /// Underlying encode failure.
    Encode(EncodeError),
    /// Underlying decode failure.
    Decode(DecodeError),
}

impl From<EncodeError> for GatewayError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

impl From<DecodeError> for GatewayError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

pub type GatewayResult<T> = Result<T, GatewayError>;

/// Output of a call to [`GatewayClient::step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    /// No bytes were written to `output` (consumed input only).
    Nothing,
    /// `n` bytes were written to `output`, starting at offset 0.
    Size(usize),
}

// =============================================================================
// PDU framing helper
// =============================================================================

/// Return the total byte size of the MS-TSGU PDU at the start of `bytes`,
/// or `None` if fewer than 8 bytes are available.
///
/// Reads the `packet_length` field of `HTTP_PACKET_HEADER` (§2.2.10.9)
/// and returns it. The caller must buffer incoming bytes from the OUT
/// channel until this function returns `Some(n)`, at which point the
/// first `n` bytes form a complete PDU ready to pass to
/// [`GatewayClient::step`].
pub fn find_packet_size(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < PACKET_HEADER_SIZE {
        return None;
    }
    let packet_length = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    Some(packet_length as usize)
}

// =============================================================================
// GatewayClient
// =============================================================================

/// Sans-io MS-TSGU HTTP Transport client state machine.
pub struct GatewayClient {
    config: GatewayClientConfig,
    state: GatewayClientState,
    /// Capability flags the server granted in `HTTP_TUNNEL_RESPONSE`.
    negotiated_caps: u32,
    /// Tunnel ID assigned by the server in `HTTP_TUNNEL_RESPONSE`.
    tunnel_id: u32,
    /// Channel ID assigned by the server in `HTTP_CHANNEL_RESPONSE`.
    channel_id: u32,
    /// Idle timeout in minutes (from `HTTP_TUNNEL_AUTH_RESPONSE`).
    idle_timeout_minutes: u32,
    /// Redirection policy flags from the server.
    redir_flags: u32,
}

impl GatewayClient {
    pub fn new(config: GatewayClientConfig) -> Self {
        Self {
            config,
            state: GatewayClientState::SendHandshake,
            negotiated_caps: 0,
            tunnel_id: 0,
            channel_id: 0,
            idle_timeout_minutes: 0,
            redir_flags: 0,
        }
    }

    pub fn state(&self) -> &GatewayClientState {
        &self.state
    }

    pub fn is_send_state(&self) -> bool {
        self.state.is_send()
    }

    pub fn is_wait_state(&self) -> bool {
        self.state.is_wait()
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state, GatewayClientState::Connected)
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.state, GatewayClientState::Closed)
    }

    pub fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }

    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    pub fn negotiated_caps(&self) -> u32 {
        self.negotiated_caps
    }

    pub fn idle_timeout_minutes(&self) -> u32 {
        self.idle_timeout_minutes
    }

    pub fn redir_flags(&self) -> u32 {
        self.redir_flags
    }

    /// Advance the state machine by one step.
    ///
    /// - For `Send*` states: pass an empty `input`. The outgoing PDU
    ///   is encoded into `output`, which is resized to the PDU size.
    /// - For `Wait*` states: pass the complete server PDU bytes. The
    ///   state machine parses the PDU and transitions; `output` is
    ///   left untouched and `Written::Nothing` is returned.
    pub fn step(&mut self, input: &[u8], output: &mut WriteBuf) -> GatewayResult<Written> {
        match self.state {
            GatewayClientState::SendHandshake => {
                if !input.is_empty() {
                    return Err(GatewayError::InvalidState(
                        "SendHandshake expects empty input",
                    ));
                }
                let extended_auth = if self.config.paa_cookie.is_some() {
                    HTTP_EXTENDED_AUTH_PAA
                } else {
                    HTTP_EXTENDED_AUTH_NONE
                };
                let pdu = HandshakeRequestPdu::new(extended_auth);
                let n = encode_to_buf(&pdu, output)?;
                self.state = GatewayClientState::WaitHandshake;
                Ok(Written::Size(n))
            }

            GatewayClientState::WaitHandshake => {
                let pdu = decode_checked::<HandshakeResponsePdu>(input, "HandshakeResponse")?;
                if pdu.error_code != STATUS_SUCCESS {
                    self.state = GatewayClientState::Closed;
                    return Err(GatewayError::ServerStatus {
                        stage: "HandshakeResponse",
                        code: pdu.error_code,
                    });
                }
                self.state = GatewayClientState::SendTunnelCreate;
                Ok(Written::Nothing)
            }

            GatewayClientState::SendTunnelCreate => {
                if !input.is_empty() {
                    return Err(GatewayError::InvalidState(
                        "SendTunnelCreate expects empty input",
                    ));
                }
                let pdu = match &self.config.paa_cookie {
                    Some(cookie) => TunnelCreatePdu::with_paa_cookie(
                        self.config.client_caps,
                        HttpByteBlob::new(cookie.clone()),
                    ),
                    None => TunnelCreatePdu::normal(self.config.client_caps),
                };
                let n = encode_to_buf(&pdu, output)?;
                self.state = GatewayClientState::WaitTunnelResponse;
                Ok(Written::Size(n))
            }

            GatewayClientState::WaitTunnelResponse => {
                let pdu = decode_checked::<TunnelResponsePdu>(input, "TunnelResponse")?;
                if pdu.status_code != STATUS_SUCCESS {
                    self.state = GatewayClientState::Closed;
                    return Err(GatewayError::ServerStatus {
                        stage: "TunnelResponse",
                        code: pdu.status_code,
                    });
                }
                self.tunnel_id = pdu.tunnel_id;
                self.negotiated_caps = pdu.caps_flags;
                self.state = GatewayClientState::SendTunnelAuth;
                Ok(Written::Nothing)
            }

            GatewayClientState::SendTunnelAuth => {
                if !input.is_empty() {
                    return Err(GatewayError::InvalidState(
                        "SendTunnelAuth expects empty input",
                    ));
                }
                let pdu = TunnelAuthPdu::new(&self.config.client_name);
                let n = encode_to_buf(&pdu, output)?;
                self.state = GatewayClientState::WaitTunnelAuthResponse;
                Ok(Written::Size(n))
            }

            GatewayClientState::WaitTunnelAuthResponse => {
                let pdu = decode_checked::<TunnelAuthResponsePdu>(input, "TunnelAuthResponse")?;
                // Per §3.3.5.2: both S_OK and E_PROXY_QUARANTINE_ACCESSDENIED
                // allow the client to continue to ChannelCreate. Any other
                // status code terminates the session.
                if pdu.error_code != STATUS_SUCCESS
                    && pdu.error_code != E_PROXY_QUARANTINE_ACCESSDENIED
                {
                    self.state = GatewayClientState::Closed;
                    return Err(GatewayError::ServerStatus {
                        stage: "TunnelAuthResponse",
                        code: pdu.error_code,
                    });
                }
                self.redir_flags = pdu.redir_flags;
                self.idle_timeout_minutes = pdu.idle_timeout_minutes;
                self.state = GatewayClientState::SendChannelCreate;
                Ok(Written::Nothing)
            }

            GatewayClientState::SendChannelCreate => {
                if !input.is_empty() {
                    return Err(GatewayError::InvalidState(
                        "SendChannelCreate expects empty input",
                    ));
                }
                let pdu = ChannelCreatePdu::new(
                    &self.config.target_host,
                    self.config.target_port,
                );
                let n = encode_to_buf(&pdu, output)?;
                self.state = GatewayClientState::WaitChannelResponse;
                Ok(Written::Size(n))
            }

            GatewayClientState::WaitChannelResponse => {
                let pdu = decode_checked::<ChannelResponsePdu>(input, "ChannelResponse")?;
                if pdu.error_code != STATUS_SUCCESS {
                    self.state = GatewayClientState::Closed;
                    return Err(GatewayError::ServerStatus {
                        stage: "ChannelResponse",
                        code: pdu.error_code,
                    });
                }
                self.channel_id = pdu.channel_id;
                self.state = GatewayClientState::Connected;
                Ok(Written::Nothing)
            }

            GatewayClientState::Connected | GatewayClientState::Closed => {
                Err(GatewayError::InvalidState(
                    "step called in Connected/Closed state; use encode_data/decode_data/encode_close",
                ))
            }
        }
    }

    /// Wrap raw RDP bytes in an `HTTP_DATA_PACKET` ready to send on
    /// the IN channel. Only valid once [`Self::is_connected`] is true.
    pub fn encode_data(&self, rdp_bytes: &[u8], output: &mut WriteBuf) -> GatewayResult<usize> {
        if !self.is_connected() {
            return Err(GatewayError::InvalidState(
                "encode_data called before Connected",
            ));
        }
        let pdu = DataPdu::new(rdp_bytes.to_vec());
        Ok(encode_to_buf(&pdu, output)?)
    }

    /// Build an `HTTP_CLOSE_PACKET` request carrying a graceful
    /// disconnect HRESULT. Transitions the state machine to `Closed`.
    pub fn encode_close(&mut self, output: &mut WriteBuf) -> GatewayResult<usize> {
        let pdu = CloseChannelPdu::request(ERROR_GRACEFUL_DISCONNECT);
        let n = encode_to_buf(&pdu, output)?;
        self.state = GatewayClientState::Closed;
        Ok(n)
    }
}

/// Decode an `HTTP_DATA_PACKET` from OUT-channel bytes and return the
/// wrapped RDP payload. Free function because it does not mutate client
/// state and the caller may want to peek at the payload without holding
/// `&mut GatewayClient`.
pub fn decode_data(bytes: &[u8]) -> GatewayResult<Vec<u8>> {
    let pdu = decode_checked::<DataPdu>(bytes, "Data")?;
    Ok(pdu.data)
}

// =============================================================================
// Internal helpers
// =============================================================================

fn encode_to_buf<T: Encode>(pdu: &T, output: &mut WriteBuf) -> Result<usize, EncodeError> {
    let size = pdu.size();
    output.resize(size);
    let mut cursor = WriteCursor::new(output.as_mut_slice());
    pdu.encode(&mut cursor)?;
    Ok(size)
}

fn decode_checked<'de, T>(bytes: &'de [u8], stage: &'static str) -> GatewayResult<T>
where
    T: Decode<'de>,
{
    if bytes.len() < PACKET_HEADER_SIZE {
        return Err(GatewayError::UnexpectedPdu {
            expected: stage,
            got: 0,
        });
    }
    let declared = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if bytes.len() < declared {
        return Err(GatewayError::Decode(DecodeError::invalid_value(
            stage,
            "truncated",
        )));
    }
    let mut cur = ReadCursor::new(&bytes[..declared]);
    T::decode(&mut cur).map_err(GatewayError::Decode)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{
        HttpPacketHeader, HttpUnicodeString, HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
        HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT,
        HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS, HTTP_TUNNEL_REDIR_DISABLE_ALL,
        HTTP_TUNNEL_RESPONSE_FIELD_CAPS, HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID,
    };
    use alloc::vec;

    fn mk_client() -> GatewayClient {
        GatewayClient::new(GatewayClientConfig::new("target.example.com", "RDG-Client1"))
    }

    fn encode_pdu<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        buf
    }

    fn mk_tunnel_response_ok(tunnel_id: u32, caps: u32) -> Vec<u8> {
        let pdu = TunnelResponsePdu {
            server_version: 1,
            status_code: STATUS_SUCCESS,
            fields_present: HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID
                | HTTP_TUNNEL_RESPONSE_FIELD_CAPS,
            tunnel_id,
            caps_flags: caps,
            nonce: [0; 16],
            server_cert: HttpUnicodeString::empty(),
            consent_msg: HttpUnicodeString::empty(),
        };
        encode_pdu(&pdu)
    }

    fn mk_tunnel_auth_response_ok(redir_flags: u32, idle_minutes: u32) -> Vec<u8> {
        let pdu = TunnelAuthResponsePdu {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS
                | HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT,
            redir_flags,
            idle_timeout_minutes: idle_minutes,
            soh_response: None,
        };
        encode_pdu(&pdu)
    }

    fn mk_channel_response_ok(channel_id: u32) -> Vec<u8> {
        let pdu = ChannelResponsePdu {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
            channel_id,
            udp_port: 0,
            authn_cookie: None,
        };
        encode_pdu(&pdu)
    }

    // ---------- Happy path ----------

    #[test]
    fn happy_path_full_handshake() {
        let mut client = mk_client();
        let mut out = WriteBuf::new();

        // 1. SendHandshake
        assert_eq!(client.state(), &GatewayClientState::SendHandshake);
        assert!(client.is_send_state());
        let written = client.step(&[], &mut out).unwrap();
        assert!(matches!(written, Written::Size(14)));
        // verify first PDU is a HandshakeRequest
        let hdr = HttpPacketHeader::decode(&mut ReadCursor::new(out.as_slice())).unwrap();
        assert_eq!(hdr.packet_type, 0x0001);
        assert_eq!(client.state(), &GatewayClientState::WaitHandshake);

        // 2. WaitHandshake
        let resp = encode_pdu(&HandshakeResponsePdu::ok(HTTP_EXTENDED_AUTH_NONE));
        assert_eq!(client.step(&resp, &mut out).unwrap(), Written::Nothing);
        assert_eq!(client.state(), &GatewayClientState::SendTunnelCreate);

        // 3. SendTunnelCreate (normal, no PAA)
        let written = client.step(&[], &mut out).unwrap();
        assert!(matches!(written, Written::Size(16)));
        let hdr = HttpPacketHeader::decode(&mut ReadCursor::new(out.as_slice())).unwrap();
        assert_eq!(hdr.packet_type, 0x0004);
        assert_eq!(client.state(), &GatewayClientState::WaitTunnelResponse);

        // 4. WaitTunnelResponse
        let resp = mk_tunnel_response_ok(0x1234_5678, 0x3F);
        assert_eq!(client.step(&resp, &mut out).unwrap(), Written::Nothing);
        assert_eq!(client.tunnel_id(), 0x1234_5678);
        assert_eq!(client.negotiated_caps(), 0x3F);
        assert_eq!(client.state(), &GatewayClientState::SendTunnelAuth);

        // 5. SendTunnelAuth
        let written = client.step(&[], &mut out).unwrap();
        // "RDG-Client1" = 11 chars = 22 UTF-16LE bytes; packet = 12 + 22 = 34
        assert!(matches!(written, Written::Size(34)));
        let hdr = HttpPacketHeader::decode(&mut ReadCursor::new(out.as_slice())).unwrap();
        assert_eq!(hdr.packet_type, 0x0006);
        assert_eq!(client.state(), &GatewayClientState::WaitTunnelAuthResponse);

        // 6. WaitTunnelAuthResponse
        let resp = mk_tunnel_auth_response_ok(HTTP_TUNNEL_REDIR_DISABLE_ALL, 60);
        assert_eq!(client.step(&resp, &mut out).unwrap(), Written::Nothing);
        assert_eq!(client.redir_flags(), HTTP_TUNNEL_REDIR_DISABLE_ALL);
        assert_eq!(client.idle_timeout_minutes(), 60);
        assert_eq!(client.state(), &GatewayClientState::SendChannelCreate);

        // 7. SendChannelCreate
        let written = client.step(&[], &mut out).unwrap();
        // target.example.com = 18 chars = 36 UTF-16LE bytes; wire = 14 + 2 + 36 = 52
        assert!(matches!(written, Written::Size(52)));
        let hdr = HttpPacketHeader::decode(&mut ReadCursor::new(out.as_slice())).unwrap();
        assert_eq!(hdr.packet_type, 0x0008);
        assert_eq!(client.state(), &GatewayClientState::WaitChannelResponse);

        // 8. WaitChannelResponse
        let resp = mk_channel_response_ok(42);
        assert_eq!(client.step(&resp, &mut out).unwrap(), Written::Nothing);
        assert_eq!(client.channel_id(), 42);
        assert!(client.is_connected());
    }

    // ---------- Error paths ----------

    #[test]
    fn handshake_error_code_terminates_session() {
        let mut client = mk_client();
        let mut out = WriteBuf::new();
        client.step(&[], &mut out).unwrap(); // SendHandshake

        let resp = encode_pdu(&HandshakeResponsePdu {
            error_code: 0x8007_59D8,
            ver_major: 1,
            ver_minor: 0,
            server_version: 0,
            extended_auth: 0,
        });
        let err = client.step(&resp, &mut out).unwrap_err();
        assert!(matches!(
            err,
            GatewayError::ServerStatus {
                stage: "HandshakeResponse",
                code: 0x8007_59D8
            }
        ));
        assert!(client.is_closed());
    }

    #[test]
    fn tunnel_response_error_terminates() {
        let mut client = mk_client();
        let mut out = WriteBuf::new();
        client.step(&[], &mut out).unwrap();
        client
            .step(
                &encode_pdu(&HandshakeResponsePdu::ok(HTTP_EXTENDED_AUTH_NONE)),
                &mut out,
            )
            .unwrap();
        client.step(&[], &mut out).unwrap(); // SendTunnelCreate

        let resp = encode_pdu(&TunnelResponsePdu {
            server_version: 0,
            status_code: 0x8007_59DA, // E_PROXY_RAP_ACCESSDENIED
            fields_present: 0,
            tunnel_id: 0,
            caps_flags: 0,
            nonce: [0; 16],
            server_cert: HttpUnicodeString::empty(),
            consent_msg: HttpUnicodeString::empty(),
        });
        let err = client.step(&resp, &mut out).unwrap_err();
        assert!(matches!(
            err,
            GatewayError::ServerStatus {
                stage: "TunnelResponse",
                code: 0x8007_59DA
            }
        ));
        assert!(client.is_closed());
    }

    #[test]
    fn tunnel_auth_response_quarantine_is_not_fatal() {
        let mut client = mk_client();
        let mut out = WriteBuf::new();
        // Drive to TunnelAuth
        client.step(&[], &mut out).unwrap();
        client
            .step(
                &encode_pdu(&HandshakeResponsePdu::ok(HTTP_EXTENDED_AUTH_NONE)),
                &mut out,
            )
            .unwrap();
        client.step(&[], &mut out).unwrap();
        client
            .step(&mk_tunnel_response_ok(1, 0x3F), &mut out)
            .unwrap();
        client.step(&[], &mut out).unwrap();

        // Server replies with QUARANTINE_ACCESSDENIED — should proceed.
        let resp = encode_pdu(&TunnelAuthResponsePdu {
            error_code: E_PROXY_QUARANTINE_ACCESSDENIED,
            fields_present: 0,
            redir_flags: 0,
            idle_timeout_minutes: 0,
            soh_response: None,
        });
        client.step(&resp, &mut out).unwrap();
        assert_eq!(client.state(), &GatewayClientState::SendChannelCreate);
    }

    // ---------- Data path ----------

    #[test]
    fn encode_data_before_connected_fails() {
        let client = mk_client();
        let mut out = WriteBuf::new();
        assert!(client.encode_data(&[1, 2, 3], &mut out).is_err());
    }

    #[test]
    fn encode_data_after_connected_wraps_payload() {
        let mut client = mk_client();
        let mut out = WriteBuf::new();
        drive_to_connected(&mut client, &mut out);

        let rdp = [0x03, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80];
        let n = client.encode_data(&rdp, &mut out).unwrap();
        assert_eq!(n, 10 + rdp.len());
        let decoded = decode_data(out.as_slice()).unwrap();
        assert_eq!(decoded, rdp);
    }

    #[test]
    fn encode_close_transitions_to_closed() {
        let mut client = mk_client();
        let mut out = WriteBuf::new();
        drive_to_connected(&mut client, &mut out);
        client.encode_close(&mut out).unwrap();
        assert!(client.is_closed());
        // Wire bytes: CloseChannel request, 12 bytes
        assert_eq!(out.len(), 12);
        assert_eq!(&out.as_slice()[0..2], &[0x10, 0x00]);
    }

    // ---------- PAA cookie path ----------

    #[test]
    fn paa_cookie_is_sent_in_tunnel_create() {
        let mut config = GatewayClientConfig::new("target", "client");
        config.paa_cookie = Some(vec![0xAA, 0xBB, 0xCC]);
        let mut client = GatewayClient::new(config);
        let mut out = WriteBuf::new();

        // Handshake — the extended_auth advertises PAA
        client.step(&[], &mut out).unwrap();
        let hs = HandshakeRequestPdu::decode(&mut ReadCursor::new(out.as_slice())).unwrap();
        assert_eq!(hs.extended_auth, HTTP_EXTENDED_AUTH_PAA);

        // Accept server response
        client
            .step(
                &encode_pdu(&HandshakeResponsePdu::ok(HTTP_EXTENDED_AUTH_PAA)),
                &mut out,
            )
            .unwrap();

        // TunnelCreate carries the PAA cookie
        client.step(&[], &mut out).unwrap();
        let create = TunnelCreatePdu::decode(&mut ReadCursor::new(out.as_slice())).unwrap();
        assert_eq!(
            create.paa_cookie.as_ref().map(|c| c.blob.clone()),
            Some(vec![0xAA, 0xBB, 0xCC])
        );
    }

    // ---------- Framing helper ----------

    #[test]
    fn find_packet_size_handles_partial_header() {
        assert_eq!(find_packet_size(&[]), None);
        assert_eq!(find_packet_size(&[0; 7]), None);
        // 8-byte header claiming a 12-byte packet
        assert_eq!(
            find_packet_size(&[0x10, 0, 0, 0, 0x0C, 0, 0, 0]),
            Some(12)
        );
    }

    // ---------- Helpers ----------

    fn drive_to_connected(client: &mut GatewayClient, out: &mut WriteBuf) {
        client.step(&[], out).unwrap();
        client
            .step(
                &encode_pdu(&HandshakeResponsePdu::ok(HTTP_EXTENDED_AUTH_NONE)),
                out,
            )
            .unwrap();
        client.step(&[], out).unwrap();
        client.step(&mk_tunnel_response_ok(1, 0x3F), out).unwrap();
        client.step(&[], out).unwrap();
        client
            .step(
                &mk_tunnel_auth_response_ok(HTTP_TUNNEL_REDIR_DISABLE_ALL, 30),
                out,
            )
            .unwrap();
        client.step(&[], out).unwrap();
        client.step(&mk_channel_response_ok(1), out).unwrap();
        assert!(client.is_connected());
    }
}
