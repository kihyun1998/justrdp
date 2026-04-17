#![forbid(unsafe_code)]

//! High-level `TsProxyClient` — tracks the connection state machine
//! (`Start → Connected → Authorized → ChannelCreated → PipeCreated`
//! per MS-TSGU §3.2.1) and produces ready-to-send DCE/RPC REQUEST
//! PDUs for each of the seven client-initiated methods, consuming
//! the corresponding RESPONSE PDUs on the other side.
//!
//! The client is **transport-agnostic**: it does not own a socket
//! or an [`RpchTunnel`][justrdp_rpch::RpchTunnel]. Callers are
//! expected to drive I/O themselves, typically:
//!
//! 1. Call `client.build_create_tunnel(pkt)` → get PDU bytes, send
//!    them through the tunnel, read the response PDU.
//! 2. Feed the response back via `client.on_create_tunnel_response(pdu)`.
//! 3. Repeat for `authorize_tunnel`, `create_channel`, etc.
//! 4. After `PipeCreated`, use `client.build_send_to_server(bytes)`
//!    for each outbound RDP buffer.
//!
//! # Out of scope
//!
//! - `MakeTunnelCall` (async consent / reauth long-poll).
//! - Multi-fragment REQUEST handling — all requests here fit in a
//!   single fragment (stub_data is always < 5840 bytes).
//! - `SetupReceivePipe` stream reassembly — only the initial REQUEST
//!   is produced; the caller streams RESPONSE fragments themselves.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::WriteCursor;
use justrdp_rpch::pdu::{
    RequestPdu, ResponsePdu, PFC_FIRST_FRAG, PFC_LAST_FRAG, RESPONSE_PTYPE,
};

use super::methods::{
    build_authorize_tunnel_stub, build_close_channel_stub, build_close_tunnel_stub,
    build_create_channel_stub, build_create_tunnel_stub, build_send_to_server_message,
    build_setup_receive_pipe_message, parse_authorize_tunnel_response,
    parse_close_channel_response, parse_close_tunnel_response, parse_create_channel_response,
    parse_create_tunnel_response, AuthorizeTunnelResponse, CreateChannelResponse,
    CreateTunnelResponse, SendToServerError, OPNUM_TS_PROXY_AUTHORIZE_TUNNEL,
    OPNUM_TS_PROXY_CLOSE_CHANNEL, OPNUM_TS_PROXY_CLOSE_TUNNEL, OPNUM_TS_PROXY_CREATE_CHANNEL,
    OPNUM_TS_PROXY_CREATE_TUNNEL, OPNUM_TS_PROXY_SEND_TO_SERVER,
    OPNUM_TS_PROXY_SETUP_RECEIVE_PIPE,
};
use super::types::{ContextHandle, TsEndpointInfo, TsgPacket};

// =============================================================================
// State machine
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsProxyState {
    /// Pre-CreateTunnel. No tunnel handle yet.
    Start,
    /// CreateTunnel succeeded. Tunnel handle held; AuthorizeTunnel
    /// required before anything else can happen.
    Connected,
    /// AuthorizeTunnel succeeded. Ready for CreateChannel.
    Authorized,
    /// CreateChannel succeeded. Channel handle held; SetupReceivePipe
    /// required before RDP data can flow.
    ChannelCreated,
    /// SetupReceivePipe has been sent. Ready for SendToServer calls.
    PipeCreated,
    /// Tunnel is tearing down (CloseChannel or CloseTunnel pending).
    Closing,
    /// Terminal — tunnel closed.
    End,
}

// =============================================================================
// Error
// =============================================================================

#[derive(Debug, Clone)]
pub enum TsProxyClientError {
    /// The method was called from a state that does not permit it.
    WrongState {
        wanted: TsProxyState,
        actual: TsProxyState,
    },
    /// Server returned a non-success HRESULT. Inspect the raw value
    /// via [`super::errors::name_of`].
    ServerError {
        method: &'static str,
        hresult: u32,
    },
    /// NDR decode failed while parsing a response.
    Ndr(justrdp_rpch::ndr::NdrError),
    /// DCE/RPC PDU decode failed.
    RpcPdu(justrdp_core::DecodeError),
    /// The response PDU carried a different PTYPE than expected.
    UnexpectedPtype {
        got: u8,
        wanted: u8,
    },
    /// SendToServer payload could not be framed.
    SendToServer(SendToServerError),
}

impl core::fmt::Display for TsProxyClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongState { wanted, actual } => write!(
                f,
                "TsProxy: wrong state for this operation (wanted {wanted:?}, got {actual:?})"
            ),
            Self::ServerError { method, hresult } => write!(
                f,
                "TsProxy: {method} returned HRESULT {hresult:#010x} ({})",
                super::errors::name_of(*hresult)
            ),
            Self::Ndr(e) => write!(f, "TsProxy NDR: {e}"),
            Self::RpcPdu(e) => write!(f, "TsProxy DCE/RPC PDU: {e}"),
            Self::UnexpectedPtype { got, wanted } => {
                write!(f, "TsProxy: unexpected PDU type {got:#04x} (wanted {wanted:#04x})")
            }
            Self::SendToServer(e) => write!(f, "TsProxy: {e}"),
        }
    }
}

impl core::error::Error for TsProxyClientError {}

impl From<justrdp_rpch::ndr::NdrError> for TsProxyClientError {
    fn from(e: justrdp_rpch::ndr::NdrError) -> Self {
        Self::Ndr(e)
    }
}

impl From<justrdp_core::DecodeError> for TsProxyClientError {
    fn from(e: justrdp_core::DecodeError) -> Self {
        Self::RpcPdu(e)
    }
}

impl From<SendToServerError> for TsProxyClientError {
    fn from(e: SendToServerError) -> Self {
        Self::SendToServer(e)
    }
}

// =============================================================================
// Client
// =============================================================================

/// State machine + REQUEST builder + RESPONSE parser for TsProxy.
#[derive(Debug, Clone)]
pub struct TsProxyClient {
    state: TsProxyState,
    context_id: u16,
    next_call_id: u32,
    tunnel_context: Option<ContextHandle>,
    channel_context: Option<ContextHandle>,
}

impl Default for TsProxyClient {
    fn default() -> Self {
        Self::new()
    }
}

impl TsProxyClient {
    /// Create a fresh client in the `Start` state. Presentation
    /// context ID defaults to 0; callers who bound the TsProxy
    /// interface at a different p_cont_id should call
    /// [`Self::with_context_id`] instead.
    pub fn new() -> Self {
        Self {
            state: TsProxyState::Start,
            context_id: 0,
            next_call_id: 1,
            tunnel_context: None,
            channel_context: None,
        }
    }

    /// Create with a specific DCE/RPC presentation-context ID.
    pub fn with_context_id(context_id: u16) -> Self {
        Self {
            state: TsProxyState::Start,
            context_id,
            next_call_id: 1,
            tunnel_context: None,
            channel_context: None,
        }
    }

    pub fn state(&self) -> TsProxyState {
        self.state
    }

    pub fn tunnel_context(&self) -> Option<&ContextHandle> {
        self.tunnel_context.as_ref()
    }

    pub fn channel_context(&self) -> Option<&ContextHandle> {
        self.channel_context.as_ref()
    }

    fn allocate_call_id(&mut self) -> u32 {
        let id = self.next_call_id;
        self.next_call_id = self.next_call_id.wrapping_add(1);
        id
    }

    fn expect_state(&self, wanted: TsProxyState) -> Result<(), TsProxyClientError> {
        if self.state == wanted {
            Ok(())
        } else {
            Err(TsProxyClientError::WrongState {
                wanted,
                actual: self.state,
            })
        }
    }

    /// Wrap a stub buffer in a REQUEST PDU with the given `opnum`.
    fn wrap_request(&mut self, opnum: u16, stub_data: Vec<u8>) -> Vec<u8> {
        let req = RequestPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: self.allocate_call_id(),
            alloc_hint: 0,
            context_id: self.context_id,
            opnum,
            object: None,
            stub_data,
            auth: None,
        };
        let mut buf = alloc::vec![0u8; req.size()];
        let mut w = WriteCursor::new(&mut buf);
        req.encode(&mut w).expect("request fits in computed buffer");
        buf
    }

    fn unwrap_response(&self, pdu_bytes: &[u8]) -> Result<Vec<u8>, TsProxyClientError> {
        if pdu_bytes.len() < 16 {
            return Err(TsProxyClientError::UnexpectedPtype {
                got: 0xFF,
                wanted: RESPONSE_PTYPE,
            });
        }
        let ptype = pdu_bytes[2];
        if ptype != RESPONSE_PTYPE {
            return Err(TsProxyClientError::UnexpectedPtype {
                got: ptype,
                wanted: RESPONSE_PTYPE,
            });
        }
        let mut c = justrdp_core::ReadCursor::new(pdu_bytes);
        let resp = ResponsePdu::decode(&mut c).map_err(TsProxyClientError::RpcPdu)?;
        Ok(resp.stub_data)
    }

    // ---- TsProxyCreateTunnel (opnum 1) ---------------------------------

    /// Build a `TsProxyCreateTunnel` REQUEST PDU. Requires
    /// [`TsProxyState::Start`].
    pub fn build_create_tunnel(
        &mut self,
        packet: &TsgPacket,
    ) -> Result<Vec<u8>, TsProxyClientError> {
        self.expect_state(TsProxyState::Start)?;
        let stub = build_create_tunnel_stub(packet);
        Ok(self.wrap_request(OPNUM_TS_PROXY_CREATE_TUNNEL, stub))
    }

    /// Consume the RESPONSE PDU for `TsProxyCreateTunnel`.
    pub fn on_create_tunnel_response(
        &mut self,
        pdu_bytes: &[u8],
    ) -> Result<CreateTunnelResponse, TsProxyClientError> {
        let stub = self.unwrap_response(pdu_bytes)?;
        let resp = parse_create_tunnel_response(&stub)?;
        if resp.return_value != super::errors::ERROR_SUCCESS {
            return Err(TsProxyClientError::ServerError {
                method: "TsProxyCreateTunnel",
                hresult: resp.return_value,
            });
        }
        self.tunnel_context = Some(resp.tunnel_context);
        self.state = TsProxyState::Connected;
        Ok(resp)
    }

    // ---- TsProxyAuthorizeTunnel (opnum 2) ------------------------------

    pub fn build_authorize_tunnel(
        &mut self,
        packet: &TsgPacket,
    ) -> Result<Vec<u8>, TsProxyClientError> {
        self.expect_state(TsProxyState::Connected)?;
        let h = self.tunnel_context.expect("tunnel_context set in Connected");
        let stub = build_authorize_tunnel_stub(&h, packet);
        Ok(self.wrap_request(OPNUM_TS_PROXY_AUTHORIZE_TUNNEL, stub))
    }

    pub fn on_authorize_tunnel_response(
        &mut self,
        pdu_bytes: &[u8],
    ) -> Result<AuthorizeTunnelResponse, TsProxyClientError> {
        let stub = self.unwrap_response(pdu_bytes)?;
        let resp = parse_authorize_tunnel_response(&stub)?;
        if resp.return_value != super::errors::ERROR_SUCCESS {
            return Err(TsProxyClientError::ServerError {
                method: "TsProxyAuthorizeTunnel",
                hresult: resp.return_value,
            });
        }
        self.state = TsProxyState::Authorized;
        Ok(resp)
    }

    // ---- TsProxyCreateChannel (opnum 4) --------------------------------

    pub fn build_create_channel(
        &mut self,
        endpoint: &TsEndpointInfo,
    ) -> Result<Vec<u8>, TsProxyClientError> {
        self.expect_state(TsProxyState::Authorized)?;
        let h = self.tunnel_context.expect("tunnel_context set in Authorized");
        let stub = build_create_channel_stub(&h, endpoint);
        Ok(self.wrap_request(OPNUM_TS_PROXY_CREATE_CHANNEL, stub))
    }

    pub fn on_create_channel_response(
        &mut self,
        pdu_bytes: &[u8],
    ) -> Result<CreateChannelResponse, TsProxyClientError> {
        let stub = self.unwrap_response(pdu_bytes)?;
        let resp = parse_create_channel_response(&stub)?;
        if resp.return_value != super::errors::ERROR_SUCCESS {
            return Err(TsProxyClientError::ServerError {
                method: "TsProxyCreateChannel",
                hresult: resp.return_value,
            });
        }
        self.channel_context = Some(resp.channel_context);
        self.state = TsProxyState::ChannelCreated;
        Ok(resp)
    }

    // ---- TsProxySetupReceivePipe (opnum 8) -----------------------------

    /// Build the REQUEST PDU that opens the receive pipe. The
    /// server's response is streamed as multiple RESPONSE fragments;
    /// the client is expected to read them until `PFC_LAST_FRAG`
    /// (the final 4 bytes of stub_data hold a DWORD return value,
    /// typically `ERROR_GRACEFUL_DISCONNECT`).
    pub fn build_setup_receive_pipe(&mut self) -> Result<Vec<u8>, TsProxyClientError> {
        self.expect_state(TsProxyState::ChannelCreated)?;
        let h = self
            .channel_context
            .expect("channel_context set in ChannelCreated");
        let stub = build_setup_receive_pipe_message(&h);
        let pdu = self.wrap_request(OPNUM_TS_PROXY_SETUP_RECEIVE_PIPE, stub);
        self.state = TsProxyState::PipeCreated;
        Ok(pdu)
    }

    // ---- TsProxySendToServer (opnum 9) ---------------------------------

    /// Build a REQUEST PDU carrying the Generic Send Data Message
    /// Packet (§2.2.9.3) with the given `buffers` (1..=3).
    pub fn build_send_to_server(
        &mut self,
        buffers: &[&[u8]],
    ) -> Result<Vec<u8>, TsProxyClientError> {
        self.expect_state(TsProxyState::PipeCreated)?;
        let h = self.channel_context.expect("channel_context set");
        let stub = build_send_to_server_message(&h, buffers)?;
        Ok(self.wrap_request(OPNUM_TS_PROXY_SEND_TO_SERVER, stub))
    }

    // ---- TsProxyCloseChannel (opnum 6) ---------------------------------

    pub fn build_close_channel(&mut self) -> Result<Vec<u8>, TsProxyClientError> {
        match self.state {
            TsProxyState::ChannelCreated | TsProxyState::PipeCreated => {}
            other => {
                // Report the earliest state at which CloseChannel
                // becomes legal, so the caller can open a channel
                // first if they are earlier in the flow.
                return Err(TsProxyClientError::WrongState {
                    wanted: TsProxyState::ChannelCreated,
                    actual: other,
                });
            }
        }
        let h = self.channel_context.expect("channel_context set");
        let stub = build_close_channel_stub(&h);
        self.state = TsProxyState::Closing;
        Ok(self.wrap_request(OPNUM_TS_PROXY_CLOSE_CHANNEL, stub))
    }

    pub fn on_close_channel_response(
        &mut self,
        pdu_bytes: &[u8],
    ) -> Result<u32, TsProxyClientError> {
        let stub = self.unwrap_response(pdu_bytes)?;
        let (_cleared, return_value) = parse_close_channel_response(&stub)?;
        if return_value != super::errors::ERROR_SUCCESS {
            return Err(TsProxyClientError::ServerError {
                method: "TsProxyCloseChannel",
                hresult: return_value,
            });
        }
        self.channel_context = None;
        // After the channel is closed, the tunnel is still open.
        // Transition back to Authorized so the caller may open
        // another channel, or proceed to CloseTunnel.
        self.state = TsProxyState::Authorized;
        Ok(return_value)
    }

    // ---- TsProxyCloseTunnel (opnum 7) ----------------------------------

    pub fn build_close_tunnel(&mut self) -> Result<Vec<u8>, TsProxyClientError> {
        // CloseTunnel is legal from any state where we still hold
        // a tunnel handle — typically `Authorized` after a normal
        // CloseChannel, or any intermediate state on error paths.
        let h = self
            .tunnel_context
            .ok_or(TsProxyClientError::WrongState {
                wanted: TsProxyState::Authorized,
                actual: self.state,
            })?;
        let stub = build_close_tunnel_stub(&h);
        self.state = TsProxyState::Closing;
        Ok(self.wrap_request(OPNUM_TS_PROXY_CLOSE_TUNNEL, stub))
    }

    /// Consume the RESPONSE PDU for `TsProxyCloseTunnel`.
    ///
    /// Regardless of the server's return code, the tunnel handle is
    /// cleared and state advances to `End` — once the RESPONSE has
    /// been received there is no protocol action left for the
    /// client to take on this handle. A non-success HRESULT is
    /// surfaced as `ServerError` so callers that care (e.g.
    /// log-and-continue wrappers) can distinguish between a clean
    /// teardown and e.g. `E_PROXY_ALREADYDISCONNECTED`.
    pub fn on_close_tunnel_response(
        &mut self,
        pdu_bytes: &[u8],
    ) -> Result<u32, TsProxyClientError> {
        let stub = self.unwrap_response(pdu_bytes)?;
        let (_cleared, return_value) = parse_close_tunnel_response(&stub)?;
        self.tunnel_context = None;
        self.state = TsProxyState::End;
        if return_value != super::errors::ERROR_SUCCESS {
            return Err(TsProxyClientError::ServerError {
                method: "TsProxyCloseTunnel",
                hresult: return_value,
            });
        }
        Ok(return_value)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpch::errors::ERROR_SUCCESS;
    use crate::rpch::methods::{
        parse_create_channel_response, parse_create_tunnel_response,
    };
    use crate::rpch::types::{
        TsgPacketQuarEncResponse, TsgPacketQuarRequest, TsgPacketVersionCaps,
        TSG_NAP_CAPABILITY_QUAR_SOH,
    };
    use alloc::string::String;
    use alloc::vec;
    use justrdp_core::ReadCursor;
    use justrdp_rpch::ndr::NdrEncoder;
    use justrdp_rpch::pdu::{RequestPdu, REQUEST_PTYPE};

    fn sample_handle() -> ContextHandle {
        ContextHandle {
            attributes: 1,
            uuid: justrdp_rpch::pdu::uuid::RpcUuid::parse(
                "aabbccdd-1122-3344-5566-77889900aabb",
            )
            .unwrap(),
        }
    }

    fn build_response_stub_create_tunnel(handle: ContextHandle, tunnel_id: u32) -> Vec<u8> {
        // Synthesize an NDR-marshaled output for CreateTunnel.
        let mut e = NdrEncoder::new();
        // TSGPacketResponse is a [ref]* — outer has no referent, inner
        // is a unique pointer referent ID + body.
        let _ = e.write_unique_pointer(true);
        TsgPacket::QuarEncResponse(TsgPacketQuarEncResponse {
            flags: 0,
            cert_chain: None,
            nonce: justrdp_rpch::pdu::uuid::RpcUuid::NIL,
            version_caps: None,
        })
        .encode_ndr(&mut e);
        // tunnel context handle
        handle.encode_ndr(&mut e);
        // tunnel_id
        e.write_u32(tunnel_id);
        // return_value
        e.write_u32(ERROR_SUCCESS);
        e.into_bytes()
    }

    fn wrap_response_pdu(stub: Vec<u8>, call_id: u32) -> Vec<u8> {
        let resp = ResponsePdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id,
            alloc_hint: 0,
            context_id: 0,
            cancel_count: 0,
            stub_data: stub,
            auth: None,
        };
        let mut buf = vec![0u8; resp.size()];
        let mut w = WriteCursor::new(&mut buf);
        resp.encode(&mut w).unwrap();
        buf
    }

    #[test]
    fn initial_state_is_start() {
        let c = TsProxyClient::new();
        assert_eq!(c.state(), TsProxyState::Start);
        assert!(c.tunnel_context().is_none());
        assert!(c.channel_context().is_none());
    }

    #[test]
    fn cannot_authorize_before_create_tunnel() {
        let mut c = TsProxyClient::new();
        let pkt = TsgPacket::QuarRequest(TsgPacketQuarRequest {
            flags: 0,
            machine_name: None,
            data: None,
        });
        let err = c.build_authorize_tunnel(&pkt).unwrap_err();
        assert!(matches!(err, TsProxyClientError::WrongState { .. }));
    }

    #[test]
    fn create_tunnel_request_has_correct_opnum() {
        let mut c = TsProxyClient::new();
        let pkt = TsgPacket::VersionCaps(TsgPacketVersionCaps::client_default(
            TSG_NAP_CAPABILITY_QUAR_SOH,
        ));
        let pdu = c.build_create_tunnel(&pkt).unwrap();
        // opnum lives at offset 22..24 of the REQUEST PDU.
        let opnum = u16::from_le_bytes([pdu[22], pdu[23]]);
        assert_eq!(opnum, OPNUM_TS_PROXY_CREATE_TUNNEL);
    }

    #[test]
    fn create_tunnel_request_pfc_flags_first_last() {
        let mut c = TsProxyClient::new();
        let pkt = TsgPacket::VersionCaps(TsgPacketVersionCaps::client_default(
            TSG_NAP_CAPABILITY_QUAR_SOH,
        ));
        let pdu = c.build_create_tunnel(&pkt).unwrap();
        assert_eq!(pdu[3], PFC_FIRST_FRAG | PFC_LAST_FRAG);
    }

    #[test]
    fn create_tunnel_success_transitions_to_connected() {
        let mut c = TsProxyClient::new();
        let pkt = TsgPacket::VersionCaps(TsgPacketVersionCaps::client_default(0));
        let _pdu = c.build_create_tunnel(&pkt).unwrap();

        let stub = build_response_stub_create_tunnel(sample_handle(), 42);
        let pdu = wrap_response_pdu(stub, 1);
        let resp = c.on_create_tunnel_response(&pdu).unwrap();

        assert_eq!(c.state(), TsProxyState::Connected);
        assert_eq!(resp.tunnel_context, sample_handle());
        assert_eq!(resp.tunnel_id, 42);
        assert_eq!(c.tunnel_context(), Some(&sample_handle()));
    }

    #[test]
    fn create_tunnel_error_hresult_is_reported() {
        let mut c = TsProxyClient::new();
        let pkt = TsgPacket::VersionCaps(TsgPacketVersionCaps::client_default(0));
        let _ = c.build_create_tunnel(&pkt).unwrap();

        // Build a response with a non-zero HRESULT.
        let mut e = NdrEncoder::new();
        let _ = e.write_unique_pointer(true);
        TsgPacket::QuarEncResponse(TsgPacketQuarEncResponse {
            flags: 0,
            cert_chain: None,
            nonce: justrdp_rpch::pdu::uuid::RpcUuid::NIL,
            version_caps: None,
        })
        .encode_ndr(&mut e);
        ContextHandle::NIL.encode_ndr(&mut e);
        e.write_u32(0);
        e.write_u32(crate::rpch::errors::E_PROXY_NOCERTAVAILABLE);
        let pdu = wrap_response_pdu(e.into_bytes(), 1);

        let err = c.on_create_tunnel_response(&pdu).unwrap_err();
        match err {
            TsProxyClientError::ServerError { hresult, .. } => {
                assert_eq!(hresult, crate::rpch::errors::E_PROXY_NOCERTAVAILABLE);
            }
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    #[test]
    fn full_happy_path_drives_state_machine() {
        let mut c = TsProxyClient::new();

        // CreateTunnel.
        let pkt = TsgPacket::VersionCaps(TsgPacketVersionCaps::client_default(0));
        let _ = c.build_create_tunnel(&pkt).unwrap();
        let stub = build_response_stub_create_tunnel(sample_handle(), 1);
        c.on_create_tunnel_response(&wrap_response_pdu(stub, 1))
            .unwrap();
        assert_eq!(c.state(), TsProxyState::Connected);

        // AuthorizeTunnel.
        let pkt = TsgPacket::QuarRequest(TsgPacketQuarRequest {
            flags: 0,
            machine_name: None,
            data: None,
        });
        let _ = c.build_authorize_tunnel(&pkt).unwrap();
        let mut e = NdrEncoder::new();
        let _ = e.write_unique_pointer(true);
        TsgPacket::Response(crate::rpch::types::TsgPacketResponse {
            flags: 0,
            response_data: vec![],
            redirection_flags: crate::rpch::types::TsgRedirectionFlags::default(),
        })
        .encode_ndr(&mut e);
        e.write_u32(ERROR_SUCCESS);
        c.on_authorize_tunnel_response(&wrap_response_pdu(e.into_bytes(), 2))
            .unwrap();
        assert_eq!(c.state(), TsProxyState::Authorized);

        // CreateChannel.
        let ep = TsEndpointInfo {
            resource_names: vec![String::from("server.example.com")],
            alternate_resource_names: vec![],
            port: TsEndpointInfo::rdp_port(3389),
        };
        let _ = c.build_create_channel(&ep).unwrap();
        let channel_handle = ContextHandle {
            attributes: 2,
            uuid: justrdp_rpch::pdu::uuid::RpcUuid::parse(
                "deadbeef-dead-beef-dead-beefdeadbeef",
            )
            .unwrap(),
        };
        let mut e = NdrEncoder::new();
        channel_handle.encode_ndr(&mut e);
        e.write_u32(99); // channel_id
        e.write_u32(ERROR_SUCCESS);
        c.on_create_channel_response(&wrap_response_pdu(e.into_bytes(), 3))
            .unwrap();
        assert_eq!(c.state(), TsProxyState::ChannelCreated);
        assert_eq!(c.channel_context(), Some(&channel_handle));

        // SetupReceivePipe.
        let _ = c.build_setup_receive_pipe().unwrap();
        assert_eq!(c.state(), TsProxyState::PipeCreated);

        // SendToServer.
        let _ = c.build_send_to_server(&[b"rdp bytes"]).unwrap();

        // CloseChannel.
        let _ = c.build_close_channel().unwrap();
        assert_eq!(c.state(), TsProxyState::Closing);
        let mut e = NdrEncoder::new();
        ContextHandle::NIL.encode_ndr(&mut e);
        e.write_u32(ERROR_SUCCESS);
        c.on_close_channel_response(&wrap_response_pdu(e.into_bytes(), 6))
            .unwrap();
        assert_eq!(c.state(), TsProxyState::Authorized);

        // CloseTunnel.
        let _ = c.build_close_tunnel().unwrap();
        let mut e = NdrEncoder::new();
        ContextHandle::NIL.encode_ndr(&mut e);
        e.write_u32(ERROR_SUCCESS);
        c.on_close_tunnel_response(&wrap_response_pdu(e.into_bytes(), 7))
            .unwrap();
        assert_eq!(c.state(), TsProxyState::End);
    }

    #[test]
    fn request_call_ids_are_monotonic() {
        let mut c = TsProxyClient::new();
        let pkt = TsgPacket::VersionCaps(TsgPacketVersionCaps::client_default(0));
        let pdu1 = c.build_create_tunnel(&pkt).unwrap();
        let call_id_1 = u32::from_le_bytes([pdu1[12], pdu1[13], pdu1[14], pdu1[15]]);
        assert_eq!(call_id_1, 1);
        // Advance state manually to allow second call.
        let stub = build_response_stub_create_tunnel(sample_handle(), 1);
        c.on_create_tunnel_response(&wrap_response_pdu(stub, 1))
            .unwrap();
        let pdu2 = c
            .build_authorize_tunnel(&TsgPacket::QuarRequest(TsgPacketQuarRequest {
                flags: 0,
                machine_name: None,
                data: None,
            }))
            .unwrap();
        let call_id_2 = u32::from_le_bytes([pdu2[12], pdu2[13], pdu2[14], pdu2[15]]);
        assert_eq!(call_id_2, 2);
    }

    #[test]
    fn unwrap_response_rejects_wrong_ptype() {
        let c = TsProxyClient::new();
        let req = RequestPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 1,
            alloc_hint: 0,
            context_id: 0,
            opnum: 0,
            object: None,
            stub_data: vec![0; 4],
            auth: None,
        };
        let mut buf = vec![0u8; req.size()];
        let mut w = WriteCursor::new(&mut buf);
        req.encode(&mut w).unwrap();
        // Feed REQUEST (PTYPE=0x00) where RESPONSE (0x02) expected.
        let err = c.unwrap_response(&buf).unwrap_err();
        match err {
            TsProxyClientError::UnexpectedPtype { got, wanted } => {
                assert_eq!(got, REQUEST_PTYPE);
                assert_eq!(wanted, RESPONSE_PTYPE);
            }
            other => panic!("expected UnexpectedPtype, got {other:?}"),
        }
    }

    // Keep import usage explicit.
    #[allow(dead_code)]
    fn _uses_imports() {
        let _ = ReadCursor::new(&[]);
        let _ = parse_create_tunnel_response(&[]);
        let _ = parse_create_channel_response(&[]);
    }
}
