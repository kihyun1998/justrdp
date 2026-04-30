#![forbid(unsafe_code)]

//! Async port of `justrdp_gateway::rpch::channel::RpchGatewayChannel`.
//!
//! `TsguRpchTransport<TIn, TOut>` is the final adapter in the
//! RPC-over-HTTP gateway stack. It takes a [`TsguRpchTunnel`] (already
//! past CONN/A/B/C) and drives:
//!
//! 1. **DCE/RPC BIND / BIND_ACK** — advertises the TsProxy v1.3
//!    interface UUID with NDR 2.0 transfer syntax.
//! 2. **TsProxyCreateTunnel** — server returns a tunnel context
//!    handle.
//! 3. **TsProxyAuthorizeTunnel** — minimal NAP-free QuarRequest
//!    (or `TSG_PACKET_AUTH` if the embedder supplied a PAA cookie).
//! 4. **TsProxyCreateChannel** — server returns a channel context
//!    handle keyed to `target_host:target_port`.
//! 5. **TsProxySetupReceivePipe** — REQUEST only; the server then
//!    streams RDP-server bytes back as a series of RESPONSE PDUs
//!    sharing the same `call_id`.
//!
//! Once `connect()` returns, [`WebTransport`] semantics map onto:
//!
//! * `send(rdp_bytes)` → one `TsProxySendToServer` REQUEST. Blocks
//!   until the matching RESPONSE arrives (server ack with DWORD
//!   return value). Pipe RESPONSEs that arrive while we wait are
//!   buffered into `rx_buffer` so the next `recv()` drains them.
//! * `recv()` → bytes from the pipe RESPONSE stream. Drains at
//!   least one byte's worth at a time (matches
//!   [`NativeTcpTransport::recv`] byte-stream semantics).
//! * `close()` → best-effort `TsProxyCloseChannel` +
//!   `TsProxyCloseTunnel`, then closes both halves of the tunnel.
//!
//! ### Cancel safety
//!
//! `send()` is **not** cancel-safe between `build_send_to_server`
//! and the matching RESPONSE — dropping the future mid-flight leaves
//! the gateway with a pending RPC call whose response will never be
//! consumed. The `WebClient` driver does not cancel mid-send, but
//! embedders that wrap this transport in their own `select!` should
//! not race `send` against a cancellation token.
//!
//! `recv()` is cancel-safe: dropping a `recv` future loses no buffered
//! data because progress only resumes from `tunnel.recv_pdu` (itself
//! cancel-safe per its contract).
//!
//! [`TsguRpchTunnel`]: super::rpch_tunnel::TsguRpchTunnel
//! [`NativeTcpTransport::recv`]: crate::native_tcp::NativeTcpTransport

use alloc::collections::VecDeque;
use alloc::format;
use alloc::vec::Vec;

use justrdp_async::{TransportError, WebTransport};
use justrdp_core::ReadCursor;
use justrdp_gateway::rpch::{
    build_tsproxy_bind_pdu, validate_tsproxy_bind_ack, PaaCookie, TsEndpointInfo, TsProxyClient,
    TsProxyClientError, TsgPacket, TsgPacketAuth, TsgPacketQuarRequest, TsgPacketVersionCaps,
    ERROR_SUCCESS, TSPROXY_CONTEXT_ID,
};
use justrdp_rpch::pdu::{ResponsePdu, PFC_LAST_FRAG};

use super::error::http_err;
use super::rpch_tunnel::TsguRpchTunnel;

/// Runtime configuration for [`TsguRpchTransport::connect`]. Mirrors
/// `justrdp_gateway::rpch::ChannelOptions` field-for-field.
#[derive(Debug, Clone)]
pub struct RpchChannelOptions {
    /// Client capability advertisement. Sent inside the
    /// `TsProxyCreateTunnel` packet (or wrapped in `TSG_PACKET_AUTH`
    /// when [`paa_cookie`](Self::paa_cookie) is `Some`).
    pub version_caps: TsgPacketVersionCaps,
    /// Optional pre-authentication cookie. When `Some`, the client
    /// sends `TSG_PACKET_AUTH`; when `None`, bare
    /// `TSG_PACKET_VERSIONCAPS` (anonymous tunnel auth).
    pub paa_cookie: Option<PaaCookie>,
    /// Target server + port the gateway should connect to. The port
    /// is wrapped via `TsEndpointInfo::rdp_port(...)` to match the
    /// IDL union shape Windows expects.
    pub endpoint: TsEndpointInfo,
}

/// Async MS-RPCH gateway transport. Construct via [`Self::connect`]
/// and hand to a [`WebClient`](justrdp_async::WebClient) just like
/// any other [`WebTransport`]; the inner RDP TLS handshake / CredSSP
/// run unmodified above.
pub struct TsguRpchTransport<TIn, TOut>
where
    TIn: WebTransport + Send,
    TOut: WebTransport + Send,
{
    tunnel: TsguRpchTunnel<TIn, TOut>,
    client: TsProxyClient,
    /// `call_id` of the outstanding `TsProxySetupReceivePipe`
    /// REQUEST. Every RESPONSE bearing this id belongs to the
    /// server → client RDP byte stream; the rest are SendToServer
    /// acks (or unsolicited ⇒ protocol error).
    receive_pipe_call_id: u32,
    /// FIFO of RDP bytes already pulled off the pipe, awaiting
    /// consumption by `recv()`. A `VecDeque` keeps both ends cheap
    /// — pipe RESPONSEs push back, `recv()` pops from the front.
    rx_buffer: VecDeque<u8>,
    /// `Some(dword)` once the pipe's final RESPONSE has been seen
    /// (PFC_LAST_FRAG). Subsequent `recv()` calls return
    /// `ConnectionClosed`. The DWORD is typically
    /// `ERROR_GRACEFUL_DISCONNECT`.
    pipe_return: Option<u32>,
    /// Sticky once `close()` has been called or a peer-side EOF
    /// observed. Subsequent `send()`/`recv()` short-circuit.
    closed: bool,
}

impl<TIn, TOut> core::fmt::Debug for TsguRpchTransport<TIn, TOut>
where
    TIn: WebTransport + Send,
    TOut: WebTransport + Send,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TsguRpchTransport")
            .field("client_state", &self.client.state())
            .field("receive_pipe_call_id", &self.receive_pipe_call_id)
            .field("rx_buffer_len", &self.rx_buffer.len())
            .field("pipe_return", &self.pipe_return)
            .field("closed", &self.closed)
            .finish()
    }
}

impl<TIn, TOut> TsguRpchTransport<TIn, TOut>
where
    TIn: WebTransport + Send,
    TOut: WebTransport + Send,
{
    /// Drive the BIND + TsProxy 4-step + SetupReceivePipe sequence
    /// over the supplied RPC-over-HTTP tunnel.
    ///
    /// On success the transport is positioned right after the client
    /// has emitted the `TsProxySetupReceivePipe` REQUEST and is
    /// awaiting the first pipe RESPONSE bringing RDP bytes from the
    /// inner server. The TsProxy state machine sits in
    /// [`TsProxyState::PipeCreated`](justrdp_gateway::rpch::TsProxyState::PipeCreated).
    pub async fn connect(
        mut tunnel: TsguRpchTunnel<TIn, TOut>,
        options: RpchChannelOptions,
    ) -> Result<Self, TransportError> {
        // Step 1: DCE/RPC BIND / BIND_ACK.
        let bind_pdu = build_tsproxy_bind_pdu(1);
        tunnel.send_pdu(&bind_pdu).await?;
        let bind_ack = tunnel
            .recv_pdu()
            .await?
            .ok_or_else(|| http_err("rpch: peer EOF before BIND_ACK"))?;
        validate_tsproxy_bind_ack(&bind_ack)
            .map_err(|e| http_err(format!("rpch BIND_ACK rejected: {e:?}")))?;

        let mut client = TsProxyClient::with_context_id(TSPROXY_CONTEXT_ID);

        // Step 2: TsProxyCreateTunnel — pick packet shape based on
        // PAA cookie presence.
        let create_tunnel_pkt = match options.paa_cookie.as_ref() {
            Some(cookie) => TsgPacket::Auth(TsgPacketAuth {
                version_caps: options.version_caps.clone(),
                cookie: cookie.as_bytes().to_vec(),
            }),
            None => TsgPacket::VersionCaps(options.version_caps.clone()),
        };
        let req = client.build_create_tunnel(&create_tunnel_pkt).map_err(ts_err)?;
        tunnel.send_pdu(&req).await?;
        let resp = tunnel
            .recv_pdu()
            .await?
            .ok_or_else(|| http_err("rpch: peer EOF before CreateTunnel RESPONSE"))?;
        client.on_create_tunnel_response(&resp).map_err(ts_err)?;

        // Step 3: TsProxyAuthorizeTunnel — minimal NAP-free request.
        let quar = TsgPacket::QuarRequest(TsgPacketQuarRequest {
            flags: 0,
            machine_name: None,
            data: None,
        });
        let req = client.build_authorize_tunnel(&quar).map_err(ts_err)?;
        tunnel.send_pdu(&req).await?;
        let resp = tunnel
            .recv_pdu()
            .await?
            .ok_or_else(|| http_err("rpch: peer EOF before AuthorizeTunnel RESPONSE"))?;
        client.on_authorize_tunnel_response(&resp).map_err(ts_err)?;

        // Step 4: TsProxyCreateChannel.
        let req = client
            .build_create_channel(&options.endpoint)
            .map_err(ts_err)?;
        tunnel.send_pdu(&req).await?;
        let resp = tunnel
            .recv_pdu()
            .await?
            .ok_or_else(|| http_err("rpch: peer EOF before CreateChannel RESPONSE"))?;
        client.on_create_channel_response(&resp).map_err(ts_err)?;

        // Step 5: TsProxySetupReceivePipe — REQUEST only. The pipe
        // RESPONSEs that follow this call carry RDP bytes from the
        // inner server; we collect them lazily as `recv()` is called.
        let pipe_pdu = client.build_setup_receive_pipe().map_err(ts_err)?;
        let receive_pipe_call_id = extract_call_id(&pipe_pdu);
        tunnel.send_pdu(&pipe_pdu).await?;

        Ok(Self {
            tunnel,
            client,
            receive_pipe_call_id,
            rx_buffer: VecDeque::new(),
            pipe_return: None,
            closed: false,
        })
    }

    /// Borrow the underlying TsProxy state machine — useful for
    /// inspecting the negotiated tunnel / channel context handles.
    pub fn client(&self) -> &TsProxyClient {
        &self.client
    }

    /// `Some(dword)` once the server's pipe RESPONSE stream
    /// terminated with PFC_LAST_FRAG. Typically
    /// `ERROR_GRACEFUL_DISCONNECT`.
    pub fn pipe_return(&self) -> Option<u32> {
        self.pipe_return
    }

    /// Pump server-originated PDUs off the OUT channel until either:
    ///
    /// * `send_call_id == Some(id)` and a RESPONSE with that
    ///   `call_id` arrives — then return `Ok(Some(dword))` carrying
    ///   the SendToServer return value.
    /// * `send_call_id == None` and at least one pipe RESPONSE has
    ///   been buffered (any forward progress for `recv()`) — then
    ///   return `Ok(None)`.
    ///
    /// Pipe traffic is always pushed into `rx_buffer` regardless of
    /// the calling context. Unsolicited RESPONSEs (call_id matching
    /// neither the pipe nor `send_call_id`) surface as
    /// [`TransportError::protocol`].
    async fn pump_until(
        &mut self,
        send_call_id: Option<u32>,
    ) -> Result<Option<u32>, TransportError> {
        loop {
            let pdu_bytes = self
                .tunnel
                .recv_pdu()
                .await?
                .ok_or_else(|| http_err("rpch: peer EOF mid-call"))?;
            let parsed = ResponsePdu::decode(&mut ReadCursor::new(&pdu_bytes))
                .map_err(|e| http_err(format!("rpch RESPONSE decode: {e}")))?;
            if parsed.call_id == self.receive_pipe_call_id {
                // Pipe traffic — interleave with SendToServer when
                // applicable.
                if parsed.pfc_flags & PFC_LAST_FRAG != 0 {
                    // Final fragment carries the 4-byte DWORD return
                    // value. Some Windows servers also send 0 bytes
                    // here — treat as ERROR_SUCCESS.
                    let rv = stub_to_dword(&parsed.stub_data);
                    self.pipe_return = Some(rv);
                } else {
                    self.rx_buffer.extend(parsed.stub_data.iter());
                }
                if send_call_id.is_none() {
                    // Called from `recv()` — any pipe progress is
                    // actionable; let the caller drain `rx_buffer`.
                    return Ok(None);
                }
                // Called from `send()` — keep pumping until the
                // SendToServer RESPONSE arrives.
            } else if Some(parsed.call_id) == send_call_id {
                // SendToServer's RESPONSE: stub_data is a 4-byte
                // DWORD on success (zero or empty on some servers).
                let rv = stub_to_dword(&parsed.stub_data);
                return Ok(Some(rv));
            } else {
                return Err(http_err(format!(
                    "rpch: unexpected call_id {} in RESPONSE (pipe id {}, in-flight send {:?})",
                    parsed.call_id, self.receive_pipe_call_id, send_call_id,
                )));
            }
        }
    }

    /// Drain `rx_buffer` into a fresh `Vec<u8>` for `recv()` return.
    /// Caps the returned chunk so a single huge pipe RESPONSE does
    /// not pin enormous allocations on the connector layer.
    fn drain_rx_buffer(&mut self) -> Vec<u8> {
        const RECV_CHUNK_CAP: usize = 64 * 1024;
        let n = self.rx_buffer.len().min(RECV_CHUNK_CAP);
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.rx_buffer.pop_front().unwrap());
        }
        out
    }
}

impl<TIn, TOut> WebTransport for TsguRpchTransport<TIn, TOut>
where
    TIn: WebTransport + Send,
    TOut: WebTransport + Send,
{
    async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::closed("tsgu-rpch: already closed"));
        }
        if bytes.is_empty() {
            return Ok(());
        }
        // Build one TsProxySendToServer REQUEST containing the
        // entire payload as buffer1. Caller-side fragmentation is
        // their responsibility — a single REQUEST must not exceed
        // the IN channel's `max_xmit_frag` (5840 default), and RDP
        // X.224/MCS/Fast-Path PDUs stay well under that.
        let pdu = self
            .client
            .build_send_to_server(&[bytes])
            .map_err(ts_err)?;
        let call_id = extract_call_id(&pdu);
        self.tunnel.send_pdu(&pdu).await?;
        // Wait for the matching RESPONSE, buffering interleaved
        // pipe traffic for later `recv()`s.
        let rv = self
            .pump_until(Some(call_id))
            .await?
            .expect("pump_until returns Some when send_call_id is Some");
        if rv != ERROR_SUCCESS {
            return Err(http_err(format!(
                "rpch SendToServer returned DWORD {rv:#010x}"
            )));
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.closed {
            return Err(TransportError::closed("tsgu-rpch: already closed"));
        }
        // Drain whatever's buffered first.
        if !self.rx_buffer.is_empty() {
            return Ok(self.drain_rx_buffer());
        }
        // EOF already observed: the pipe's final RESPONSE arrived
        // with PFC_LAST_FRAG. Match `NativeTcpTransport`'s
        // ConnectionClosed semantics so the connector layer maps it
        // to a clean session termination.
        if self.pipe_return.is_some() {
            self.closed = true;
            return Err(TransportError::closed(
                "tsgu-rpch: pipe ended (server closed)",
            ));
        }
        // Pump until the buffer fills with pipe data or EOF.
        match self.pump_until(None).await {
            Ok(_) => {}
            Err(e) => {
                self.closed = true;
                return Err(e);
            }
        }
        if self.rx_buffer.is_empty() {
            // EOF arrived (PFC_LAST_FRAG seen with no payload).
            self.closed = true;
            return Err(TransportError::closed(
                "tsgu-rpch: pipe ended (server closed)",
            ));
        }
        Ok(self.drain_rx_buffer())
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // Best-effort tear-down: emit CloseChannel + CloseTunnel
        // PDUs but do not block on their RESPONSEs (the connection
        // may already be half-dead). Silently swallow failures —
        // the embedder cares about resource release, not graceful
        // protocol close.
        if let Ok(req) = self.client.build_close_channel() {
            let _ = self.tunnel.send_pdu(&req).await;
        }
        if let Ok(req) = self.client.build_close_tunnel() {
            let _ = self.tunnel.send_pdu(&req).await;
        }
        Ok(())
    }
}

/// Wrap a [`TsProxyClientError`] into the transport's protocol-class
/// error envelope.
fn ts_err(e: TsProxyClientError) -> TransportError {
    http_err(format!("tsproxy: {e}"))
}

/// Extract the `call_id` field (offset 12..16 of the common CO PDU
/// header) without fully decoding the PDU. Used after building a
/// REQUEST to remember its call_id for later response dispatch.
fn extract_call_id(pdu: &[u8]) -> u32 {
    debug_assert!(pdu.len() >= 16, "PDU shorter than common header");
    u32::from_le_bytes([pdu[12], pdu[13], pdu[14], pdu[15]])
}

/// Decode the 4-byte DWORD return value carried in a SendToServer /
/// pipe-final RESPONSE's stub_data. Some Windows servers send 0
/// bytes — treat that as `ERROR_SUCCESS` (matches blocking).
fn stub_to_dword(stub: &[u8]) -> u32 {
    if stub.len() >= 4 {
        u32::from_le_bytes([stub[0], stub[1], stub[2], stub[3]])
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::string::String;
    use alloc::vec;
    use justrdp_async::TransportErrorKind;
    use justrdp_core::WriteCursor;
    use justrdp_gateway::rpch::{
        ContextHandle, TsgPacket, TsgPacketQuarEncResponse, TsgPacketResponse, TsgPacketVersionCaps,
        TsgRedirectionFlags, ERROR_GRACEFUL_DISCONNECT, TSG_NAP_CAPABILITY_QUAR_SOH,
    };
    use justrdp_rpch::ndr::NdrEncoder;
    use justrdp_rpch::pdu::{
        uuid::RpcUuid, BindAckPdu, ContextResult, RtsCommand, RtsPdu, SyntaxId, BIND_ACK_PTYPE,
        PFC_FIRST_FRAG, PFC_LAST_FRAG, RESULT_ACCEPTANCE, RTS_FLAG_NONE,
    };
    use justrdp_rpch::tunnel::RpchTunnelConfig;

    /// Same scripted-WebTransport helper as elsewhere.
    #[derive(Debug, Default)]
    struct ScriptedTransport {
        sent: Vec<Vec<u8>>,
        recv_queue: VecDeque<Result<Vec<u8>, TransportError>>,
        closed: bool,
    }

    impl ScriptedTransport {
        fn from_script(script: Vec<u8>) -> Self {
            let mut t = Self::default();
            t.recv_queue.push_back(Ok(script));
            t
        }
        fn empty() -> Self {
            Self::default()
        }
    }

    impl WebTransport for ScriptedTransport {
        async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
            if self.closed {
                return Err(TransportError::closed("scripted: closed"));
            }
            self.sent.push(bytes.to_vec());
            Ok(())
        }
        async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
            self.recv_queue
                .pop_front()
                .unwrap_or_else(|| Err(TransportError::closed("scripted: drained")))
        }
        async fn close(&mut self) -> Result<(), TransportError> {
            self.closed = true;
            Ok(())
        }
    }

    // ── Test fixtures (ported from blocking::rpch::channel tests) ──

    fn encode_rts(pdu: &RtsPdu) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        buf
    }

    fn synthetic_a3() -> Vec<u8> {
        encode_rts(&RtsPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            flags: RTS_FLAG_NONE,
            commands: vec![RtsCommand::Version(1), RtsCommand::ReceiveWindowSize(65536)],
        })
    }

    fn synthetic_c2() -> Vec<u8> {
        encode_rts(&RtsPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            flags: RTS_FLAG_NONE,
            commands: vec![
                RtsCommand::Version(1),
                RtsCommand::ReceiveWindowSize(65536),
                RtsCommand::ConnectionTimeout(120_000),
            ],
        })
    }

    fn encode_bind_ack(call_id: u32) -> Vec<u8> {
        let ack = BindAckPdu {
            ptype: BIND_ACK_PTYPE,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0x1000,
            sec_addr: vec![],
            results: vec![ContextResult {
                result: RESULT_ACCEPTANCE,
                reason: 0,
                transfer_syntax: SyntaxId {
                    uuid: RpcUuid::from_str_unchecked(
                        "8a885d04-1ceb-11c9-9fe8-08002b104860",
                    ),
                    version_major: 2,
                    version_minor: 0,
                },
            }],
            auth: None,
        };
        let mut out = vec![0u8; ack.size()];
        let mut w = WriteCursor::new(&mut out);
        ack.encode(&mut w).unwrap();
        out
    }

    fn encode_response_pdu(call_id: u32, pfc_flags: u8, stub_data: Vec<u8>) -> Vec<u8> {
        // Build a RESPONSE PDU manually: rpc_vers=5, vers_minor=0,
        // ptype=0x02 (RESPONSE), flags, drep, frag_length,
        // auth_length=0, call_id, alloc_hint=0, p_cont_id=0,
        // cancel_count=0, reserved=0, then stub.
        let header_size = 24usize; // CommonHeader 16 + RESPONSE-specific 8
        let frag_length = (header_size + stub_data.len()) as u16;
        let mut pdu = Vec::with_capacity(frag_length as usize);
        pdu.push(5); // rpc_vers
        pdu.push(0); // rpc_vers_minor
        pdu.push(0x02); // PTYPE_RESPONSE
        pdu.push(pfc_flags);
        pdu.extend_from_slice(&[0x10, 0, 0, 0]); // packed_drep
        pdu.extend_from_slice(&frag_length.to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
        pdu.extend_from_slice(&call_id.to_le_bytes());
        // RESPONSE-specific:
        pdu.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
        pdu.extend_from_slice(&TSPROXY_CONTEXT_ID.to_le_bytes()); // p_cont_id
        pdu.push(0); // cancel_count
        pdu.push(0); // reserved
        pdu.extend_from_slice(&stub_data);
        pdu
    }

    fn build_create_tunnel_response_stub(handle: ContextHandle, tunnel_id: u32) -> Vec<u8> {
        let mut e = NdrEncoder::new();
        let _ = e.write_unique_pointer(true);
        TsgPacket::QuarEncResponse(TsgPacketQuarEncResponse {
            flags: 0,
            cert_chain: None,
            nonce: RpcUuid::NIL,
            version_caps: None,
        })
        .encode_ndr(&mut e);
        handle.encode_ndr(&mut e);
        e.write_u32(tunnel_id);
        e.write_u32(ERROR_SUCCESS);
        e.into_bytes()
    }

    fn build_authorize_tunnel_response_stub() -> Vec<u8> {
        let mut e = NdrEncoder::new();
        let _ = e.write_unique_pointer(true);
        TsgPacket::Response(TsgPacketResponse {
            flags: 0,
            response_data: vec![],
            redirection_flags: TsgRedirectionFlags::default(),
        })
        .encode_ndr(&mut e);
        e.write_u32(ERROR_SUCCESS);
        e.into_bytes()
    }

    fn build_create_channel_response_stub(handle: ContextHandle) -> Vec<u8> {
        let mut e = NdrEncoder::new();
        handle.encode_ndr(&mut e);
        e.write_u32(0xBEEF);
        e.write_u32(ERROR_SUCCESS);
        e.into_bytes()
    }

    fn sample_options() -> RpchChannelOptions {
        RpchChannelOptions {
            version_caps: TsgPacketVersionCaps::client_default(TSG_NAP_CAPABILITY_QUAR_SOH),
            paa_cookie: None,
            endpoint: TsEndpointInfo {
                resource_names: vec![String::from("server.example.com")],
                alternate_resource_names: vec![],
                port: TsEndpointInfo::rdp_port(3389),
            },
        }
    }

    fn sample_tunnel_ctx() -> ContextHandle {
        ContextHandle {
            attributes: 1,
            uuid: RpcUuid::from_str_unchecked("abcdef01-2345-6789-abcd-ef0123456789"),
        }
    }

    fn sample_channel_ctx() -> ContextHandle {
        ContextHandle {
            attributes: 2,
            uuid: RpcUuid::from_str_unchecked("deadbeef-cafe-f00d-dead-beefcafef00d"),
        }
    }

    fn tunnel_config() -> RpchTunnelConfig {
        RpchTunnelConfig {
            virtual_connection_cookie: RpcUuid::from_str_unchecked(
                "11111111-1111-1111-1111-111111111111",
            ),
            out_channel_cookie: RpcUuid::from_str_unchecked(
                "22222222-2222-2222-2222-222222222222",
            ),
            in_channel_cookie: RpcUuid::from_str_unchecked(
                "33333333-3333-3333-3333-333333333333",
            ),
            association_group_id: RpcUuid::from_str_unchecked(
                "44444444-4444-4444-4444-444444444444",
            ),
            receive_window_size: 65_536,
            channel_lifetime: 0x4000_0000,
            client_keepalive: 300_000,
        }
    }

    /// Assemble a scripted OUT stream containing all the PDUs the
    /// server must emit during the BIND + 4-step + optional pipe
    /// data, in order. Same call_id ordering as blocking's
    /// `out_stream_for_establish`:
    ///   - CONN/A3, CONN/C2 (handshake)
    ///   - BIND_ACK (call_id=1)
    ///   - CreateTunnel RESPONSE (call_id=1 — TsProxyClient restarts
    ///     counting after BIND)
    ///   - AuthorizeTunnel RESPONSE (call_id=2)
    ///   - CreateChannel RESPONSE (call_id=3)
    ///   - Optional pipe RESPONSE (call_id=4)
    fn out_stream_for_establish(include_pipe_data: Option<(&[u8], bool)>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&synthetic_a3());
        out.extend_from_slice(&synthetic_c2());
        out.extend_from_slice(&encode_bind_ack(1));
        out.extend_from_slice(&encode_response_pdu(
            1,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            build_create_tunnel_response_stub(sample_tunnel_ctx(), 0xAAAA),
        ));
        out.extend_from_slice(&encode_response_pdu(
            2,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            build_authorize_tunnel_response_stub(),
        ));
        out.extend_from_slice(&encode_response_pdu(
            3,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            build_create_channel_response_stub(sample_channel_ctx()),
        ));
        if let Some((bytes, is_final)) = include_pipe_data {
            let pfc = if is_final {
                PFC_FIRST_FRAG | PFC_LAST_FRAG
            } else {
                PFC_FIRST_FRAG
            };
            out.extend_from_slice(&encode_response_pdu(4, pfc, bytes.to_vec()));
        }
        out
    }

    async fn fresh_transport_with_out(
        out_bytes: Vec<u8>,
    ) -> TsguRpchTransport<ScriptedTransport, ScriptedTransport> {
        let inbound = ScriptedTransport::empty();
        let outbound = ScriptedTransport::from_script(out_bytes);
        let tunnel = TsguRpchTunnel::connect(inbound, outbound, tunnel_config(), Vec::new())
            .await
            .unwrap();
        TsguRpchTransport::connect(tunnel, sample_options())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn connect_succeeds_on_scripted_happy_path() {
        let transport = fresh_transport_with_out(out_stream_for_establish(None)).await;
        assert_eq!(
            transport.client.state(),
            justrdp_gateway::rpch::TsProxyState::PipeCreated
        );
        assert_eq!(
            transport.client.tunnel_context(),
            Some(&sample_tunnel_ctx())
        );
        assert_eq!(
            transport.client.channel_context(),
            Some(&sample_channel_ctx())
        );
    }

    #[tokio::test]
    async fn connect_fails_on_unexpected_eof_before_bind_ack() {
        // OUT stream stops right after CONN/C2 → BIND_ACK never
        // arrives.
        let mut script = Vec::new();
        script.extend_from_slice(&synthetic_a3());
        script.extend_from_slice(&synthetic_c2());
        let inbound = ScriptedTransport::empty();
        let outbound = ScriptedTransport::from_script(script);
        let tunnel = TsguRpchTunnel::connect(inbound, outbound, tunnel_config(), Vec::new())
            .await
            .unwrap();
        let err = TsguRpchTransport::connect(tunnel, sample_options())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[tokio::test]
    async fn recv_returns_pipe_stub_data() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xF0, 0x0D];
        let mut transport =
            fresh_transport_with_out(out_stream_for_establish(Some((&payload, false)))).await;
        let bytes = transport.recv().await.unwrap();
        assert_eq!(bytes.as_slice(), &payload);
    }

    #[tokio::test]
    async fn recv_after_pipe_eof_reports_connection_closed() {
        // Final RESPONSE: 4-byte DWORD ERROR_GRACEFUL_DISCONNECT,
        // PFC_LAST_FRAG set.
        let final_stub = ERROR_GRACEFUL_DISCONNECT.to_le_bytes();
        let mut transport =
            fresh_transport_with_out(out_stream_for_establish(Some((&final_stub, true)))).await;
        let err = transport.recv().await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
        assert_eq!(transport.pipe_return(), Some(ERROR_GRACEFUL_DISCONNECT));
    }

    #[tokio::test]
    async fn send_writes_send_to_server_and_waits_for_response() {
        // Build OUT stream: handshake + 4-step, then a SendToServer
        // RESPONSE (call_id=5, the next id after CreateChannel /
        // SetupReceivePipe used 3 / 4).
        let mut out = out_stream_for_establish(None);
        // Pipe traffic between handshake and SendToServer ack —
        // proves the buffer-while-waiting path.
        out.extend_from_slice(&encode_response_pdu(
            4, // pipe call_id
            PFC_FIRST_FRAG,
            b"PIPE-INTERLEAVED".to_vec(),
        ));
        // SendToServer RESPONSE (call_id=5, success DWORD).
        out.extend_from_slice(&encode_response_pdu(
            5,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            ERROR_SUCCESS.to_le_bytes().to_vec(),
        ));
        let mut transport = fresh_transport_with_out(out).await;
        transport.send(b"client-payload").await.unwrap();
        // The interleaved pipe data is now buffered for the next
        // recv() call.
        let pipe = transport.recv().await.unwrap();
        assert_eq!(pipe.as_slice(), b"PIPE-INTERLEAVED");
    }

    #[tokio::test]
    async fn send_oversize_protocol_error_path_is_quiet_for_normal_payloads() {
        // Sanity: a normal-size send completes without error.
        let mut out = out_stream_for_establish(None);
        out.extend_from_slice(&encode_response_pdu(
            5,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            ERROR_SUCCESS.to_le_bytes().to_vec(),
        ));
        let mut transport = fresh_transport_with_out(out).await;
        transport.send(b"normal-size-payload").await.unwrap();
    }

    #[tokio::test]
    async fn close_short_circuits_subsequent_send_recv() {
        let transport = fresh_transport_with_out(out_stream_for_establish(None)).await;
        let mut transport = transport;
        transport.close().await.unwrap();
        let err = transport.send(b"x").await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
        let err = transport.recv().await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
        // Idempotent.
        transport.close().await.unwrap();
    }

    #[tokio::test]
    async fn empty_send_is_a_noop() {
        let mut transport = fresh_transport_with_out(out_stream_for_establish(None)).await;
        // Empty payload returns Ok without touching the wire — no
        // SendToServer REQUEST should be queued, so no RESPONSE
        // needs to be scripted on the OUT side. An attempt to send
        // a real payload right after would block waiting for a
        // RESPONSE that isn't there; we only test the no-op shape.
        transport.send(&[]).await.unwrap();
    }
}
