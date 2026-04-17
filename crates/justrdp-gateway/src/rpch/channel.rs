#![forbid(unsafe_code)]

//! `RpchGatewayChannel` — the end-to-end Read+Write adapter that
//! turns an RPC-over-HTTP virtual connection into a byte pipe
//! suitable for the RDP handshake to flow through.
//!
//! It glues together:
//!
//! - an [`RpchTunnel`][justrdp_rpch::RpchTunnel] that already
//!   completed CONN/A/B/C,
//! - a [`TsProxyClient`] state machine, and
//! - a background multiplex loop that dispatches incoming RESPONSE
//!   PDUs to either the `TsProxySetupReceivePipe` stream (yields
//!   bytes to the caller's `read`) or the `TsProxySendToServer`
//!   response queue (signals completion of the caller's `write`).
//!
//! The adapter implements blocking `std::io::Read` and
//! `std::io::Write`. RDP bytes handed to `write` are wrapped as a
//! single SendToServer REQUEST; bytes returned by `read` are the
//! stub_data of one or more pipe RESPONSE PDUs. The pipe's final
//! RESPONSE (the one with `PFC_LAST_FRAG` set) carries the 4-byte
//! DWORD return value and ends the byte stream — subsequent `read`
//! calls return EOF (`Ok(0)`).
//!
//! # Concurrency model
//!
//! This is a strictly **single-threaded blocking** adapter. Under
//! the hood each `read`/`write` may pull any number of interleaved
//! PDUs off the OUT channel before returning (to drain backlog
//! before a SendToServer response or to accumulate pipe bytes), so
//! the caller must NOT share one channel across threads without
//! external synchronization.
//!
//! # Scope
//!
//! This is the piece that makes a fully established TsProxy tunnel
//! look like a TcpStream to the existing RDP connector. What is
//! **not** handled:
//!
//! - HTTP NTLM 401 retry and TLS upgrade on the IN/OUT sockets —
//!   that is the `justrdp-blocking` wire-up's responsibility
//!   (roadmap C5b).
//! - Tunnel recycling, reauthentication, and long-lived pings.
//! - Fragmenting single `write` calls larger than the IN channel
//!   `max_xmit_frag` (5840 default) — the caller must split
//!   oversize writes. In practice RDP X.224/MCS/Fast-Path packets
//!   stay well under this limit.

extern crate alloc;
extern crate std;

use alloc::collections::VecDeque;

use std::io::{self, Read, Write};
use std::string::ToString;

use justrdp_core::ReadCursor;
use justrdp_rpch::pdu::{ResponsePdu, PFC_LAST_FRAG};
use justrdp_rpch::RpchTunnel;

use super::bind::{build_tsproxy_bind_pdu, validate_tsproxy_bind_ack, TSPROXY_CONTEXT_ID};
use super::client::{TsProxyClient, TsProxyClientError};
use super::errors::ERROR_SUCCESS;
use super::paa::PaaCookie;
use super::types::{
    TsEndpointInfo, TsgPacket, TsgPacketAuth, TsgPacketQuarRequest, TsgPacketVersionCaps,
};

// =============================================================================
// Error type
// =============================================================================

/// Errors raised while establishing or operating an
/// [`RpchGatewayChannel`].
#[derive(Debug)]
pub enum ChannelError {
    /// Low-level I/O on either the IN or OUT stream.
    Io(io::Error),
    /// Decoding an incoming PDU failed.
    Pdu(justrdp_core::DecodeError),
    /// The OUT stream ended while we still expected a response.
    UnexpectedEof,
    /// The BIND_ACK reply rejected the TsProxy interface.
    BindRejected(super::bind::BindAckError),
    /// TsProxy state machine reported an error (wrong state,
    /// server HRESULT, NDR decode failure …).
    TsProxy(TsProxyClientError),
    /// A SendToServer REQUEST got a RESPONSE whose DWORD return
    /// code was non-zero.
    SendFailed(u32),
    /// An unsolicited RESPONSE arrived whose `call_id` was not the
    /// receive-pipe call_id nor any in-flight SendToServer call_id.
    UnexpectedCallId(u32),
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "rpch channel: {e}"),
            Self::Pdu(e) => write!(f, "rpch channel: PDU decode: {e}"),
            Self::UnexpectedEof => f.write_str("rpch channel: unexpected EOF"),
            Self::BindRejected(e) => write!(f, "rpch channel: BIND_ACK rejected: {e}"),
            Self::TsProxy(e) => write!(f, "rpch channel: {e}"),
            Self::SendFailed(rv) => {
                write!(f, "rpch channel: SendToServer returned DWORD {rv:#010x}")
            }
            Self::UnexpectedCallId(id) => {
                write!(f, "rpch channel: unexpected call_id {id} in RESPONSE")
            }
        }
    }
}

impl core::error::Error for ChannelError {}

impl From<io::Error> for ChannelError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<justrdp_core::DecodeError> for ChannelError {
    fn from(e: justrdp_core::DecodeError) -> Self {
        Self::Pdu(e)
    }
}

impl From<TsProxyClientError> for ChannelError {
    fn from(e: TsProxyClientError) -> Self {
        Self::TsProxy(e)
    }
}

impl From<super::bind::BindAckError> for ChannelError {
    fn from(e: super::bind::BindAckError) -> Self {
        Self::BindRejected(e)
    }
}

fn to_io(e: ChannelError) -> io::Error {
    io::Error::other(e.to_string())
}

// =============================================================================
// Establishment options
// =============================================================================

/// Options consumed by [`RpchGatewayChannel::establish`].
#[derive(Debug, Clone)]
pub struct ChannelOptions {
    /// What the client advertises as its own protocol version and
    /// capabilities in the initial `TsProxyCreateTunnel` packet.
    pub version_caps: TsgPacketVersionCaps,
    /// Optional PAA cookie. If `Some`, the client sends
    /// `TSG_PACKET_AUTH`; if `None`, it sends bare
    /// `TSG_PACKET_VERSIONCAPS` (RPC-level auth path).
    pub paa_cookie: Option<PaaCookie>,
    /// Target server + port the caller wants to tunnel to.
    pub endpoint: TsEndpointInfo,
}

// =============================================================================
// Channel
// =============================================================================

/// Fully established RPC-over-HTTP tunnel exposing a byte
/// duplex-stream API. Construct with [`Self::establish`].
pub struct RpchGatewayChannel<I, O>
where
    I: Read + Write,
    O: Read + Write,
{
    tunnel: RpchTunnel<I, O>,
    client: TsProxyClient,
    /// call_id used by the one outstanding SetupReceivePipe. All
    /// RESPONSE PDUs bearing this call_id belong to the server →
    /// client RDP byte stream.
    receive_pipe_call_id: u32,
    /// FIFO of RDP bytes already pulled off the pipe, awaiting
    /// consumption by `read`.
    rx_buffer: VecDeque<u8>,
    /// `Some(dword)` once the pipe's final RESPONSE has been seen.
    /// Further `read` calls return EOF. The `u32` is the pipe's
    /// DWORD return value (typically `ERROR_GRACEFUL_DISCONNECT`).
    pipe_return: Option<u32>,
}

impl<I, O> core::fmt::Debug for RpchGatewayChannel<I, O>
where
    I: Read + Write,
    O: Read + Write,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RpchGatewayChannel")
            .field("client_state", &self.client.state())
            .field("receive_pipe_call_id", &self.receive_pipe_call_id)
            .field("rx_buffer_len", &self.rx_buffer.len())
            .field("pipe_return", &self.pipe_return)
            .finish()
    }
}

impl<I, O> RpchGatewayChannel<I, O>
where
    I: Read + Write,
    O: Read + Write,
{
    /// Drive the full TsProxy connect sequence over an already-up
    /// RPC-over-HTTP tunnel:
    ///
    /// 1. DCE/RPC BIND / BIND_ACK (TsProxy v1.3 + NDR 2.0)
    /// 2. TsProxyCreateTunnel
    /// 3. TsProxyAuthorizeTunnel (PAA cookie if supplied, quarantine
    ///    `flags=0` with no SoH data otherwise)
    /// 4. TsProxyCreateChannel
    /// 5. TsProxySetupReceivePipe (REQUEST only — the pipe is a
    ///    streamed RESPONSE that this adapter consumes lazily as
    ///    the caller `read`s)
    ///
    /// Returns the channel ready for `read` / `write`.
    pub fn establish(
        mut tunnel: RpchTunnel<I, O>,
        options: ChannelOptions,
    ) -> Result<Self, ChannelError> {
        // Step 1: BIND / BIND_ACK.
        let bind_pdu = build_tsproxy_bind_pdu(1);
        tunnel.send_pdu(&bind_pdu).map_err(io_error_from_tunnel)?;
        let bind_ack = tunnel
            .recv_pdu()
            .map_err(io_error_from_tunnel)?
            .ok_or(ChannelError::UnexpectedEof)?;
        validate_tsproxy_bind_ack(&bind_ack)?;

        let mut client = TsProxyClient::with_context_id(TSPROXY_CONTEXT_ID);

        // Step 2: CreateTunnel (pick packet shape based on PAA).
        let create_tunnel_pkt = match options.paa_cookie.as_ref() {
            Some(cookie) => TsgPacket::Auth(TsgPacketAuth {
                version_caps: options.version_caps.clone(),
                cookie: cookie.as_bytes().to_vec(),
            }),
            None => TsgPacket::VersionCaps(options.version_caps.clone()),
        };
        let req = client.build_create_tunnel(&create_tunnel_pkt)?;
        tunnel.send_pdu(&req).map_err(io_error_from_tunnel)?;
        let resp = tunnel
            .recv_pdu()
            .map_err(io_error_from_tunnel)?
            .ok_or(ChannelError::UnexpectedEof)?;
        client.on_create_tunnel_response(&resp)?;

        // Step 3: AuthorizeTunnel. Minimal NAP-free QuarRequest.
        let quar = TsgPacket::QuarRequest(TsgPacketQuarRequest {
            flags: 0,
            machine_name: None,
            data: None,
        });
        let req = client.build_authorize_tunnel(&quar)?;
        tunnel.send_pdu(&req).map_err(io_error_from_tunnel)?;
        let resp = tunnel
            .recv_pdu()
            .map_err(io_error_from_tunnel)?
            .ok_or(ChannelError::UnexpectedEof)?;
        client.on_authorize_tunnel_response(&resp)?;

        // Step 4: CreateChannel.
        let req = client.build_create_channel(&options.endpoint)?;
        tunnel.send_pdu(&req).map_err(io_error_from_tunnel)?;
        let resp = tunnel
            .recv_pdu()
            .map_err(io_error_from_tunnel)?
            .ok_or(ChannelError::UnexpectedEof)?;
        client.on_create_channel_response(&resp)?;

        // Step 5: SetupReceivePipe (REQUEST only; no wait for
        // RESPONSE — those arrive lazily and carry RDP bytes).
        let pipe_pdu = client.build_setup_receive_pipe()?;
        let receive_pipe_call_id = extract_call_id(&pipe_pdu);
        tunnel.send_pdu(&pipe_pdu).map_err(io_error_from_tunnel)?;

        Ok(Self {
            tunnel,
            client,
            receive_pipe_call_id,
            rx_buffer: VecDeque::new(),
            pipe_return: None,
        })
    }

    /// Return the pipe's DWORD return value once the server has
    /// closed the stream, else `None`.
    pub fn pipe_return(&self) -> Option<u32> {
        self.pipe_return
    }

    /// Inspect the underlying TsProxy state machine.
    pub fn client(&self) -> &TsProxyClient {
        &self.client
    }

    /// Configure the byte threshold at which the tunnel signals
    /// that its IN stream needs to be replaced (MS-RPCH §3.2.2.3.3).
    /// A common choice is 75% of `channel_lifetime`.
    pub fn set_recycle_threshold(&mut self, bytes: u64) {
        self.tunnel.set_recycle_threshold(bytes);
    }

    /// Whether the configured recycle threshold has been crossed
    /// on the current IN stream.
    pub fn needs_in_channel_recycle(&self) -> bool {
        self.tunnel.needs_recycle()
    }

    /// Swap the IN stream for a fresh one the caller has already
    /// negotiated (new TCP + TLS + NTLM + HTTP 200). Emits the
    /// required `OutOfProcConnB3` RTS handshake on the new stream
    /// before switching — see [`justrdp_rpch::RpchTunnel::recycle_in_channel`].
    pub fn recycle_in_channel(
        &mut self,
        new_inbound: I,
        new_in_channel_cookie: justrdp_rpch::pdu::uuid::RpcUuid,
    ) -> Result<(), ChannelError> {
        self.tunnel
            .recycle_in_channel(new_inbound, new_in_channel_cookie)
            .map_err(io_error_from_tunnel)
    }

    /// Read PDUs from the OUT channel until either a RESPONSE
    /// carrying the SendToServer call_id arrives (returning it as
    /// `Ok(Some(dword))`) or, if `send_call_id` is `None`, until a
    /// pipe RESPONSE has been buffered / EOF'd. Pipe bytes are
    /// always buffered into `rx_buffer`.
    fn pump_until(
        &mut self,
        send_call_id: Option<u32>,
    ) -> Result<Option<u32>, ChannelError> {
        loop {
            let Some(pdu_bytes) = self
                .tunnel
                .recv_pdu()
                .map_err(io_error_from_tunnel)?
            else {
                return Err(ChannelError::UnexpectedEof);
            };
            let parsed = ResponsePdu::decode(&mut ReadCursor::new(&pdu_bytes))?;
            if parsed.call_id == self.receive_pipe_call_id {
                // Pipe traffic.
                if parsed.pfc_flags & PFC_LAST_FRAG != 0 {
                    // Final fragment: its stub_data is the 4-byte
                    // DWORD return value. Some servers send 0
                    // bytes here (treat as ERROR_SUCCESS).
                    let rv = if parsed.stub_data.len() >= 4 {
                        u32::from_le_bytes([
                            parsed.stub_data[0],
                            parsed.stub_data[1],
                            parsed.stub_data[2],
                            parsed.stub_data[3],
                        ])
                    } else {
                        0
                    };
                    self.pipe_return = Some(rv);
                } else {
                    self.rx_buffer.extend(parsed.stub_data.iter());
                }
                if send_call_id.is_none() {
                    // Called from `read` — any pipe traffic is
                    // actionable; return so the caller drains the
                    // buffer.
                    return Ok(None);
                }
                // Called from `write` — keep pumping until the
                // SendToServer RESPONSE arrives (its call_id
                // matches `send_call_id`).
            } else if Some(parsed.call_id) == send_call_id {
                // SendToServer's RESPONSE. stub_data is a 4-byte
                // DWORD on success; may be empty on some servers.
                let rv = if parsed.stub_data.len() >= 4 {
                    u32::from_le_bytes([
                        parsed.stub_data[0],
                        parsed.stub_data[1],
                        parsed.stub_data[2],
                        parsed.stub_data[3],
                    ])
                } else {
                    0
                };
                return Ok(Some(rv));
            } else {
                return Err(ChannelError::UnexpectedCallId(parsed.call_id));
            }
        }
    }
}

// =============================================================================
// Read / Write plumbing
// =============================================================================

impl<I, O> Read for RpchGatewayChannel<I, O>
where
    I: Read + Write,
    O: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Serve from buffer first.
        if self.rx_buffer.is_empty() && self.pipe_return.is_none() {
            // Pump until we either buffer more or see EOF.
            self.pump_until(None).map_err(to_io)?;
        }
        if self.rx_buffer.is_empty() {
            // EOF reached.
            return Ok(0);
        }
        let n = core::cmp::min(buf.len(), self.rx_buffer.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.rx_buffer.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl<I, O> Write for RpchGatewayChannel<I, O>
where
    I: Read + Write,
    O: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Build one SendToServer REQUEST containing the entire
        // buffer as buffer1. Larger writes are the caller's
        // responsibility to split.
        let pdu = self.client.build_send_to_server(&[buf]).map_err(|e| {
            to_io(ChannelError::TsProxy(e))
        })?;
        let call_id = extract_call_id(&pdu);
        self.tunnel
            .send_pdu(&pdu)
            .map_err(|e| to_io(io_error_from_tunnel(e)))?;
        // Wait for the SendToServer's RESPONSE, buffering any
        // interleaved pipe traffic for later `read`s.
        let rv = self
            .pump_until(Some(call_id))
            .map_err(to_io)?
            .expect("pump_until returns Some when send_call_id is Some");
        if rv != ERROR_SUCCESS {
            return Err(to_io(ChannelError::SendFailed(rv)));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Extract the `call_id` field (offset 12..16 of the common CO PDU
/// header) without fully decoding the PDU. Used after building a
/// REQUEST to remember its call_id for later response dispatch.
fn extract_call_id(pdu: &[u8]) -> u32 {
    debug_assert!(pdu.len() >= 16, "PDU shorter than common header");
    u32::from_le_bytes([pdu[12], pdu[13], pdu[14], pdu[15]])
}

/// Translate a `TunnelIoError` from `justrdp-rpch` into our
/// `ChannelError`. `TunnelIoError::Io` unwraps cleanly; everything
/// else is wrapped as a generic `io::Error` so the caller still
/// sees a single error type.
fn io_error_from_tunnel(e: justrdp_rpch::TunnelIoError) -> ChannelError {
    match e {
        justrdp_rpch::TunnelIoError::Io(io) => ChannelError::Io(io),
        other => ChannelError::Io(io::Error::other(alloc::format!("{other}"))),
    }
}

// =============================================================================
// Tests — end-to-end over a scripted fake tunnel
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use crate::rpch::errors::{ERROR_GRACEFUL_DISCONNECT, ERROR_SUCCESS};
    use crate::rpch::types::{
        ContextHandle, TsgPacketQuarEncResponse, TsgPacketResponse, TsgRedirectionFlags,
        TSG_NAP_CAPABILITY_QUAR_SOH,
    };
    use alloc::string::String;
    use alloc::vec;
    use justrdp_core::WriteCursor;
    use justrdp_rpch::pdu::{
        BindAckPdu, ContextResult, RtsCommand, RtsPdu, SyntaxId, BIND_ACK_PTYPE,
        PFC_FIRST_FRAG, RESULT_ACCEPTANCE, RTS_FLAG_NONE,
    };
    use justrdp_rpch::ndr::NdrEncoder;
    use justrdp_rpch::pdu::uuid::RpcUuid;
    use justrdp_rpch::{RpchTunnelConfig, RpchTunnel};
    use std::io::Cursor;

    /// Fake channel for tunnel tests — mirrors the one in
    /// `justrdp-rpch::blocking`.
    #[derive(Debug, Default)]
    struct FakeChannel {
        read_buf: Cursor<Vec<u8>>,
        write_buf: Vec<u8>,
    }

    impl FakeChannel {
        fn with_read(bytes: Vec<u8>) -> Self {
            Self {
                read_buf: Cursor::new(bytes),
                write_buf: Vec::new(),
            }
        }
    }

    impl Read for FakeChannel {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_buf.read(buf)
        }
    }

    impl Write for FakeChannel {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_buf.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn rts_encode(pdu: &RtsPdu) -> Vec<u8> {
        let mut out = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut out);
        pdu.encode(&mut w).unwrap();
        out
    }

    fn synthetic_a3() -> Vec<u8> {
        rts_encode(&RtsPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            flags: RTS_FLAG_NONE,
            commands: vec![
                RtsCommand::Version(1),
                RtsCommand::ReceiveWindowSize(65536),
            ],
        })
    }

    fn synthetic_c2() -> Vec<u8> {
        rts_encode(&RtsPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            flags: RTS_FLAG_NONE,
            commands: vec![
                RtsCommand::Version(1),
                RtsCommand::ReceiveWindowSize(65536),
                RtsCommand::ConnectionTimeout(120_000),
            ],
        })
    }

    fn tunnel_config() -> RpchTunnelConfig {
        RpchTunnelConfig {
            virtual_connection_cookie: RpcUuid::parse("11111111-1111-1111-1111-111111111111")
                .unwrap(),
            out_channel_cookie: RpcUuid::parse("22222222-2222-2222-2222-222222222222").unwrap(),
            in_channel_cookie: RpcUuid::parse("33333333-3333-3333-3333-333333333333").unwrap(),
            association_group_id: RpcUuid::parse("44444444-4444-4444-4444-444444444444").unwrap(),
            receive_window_size: 65536,
            channel_lifetime: 0x4000_0000,
            client_keepalive: 300_000,
        }
    }

    fn encode_response_pdu(call_id: u32, pfc: u8, stub: Vec<u8>) -> Vec<u8> {
        let resp = ResponsePdu {
            pfc_flags: pfc,
            call_id,
            alloc_hint: 0,
            context_id: 0,
            cancel_count: 0,
            stub_data: stub,
            auth: None,
        };
        let mut out = vec![0u8; resp.size()];
        let mut w = WriteCursor::new(&mut out);
        resp.encode(&mut w).unwrap();
        out
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

    fn sample_options() -> ChannelOptions {
        ChannelOptions {
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

    /// Assemble a scripted OUT stream containing all the PDUs the
    /// server must emit during `establish`, in order. Call IDs are
    /// chosen to match the client: the client's first REQUEST
    /// after BIND has call_id=1 (for BIND itself we use 1 too).
    fn out_stream_for_establish(
        include_pipe_data: Option<(&[u8], bool)>,
    ) -> Vec<u8> {
        // NOTE: client builds BIND with call_id=1, then the
        // TsProxyClient allocates call_ids starting at 1 for each
        // REQUEST. So the RPC-level REQUESTs are call_id 1..=5:
        //   1: CreateTunnel
        //   2: AuthorizeTunnel
        //   3: CreateChannel
        //   4: SetupReceivePipe
        //
        // But BIND itself was call_id=1 separately. The BIND_ACK's
        // call_id matches BIND's (1).
        let mut out = Vec::new();
        out.extend_from_slice(&synthetic_a3());
        out.extend_from_slice(&synthetic_c2());
        // BIND_ACK (call_id=1).
        out.extend_from_slice(&encode_bind_ack(1));
        // CreateTunnel RESPONSE (call_id=1 again — TsProxyClient
        // restarts counting).
        out.extend_from_slice(&encode_response_pdu(
            1,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            build_create_tunnel_response_stub(sample_tunnel_ctx(), 0xAAAA),
        ));
        // AuthorizeTunnel RESPONSE (call_id=2).
        out.extend_from_slice(&encode_response_pdu(
            2,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            build_authorize_tunnel_response_stub(),
        ));
        // CreateChannel RESPONSE (call_id=3).
        out.extend_from_slice(&encode_response_pdu(
            3,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            build_create_channel_response_stub(sample_channel_ctx()),
        ));
        // Optional scripted pipe RESPONSE (call_id=4 — the
        // SetupReceivePipe REQUEST we sent last).
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

    #[test]
    fn establish_succeeds_on_scripted_happy_path() {
        let out_bytes = out_stream_for_establish(None);
        let tunnel = RpchTunnel::connect(
            FakeChannel::default(),
            FakeChannel::with_read(out_bytes),
            tunnel_config(),
        )
        .unwrap();

        let channel = RpchGatewayChannel::establish(tunnel, sample_options()).unwrap();
        assert_eq!(
            channel.client().state(),
            crate::rpch::TsProxyState::PipeCreated
        );
        assert_eq!(channel.client().tunnel_context(), Some(&sample_tunnel_ctx()));
        assert_eq!(
            channel.client().channel_context(),
            Some(&sample_channel_ctx())
        );
    }

    #[test]
    fn read_returns_pipe_stub_data() {
        // Send one mid-stream pipe RESPONSE with 8 bytes of payload.
        let payload = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xF0, 0x0D];
        let out_bytes = out_stream_for_establish(Some((&payload, false)));
        let tunnel = RpchTunnel::connect(
            FakeChannel::default(),
            FakeChannel::with_read(out_bytes),
            tunnel_config(),
        )
        .unwrap();

        let mut channel = RpchGatewayChannel::establish(tunnel, sample_options()).unwrap();
        let mut buf = [0u8; 8];
        let n = channel.read(&mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(buf, payload);
    }

    #[test]
    fn read_returns_eof_on_final_pipe_fragment() {
        // Final RESPONSE: stub_data is 4 bytes of DWORD
        // ERROR_GRACEFUL_DISCONNECT, PFC_LAST_FRAG set.
        let final_stub = ERROR_GRACEFUL_DISCONNECT.to_le_bytes();
        let out_bytes = out_stream_for_establish(Some((&final_stub, true)));
        let tunnel = RpchTunnel::connect(
            FakeChannel::default(),
            FakeChannel::with_read(out_bytes),
            tunnel_config(),
        )
        .unwrap();
        let mut channel = RpchGatewayChannel::establish(tunnel, sample_options()).unwrap();

        let mut buf = [0u8; 16];
        // First read consumes the final RESPONSE → sets
        // pipe_return, buffer stays empty → returns 0 (EOF).
        let n = channel.read(&mut buf).unwrap();
        assert_eq!(n, 0);
        assert_eq!(channel.pipe_return(), Some(ERROR_GRACEFUL_DISCONNECT));
    }

    #[test]
    fn write_emits_send_to_server_and_consumes_its_response() {
        // Script the OUT stream to also include a SendToServer
        // RESPONSE with DWORD=0 at call_id=5 (next after pipe).
        let mut out = out_stream_for_establish(None);
        out.extend_from_slice(&encode_response_pdu(
            5,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            ERROR_SUCCESS.to_le_bytes().to_vec(),
        ));

        let tunnel = RpchTunnel::connect(
            FakeChannel::default(),
            FakeChannel::with_read(out),
            tunnel_config(),
        )
        .unwrap();
        let mut channel = RpchGatewayChannel::establish(tunnel, sample_options()).unwrap();

        let payload = b"rdp client hello";
        let n = channel.write(payload).unwrap();
        assert_eq!(n, payload.len());
    }

    #[test]
    fn write_empty_buffer_is_noop() {
        let out_bytes = out_stream_for_establish(None);
        let tunnel = RpchTunnel::connect(
            FakeChannel::default(),
            FakeChannel::with_read(out_bytes),
            tunnel_config(),
        )
        .unwrap();
        let mut channel = RpchGatewayChannel::establish(tunnel, sample_options()).unwrap();
        assert_eq!(channel.write(&[]).unwrap(), 0);
    }

    #[test]
    fn write_buffers_interleaved_pipe_data_before_send_response() {
        // Script OUT stream so that between establish and the
        // SendToServer RESPONSE (call_id=5) a pipe RESPONSE
        // fragment (call_id=4, 4 bytes, non-final) arrives first.
        // The write must return success AND the read that follows
        // must recover the pipe bytes that were buffered during
        // the wait.
        let mut out = out_stream_for_establish(None);
        out.extend_from_slice(&encode_response_pdu(
            4, // pipe call_id
            PFC_FIRST_FRAG,
            vec![0x10, 0x20, 0x30, 0x40],
        ));
        out.extend_from_slice(&encode_response_pdu(
            5, // SendToServer call_id
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            ERROR_SUCCESS.to_le_bytes().to_vec(),
        ));

        let tunnel = RpchTunnel::connect(
            FakeChannel::default(),
            FakeChannel::with_read(out),
            tunnel_config(),
        )
        .unwrap();
        let mut channel = RpchGatewayChannel::establish(tunnel, sample_options()).unwrap();

        let n = channel.write(b"hi").unwrap();
        assert_eq!(n, 2, "write must still succeed");

        // The interleaved pipe fragment must still be readable.
        let mut buf = [0u8; 4];
        assert_eq!(channel.read(&mut buf).unwrap(), 4);
        assert_eq!(buf, [0x10, 0x20, 0x30, 0x40]);
    }

    #[test]
    fn read_interleaves_pipe_data_and_returns_bytes() {
        // Stream two pipe RESPONSE fragments: 4 bytes, then 4 more
        // bytes, no final flag yet.
        let mut out = out_stream_for_establish(None);
        out.extend_from_slice(&encode_response_pdu(
            4,
            PFC_FIRST_FRAG,
            vec![0x01, 0x02, 0x03, 0x04],
        ));
        out.extend_from_slice(&encode_response_pdu(
            4,
            0,
            vec![0x05, 0x06, 0x07, 0x08],
        ));
        let tunnel = RpchTunnel::connect(
            FakeChannel::default(),
            FakeChannel::with_read(out),
            tunnel_config(),
        )
        .unwrap();
        let mut channel = RpchGatewayChannel::establish(tunnel, sample_options()).unwrap();

        let mut buf = [0u8; 4];
        assert_eq!(channel.read(&mut buf).unwrap(), 4);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(channel.read(&mut buf).unwrap(), 4);
        assert_eq!(buf, [0x05, 0x06, 0x07, 0x08]);
    }
}
