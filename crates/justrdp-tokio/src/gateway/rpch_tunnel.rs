#![forbid(unsafe_code)]

//! Async port of `justrdp_rpch::blocking::RpchTunnel`.
//!
//! Drives the MS-RPCH §3.2.1.5 CONN/A/B/C handshake over a paired
//! IN / OUT [`WebTransport`] couple (typically two TLS sessions
//! freshly authenticated via [`authenticate_rpch_channel`]) and then
//! exposes a `send_pdu` / `recv_pdu` byte interface for the
//! [`TsguRpchTransport`] (G10) layer above.
//!
//! The state machine itself ([`RpchTunnelState`]) is no_std and
//! reused unmodified from `justrdp-rpch`. Only the I/O is async.
//!
//! [`authenticate_rpch_channel`]: super::rpch_auth::authenticate_rpch_channel
//! [`TsguRpchTransport`]: super::ws_transport
//                                 ^ G10 follow-up

use alloc::format;
use alloc::vec::Vec;

use justrdp_async::{TransportError, TransportErrorKind, WebTransport};
use justrdp_rpch::pdu::common::COMMON_HEADER_SIZE;
use justrdp_rpch::tunnel::{
    peek_frag_length, HandshakeStage, OutboundAction, RpchTunnelConfig, RpchTunnelState,
};

use super::error::http_err;

/// Async paired-channel adapter that owns the IN / OUT [`WebTransport`]s
/// and the [`RpchTunnelState`] state machine.
///
/// Construct via [`Self::connect`]; once that returns the virtual
/// connection is past CONN/A/B/C and ready for DCE/RPC byte I/O via
/// [`Self::send_pdu`] / [`Self::recv_pdu`].
pub struct TsguRpchTunnel<TIn, TOut>
where
    TIn: WebTransport + Send,
    TOut: WebTransport + Send,
{
    /// IN channel — `RPC_IN_DATA` request body. Client → server PDUs
    /// are emitted here.
    inbound: TIn,
    /// OUT channel — `RPC_OUT_DATA` response body. Server → client
    /// PDUs (RTS + DCE/RPC RESPONSE) arrive here.
    outbound: TOut,
    state: RpchTunnelState,
    /// Bytes received from `outbound.recv()` but not yet parsed into
    /// a complete CO PDU.
    out_buffer: Vec<u8>,
}

impl<TIn, TOut> core::fmt::Debug for TsguRpchTunnel<TIn, TOut>
where
    TIn: WebTransport + Send,
    TOut: WebTransport + Send,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TsguRpchTunnel")
            .field("stage", &self.state.stage())
            .field("out_buffer_len", &self.out_buffer.len())
            .finish_non_exhaustive()
    }
}

impl<TIn, TOut> TsguRpchTunnel<TIn, TOut>
where
    TIn: WebTransport + Send,
    TOut: WebTransport + Send,
{
    /// Drive the CONN/A1 → A3 → C2 handshake.
    ///
    /// Writes CONN/A1 onto `outbound.send` (the OUT channel request
    /// body), CONN/B1 onto `inbound.send` (the IN channel request
    /// body), then reads server-side RTS PDUs off `outbound.recv`
    /// until the state machine reaches [`HandshakeStage::Ready`].
    ///
    /// `out_leftover` carries the bytes
    /// [`authenticate_rpch_channel`] already pulled past the OUT
    /// channel's `200 OK` headers — they are fed into the framing
    /// loop before any new `recv()` call so no boundary is lost
    /// across the auth/handshake hand-off.
    ///
    /// [`authenticate_rpch_channel`]: super::rpch_auth::authenticate_rpch_channel
    pub async fn connect(
        mut inbound: TIn,
        mut outbound: TOut,
        cfg: RpchTunnelConfig,
        out_leftover: Vec<u8>,
    ) -> Result<Self, TransportError> {
        let mut state = RpchTunnelState::new(cfg);

        let a1 = state.build_conn_a1();
        outbound
            .send(&a1)
            .await
            .map_err(|e| http_err(format!("rpch CONN/A1 send: {e}")))?;
        let b1 = state.build_conn_b1();
        inbound
            .send(&b1)
            .await
            .map_err(|e| http_err(format!("rpch CONN/B1 send: {e}")))?;

        let mut out_buffer = out_leftover;
        while state.stage() != HandshakeStage::Ready {
            let pdu = pump_one_pdu(&mut outbound, &mut out_buffer)
                .await?
                .ok_or_else(|| {
                    http_err(format!(
                        "rpch tunnel: unexpected EOF at handshake stage {:?}",
                        state.stage()
                    ))
                })?;
            match state
                .feed_out_pdu(&pdu)
                .map_err(|e| http_err(format!("rpch tunnel: {e}")))?
            {
                OutboundAction::HandshakeProgress | OutboundAction::Ping => {}
                OutboundAction::DataPdu(_) => {
                    return Err(http_err(
                        "rpch tunnel: unexpected DCE/RPC data PDU during handshake",
                    ));
                }
                OutboundAction::FlowControlAck { .. } => {
                    // Legal per §3.2.2.1; ignored during handshake.
                }
            }
        }

        Ok(Self {
            inbound,
            outbound,
            state,
            out_buffer,
        })
    }

    /// Borrow the underlying state machine — exposed for metrics /
    /// inspection (handshake stage, bytes_received).
    pub fn state(&self) -> &RpchTunnelState {
        &self.state
    }

    /// Write one complete DCE/RPC PDU to the IN channel.
    ///
    /// One `WebTransport::send` call → one logical PDU. The MS-TSGU
    /// gateway demands clean PDU boundaries on the IN body; partial
    /// fragments are not allowed. Caller-side fragmentation (REQUEST
    /// `frag_length` <= `max_xmit_frag`) is the upper layer's
    /// responsibility — this adapter passes bytes through as-is.
    pub async fn send_pdu(&mut self, pdu: &[u8]) -> Result<(), TransportError> {
        self.inbound.send(pdu).await
    }

    /// Read one complete DCE/RPC data PDU off the OUT channel.
    ///
    /// Server-originated RTS (FlowControlAck, Ping, …) is consumed
    /// transparently and absorbed: this call keeps reading until a
    /// non-RTS PDU arrives or the stream closes cleanly. A clean
    /// close at a PDU boundary surfaces as `Ok(None)`.
    ///
    /// If the state machine reports a flow-ack is due after the
    /// returned data PDU, the ack is emitted on the IN channel
    /// before returning so the server's send window stays open.
    pub async fn recv_pdu(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        loop {
            let Some(pdu) = pump_one_pdu(&mut self.outbound, &mut self.out_buffer).await? else {
                return Ok(None);
            };
            match self
                .state
                .feed_out_pdu(&pdu)
                .map_err(|e| http_err(format!("rpch tunnel: {e}")))?
            {
                OutboundAction::DataPdu(data) => {
                    if let Some(ack) = self.state.flow_ack_if_due() {
                        self.inbound.send(&ack).await?;
                    }
                    return Ok(Some(data));
                }
                OutboundAction::HandshakeProgress
                | OutboundAction::FlowControlAck { .. }
                | OutboundAction::Ping => {
                    // Absorb and keep reading.
                }
            }
        }
    }
}

/// Pull one complete CO PDU off `transport`, drawing fresh bytes via
/// `recv()` as needed. Returns `Ok(None)` when the stream closes
/// cleanly at a PDU boundary; returns an error if EOF lands mid-PDU
/// or a malformed common header is observed.
async fn pump_one_pdu<T: WebTransport>(
    transport: &mut T,
    buffer: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, TransportError> {
    loop {
        if buffer.len() >= COMMON_HEADER_SIZE {
            let frag = peek_frag_length(&buffer[..COMMON_HEADER_SIZE])
                .map_err(|e| http_err(format!("rpch common header: {e}")))?
                .ok_or_else(|| http_err("rpch common header: unparseable frag_length"))?;
            let frag = frag as usize;
            if frag < COMMON_HEADER_SIZE {
                return Err(http_err(format!(
                    "rpch common header: frag_length {frag} below header size"
                )));
            }
            if buffer.len() >= frag {
                let pdu: Vec<u8> = buffer.drain(..frag).collect();
                return Ok(Some(pdu));
            }
        }
        let chunk = match transport.recv().await {
            Ok(b) => b,
            Err(e) if e.kind() == TransportErrorKind::ConnectionClosed => {
                return if buffer.is_empty() {
                    Ok(None)
                } else {
                    Err(http_err(format!(
                        "rpch tunnel: peer closed mid-PDU ({} buffered bytes)",
                        buffer.len()
                    )))
                };
            }
            Err(e) => return Err(e),
        };
        if chunk.is_empty() {
            return if buffer.is_empty() {
                Ok(None)
            } else {
                Err(http_err("rpch tunnel: peer closed mid-PDU"))
            };
        }
        buffer.extend_from_slice(&chunk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::vec;
    use justrdp_core::WriteCursor;
    use justrdp_rpch::pdu::uuid::RpcUuid;
    use justrdp_rpch::pdu::{
        PFC_FIRST_FRAG, PFC_LAST_FRAG, RTS_FLAG_NONE, RTS_FLAG_OTHER_CMD,
    };
    use justrdp_rpch::pdu::{RtsCommand, RtsPdu};

    /// Same scripted-WebTransport helper as in the other gateway
    /// modules. Local copy so tests own their fixtures.
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

    fn encode_rts(pdu: &RtsPdu) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        buf
    }

    fn test_config() -> RpchTunnelConfig {
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

    /// One complete OUT-channel server response stream: A3 + C2.
    /// Used for happy-path handshake tests.
    fn happy_a3_c2() -> Vec<u8> {
        let mut all = Vec::new();
        all.extend_from_slice(&synthetic_a3());
        all.extend_from_slice(&synthetic_c2());
        all
    }

    /// Build a synthetic DCE/RPC RESPONSE-shaped PDU. Only the
    /// common header fields the tunnel state machine inspects are
    /// filled in; the body is opaque bytes.
    fn synthetic_data_pdu(payload: &[u8]) -> Vec<u8> {
        // CommonHeader: rpc_vers=5, rpc_vers_minor=0, ptype=0x02
        // (RESPONSE), pfc_flags=03 (FIRST|LAST), packed_drep=
        // [0x10,0,0,0] (little endian, ASCII, IEEE), frag_length,
        // auth_length=0, call_id=1.
        let frag_length = (16 + payload.len()) as u16;
        let mut pdu = Vec::with_capacity(frag_length as usize);
        pdu.push(5); // rpc_vers
        pdu.push(0); // rpc_vers_minor
        pdu.push(0x02); // PTYPE = RESPONSE (any non-RTS works)
        pdu.push(PFC_FIRST_FRAG | PFC_LAST_FRAG);
        pdu.extend_from_slice(&[0x10, 0, 0, 0]); // drep
        pdu.extend_from_slice(&frag_length.to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
        pdu.extend_from_slice(&1u32.to_le_bytes()); // call_id
        pdu.extend_from_slice(payload);
        pdu
    }

    #[tokio::test]
    async fn connect_drives_a1_b1_send_and_a3_c2_read() {
        let outbound = ScriptedTransport::from_script(happy_a3_c2());
        let inbound = ScriptedTransport::empty();
        let tunnel =
            TsguRpchTunnel::connect(inbound, outbound, test_config(), Vec::new())
                .await
                .unwrap();
        assert_eq!(tunnel.state.stage(), HandshakeStage::Ready);
        // CONN/A1 went out on outbound (OUT channel request body),
        // CONN/B1 on inbound (IN channel request body).
        assert_eq!(tunnel.outbound.sent.len(), 1);
        assert_eq!(tunnel.inbound.sent.len(), 1);
        // Both PDUs MUST be RTS (ptype=0x14 at byte offset 2).
        assert_eq!(tunnel.outbound.sent[0][2], 0x14);
        assert_eq!(tunnel.inbound.sent[0][2], 0x14);
    }

    #[tokio::test]
    async fn connect_consumes_out_leftover_before_first_recv() {
        // Half the OUT response body lives in the auth-phase leftover;
        // the rest comes from the next recv().
        let mut all = happy_a3_c2();
        let split = all.len() / 2;
        let leftover = all.drain(..split).collect::<Vec<u8>>();
        let outbound = ScriptedTransport::from_script(all);
        let inbound = ScriptedTransport::empty();
        let tunnel = TsguRpchTunnel::connect(inbound, outbound, test_config(), leftover)
            .await
            .unwrap();
        assert_eq!(tunnel.state.stage(), HandshakeStage::Ready);
    }

    #[tokio::test]
    async fn connect_fails_on_premature_eof() {
        // OUT channel returns nothing — handshake can't progress.
        let outbound = ScriptedTransport::empty();
        let inbound = ScriptedTransport::empty();
        let err =
            TsguRpchTunnel::connect(inbound, outbound, test_config(), Vec::new())
                .await
                .unwrap_err();
        // EOF mid-handshake surfaces as Protocol (we wrap as
        // http_err which is Protocol-class).
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[tokio::test]
    async fn recv_pdu_returns_data_pdu_and_filters_rts() {
        // Build OUT stream containing: A3, C2, a FlowControlAck RTS,
        // and finally a synthetic RESPONSE-shaped PDU.
        let ack = encode_rts(&RtsPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            flags: RTS_FLAG_OTHER_CMD,
            commands: vec![
                RtsCommand::Destination(2),
                RtsCommand::FlowControlAck {
                    bytes_received: 1024,
                    available_window: 65536,
                    channel_cookie: RpcUuid::parse("22222222-2222-2222-2222-222222222222")
                        .unwrap(),
                },
            ],
        });
        let data = synthetic_data_pdu(b"DCE-RPC-DATA");
        let mut all = happy_a3_c2();
        all.extend_from_slice(&ack);
        all.extend_from_slice(&data);

        let outbound = ScriptedTransport::from_script(all);
        let inbound = ScriptedTransport::empty();
        let mut tunnel =
            TsguRpchTunnel::connect(inbound, outbound, test_config(), Vec::new())
                .await
                .unwrap();
        let received = tunnel.recv_pdu().await.unwrap().expect("data PDU expected");
        // recv_pdu returns the entire raw PDU bytes, including the
        // 16-byte common header.
        assert_eq!(received.len(), 16 + b"DCE-RPC-DATA".len());
        assert_eq!(&received[16..], b"DCE-RPC-DATA");
    }

    #[tokio::test]
    async fn recv_pdu_clean_eof_returns_none() {
        let outbound = ScriptedTransport::from_script(happy_a3_c2());
        let inbound = ScriptedTransport::empty();
        let mut tunnel =
            TsguRpchTunnel::connect(inbound, outbound, test_config(), Vec::new())
                .await
                .unwrap();
        // No more bytes scripted; recv() will surface Closed which
        // pump_one_pdu translates to Ok(None) at PDU boundary.
        let none = tunnel.recv_pdu().await.unwrap();
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn send_pdu_writes_to_inbound_channel() {
        let outbound = ScriptedTransport::from_script(happy_a3_c2());
        let inbound = ScriptedTransport::empty();
        let mut tunnel =
            TsguRpchTunnel::connect(inbound, outbound, test_config(), Vec::new())
                .await
                .unwrap();
        let payload = synthetic_data_pdu(b"CLIENT-REQ");
        tunnel.send_pdu(&payload).await.unwrap();
        // First IN write was CONN/B1 during handshake; second is our
        // DCE/RPC PDU.
        assert_eq!(tunnel.inbound.sent.len(), 2);
        assert_eq!(tunnel.inbound.sent[1], payload);
    }
}
