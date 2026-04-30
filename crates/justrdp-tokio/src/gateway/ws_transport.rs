#![forbid(unsafe_code)]

//! Async port of `justrdp_gateway::ws_transport::WsGatewayConnection`.
//!
//! `TsguWsTransport<T>` wraps a single already-upgraded WebSocket
//! [`WebTransport`] (typically a `NativeTlsTransport` whose HTTP/1.1
//! Upgrade handshake just completed via [`authenticate_ws_channel`])
//! and exposes a [`WebTransport`] surface whose payloads are RDP
//! bytes. WebSocket framing, MS-TSGU `HTTP_DATA_PACKET` envelopes,
//! and Ping/Pong/Close handling are all internal.
//!
//! Differences from the HTTP variant ([`TsguHttpTransport`]):
//!
//! * One stream instead of an IN/OUT pair.
//! * No 100-byte preamble.
//! * RFC 6455 binary frames instead of HTTP chunked encoding.
//! * Each client-to-server frame is masked with a fresh 4-byte
//!   random key (RFC 6455 §5.3).
//!
//! The same `GatewayClient` state machine drives the inner MS-TSGU
//! handshake — only the framing and the I/O are different.
//!
//! [`authenticate_ws_channel`]: super::ws_auth::authenticate_ws_channel
//! [`TsguHttpTransport`]: super::http_transport::TsguHttpTransport

use alloc::format;
use alloc::vec::Vec;

use justrdp_async::{TransportError, WebTransport};
use justrdp_core::{Decode, ReadCursor, WriteBuf};
use justrdp_gateway::ws::{
    encode_close_payload, encode_frame, WsFrame, WsFrameDecoder, WS_CLOSE_NORMAL, WS_OPCODE_BINARY,
    WS_OPCODE_CLOSE, WS_OPCODE_PONG,
};
use justrdp_gateway::{find_packet_size, DataPdu, GatewayClient, DATA_PACKET_MIN_SIZE};

use super::error::{gw_err, http_err};

/// Async MS-TSGU WebSocket Transport adapter.
pub struct TsguWsTransport<T: WebTransport> {
    client: GatewayClient,
    stream: T,
    decoder: WsFrameDecoder,
    /// Bytes from server-side Binary frames waiting to be parsed
    /// into MS-TSGU PDUs.
    decoded: Vec<u8>,
    /// Sticky once Close has been observed in either direction.
    closed: bool,
}

impl<T: WebTransport> core::fmt::Debug for TsguWsTransport<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TsguWsTransport")
            .field("decoded_len", &self.decoded.len())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl<T: WebTransport + Send> TsguWsTransport<T> {
    /// Drive `client` through the MS-TSGU
    /// Handshake / TunnelCreate / TunnelAuth / ChannelCreate sequence
    /// over the supplied WebSocket stream, then return a transport
    /// ready for byte-level RDP I/O.
    ///
    /// `stream` MUST already be past the HTTP/1.1 `101 Switching
    /// Protocols` boundary — i.e. the next bytes the caller reads
    /// off it are WebSocket frames. `leftover` carries the bytes
    /// [`authenticate_ws_channel`] already pulled past the response
    /// headers (the start of the first server-side WS frame).
    ///
    /// [`authenticate_ws_channel`]: super::ws_auth::authenticate_ws_channel
    pub async fn connect(
        client: GatewayClient,
        stream: T,
        leftover: Vec<u8>,
    ) -> Result<Self, TransportError> {
        let mut transport = Self {
            client,
            stream,
            decoder: WsFrameDecoder::new(),
            decoded: Vec::new(),
            closed: false,
        };

        // Replay auth-phase leftover bytes through the WS frame
        // decoder so the handshake pump starts reading at the same
        // offset both client and server agree on.
        if !leftover.is_empty() {
            transport.absorb_ws_bytes(&leftover).await?;
        }

        let mut out_buf = WriteBuf::new();
        while !transport.client.is_connected() {
            if transport.client.is_send_state() {
                transport
                    .client
                    .step(&[], &mut out_buf)
                    .map_err(gw_err)?;
                send_binary_frame(&mut transport.stream, out_buf.as_slice()).await?;
            } else if transport.client.is_wait_state() {
                let pdu = transport.pump_one_pdu().await?;
                transport
                    .client
                    .step(&pdu, &mut out_buf)
                    .map_err(gw_err)?;
            } else {
                return Err(http_err(
                    "MS-TSGU state machine reached terminal state mid-ws-handshake",
                ));
            }
        }

        Ok(transport)
    }

    /// Borrow the underlying [`GatewayClient`].
    pub fn client(&self) -> &GatewayClient {
        &self.client
    }

    /// Feed bytes through the WebSocket decoder, handling control
    /// frames inline (Ping → Pong, Close → echo + sticky closed) and
    /// pushing Binary payloads into `decoded`.
    async fn absorb_ws_bytes(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        let frames = self
            .decoder
            .feed(bytes)
            .map_err(|e| http_err(format!("ws frame decode: {e:?}")))?;
        for frame in frames {
            match frame {
                WsFrame::Binary(bytes) => self.decoded.extend_from_slice(&bytes),
                WsFrame::Ping(payload) => {
                    send_control_frame(&mut self.stream, WS_OPCODE_PONG, &payload).await?;
                }
                WsFrame::Pong(_) => { /* discard */ }
                WsFrame::Close { .. } => {
                    // RFC 6455 §5.5.1: echo + treat as closed. Mark
                    // closed first so a failing echo doesn't double-
                    // close. Existing decoded bytes are still served
                    // by `recv()` before the next call returns
                    // ConnectionClosed.
                    self.closed = true;
                    let payload = encode_close_payload(Some(WS_CLOSE_NORMAL), "");
                    let _ = send_control_frame(&mut self.stream, WS_OPCODE_CLOSE, &payload).await;
                }
            }
        }
        Ok(())
    }

    /// Pull a single complete MS-TSGU PDU out of the stream. Used
    /// during the handshake pump only — `recv()` inlines a similar
    /// loop with a `parse_data_pdu` step at the end.
    async fn pump_one_pdu(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            if let Some(size) = find_packet_size(&self.decoded)
                .map_err(|e| http_err(format!("gateway packet size: {e}")))?
            {
                if self.decoded.len() >= size {
                    let pdu: Vec<u8> = self.decoded.drain(..size).collect();
                    return Ok(pdu);
                }
            }
            if self.closed {
                return Err(TransportError::closed("tsgu-ws: server closed mid-pdu"));
            }
            let chunk = self.stream.recv().await?;
            self.absorb_ws_bytes(&chunk).await?;
        }
    }
}

/// Send `payload` as one WebSocket Binary frame with FIN=1 and a
/// fresh random 4-byte mask. RFC 6455 §5.3 requires masking on every
/// client-to-server frame; the mask is regenerated from the OS RNG
/// each call.
async fn send_binary_frame<T: WebTransport>(
    stream: &mut T,
    payload: &[u8],
) -> Result<(), TransportError> {
    let mask = make_mask()?;
    let mut frame = Vec::with_capacity(payload.len() + 16);
    encode_frame(WS_OPCODE_BINARY, true, payload, mask, &mut frame)
        .map_err(|e| http_err(format!("ws encode binary frame: {e:?}")))?;
    stream.send(&frame).await
}

async fn send_control_frame<T: WebTransport>(
    stream: &mut T,
    opcode: u8,
    payload: &[u8],
) -> Result<(), TransportError> {
    let mask = make_mask()?;
    let mut frame = Vec::with_capacity(payload.len() + 14);
    encode_frame(opcode, true, payload, mask, &mut frame)
        .map_err(|e| http_err(format!("ws encode control frame: {e:?}")))?;
    stream.send(&frame).await
}

fn make_mask() -> Result<[u8; 4], TransportError> {
    let mut mask = [0u8; 4];
    getrandom::getrandom(&mut mask)
        .map_err(|e| TransportError::io(format!("OS random failure: {e}")))?;
    Ok(mask)
}

/// Decode a single `HTTP_DATA_PACKET` PDU and return its inner RDP
/// bytes. Same helper as in the HTTP transport — duplicated rather
/// than shared because both modules want their own ctx string and
/// the helper is six lines.
fn parse_data_pdu(bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
    if bytes.len() < DATA_PACKET_MIN_SIZE {
        return Err(http_err("ws data pdu: short header"));
    }
    let mut cur = ReadCursor::new(bytes);
    let pdu = DataPdu::decode(&mut cur).map_err(|e| http_err(format!("ws data pdu decode: {e}")))?;
    Ok(pdu.data)
}

impl<T: WebTransport + Send> WebTransport for TsguWsTransport<T> {
    async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::closed("tsgu-ws: already closed"));
        }
        if bytes.is_empty() {
            return Ok(());
        }
        if bytes.len() > u16::MAX as usize {
            return Err(http_err(format!(
                "gateway ws send {} bytes exceeds HTTP_DATA_PACKET u16 limit",
                bytes.len()
            )));
        }
        let mut out_buf = WriteBuf::new();
        self.client
            .encode_data(bytes, &mut out_buf)
            .map_err(gw_err)?;
        send_binary_frame(&mut self.stream, out_buf.as_slice()).await
    }

    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.closed && self.decoded.is_empty() {
            return Err(TransportError::closed("tsgu-ws: already closed"));
        }
        loop {
            if let Some(size) = find_packet_size(&self.decoded)
                .map_err(|e| http_err(format!("gateway packet size: {e}")))?
            {
                if self.decoded.len() >= size {
                    let pdu_bytes: Vec<u8> = self.decoded.drain(..size).collect();
                    return parse_data_pdu(&pdu_bytes);
                }
            }
            if self.closed {
                return Err(TransportError::closed(
                    "tsgu-ws: server closed before next pdu",
                ));
            }
            let chunk = match self.stream.recv().await {
                Ok(b) => b,
                Err(e) => {
                    self.closed = true;
                    return Err(e);
                }
            };
            self.absorb_ws_bytes(&chunk).await?;
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let mut out_buf = WriteBuf::new();
        if self.client.encode_close(&mut out_buf).is_ok() {
            let _ = send_binary_frame(&mut self.stream, out_buf.as_slice()).await;
        }
        let payload = encode_close_payload(Some(WS_CLOSE_NORMAL), "");
        let _ = send_control_frame(&mut self.stream, WS_OPCODE_CLOSE, &payload).await;
        let _ = self.stream.close().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::vec;
    use justrdp_async::TransportErrorKind;
    use justrdp_core::Encode;
    use justrdp_gateway::{
        ChannelResponsePdu, GatewayClientConfig, HandshakeResponsePdu, HttpUnicodeString,
        TunnelAuthResponsePdu, TunnelResponsePdu, HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
        HTTP_EXTENDED_AUTH_NONE, HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT,
        HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS, HTTP_TUNNEL_REDIR_DISABLE_ALL,
        HTTP_TUNNEL_RESPONSE_FIELD_CAPS, HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID, STATUS_SUCCESS,
    };

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

    fn encode<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut cur = justrdp_core::WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        buf
    }

    /// Wrap one MS-TSGU PDU as one server-side WebSocket Binary
    /// frame (FIN=1, no mask). Server-to-client frames are unmasked
    /// per RFC 6455 §5.3.
    fn server_binary_frame(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x80 | WS_OPCODE_BINARY);
        let len = payload.len();
        if len <= 125 {
            out.push(len as u8);
        } else if len <= u16::MAX as usize {
            out.push(126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    fn fake_handshake_frames(trailing_data: &[&[u8]]) -> Vec<u8> {
        let mut all = Vec::new();
        all.extend(server_binary_frame(&encode(&HandshakeResponsePdu::ok(
            HTTP_EXTENDED_AUTH_NONE,
        ))));
        all.extend(server_binary_frame(&encode(&TunnelResponsePdu {
            server_version: 1,
            status_code: STATUS_SUCCESS,
            fields_present: HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID
                | HTTP_TUNNEL_RESPONSE_FIELD_CAPS,
            tunnel_id: 0xFEED_BEEF,
            caps_flags: 0x3F,
            nonce: [0; 16],
            server_cert: HttpUnicodeString::empty(),
            consent_msg: HttpUnicodeString::empty(),
        })));
        all.extend(server_binary_frame(&encode(&TunnelAuthResponsePdu {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS
                | HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT,
            redir_flags: HTTP_TUNNEL_REDIR_DISABLE_ALL,
            idle_timeout_minutes: 30,
            soh_response: None,
        })));
        all.extend(server_binary_frame(&encode(&ChannelResponsePdu {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
            channel_id: 7,
            udp_port: 0,
            authn_cookie: None,
        })));
        for payload in trailing_data {
            all.extend(server_binary_frame(&encode(&DataPdu::new(payload.to_vec()))));
        }
        all
    }

    fn fresh_client() -> GatewayClient {
        GatewayClient::new(GatewayClientConfig {
            target_host: "rdp.example.com".into(),
            target_port: 3389,
            client_name: "gw.example.com".into(),
            client_caps: GatewayClientConfig::default_caps(),
            paa_cookie: None,
        })
    }

    #[tokio::test]
    async fn connect_drives_handshake_over_one_ws_stream() {
        let stream = ScriptedTransport::from_script(fake_handshake_frames(&[]));
        let transport = TsguWsTransport::connect(fresh_client(), stream, Vec::new())
            .await
            .unwrap();
        // Four client request PDUs sent as four masked Binary frames.
        assert_eq!(transport.stream.sent.len(), 4);
        assert_eq!(transport.client.tunnel_id(), 0xFEED_BEEF);
    }

    #[tokio::test]
    async fn connect_consumes_leftover_before_first_recv() {
        let mut all = fake_handshake_frames(&[]);
        let split = all.len() / 2;
        let leftover = all.drain(..split).collect::<Vec<u8>>();
        let stream = ScriptedTransport::from_script(all);
        let transport = TsguWsTransport::connect(fresh_client(), stream, leftover)
            .await
            .unwrap();
        assert!(transport.client.is_connected());
    }

    #[tokio::test]
    async fn send_after_handshake_emits_one_masked_binary_frame() {
        let stream = ScriptedTransport::from_script(fake_handshake_frames(&[]));
        let mut transport = TsguWsTransport::connect(fresh_client(), stream, Vec::new())
            .await
            .unwrap();
        let before = transport.stream.sent.len();
        transport.send(b"PAYLOAD").await.unwrap();
        assert_eq!(transport.stream.sent.len(), before + 1);
        let frame = transport.stream.sent.last().unwrap();
        // First byte: FIN=1, opcode=Binary (0x82).
        assert_eq!(frame[0], 0x80 | WS_OPCODE_BINARY);
        // MASK bit must be set on a client-to-server frame.
        assert_ne!(frame[1] & 0x80, 0);
    }

    #[tokio::test]
    async fn recv_returns_data_pdu_payloads_in_order() {
        let stream =
            ScriptedTransport::from_script(fake_handshake_frames(&[b"FIRST", b"SECOND"]));
        let mut transport = TsguWsTransport::connect(fresh_client(), stream, Vec::new())
            .await
            .unwrap();
        let p1 = transport.recv().await.unwrap();
        let p2 = transport.recv().await.unwrap();
        assert_eq!(p1.as_slice(), b"FIRST");
        assert_eq!(p2.as_slice(), b"SECOND");
    }

    #[tokio::test]
    async fn send_oversize_returns_protocol_error() {
        let stream = ScriptedTransport::from_script(fake_handshake_frames(&[]));
        let mut transport = TsguWsTransport::connect(fresh_client(), stream, Vec::new())
            .await
            .unwrap();
        let too_big = vec![0u8; (u16::MAX as usize) + 1];
        let err = transport.send(&too_big).await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[tokio::test]
    async fn send_empty_is_a_noop() {
        let stream = ScriptedTransport::from_script(fake_handshake_frames(&[]));
        let mut transport = TsguWsTransport::connect(fresh_client(), stream, Vec::new())
            .await
            .unwrap();
        let before = transport.stream.sent.len();
        transport.send(&[]).await.unwrap();
        assert_eq!(transport.stream.sent.len(), before);
    }

    #[tokio::test]
    async fn close_emits_close_pdu_and_close_frame_then_short_circuits() {
        let stream = ScriptedTransport::from_script(fake_handshake_frames(&[]));
        let mut transport = TsguWsTransport::connect(fresh_client(), stream, Vec::new())
            .await
            .unwrap();
        transport.close().await.unwrap();
        let err = transport.send(b"x").await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
        let err = transport.recv().await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
        // Idempotent.
        transport.close().await.unwrap();
    }

    #[tokio::test]
    async fn server_close_frame_marks_transport_closed() {
        // Drive past handshake, then push a server-side Close frame.
        let mut all = fake_handshake_frames(&[]);
        // Server Close frame: FIN=1, opcode=8 (Close), no payload.
        all.push(0x80 | WS_OPCODE_CLOSE);
        all.push(0); // length=0
        let stream = ScriptedTransport::from_script(all);
        let mut transport = TsguWsTransport::connect(fresh_client(), stream, Vec::new())
            .await
            .unwrap();
        // Next recv should surface ConnectionClosed.
        let err = transport.recv().await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
    }
}
