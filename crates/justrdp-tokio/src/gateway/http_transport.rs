#![forbid(unsafe_code)]

//! Async port of `justrdp_gateway::transport::GatewayConnection`.
//!
//! `TsguHttpTransport<T>` wraps two already-authenticated
//! [`WebTransport`] streams (one for the `RDG_OUT_DATA` channel, one
//! for `RDG_IN_DATA`) and presents a single `WebTransport` whose
//! payloads are RDP bytes. The MS-TSGU framing — chunked HTTP body,
//! 100-byte OUT preamble, [`HTTP_DATA_PACKET`] envelopes — is handled
//! entirely inside this type, so the layers above (the connector,
//! `WebClient`, etc.) see a flat byte pipe.
//!
//! The state machine itself comes from
//! [`justrdp_gateway::GatewayClient`], which is `no_std + alloc` and
//! shared verbatim with the blocking adapter. Only the I/O is async.
//!
//! ### Cancel safety
//!
//! `send` is **not** cancel-safe under cancellation between the
//! `encode_data` step and the inner `in_writer.send` write — if the
//! future is dropped after `encode_data` advanced the state machine
//! but before the bytes hit the wire, the gateway's view diverges from
//! ours. The `WebClient` driver does not cancel mid-send, but
//! embedders that wrap this transport in their own `select!` should
//! not race `send` against a cancellation token. `recv` is cancel-safe
//! by construction (no state mutation before the first awaitable
//! progress).
//!
//! [`HTTP_DATA_PACKET`]: justrdp_gateway::DataPdu

use alloc::format;
use alloc::vec::Vec;

use justrdp_async::{TransportError, WebTransport};
use justrdp_core::{Decode, ReadCursor, WriteBuf};
use justrdp_gateway::{
    encode_chunk, encode_final_chunk, find_packet_size, ChunkedDecoder, DataPdu, GatewayClient,
    PreambleSkipper, DATA_PACKET_MIN_SIZE,
};

use super::error::{gw_err, http_err};

/// Async MS-TSGU HTTP Transport adapter.
///
/// Construct via [`Self::connect`], hand to [`WebClient`]:
///
/// ```ignore
/// let tsgu = TsguHttpTransport::connect(client, in_writer, out_reader, leftover).await?;
/// WebClient::new(tsgu).connect_with_upgrade(rdp_config, inner_tls_upgrader).await?;
/// ```
///
/// [`WebClient`]: justrdp_async::WebClient
pub struct TsguHttpTransport<T: WebTransport> {
    client: GatewayClient,
    in_writer: T,
    out_reader: T,

    chunked: ChunkedDecoder,
    preamble: PreambleSkipper,
    /// Dechunked + de-preambled bytes, not yet parsed into a PDU.
    decoded: Vec<u8>,

    /// Sticky once `close()` has been called or a peer-side EOF was
    /// observed. Subsequent `send`/`recv` calls fail fast with
    /// `ConnectionClosed` rather than re-touching the streams.
    closed: bool,
}

impl<T: WebTransport> core::fmt::Debug for TsguHttpTransport<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `GatewayClient` doesn't impl `Debug` so we can't derive.
        // Surface the data we do have without leaking the private
        // state-machine internals.
        f.debug_struct("TsguHttpTransport")
            .field("decoded_len", &self.decoded.len())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl<T: WebTransport> TsguHttpTransport<T> {
    /// Drive the `client` state machine through the MS-TSGU
    /// Handshake / TunnelCreate / TunnelAuth / ChannelCreate sequence
    /// over the supplied streams, then return a transport ready for
    /// byte-level RDP I/O.
    ///
    /// `in_writer` and `out_reader` MUST already be past the HTTP/1.1
    /// header phase — i.e. the next byte read from `out_reader` is
    /// either part of the 100-byte random preamble (or the chunked-
    /// encoded body that wraps it) and the next byte written to
    /// `in_writer` becomes the first chunk of the IN channel body.
    ///
    /// `out_leftover` carries the bytes [G2's
    /// `authenticate_http_channel`](super::http_auth::authenticate_http_channel)
    /// already pulled past the `200 OK` response headers — they are
    /// fed straight into the chunked decoder so no boundary is lost
    /// across the auth/data hand-off.
    pub async fn connect(
        client: GatewayClient,
        in_writer: T,
        out_reader: T,
        out_leftover: Vec<u8>,
    ) -> Result<Self, TransportError> {
        let mut transport = Self {
            client,
            in_writer,
            out_reader,
            chunked: ChunkedDecoder::new(),
            preamble: PreambleSkipper::new(),
            decoded: Vec::new(),
            closed: false,
        };

        // Replay the auth-phase leftover bytes into the dechunker so
        // the OUT-channel PDU stream starts at byte zero from the
        // state machine's perspective.
        if !out_leftover.is_empty() {
            transport.absorb_out_bytes(&out_leftover)?;
        }

        let mut out_buf = WriteBuf::new();
        while !transport.client.is_connected() {
            if transport.client.is_send_state() {
                transport
                    .client
                    .step(&[], &mut out_buf)
                    .map_err(gw_err)?;
                send_chunk(&mut transport.in_writer, out_buf.as_slice()).await?;
            } else if transport.client.is_wait_state() {
                let pdu = transport.pump_one_pdu().await?;
                transport
                    .client
                    .step(&pdu, &mut out_buf)
                    .map_err(gw_err)?;
            } else {
                return Err(http_err(
                    "MS-TSGU state machine reached terminal state mid-handshake",
                ));
            }
        }

        Ok(transport)
    }

    /// Borrow the underlying [`GatewayClient`] — useful for inspecting
    /// the negotiated tunnel id / capability flags after handshake.
    pub fn client(&self) -> &GatewayClient {
        &self.client
    }

    // ---------- internal byte plumbing ----------

    /// Feed a slice through dechunker → preamble skipper → decoded
    /// buffer. Used both during handshake and post-handshake recv.
    fn absorb_out_bytes(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        let dechunked = self
            .chunked
            .feed(bytes)
            .map_err(|e| http_err(format!("gateway chunked encoding: {e:?}")))?;
        let post_preamble = self.preamble.feed(&dechunked);
        self.decoded.extend_from_slice(post_preamble);
        Ok(())
    }

    /// Pull a single complete MS-TSGU PDU out of the OUT channel,
    /// reading and decoding more bytes as needed. Used during the
    /// handshake pump only — post-handshake recv inlines the same
    /// loop with a `parse_data_pdu` call at the end.
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
            let chunk = self.out_reader.recv().await?;
            self.absorb_out_bytes(&chunk)?;
        }
    }
}

/// Encode `payload` as one HTTP chunk and write it to `writer` as a
/// single `WebTransport::send` call. Emitting the chunk header and
/// payload in one frame keeps the gateway's chunked-body parser from
/// observing intermediate split points.
async fn send_chunk<T: WebTransport>(writer: &mut T, payload: &[u8]) -> Result<(), TransportError> {
    let mut frame = Vec::with_capacity(payload.len() + 16);
    encode_chunk(payload, &mut frame);
    writer.send(&frame).await
}

/// Decode a single `HTTP_DATA_PACKET` PDU and return its inner RDP
/// bytes. Inlined from `justrdp_gateway::transport_util::parse_data_pdu`
/// because that helper is `#[cfg(feature = "std")]` and we consume the
/// crate in `alloc`-only mode.
fn parse_data_pdu(bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
    if bytes.len() < DATA_PACKET_MIN_SIZE {
        return Err(http_err("data pdu: short header"));
    }
    let mut cur = ReadCursor::new(bytes);
    let pdu = DataPdu::decode(&mut cur).map_err(|e| http_err(format!("data pdu decode: {e}")))?;
    Ok(pdu.data)
}

impl<T: WebTransport + Send> WebTransport for TsguHttpTransport<T> {
    async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::closed("tsgu-http: already closed"));
        }
        if bytes.is_empty() {
            return Ok(());
        }
        // One call → one HTTP_DATA_PACKET. Refuse oversize writes
        // rather than silently fragmenting; 65535 bytes is well above
        // any single RDP PDU we actually emit.
        if bytes.len() > u16::MAX as usize {
            return Err(http_err(format!(
                "gateway send {} bytes exceeds HTTP_DATA_PACKET u16 limit",
                bytes.len()
            )));
        }
        let mut out_buf = WriteBuf::new();
        self.client
            .encode_data(bytes, &mut out_buf)
            .map_err(gw_err)?;
        send_chunk(&mut self.in_writer, out_buf.as_slice()).await
    }

    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.closed {
            return Err(TransportError::closed("tsgu-http: already closed"));
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
            let chunk = match self.out_reader.recv().await {
                Ok(b) => b,
                Err(e) => {
                    // Sticky the closed flag so subsequent calls
                    // short-circuit to ConnectionClosed without
                    // re-touching the underlying stream.
                    self.closed = true;
                    return Err(e);
                }
            };
            self.absorb_out_bytes(&chunk)?;
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // Best-effort graceful close: emit an MS-TSGU CloseChannel
        // PDU + the chunked-final marker, then close both streams.
        // Ignore non-Closed transport errors here so a partially
        // dead connection still closes cleanly.
        let mut out_buf = WriteBuf::new();
        if self.client.encode_close(&mut out_buf).is_ok() {
            let _ = send_chunk(&mut self.in_writer, out_buf.as_slice()).await;
            let mut trailer = Vec::new();
            encode_final_chunk(&mut trailer);
            let _ = self.in_writer.send(&trailer).await;
        }
        let _ = self.in_writer.close().await;
        let _ = self.out_reader.close().await;
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

    /// In-memory WebTransport that scripts a recv queue and records
    /// every send call. Same shape as the helpers in `http_io.rs` /
    /// `http_auth.rs`; kept local so each module's tests own their
    /// fixtures.
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

    fn encode<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut cur = justrdp_core::WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        buf
    }

    /// Fake OUT-channel body: 100-byte preamble + four canned response
    /// PDUs + optional trailing Data PDUs, all wrapped in one HTTP
    /// chunk + final marker. Mirrors the blocking gateway test fixture.
    fn fake_out_body(trailing_data: &[&[u8]]) -> Vec<u8> {
        let mut body = vec![0xFFu8; 100]; // random preamble
        body.extend(encode(&HandshakeResponsePdu::ok(HTTP_EXTENDED_AUTH_NONE)));
        body.extend(encode(&TunnelResponsePdu {
            server_version: 1,
            status_code: STATUS_SUCCESS,
            fields_present: HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID
                | HTTP_TUNNEL_RESPONSE_FIELD_CAPS,
            tunnel_id: 0xDEAD_BEEF,
            caps_flags: 0x3F,
            nonce: [0; 16],
            server_cert: HttpUnicodeString::empty(),
            consent_msg: HttpUnicodeString::empty(),
        }));
        body.extend(encode(&TunnelAuthResponsePdu {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS
                | HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT,
            redir_flags: HTTP_TUNNEL_REDIR_DISABLE_ALL,
            idle_timeout_minutes: 30,
            soh_response: None,
        }));
        body.extend(encode(&ChannelResponsePdu {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
            channel_id: 7,
            udp_port: 0,
            authn_cookie: None,
        }));
        for payload in trailing_data {
            body.extend(encode(&DataPdu::new(payload.to_vec())));
        }
        let mut chunked = Vec::new();
        encode_chunk(&body, &mut chunked);
        encode_final_chunk(&mut chunked);
        chunked
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
    async fn connect_drives_handshake_and_emits_four_send_chunks() {
        // OUT body has the four server response PDUs in order; IN
        // writer gets the four client request PDUs (handshake,
        // tunnel-create, tunnel-auth, channel-create), each as one
        // HTTP chunk frame.
        let out = ScriptedTransport::from_script(fake_out_body(&[]));
        let in_w = ScriptedTransport::empty();
        let transport = TsguHttpTransport::connect(fresh_client(), in_w, out, Vec::new())
            .await
            .unwrap();
        // Four chunked frames sent over the IN channel during the
        // handshake — one per send state.
        assert_eq!(transport.in_writer.sent.len(), 4);
        // Negotiated tunnel id is what the fixture announced.
        assert_eq!(transport.client.tunnel_id(), 0xDEAD_BEEF);
    }

    #[tokio::test]
    async fn connect_consumes_out_leftover_before_recv() {
        // Half the OUT body lives in the auth-phase leftover Vec; the
        // remainder comes from the next recv(). Handshake must
        // complete identically.
        let mut full = fake_out_body(&[]);
        let leftover_split = full.len() / 2;
        let leftover = full.drain(..leftover_split).collect::<Vec<u8>>();
        let out = ScriptedTransport::from_script(full);
        let in_w = ScriptedTransport::empty();
        let transport = TsguHttpTransport::connect(fresh_client(), in_w, out, leftover)
            .await
            .unwrap();
        assert!(transport.client.is_connected());
    }

    #[tokio::test]
    async fn send_after_handshake_emits_one_chunked_data_pdu() {
        let out = ScriptedTransport::from_script(fake_out_body(&[]));
        let in_w = ScriptedTransport::empty();
        let mut transport = TsguHttpTransport::connect(fresh_client(), in_w, out, Vec::new())
            .await
            .unwrap();

        let in_writes_before = transport.in_writer.sent.len();
        transport.send(b"PAYLOAD").await.unwrap();
        // Exactly one new chunked frame.
        assert_eq!(transport.in_writer.sent.len(), in_writes_before + 1);
        let frame = transport.in_writer.sent.last().unwrap();
        // Each frame is `<hex-len>\r\n<bytes>\r\n` per RFC 9112; the
        // payload bytes "PAYLOAD" should appear inside.
        assert!(
            frame
                .windows(b"PAYLOAD".len())
                .any(|w| w == b"PAYLOAD"),
            "expected raw payload bytes inside chunk frame"
        );
    }

    #[tokio::test]
    async fn recv_returns_data_pdu_payloads_in_order() {
        let out = ScriptedTransport::from_script(fake_out_body(&[b"FIRST", b"SECOND"]));
        let in_w = ScriptedTransport::empty();
        let mut transport = TsguHttpTransport::connect(fresh_client(), in_w, out, Vec::new())
            .await
            .unwrap();
        let p1 = transport.recv().await.unwrap();
        let p2 = transport.recv().await.unwrap();
        assert_eq!(p1.as_slice(), b"FIRST");
        assert_eq!(p2.as_slice(), b"SECOND");
    }

    #[tokio::test]
    async fn send_oversize_returns_protocol_error() {
        let out = ScriptedTransport::from_script(fake_out_body(&[]));
        let in_w = ScriptedTransport::empty();
        let mut transport = TsguHttpTransport::connect(fresh_client(), in_w, out, Vec::new())
            .await
            .unwrap();
        let too_big = vec![0u8; (u16::MAX as usize) + 1];
        let err = transport.send(&too_big).await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[tokio::test]
    async fn send_empty_is_a_noop() {
        let out = ScriptedTransport::from_script(fake_out_body(&[]));
        let in_w = ScriptedTransport::empty();
        let mut transport = TsguHttpTransport::connect(fresh_client(), in_w, out, Vec::new())
            .await
            .unwrap();
        let in_writes_before = transport.in_writer.sent.len();
        transport.send(&[]).await.unwrap();
        assert_eq!(transport.in_writer.sent.len(), in_writes_before);
    }

    #[tokio::test]
    async fn close_emits_close_pdu_and_final_chunk_then_short_circuits() {
        let out = ScriptedTransport::from_script(fake_out_body(&[]));
        let in_w = ScriptedTransport::empty();
        let mut transport = TsguHttpTransport::connect(fresh_client(), in_w, out, Vec::new())
            .await
            .unwrap();
        transport.close().await.unwrap();
        // Subsequent send/recv short-circuits as ConnectionClosed.
        let err = transport.send(b"x").await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
        let err = transport.recv().await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
        // Idempotent close.
        transport.close().await.unwrap();
    }

    #[tokio::test]
    async fn recv_eof_mid_handshake_surfaces_as_closed() {
        // OUT channel returns just the preamble + handshake response,
        // then drains. The state machine asks for TunnelResponse next
        // and the recv() fails with `ConnectionClosed`.
        let mut body = vec![0xFFu8; 100];
        body.extend(encode(&HandshakeResponsePdu::ok(HTTP_EXTENDED_AUTH_NONE)));
        let mut chunked = Vec::new();
        encode_chunk(&body, &mut chunked);
        encode_final_chunk(&mut chunked);
        let out = ScriptedTransport::from_script(chunked);
        let in_w = ScriptedTransport::empty();
        let err = TsguHttpTransport::connect(fresh_client(), in_w, out, Vec::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
    }
}
