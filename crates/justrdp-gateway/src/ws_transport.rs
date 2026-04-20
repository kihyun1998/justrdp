#![forbid(unsafe_code)]

//! `std::io::Read + Write` adapter for the MS-TSGU WebSocket Transport
//! variant.
//!
//! [`WsGatewayConnection`] wraps a single already-upgraded WebSocket
//! byte stream (typically a TLS session that has just completed the
//! HTTP/1.1 `101 Switching Protocols` handshake) and exposes a
//! transparent `Read + Write` pipe carrying the inner RDP bytes.
//!
//! Unlike the HTTP Transport variant (see [`crate::transport`]) this
//! uses one connection instead of two, RFC 6455 binary frames instead
//! of HTTP chunked encoding, and no 100-byte preamble. Every MS-TSGU
//! PDU is sent as one WebSocket Binary frame with `FIN=1`; server-side
//! fragmentation is handled on the receive path.
//!
//! **Scope.** This module assumes the caller has already completed
//! the outer TLS handshake, the HTTP `101 Switching Protocols`
//! upgrade, and any HTTP 401 NTLM retry loop. It does not parse HTTP
//! at all — the first bytes it reads from `stream` must be WebSocket
//! frames.

extern crate std;

use std::io::{self, Read, Write};
use std::vec::Vec;

use justrdp_core::WriteBuf;

use crate::client::{find_packet_size, GatewayClient, GatewayError};
use crate::ws::{
    encode_close_payload, encode_frame, WsError, WsFrame, WsFrameDecoder, WS_CLOSE_NORMAL,
    WS_OPCODE_BINARY, WS_OPCODE_CLOSE, WS_OPCODE_PONG,
};

// =============================================================================
// Errors
// =============================================================================

/// Errors reported by the WebSocket transport adapter.
#[derive(Debug)]
pub enum WsConnectError {
    Io(io::Error),
    Gateway(GatewayError),
    Ws(WsError),
    /// Server closed the stream before the MS-TSGU handshake
    /// completed (or mid-PDU during steady state).
    UnexpectedEof,
    /// Server initiated the WebSocket close handshake.
    ServerClosed { code: Option<u16> },
    /// The server announced a `packet_length` exceeding
    /// [`crate::pdu::MAX_PACKET_SIZE`].
    PacketTooLarge(crate::client::PacketTooLarge),
}

impl core::fmt::Display for WsConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ws transport io: {e}"),
            Self::Gateway(e) => write!(f, "ws transport gateway: {e:?}"),
            Self::Ws(e) => write!(f, "ws transport framing: {e:?}"),
            Self::UnexpectedEof => write!(f, "ws transport: unexpected EOF"),
            Self::ServerClosed { code } => {
                write!(f, "ws transport: server closed (code {code:?})")
            }
            Self::PacketTooLarge(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WsConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::PacketTooLarge(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for WsConnectError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<GatewayError> for WsConnectError {
    fn from(e: GatewayError) -> Self {
        Self::Gateway(e)
    }
}
impl From<WsError> for WsConnectError {
    fn from(e: WsError) -> Self {
        Self::Ws(e)
    }
}
impl From<crate::client::PacketTooLarge> for WsConnectError {
    fn from(e: crate::client::PacketTooLarge) -> Self {
        Self::PacketTooLarge(e)
    }
}

// =============================================================================
// Mask source
// =============================================================================

/// Source of 4-byte masking keys for client-to-server WebSocket
/// frames. RFC 6455 §5.3 requires a fresh key per frame, drawn from
/// a cryptographic RNG in environments where an attacker could
/// control the plaintext (which applies to any proxy scenario).
///
/// The gateway crate has no built-in RNG so the caller supplies one.
/// Blocking runtimes typically wrap `getrandom` in a closure; tests
/// may use a counter.
pub type MaskSource = std::boxed::Box<dyn FnMut() -> [u8; 4] + Send>;

// =============================================================================
// WsGatewayConnection
// =============================================================================

/// `Read + Write` adapter wrapping a single upgraded WebSocket
/// connection to an MS-TSGU gateway.
pub struct WsGatewayConnection<S: Read + Write> {
    #[allow(dead_code)]
    client: GatewayClient,
    stream: S,
    mask_source: MaskSource,
    decoder: WsFrameDecoder,
    /// Buffer of WebSocket-dechunked bytes waiting to be parsed into
    /// MS-TSGU PDUs.
    decoded: Vec<u8>,
    /// A fully decoded Data PDU payload not yet delivered to the
    /// caller + how much has been consumed.
    pending: Vec<u8>,
    pending_cursor: usize,
    /// Scratch buffer for reads from the underlying stream.
    read_scratch: [u8; READ_SCRATCH_SIZE],
    /// Set once we have seen a server Close frame or initiated one.
    closed: bool,
}

const READ_SCRATCH_SIZE: usize = 4096;

impl<S: Read + Write> WsGatewayConnection<S> {
    /// Drive `client` through the MS-TSGU handshake over the given
    /// WebSocket stream, then return a connection ready for byte-level
    /// I/O of RDP traffic.
    pub fn connect(
        mut client: GatewayClient,
        mut stream: S,
        mut mask_source: MaskSource,
    ) -> Result<Self, WsConnectError> {
        let mut decoder = WsFrameDecoder::new();
        let mut decoded: Vec<u8> = Vec::new();
        let mut scratch = [0u8; READ_SCRATCH_SIZE];
        let mut out_buf = WriteBuf::new();

        while !client.is_connected() {
            if client.is_send_state() {
                client.step(&[], &mut out_buf)?;
                send_binary_frame(&mut stream, out_buf.as_slice(), &mut mask_source)?;
            } else if client.is_wait_state() {
                let pdu = read_next_pdu(
                    &mut stream,
                    &mut decoder,
                    &mut decoded,
                    &mut scratch,
                    &mut mask_source,
                )?;
                client.step(&pdu, &mut out_buf)?;
            } else {
                return Err(WsConnectError::Gateway(GatewayError::InvalidState(
                    "unexpected terminal state during ws handshake",
                )));
            }
        }

        Ok(Self {
            client,
            stream,
            mask_source,
            decoder,
            decoded,
            pending: Vec::new(),
            pending_cursor: 0,
            read_scratch: [0; READ_SCRATCH_SIZE],
            closed: false,
        })
    }

    /// Send the MS-TSGU graceful close PDU followed by a WebSocket
    /// Close frame (status 1000), then return the underlying stream.
    pub fn shutdown(mut self) -> Result<S, WsConnectError> {
        if !self.closed {
            let mut out_buf = WriteBuf::new();
            self.client.encode_close(&mut out_buf)?;
            send_binary_frame(&mut self.stream, out_buf.as_slice(), &mut self.mask_source)?;
            let payload = encode_close_payload(Some(WS_CLOSE_NORMAL), "");
            send_control_frame(
                &mut self.stream,
                WS_OPCODE_CLOSE,
                &payload,
                &mut self.mask_source,
            )?;
            self.closed = true;
        }
        Ok(self.stream)
    }

    pub fn client(&self) -> &GatewayClient {
        &self.client
    }
}

// =============================================================================
// Read / Write
// =============================================================================

impl<S: Read + Write> Read for WsGatewayConnection<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pending_cursor < self.pending.len() {
            return Ok(self.copy_pending(buf));
        }
        if self.closed {
            return Ok(0);
        }
        loop {
            if let Some(size) = find_packet_size(&self.decoded).map_err(io_other)? {
                if self.decoded.len() >= size {
                    let pdu_bytes: Vec<u8> = self.decoded.drain(..size).collect();
                    let data = parse_data_pdu(&pdu_bytes).map_err(io_other)?;
                    self.pending = data;
                    self.pending_cursor = 0;
                    return Ok(self.copy_pending(buf));
                }
            }
            let n = self.stream.read(&mut self.read_scratch)?;
            if n == 0 {
                if self.decoded.is_empty() && self.pending_cursor >= self.pending.len() {
                    return Ok(0);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ws gateway stream closed mid-PDU",
                ));
            }
            let frames = self
                .decoder
                .feed(&self.read_scratch[..n])
                .map_err(io_other)?;
            for frame in frames {
                match frame {
                    WsFrame::Binary(bytes) => self.decoded.extend_from_slice(&bytes),
                    WsFrame::Ping(payload) => {
                        // RFC 6455 §5.5.3: reply immediately with a Pong
                        // carrying an identical payload. Ping payloads are
                        // bounded to 125 bytes by the decoder.
                        send_control_frame(
                            &mut self.stream,
                            WS_OPCODE_PONG,
                            &payload,
                            &mut self.mask_source,
                        )
                        .map_err(io_other)?;
                    }
                    WsFrame::Pong(_) => { /* discard */ }
                    WsFrame::Close { .. } => {
                        // RFC 6455 §5.5.1: on receiving a Close, echo
                        // one and treat the connection as closed. Mark
                        // `self.closed = true` up front so we do not
                        // try to send a second echo if the echo itself
                        // fails (and so any future writes short-circuit).
                        self.closed = true;
                        let payload = encode_close_payload(Some(WS_CLOSE_NORMAL), "");
                        send_control_frame(
                            &mut self.stream,
                            WS_OPCODE_CLOSE,
                            &payload,
                            &mut self.mask_source,
                        )
                        .map_err(io_other)?;
                        if self.decoded.is_empty() && self.pending_cursor >= self.pending.len() {
                            return Ok(0);
                        }
                        // Serve any already-decoded data before the Close.
                        break;
                    }
                }
            }
        }
    }
}

impl<S: Read + Write> Write for WsGatewayConnection<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ws gateway write exceeds HTTP_DATA_PACKET u16 limit",
            ));
        }
        let mut out_buf = WriteBuf::new();
        self.client
            .encode_data(buf, &mut out_buf)
            .map_err(io_other)?;
        send_binary_frame(&mut self.stream, out_buf.as_slice(), &mut self.mask_source)
            .map_err(io_other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl<S: Read + Write> WsGatewayConnection<S> {
    fn copy_pending(&mut self, buf: &mut [u8]) -> usize {
        let avail = &self.pending[self.pending_cursor..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.pending_cursor += n;
        n
    }
}

// =============================================================================
// Framing helpers
// =============================================================================

fn send_binary_frame<W: Write>(
    w: &mut W,
    payload: &[u8],
    mask_source: &mut MaskSource,
) -> Result<(), WsConnectError> {
    let mask = (mask_source)();
    let mut frame = Vec::with_capacity(payload.len() + 16);
    encode_frame(WS_OPCODE_BINARY, true, payload, mask, &mut frame)?;
    w.write_all(&frame)?;
    w.flush()?;
    Ok(())
}

fn send_control_frame<W: Write>(
    w: &mut W,
    opcode: u8,
    payload: &[u8],
    mask_source: &mut MaskSource,
) -> Result<(), WsConnectError> {
    let mask = (mask_source)();
    let mut frame = Vec::with_capacity(payload.len() + 14);
    encode_frame(opcode, true, payload, mask, &mut frame)?;
    w.write_all(&frame)?;
    w.flush()?;
    Ok(())
}

/// Block until one complete MS-TSGU PDU can be parsed from the
/// WebSocket stream and return its bytes.
fn read_next_pdu<S: Read + Write>(
    stream: &mut S,
    decoder: &mut WsFrameDecoder,
    decoded: &mut Vec<u8>,
    scratch: &mut [u8],
    mask_source: &mut MaskSource,
) -> Result<Vec<u8>, WsConnectError> {
    loop {
        if let Some(size) = find_packet_size(decoded)? {
            if decoded.len() >= size {
                let pdu = decoded.drain(..size).collect::<Vec<u8>>();
                return Ok(pdu);
            }
        }
        let n = stream.read(scratch)?;
        if n == 0 {
            return Err(WsConnectError::UnexpectedEof);
        }
        let frames = decoder.feed(&scratch[..n])?;
        for frame in frames {
            match frame {
                WsFrame::Binary(bytes) => decoded.extend_from_slice(&bytes),
                WsFrame::Ping(payload) => {
                    send_control_frame(stream, WS_OPCODE_PONG, &payload, mask_source)?;
                }
                WsFrame::Pong(_) => {}
                WsFrame::Close { code, .. } => {
                    return Err(WsConnectError::ServerClosed { code });
                }
            }
        }
    }
}

use crate::transport_util::{io_other, parse_data_pdu as parse_data_pdu_shared};

fn parse_data_pdu(bytes: &[u8]) -> Result<Vec<u8>, GatewayError> {
    parse_data_pdu_shared(bytes, "ws data pdu: short header")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::GatewayClientConfig;
    use crate::pdu::{
        ChannelResponsePdu, DataPdu as DataPduType, HandshakeResponsePdu, HttpUnicodeString,
        TunnelAuthResponsePdu, TunnelResponsePdu, HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
        HTTP_EXTENDED_AUTH_NONE, HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT,
        HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS, HTTP_TUNNEL_REDIR_DISABLE_ALL,
        HTTP_TUNNEL_RESPONSE_FIELD_CAPS, HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID, STATUS_SUCCESS,
    };
    use crate::ws::{encode_frame, WS_OPCODE_BINARY, WS_OPCODE_PING};

    use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
    use std::collections::VecDeque;
    use std::io::Result as IoResult;

    fn fixed_mask() -> MaskSource {
        std::boxed::Box::new(|| [0xAAu8, 0xBB, 0xCC, 0xDD])
    }

    fn encode_pdu<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf = std::vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        buf
    }

    /// Wrap a raw MS-TSGU PDU in one unmasked server-side WS Binary frame.
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

    fn build_fake_server_script(trailing: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        // 1. HandshakeResponse
        out.extend(server_binary_frame(&encode_pdu(&HandshakeResponsePdu::ok(
            HTTP_EXTENDED_AUTH_NONE,
        ))));
        // 2. TunnelResponse
        out.extend(server_binary_frame(&encode_pdu(&TunnelResponsePdu {
            server_version: 1,
            status_code: STATUS_SUCCESS,
            fields_present: HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID
                | HTTP_TUNNEL_RESPONSE_FIELD_CAPS,
            tunnel_id: 0xCAFE_F00D,
            caps_flags: 0x3F,
            nonce: [0; 16],
            server_cert: HttpUnicodeString::empty(),
            consent_msg: HttpUnicodeString::empty(),
        })));
        // 3. TunnelAuthResponse
        out.extend(server_binary_frame(&encode_pdu(&TunnelAuthResponsePdu {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS
                | HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT,
            redir_flags: HTTP_TUNNEL_REDIR_DISABLE_ALL,
            idle_timeout_minutes: 15,
            soh_response: None,
        })));
        // 4. ChannelResponse
        out.extend(server_binary_frame(&encode_pdu(&ChannelResponsePdu {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
            channel_id: 99,
            udp_port: 0,
            authn_cookie: None,
        })));
        // 5+. Trailing Data PDUs, each in its own Binary frame.
        for p in trailing {
            out.extend(server_binary_frame(&encode_pdu(&DataPduType::new(
                p.to_vec(),
            ))));
        }
        out
    }

    /// Scripted duplex: writes are recorded, reads come from a pre-
    /// filled VecDeque. The server script can be extended after
    /// construction via `push_script`.
    struct Duplex {
        script: VecDeque<u8>,
        written: Vec<u8>,
    }

    impl Duplex {
        fn new(script: Vec<u8>) -> Self {
            Self {
                script: script.into(),
                written: Vec::new(),
            }
        }
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
            if self.script.is_empty() {
                return Ok(0);
            }
            let n = buf.len().min(self.script.len());
            for slot in buf.iter_mut().take(n) {
                *slot = self.script.pop_front().unwrap();
            }
            Ok(n)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    #[test]
    fn ws_connect_runs_full_handshake() {
        let stream = Duplex::new(build_fake_server_script(&[]));
        let client = GatewayClient::new(GatewayClientConfig::new("target.host", "RDG-Client1"));
        let conn = WsGatewayConnection::connect(client, stream, fixed_mask()).unwrap();
        assert!(conn.client().is_connected());
        assert_eq!(conn.client().tunnel_id(), 0xCAFE_F00D);
        assert_eq!(conn.client().channel_id(), 99);
        assert_eq!(conn.client().idle_timeout_minutes(), 15);
    }

    #[test]
    fn ws_handshake_emits_four_binary_frames() {
        let stream = Duplex::new(build_fake_server_script(&[]));
        let client = GatewayClient::new(GatewayClientConfig::new("target.host", "c"));
        let conn = WsGatewayConnection::connect(client, stream, fixed_mask()).unwrap();

        // Inspect what the client wrote: four client-masked binary
        // frames (Handshake, TunnelCreate, TunnelAuth, ChannelCreate).
        let out = conn.stream.written.clone();
        let mut offset = 0;
        let mut frames = 0;
        while offset + 2 <= out.len() {
            let b0 = out[offset];
            let b1 = out[offset + 1];
            assert_eq!(b0 & 0x0F, WS_OPCODE_BINARY, "expected binary frame");
            assert!(b0 & 0x80 != 0, "expected FIN");
            assert!(b1 & 0x80 != 0, "client frames must be masked");
            let short_len = b1 & 0x7F;
            let (header, payload_len) = match short_len {
                126 => (
                    4 + 4,
                    u16::from_be_bytes([out[offset + 2], out[offset + 3]]) as usize,
                ),
                127 => panic!("unexpected u64 length"),
                n => (2 + 4, n as usize),
            };
            offset += header + payload_len;
            frames += 1;
        }
        assert_eq!(frames, 4);
    }

    #[test]
    fn ws_read_returns_data_pdu_payload() {
        let payload = b"RDP-TPKT";
        let stream = Duplex::new(build_fake_server_script(&[payload]));
        let client = GatewayClient::new(GatewayClientConfig::new("t", "c"));
        let mut conn = WsGatewayConnection::connect(client, stream, fixed_mask()).unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], payload);
    }

    #[test]
    fn ws_write_wraps_caller_bytes_in_data_pdu_and_binary_frame() {
        let stream = Duplex::new(build_fake_server_script(&[]));
        let client = GatewayClient::new(GatewayClientConfig::new("t", "c"));
        let mut conn = WsGatewayConnection::connect(client, stream, fixed_mask()).unwrap();

        let handshake_len = conn.stream.written.len();
        let rdp = [0x03u8, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80];
        conn.write_all(&rdp).unwrap();

        // The bytes appended after the handshake form one client WS
        // Binary frame. Decode it (un-mask) and verify the inner
        // DataPdu.
        let new_bytes = &conn.stream.written[handshake_len..];
        assert!(new_bytes[0] & 0x80 != 0); // FIN
        assert_eq!(new_bytes[0] & 0x0F, WS_OPCODE_BINARY);
        assert!(new_bytes[1] & 0x80 != 0); // masked
        let len = (new_bytes[1] & 0x7F) as usize;
        let mask = [new_bytes[2], new_bytes[3], new_bytes[4], new_bytes[5]];
        let masked_payload = &new_bytes[6..6 + len];
        let mut payload = Vec::with_capacity(len);
        for (i, b) in masked_payload.iter().enumerate() {
            payload.push(b ^ mask[i & 3]);
        }
        let mut cur = ReadCursor::new(&payload);
        let data_pdu = DataPduType::decode(&mut cur).unwrap();
        assert_eq!(data_pdu.data, rdp);
    }

    #[test]
    fn ws_read_auto_responds_to_ping() {
        // Server script: full handshake + one Ping frame. The Ping
        // may be consumed while the handshake is draining the TCP
        // buffer, so we scan the entire write stream for a Pong
        // frame rather than assuming it shows up after `connect`.
        let mut script = build_fake_server_script(&[]);
        script.push(0x80 | WS_OPCODE_PING);
        script.push(2);
        script.extend_from_slice(b"pp");

        let stream = Duplex::new(script);
        let client = GatewayClient::new(GatewayClientConfig::new("t", "c"));
        let mut conn = WsGatewayConnection::connect(client, stream, fixed_mask()).unwrap();

        // Reading past the handshake returns Ok(0) — no Data PDUs.
        let mut buf = [0u8; 4];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(n, 0);

        // Scan the client's output: there must be exactly one Pong
        // frame whose unmasked payload is "pp".
        let out = &conn.stream.written;
        let mut offset = 0;
        let mut pong_payloads: Vec<Vec<u8>> = Vec::new();
        while offset + 2 <= out.len() {
            let b0 = out[offset];
            let b1 = out[offset + 1];
            let short = b1 & 0x7F;
            let (hdr, payload_len) = match short {
                126 => (
                    4 + 4,
                    u16::from_be_bytes([out[offset + 2], out[offset + 3]]) as usize,
                ),
                127 => panic!("unexpected u64 length"),
                n => (2 + 4, n as usize),
            };
            let mask = [
                out[offset + hdr - 4],
                out[offset + hdr - 3],
                out[offset + hdr - 2],
                out[offset + hdr - 1],
            ];
            let payload: Vec<u8> = out[offset + hdr..offset + hdr + payload_len]
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ mask[i & 3])
                .collect();
            if b0 & 0x0F == WS_OPCODE_PONG {
                pong_payloads.push(payload);
            }
            offset += hdr + payload_len;
        }
        assert_eq!(pong_payloads.len(), 1, "exactly one Pong expected");
        assert_eq!(pong_payloads[0], b"pp");
    }

    #[test]
    fn ws_write_rejects_oversize_payload() {
        let stream = Duplex::new(build_fake_server_script(&[]));
        let client = GatewayClient::new(GatewayClientConfig::new("t", "c"));
        let mut conn = WsGatewayConnection::connect(client, stream, fixed_mask()).unwrap();
        let huge = std::vec![0u8; u16::MAX as usize + 1];
        let err = conn.write(&huge).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn ws_shutdown_sends_close_pdu_and_frame() {
        let stream = Duplex::new(build_fake_server_script(&[]));
        let client = GatewayClient::new(GatewayClientConfig::new("t", "c"));
        let conn = WsGatewayConnection::connect(client, stream, fixed_mask()).unwrap();
        let handshake_len = conn.stream.written.len();
        let stream = conn.shutdown().unwrap();

        // After shutdown, we should have a MS-TSGU Close PDU wrapped
        // in a Binary frame, followed by a WS Close frame (opcode 0x8).
        let new_bytes = &stream.written[handshake_len..];
        // First frame: Binary containing the close PDU.
        assert_eq!(new_bytes[0] & 0x0F, WS_OPCODE_BINARY);
        // Find the end of the binary frame and check the next one is Close.
        let first_len = (new_bytes[1] & 0x7F) as usize;
        let first_total = 2 + 4 + first_len;
        let second = &new_bytes[first_total..];
        assert_eq!(second[0] & 0x0F, WS_OPCODE_CLOSE);
        assert!(second[0] & 0x80 != 0);
    }

    // Sanity-check the test helper itself.
    #[test]
    fn encode_frame_matches_server_frame_when_mask_zero() {
        let mut client_encoded = Vec::new();
        encode_frame(WS_OPCODE_BINARY, true, b"abc", [0, 0, 0, 0], &mut client_encoded).unwrap();
        let server_encoded = server_binary_frame(b"abc");
        // The server-format frame has no mask, so the client format
        // differs by exactly 4 bytes of zero mask + the unmasked
        // payload. Verify the bytes line up.
        assert_eq!(client_encoded[0], server_encoded[0]); // FIN+opcode
        // client[1] has MASK bit set; server[1] does not.
        assert_eq!(client_encoded[1] & 0x7F, server_encoded[1]);
    }
}
