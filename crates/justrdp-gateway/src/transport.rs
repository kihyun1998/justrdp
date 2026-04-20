#![forbid(unsafe_code)]

//! `std::io::Read + Write` adapter for the MS-TSGU HTTP Transport.
//!
//! [`GatewayConnection`] wraps two already-established byte streams —
//! typically TLS sessions to the gateway carrying an HTTP/1.1
//! `RDG_IN_DATA` and `RDG_OUT_DATA` connection — and presents a
//! transparent `Read + Write` pipe for the RDP bytes that live inside
//! MS-TSGU `HTTP_DATA_PACKET` frames.
//!
//! The adapter drives the [`GatewayClient`](crate::GatewayClient)
//! state machine during construction, consuming the 100-byte OUT
//! channel preamble and the chunked-encoded handshake/tunnel/channel
//! PDUs. Once [`GatewayConnection::connect`] returns, every `write`
//! wraps the caller's bytes in one `HTTP_DATA_PACKET` inside one
//! chunked frame, and every `read` dechunks + unwraps the next
//! incoming Data PDU.
//!
//! **Scope.** This module does NOT open sockets, perform TLS, send
//! the initial HTTP request line, or handle HTTP 401 NTLM retries.
//! It assumes the caller has already completed that setup and hands
//! over two streams whose next bytes are the chunked body of the IN
//! and OUT channels respectively.

extern crate std;

use std::io::{self, Read, Write};
use std::vec::Vec;

use justrdp_core::WriteBuf;

use crate::client::{find_packet_size, GatewayClient, GatewayError};
use crate::http::{encode_chunk, encode_final_chunk, ChunkError, ChunkedDecoder, PreambleSkipper};
#[cfg(test)]
use crate::pdu::PACKET_HEADER_SIZE;

// =============================================================================
// Error
// =============================================================================

/// Errors reported while establishing or operating a
/// [`GatewayConnection`].
#[derive(Debug)]
pub enum ConnectError {
    /// The wrapped streams returned an I/O error.
    Io(io::Error),
    /// The MS-TSGU state machine rejected a server PDU or failed to
    /// encode an outgoing PDU.
    Gateway(GatewayError),
    /// The chunked transfer encoding on the OUT channel was malformed.
    Chunk(ChunkError),
    /// The OUT channel closed before the handshake completed, or
    /// before an expected Data PDU payload was fully received.
    UnexpectedEof,
    /// The server announced a `packet_length` that exceeds
    /// [`crate::pdu::MAX_PACKET_SIZE`].
    PacketTooLarge(crate::client::PacketTooLarge),
}

impl core::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "gateway transport io: {e}"),
            Self::Gateway(e) => write!(f, "gateway protocol: {e:?}"),
            Self::Chunk(e) => write!(f, "gateway chunked encoding: {e:?}"),
            Self::UnexpectedEof => write!(f, "gateway transport: unexpected EOF"),
            Self::PacketTooLarge(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::PacketTooLarge(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ConnectError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<GatewayError> for ConnectError {
    fn from(e: GatewayError) -> Self {
        Self::Gateway(e)
    }
}

impl From<ChunkError> for ConnectError {
    fn from(e: ChunkError) -> Self {
        Self::Chunk(e)
    }
}

impl From<crate::client::PacketTooLarge> for ConnectError {
    fn from(e: crate::client::PacketTooLarge) -> Self {
        Self::PacketTooLarge(e)
    }
}

// =============================================================================
// GatewayConnection
// =============================================================================

/// `Read + Write` adapter carrying RDP bytes over an established
/// MS-TSGU HTTP Transport tunnel.
pub struct GatewayConnection<R: Read, W: Write> {
    #[allow(dead_code)]
    client: GatewayClient,
    in_writer: W,
    out_reader: R,

    /// Chunked decoder for the OUT channel body.
    chunked: ChunkedDecoder,
    /// 100-byte random preamble skipper. Consumed during handshake.
    preamble: PreambleSkipper,
    /// Bytes that have been dechunked and un-preambled but not yet
    /// parsed into MS-TSGU PDUs.
    decoded: Vec<u8>,
    /// A fully-decoded Data PDU payload not yet delivered to the
    /// caller, plus the position up to which the caller has consumed.
    pending: Vec<u8>,
    pending_cursor: usize,

    /// Scratch buffer for reads from the underlying stream.
    read_scratch: [u8; READ_SCRATCH_SIZE],
}

const READ_SCRATCH_SIZE: usize = 4096;

impl<R: Read, W: Write> GatewayConnection<R, W> {
    /// Drive `client` through the MS-TSGU handshake over the given
    /// streams, then return a connection ready for byte-level I/O.
    ///
    /// On entry, `in_writer` is assumed to be positioned immediately
    /// after the HTTP request headers for `RDG_IN_DATA` and ready to
    /// receive chunked body bytes. Similarly `out_reader` is expected
    /// to produce the OUT channel body starting with the mandatory
    /// 100-byte random preamble (§3.3.5.1) followed by chunked PDU
    /// data.
    pub fn connect(
        mut client: GatewayClient,
        mut in_writer: W,
        mut out_reader: R,
    ) -> Result<Self, ConnectError> {
        let mut state = PumpState {
            chunked: ChunkedDecoder::new(),
            preamble: PreambleSkipper::new(),
            decoded: Vec::new(),
        };
        let mut scratch = [0u8; READ_SCRATCH_SIZE];
        let mut out_buf = WriteBuf::new();

        while !client.is_connected() {
            if client.is_send_state() {
                client.step(&[], &mut out_buf)?;
                write_chunk(&mut in_writer, out_buf.as_slice())?;
            } else if client.is_wait_state() {
                let pdu = read_next_pdu(&mut out_reader, &mut state, &mut scratch)?;
                client.step(&pdu, &mut out_buf)?;
            } else {
                return Err(ConnectError::Gateway(GatewayError::InvalidState(
                    "unexpected terminal state during handshake",
                )));
            }
        }

        Ok(Self {
            client,
            in_writer,
            out_reader,
            chunked: state.chunked,
            preamble: state.preamble,
            decoded: state.decoded,
            pending: Vec::new(),
            pending_cursor: 0,
            read_scratch: [0; READ_SCRATCH_SIZE],
        })
    }

    /// Send a gateway-level graceful close PDU and return the
    /// underlying streams. The caller is expected to close them.
    pub fn shutdown(mut self) -> Result<(R, W), ConnectError> {
        let mut out_buf = WriteBuf::new();
        self.client.encode_close(&mut out_buf)?;
        write_chunk(&mut self.in_writer, out_buf.as_slice())?;
        // RFC 9112 §7.1: terminate the chunked body.
        let mut trailer = Vec::new();
        encode_final_chunk(&mut trailer);
        self.in_writer.write_all(&trailer)?;
        self.in_writer.flush()?;
        Ok((self.out_reader, self.in_writer))
    }

    /// Borrow the underlying `GatewayClient` (e.g. to inspect the
    /// negotiated tunnel id or idle timeout).
    pub fn client(&self) -> &GatewayClient {
        &self.client
    }
}

// Internal state threaded between the handshake pump and the
// steady-state read path so the chunked decoder / preamble skipper
// survive into the data phase.
struct PumpState {
    chunked: ChunkedDecoder,
    preamble: PreambleSkipper,
    decoded: Vec<u8>,
}

// =============================================================================
// Handshake helpers
// =============================================================================

fn write_chunk<W: Write>(w: &mut W, payload: &[u8]) -> Result<(), ConnectError> {
    let mut frame = Vec::with_capacity(payload.len() + 16);
    encode_chunk(payload, &mut frame);
    w.write_all(&frame)?;
    w.flush()?;
    Ok(())
}

/// Block until one complete MS-TSGU PDU can be parsed from the OUT
/// stream and return its bytes (header + body, ready for
/// `GatewayClient::step`).
fn read_next_pdu<R: Read>(
    reader: &mut R,
    state: &mut PumpState,
    scratch: &mut [u8],
) -> Result<Vec<u8>, ConnectError> {
    loop {
        if let Some(size) = find_packet_size(&state.decoded)? {
            if state.decoded.len() >= size {
                let pdu = state.decoded.drain(..size).collect::<Vec<u8>>();
                return Ok(pdu);
            }
        }
        let n = reader.read(scratch)?;
        if n == 0 {
            return Err(ConnectError::UnexpectedEof);
        }
        let dechunked = state.chunked.feed(&scratch[..n])?;
        let post_preamble = state.preamble.feed(&dechunked);
        state.decoded.extend_from_slice(post_preamble);
    }
}

// =============================================================================
// std::io::Read + Write
// =============================================================================

impl<R: Read, W: Write> Read for GatewayConnection<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Drain any payload left over from the previous PDU first.
        if self.pending_cursor < self.pending.len() {
            return Ok(self.copy_pending(buf));
        }

        // Otherwise pull in enough bytes to decode the next Data PDU
        // and stash its payload in `pending`.
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
            let n = self.out_reader.read(&mut self.read_scratch)?;
            if n == 0 {
                // Clean EOF at a PDU boundary: report 0; mid-PDU is
                // an error.
                if self.decoded.is_empty() && self.pending_cursor >= self.pending.len() {
                    return Ok(0);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "gateway OUT channel closed mid-PDU",
                ));
            }
            let dechunked = self.chunked.feed(&self.read_scratch[..n]).map_err(io_other)?;
            let post_preamble = self.preamble.feed(&dechunked);
            self.decoded.extend_from_slice(post_preamble);
        }
    }
}

impl<R: Read, W: Write> Write for GatewayConnection<R, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Each call becomes one HTTP_DATA_PACKET. Refuse oversize
        // writes rather than silently fragmenting — a 65535-byte
        // ceiling is well above any single RDP PDU we emit.
        if buf.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gateway write exceeds HTTP_DATA_PACKET u16 limit",
            ));
        }
        let mut out_buf = WriteBuf::new();
        self.client
            .encode_data(buf, &mut out_buf)
            .map_err(io_other)?;
        write_chunk(&mut self.in_writer, out_buf.as_slice()).map_err(|e| match e {
            ConnectError::Io(io) => io,
            other => io::Error::other(alloc::format!("{other}")),
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.in_writer.flush()
    }
}

impl<R: Read, W: Write> GatewayConnection<R, W> {
    fn copy_pending(&mut self, buf: &mut [u8]) -> usize {
        let avail = &self.pending[self.pending_cursor..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.pending_cursor += n;
        n
    }
}

// =============================================================================
// Internal parse helpers (shared with ws_transport via transport_util)
// =============================================================================

use crate::transport_util::{io_other, parse_data_pdu as parse_data_pdu_shared};

fn parse_data_pdu(bytes: &[u8]) -> Result<Vec<u8>, GatewayError> {
    parse_data_pdu_shared(bytes, "data pdu: short header")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::GatewayClientConfig;
    use crate::http::encode_chunk;
    use crate::pdu::{
        ChannelResponsePdu, DataPdu as DataPduType, HandshakeResponsePdu, HttpUnicodeString,
        TunnelAuthResponsePdu, TunnelResponsePdu, HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
        HTTP_EXTENDED_AUTH_NONE, HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT,
        HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS, HTTP_TUNNEL_REDIR_DISABLE_ALL,
        HTTP_TUNNEL_RESPONSE_FIELD_CAPS, HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID, STATUS_SUCCESS,
    };

    use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
    use std::io::Cursor;

    fn encode_pdu<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf = std::vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        buf
    }

    /// Build a fake OUT-channel body: 100-byte preamble, then one
    /// chunk containing the four server response PDUs in order, then
    /// the final chunk marker.
    fn fake_out_channel_body(trailing_data: &[&[u8]]) -> Vec<u8> {
        let mut body = std::vec![0xFFu8; 100]; // random preamble

        // 1. HandshakeResponse
        body.extend(encode_pdu(&HandshakeResponsePdu::ok(HTTP_EXTENDED_AUTH_NONE)));

        // 2. TunnelResponse
        body.extend(encode_pdu(&TunnelResponsePdu {
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

        // 3. TunnelAuthResponse
        body.extend(encode_pdu(&TunnelAuthResponsePdu {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS
                | HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT,
            redir_flags: HTTP_TUNNEL_REDIR_DISABLE_ALL,
            idle_timeout_minutes: 30,
            soh_response: None,
        }));

        // 4. ChannelResponse
        body.extend(encode_pdu(&ChannelResponsePdu {
            error_code: STATUS_SUCCESS,
            fields_present: HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
            channel_id: 7,
            udp_port: 0,
            authn_cookie: None,
        }));

        // 5+. Data PDUs for the post-handshake path.
        for payload in trailing_data {
            body.extend(encode_pdu(&DataPduType::new(payload.to_vec())));
        }

        // Wrap the whole body in a single HTTP chunk + final chunk.
        let mut chunked = Vec::new();
        encode_chunk(&body, &mut chunked);
        crate::http::encode_final_chunk(&mut chunked);
        chunked
    }

    fn connect_with_fake_streams(
        trailing: &[&[u8]],
    ) -> (GatewayConnection<Cursor<Vec<u8>>, Vec<u8>>, ()) {
        let client = GatewayClient::new(GatewayClientConfig::new("target.host", "RDG-Client1"));
        let out_reader = Cursor::new(fake_out_channel_body(trailing));
        let in_writer: Vec<u8> = Vec::new();
        let conn = GatewayConnection::connect(client, in_writer, out_reader).unwrap();
        (conn, ())
    }

    #[test]
    fn connect_runs_full_handshake() {
        let (conn, _) = connect_with_fake_streams(&[]);
        assert!(conn.client().is_connected());
        assert_eq!(conn.client().tunnel_id(), 0xDEAD_BEEF);
        assert_eq!(conn.client().channel_id(), 7);
        assert_eq!(conn.client().idle_timeout_minutes(), 30);
    }

    #[test]
    fn connect_writes_all_four_client_pdus_as_chunks() {
        let (conn, _) = connect_with_fake_streams(&[]);
        // The in_writer contains four chunked frames — one per client
        // PDU (Handshake, TunnelCreate, TunnelAuth, ChannelCreate).
        // Decoding the whole stream back should give four MS-TSGU PDUs.
        let in_bytes = conn.in_writer.clone();
        let mut dec = ChunkedDecoder::new();
        let body = dec.feed(&in_bytes).unwrap();

        // Walk the body and count PDUs by parsing each packet_length.
        let mut offset = 0;
        let mut pdus = 0;
        while offset + PACKET_HEADER_SIZE <= body.len() {
            let size = find_packet_size(&body[offset..]).unwrap().unwrap();
            assert!(offset + size <= body.len(), "body truncated mid-PDU");
            offset += size;
            pdus += 1;
        }
        assert_eq!(pdus, 4);
    }

    #[test]
    fn read_returns_wrapped_data_pdu_payload() {
        let payload = b"\x03\x00\x00\x07\x02\xF0\x80"; // tiny X.224
        let (mut conn, _) = connect_with_fake_streams(&[payload]);
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], payload);
    }

    #[test]
    fn read_handles_partial_caller_buffer() {
        let payload = b"ABCDEFGHIJKLMNOP";
        let (mut conn, _) = connect_with_fake_streams(&[payload]);
        // Read 4 bytes at a time, expect the full payload in sequence.
        let mut acc = Vec::new();
        let mut chunk = [0u8; 4];
        while acc.len() < payload.len() {
            let n = conn.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            acc.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(acc, payload);
    }

    #[test]
    fn read_multiple_data_pdus_in_sequence() {
        let a: &[u8] = b"first";
        let b: &[u8] = b"second_message";
        let (mut conn, _) = connect_with_fake_streams(&[a, b]);
        let mut got_a = std::vec![0u8; a.len()];
        conn.read_exact(&mut got_a).unwrap();
        assert_eq!(got_a, a);
        let mut got_b = std::vec![0u8; b.len()];
        conn.read_exact(&mut got_b).unwrap();
        assert_eq!(got_b, b);
    }

    #[test]
    fn write_wraps_caller_bytes_in_data_pdu_and_chunk() {
        let (mut conn, _) = connect_with_fake_streams(&[]);
        // Remember how many bytes the handshake wrote into in_writer.
        let handshake_len = conn.in_writer.len();
        let payload = [0x01, 0x02, 0x03, 0x04];
        conn.write_all(&payload).unwrap();

        // The bytes appended after the handshake form one chunked
        // frame wrapping one HTTP_DATA_PACKET wrapping `payload`.
        let new_bytes = &conn.in_writer[handshake_len..];
        let mut dec = ChunkedDecoder::new();
        let body = dec.feed(new_bytes).unwrap();
        // Body = one DataPdu with `payload` inside.
        let mut cur = ReadCursor::new(&body);
        let pdu = DataPduType::decode(&mut cur).unwrap();
        assert_eq!(pdu.data, payload);
    }

    #[test]
    fn write_rejects_oversize_payload() {
        let (mut conn, _) = connect_with_fake_streams(&[]);
        let huge = std::vec![0u8; u16::MAX as usize + 1];
        let err = conn.write(&huge).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
