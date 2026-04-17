//! End-to-end integration test for the RPC-over-HTTP v2 gateway stack
//! (§10.1 layer C6).
//!
//! Builds an in-process mock rpcproxy that speaks:
//!   1. HTTP NTLM 401 retry on two separate TCP channels (IN / OUT)
//!   2. CONN/A1 → CONN/A3 + CONN/C2 on the OUT channel (MS-RPCH §2.2.4.x)
//!   3. DCE/RPC BIND → BIND_ACK
//!   4. Canned TsProxy responses in the exact order the client issues
//!      them (CreateTunnel, AuthorizeTunnel, CreateChannel, SetupReceivePipe)
//!   5. Streams one pipe RESPONSE with 8 bytes of "server→client" payload
//!   6. Consumes the client's first SendToServer REQUEST and returns
//!      ERROR_SUCCESS, then reads the RDP payload bytes and asserts
//!      they match what the client wrote.
//!
//! The TLS upgrader is a no-op pass-through — the test exercises the
//! full TsProxy stack over raw TCP, which is what `establish_gateway_tunnel_rpch`
//! reduces to once TLS is trivially transparent.
//!
//! Verified behaviour:
//!   * CONN/A/B/C completes
//!   * BIND accepted on presentation-context id 0
//!   * Full TsProxy state machine transitions through PipeCreated
//!   * Write path wraps the payload in SendToServer with correct
//!     big-endian length fields
//!   * Read path extracts stream stub bytes from a PFC_FIRST-only
//!     RESPONSE fragment

use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

use justrdp_blocking::gateway::{establish_gateway_tunnel_rpch, RpchGatewayConfig};
use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_gateway::auth::base64_encode;
use justrdp_gateway::rpch::errors::{ERROR_GRACEFUL_DISCONNECT, ERROR_SUCCESS};
use justrdp_gateway::rpch::types::{
    ContextHandle, TsgPacket, TsgPacketQuarEncResponse, TsgPacketResponse, TsgRedirectionFlags,
};
use justrdp_gateway::NtlmCredentials;
use justrdp_rpch::ndr::NdrEncoder;
use justrdp_rpch::pdu::uuid::RpcUuid;
use justrdp_rpch::pdu::{
    BindAckPdu, ContextResult, RtsCommand, RtsPdu, SyntaxId, BIND_ACK_PTYPE, BIND_PTYPE,
    PFC_FIRST_FRAG, PFC_LAST_FRAG, REQUEST_PTYPE, RESULT_ACCEPTANCE, RTS_FLAG_NONE,
};
use justrdp_tls::{ReadWrite, TlsError, TlsUpgradeResult, TlsUpgrader};

// =============================================================================
// No-op TLS upgrader (tests run raw over TCP)
// =============================================================================

struct Passthrough<S: Read + Write>(S);

impl<S: Read + Write> Read for Passthrough<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: Read + Write> Write for Passthrough<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

struct NoopUpgrader;

impl TlsUpgrader for NoopUpgrader {
    type Stream = Passthrough<Box<dyn ReadWrite>>;
    fn upgrade<S: Read + Write + 'static>(
        &self,
        stream: S,
        _server_name: &str,
    ) -> Result<TlsUpgradeResult<Self::Stream>, TlsError> {
        let boxed: Box<dyn ReadWrite> = Box::new(stream);
        Ok(TlsUpgradeResult {
            stream: Passthrough(boxed),
            server_public_key: vec![0u8; 32],
        })
    }
}

// =============================================================================
// NTLM helpers — synthesize a minimal CHALLENGE that drives NtlmClient
// =============================================================================

fn synthetic_challenge() -> Vec<u8> {
    use justrdp_pdu::ntlm::messages::{to_utf16le, NegotiateFlags};
    let nb = to_utf16le("TEST");
    let mut target_info = Vec::new();
    target_info.extend_from_slice(&2u16.to_le_bytes());
    target_info.extend_from_slice(&(nb.len() as u16).to_le_bytes());
    target_info.extend_from_slice(&nb);
    target_info.extend_from_slice(&[0, 0, 0, 0]); // EOL

    let target_name = to_utf16le("TEST");
    let header_size = 56u32;
    let target_name_off = header_size;
    let target_info_off = target_name_off + target_name.len() as u32;
    let flags = NegotiateFlags::client_default();

    let mut buf = Vec::new();
    buf.extend_from_slice(b"NTLMSSP\0");
    buf.extend_from_slice(&2u32.to_le_bytes());
    buf.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&target_name_off.to_le_bytes());
    buf.extend_from_slice(&flags.bits().to_le_bytes());
    buf.extend_from_slice(&[0xAAu8; 8]);
    buf.extend_from_slice(&[0u8; 8]);
    buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    buf.extend_from_slice(&target_info_off.to_le_bytes());
    buf.extend_from_slice(&[10, 0, 0x61, 0x58, 0, 0, 0, 15]);
    buf.extend_from_slice(&target_name);
    buf.extend_from_slice(&target_info);
    buf
}

// =============================================================================
// HTTP parsing utilities
// =============================================================================

fn read_headers<R: Read>(reader: &mut R) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).unwrap();
        if n == 0 {
            panic!("EOF while reading HTTP headers");
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            return buf;
        }
        if buf.len() > 16 * 1024 {
            panic!("runaway HTTP headers");
        }
    }
}

/// Run the server side of the three-round NTLM 401 retry dance on
/// `stream`. Expects three HTTP request heads from the client.
/// Writes 401, 401+challenge, 200 in turn.
fn handle_ntlm_401_retry<S: Read + Write>(stream: &mut S) {
    let challenge_b64 = base64_encode(&synthetic_challenge());

    // Round 1: anonymous → 401.
    let _hdr1 = read_headers(stream);
    stream
        .write_all(
            b"HTTP/1.1 401 Unauthorized\r\n\
              WWW-Authenticate: NTLM\r\n\
              Content-Length: 0\r\n\
              \r\n",
        )
        .unwrap();

    // Round 2: NEGOTIATE → 401 + challenge.
    let _hdr2 = read_headers(stream);
    let resp2 = format!(
        "HTTP/1.1 401 Unauthorized\r\n\
         WWW-Authenticate: NTLM {challenge_b64}\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );
    stream.write_all(resp2.as_bytes()).unwrap();

    // Round 3: AUTHENTICATE → 200 OK.
    let _hdr3 = read_headers(stream);
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\n\
              Content-Type: application/rpc\r\n\
              \r\n",
        )
        .unwrap();
}

// =============================================================================
// PDU helpers (mirror the patterns used in justrdp-rpch unit tests)
// =============================================================================

fn encode_rts(pdu: &RtsPdu) -> Vec<u8> {
    let mut out = vec![0u8; pdu.size()];
    let mut w = WriteCursor::new(&mut out);
    pdu.encode(&mut w).unwrap();
    out
}

fn conn_a3() -> Vec<u8> {
    encode_rts(&RtsPdu {
        pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
        flags: RTS_FLAG_NONE,
        commands: vec![
            RtsCommand::Version(1),
            RtsCommand::ReceiveWindowSize(65_536),
        ],
    })
}

fn conn_c2() -> Vec<u8> {
    encode_rts(&RtsPdu {
        pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
        flags: RTS_FLAG_NONE,
        commands: vec![
            RtsCommand::Version(1),
            RtsCommand::ReceiveWindowSize(65_536),
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
        assoc_group_id: 0x1234,
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

fn encode_response(call_id: u32, pfc: u8, stub: Vec<u8>) -> Vec<u8> {
    let resp = justrdp_rpch::pdu::ResponsePdu {
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

fn tunnel_handle() -> ContextHandle {
    ContextHandle {
        attributes: 1,
        uuid: RpcUuid::from_str_unchecked("11111111-aaaa-bbbb-cccc-dddddddddddd"),
    }
}

fn channel_handle() -> ContextHandle {
    ContextHandle {
        attributes: 2,
        uuid: RpcUuid::from_str_unchecked("22222222-eeee-ffff-1111-222222222222"),
    }
}

fn create_tunnel_response_stub() -> Vec<u8> {
    let mut e = NdrEncoder::new();
    let _ = e.write_unique_pointer(true);
    TsgPacket::QuarEncResponse(TsgPacketQuarEncResponse {
        flags: 0,
        cert_chain: None,
        nonce: RpcUuid::NIL,
        version_caps: None,
    })
    .encode_ndr(&mut e);
    tunnel_handle().encode_ndr(&mut e);
    e.write_u32(0xAAAA); // tunnel_id
    e.write_u32(ERROR_SUCCESS);
    e.into_bytes()
}

fn authorize_tunnel_response_stub() -> Vec<u8> {
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

fn create_channel_response_stub() -> Vec<u8> {
    let mut e = NdrEncoder::new();
    channel_handle().encode_ndr(&mut e);
    e.write_u32(0xBBBB); // channel_id
    e.write_u32(ERROR_SUCCESS);
    e.into_bytes()
}

// =============================================================================
// Frame reader — peek common-header frag_length and read one full PDU
// =============================================================================

fn read_one_pdu<R: Read>(reader: &mut R) -> Vec<u8> {
    let mut header = [0u8; 16];
    reader.read_exact(&mut header).unwrap();
    let frag_length = u16::from_le_bytes([header[8], header[9]]) as usize;
    assert!(frag_length >= 16);
    let mut body = vec![0u8; frag_length - 16];
    reader.read_exact(&mut body).unwrap();
    let mut out = Vec::with_capacity(frag_length);
    out.extend_from_slice(&header);
    out.extend_from_slice(&body);
    out
}

// =============================================================================
// Mock gateway server
// =============================================================================

/// Server-side event sent from the IN-thread to the OUT-thread so
/// the OUT-thread knows what to respond with.
#[derive(Debug)]
enum InEvent {
    /// Client finished sending CONN/B1. OUT thread may now send
    /// CONN/A3 + C2 (the OUT thread is expected to be waiting).
    ConnB1Received,
    /// Client sent a REQUEST PDU (BIND / REQUEST). The OUT thread
    /// replies based on the opnum / ptype.
    Request(Vec<u8>),
}

/// Run the mock server. Binds two TcpListeners (same port via
/// shared listener acceptor) and orchestrates both channels using
/// mpsc to coordinate REQUEST → RESPONSE pairing.
fn run_mock_server(
    listener: TcpListener,
    client_rdp_payload_tx: Sender<Vec<u8>>,
) {
    // The client's `establish_gateway_tunnel_rpch` opens OUT
    // channel first, fully authenticates it through the three-
    // round NTLM dance, and only then dials IN. So we must
    // accept + authenticate OUT, then accept + authenticate IN.
    // Accepting IN before OUT's auth completes would deadlock
    // the client.
    let (mut out_sock, _) = listener.accept().unwrap();
    handle_ntlm_401_retry(&mut out_sock);

    let (in_sock, _) = listener.accept().unwrap();

    // One-way coordination channel.
    let (in_tx, in_rx): (Sender<InEvent>, Receiver<InEvent>) = channel();

    // IN thread.
    let in_handle = thread::spawn(move || {
        let mut s = in_sock;
        handle_ntlm_401_retry(&mut s);

        // CONN/B1 — first PDU on the IN channel request body.
        let b1 = read_one_pdu(&mut s);
        assert_eq!(b1[2], justrdp_rpch::pdu::RTS_PTYPE, "expected RTS for CONN/B1");
        in_tx.send(InEvent::ConnB1Received).unwrap();

        // From here on, every PDU is a DCE/RPC REQUEST: BIND,
        // CreateTunnel, AuthorizeTunnel, CreateChannel,
        // SetupReceivePipe, then one or more SendToServer.
        loop {
            let pdu = match read_one_pdu_or_eof(&mut s) {
                Some(p) => p,
                None => break,
            };
            in_tx.send(InEvent::Request(pdu)).unwrap();
        }
    });

    // OUT thread — this is `run_mock_server`'s own body.
    let mut out = out_sock;

    // Read CONN/A1 on the OUT channel request body.
    let a1 = read_one_pdu(&mut out);
    assert_eq!(a1[2], justrdp_rpch::pdu::RTS_PTYPE, "expected RTS for CONN/A1");

    // Wait until IN thread has also seen CONN/B1 before emitting A3/C2.
    match in_rx.recv().unwrap() {
        InEvent::ConnB1Received => {}
        other => panic!("expected ConnB1Received first, got {other:?}"),
    }
    out.write_all(&conn_a3()).unwrap();
    out.write_all(&conn_c2()).unwrap();

    // Process REQUEST PDUs. Order is deterministic from the
    // client's state machine.
    // 1. BIND → BIND_ACK
    let bind = match in_rx.recv().unwrap() {
        InEvent::Request(p) => p,
        other => panic!("expected BIND, got {other:?}"),
    };
    assert_eq!(bind[2], BIND_PTYPE);
    let bind_call_id = u32::from_le_bytes([bind[12], bind[13], bind[14], bind[15]]);
    out.write_all(&encode_bind_ack(bind_call_id)).unwrap();

    // 2. CreateTunnel REQUEST → RESPONSE
    let req = match in_rx.recv().unwrap() {
        InEvent::Request(p) => p,
        other => panic!("expected REQUEST, got {other:?}"),
    };
    assert_eq!(req[2], REQUEST_PTYPE);
    let call_id = u32::from_le_bytes([req[12], req[13], req[14], req[15]]);
    out.write_all(&encode_response(
        call_id,
        PFC_FIRST_FRAG | PFC_LAST_FRAG,
        create_tunnel_response_stub(),
    ))
    .unwrap();

    // 3. AuthorizeTunnel REQUEST → RESPONSE
    let req = match in_rx.recv().unwrap() {
        InEvent::Request(p) => p,
        _ => unreachable!(),
    };
    let call_id = u32::from_le_bytes([req[12], req[13], req[14], req[15]]);
    out.write_all(&encode_response(
        call_id,
        PFC_FIRST_FRAG | PFC_LAST_FRAG,
        authorize_tunnel_response_stub(),
    ))
    .unwrap();

    // 4. CreateChannel REQUEST → RESPONSE
    let req = match in_rx.recv().unwrap() {
        InEvent::Request(p) => p,
        _ => unreachable!(),
    };
    let call_id = u32::from_le_bytes([req[12], req[13], req[14], req[15]]);
    out.write_all(&encode_response(
        call_id,
        PFC_FIRST_FRAG | PFC_LAST_FRAG,
        create_channel_response_stub(),
    ))
    .unwrap();

    // 5. SetupReceivePipe REQUEST — remember its call_id for the
    //    streamed pipe responses.
    let pipe_req = match in_rx.recv().unwrap() {
        InEvent::Request(p) => p,
        _ => unreachable!(),
    };
    let pipe_call_id = u32::from_le_bytes([
        pipe_req[12], pipe_req[13], pipe_req[14], pipe_req[15],
    ]);

    // Push one pipe RESPONSE with 8 bytes of scripted "server →
    // client" RDP payload, non-final.
    let pipe_payload = b"SERVER01";
    out.write_all(&encode_response(
        pipe_call_id,
        PFC_FIRST_FRAG,
        pipe_payload.to_vec(),
    ))
    .unwrap();

    // 6. First SendToServer REQUEST — extract the payload and ack.
    let s2s_req = match in_rx.recv().unwrap() {
        InEvent::Request(p) => p,
        _ => unreachable!(),
    };
    let s2s_call_id = u32::from_le_bytes([
        s2s_req[12], s2s_req[13], s2s_req[14], s2s_req[15],
    ]);
    // Parse the SendToServer stub_data layout: 20-byte handle +
    // 4 totalDataBytes BE + 4 numBuffers BE + 12 length-fields BE
    // + buffer1 bytes.
    let req = justrdp_rpch::pdu::RequestPdu::decode(&mut ReadCursor::new(&s2s_req));
    let stub = req.unwrap().stub_data;
    assert!(stub.len() >= 40);
    let buffer1_length =
        u32::from_be_bytes([stub[28], stub[29], stub[30], stub[31]]) as usize;
    let buffer1 = &stub[40..40 + buffer1_length];
    client_rdp_payload_tx.send(buffer1.to_vec()).unwrap();

    // Ack with DWORD = ERROR_SUCCESS.
    out.write_all(&encode_response(
        s2s_call_id,
        PFC_FIRST_FRAG | PFC_LAST_FRAG,
        ERROR_SUCCESS.to_le_bytes().to_vec(),
    ))
    .unwrap();

    // Close the pipe cleanly with the final fragment carrying the
    // DWORD return value (ERROR_GRACEFUL_DISCONNECT).
    out.write_all(&encode_response(
        pipe_call_id,
        PFC_FIRST_FRAG | PFC_LAST_FRAG,
        ERROR_GRACEFUL_DISCONNECT.to_le_bytes().to_vec(),
    ))
    .unwrap();

    // Shut down IN side: drop the socket by joining the handle.
    let _ = in_handle.join();
}

fn read_one_pdu_or_eof<R: Read>(reader: &mut R) -> Option<Vec<u8>> {
    let mut header = [0u8; 16];
    let mut read = 0;
    while read < 16 {
        let n = reader.read(&mut header[read..]).ok()?;
        if n == 0 {
            return if read == 0 { None } else { panic!("EOF mid-header") };
        }
        read += n;
    }
    let frag_length = u16::from_le_bytes([header[8], header[9]]) as usize;
    let mut body = vec![0u8; frag_length - 16];
    reader.read_exact(&mut body).unwrap();
    let mut out = Vec::with_capacity(frag_length);
    out.extend_from_slice(&header);
    out.extend_from_slice(&body);
    Some(out)
}

// =============================================================================
// The test
// =============================================================================

#[test]
fn end_to_end_rpch_tunnel_write_and_read() {
    // Two sequential accepts on one listener — `TcpStream::connect`
    // on the client side is blocking, so the client connects IN
    // and OUT in the order dictated by `establish_gateway_tunnel_rpch`
    // (OUT first, then IN).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (client_payload_tx, client_payload_rx) = channel::<Vec<u8>>();
    let server_handle = thread::spawn(move || run_mock_server(listener, client_payload_tx));

    // Client side.
    let cfg = RpchGatewayConfig::new(
        format!("127.0.0.1:{}", addr.port()),
        "localhost",
        NtlmCredentials::new("alice", "hunter2", ""),
        "rdp.example.com",
    );
    let mut tunnel = establish_gateway_tunnel_rpch(&cfg, &NoopUpgrader).unwrap();

    // Read 8 bytes the server pre-scripted onto the pipe.
    let mut read_buf = [0u8; 8];
    tunnel.read_exact(&mut read_buf).unwrap();
    assert_eq!(&read_buf, b"SERVER01");

    // Write 5 bytes and verify the server received them through
    // SendToServer's buffer1.
    tunnel.write_all(b"HELLO").unwrap();

    let got = client_payload_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("mock server must relay the SendToServer payload");
    assert_eq!(got, b"HELLO");

    // Now that the server closed the pipe, the next read returns
    // EOF (0 bytes).
    let mut end_buf = [0u8; 4];
    let n = tunnel.read(&mut end_buf).unwrap();
    assert_eq!(n, 0, "tunnel must report EOF after pipe closes");

    // Drop the tunnel to release the server-side IN socket. Give
    // the server thread a chance to exit cleanly.
    drop(tunnel);
    let _ = server_handle.join();
}
