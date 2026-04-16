//! End-to-end mock integration test for the MS-TSGU HTTP Transport.
//!
//! Drives the full client-side flow through a scripted "mock gateway":
//!
//! 1. **HTTP NTLM 401 retry loop** on the OUT channel — three rounds
//!    using real [`NtlmClient`], [`RdgHttpRequest`],
//!    [`parse_www_authenticate`], and [`build_authorization_header`].
//! 2. **MS-TSGU handshake** via [`GatewayConnection::connect`] over the
//!    stream that survives the 401 dance (positioned at the start of
//!    the 200 OK chunked body).
//! 3. **Data path** — read one server-originated `HTTP_DATA_PACKET`
//!    payload, write one client-originated payload, clean shutdown.
//!
//! The "gateway" side is a pre-scripted `Cursor<Vec<u8>>`: since the
//! mock does not validate NTLM cryptographically, it can emit its
//! three canned responses up-front without ever looking at the
//! client's bytes. The test then asserts on the client's outbound
//! byte stream to prove the expected HTTP requests were produced in
//! the correct order.

#![allow(clippy::unwrap_used)]

use std::io::{Cursor, Read, Write};

use justrdp_core::{Encode, WriteCursor};
use justrdp_gateway::{
    base64_encode, build_authorization_header, encode_chunk, encode_final_chunk,
    parse_www_authenticate, AuthScheme, ChannelResponsePdu, ChunkedDecoder, DataPdu,
    GatewayClient, GatewayClientConfig, GatewayConnection, HandshakeResponsePdu,
    HttpUnicodeString, NtlmClient, NtlmCredentials, NtlmRandom, RdgHttpRequest, RdgMethod,
    TunnelAuthResponsePdu, TunnelResponsePdu, HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
    HTTP_EXTENDED_AUTH_NONE, HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT,
    HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS, HTTP_TUNNEL_REDIR_DISABLE_ALL,
    HTTP_TUNNEL_RESPONSE_FIELD_CAPS, HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID, STATUS_SUCCESS,
};
use justrdp_pdu::ntlm::messages::{to_utf16le, NegotiateFlags};

// =============================================================================
// Helpers
// =============================================================================

fn encode_pdu<T: Encode>(pdu: &T) -> Vec<u8> {
    let mut buf = vec![0u8; pdu.size()];
    let mut cur = WriteCursor::new(&mut buf);
    pdu.encode(&mut cur).unwrap();
    buf
}

/// Minimal synthetic NTLM CHALLENGE message — just enough to drive
/// `NtlmClient::authenticate` through target_info parsing, response
/// computation, and MIC generation. (Mirrors the helper in `auth.rs`
/// tests; the integration crate can't reach the private test module.)
fn synthetic_challenge() -> Vec<u8> {
    let nb = to_utf16le("TEST");
    let mut target_info = Vec::new();
    target_info.extend_from_slice(&2u16.to_le_bytes()); // AvId = MsvAvNbDomainName
    target_info.extend_from_slice(&(nb.len() as u16).to_le_bytes());
    target_info.extend_from_slice(&nb);
    target_info.extend_from_slice(&[0, 0, 0, 0]); // MsvAvEOL

    let target_name = to_utf16le("TEST");
    let header_size = 56u32; // §2.2.1.2 fixed header with Version
    let target_name_off = header_size;
    let target_info_off = target_name_off + target_name.len() as u32;

    let flags = NegotiateFlags::client_default();

    let mut buf = Vec::new();
    buf.extend_from_slice(b"NTLMSSP\0");
    buf.extend_from_slice(&2u32.to_le_bytes()); // NTLM_CHALLENGE
    buf.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&target_name_off.to_le_bytes());
    buf.extend_from_slice(&flags.bits().to_le_bytes());
    buf.extend_from_slice(&[0xAAu8; 8]); // ServerChallenge
    buf.extend_from_slice(&[0u8; 8]); // Reserved
    buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    buf.extend_from_slice(&target_info_off.to_le_bytes());
    buf.extend_from_slice(&[10, 0, 0x61, 0x58, 0, 0, 0, 15]); // windows_10() version
    buf.extend_from_slice(&target_name);
    buf.extend_from_slice(&target_info);
    buf
}

/// Build the OUT channel body a cooperative gateway would stream back:
/// the 100-byte random preamble, the four MS-TSGU handshake responses,
/// and any trailing Data PDUs.
fn build_handshake_body(tunnel_id: u32, channel_id: u32, trailing: &[&[u8]]) -> Vec<u8> {
    let mut body = vec![0xFFu8; 100];
    body.extend(encode_pdu(&HandshakeResponsePdu::ok(HTTP_EXTENDED_AUTH_NONE)));
    body.extend(encode_pdu(&TunnelResponsePdu {
        server_version: 1,
        status_code: STATUS_SUCCESS,
        fields_present: HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID | HTTP_TUNNEL_RESPONSE_FIELD_CAPS,
        tunnel_id,
        caps_flags: 0x3F,
        nonce: [0; 16],
        server_cert: HttpUnicodeString::empty(),
        consent_msg: HttpUnicodeString::empty(),
    }));
    body.extend(encode_pdu(&TunnelAuthResponsePdu {
        error_code: STATUS_SUCCESS,
        fields_present: HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS
            | HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT,
        redir_flags: HTTP_TUNNEL_REDIR_DISABLE_ALL,
        idle_timeout_minutes: 30,
        soh_response: None,
    }));
    body.extend(encode_pdu(&ChannelResponsePdu {
        error_code: STATUS_SUCCESS,
        fields_present: HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
        channel_id,
        udp_port: 0,
        authn_cookie: None,
    }));
    for payload in trailing {
        body.extend(encode_pdu(&DataPdu::new(payload.to_vec())));
    }
    body
}

/// Wrap `body` in one HTTP chunk + final-chunk marker.
fn chunked(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_chunk(body, &mut out);
    encode_final_chunk(&mut out);
    out
}

/// Read bytes from the scripted server cursor up to and including the
/// first `\r\n\r\n` separator; returns the header block.
fn read_http_headers(cur: &mut Cursor<Vec<u8>>) -> Vec<u8> {
    let start = cur.position() as usize;
    let (end, block) = {
        let data = cur.get_ref();
        let idx = data[start..]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("no CRLFCRLF in scripted server response");
        let end = start + idx + 4;
        (end, data[start..end].to_vec())
    };
    cur.set_position(end as u64);
    block
}

fn find_header_value<'a>(headers: &'a [u8], name: &str) -> Option<&'a str> {
    let s = core::str::from_utf8(headers).ok()?;
    for line in s.split("\r\n") {
        if let Some(rest) = line.strip_prefix(&alloc_fmt_prefix(name)) {
            return Some(rest);
        }
        // case-insensitive fallback
        if let Some((h, v)) = line.split_once(": ") {
            if h.eq_ignore_ascii_case(name) {
                return Some(v);
            }
        }
    }
    None
}

fn alloc_fmt_prefix(name: &str) -> String {
    let mut s = String::with_capacity(name.len() + 2);
    s.push_str(name);
    s.push_str(": ");
    s
}

// =============================================================================
// The integration test
// =============================================================================

#[test]
fn end_to_end_ntlm_retry_then_gateway_handshake_then_data() {
    let challenge = synthetic_challenge();
    let tunnel_id: u32 = 0xDEAD_BEEF;
    let channel_id: u32 = 7;
    let server_to_client_payload: &[u8] = b"HELLO-FROM-GATEWAY";

    // -----------------------------------------------------------------
    // 1. Build the scripted "gateway" response stream:
    //    401 (invite NTLM) → 401 (challenge) → 200 OK + chunked body.
    // -----------------------------------------------------------------
    let mut scripted = Vec::<u8>::new();
    scripted.extend_from_slice(
        b"HTTP/1.1 401 Unauthorized\r\n\
          WWW-Authenticate: NTLM\r\n\
          Content-Length: 0\r\n\
          \r\n",
    );
    let resp2 = format!(
        "HTTP/1.1 401 Unauthorized\r\n\
         WWW-Authenticate: NTLM {}\r\n\
         Content-Length: 0\r\n\
         \r\n",
        base64_encode(&challenge)
    );
    scripted.extend_from_slice(resp2.as_bytes());
    scripted.extend_from_slice(
        b"HTTP/1.1 200 OK\r\n\
          Content-Type: application/octet-stream\r\n\
          Transfer-Encoding: chunked\r\n\
          \r\n",
    );
    let body = build_handshake_body(tunnel_id, channel_id, &[server_to_client_payload]);
    scripted.extend_from_slice(&chunked(&body));
    let mut server = Cursor::new(scripted);

    // -----------------------------------------------------------------
    // 2. Drive the HTTP NTLM 401 retry loop (OUT channel).
    // -----------------------------------------------------------------
    let connection_id = [0x11u8; 16];
    let mut ntlm_client = NtlmClient::new(
        NtlmCredentials::new("alice", "hunter2", ""),
        NtlmRandom {
            client_challenge: [0x22u8; 8],
            exported_session_key: [0x33u8; 16],
        },
    );
    let mut auth_requests: Vec<u8> = Vec::new();

    // --- Round 1: anonymous request → 401 (bare NTLM) ---
    let req1 = RdgHttpRequest::new(RdgMethod::OutData, "gw.example.com", connection_id);
    auth_requests.extend_from_slice(&req1.to_bytes());

    let headers1 = read_http_headers(&mut server);
    assert!(headers1.starts_with(b"HTTP/1.1 401"));
    let www1 = find_header_value(&headers1, "WWW-Authenticate").unwrap();
    let token1 = parse_www_authenticate(www1, AuthScheme::Ntlm).unwrap();
    assert!(
        token1.is_empty(),
        "first 401 must not carry a challenge token"
    );

    // --- Round 2: Authorization: NTLM <Type1> → 401 with challenge ---
    let type1 = ntlm_client.negotiate().unwrap();
    assert_eq!(&type1[0..8], b"NTLMSSP\0");
    assert_eq!(&type1[8..12], &[0x01, 0x00, 0x00, 0x00]);

    let mut req2 = RdgHttpRequest::new(RdgMethod::OutData, "gw.example.com", connection_id);
    req2.authorization = Some(build_authorization_header(AuthScheme::Ntlm, &type1));
    auth_requests.extend_from_slice(&req2.to_bytes());

    let headers2 = read_http_headers(&mut server);
    assert!(headers2.starts_with(b"HTTP/1.1 401"));
    let www2 = find_header_value(&headers2, "WWW-Authenticate").unwrap();
    let received_challenge = parse_www_authenticate(www2, AuthScheme::Ntlm).unwrap();
    assert_eq!(
        received_challenge, challenge,
        "client must recover the exact challenge bytes from the header"
    );

    // --- Round 3: Authorization: NTLM <Type3> → 200 OK ---
    let type3 = ntlm_client.authenticate(&received_challenge).unwrap();
    assert_eq!(&type3[0..8], b"NTLMSSP\0");
    assert_eq!(&type3[8..12], &[0x03, 0x00, 0x00, 0x00]);

    let mut req3 = RdgHttpRequest::new(RdgMethod::OutData, "gw.example.com", connection_id);
    req3.authorization = Some(build_authorization_header(AuthScheme::Ntlm, &type3));
    auth_requests.extend_from_slice(&req3.to_bytes());

    let headers3 = read_http_headers(&mut server);
    assert!(headers3.starts_with(b"HTTP/1.1 200"));

    // -----------------------------------------------------------------
    // 3. Sanity-check the HTTP requests the client emitted.
    // -----------------------------------------------------------------
    // Three RDG_OUT_DATA request lines.
    let req_count = auth_requests
        .windows("RDG_OUT_DATA".len())
        .filter(|w| *w == b"RDG_OUT_DATA")
        .count();
    assert_eq!(req_count, 3, "client must issue exactly three HTTP requests");
    // Exactly two of them carry an Authorization header.
    let auth_header_count = auth_requests
        .windows("Authorization: NTLM ".len())
        .filter(|w| *w == b"Authorization: NTLM ")
        .count();
    assert_eq!(
        auth_header_count, 2,
        "only the NEGOTIATE and AUTHENTICATE retries carry an Authorization header"
    );

    // -----------------------------------------------------------------
    // 4. Hand the post-auth stream to GatewayConnection::connect and
    //    drive the MS-TSGU handshake.
    // -----------------------------------------------------------------
    let in_writer: Vec<u8> = Vec::new();
    let gw_client = GatewayClient::new(GatewayClientConfig::new("rdp.example.com", "RDG-Client1"));
    let mut conn = GatewayConnection::connect(gw_client, in_writer, server).unwrap();
    assert!(conn.client().is_connected());
    assert_eq!(conn.client().tunnel_id(), tunnel_id);
    assert_eq!(conn.client().channel_id(), channel_id);
    assert_eq!(conn.client().idle_timeout_minutes(), 30);

    // -----------------------------------------------------------------
    // 5. Data path: read the trailing Data PDU, write one back.
    // -----------------------------------------------------------------
    let mut got = vec![0u8; server_to_client_payload.len()];
    conn.read_exact(&mut got).unwrap();
    assert_eq!(got.as_slice(), server_to_client_payload);

    let client_to_server_payload = b"CLIENT-DATA-42";
    conn.write_all(client_to_server_payload).unwrap();
    conn.flush().unwrap();

    // Clean shutdown: recover the in_writer and inspect the bytes the
    // gateway handshake + data phase produced.
    let (_reader, handshake_bytes) = conn.shutdown().unwrap();

    // The handshake writer contains: four handshake request PDUs
    // (chunked), one Data PDU (chunked), one CloseChannel PDU (chunked),
    // and a final-chunk marker.
    let mut decoder = ChunkedDecoder::new();
    let decoded = decoder.feed(&handshake_bytes).unwrap();

    // Walk the decoded stream and count PDUs — we expect six:
    // Handshake, TunnelCreate, TunnelAuth, ChannelCreate, Data, Close.
    let mut offset = 0;
    let mut pdu_sizes = Vec::new();
    while offset + 8 <= decoded.len() {
        let size =
            u32::from_le_bytes([decoded[offset + 4], decoded[offset + 5], decoded[offset + 6], decoded[offset + 7]])
                as usize;
        assert!(offset + size <= decoded.len(), "truncated mid-PDU");
        pdu_sizes.push(size);
        offset += size;
    }
    assert_eq!(
        pdu_sizes.len(),
        6,
        "expected Handshake+Create+Auth+Create+Data+Close on the in_writer"
    );

    // The 5th PDU is the Data we wrote — verify its payload round-trips.
    let data_start: usize = pdu_sizes[..4].iter().sum();
    let data_len = pdu_sizes[4];
    let data_bytes = &decoded[data_start..data_start + data_len];
    let mut cur = justrdp_core::ReadCursor::new(data_bytes);
    let data_pdu = <DataPdu as justrdp_core::Decode>::decode(&mut cur).unwrap();
    assert_eq!(data_pdu.data, client_to_server_payload);
}
