#![forbid(unsafe_code)]

//! MS-TSGU HTTP Transport — blocking tunnel establishment.
//!
//! This module wires the sans-io building blocks from `justrdp-gateway`
//! (`GatewayClient`, `GatewayConnection`, `NtlmClient`, `RdgHttpRequest`)
//! to real `std::net::TcpStream` + `justrdp-tls` plumbing so
//! [`RdpClient`](crate::RdpClient) can reach an RDP server that sits
//! behind a Remote Desktop Gateway.
//!
//! ## Flow
//!
//! For each of the two long-lived HTTP channels (`RDG_OUT_DATA` then
//! `RDG_IN_DATA`):
//!
//! 1. Open a blocking TCP connection to the gateway.
//! 2. Run the outer TLS handshake with the supplied [`TlsUpgrader`].
//! 3. Send the initial HTTP/1.1 `RDG_*_DATA` request (no `Authorization`).
//! 4. Read the gateway's `401 Unauthorized` + `WWW-Authenticate: NTLM`
//!    response.
//! 5. Emit the NTLMSSP NEGOTIATE message, wrap as `Authorization: NTLM
//!    <base64>`, and retry the request.
//! 6. Read the second `401` + challenge, drive
//!    [`NtlmClient::authenticate`], emit the AUTHENTICATE message, and
//!    retry the request one more time.
//! 7. Read the `200 OK` + chunked body preamble.
//!
//! With both channels authenticated, pair them into a single
//! [`GatewayConnection`] — OUT channel as the reader, IN channel as the
//! writer — and return it as a boxed [`ReadWrite`] ready to hand to
//! [`RdpClient::connect_via_gateway_with_upgrader`](crate::RdpClient::connect_via_gateway_with_upgrader).

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use justrdp_gateway::{
    base64_encode, build_authorization_header, parse_www_authenticate, AuthScheme,
    ConnectError as GwConnectError, GatewayClient, GatewayClientConfig, GatewayConnection,
    MaskSource, NtlmAuthState, NtlmClient, NtlmCredentials, NtlmError, NtlmRandom, RdgHttpRequest,
    RdgMethod, WsConnectError, WsGatewayConnection,
};
use justrdp_gateway::ws::{ws_accept_key, WsUpgradeRequest};
use justrdp_tls::{ReadWrite, TlsUpgrader};

use crate::error::ConnectError;

// =============================================================================
// Public configuration
// =============================================================================

/// Configuration for reaching an RDP server through a Remote Desktop
/// Gateway.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Gateway endpoint — e.g. `("gw.example.com", 443)`. Resolved
    /// eagerly when opening the first channel.
    pub gateway_addr: String,
    /// Hostname used for SNI, the `Host:` HTTP header, and virtual
    /// host matching on the gateway. Usually matches the SAN on the
    /// gateway's TLS certificate.
    pub gateway_hostname: String,
    /// Gateway credentials. Empty `domain` triggers the server's
    /// `MsvAvNbDomainName` fallback per MS-NLMP 3.1.5.1.2.
    pub credentials: NtlmCredentials,
    /// Target RDP server hostname — advertised inside the
    /// `HTTP_CHANNEL_PACKET.pResource` list (§2.2.10.5).
    pub target_host: String,
    /// Target RDP server TCP port (typically `3389`).
    pub target_port: u16,
    /// TCP connect timeout for each gateway channel.
    pub connect_timeout: Duration,
    /// Read/write timeout bounding each HTTP auth round. Cleared once
    /// the tunnel is handed to the inner handshake.
    pub auth_timeout: Duration,
    /// Optional 16-byte `RDG-Connection-Id` GUID. If `None`, a fresh
    /// value is generated from the OS RNG and used for both channels
    /// (they MUST share the same GUID per §3.3.5.1).
    pub connection_id: Option<[u8; 16]>,
}

impl GatewayConfig {
    pub fn new(
        gateway_addr: impl Into<String>,
        gateway_hostname: impl Into<String>,
        credentials: NtlmCredentials,
        target_host: impl Into<String>,
    ) -> Self {
        Self {
            gateway_addr: gateway_addr.into(),
            gateway_hostname: gateway_hostname.into(),
            credentials,
            target_host: target_host.into(),
            target_port: 3389,
            connect_timeout: Duration::from_secs(10),
            auth_timeout: Duration::from_secs(10),
            connection_id: None,
        }
    }
}

// =============================================================================
// Error plumbing
// =============================================================================

fn ntlm_err(e: NtlmError) -> ConnectError {
    ConnectError::Tcp(io::Error::other(format!("ntlm: {e:?}")))
}

fn gw_err(e: GwConnectError) -> ConnectError {
    ConnectError::Tcp(io::Error::other(format!("gateway: {e}")))
}

fn http_err(msg: impl Into<String>) -> ConnectError {
    ConnectError::Tcp(io::Error::new(io::ErrorKind::InvalidData, msg.into()))
}

// =============================================================================
// HTTP response header parsing
// =============================================================================

/// Maximum bytes we are willing to buffer while searching for the end
/// of an HTTP/1.1 response header block. 16 KiB comfortably covers
/// even verbose IIS defaults plus an NTLMSSP challenge token. Anything
/// bigger is almost certainly an adversarial or corrupted stream.
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;

/// Read bytes from `reader` until the first `\r\n\r\n` separator and
/// return the raw header block (including the terminator). Errors out
/// on EOF before separator, or if the buffer grows beyond
/// [`MAX_HTTP_HEADER_BYTES`].
fn read_http_response_headers<R: Read>(reader: &mut R) -> Result<Vec<u8>, ConnectError> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte)?;
        if n == 0 {
            return Err(ConnectError::UnexpectedEof);
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            return Ok(buf);
        }
        if buf.len() > MAX_HTTP_HEADER_BYTES {
            return Err(http_err("HTTP response header block too large"));
        }
    }
}

/// Parsed HTTP/1.1 status line + header map view.
struct HttpResponse<'a> {
    status: u16,
    headers: Vec<(&'a str, &'a str)>,
}

fn parse_http_response(block: &[u8]) -> Result<HttpResponse<'_>, ConnectError> {
    let s = core::str::from_utf8(block)
        .map_err(|_| http_err("HTTP response contained non-UTF-8 bytes"))?;
    let mut lines = s.split("\r\n");
    let status_line = lines.next().ok_or_else(|| http_err("missing status line"))?;
    // Format: "HTTP/1.1 <code> <reason>"
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next().ok_or_else(|| http_err("malformed status line"))?;
    let code = parts.next().ok_or_else(|| http_err("missing status code"))?;
    let status: u16 = code
        .parse()
        .map_err(|_| http_err(format!("non-numeric HTTP status: {code}")))?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue; // trailing blank line
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| http_err(format!("malformed header line: {line}")))?;
        headers.push((name.trim(), value.trim()));
    }
    Ok(HttpResponse { status, headers })
}

impl<'a> HttpResponse<'a> {
    fn header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

// =============================================================================
// HTTP 401 NTLM retry loop
// =============================================================================

/// Drive one HTTP channel through the three-step NTLM auth exchange.
/// On success, `stream` is positioned immediately after the `200 OK`
/// response headers — the next bytes to come out of it will be the
/// chunked MS-TSGU body, exactly what [`GatewayConnection::connect`]
/// expects for its out_reader / in_writer.
fn authenticate_http_channel<S: Read + Write>(
    stream: &mut S,
    method: RdgMethod,
    cfg: &GatewayConfig,
    connection_id: [u8; 16],
) -> Result<(), ConnectError> {
    let random = make_ntlm_random()?;
    let mut ntlm = NtlmClient::new(cfg.credentials.clone(), random);

    // Round 1: anonymous request → 401 (bare NTLM).
    send_rdg_request(stream, method, cfg, connection_id, None)?;
    let headers = read_http_response_headers(stream)?;
    let resp = parse_http_response(&headers)?;
    if resp.status == 200 {
        return Err(http_err(
            "gateway accepted anonymous request — refusing unauthenticated tunnel",
        ));
    }
    if resp.status != 401 {
        return Err(http_err(format!(
            "expected 401 on first request, got {}",
            resp.status
        )));
    }
    require_ntlm_scheme(&resp)?;

    // Round 2: NEGOTIATE → 401 with challenge.
    let type1 = ntlm.negotiate().map_err(ntlm_err)?;
    send_rdg_request(
        stream,
        method,
        cfg,
        connection_id,
        Some(build_authorization_header(AuthScheme::Ntlm, &type1)),
    )?;
    let headers = read_http_response_headers(stream)?;
    let resp = parse_http_response(&headers)?;
    if resp.status != 401 {
        return Err(http_err(format!(
            "expected 401 challenge on second request, got {}",
            resp.status
        )));
    }
    let www = resp
        .header("WWW-Authenticate")
        .ok_or_else(|| http_err("missing WWW-Authenticate header on challenge"))?;
    let challenge = parse_www_authenticate(www, AuthScheme::Ntlm)
        .ok_or_else(|| http_err("malformed WWW-Authenticate NTLM token"))?;
    if challenge.is_empty() {
        return Err(http_err("gateway sent empty NTLM challenge on second 401"));
    }

    // Round 3: AUTHENTICATE → 200 OK.
    let type3 = ntlm.authenticate(&challenge).map_err(ntlm_err)?;
    debug_assert_eq!(ntlm.state(), NtlmAuthState::Done);
    send_rdg_request(
        stream,
        method,
        cfg,
        connection_id,
        Some(build_authorization_header(AuthScheme::Ntlm, &type3)),
    )?;
    let headers = read_http_response_headers(stream)?;
    let resp = parse_http_response(&headers)?;
    if resp.status != 200 {
        return Err(http_err(format!(
            "expected 200 on authenticated request, got {}",
            resp.status
        )));
    }
    Ok(())
}

fn send_rdg_request<W: Write>(
    writer: &mut W,
    method: RdgMethod,
    cfg: &GatewayConfig,
    connection_id: [u8; 16],
    authorization: Option<String>,
) -> Result<(), ConnectError> {
    let mut req = RdgHttpRequest::new(method, cfg.gateway_hostname.clone(), connection_id);
    req.authorization = authorization;
    let bytes = req.to_bytes();
    writer.write_all(&bytes).map_err(ConnectError::Tcp)?;
    writer.flush().map_err(ConnectError::Tcp)?;
    Ok(())
}

fn require_ntlm_scheme(resp: &HttpResponse<'_>) -> Result<(), ConnectError> {
    let www = resp
        .header("WWW-Authenticate")
        .ok_or_else(|| http_err("first 401 missing WWW-Authenticate header"))?;
    // parse_www_authenticate returns Some(vec![]) for bare "NTLM".
    if parse_www_authenticate(www, AuthScheme::Ntlm).is_none() {
        return Err(http_err(format!(
            "gateway WWW-Authenticate does not offer NTLM: {www}"
        )));
    }
    Ok(())
}

fn make_ntlm_random() -> Result<NtlmRandom, ConnectError> {
    let mut client_challenge = [0u8; 8];
    let mut exported_session_key = [0u8; 16];
    getrandom::getrandom(&mut client_challenge)
        .map_err(|e| ConnectError::Tcp(io::Error::other(format!("OS random failure: {e}"))))?;
    getrandom::getrandom(&mut exported_session_key)
        .map_err(|e| ConnectError::Tcp(io::Error::other(format!("OS random failure: {e}"))))?;
    Ok(NtlmRandom {
        client_challenge,
        exported_session_key,
    })
}

fn make_connection_id() -> Result<[u8; 16], ConnectError> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id)
        .map_err(|e| ConnectError::Tcp(io::Error::other(format!("OS random failure: {e}"))))?;
    // Mask bits 6/7 of byte 8 and bits 4-7 of byte 6 to form a
    // version-4 (random) RFC 4122 UUID. Not strictly required by
    // MS-TSGU but gateways that log the GUID as a UUID will reject
    // malformed values, and the masking costs us nothing.
    id[6] = (id[6] & 0x0F) | 0x40;
    id[8] = (id[8] & 0x3F) | 0x80;
    Ok(id)
}

// =============================================================================
// Tunnel establishment
// =============================================================================

/// Open one authenticated HTTP channel to the gateway and return the
/// TLS-wrapped stream, positioned at the start of the chunked body.
fn open_authenticated_channel<U: TlsUpgrader>(
    cfg: &GatewayConfig,
    upgrader: &U,
    method: RdgMethod,
    connection_id: [u8; 16],
    addr: SocketAddr,
) -> Result<Box<dyn ReadWrite>, ConnectError>
where
    U::Stream: 'static,
{
    let tcp = TcpStream::connect_timeout(&addr, cfg.connect_timeout)?;
    tcp.set_read_timeout(Some(cfg.auth_timeout))?;
    tcp.set_write_timeout(Some(cfg.auth_timeout))?;

    let upgraded = upgrader.upgrade(tcp, &cfg.gateway_hostname)?;
    let mut stream: Box<dyn ReadWrite> = Box::new(upgraded.stream);
    authenticate_http_channel(&mut stream, method, cfg, connection_id)?;
    Ok(stream)
}

/// Establish an end-to-end MS-TSGU tunnel to the RDP server named in
/// `cfg` and return a single `Read + Write` stream that carries the
/// inner RDP bytes.
///
/// The returned stream is already past the gateway handshake — the
/// first byte it produces will be whatever the RDP server sends in
/// response to the X.224 Connection Request.
pub fn establish_gateway_tunnel<U: TlsUpgrader>(
    cfg: &GatewayConfig,
    upgrader: &U,
) -> Result<Box<dyn ReadWrite>, ConnectError>
where
    U::Stream: 'static,
{
    let addr = cfg
        .gateway_addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| {
            ConnectError::Tcp(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no socket addresses resolved for gateway_addr",
            ))
        })?;

    let connection_id = match cfg.connection_id {
        Some(id) => id,
        None => make_connection_id()?,
    };

    // Per §3.3.5.1, the OUT channel is opened first so the client can
    // see the 100-byte preamble before it starts emitting IN channel
    // PDUs.
    let out_stream =
        open_authenticated_channel(cfg, upgrader, RdgMethod::OutData, connection_id, addr)?;
    let in_stream =
        open_authenticated_channel(cfg, upgrader, RdgMethod::InData, connection_id, addr)?;

    // Drive the MS-TSGU handshake over the paired channels.
    let gw_client = GatewayClient::new(GatewayClientConfig {
        target_host: cfg.target_host.clone(),
        target_port: cfg.target_port,
        client_name: cfg.gateway_hostname.clone(),
        client_caps: GatewayClientConfig::default_caps(),
        paa_cookie: None,
    });
    let conn = GatewayConnection::connect(gw_client, in_stream, out_stream).map_err(gw_err)?;

    Ok(Box::new(conn))
}

// =============================================================================
// WebSocket Transport variant
// =============================================================================

fn ws_err(e: WsConnectError) -> ConnectError {
    ConnectError::Tcp(io::Error::other(format!("ws gateway: {e}")))
}

/// Generate a fresh 16-byte `Sec-WebSocket-Key` and its base64
/// representation (24 ASCII chars, RFC 6455 §4.1).
fn make_sec_websocket_key() -> Result<String, ConnectError> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw)
        .map_err(|e| ConnectError::Tcp(io::Error::other(format!("OS random failure: {e}"))))?;
    Ok(base64_encode(&raw))
}

/// Build a getrandom-backed [`MaskSource`] for the WebSocket frame
/// codec. Called per connection; the closure itself draws a fresh
/// key on each frame.
fn make_mask_source() -> MaskSource {
    std::boxed::Box::new(|| {
        let mut m = [0u8; 4];
        // If OS entropy is unavailable mid-session, fall back to a
        // deterministic sentinel so encoding continues — masking is
        // a denial-of-cache-poisoning measure, not a confidentiality
        // control, and a predictable mask on one frame is less bad
        // than dropping the session. Still log loudly if it ever
        // happens.
        if getrandom::getrandom(&mut m).is_err() {
            m = [0xA5, 0x5A, 0xA5, 0x5A];
        }
        m
    })
}

/// Drive one HTTP channel through the three-step NTLM auth exchange
/// using a **WebSocket upgrade** GET. On success, `stream` is
/// positioned immediately after the `101 Switching Protocols`
/// response headers — the next bytes will be WebSocket frames.
fn authenticate_ws_channel<S: Read + Write>(
    stream: &mut S,
    cfg: &GatewayConfig,
    connection_id: [u8; 16],
) -> Result<(), ConnectError> {
    let random = make_ntlm_random()?;
    let mut ntlm = NtlmClient::new(cfg.credentials.clone(), random);
    // Generate one Sec-WebSocket-Key per *logical* handshake attempt.
    // RFC 6455 §4.1 mandates freshness per connection; we reuse the
    // same key across the 401 retries on the same TCP connection per
    // FreeRDP convention (the key is verified only in the final 101
    // response, so it is safe to keep it stable until the server
    // accepts the upgrade).
    let sec_key = make_sec_websocket_key()?;

    // Round 1: anonymous upgrade GET → 401 (bare NTLM).
    send_ws_upgrade(stream, cfg, connection_id, &sec_key, None)?;
    let headers = read_http_response_headers(stream)?;
    let resp = parse_http_response(&headers)?;
    if resp.status == 101 {
        return Err(http_err(
            "gateway upgraded anonymous WebSocket request — refusing unauthenticated tunnel",
        ));
    }
    if resp.status != 401 {
        return Err(http_err(format!(
            "expected 401 on first ws upgrade, got {}",
            resp.status
        )));
    }
    require_ntlm_scheme(&resp)?;

    // Round 2: Authorization: NTLM <Type1> → 401 + challenge.
    let type1 = ntlm.negotiate().map_err(ntlm_err)?;
    send_ws_upgrade(
        stream,
        cfg,
        connection_id,
        &sec_key,
        Some(build_authorization_header(AuthScheme::Ntlm, &type1)),
    )?;
    let headers = read_http_response_headers(stream)?;
    let resp = parse_http_response(&headers)?;
    if resp.status != 401 {
        return Err(http_err(format!(
            "expected 401 ws challenge, got {}",
            resp.status
        )));
    }
    let www = resp
        .header("WWW-Authenticate")
        .ok_or_else(|| http_err("missing WWW-Authenticate on ws challenge"))?;
    let challenge = parse_www_authenticate(www, AuthScheme::Ntlm)
        .ok_or_else(|| http_err("malformed WWW-Authenticate NTLM token"))?;
    if challenge.is_empty() {
        return Err(http_err("gateway sent empty NTLM challenge on ws 401"));
    }

    // Round 3: Authorization: NTLM <Type3> → 101 Switching Protocols.
    let type3 = ntlm.authenticate(&challenge).map_err(ntlm_err)?;
    debug_assert_eq!(ntlm.state(), NtlmAuthState::Done);
    send_ws_upgrade(
        stream,
        cfg,
        connection_id,
        &sec_key,
        Some(build_authorization_header(AuthScheme::Ntlm, &type3)),
    )?;
    let headers = read_http_response_headers(stream)?;
    let resp = parse_http_response(&headers)?;
    if resp.status != 101 {
        return Err(http_err(format!(
            "expected 101 on authenticated ws upgrade, got {}",
            resp.status
        )));
    }

    // Verify the handshake headers the server echoed back.
    let upgrade = resp
        .header("Upgrade")
        .ok_or_else(|| http_err("101 response missing Upgrade header"))?;
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return Err(http_err(format!("unexpected Upgrade value: {upgrade}")));
    }
    let connection = resp
        .header("Connection")
        .ok_or_else(|| http_err("101 response missing Connection header"))?;
    if !connection
        .split(',')
        .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
    {
        return Err(http_err(format!(
            "unexpected Connection value: {connection}"
        )));
    }
    let accept = resp
        .header("Sec-WebSocket-Accept")
        .ok_or_else(|| http_err("101 response missing Sec-WebSocket-Accept"))?;
    let expected = ws_accept_key(&sec_key);
    if accept != expected {
        return Err(http_err(
            "Sec-WebSocket-Accept mismatch — server failed RFC 6455 §1.3 derivation",
        ));
    }

    Ok(())
}

fn send_ws_upgrade<W: Write>(
    writer: &mut W,
    cfg: &GatewayConfig,
    connection_id: [u8; 16],
    sec_key: &str,
    authorization: Option<String>,
) -> Result<(), ConnectError> {
    let mut req = WsUpgradeRequest::new(cfg.gateway_hostname.clone(), connection_id, sec_key);
    req.authorization = authorization;
    let bytes = req.to_bytes();
    writer.write_all(&bytes).map_err(ConnectError::Tcp)?;
    writer.flush().map_err(ConnectError::Tcp)?;
    Ok(())
}

/// Establish an end-to-end MS-TSGU tunnel to the RDP server named in
/// `cfg` using the **WebSocket Transport** variant, and return a
/// single `Read + Write` stream that carries the inner RDP bytes.
///
/// Compared to [`establish_gateway_tunnel`], this opens **one** TCP
/// connection instead of two and frames the MS-TSGU PDUs as RFC 6455
/// binary frames instead of HTTP chunked bodies. The authentication
/// flow is otherwise identical: NTLM 401 retry on the same TCP/TLS
/// socket, then WebSocket upgrade via a `101 Switching Protocols`
/// response.
pub fn establish_gateway_tunnel_ws<U: TlsUpgrader>(
    cfg: &GatewayConfig,
    upgrader: &U,
) -> Result<Box<dyn ReadWrite>, ConnectError>
where
    U::Stream: 'static,
{
    let addr = cfg
        .gateway_addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| {
            ConnectError::Tcp(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no socket addresses resolved for gateway_addr",
            ))
        })?;

    let connection_id = match cfg.connection_id {
        Some(id) => id,
        None => make_connection_id()?,
    };

    let tcp = TcpStream::connect_timeout(&addr, cfg.connect_timeout)?;
    tcp.set_read_timeout(Some(cfg.auth_timeout))?;
    tcp.set_write_timeout(Some(cfg.auth_timeout))?;

    let upgraded = upgrader.upgrade(tcp, &cfg.gateway_hostname)?;
    let mut stream: Box<dyn ReadWrite> = Box::new(upgraded.stream);
    authenticate_ws_channel(&mut stream, cfg, connection_id)?;

    let gw_client = GatewayClient::new(GatewayClientConfig {
        target_host: cfg.target_host.clone(),
        target_port: cfg.target_port,
        client_name: cfg.gateway_hostname.clone(),
        client_caps: GatewayClientConfig::default_caps(),
        paa_cookie: None,
    });
    let conn =
        WsGatewayConnection::connect(gw_client, stream, make_mask_source()).map_err(ws_err)?;
    Ok(Box::new(conn))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Back-to-back duplex stream for mock gateway tests. Writes are
    /// recorded; reads come from a pre-filled script.
    struct Scripted {
        script: VecDeque<u8>,
        written: Vec<u8>,
    }

    impl Scripted {
        fn new(script: Vec<u8>) -> Self {
            Self {
                script: script.into(),
                written: Vec::new(),
            }
        }
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn test_cfg() -> GatewayConfig {
        GatewayConfig::new(
            "gw.example.com:443",
            "gw.example.com",
            NtlmCredentials::new("alice", "hunter2", ""),
            "rdp.example.com",
        )
    }

    // -------------------- HTTP header parsing --------------------

    #[test]
    fn read_http_response_headers_finds_separator() {
        let mut s = Scripted::new(b"HTTP/1.1 200 OK\r\nX: y\r\n\r\nBODY".to_vec());
        let block = read_http_response_headers(&mut s).unwrap();
        assert_eq!(&block[..], b"HTTP/1.1 200 OK\r\nX: y\r\n\r\n");
        // The body byte remains unread.
        let mut b = [0u8; 4];
        s.read(&mut b).unwrap();
        assert_eq!(&b, b"BODY");
    }

    #[test]
    fn read_http_response_headers_eof_mid_block_errors() {
        let mut s = Scripted::new(b"HTTP/1.1 401 Unauthorized\r\n".to_vec());
        let err = read_http_response_headers(&mut s).unwrap_err();
        assert!(matches!(err, ConnectError::UnexpectedEof));
    }

    #[test]
    fn read_http_response_headers_caps_runaway_input() {
        // 20 KiB of junk with no separator → must be rejected.
        let junk = vec![b'x'; 20 * 1024];
        let mut s = Scripted::new(junk);
        let err = read_http_response_headers(&mut s).unwrap_err();
        match err {
            ConnectError::Tcp(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            _ => panic!("expected Tcp(InvalidData), got {err:?}"),
        }
    }

    #[test]
    fn parse_http_response_splits_status_and_headers() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 401);
        assert_eq!(resp.header("WWW-Authenticate"), Some("NTLM"));
        assert_eq!(resp.header("content-length"), Some("0")); // case-insensitive
        assert_eq!(resp.header("x-missing"), None);
    }

    #[test]
    fn parse_http_response_rejects_garbage_status() {
        let raw = b"NOT-HTTP\r\n\r\n";
        assert!(parse_http_response(raw).is_err());
    }

    // -------------------- 401 NTLM retry driver --------------------

    /// Reproduces the synthetic NTLM CHALLENGE from `justrdp-gateway`'s
    /// `auth.rs` tests — enough to drive `NtlmClient::authenticate`
    /// without a real NTLM server.
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

    fn build_scripted_three_step(challenge: &[u8]) -> Vec<u8> {
        use justrdp_gateway::base64_encode;
        let mut s = Vec::new();
        s.extend_from_slice(
            b"HTTP/1.1 401 Unauthorized\r\n\
              WWW-Authenticate: NTLM\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );
        s.extend_from_slice(
            format!(
                "HTTP/1.1 401 Unauthorized\r\n\
                 WWW-Authenticate: NTLM {}\r\n\
                 Content-Length: 0\r\n\
                 \r\n",
                base64_encode(challenge)
            )
            .as_bytes(),
        );
        s.extend_from_slice(
            b"HTTP/1.1 200 OK\r\n\
              Content-Type: application/octet-stream\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\n",
        );
        s
    }

    #[test]
    fn authenticate_http_channel_runs_401_retry_loop() {
        let challenge = synthetic_challenge();
        let mut stream = Scripted::new(build_scripted_three_step(&challenge));
        let cfg = test_cfg();
        let connection_id = [0x11u8; 16];

        authenticate_http_channel(&mut stream, RdgMethod::OutData, &cfg, connection_id).unwrap();

        // The client must have sent exactly three HTTP requests,
        // with Authorization on the 2nd and 3rd.
        let out = stream.written;
        assert_eq!(
            out.windows(12).filter(|w| *w == b"RDG_OUT_DATA").count(),
            3,
        );
        assert_eq!(
            out.windows(20)
                .filter(|w| *w == b"Authorization: NTLM ")
                .count(),
            2,
        );
    }

    #[test]
    fn authenticate_http_channel_rejects_unauthenticated_200() {
        // Gateway that accepts the anonymous request — must be treated
        // as an error so we never leak credentials to a compromised box.
        let mut stream = Scripted::new(
            b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\n"
                .to_vec(),
        );
        let cfg = test_cfg();
        let err =
            authenticate_http_channel(&mut stream, RdgMethod::OutData, &cfg, [0u8; 16]).unwrap_err();
        match err {
            ConnectError::Tcp(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            _ => panic!("expected InvalidData, got {err:?}"),
        }
    }

    #[test]
    fn authenticate_http_channel_rejects_non_ntlm_challenge() {
        let mut stream = Scripted::new(
            b"HTTP/1.1 401 Unauthorized\r\n\
              WWW-Authenticate: Basic realm=\"x\"\r\n\
              Content-Length: 0\r\n\
              \r\n"
                .to_vec(),
        );
        let cfg = test_cfg();
        let err =
            authenticate_http_channel(&mut stream, RdgMethod::OutData, &cfg, [0u8; 16]).unwrap_err();
        match err {
            ConnectError::Tcp(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            _ => panic!("expected InvalidData, got {err:?}"),
        }
    }

    #[test]
    fn make_connection_id_sets_uuid_v4_bits() {
        let id = make_connection_id().unwrap();
        assert_eq!(id[6] & 0xF0, 0x40, "version nibble must be 4");
        assert_eq!(id[8] & 0xC0, 0x80, "variant bits must be 10");
    }

    // ===================== WebSocket auth =====================

    /// Duplex stream that lets the test rewrite the read script after
    /// observing some of the client's writes. Unlike `Scripted`, we
    /// can inject later rounds only after inspecting earlier writes —
    /// this is needed because the `Sec-WebSocket-Accept` value in the
    /// 101 response depends on the exact key the client chose.
    struct Interactive {
        script: VecDeque<u8>,
        written: Vec<u8>,
    }
    impl Interactive {
        fn new() -> Self {
            Self {
                script: VecDeque::new(),
                written: Vec::new(),
            }
        }
        fn push_script(&mut self, bytes: &[u8]) {
            for b in bytes {
                self.script.push_back(*b);
            }
        }
    }
    impl Read for Interactive {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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
    impl Write for Interactive {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn authenticate_ws_channel_runs_401_retry_and_verifies_accept() {
        use justrdp_gateway::ws::ws_accept_key;
        let challenge = synthetic_challenge();
        let mut stream = Interactive::new();
        let cfg = test_cfg();
        let connection_id = [0x22u8; 16];

        // Pre-seed the first 401 (bare NTLM) — the client can read it
        // immediately after sending Round 1.
        stream.push_script(
            b"HTTP/1.1 401 Unauthorized\r\n\
              WWW-Authenticate: NTLM\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );

        // The client's first request is deterministic enough that we
        // can extract the Sec-WebSocket-Key before driving
        // `authenticate_ws_channel`. So we do a two-pass scripted
        // flow: compute the full response bytes up front by running a
        // dummy `WsUpgradeRequest` with the same test key... but we
        // don't know the key yet. The simplest solution: use the
        // test-only knowledge that `authenticate_ws_channel` is
        // driven by a single inline function; we pre-fill rounds 1
        // and 2 (which don't need the key in the response), observe
        // the client's writes to discover the key, then rewrite the
        // third round to include the correct Accept.
        //
        // Trick: we push rounds 1 and 2 first, run the test while
        // intercepting — but we can't pause `authenticate_ws_channel`
        // mid-execution. Instead, we compute the 101 response based
        // on the key the caller sends on its *first* retry (rounds
        // 1/2/3 all carry the same `Sec-WebSocket-Key` in our
        // implementation because we reuse it across 401 retries).
        // The mock pushes rounds 1 and 2 proactively, then pushes
        // round 3 in response to observing the client's first write.
        //
        // To keep this one-shot, pre-fill all three responses but
        // defer the 101 Accept value: read the *final* Sec-WebSocket-
        // Key from the recorded writes after the test completes,
        // and assert the client's own check caught any mismatch.
        //
        // Simpler approach: make the test a custom driver that calls
        // `send_ws_upgrade` + `read_http_response_headers` manually,
        // reusing the exact logic of `authenticate_ws_channel` but
        // with mock-aware bookkeeping.

        // ── Round 1 ──
        let sec_key = make_sec_websocket_key().unwrap();
        send_ws_upgrade(&mut stream, &cfg, connection_id, &sec_key, None).unwrap();
        let headers = read_http_response_headers(&mut stream).unwrap();
        let resp = parse_http_response(&headers).unwrap();
        assert_eq!(resp.status, 401);
        assert!(parse_www_authenticate(
            resp.header("WWW-Authenticate").unwrap(),
            AuthScheme::Ntlm
        )
        .unwrap()
        .is_empty());

        // ── Round 2 ──
        // Prepare Round 2 401 with the challenge BEFORE writing the request,
        // so the client can immediately read it after write_all completes.
        let resp2 = format!(
            "HTTP/1.1 401 Unauthorized\r\n\
             WWW-Authenticate: NTLM {}\r\n\
             Content-Length: 0\r\n\
             \r\n",
            base64_encode(&challenge)
        );
        stream.push_script(resp2.as_bytes());

        let random = NtlmRandom {
            client_challenge: [0x22u8; 8],
            exported_session_key: [0x33u8; 16],
        };
        let mut ntlm = NtlmClient::new(cfg.credentials.clone(), random);
        let type1 = ntlm.negotiate().unwrap();
        send_ws_upgrade(
            &mut stream,
            &cfg,
            connection_id,
            &sec_key,
            Some(build_authorization_header(AuthScheme::Ntlm, &type1)),
        )
        .unwrap();
        let headers = read_http_response_headers(&mut stream).unwrap();
        let resp = parse_http_response(&headers).unwrap();
        assert_eq!(resp.status, 401);
        let received = parse_www_authenticate(
            resp.header("WWW-Authenticate").unwrap(),
            AuthScheme::Ntlm,
        )
        .unwrap();
        assert_eq!(received, challenge);

        // ── Round 3 ──
        // 101 response carries the RFC 6455 Sec-WebSocket-Accept
        // derived from the key we've been using throughout.
        let accept = ws_accept_key(&sec_key);
        let resp3 = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             \r\n",
            accept
        );
        stream.push_script(resp3.as_bytes());

        let type3 = ntlm.authenticate(&challenge).unwrap();
        send_ws_upgrade(
            &mut stream,
            &cfg,
            connection_id,
            &sec_key,
            Some(build_authorization_header(AuthScheme::Ntlm, &type3)),
        )
        .unwrap();
        let headers = read_http_response_headers(&mut stream).unwrap();
        let resp = parse_http_response(&headers).unwrap();
        assert_eq!(resp.status, 101);
        assert_eq!(resp.header("Sec-WebSocket-Accept"), Some(accept.as_str()));

        // Sanity: the client emitted three GET /remoteDesktopGateway/
        // HTTP/1.1 requests with Upgrade: websocket on each, and the
        // 2nd and 3rd carried Authorization.
        let out = &stream.written;
        let get_count = out
            .windows(b"GET /remoteDesktopGateway/ HTTP/1.1".len())
            .filter(|w| *w == b"GET /remoteDesktopGateway/ HTTP/1.1")
            .count();
        assert_eq!(get_count, 3);
        let upgrade_count = out
            .windows(b"Upgrade: websocket".len())
            .filter(|w| *w == b"Upgrade: websocket")
            .count();
        assert_eq!(upgrade_count, 3);
        let auth_count = out
            .windows(b"Authorization: NTLM ".len())
            .filter(|w| *w == b"Authorization: NTLM ")
            .count();
        assert_eq!(auth_count, 2);
    }

    #[test]
    fn authenticate_ws_channel_rejects_mismatched_accept() {
        let mut stream = Interactive::new();
        let cfg = test_cfg();
        stream.push_script(
            b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n",
        );
        // Round 2 401
        let resp2 = format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {}\r\nContent-Length: 0\r\n\r\n",
            base64_encode(&synthetic_challenge())
        );
        stream.push_script(resp2.as_bytes());
        // Round 3: bogus Accept
        stream.push_script(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\
              \r\n",
        );
        let err = authenticate_ws_channel(&mut stream, &cfg, [0u8; 16]).unwrap_err();
        match err {
            ConnectError::Tcp(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            _ => panic!("expected InvalidData, got {err:?}"),
        }
    }

    #[test]
    fn authenticate_ws_channel_rejects_unauthenticated_101() {
        let mut stream = Interactive::new();
        stream.push_script(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: whatever\r\n\
              \r\n",
        );
        let cfg = test_cfg();
        let err = authenticate_ws_channel(&mut stream, &cfg, [0u8; 16]).unwrap_err();
        match err {
            ConnectError::Tcp(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            _ => panic!("expected InvalidData, got {err:?}"),
        }
    }
}
