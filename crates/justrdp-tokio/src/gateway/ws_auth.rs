#![forbid(unsafe_code)]

//! Async port of the MS-TSGU WebSocket Transport HTTP/1.1 Upgrade
//! handshake (with the same NTLM 401 retry loop as the HTTP variant).
//!
//! The flow mirrors `justrdp_blocking::gateway::authenticate_ws_channel`
//! step-for-step:
//!
//! 1. Send `GET ... HTTP/1.1` with `Upgrade: websocket` + custom
//!    MS-TSGU headers, no `Authorization`. Read `401 Unauthorized`
//!    advertising NTLM.
//! 2. Send the same request again with `Authorization: NTLM <Type1>`.
//!    Read `401` carrying the NTLM challenge.
//! 3. Send the request a third time with `Authorization: NTLM <Type3>`.
//!    Read `101 Switching Protocols` and verify the
//!    `Sec-WebSocket-Accept` echo.
//!
//! On success the transport is positioned at the very first byte of
//! the WebSocket frame stream — handed to
//! [`TsguWsTransport::connect`](super::ws_transport::TsguWsTransport::connect).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_async::{TransportError, WebTransport};
use justrdp_gateway::ws::{ws_accept_key, WsUpgradeRequest};
use justrdp_gateway::{
    base64_encode, build_authorization_header, parse_www_authenticate, AuthScheme, NtlmAuthState,
    NtlmClient,
};
use tokio::time;

use super::config::GatewayConfig;
use super::error::{http_err, ntlm_err};
use super::http_io::{parse_http_response, read_http_response_headers, HttpResponse};
use super::random::make_ntlm_random;

/// Drive one WebSocket Upgrade through the three-step NTLM 401 retry
/// + RFC 6455 `Sec-WebSocket-Accept` verification.
///
/// On success the transport is positioned immediately after the
/// `101 Switching Protocols` response headers — the next bytes from
/// `recv()` will be WebSocket frames carrying MS-TSGU PDUs. Any
/// leftover bytes that already arrived past the final `\r\n\r\n` are
/// returned so the caller can feed them into the WebSocket frame
/// decoder without re-reading.
#[allow(dead_code)]
pub(crate) async fn authenticate_ws_channel<T>(
    transport: &mut T,
    cfg: &GatewayConfig,
    connection_id: [u8; 16],
) -> Result<Vec<u8>, TransportError>
where
    T: WebTransport,
{
    let random = make_ntlm_random()?;
    let mut ntlm = NtlmClient::new(cfg.credentials.clone(), random);

    // Per FreeRDP convention: one Sec-WebSocket-Key per logical
    // handshake attempt, reused across the 401 retries on the same
    // TCP connection. The key is verified only in the final 101
    // response.
    let sec_key = make_sec_websocket_key()?;

    // Round 1: anonymous Upgrade GET → 401 (bare NTLM).
    auth_timeout(
        cfg,
        send_ws_upgrade(transport, cfg, connection_id, &sec_key, None),
    )
    .await?;
    let (headers, leftover) =
        auth_timeout(cfg, read_http_response_headers(transport, Vec::new())).await?;
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

    // Round 2: NEGOTIATE → 401 with challenge.
    let type1 = ntlm.negotiate().map_err(ntlm_err)?;
    auth_timeout(
        cfg,
        send_ws_upgrade(
            transport,
            cfg,
            connection_id,
            &sec_key,
            Some(build_authorization_header(AuthScheme::Ntlm, &type1)),
        ),
    )
    .await?;
    let (headers, leftover) =
        auth_timeout(cfg, read_http_response_headers(transport, leftover)).await?;
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

    // Round 3: AUTHENTICATE → 101 Switching Protocols.
    let type3 = ntlm.authenticate(&challenge).map_err(ntlm_err)?;
    debug_assert_eq!(ntlm.state(), NtlmAuthState::Done);
    auth_timeout(
        cfg,
        send_ws_upgrade(
            transport,
            cfg,
            connection_id,
            &sec_key,
            Some(build_authorization_header(AuthScheme::Ntlm, &type3)),
        ),
    )
    .await?;
    let (headers, leftover) =
        auth_timeout(cfg, read_http_response_headers(transport, leftover)).await?;
    let resp = parse_http_response(&headers)?;
    if resp.status != 101 {
        return Err(http_err(format!(
            "expected 101 on authenticated ws upgrade, got {}",
            resp.status
        )));
    }
    verify_101_handshake_headers(&resp, &sec_key)?;

    Ok(leftover)
}

/// Build and send one WebSocket Upgrade request. Mirrors blocking's
/// `send_ws_upgrade`.
async fn send_ws_upgrade<T: WebTransport>(
    transport: &mut T,
    cfg: &GatewayConfig,
    connection_id: [u8; 16],
    sec_key: &str,
    authorization: Option<String>,
) -> Result<(), TransportError> {
    let mut req = WsUpgradeRequest::new(cfg.gateway_hostname.clone(), connection_id, sec_key);
    req.authorization = authorization;
    let bytes = req.to_bytes();
    transport.send(&bytes).await
}

/// Reject the first 401 unless the gateway offers NTLM. (Same rule
/// as the HTTP variant.)
fn require_ntlm_scheme(resp: &HttpResponse<'_>) -> Result<(), TransportError> {
    let www = resp
        .header("WWW-Authenticate")
        .ok_or_else(|| http_err("first 401 missing WWW-Authenticate header"))?;
    if parse_www_authenticate(www, AuthScheme::Ntlm).is_none() {
        return Err(http_err(format!(
            "gateway WWW-Authenticate does not offer NTLM: {www}"
        )));
    }
    Ok(())
}

/// Verify the three RFC 6455 §1.3 / §4.1 headers in the `101`
/// response: `Upgrade: websocket`, `Connection` containing
/// `Upgrade`, and `Sec-WebSocket-Accept` matching the SHA-1
/// derivation of our key. A mismatch on any of these indicates a
/// broken or hostile proxy.
fn verify_101_handshake_headers(
    resp: &HttpResponse<'_>,
    sec_key: &str,
) -> Result<(), TransportError> {
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
    let expected = ws_accept_key(sec_key);
    if accept != expected {
        return Err(http_err(
            "Sec-WebSocket-Accept mismatch — server failed RFC 6455 §1.3 derivation",
        ));
    }
    Ok(())
}

/// Generate a fresh 16-byte `Sec-WebSocket-Key` and base64 encode it
/// (RFC 6455 §4.1, 24 ASCII chars).
#[allow(dead_code)]
pub(crate) fn make_sec_websocket_key() -> Result<String, TransportError> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw)
        .map_err(|e| TransportError::io(format!("OS random failure: {e}")))?;
    Ok(base64_encode(&raw))
}

async fn auth_timeout<F, R>(cfg: &GatewayConfig, fut: F) -> Result<R, TransportError>
where
    F: core::future::Future<Output = Result<R, TransportError>>,
{
    match time::timeout(cfg.auth_timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err(TransportError::io(format!(
            "gateway: ws auth round timed out after {:?}",
            cfg.auth_timeout
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use core::time::Duration;
    use justrdp_async::TransportErrorKind;
    use justrdp_gateway::{base64_encode, NtlmCredentials};

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

    fn test_cfg() -> GatewayConfig {
        let mut c = GatewayConfig::new(
            "gw.example.com:443",
            "gw.example.com",
            NtlmCredentials::new("alice", "hunter2", ""),
            "rdp.example.com",
        );
        c.auth_timeout = Duration::from_secs(5);
        c
    }

    /// Reproduces the synthetic NTLM challenge from
    /// `justrdp-gateway::auth` tests — copied verbatim from
    /// blocking's `synthetic_challenge`.
    fn synthetic_challenge() -> Vec<u8> {
        use justrdp_pdu::ntlm::messages::{to_utf16le, NegotiateFlags};
        let nb = to_utf16le("TEST");
        let mut target_info = Vec::new();
        target_info.extend_from_slice(&2u16.to_le_bytes());
        target_info.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        target_info.extend_from_slice(&nb);
        target_info.extend_from_slice(&[0, 0, 0, 0]);
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

    /// Build a scripted server response that walks through the three
    /// rounds: 401 → 401+challenge → 101. Includes the matching
    /// `Sec-WebSocket-Accept` for the supplied client key.
    fn build_three_step_script(challenge: &[u8], sec_key: &str) -> Vec<u8> {
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
        let accept = ws_accept_key(sec_key);
        s.extend_from_slice(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 \r\nWS-FIRST-FRAME"
            )
            .as_bytes(),
        );
        s
    }

    /// Capture the key the client sent so the synthetic 101 echoes
    /// the matching Sec-WebSocket-Accept. Test-only — production code
    /// generates the key fresh inside the auth function and the server
    /// echoes it independently.
    fn extract_sec_key(written: &[u8]) -> String {
        let s = core::str::from_utf8(written).unwrap();
        let key_line = s
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
            .expect("no Sec-WebSocket-Key in upgrade request");
        key_line
            .split_once(':')
            .unwrap()
            .1
            .trim()
            .to_string()
    }

    #[tokio::test]
    async fn authenticate_ws_channel_runs_401_retry_loop() {
        // Two-pass: first run captures the key the client picks, then
        // we build a matching script and replay. The key is generated
        // fresh inside the auth function via getrandom.
        let mut t1 = ScriptedTransport::default();
        t1.recv_queue.push_back(Ok(b"HTTP/1.1 500 Server Error\r\n\r\n".to_vec()));
        let _ = authenticate_ws_channel(&mut t1, &test_cfg(), [0x11; 16]).await;
        let sec_key = extract_sec_key(&t1.sent[0]);

        // Now run the real test with a script that knows the key.
        // Note: the auth function generates a NEW key each call, so
        // we can't rely on the captured key. Instead, capture the key
        // mid-flight by hooking into the script via a more elaborate
        // mock. Simpler approach: bypass the verify-step assertion by
        // building a script that derives the accept value AFTER we've
        // observed what key the client used. That requires a script
        // that reads the first request, computes accept, and sends
        // round 2/3 dynamically.
        //
        // We go the elaborate route below.
        drop(sec_key); // captured-key path proved out the request
                       // shape above (key field present); the dynamic
                       // server below validates the rest.
        run_dynamic_three_step().await;
    }

    /// Dynamic server: after the auth function sends round 1, parse
    /// out the `Sec-WebSocket-Key`, derive the matching accept, and
    /// build the round-3 (101) response with the correct echo.
    async fn run_dynamic_three_step() {
        // We model this with a hand-rolled WebTransport that captures
        // the key from the first send before responding. This proves
        // the verify_101_handshake_headers path against a correct
        // accept value.
        struct DynamicServer {
            sent: Vec<Vec<u8>>,
            sec_key: Option<String>,
            challenge: Vec<u8>,
            recv_buffer: Vec<u8>,
        }

        impl WebTransport for DynamicServer {
            async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
                self.sent.push(bytes.to_vec());
                if self.sec_key.is_none() {
                    self.sec_key = Some(extract_sec_key(bytes));
                }
                // After each send, queue the matching server
                // response into recv_buffer so the next recv()
                // returns it.
                let round = self.sent.len();
                let response = match round {
                    1 => b"HTTP/1.1 401 Unauthorized\r\n\
                           WWW-Authenticate: NTLM\r\n\
                           Content-Length: 0\r\n\
                           \r\n"
                        .to_vec(),
                    2 => format!(
                        "HTTP/1.1 401 Unauthorized\r\n\
                         WWW-Authenticate: NTLM {}\r\n\
                         Content-Length: 0\r\n\
                         \r\n",
                        base64_encode(&self.challenge)
                    )
                    .into_bytes(),
                    3 => {
                        let accept = ws_accept_key(self.sec_key.as_ref().unwrap());
                        format!(
                            "HTTP/1.1 101 Switching Protocols\r\n\
                             Upgrade: websocket\r\n\
                             Connection: Upgrade\r\n\
                             Sec-WebSocket-Accept: {accept}\r\n\
                             \r\nWS-FIRST-FRAME"
                        )
                        .into_bytes()
                    }
                    _ => Vec::new(),
                };
                self.recv_buffer.extend_from_slice(&response);
                Ok(())
            }

            async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
                if self.recv_buffer.is_empty() {
                    return Err(TransportError::closed("dynamic: drained"));
                }
                let chunk = core::mem::take(&mut self.recv_buffer);
                Ok(chunk)
            }

            async fn close(&mut self) -> Result<(), TransportError> {
                Ok(())
            }
        }

        let challenge = synthetic_challenge();
        let mut server = DynamicServer {
            sent: Vec::new(),
            sec_key: None,
            challenge,
            recv_buffer: Vec::new(),
        };
        let leftover =
            authenticate_ws_channel(&mut server, &test_cfg(), [0x22; 16])
                .await
                .expect("ws auth must succeed against matching dynamic server");
        // The leftover bytes are the start of the WebSocket frame
        // stream — fed to TsguWsTransport in the next layer.
        assert_eq!(&leftover[..], b"WS-FIRST-FRAME");
        // Three Upgrade requests sent: anonymous, NEGOTIATE,
        // AUTHENTICATE.
        assert_eq!(server.sent.len(), 3);
        let total: Vec<u8> = server.sent.iter().flatten().copied().collect();
        assert_eq!(
            total
                .windows(b"Upgrade: websocket".len())
                .filter(|w| *w == b"Upgrade: websocket")
                .count(),
            3
        );
        assert_eq!(
            total
                .windows(b"Authorization: NTLM ".len())
                .filter(|w| *w == b"Authorization: NTLM ")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn authenticate_ws_channel_rejects_unauthenticated_101() {
        let mut t = ScriptedTransport::from_script(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: x\r\n\
              \r\n"
                .to_vec(),
        );
        let err = authenticate_ws_channel(&mut t, &test_cfg(), [0u8; 16])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[tokio::test]
    async fn authenticate_ws_channel_rejects_non_ntlm_first_401() {
        let mut t = ScriptedTransport::from_script(
            b"HTTP/1.1 401 Unauthorized\r\n\
              WWW-Authenticate: Basic realm=\"x\"\r\n\
              Content-Length: 0\r\n\
              \r\n"
                .to_vec(),
        );
        let err = authenticate_ws_channel(&mut t, &test_cfg(), [0u8; 16])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[tokio::test]
    async fn make_sec_websocket_key_is_24_ascii_chars() {
        let key = make_sec_websocket_key().unwrap();
        // base64 of 16 bytes — always 24 chars including `=` padding.
        assert_eq!(key.len(), 24);
        assert!(key.chars().all(|c| c.is_ascii()));
    }

    #[tokio::test]
    async fn make_sec_websocket_key_is_distinct_across_calls() {
        let a = make_sec_websocket_key().unwrap();
        let b = make_sec_websocket_key().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn verify_101_handshake_headers_rejects_wrong_upgrade_value() {
        let raw = b"HTTP/1.1 101 Switching Protocols\r\n\
                    Upgrade: not-websocket\r\n\
                    Connection: Upgrade\r\n\
                    Sec-WebSocket-Accept: x\r\n\
                    \r\n";
        let resp = parse_http_response(raw).unwrap();
        let err = verify_101_handshake_headers(&resp, "any").unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[test]
    fn verify_101_handshake_headers_rejects_mismatched_accept() {
        let raw = b"HTTP/1.1 101 Switching Protocols\r\n\
                    Upgrade: websocket\r\n\
                    Connection: Upgrade\r\n\
                    Sec-WebSocket-Accept: not-the-right-hash\r\n\
                    \r\n";
        let resp = parse_http_response(raw).unwrap();
        let err = verify_101_handshake_headers(&resp, "key").unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    // Quiet `unused` warning while keeping the helper available for
    // future tests that script Connection-only edge cases.
    #[allow(dead_code)]
    fn _build_three_step_script_alias(c: &[u8], k: &str) -> Vec<u8> {
        build_three_step_script(c, k)
    }
}
