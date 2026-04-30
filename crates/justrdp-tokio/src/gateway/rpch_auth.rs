#![forbid(unsafe_code)]

//! Async port of the MS-TSGU RPC-over-HTTP v2 NTLM 401 retry loop.
//!
//! Mirrors `justrdp_blocking::gateway::authenticate_rpch_channel`
//! step-for-step; only the I/O is async. Used twice per session
//! (once for the `RPC_IN_DATA` channel, once for `RPC_OUT_DATA`),
//! producing two authenticated [`WebTransport`]s positioned at the
//! start of the request body (IN) / response body (OUT).
//!
//! The HTTP-1.1 envelope is identical to the HTTP Transport variant
//! save for the verb (`RPC_IN_DATA` / `RPC_OUT_DATA`) and the
//! Content-Length advertised on the IN channel (1 GiB so the channel
//! can carry up to that many client→server bytes before recycling).
//! All NTLM state lives in `justrdp_gateway::NtlmClient` (no_std);
//! the function is a thin async I/O wrapper around it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_async::{TransportError, WebTransport};
use justrdp_gateway::{
    build_authorization_header, parse_www_authenticate, AuthScheme, NtlmAuthState, NtlmClient,
};
use justrdp_rpch::http::{RpchChannel, RpchHttpRequest};
use tokio::time;

use super::config::RpchGatewayConfig;
use super::error::{http_err, ntlm_err};
use super::http_io::{parse_http_response, read_http_response_headers, HttpResponse};
use super::random::make_ntlm_random;

/// Drive one RPC-over-HTTP channel through the three-step NTLM 401
/// retry exchange.
///
/// On success the transport is positioned immediately after the
/// `200 OK` response headers — the next bytes flowing in the
/// configured direction are CONN/* RTS PDUs (for the OUT channel
/// response body) or are awaited from the caller (for the IN
/// channel request body). Returns leftover bytes that arrived past
/// the final `\r\n\r\n` so [`TsguRpchTransport`] can feed them
/// straight into the RTS frame parser without re-reading.
///
/// [`TsguRpchTransport`]: super::ws_transport
//                                          ^ G9 / G10 follow-up
#[allow(dead_code)]
pub(crate) async fn authenticate_rpch_channel<T>(
    transport: &mut T,
    channel: RpchChannel,
    cfg: &RpchGatewayConfig,
) -> Result<Vec<u8>, TransportError>
where
    T: WebTransport,
{
    let random = make_ntlm_random()?;
    let mut ntlm = NtlmClient::new(cfg.credentials.clone(), random);

    // Round 1: anonymous header-only request → 401 (bare NTLM).
    auth_timeout(cfg, send_rpch_request(transport, channel, cfg, None)).await?;
    let (headers, leftover) =
        auth_timeout(cfg, read_http_response_headers(transport, Vec::new())).await?;
    let resp = parse_http_response(&headers)?;
    if resp.status == 200 {
        return Err(http_err(
            "rpch gateway accepted anonymous request — refusing unauthenticated tunnel",
        ));
    }
    if resp.status != 401 {
        return Err(http_err(format!(
            "expected 401 on first rpch request, got {}",
            resp.status
        )));
    }
    require_ntlm_scheme(&resp)?;

    // Round 2: NTLM NEGOTIATE → 401 + challenge.
    let type1 = ntlm.negotiate().map_err(ntlm_err)?;
    auth_timeout(
        cfg,
        send_rpch_request(
            transport,
            channel,
            cfg,
            Some(build_authorization_header(AuthScheme::Ntlm, &type1)),
        ),
    )
    .await?;
    let (headers, leftover) =
        auth_timeout(cfg, read_http_response_headers(transport, leftover)).await?;
    let resp = parse_http_response(&headers)?;
    if resp.status != 401 {
        return Err(http_err(format!(
            "expected 401 challenge on second rpch request, got {}",
            resp.status
        )));
    }
    let www = resp
        .header("WWW-Authenticate")
        .ok_or_else(|| http_err("missing WWW-Authenticate on rpch challenge"))?;
    let challenge = parse_www_authenticate(www, AuthScheme::Ntlm)
        .ok_or_else(|| http_err("malformed WWW-Authenticate NTLM token"))?;
    if challenge.is_empty() {
        return Err(http_err(
            "rpch gateway sent empty NTLM challenge on second 401",
        ));
    }

    // Round 3: NTLM AUTHENTICATE → 200 OK.
    let type3 = ntlm.authenticate(&challenge).map_err(ntlm_err)?;
    debug_assert_eq!(ntlm.state(), NtlmAuthState::Done);
    auth_timeout(
        cfg,
        send_rpch_request(
            transport,
            channel,
            cfg,
            Some(build_authorization_header(AuthScheme::Ntlm, &type3)),
        ),
    )
    .await?;
    let (headers, leftover) =
        auth_timeout(cfg, read_http_response_headers(transport, leftover)).await?;
    let resp = parse_http_response(&headers)?;
    if resp.status != 200 {
        return Err(http_err(format!(
            "expected 200 on authenticated rpch request, got {}",
            resp.status
        )));
    }
    Ok(leftover)
}

async fn send_rpch_request<T: WebTransport>(
    transport: &mut T,
    channel: RpchChannel,
    cfg: &RpchGatewayConfig,
    authorization: Option<String>,
) -> Result<(), TransportError> {
    let target = format!("{}:{}", cfg.target_host, cfg.target_port);
    let host = cfg.gateway_hostname.clone();
    let mut req = RpchHttpRequest::new(channel, target, host);
    if let Some(auth) = authorization {
        req = req.authorization(auth);
    }
    let bytes = req.to_bytes();
    transport.send(&bytes).await
}

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

async fn auth_timeout<F, R>(cfg: &RpchGatewayConfig, fut: F) -> Result<R, TransportError>
where
    F: core::future::Future<Output = Result<R, TransportError>>,
{
    match time::timeout(cfg.auth_timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err(TransportError::io(format!(
            "gateway: rpch auth round timed out after {:?}",
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

    fn test_cfg() -> RpchGatewayConfig {
        let mut c = RpchGatewayConfig::new(
            "gw.example.com:443",
            "gw.example.com",
            NtlmCredentials::new("alice", "hunter2", ""),
            "rdp.example.com",
        );
        c.auth_timeout = Duration::from_secs(5);
        c
    }

    /// Reproduces the synthetic NTLM challenge from
    /// `justrdp-gateway::auth` tests — copied verbatim from blocking.
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

    fn build_three_step_script(challenge: &[u8]) -> Vec<u8> {
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
              Content-Type: application/rpc\r\n\
              \r\nRTS-FIRST-FRAME",
        );
        s
    }

    #[tokio::test]
    async fn authenticate_rpch_channel_runs_401_retry_for_out_channel() {
        let challenge = synthetic_challenge();
        let mut t = ScriptedTransport::from_script(build_three_step_script(&challenge));
        let cfg = test_cfg();
        let leftover = authenticate_rpch_channel(&mut t, RpchChannel::Out, &cfg)
            .await
            .unwrap();
        // Body bytes past the final \r\n\r\n must be returned for
        // G9 to feed into the RTS / DCE-RPC PDU parser.
        assert_eq!(&leftover[..], b"RTS-FIRST-FRAME");

        // Three RPC_OUT_DATA requests sent. Authorization on rounds
        // 2 and 3.
        let total: Vec<u8> = t.sent.iter().flatten().copied().collect();
        assert_eq!(
            total
                .windows(b"RPC_OUT_DATA".len())
                .filter(|w| *w == b"RPC_OUT_DATA")
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
    async fn authenticate_rpch_channel_in_data_method_emits_in_data_request_line() {
        let challenge = synthetic_challenge();
        let mut t = ScriptedTransport::from_script(build_three_step_script(&challenge));
        authenticate_rpch_channel(&mut t, RpchChannel::In, &test_cfg())
            .await
            .unwrap();
        let total: Vec<u8> = t.sent.iter().flatten().copied().collect();
        assert!(
            total
                .windows(b"RPC_IN_DATA".len())
                .any(|w| w == b"RPC_IN_DATA")
        );
        // The IN-channel default is `Content-Length: 1073741824`
        // (1 GiB) — easy substring to verify per-channel sizing.
        assert!(
            total
                .windows(b"1073741824".len())
                .any(|w| w == b"1073741824"),
            "expected IN-channel default Content-Length 1 GiB"
        );
    }

    #[tokio::test]
    async fn authenticate_rpch_channel_rejects_unauthenticated_200() {
        let mut t = ScriptedTransport::from_script(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        );
        let err = authenticate_rpch_channel(&mut t, RpchChannel::Out, &test_cfg())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[tokio::test]
    async fn authenticate_rpch_channel_rejects_non_ntlm_first_401() {
        let mut t = ScriptedTransport::from_script(
            b"HTTP/1.1 401 Unauthorized\r\n\
              WWW-Authenticate: Basic realm=\"x\"\r\n\
              Content-Length: 0\r\n\
              \r\n"
                .to_vec(),
        );
        let err = authenticate_rpch_channel(&mut t, RpchChannel::Out, &test_cfg())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[tokio::test]
    async fn authenticate_rpch_channel_rejects_empty_challenge() {
        let script: Vec<u8> = b"HTTP/1.1 401 Unauthorized\r\n\
              WWW-Authenticate: NTLM\r\n\
              Content-Length: 0\r\n\
              \r\n\
              HTTP/1.1 401 Unauthorized\r\n\
              WWW-Authenticate: NTLM\r\n\
              Content-Length: 0\r\n\
              \r\n"
            .to_vec();
        let mut t = ScriptedTransport::from_script(script);
        let err = authenticate_rpch_channel(&mut t, RpchChannel::Out, &test_cfg())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }
}
