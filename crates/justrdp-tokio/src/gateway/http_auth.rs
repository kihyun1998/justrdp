#![forbid(unsafe_code)]

//! Async port of the MS-TSGU HTTP/1.1 NTLM 401 retry loop.
//!
//! Mirrors `justrdp_blocking::gateway::authenticate_http_channel`
//! step-for-step; only the I/O is async. Each round is bounded by
//! `cfg.auth_timeout` to match the blocking side's
//! `set_{read,write}_timeout` behaviour. The NTLM state machine
//! itself comes from `justrdp_gateway::NtlmClient`, which is
//! `no_std + alloc`, so the same code drives both transports.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_async::{TransportError, WebTransport};
use justrdp_gateway::{
    build_authorization_header, parse_www_authenticate, AuthScheme, NtlmAuthState, NtlmClient,
    RdgHttpRequest, RdgMethod,
};
use tokio::time;

use super::config::GatewayConfig;
use super::error::{http_err, ntlm_err};
use super::http_io::{parse_http_response, read_http_response_headers, HttpResponse};
use super::random::make_ntlm_random;

/// Drive one HTTP channel through the three-step NTLM 401 retry
/// exchange.
///
/// On success the transport is positioned immediately after the
/// `200 OK` response headers — the next bytes the connector layer
/// reads off it will be the chunked MS-TSGU body, exactly what
/// [`GatewayConnection::connect`](justrdp_gateway::GatewayConnection)
/// expects. Any leftover bytes that arrived past the final `\r\n\r\n`
/// (the body preamble starting before recv granularity) are returned
/// so G3 can feed them into the chunked-body parser without re-reading.
#[allow(dead_code)]
pub(crate) async fn authenticate_http_channel<T>(
    transport: &mut T,
    method: RdgMethod,
    cfg: &GatewayConfig,
    connection_id: [u8; 16],
) -> Result<Vec<u8>, TransportError>
where
    T: WebTransport,
{
    let random = make_ntlm_random()?;
    let mut ntlm = NtlmClient::new(cfg.credentials.clone(), random);

    // Round 1: anonymous request → 401 (bare NTLM).
    auth_timeout(
        cfg,
        send_rdg_request(transport, method, cfg, connection_id, None),
    )
    .await?;
    let (headers, leftover) = auth_timeout(
        cfg,
        read_http_response_headers(transport, Vec::new()),
    )
    .await?;
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
    auth_timeout(
        cfg,
        send_rdg_request(
            transport,
            method,
            cfg,
            connection_id,
            Some(build_authorization_header(AuthScheme::Ntlm, &type1)),
        ),
    )
    .await?;
    let (headers, leftover) = auth_timeout(
        cfg,
        read_http_response_headers(transport, leftover),
    )
    .await?;
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
    auth_timeout(
        cfg,
        send_rdg_request(
            transport,
            method,
            cfg,
            connection_id,
            Some(build_authorization_header(AuthScheme::Ntlm, &type3)),
        ),
    )
    .await?;
    let (headers, leftover) = auth_timeout(
        cfg,
        read_http_response_headers(transport, leftover),
    )
    .await?;
    let resp = parse_http_response(&headers)?;
    if resp.status != 200 {
        return Err(http_err(format!(
            "expected 200 on authenticated request, got {}",
            resp.status
        )));
    }
    Ok(leftover)
}

/// Build and send one `RDG_*_DATA` request. Mirrors the blocking
/// `send_rdg_request` byte-for-byte; the bytes go out as a single
/// `WebTransport::send` call so any TLS framing on the line stays
/// atomic at the request boundary.
async fn send_rdg_request<T: WebTransport>(
    transport: &mut T,
    method: RdgMethod,
    cfg: &GatewayConfig,
    connection_id: [u8; 16],
    authorization: Option<String>,
) -> Result<(), TransportError> {
    let mut req = RdgHttpRequest::new(method, cfg.gateway_hostname.clone(), connection_id);
    req.authorization = authorization;
    let bytes = req.to_bytes();
    transport.send(&bytes).await
}

/// Reject the first 401 unless the gateway offers NTLM. We only ever
/// drive NTLM here — Negotiate / Kerberos paths are out of scope for
/// MS-TSGU phase-2 auth.
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

/// Bound an auth-round future by `cfg.auth_timeout`. Used for both
/// send and recv halves; the only difference is the message in the
/// timeout error, which is generic enough to be shared.
async fn auth_timeout<F, R>(cfg: &GatewayConfig, fut: F) -> Result<R, TransportError>
where
    F: core::future::Future<Output = Result<R, TransportError>>,
{
    match time::timeout(cfg.auth_timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err(TransportError::io(format!(
            "gateway: http auth round timed out after {:?}",
            cfg.auth_timeout
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::vec;
    use core::time::Duration;
    use justrdp_async::TransportErrorKind;
    use justrdp_gateway::{base64_encode, NtlmCredentials};

    /// Test mock — same shape as `http_io::tests::ScriptedTransport`
    /// but local so each test module can own its script setup.
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
        // Loosen for CI variability — tests don't depend on the
        // timeout firing.
        c.auth_timeout = Duration::from_secs(5);
        c
    }

    /// Reproduces the synthetic NTLM CHALLENGE from
    /// `justrdp-gateway::auth` tests — enough byte-shape to drive
    /// `NtlmClient::authenticate` without a real NTLM server.
    /// Copied verbatim from blocking's `synthetic_challenge`.
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
              Content-Type: application/octet-stream\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\nBODY-START",
        );
        s
    }

    #[tokio::test]
    async fn authenticate_http_channel_runs_401_retry_loop() {
        let challenge = synthetic_challenge();
        let mut t = ScriptedTransport::from_script(build_three_step_script(&challenge));
        let cfg = test_cfg();
        let leftover =
            authenticate_http_channel(&mut t, RdgMethod::OutData, &cfg, [0x11; 16])
                .await
                .unwrap();
        // Body bytes that arrived past the final \r\n\r\n must be
        // returned for G3 to feed into the chunked parser.
        assert_eq!(&leftover[..], b"BODY-START");

        // Three HTTP requests must have been sent (R1 anonymous, R2
        // with NEGOTIATE, R3 with AUTHENTICATE). The mock concatenates
        // everything into one Vec but each `send()` is recorded as a
        // separate entry.
        let total: Vec<u8> = t.sent.iter().flatten().copied().collect();
        assert_eq!(
            total
                .windows(b"RDG_OUT_DATA".len())
                .filter(|w| *w == b"RDG_OUT_DATA")
                .count(),
            3,
        );
        // Two of those three must carry an `Authorization: NTLM`
        // header — R2 and R3.
        assert_eq!(
            total
                .windows(b"Authorization: NTLM ".len())
                .filter(|w| *w == b"Authorization: NTLM ")
                .count(),
            2,
        );
    }

    #[tokio::test]
    async fn authenticate_http_channel_rejects_unauthenticated_200() {
        // A gateway that accepts the anonymous request must be treated
        // as an error so credentials never leak to a compromised box.
        let mut t = ScriptedTransport::from_script(
            b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\n"
                .to_vec(),
        );
        let cfg = test_cfg();
        let err = authenticate_http_channel(&mut t, RdgMethod::OutData, &cfg, [0u8; 16])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[tokio::test]
    async fn authenticate_http_channel_rejects_non_ntlm_challenge() {
        let mut t = ScriptedTransport::from_script(
            b"HTTP/1.1 401 Unauthorized\r\n\
              WWW-Authenticate: Basic realm=\"x\"\r\n\
              Content-Length: 0\r\n\
              \r\n"
                .to_vec(),
        );
        let cfg = test_cfg();
        let err = authenticate_http_channel(&mut t, RdgMethod::OutData, &cfg, [0u8; 16])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[tokio::test]
    async fn authenticate_http_channel_rejects_empty_challenge() {
        // Round 1 = bare 401 (NTLM), Round 2 = 401 with NTLM but no
        // base64 token. The client must refuse to drive
        // `NtlmClient::authenticate` against an empty challenge.
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
        let cfg = test_cfg();
        let err = authenticate_http_channel(&mut t, RdgMethod::OutData, &cfg, [0u8; 16])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }

    #[tokio::test]
    async fn authenticate_http_channel_in_data_method_emits_in_data_request_line() {
        let challenge = synthetic_challenge();
        let mut t = ScriptedTransport::from_script(build_three_step_script(&challenge));
        let cfg = test_cfg();
        authenticate_http_channel(&mut t, RdgMethod::InData, &cfg, [0u8; 16])
            .await
            .unwrap();
        let total: Vec<u8> = t.sent.iter().flatten().copied().collect();
        assert!(total.windows(b"RDG_IN_DATA".len()).any(|w| w == b"RDG_IN_DATA"));
        assert!(!total.windows(b"RDG_OUT_DATA".len()).any(|w| w == b"RDG_OUT_DATA"));
    }

    /// MAX_HTTP_HEADER_BYTES guard — a malicious / broken server
    /// that never emits `\r\n\r\n` must surface as `Protocol`, not
    /// hang indefinitely. The `auth_timeout` path is independently
    /// covered by `outer_tls::tests::tls_handshake_timeout_…` so the
    /// `Io` branch isn't re-tested here.
    #[tokio::test]
    async fn authenticate_http_channel_caps_runaway_server() {
        let mut t = ScriptedTransport::default();
        // 20 KiB of junk in 2 KiB frames, no separator. Capped at
        // 16 KiB by the header reader.
        for _ in 0..10 {
            t.recv_queue.push_back(Ok(vec![b'x'; 2048]));
        }
        let cfg = test_cfg();
        let err = authenticate_http_channel(&mut t, RdgMethod::OutData, &cfg, [0u8; 16])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::Protocol);
    }
}
