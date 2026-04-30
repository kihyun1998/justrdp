#![forbid(unsafe_code)]

//! Async byte-level HTTP/1.1 helpers over a [`WebTransport`].
//!
//! The MS-TSGU HTTP / WebSocket transport variants drive a small slice
//! of HTTP/1.1 manually: a single request, a single response, no
//! pipelining, no keep-alive (the gateway connection is long-lived
//! but each NTLM round consumes one request/response pair before the
//! next one is sent). The blocking side does this with raw
//! `std::io::Read` / `Write`; this module is the async equivalent.
//!
//! The byte stream view sits *above* `WebTransport`: each `recv()`
//! returns one transport-level frame (TLS record, WebSocket binary
//! frame, etc.). For byte-oriented HTTP parsing we accumulate frames
//! into a `Vec<u8>` and split out a header block once we see
//! `\r\n\r\n`. Any tail bytes that arrived past the separator are
//! returned to the caller — those are the start of the response body
//! (chunked-transfer MS-TSGU PDUs in practice).

use alloc::format;
use alloc::vec::Vec;

use justrdp_async::{TransportError, WebTransport};

use super::error::http_err;

/// Maximum bytes we are willing to buffer while searching for the end
/// of an HTTP/1.1 response header block. 16 KiB comfortably covers
/// even verbose IIS defaults plus an NTLMSSP challenge token. Anything
/// bigger is almost certainly an adversarial or corrupted stream.
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;

/// Parsed HTTP/1.1 status line + header map view.
///
/// Same shape as the blocking side's `HttpResponse`. Borrows from the
/// raw byte block so callers must keep that alive for the duration of
/// header lookups.
#[derive(Debug)]
pub(crate) struct HttpResponse<'a> {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(&'a str, &'a str)>,
}

impl<'a> HttpResponse<'a> {
    /// Case-insensitive header lookup. Returns the trimmed value of
    /// the first matching header (HTTP/1.1 allows folding identical
    /// header names; we don't observe any in practice for MS-TSGU).
    pub(crate) fn header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

/// Read from `transport` (and any `pending` leftover bytes carried in
/// from a previous round) until the first `\r\n\r\n` header/body
/// separator. Returns `(headers, leftover)` — the body bytes that
/// arrived past the separator, if any.
///
/// Errors out on EOF before the separator, or if the buffer grows
/// beyond [`MAX_HTTP_HEADER_BYTES`].
#[allow(dead_code)]
pub(crate) async fn read_http_response_headers<T: WebTransport>(
    transport: &mut T,
    pending: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), TransportError> {
    let mut buf = pending;
    if let Some(idx) = find_double_crlf(&buf) {
        let split = idx + 4;
        let leftover = buf.split_off(split);
        return Ok((buf, leftover));
    }
    loop {
        if buf.len() > MAX_HTTP_HEADER_BYTES {
            return Err(http_err("HTTP response header block too large"));
        }
        let chunk = transport.recv().await?;
        if chunk.is_empty() {
            // recv() should not normally return an empty Vec — peer
            // close surfaces as `ConnectionClosed`. If we get here it
            // is a transport bug; treat as EOF.
            return Err(TransportError::closed("eof during http header read"));
        }
        let prev_len = buf.len();
        buf.extend_from_slice(&chunk);
        // Resume scanning from up to 3 bytes before the new chunk so
        // a separator straddling the boundary is still detected.
        let scan_from = prev_len.saturating_sub(3);
        if let Some(rel) = find_double_crlf_from(&buf, scan_from) {
            let split = rel + 4;
            let leftover = buf.split_off(split);
            return Ok((buf, leftover));
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    find_double_crlf_from(buf, 0)
}

fn find_double_crlf_from(buf: &[u8], start: usize) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let begin = start.min(buf.len().saturating_sub(4));
    for i in begin..=buf.len().saturating_sub(4) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

/// Parse the raw header bytes returned by [`read_http_response_headers`]
/// into a status code + header map.
#[allow(dead_code)]
pub(crate) fn parse_http_response(block: &[u8]) -> Result<HttpResponse<'_>, TransportError> {
    let s = core::str::from_utf8(block)
        .map_err(|_| http_err("HTTP response contained non-UTF-8 bytes"))?;
    let mut lines = s.split("\r\n");
    let status_line = lines.next().ok_or_else(|| http_err("missing status line"))?;
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next().ok_or_else(|| http_err("malformed status line"))?;
    let code = parts.next().ok_or_else(|| http_err("missing status code"))?;
    let status: u16 = code
        .parse()
        .map_err(|_| http_err(format!("non-numeric HTTP status: {code}")))?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| http_err(format!("malformed header line: {line}")))?;
        headers.push((name.trim(), value.trim()));
    }
    Ok(HttpResponse { status, headers })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::vec;

    /// Mock `WebTransport` that returns pre-scripted recv frames and
    /// records all sent bytes. Same shape as `justrdp-async`'s
    /// `MockTransport` but local to this crate so the test code can
    /// own the script ergonomically.
    #[derive(Debug, Default)]
    struct ScriptedTransport {
        sent: Vec<Vec<u8>>,
        recv_queue: VecDeque<Result<Vec<u8>, TransportError>>,
        closed: bool,
    }

    impl ScriptedTransport {
        fn push_recv(&mut self, frame: Vec<u8>) {
            self.recv_queue.push_back(Ok(frame));
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

    fn block_on<F: core::future::Future>(f: F) -> F::Output {
        // tokio block_on is not available in #[test], use a small
        // single-threaded runtime per call. Tests that exercise the
        // async path use `#[tokio::test]` directly so this helper is
        // only for incidental sync use.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(f)
    }

    #[test]
    fn read_http_response_headers_finds_separator_in_single_frame() {
        block_on(async {
            let mut t = ScriptedTransport::default();
            t.push_recv(b"HTTP/1.1 200 OK\r\nX: y\r\n\r\nBODY".to_vec());
            let (headers, leftover) =
                read_http_response_headers(&mut t, Vec::new()).await.unwrap();
            assert_eq!(&headers[..], b"HTTP/1.1 200 OK\r\nX: y\r\n\r\n");
            assert_eq!(&leftover[..], b"BODY");
        });
    }

    #[test]
    fn read_http_response_headers_splits_across_recv_frames() {
        block_on(async {
            let mut t = ScriptedTransport::default();
            // Three frames: header start, mid (separator straddles
            // frame boundary), and a tail frame containing the body.
            t.push_recv(b"HTTP/1.1 401 Unauthorized\r\nWWW".to_vec());
            t.push_recv(b"-Authenticate: NTLM\r\n\r".to_vec());
            t.push_recv(b"\nBODY-START".to_vec());
            let (headers, leftover) =
                read_http_response_headers(&mut t, Vec::new()).await.unwrap();
            assert_eq!(
                &headers[..],
                b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\n\r\n"
            );
            assert_eq!(&leftover[..], b"BODY-START");
        });
    }

    #[test]
    fn read_http_response_headers_consumes_pending_leftover_first() {
        block_on(async {
            // Bytes from a prior auth round that already contain the
            // entire next response — no recv() should be issued.
            let mut t = ScriptedTransport::default();
            // Intentionally leave recv_queue empty: a recv() call
            // here would surface as `closed: drained`.
            let pending = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
            let (headers, leftover) =
                read_http_response_headers(&mut t, pending).await.unwrap();
            assert_eq!(&headers[..], b"HTTP/1.1 200 OK\r\n\r\n");
            assert!(leftover.is_empty());
        });
    }

    #[test]
    fn read_http_response_headers_eof_mid_block_errors() {
        block_on(async {
            let mut t = ScriptedTransport::default();
            t.push_recv(b"HTTP/1.1 401 Unauthorized\r\n".to_vec());
            // No more frames → next recv returns "drained" Closed.
            let err = read_http_response_headers(&mut t, Vec::new())
                .await
                .unwrap_err();
            assert_eq!(err.kind(), justrdp_async::TransportErrorKind::ConnectionClosed);
        });
    }

    #[test]
    fn read_http_response_headers_caps_runaway_input() {
        block_on(async {
            let mut t = ScriptedTransport::default();
            // Push 20 KiB of junk in 2 KiB frames with no separator.
            for _ in 0..10 {
                t.push_recv(vec![b'x'; 2048]);
            }
            let err = read_http_response_headers(&mut t, Vec::new())
                .await
                .unwrap_err();
            assert_eq!(err.kind(), justrdp_async::TransportErrorKind::Protocol);
        });
    }

    #[test]
    fn parse_http_response_splits_status_and_headers() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 401);
        assert_eq!(resp.header("WWW-Authenticate"), Some("NTLM"));
        // Case-insensitive lookup matches the contract for HTTP header
        // names.
        assert_eq!(resp.header("content-length"), Some("0"));
        assert_eq!(resp.header("x-missing"), None);
    }

    #[test]
    fn parse_http_response_rejects_non_numeric_status() {
        let raw = b"HTTP/1.1 ABC Bad\r\n\r\n";
        let err = parse_http_response(raw).unwrap_err();
        assert_eq!(err.kind(), justrdp_async::TransportErrorKind::Protocol);
    }

    #[test]
    fn parse_http_response_rejects_missing_status() {
        let raw = b"HTTP/1.1\r\n\r\n";
        let err = parse_http_response(raw).unwrap_err();
        assert_eq!(err.kind(), justrdp_async::TransportErrorKind::Protocol);
    }
}
