#![forbid(unsafe_code)]

//! HTTP/1.1 framing for RPC-over-HTTP v2 (**MS-RPCH §2.1**, §2.2.2).
//!
//! RPC-over-HTTP v2 is the legacy Windows-only transport used by
//! RD Gateway before the HTTP Transport / WebSocket Transport were
//! added. It runs DCE/RPC PDUs through two parallel HTTP/1.1
//! requests on separate TCP connections:
//!
//! | Channel | HTTP verb       | Request body                                   | Response body                                                  |
//! |---------|-----------------|------------------------------------------------|----------------------------------------------------------------|
//! | IN      | `RPC_IN_DATA`   | Long-lived: CONN/B1 followed by client PDUs    | Trivial (response headers + empty body, server closes on EOF) |
//! | OUT     | `RPC_OUT_DATA`  | Small (CONN/A1 only, `Content-Length ~= 76`)   | Long-lived: CONN/A3 / B3 / C2, then server PDUs               |
//!
//! The IN-channel request body is typically declared as
//! `Content-Length: 1073741824` (1 GiB) — a fake ceiling that
//! allows ~1 GiB of client→server data before the client must open
//! a fresh IN channel to replace it ("channel recycling"). The OUT
//! channel similarly has a large response body bound.
//!
//! This module only produces the **HTTP framing bytes**. It does not
//! own a socket, does not perform NTLM 401 retries (caller reuses
//! `justrdp-gateway::auth::NtlmClient`), and does not drive the
//! RPC-over-HTTP state machine beyond request generation — that
//! lives in [`super::tunnel`].

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

// =============================================================================
// Custom HTTP verbs (MS-RPCH §2.1.2.1)
// =============================================================================

/// Client → server channel; carries CONN/B1 followed by all DCE/RPC
/// REQUEST PDUs and outbound RTS commands.
pub const METHOD_RPC_IN_DATA: &str = "RPC_IN_DATA";

/// Client → server channel whose *response body* carries the
/// server's CONN/A3, CONN/B3, CONN/C2 and all DCE/RPC RESPONSE PDUs.
pub const METHOD_RPC_OUT_DATA: &str = "RPC_OUT_DATA";

/// Default URL path exposed by `rpcproxy.dll` (MS-RPCH §3.2.1.5).
/// Clients append `?servername:port` in the query string.
pub const DEFAULT_PATH: &str = "/rpc/rpcproxy.dll";

/// `Content-Length` value advertised by the IN channel request
/// (1 GiB). When the client has sent this many bytes of PDU data it
/// must recycle the IN channel (MS-RPCH §3.2.2.3.1).
pub const IN_CHANNEL_DEFAULT_CONTENT_LENGTH: u64 = 1_073_741_824;

/// Typical size of a CONN/A1 PDU (20 byte RTS header + four
/// commands). Used as the `Content-Length` of the OUT channel
/// request.
pub const CONN_A1_CONTENT_LENGTH: u64 = 76;

// =============================================================================
// HTTP request builder
// =============================================================================

/// Which channel the request opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpchChannel {
    In,
    Out,
}

impl RpchChannel {
    #[inline]
    pub fn method(self) -> &'static str {
        match self {
            Self::In => METHOD_RPC_IN_DATA,
            Self::Out => METHOD_RPC_OUT_DATA,
        }
    }
}

/// Build an RPC-over-HTTP request line + headers.
///
/// Mirrors the `RdgHttpRequest` builder used by the HTTP Transport
/// but with rpcproxy-specific defaults and no chunked encoding.
#[derive(Debug, Clone)]
pub struct RpchHttpRequest {
    channel: RpchChannel,
    /// Virtual host + port the IN or OUT channel ultimately targets,
    /// sent as the query string (e.g. `server1.contoso.com:3388`).
    target: String,
    /// Hostname header value (the gateway itself, e.g.
    /// `gateway.contoso.com:443`).
    host: String,
    /// Content-Length to advertise on this request.
    content_length: u64,
    /// Optional `Authorization` header value (e.g. NTLM material).
    /// None = no Authorization header emitted.
    authorization: Option<String>,
    /// Extra headers to append verbatim (e.g. User-Agent).
    extra_headers: Vec<(String, String)>,
}

impl RpchHttpRequest {
    /// Build a request for the given channel with the standard
    /// RPC-over-HTTP headers and the spec-defined default
    /// `Content-Length` for that channel.
    pub fn new(channel: RpchChannel, target: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            channel,
            target: target.into(),
            host: host.into(),
            content_length: match channel {
                RpchChannel::In => IN_CHANNEL_DEFAULT_CONTENT_LENGTH,
                RpchChannel::Out => CONN_A1_CONTENT_LENGTH,
            },
            authorization: None,
            extra_headers: Vec::new(),
        }
    }

    /// Override the `Content-Length`.
    pub fn content_length(mut self, n: u64) -> Self {
        self.content_length = n;
        self
    }

    /// Attach an `Authorization` header (e.g. `NTLM <base64>`).
    pub fn authorization(mut self, value: impl Into<String>) -> Self {
        self.authorization = Some(value.into());
        self
    }

    /// Append an arbitrary extra header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_headers.push((name.into(), value.into()));
        self
    }

    /// Serialize to the full HTTP/1.1 request line + headers,
    /// terminated with the usual `\r\n\r\n` separator.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut s = String::with_capacity(256);
        let _ = write!(
            s,
            "{} {}?{} HTTP/1.1\r\n",
            self.channel.method(),
            DEFAULT_PATH,
            self.target
        );
        let _ = write!(s, "Host: {}\r\n", self.host);
        let _ = write!(s, "Accept: application/rpc\r\n");
        let _ = write!(s, "Connection: keep-alive\r\n");
        let _ = write!(s, "Cache-Control: no-cache\r\n");
        let _ = write!(s, "Pragma: no-cache\r\n");
        let _ = write!(s, "Content-Length: {}\r\n", self.content_length);
        if let Some(auth) = &self.authorization {
            let _ = write!(s, "Authorization: {}\r\n", auth);
        }
        for (k, v) in &self.extra_headers {
            let _ = write!(s, "{}: {}\r\n", k, v);
        }
        s.push_str("\r\n");
        s.into_bytes()
    }
}

// =============================================================================
// HTTP response parser
// =============================================================================

/// Minimal HTTP/1.1 response-line + header parser. Tailored to the
/// RPC-over-HTTP dance: we only need the status code, a handful of
/// headers, and the byte offset where the body begins.
///
/// Rejects anything more exotic (transfer-encoding: chunked,
/// trailers, etc.) — rpcproxy never uses them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    /// Byte index into the original buffer where the response body
    /// begins (just past the trailing `\r\n\r\n`).
    pub body_offset: usize,
}

impl HttpResponse {
    /// Parse a response head out of `buf`. Returns `Ok(Some(resp))`
    /// on success, `Ok(None)` if the buffer does not yet contain a
    /// complete head (`\r\n\r\n` missing — caller should read more
    /// bytes), or `Err` on malformed input.
    pub fn parse(buf: &[u8]) -> Result<Option<Self>, HttpError> {
        let Some(head_end) = find_double_crlf(buf) else {
            return Ok(None);
        };
        let head = &buf[..head_end];
        let text = core::str::from_utf8(head).map_err(|_| HttpError::InvalidUtf8)?;

        let mut lines = text.split("\r\n");
        let status_line = lines.next().ok_or(HttpError::MissingStatusLine)?;

        let (status, reason) = parse_status_line(status_line)?;

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').ok_or(HttpError::MalformedHeader)?;
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }

        Ok(Some(Self {
            status,
            reason,
            headers,
            body_offset: head_end + 4, // length of "\r\n\r\n"
        }))
    }

    /// Find a header by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Collect all `WWW-Authenticate` header values (there may be
    /// more than one for multi-scheme proxies).
    pub fn www_authenticate(&self) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("WWW-Authenticate"))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// Error type produced by the HTTP response parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    InvalidUtf8,
    MissingStatusLine,
    MalformedStatusLine,
    MalformedHeader,
    UnsupportedHttpVersion,
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    // Scan for the four-byte sequence "\r\n\r\n".
    if buf.len() < 4 {
        return None;
    }
    for i in 0..=buf.len() - 4 {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

fn parse_status_line(line: &str) -> Result<(u16, String), HttpError> {
    // "HTTP/1.1 401 Unauthorized"
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().ok_or(HttpError::MalformedStatusLine)?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HttpError::UnsupportedHttpVersion);
    }
    let status_str = parts.next().ok_or(HttpError::MalformedStatusLine)?;
    let status: u16 = status_str.parse().map_err(|_| HttpError::MalformedStatusLine)?;
    let reason = parts.next().unwrap_or("").to_string();
    Ok((status, reason))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn in_channel_request_has_expected_method_and_length() {
        let req = RpchHttpRequest::new(
            RpchChannel::In,
            "targetsrv.contoso.com:3388",
            "gateway.contoso.com:443",
        );
        let bytes = req.to_bytes();
        let text = core::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("RPC_IN_DATA /rpc/rpcproxy.dll?targetsrv.contoso.com:3388 HTTP/1.1\r\n"));
        assert!(text.contains("Host: gateway.contoso.com:443\r\n"));
        assert!(text.contains("Content-Length: 1073741824\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn out_channel_request_has_short_content_length() {
        let req = RpchHttpRequest::new(RpchChannel::Out, "t:3388", "g:443");
        let text = String::from_utf8(req.to_bytes()).unwrap();
        assert!(text.contains("RPC_OUT_DATA "));
        assert!(text.contains("Content-Length: 76\r\n"));
    }

    #[test]
    fn custom_content_length_takes_effect() {
        let req = RpchHttpRequest::new(RpchChannel::Out, "t:3388", "g:443").content_length(100);
        assert!(String::from_utf8(req.to_bytes())
            .unwrap()
            .contains("Content-Length: 100\r\n"));
    }

    #[test]
    fn authorization_header_emitted_when_set() {
        let req = RpchHttpRequest::new(RpchChannel::In, "t:3388", "g:443")
            .authorization("NTLM TlRMTVNTUAABAAAA");
        let text = String::from_utf8(req.to_bytes()).unwrap();
        assert!(text.contains("Authorization: NTLM TlRMTVNTUAABAAAA\r\n"));
    }

    #[test]
    fn no_authorization_header_by_default() {
        let req = RpchHttpRequest::new(RpchChannel::In, "t:3388", "g:443");
        let text = String::from_utf8(req.to_bytes()).unwrap();
        assert!(!text.contains("Authorization:"));
    }

    #[test]
    fn extra_headers_appended_verbatim() {
        let req = RpchHttpRequest::new(RpchChannel::In, "t:3388", "g:443")
            .header("User-Agent", "MSRPC")
            .header("X-Trace-Id", "abc");
        let text = String::from_utf8(req.to_bytes()).unwrap();
        assert!(text.contains("User-Agent: MSRPC\r\n"));
        assert!(text.contains("X-Trace-Id: abc\r\n"));
    }

    #[test]
    fn parse_401_response() {
        let body = b"HTTP/1.1 401 Unauthorized\r\n\
            Content-Length: 0\r\n\
            Server: Microsoft-HTTPAPI/2.0\r\n\
            WWW-Authenticate: Negotiate\r\n\
            WWW-Authenticate: NTLM\r\n\
            \r\n";
        let resp = HttpResponse::parse(body).unwrap().unwrap();
        assert_eq!(resp.status, 401);
        assert_eq!(resp.reason, "Unauthorized");
        assert_eq!(resp.header("Content-Length"), Some("0"));
        assert_eq!(
            resp.www_authenticate(),
            vec!["Negotiate", "NTLM"],
        );
        assert_eq!(resp.body_offset, body.len());
    }

    #[test]
    fn parse_200_response() {
        let body = b"HTTP/1.1 200 Success\r\n\
            Content-Length: 4294967295\r\n\
            \r\n\
            raw bytes...";
        let resp = HttpResponse::parse(body).unwrap().unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "Success");
        assert_eq!(&body[resp.body_offset..], b"raw bytes...");
    }

    #[test]
    fn parse_partial_returns_none() {
        // Missing final \r\n\r\n.
        let body = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n";
        assert_eq!(HttpResponse::parse(body).unwrap(), None);
    }

    #[test]
    fn parse_rejects_http_0_9() {
        let body = b"HTTP/0.9 200 OK\r\n\r\n";
        assert!(matches!(
            HttpResponse::parse(body),
            Err(HttpError::UnsupportedHttpVersion)
        ));
    }

    #[test]
    fn parse_rejects_malformed_header() {
        let body = b"HTTP/1.1 200 OK\r\nBogusLineNoColon\r\n\r\n";
        assert!(matches!(
            HttpResponse::parse(body),
            Err(HttpError::MalformedHeader)
        ));
    }

    #[test]
    fn case_insensitive_header_lookup() {
        let body = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        let resp = HttpResponse::parse(body).unwrap().unwrap();
        assert_eq!(resp.header("Content-Length"), Some("0"));
        assert_eq!(resp.header("CONTENT-LENGTH"), Some("0"));
    }

    #[test]
    fn reason_may_contain_spaces() {
        let body = b"HTTP/1.1 503 Service Unavailable\r\n\r\n";
        let resp = HttpResponse::parse(body).unwrap().unwrap();
        assert_eq!(resp.status, 503);
        assert_eq!(resp.reason, "Service Unavailable");
    }

    #[test]
    fn body_offset_is_past_double_crlf() {
        let body = b"HTTP/1.1 200 OK\r\nX-Foo: bar\r\n\r\nBODY";
        let resp = HttpResponse::parse(body).unwrap().unwrap();
        assert_eq!(&body[resp.body_offset..], b"BODY");
    }

    #[test]
    fn channel_method_strings() {
        assert_eq!(RpchChannel::In.method(), "RPC_IN_DATA");
        assert_eq!(RpchChannel::Out.method(), "RPC_OUT_DATA");
    }
}
