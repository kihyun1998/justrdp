#![forbid(unsafe_code)]

//! HTTP/1.1 framing helpers for the MS-TSGU HTTP Transport.
//!
//! MS-TSGU §3.3.5.1 specifies that the gateway client opens two
//! long-lived HTTP connections: an **IN channel** (client → gateway)
//! using the custom verb `RDG_IN_DATA`, and an **OUT channel**
//! (gateway → client) using `RDG_OUT_DATA`. Both use chunked transfer
//! encoding and carry a `RDG-Connection-Id` GUID header that ties the
//! two sides together.
//!
//! This module is pure framing — no I/O. Callers build the HTTP
//! request bytes with [`RdgHttpRequest`], write chunks with
//! [`encode_chunk`] / [`encode_final_chunk`], decode chunks with
//! [`ChunkedDecoder`], and skip the mandatory 100-byte random
//! preamble at the start of the OUT channel stream with
//! [`PreambleSkipper`].

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

// =============================================================================
// HTTP constants (MS-TSGU §2.2.3)
// =============================================================================

/// Custom HTTP verb for the client → gateway IN channel. §2.2.3.1.1
pub const METHOD_RDG_IN_DATA: &str = "RDG_IN_DATA";
/// Custom HTTP verb for the gateway → client OUT channel. §2.2.3.1.2
pub const METHOD_RDG_OUT_DATA: &str = "RDG_OUT_DATA";
/// Default URL path for the gateway endpoint. §3.3.5.1
pub const DEFAULT_URL_PATH: &str = "/remoteDesktopGateway/";

/// Client identifier header — a GUID that correlates the IN and OUT
/// channels. §2.2.3.2.1
pub const HEADER_RDG_CONNECTION_ID: &str = "RDG-Connection-Id";
/// Diagnostic correlation header. §2.2.3.2.2
pub const HEADER_RDG_CORRELATION_ID: &str = "RDG-Correlation-Id";
/// Optional user name header. §2.2.3.2.3
pub const HEADER_RDG_USER_ID: &str = "RDG-User-Id";

/// Size in bytes of the mandatory random preamble that the OUT channel
/// server emits before any MS-TSGU PDU bytes. §3.3.5.1 Normal Scenario.
pub const OUT_CHANNEL_PREAMBLE_SIZE: usize = 100;

// =============================================================================
// GUID formatter
// =============================================================================

/// Format a 16-byte connection identifier as an MS-style GUID string
/// (`{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`).
///
/// The input is treated as raw bytes in the GUID's canonical on-the-
/// wire layout (RFC 4122 §4.1.2): the first four bytes become the
/// first group, the next two bytes become the second group, etc. No
/// endian conversion is applied — pass the bytes in the order they
/// should appear in the textual output.
pub fn format_guid_braces(id: &[u8; 16]) -> String {
    let mut s = String::with_capacity(38);
    s.push('{');
    push_hex(&mut s, &id[0..4]);
    s.push('-');
    push_hex(&mut s, &id[4..6]);
    s.push('-');
    push_hex(&mut s, &id[6..8]);
    s.push('-');
    push_hex(&mut s, &id[8..10]);
    s.push('-');
    push_hex(&mut s, &id[10..16]);
    s.push('}');
    s
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
}

// =============================================================================
// RdgHttpRequest
// =============================================================================

/// Which of the two gateway HTTP methods this request uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdgMethod {
    /// `RDG_IN_DATA` — client-to-gateway channel.
    InData,
    /// `RDG_OUT_DATA` — gateway-to-client channel.
    OutData,
}

impl RdgMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InData => METHOD_RDG_IN_DATA,
            Self::OutData => METHOD_RDG_OUT_DATA,
        }
    }
}

/// Builder for an HTTP/1.1 request that opens one half of the
/// MS-TSGU HTTP Transport (either IN or OUT channel).
///
/// The builder does not compose authentication headers — those are
/// added by the caller on the HTTP 401 retry (NTLM/Negotiate
/// handshake).
#[derive(Debug, Clone)]
pub struct RdgHttpRequest {
    pub method: RdgMethod,
    pub host: String,
    pub url_path: String,
    /// 16-byte connection ID — MUST be identical on the IN and OUT
    /// channels of the same session.
    pub connection_id: [u8; 16],
    /// Optional correlation GUID for diagnostics.
    pub correlation_id: Option<[u8; 16]>,
    /// Optional user name string (not base64, not encrypted).
    pub user_id: Option<String>,
    /// Optional `Authorization` header value (filled in on the retry
    /// after the 401 challenge).
    pub authorization: Option<String>,
    /// `User-Agent` string. Defaults to a short diagnostic value if
    /// left empty.
    pub user_agent: String,
}

impl RdgHttpRequest {
    pub fn new(method: RdgMethod, host: impl Into<String>, connection_id: [u8; 16]) -> Self {
        Self {
            method,
            host: host.into(),
            url_path: DEFAULT_URL_PATH.to_string(),
            connection_id,
            correlation_id: None,
            user_id: None,
            authorization: None,
            user_agent: "MS-RDGClient/1.0".to_string(),
        }
    }

    /// Serialise the request line + headers + trailing CRLF into
    /// `out`. The caller is responsible for streaming the chunked body
    /// that follows (use [`encode_chunk`] / [`encode_final_chunk`]).
    pub fn write_to(&self, out: &mut Vec<u8>) {
        push_str(out, self.method.as_str());
        out.push(b' ');
        push_str(out, &self.url_path);
        push_str(out, " HTTP/1.1\r\n");

        header(out, "Host", &self.host);
        header(out, "Accept", "*/*");
        header(out, "Cache-Control", "no-cache");
        header(out, "Connection", "Keep-Alive");
        header(out, "Pragma", "no-cache");
        header(out, "User-Agent", &self.user_agent);
        header(out, "Transfer-Encoding", "chunked");

        header(
            out,
            HEADER_RDG_CONNECTION_ID,
            &format_guid_braces(&self.connection_id),
        );
        if let Some(corr) = &self.correlation_id {
            header(out, HEADER_RDG_CORRELATION_ID, &format_guid_braces(corr));
        }
        if let Some(uid) = &self.user_id {
            header(out, HEADER_RDG_USER_ID, uid);
        }
        if let Some(auth) = &self.authorization {
            header(out, "Authorization", auth);
        }

        push_str(out, "\r\n");
    }

    /// Convenience: serialise directly into a new `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        self.write_to(&mut out);
        out
    }
}

fn header(out: &mut Vec<u8>, name: &str, value: &str) {
    push_str(out, name);
    push_str(out, ": ");
    push_header_value(out, value);
    push_str(out, "\r\n");
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
}

/// Append an HTTP header value byte-by-byte, dropping any CR (`\r`)
/// or LF (`\n`). RFC 9110 §5.5 forbids these in field values; if an
/// attacker-controlled field (`RDG-User-Id`, `Authorization`, the
/// user-agent override) smuggled them in, the result would be an
/// extra header or — with `Content-Length` — request smuggling.
/// Silently stripping matches how browsers and curl treat the same
/// input and avoids a fallible `header()` signature.
fn push_header_value(out: &mut Vec<u8>, value: &str) {
    for &b in value.as_bytes() {
        if b != b'\r' && b != b'\n' {
            out.push(b);
        }
    }
}

// =============================================================================
// Chunked transfer encoding (RFC 9112 §7.1)
// =============================================================================

/// Errors reported by [`ChunkedDecoder::feed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkError {
    /// The chunk size line was not valid ASCII hex.
    BadChunkSize,
    /// A chunk or line was not terminated with CRLF where required.
    BadFraming,
    /// The chunk size header exceeded an internal sanity limit.
    ChunkSizeTooLarge,
}

/// Append a single chunked-encoded frame containing `data` to `out`.
///
/// The frame format is `<hex-size>\r\n<data>\r\n`. Empty chunks are
/// permitted (they encode as `0\r\n\r\n`, the final-chunk marker —
/// use [`encode_final_chunk`] for explicitness).
pub fn encode_chunk(data: &[u8], out: &mut Vec<u8>) {
    write_hex_size(out, data.len());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// Append the final (`0`-sized) chunk + trailing CRLF to `out`,
/// terminating the chunked body.
pub fn encode_final_chunk(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0\r\n\r\n");
}

fn write_hex_size(out: &mut Vec<u8>, mut size: usize) {
    if size == 0 {
        out.push(b'0');
        return;
    }
    // Write hex digits in reverse, then flip.
    let start = out.len();
    while size > 0 {
        let nibble = (size & 0xF) as u8;
        out.push(if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        });
        size >>= 4;
    }
    out[start..].reverse();
}

/// Internal sanity cap on chunk size (16 MiB). RDP PDUs fit inside
/// `HTTP_DATA_PACKET` (u16 payload), so this is generous.
const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
enum ChunkState {
    /// Waiting for the hex size line (terminated by CRLF).
    Size,
    /// Reading `remaining` bytes of chunk payload.
    Data { remaining: usize },
    /// Reading the CRLF that follows a chunk payload.
    PostDataCrlf,
    /// Reading the CRLF that follows the final `0` chunk.
    PostFinalCrlf,
    /// No more data expected.
    Done,
}

/// Incremental decoder for HTTP/1.1 chunked transfer encoding.
///
/// The decoder accumulates bytes in an internal buffer until at least
/// one full chunk is available, then returns its payload. Usage:
///
/// ```ignore
/// let mut dec = ChunkedDecoder::new();
/// let payload = dec.feed(&bytes_from_socket)?;
/// // `payload` contains all chunk bodies decoded from this feed
/// // (possibly empty if no chunk completed yet).
/// ```
#[derive(Debug, Clone)]
pub struct ChunkedDecoder {
    state: ChunkState,
    /// Partial unparsed bytes (never includes fully-decoded payload).
    pending: Vec<u8>,
}

impl Default for ChunkedDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkedDecoder {
    pub fn new() -> Self {
        Self {
            state: ChunkState::Size,
            pending: Vec::new(),
        }
    }

    /// Returns `true` once the terminating `0`-sized chunk has been
    /// observed and its trailing CRLF consumed.
    pub fn is_done(&self) -> bool {
        matches!(self.state, ChunkState::Done)
    }

    /// Accept another block of bytes from the transport and return
    /// any fully-decoded payload bytes extracted so far. Payload may
    /// be empty if the feed ended mid-chunk.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ChunkError> {
        self.pending.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            match &mut self.state {
                ChunkState::Size => {
                    let Some(line_end) = find_crlf(&self.pending) else {
                        break;
                    };
                    let size = parse_hex_size(&self.pending[..line_end])?;
                    if size > MAX_CHUNK_SIZE {
                        return Err(ChunkError::ChunkSizeTooLarge);
                    }
                    // Drop "size\r\n".
                    self.pending.drain(..line_end + 2);
                    if size == 0 {
                        self.state = ChunkState::PostFinalCrlf;
                    } else {
                        self.state = ChunkState::Data { remaining: size };
                    }
                }
                ChunkState::Data { remaining } => {
                    if self.pending.is_empty() {
                        break;
                    }
                    let take = (*remaining).min(self.pending.len());
                    out.extend_from_slice(&self.pending[..take]);
                    self.pending.drain(..take);
                    *remaining -= take;
                    if *remaining == 0 {
                        self.state = ChunkState::PostDataCrlf;
                    }
                }
                ChunkState::PostDataCrlf => {
                    if self.pending.len() < 2 {
                        break;
                    }
                    if &self.pending[..2] != b"\r\n" {
                        return Err(ChunkError::BadFraming);
                    }
                    self.pending.drain(..2);
                    self.state = ChunkState::Size;
                }
                ChunkState::PostFinalCrlf => {
                    if self.pending.len() < 2 {
                        break;
                    }
                    if &self.pending[..2] != b"\r\n" {
                        return Err(ChunkError::BadFraming);
                    }
                    self.pending.drain(..2);
                    self.state = ChunkState::Done;
                    break;
                }
                ChunkState::Done => break,
            }
        }
        Ok(out)
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn parse_hex_size(bytes: &[u8]) -> Result<usize, ChunkError> {
    // Accept an optional `;ext=value` chunk extension by stripping at
    // the first `;` (RFC 9112 §7.1.1 permits extensions).
    let end = bytes.iter().position(|&b| b == b';').unwrap_or(bytes.len());
    let hex = &bytes[..end];
    if hex.is_empty() || hex.len() > 16 {
        return Err(ChunkError::BadChunkSize);
    }
    let mut value: usize = 0;
    for &b in hex {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => 10 + b - b'a',
            b'A'..=b'F' => 10 + b - b'A',
            _ => return Err(ChunkError::BadChunkSize),
        };
        value = value
            .checked_shl(4)
            .and_then(|v| v.checked_add(digit as usize))
            .ok_or(ChunkError::BadChunkSize)?;
    }
    Ok(value)
}

// =============================================================================
// OUT channel preamble skipper (MS-TSGU §3.3.5.1)
// =============================================================================

/// Stateful helper that discards the first
/// [`OUT_CHANNEL_PREAMBLE_SIZE`] bytes of the OUT channel's
/// post-chunked stream before exposing MS-TSGU PDU bytes to the
/// caller. Feed bytes in any chunk size; the returned slice contains
/// only the post-preamble portion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreambleSkipper {
    remaining: usize,
}

impl Default for PreambleSkipper {
    fn default() -> Self {
        Self::new()
    }
}

impl PreambleSkipper {
    pub const fn new() -> Self {
        Self {
            remaining: OUT_CHANNEL_PREAMBLE_SIZE,
        }
    }

    /// `true` once all 100 preamble bytes have been observed.
    pub const fn done(&self) -> bool {
        self.remaining == 0
    }

    /// Number of preamble bytes still to discard.
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    /// Consume as much of the preamble as possible from `bytes` and
    /// return the slice of `bytes` that follows the preamble (possibly
    /// empty). Subsequent calls pass through unchanged once
    /// [`Self::done`] is true.
    pub fn feed<'a>(&mut self, bytes: &'a [u8]) -> &'a [u8] {
        if self.remaining == 0 {
            return bytes;
        }
        let drop = self.remaining.min(bytes.len());
        self.remaining -= drop;
        &bytes[drop..]
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // ---------- format_guid_braces ----------

    #[test]
    fn guid_format_is_lowercase_braced() {
        let id = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        assert_eq!(
            format_guid_braces(&id),
            "{12345678-9abc-def0-1122-334455667788}"
        );
    }

    #[test]
    fn guid_format_all_zero() {
        assert_eq!(
            format_guid_braces(&[0u8; 16]),
            "{00000000-0000-0000-0000-000000000000}"
        );
    }

    // ---------- RdgHttpRequest ----------

    #[test]
    fn in_data_request_has_required_headers() {
        let req = RdgHttpRequest::new(
            RdgMethod::InData,
            "gateway.example.com:443",
            [0xAA; 16],
        );
        let bytes = req.to_bytes();
        let text = core::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("RDG_IN_DATA /remoteDesktopGateway/ HTTP/1.1\r\n"));
        assert!(text.contains("\r\nHost: gateway.example.com:443\r\n"));
        assert!(text.contains("\r\nTransfer-Encoding: chunked\r\n"));
        assert!(text.contains("\r\nConnection: Keep-Alive\r\n"));
        assert!(text.contains("\r\nAccept: */*\r\n"));
        assert!(text.contains("\r\nCache-Control: no-cache\r\n"));
        assert!(text.contains("\r\nPragma: no-cache\r\n"));
        assert!(text.contains(
            "\r\nRDG-Connection-Id: {aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\r\n"
        ));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn out_data_request_uses_correct_verb() {
        let req = RdgHttpRequest::new(RdgMethod::OutData, "gw", [0; 16]);
        let bytes = req.to_bytes();
        assert!(bytes.starts_with(b"RDG_OUT_DATA "));
    }

    #[test]
    fn request_omits_optional_headers_by_default() {
        let bytes = RdgHttpRequest::new(RdgMethod::InData, "h", [0; 16]).to_bytes();
        let text = core::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("Authorization"));
        assert!(!text.contains("RDG-Correlation-Id"));
        assert!(!text.contains("RDG-User-Id"));
    }

    #[test]
    fn request_includes_authorization_when_set() {
        let mut req = RdgHttpRequest::new(RdgMethod::InData, "h", [0; 16]);
        req.authorization = Some("Negotiate TlRMTVNTUAAB".to_string());
        req.correlation_id = Some([0xBB; 16]);
        req.user_id = Some("alice".to_string());
        let text = String::from_utf8(req.to_bytes()).unwrap();
        assert!(text.contains("\r\nAuthorization: Negotiate TlRMTVNTUAAB\r\n"));
        assert!(text.contains(
            "\r\nRDG-Correlation-Id: {bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}\r\n"
        ));
        assert!(text.contains("\r\nRDG-User-Id: alice\r\n"));
    }

    #[test]
    fn header_values_strip_crlf_to_prevent_injection() {
        // Hostile `user_id` attempts to smuggle an extra header; the
        // request builder must drop the CR/LF and emit the remaining
        // text on a single header line. A naive splice would have
        // produced `\r\nX-Injected: yes\r\n` as a standalone header.
        let mut req = RdgHttpRequest::new(RdgMethod::InData, "h", [0; 16]);
        req.user_id = Some("alice\r\nX-Injected: yes".to_string());
        req.authorization = Some("NTLM token\nX-Evil: 1".to_string());
        let text = String::from_utf8(req.to_bytes()).unwrap();
        // The smuggled name must NOT appear as a standalone header.
        assert!(!text.contains("\r\nX-Injected:"));
        assert!(!text.contains("\r\nX-Evil:"));
        // Sanitised values survive minus the CR/LF — concatenated
        // into the legitimate header value.
        assert!(text.contains("\r\nRDG-User-Id: aliceX-Injected: yes\r\n"));
        assert!(text.contains("\r\nAuthorization: NTLM tokenX-Evil: 1\r\n"));
    }

    // ---------- encode_chunk / encode_final_chunk ----------

    #[test]
    fn encode_chunk_small_payload() {
        let mut out = Vec::new();
        encode_chunk(b"hello", &mut out);
        assert_eq!(out, b"5\r\nhello\r\n");
    }

    #[test]
    fn encode_chunk_multi_hex_digits() {
        let data = vec![0u8; 0x1AB];
        let mut out = Vec::new();
        encode_chunk(&data, &mut out);
        assert_eq!(&out[..5], b"1ab\r\n");
        assert_eq!(&out[5..5 + 0x1AB], &data[..]);
        assert_eq!(&out[5 + 0x1AB..], b"\r\n");
    }

    #[test]
    fn encode_chunk_zero_size() {
        let mut out = Vec::new();
        encode_chunk(&[], &mut out);
        assert_eq!(out, b"0\r\n\r\n");
    }

    #[test]
    fn encode_final_chunk_shape() {
        let mut out = Vec::new();
        encode_final_chunk(&mut out);
        assert_eq!(out, b"0\r\n\r\n");
    }

    // ---------- ChunkedDecoder ----------

    #[test]
    fn chunked_decoder_single_chunk_roundtrip() {
        let mut enc = Vec::new();
        encode_chunk(b"hello world", &mut enc);
        encode_final_chunk(&mut enc);

        let mut dec = ChunkedDecoder::new();
        let out = dec.feed(&enc).unwrap();
        assert_eq!(out, b"hello world");
        assert!(dec.is_done());
    }

    #[test]
    fn chunked_decoder_split_across_feeds() {
        let mut enc = Vec::new();
        encode_chunk(b"abcdefgh", &mut enc);
        encode_final_chunk(&mut enc);

        let mut dec = ChunkedDecoder::new();
        let mut total = Vec::new();
        // Feed one byte at a time.
        for b in &enc {
            total.extend_from_slice(&dec.feed(core::slice::from_ref(b)).unwrap());
        }
        assert_eq!(total, b"abcdefgh");
        assert!(dec.is_done());
    }

    #[test]
    fn chunked_decoder_multiple_chunks() {
        let mut enc = Vec::new();
        encode_chunk(b"aaa", &mut enc);
        encode_chunk(b"bbbb", &mut enc);
        encode_chunk(b"ccccc", &mut enc);
        encode_final_chunk(&mut enc);

        let mut dec = ChunkedDecoder::new();
        let out = dec.feed(&enc).unwrap();
        assert_eq!(out, b"aaabbbbccccc");
        assert!(dec.is_done());
    }

    #[test]
    fn chunked_decoder_rejects_bad_size() {
        let mut dec = ChunkedDecoder::new();
        assert_eq!(dec.feed(b"zzz\r\n").unwrap_err(), ChunkError::BadChunkSize);
    }

    #[test]
    fn chunked_decoder_rejects_missing_trailing_crlf() {
        let bytes = b"3\r\nabcXX";
        let mut dec = ChunkedDecoder::new();
        assert_eq!(dec.feed(bytes).unwrap_err(), ChunkError::BadFraming);
    }

    #[test]
    fn chunked_decoder_accepts_chunk_extension() {
        // `5;ext=foo\r\nhello\r\n0\r\n\r\n`
        let bytes = b"5;ext=foo\r\nhello\r\n0\r\n\r\n";
        let mut dec = ChunkedDecoder::new();
        let out = dec.feed(bytes).unwrap();
        assert_eq!(out, b"hello");
        assert!(dec.is_done());
    }

    // ---------- PreambleSkipper ----------

    #[test]
    fn preamble_skipper_consumes_exactly_100_bytes() {
        let mut skip = PreambleSkipper::new();
        let big = vec![0xABu8; 150];
        let rest = skip.feed(&big);
        assert_eq!(rest.len(), 50);
        assert!(skip.done());
    }

    #[test]
    fn preamble_skipper_handles_multi_feed() {
        let mut skip = PreambleSkipper::new();
        // 40 + 40 + 30 = 110 → 10 bytes emerge after the 100B preamble
        assert_eq!(skip.feed(&vec![0; 40]), &[] as &[u8]);
        assert_eq!(skip.remaining(), 60);
        assert_eq!(skip.feed(&vec![0; 40]), &[] as &[u8]);
        assert_eq!(skip.remaining(), 20);
        let tail = skip.feed(&[1u8; 30]);
        assert_eq!(tail.len(), 10);
        assert!(skip.done());
    }

    #[test]
    fn preamble_skipper_pass_through_after_done() {
        let mut skip = PreambleSkipper::new();
        skip.feed(&vec![0; OUT_CHANNEL_PREAMBLE_SIZE]);
        assert!(skip.done());
        let payload = [1, 2, 3, 4];
        assert_eq!(skip.feed(&payload), &payload);
    }

    // ---------- Integration: request → chunk → decode → skip ----------

    #[test]
    fn full_out_channel_wire_roundtrip() {
        // Simulate a full OUT-channel stream: 100B preamble + one
        // chunked PDU + final chunk. Caller threads the decoder and
        // skipper together to recover the inner PDU bytes.
        let preamble = vec![0xFFu8; OUT_CHANNEL_PREAMBLE_SIZE];
        let pdu = [0x0D, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00]; // Keepalive

        let mut body = Vec::new();
        body.extend_from_slice(&preamble);
        body.extend_from_slice(&pdu);
        let mut chunked = Vec::new();
        encode_chunk(&body, &mut chunked);
        encode_final_chunk(&mut chunked);

        let mut dec = ChunkedDecoder::new();
        let decoded = dec.feed(&chunked).unwrap();
        assert!(dec.is_done());
        let mut skipper = PreambleSkipper::new();
        let rest = skipper.feed(&decoded);
        assert!(skipper.done());
        assert_eq!(rest, &pdu);
    }
}
