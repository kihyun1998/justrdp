#![forbid(unsafe_code)]

//! WebSocket framing + opening handshake helpers (RFC 6455).
//!
//! Pure framing module — no I/O, no state machine beyond the
//! incremental [`WsFrameDecoder`]. Used by the MS-TSGU WebSocket
//! Transport variant (MS-TSGU §2.2.3.1.2 + "During HTTP and WebSocket
//! Transport Setup") to carry the same `GatewayClient` PDUs over
//! RFC 6455 binary frames instead of HTTP chunked encoding.
//!
//! ## Scope
//!
//! - [`ws_accept_key`]: Sec-WebSocket-Accept derivation for verifying
//!   the 101 response (RFC 6455 §1.3, §4.1).
//! - [`WsUpgradeRequest`]: builds the opening `GET` with MS-TSGU
//!   custom headers + RFC 6455 upgrade headers.
//! - [`encode_frame`] / [`WsFrameDecoder`]: minimal client-side frame
//!   codec (Binary + Close + Ping + Pong + Continuation).
//!
//! Not in scope: autobahn compliance, permessage-deflate, text frames
//! (MS-TSGU is binary-only), server-side framing.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use justrdp_core::crypto::sha1;

use crate::auth::base64_encode;
use crate::http::{format_guid_braces, DEFAULT_URL_PATH, HEADER_RDG_CONNECTION_ID};

// =============================================================================
// Constants
// =============================================================================

/// RFC 6455 §1.3 server challenge magic value. Concatenated with the
/// client's `Sec-WebSocket-Key` before hashing to derive the
/// `Sec-WebSocket-Accept` value.
pub const WS_MAGIC_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// RFC 6455 §4.1 protocol version. The only version MS-TSGU accepts.
pub const WS_VERSION: u8 = 13;

/// Maximum payload size of a control frame (Close / Ping / Pong)
/// per RFC 6455 §5.5.
pub const WS_MAX_CONTROL_PAYLOAD: usize = 125;

// ── Opcodes (RFC 6455 §11.8) ──

pub const WS_OPCODE_CONTINUATION: u8 = 0x0;
pub const WS_OPCODE_TEXT: u8 = 0x1;
pub const WS_OPCODE_BINARY: u8 = 0x2;
pub const WS_OPCODE_CLOSE: u8 = 0x8;
pub const WS_OPCODE_PING: u8 = 0x9;
pub const WS_OPCODE_PONG: u8 = 0xA;

// ── Close status codes (RFC 6455 §7.4.1) ──

pub const WS_CLOSE_NORMAL: u16 = 1000;
pub const WS_CLOSE_GOING_AWAY: u16 = 1001;
pub const WS_CLOSE_PROTOCOL_ERROR: u16 = 1002;
pub const WS_CLOSE_UNSUPPORTED_DATA: u16 = 1003;

// =============================================================================
// Sec-WebSocket-Accept
// =============================================================================

/// Compute the `Sec-WebSocket-Accept` value for a given client
/// `Sec-WebSocket-Key` per RFC 6455 §1.3:
///
/// ```text
/// base64(SHA-1(key || WS_MAGIC_GUID))
/// ```
pub fn ws_accept_key(client_key: &str) -> String {
    let mut buf = Vec::with_capacity(client_key.len() + WS_MAGIC_GUID.len());
    buf.extend_from_slice(client_key.as_bytes());
    buf.extend_from_slice(WS_MAGIC_GUID.as_bytes());
    let digest = sha1(&buf);
    base64_encode(&digest)
}

// =============================================================================
// WsUpgradeRequest
// =============================================================================

/// HTTP/1.1 opening handshake request for the MS-TSGU WebSocket
/// Transport variant.
///
/// Unlike [`crate::http::RdgHttpRequest`] this uses the standard
/// `GET` verb and advertises the RFC 6455 upgrade headers instead of
/// `Transfer-Encoding: chunked`. The MS-TSGU custom headers
/// (`RDG-Connection-Id`, optional `RDG-Correlation-Id`, optional
/// `RDG-User-Id`) are preserved because they still identify the
/// logical tunnel session to the gateway.
#[derive(Debug, Clone)]
pub struct WsUpgradeRequest {
    pub host: String,
    pub url_path: String,
    pub connection_id: [u8; 16],
    pub correlation_id: Option<[u8; 16]>,
    pub user_id: Option<String>,
    /// Exactly-24-character base64-encoded 16 random bytes. Callers
    /// MUST generate a fresh value per connection (RFC 6455 §4.1
    /// client requirement 7).
    pub sec_websocket_key: String,
    /// Optional `Sec-WebSocket-Protocol` subprotocol name. MS-TSGU
    /// does not mandate a value; Azure AVD gateways observed in the
    /// wild accept both absent and `RDG_Websocket`. Left `None` by
    /// default.
    pub sec_websocket_protocol: Option<String>,
    /// Optional `Authorization` header value — filled in on NTLM
    /// retry rounds.
    pub authorization: Option<String>,
    pub user_agent: String,
}

impl WsUpgradeRequest {
    pub fn new(
        host: impl Into<String>,
        connection_id: [u8; 16],
        sec_websocket_key: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            url_path: DEFAULT_URL_PATH.to_string(),
            connection_id,
            correlation_id: None,
            user_id: None,
            sec_websocket_key: sec_websocket_key.into(),
            sec_websocket_protocol: None,
            authorization: None,
            user_agent: "MS-RDGClient/1.0".to_string(),
        }
    }

    pub fn write_to(&self, out: &mut Vec<u8>) {
        push(out, "GET ");
        push(out, &self.url_path);
        push(out, " HTTP/1.1\r\n");

        header(out, "Host", &self.host);
        header(out, "Upgrade", "websocket");
        header(out, "Connection", "Upgrade");
        header(out, "Sec-WebSocket-Version", "13");
        header(out, "Sec-WebSocket-Key", &self.sec_websocket_key);
        if let Some(proto) = &self.sec_websocket_protocol {
            header(out, "Sec-WebSocket-Protocol", proto);
        }
        header(out, "Cache-Control", "no-cache");
        header(out, "Pragma", "no-cache");
        header(out, "Accept", "*/*");
        header(out, "User-Agent", &self.user_agent);
        header(
            out,
            HEADER_RDG_CONNECTION_ID,
            &format_guid_braces(&self.connection_id),
        );
        if let Some(corr) = &self.correlation_id {
            header(out, "RDG-Correlation-Id", &format_guid_braces(corr));
        }
        if let Some(uid) = &self.user_id {
            header(out, "RDG-User-Id", uid);
        }
        if let Some(auth) = &self.authorization {
            header(out, "Authorization", auth);
        }
        push(out, "\r\n");
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        self.write_to(&mut out);
        out
    }
}

fn header(out: &mut Vec<u8>, name: &str, value: &str) {
    push(out, name);
    push(out, ": ");
    push_header_value(out, value);
    push(out, "\r\n");
}

fn push(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
}

/// Append an HTTP header value byte-by-byte, dropping any CR (`\r`)
/// or LF (`\n`) per RFC 9110 §5.5. Prevents header injection via
/// attacker-controlled fields (Host override, sub-protocol, auth
/// header).
fn push_header_value(out: &mut Vec<u8>, value: &str) {
    for &b in value.as_bytes() {
        if b != b'\r' && b != b'\n' {
            out.push(b);
        }
    }
}

// =============================================================================
// Frame codec
// =============================================================================

/// Errors reported by the frame decoder / encoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsError {
    /// RSV1/RSV2/RSV3 bits set with no extension negotiated.
    ReservedBitsSet,
    /// Opcode not in {0, 2, 8, 9, 10}.
    UnsupportedOpcode(u8),
    /// Text (0x1) frame received; MS-TSGU is binary-only.
    TextFrame,
    /// Non-minimal length encoding on receive (payload ≤ 125 encoded
    /// with 126/127, or ≤ 65535 encoded with 127). RFC 6455 §5.2.
    NonMinimalLength,
    /// Control frame with FIN = 0 or payload > 125 bytes.
    BadControlFrame,
    /// Server frame had MASK bit set (servers MUST NOT mask client-
    /// bound frames, RFC 6455 §5.1).
    MaskedServerFrame,
    /// 127-variant length field with the MSB set (reserved).
    LengthMsbSet,
    /// Payload exceeded the decoder budget.
    FrameTooLarge(usize),
}

/// A single decoded (unmasked, reassembled) application-data frame,
/// or a decoded control frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsFrame {
    /// Reassembled application data (Binary or Continuation chain),
    /// delivered only once FIN is observed.
    Binary(Vec<u8>),
    /// Close frame with optional 2-byte status code + reason.
    Close { code: Option<u16>, reason: Vec<u8> },
    /// Ping frame (payload ≤ 125 bytes).
    Ping(Vec<u8>),
    /// Pong frame (payload ≤ 125 bytes).
    Pong(Vec<u8>),
}

/// Encode a single frame from the client to the server.
///
/// Client-to-server frames MUST be masked (RFC 6455 §5.3). The caller
/// supplies the 4-byte masking key; each call should use a fresh key
/// drawn from a cryptographic RNG.
///
/// Control frames panic if `payload.len() > WS_MAX_CONTROL_PAYLOAD` —
/// the caller is responsible for enforcing the limit on application
/// data before choosing the opcode.
pub fn encode_frame(
    opcode: u8,
    fin: bool,
    payload: &[u8],
    mask: [u8; 4],
    out: &mut Vec<u8>,
) -> Result<(), WsError> {
    let is_control = matches!(
        opcode,
        WS_OPCODE_CLOSE | WS_OPCODE_PING | WS_OPCODE_PONG
    );
    if is_control {
        if !fin {
            return Err(WsError::BadControlFrame);
        }
        if payload.len() > WS_MAX_CONTROL_PAYLOAD {
            return Err(WsError::BadControlFrame);
        }
    }
    if opcode == WS_OPCODE_TEXT {
        return Err(WsError::TextFrame);
    }
    if opcode > 0xF {
        return Err(WsError::UnsupportedOpcode(opcode));
    }

    let b0 = (if fin { 0x80 } else { 0 }) | (opcode & 0x0F);
    out.push(b0);

    let len = payload.len();
    let mask_bit: u8 = 0x80;
    if len <= 125 {
        out.push(mask_bit | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }

    out.extend_from_slice(&mask);
    // Masked payload: out[i] = in[i] XOR mask[i % 4] (§5.3).
    let start = out.len();
    out.extend_from_slice(payload);
    for (i, byte) in out[start..].iter_mut().enumerate() {
        *byte ^= mask[i & 0x3];
    }
    Ok(())
}

/// Incremental frame decoder for the server → client direction. Feed
/// bytes as they arrive; it emits zero or more fully-parsed
/// [`WsFrame`]s per call. Reassembles fragmented application-data
/// frames (Binary + Continuation) into a single [`WsFrame::Binary`]
/// delivered only once FIN is observed. Control frames interleaved
/// among fragments are delivered immediately.
pub struct WsFrameDecoder {
    /// Byte buffer of bytes received but not yet parsed.
    buf: Vec<u8>,
    /// Reassembly buffer for fragmented Binary frames.
    fragmented: Vec<u8>,
    /// True while we are in the middle of a fragmented Binary message
    /// (at least one frame with FIN = 0 has been received for the
    /// current logical message).
    in_fragment: bool,
    /// Cap on a single reassembled message. Default: 16 MiB.
    max_message: usize,
}

impl WsFrameDecoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            fragmented: Vec::new(),
            in_fragment: false,
            max_message: 16 * 1024 * 1024,
        }
    }

    pub fn with_max_message(max_message: usize) -> Self {
        Self {
            buf: Vec::new(),
            fragmented: Vec::new(),
            in_fragment: false,
            max_message,
        }
    }

    /// Append `bytes` to the decoder and return every fully-parsed
    /// frame that is now available.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<WsFrame>, WsError> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(frame) = self.try_parse_one()? {
            out.push(frame);
        }
        Ok(out)
    }

    fn try_parse_one(&mut self) -> Result<Option<WsFrame>, WsError> {
        if self.buf.len() < 2 {
            return Ok(None);
        }
        let b0 = self.buf[0];
        let b1 = self.buf[1];

        let fin = (b0 & 0x80) != 0;
        let rsv = b0 & 0x70;
        if rsv != 0 {
            return Err(WsError::ReservedBitsSet);
        }
        let opcode = b0 & 0x0F;
        let masked = (b1 & 0x80) != 0;
        if masked {
            return Err(WsError::MaskedServerFrame);
        }
        let short_len = b1 & 0x7F;

        // Work out header size + payload length without mutating buf yet.
        let (header_len, payload_len) = match short_len {
            0..=125 => (2usize, short_len as usize),
            126 => {
                if self.buf.len() < 4 {
                    return Ok(None);
                }
                let n = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize;
                if n <= 125 {
                    return Err(WsError::NonMinimalLength);
                }
                (4, n)
            }
            127 => {
                if self.buf.len() < 10 {
                    return Ok(None);
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&self.buf[2..10]);
                if arr[0] & 0x80 != 0 {
                    return Err(WsError::LengthMsbSet);
                }
                let n = u64::from_be_bytes(arr) as usize;
                if n <= u16::MAX as usize {
                    return Err(WsError::NonMinimalLength);
                }
                (10, n)
            }
            _ => unreachable!(),
        };

        if payload_len > self.max_message {
            return Err(WsError::FrameTooLarge(payload_len));
        }

        let total = header_len + payload_len;
        if self.buf.len() < total {
            return Ok(None);
        }

        let payload_start = header_len;
        let payload_end = header_len + payload_len;
        let payload: Vec<u8> = self.buf[payload_start..payload_end].to_vec();
        self.buf.drain(..total);

        // ── Validate + route by opcode ──
        let is_control = matches!(
            opcode,
            WS_OPCODE_CLOSE | WS_OPCODE_PING | WS_OPCODE_PONG
        );
        if is_control {
            if !fin || payload.len() > WS_MAX_CONTROL_PAYLOAD {
                return Err(WsError::BadControlFrame);
            }
            return Ok(Some(self.build_control(opcode, payload)));
        }

        match opcode {
            WS_OPCODE_TEXT => Err(WsError::TextFrame),
            WS_OPCODE_BINARY => {
                if self.in_fragment {
                    // RFC 6455 §5.4: a new data frame arriving while a
                    // fragmented one is in progress is a protocol error.
                    return Err(WsError::BadControlFrame);
                }
                if fin {
                    Ok(Some(WsFrame::Binary(payload)))
                } else {
                    self.in_fragment = true;
                    self.append_fragment(&payload)?;
                    // Wait for the next frame.
                    self.try_parse_one()
                }
            }
            WS_OPCODE_CONTINUATION => {
                if !self.in_fragment {
                    return Err(WsError::BadControlFrame);
                }
                self.append_fragment(&payload)?;
                if fin {
                    self.in_fragment = false;
                    let done = core::mem::take(&mut self.fragmented);
                    Ok(Some(WsFrame::Binary(done)))
                } else {
                    // Still building — keep going.
                    self.try_parse_one()
                }
            }
            other => Err(WsError::UnsupportedOpcode(other)),
        }
    }

    fn append_fragment(&mut self, chunk: &[u8]) -> Result<(), WsError> {
        let new_len = self.fragmented.len() + chunk.len();
        if new_len > self.max_message {
            return Err(WsError::FrameTooLarge(new_len));
        }
        self.fragmented.extend_from_slice(chunk);
        Ok(())
    }

    fn build_control(&self, opcode: u8, payload: Vec<u8>) -> WsFrame {
        match opcode {
            WS_OPCODE_PING => WsFrame::Ping(payload),
            WS_OPCODE_PONG => WsFrame::Pong(payload),
            WS_OPCODE_CLOSE => {
                if payload.len() >= 2 {
                    let code = u16::from_be_bytes([payload[0], payload[1]]);
                    WsFrame::Close {
                        code: Some(code),
                        reason: payload[2..].to_vec(),
                    }
                } else {
                    WsFrame::Close {
                        code: None,
                        reason: Vec::new(),
                    }
                }
            }
            _ => unreachable!("build_control called for non-control opcode"),
        }
    }
}

impl Default for WsFrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the payload of a Close frame: 2-byte big-endian status code
/// (if present) followed by the UTF-8 reason. Empty reason allowed.
pub fn encode_close_payload(code: Option<u16>, reason: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(c) = code {
        out.extend_from_slice(&c.to_be_bytes());
        out.extend_from_slice(reason.as_bytes());
    }
    out
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // ── Sec-WebSocket-Accept ──

    #[test]
    fn ws_accept_key_rfc6455_example() {
        // RFC 6455 §1.3 worked example.
        let got = ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(got, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    // ── Upgrade request ──

    #[test]
    fn ws_upgrade_request_contains_required_headers() {
        let req = WsUpgradeRequest::new("gw.example.com", [0x11; 16], "dGVzdGtleXRlc3RrZXkxMjM=");
        let bytes = req.to_bytes();
        let s = core::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("GET /remoteDesktopGateway/ HTTP/1.1\r\n"));
        assert!(s.contains("Upgrade: websocket\r\n"));
        assert!(s.contains("Connection: Upgrade\r\n"));
        assert!(s.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(s.contains("Sec-WebSocket-Key: dGVzdGtleXRlc3RrZXkxMjM=\r\n"));
        assert!(s.contains("Host: gw.example.com\r\n"));
        assert!(s.contains("RDG-Connection-Id: {11111111-1111-1111-1111-111111111111}\r\n"));
        assert!(!s.contains("Transfer-Encoding"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn ws_upgrade_request_optional_auth_and_subprotocol() {
        let mut req = WsUpgradeRequest::new("gw", [0; 16], "k");
        req.authorization = Some("SSPI_NTLM Zm9v".into());
        req.sec_websocket_protocol = Some("RDG_Websocket".into());
        let s = String::from_utf8(req.to_bytes()).unwrap();
        assert!(s.contains("Authorization: SSPI_NTLM Zm9v\r\n"));
        assert!(s.contains("Sec-WebSocket-Protocol: RDG_Websocket\r\n"));
    }

    // ── encode_frame ──

    #[test]
    fn encode_binary_short_length() {
        // FIN + Binary, payload = "Hi" (2 bytes), mask = 0,0,0,0 → unchanged.
        let mut out = Vec::new();
        encode_frame(WS_OPCODE_BINARY, true, b"Hi", [0; 4], &mut out).unwrap();
        assert_eq!(out[0], 0x82); // FIN + binary
        assert_eq!(out[1], 0x80 | 2); // mask + len 2
        assert_eq!(&out[2..6], &[0, 0, 0, 0]); // mask
        assert_eq!(&out[6..], b"Hi"); // unmasked because key is 0
    }

    #[test]
    fn encode_masking_xors_payload() {
        // RFC 6455 §5.3 known-good vector.
        let mut out = Vec::new();
        encode_frame(
            WS_OPCODE_BINARY,
            true,
            &[0x48, 0x65, 0x6c, 0x6c],
            [0x37, 0xfa, 0x21, 0x3d],
            &mut out,
        )
        .unwrap();
        // Header: 0x82, 0x84, then 4-byte mask, then masked payload.
        assert_eq!(&out[0..2], &[0x82, 0x84]);
        assert_eq!(&out[2..6], &[0x37, 0xfa, 0x21, 0x3d]);
        assert_eq!(&out[6..10], &[0x7f, 0x9f, 0x4d, 0x51]);
    }

    #[test]
    fn encode_medium_length_variant() {
        let payload = vec![0xAAu8; 200];
        let mut out = Vec::new();
        encode_frame(WS_OPCODE_BINARY, true, &payload, [0, 0, 0, 0], &mut out).unwrap();
        assert_eq!(out[0], 0x82);
        assert_eq!(out[1], 0x80 | 126);
        assert_eq!(&out[2..4], &200u16.to_be_bytes());
    }

    #[test]
    fn encode_large_length_variant() {
        let payload = vec![0u8; 70_000];
        let mut out = Vec::new();
        encode_frame(WS_OPCODE_BINARY, true, &payload, [0, 0, 0, 0], &mut out).unwrap();
        assert_eq!(out[0], 0x82);
        assert_eq!(out[1], 0x80 | 127);
        assert_eq!(&out[2..10], &70_000u64.to_be_bytes());
    }

    #[test]
    fn encode_rejects_text_opcode() {
        let err = encode_frame(WS_OPCODE_TEXT, true, b"", [0; 4], &mut Vec::new()).unwrap_err();
        assert_eq!(err, WsError::TextFrame);
    }

    #[test]
    fn encode_rejects_oversized_control_frame() {
        let err = encode_frame(
            WS_OPCODE_PING,
            true,
            &[0u8; 126],
            [0; 4],
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(err, WsError::BadControlFrame);
    }

    #[test]
    fn encode_rejects_fragmented_control_frame() {
        let err = encode_frame(WS_OPCODE_PING, false, b"", [0; 4], &mut Vec::new()).unwrap_err();
        assert_eq!(err, WsError::BadControlFrame);
    }

    // ── WsFrameDecoder ──

    /// Helper to build a server-to-client frame (unmasked) for test input.
    fn server_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push((if fin { 0x80 } else { 0 }) | (opcode & 0x0F));
        let len = payload.len();
        if len <= 125 {
            out.push(len as u8);
        } else if len <= u16::MAX as usize {
            out.push(126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn decode_single_binary_frame() {
        let mut d = WsFrameDecoder::new();
        let frames = d.feed(&server_frame(WS_OPCODE_BINARY, true, b"hello")).unwrap();
        assert_eq!(frames, vec![WsFrame::Binary(b"hello".to_vec())]);
    }

    #[test]
    fn decode_fragmented_binary_reassembled_on_fin() {
        let mut d = WsFrameDecoder::new();
        let mut input = Vec::new();
        input.extend(server_frame(WS_OPCODE_BINARY, false, b"foo"));
        input.extend(server_frame(WS_OPCODE_CONTINUATION, false, b"bar"));
        input.extend(server_frame(WS_OPCODE_CONTINUATION, true, b"baz"));
        let frames = d.feed(&input).unwrap();
        assert_eq!(frames, vec![WsFrame::Binary(b"foobarbaz".to_vec())]);
    }

    #[test]
    fn decode_ping_interleaved_among_fragments() {
        // Some gateways like to sprinkle control frames between data
        // fragments. The decoder must deliver the Ping immediately
        // without disturbing the in-progress reassembly buffer.
        let mut d = WsFrameDecoder::new();
        let mut input = Vec::new();
        input.extend(server_frame(WS_OPCODE_BINARY, false, b"AB"));
        input.extend(server_frame(WS_OPCODE_PING, true, b"ping"));
        input.extend(server_frame(WS_OPCODE_CONTINUATION, true, b"CD"));
        let frames = d.feed(&input).unwrap();
        assert_eq!(
            frames,
            vec![
                WsFrame::Ping(b"ping".to_vec()),
                WsFrame::Binary(b"ABCD".to_vec()),
            ]
        );
    }

    #[test]
    fn decode_close_with_status_code() {
        let mut d = WsFrameDecoder::new();
        let payload = [0x03, 0xE8, b'b', b'y', b'e']; // 1000 + "bye"
        let frames = d.feed(&server_frame(WS_OPCODE_CLOSE, true, &payload)).unwrap();
        assert_eq!(
            frames,
            vec![WsFrame::Close {
                code: Some(1000),
                reason: b"bye".to_vec()
            }]
        );
    }

    #[test]
    fn decode_close_without_payload() {
        let mut d = WsFrameDecoder::new();
        let frames = d.feed(&server_frame(WS_OPCODE_CLOSE, true, &[])).unwrap();
        assert_eq!(
            frames,
            vec![WsFrame::Close {
                code: None,
                reason: Vec::new()
            }]
        );
    }

    #[test]
    fn decode_partial_header_waits_for_more_bytes() {
        let mut d = WsFrameDecoder::new();
        // Short-form header split across two feed() calls.
        let frames = d.feed(&[0x82]).unwrap();
        assert!(frames.is_empty());
        let frames = d.feed(&[0x03, b'x', b'y', b'z']).unwrap();
        assert_eq!(frames, vec![WsFrame::Binary(b"xyz".to_vec())]);
    }

    #[test]
    fn decode_medium_length_split_feeds() {
        let mut d = WsFrameDecoder::new();
        // 200-byte payload → forces the 126/u16 variant.
        let payload = vec![0xAA; 200];
        let mut frame = vec![0x82u8, 0x7E];
        frame.extend_from_slice(&200u16.to_be_bytes());
        frame.extend_from_slice(&payload);

        // Feed header + 50 bytes, then the remaining 150.
        let got = d.feed(&frame[..54]).unwrap();
        assert!(got.is_empty());
        let got = d.feed(&frame[54..]).unwrap();
        assert_eq!(got, vec![WsFrame::Binary(payload)]);
    }

    #[test]
    fn decode_rejects_masked_server_frame() {
        let mut d = WsFrameDecoder::new();
        // FIN + Binary + MASK + len 0
        let err = d.feed(&[0x82, 0x80, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, WsError::MaskedServerFrame);
    }

    #[test]
    fn decode_rejects_reserved_bits() {
        let mut d = WsFrameDecoder::new();
        // RSV1 set
        let err = d.feed(&[0xC2, 0x00]).unwrap_err();
        assert_eq!(err, WsError::ReservedBitsSet);
    }

    #[test]
    fn decode_rejects_non_minimal_length_16() {
        let mut d = WsFrameDecoder::new();
        // 126 extended-length variant but with payload = 5 (should have used short form)
        let err = d.feed(&[0x82, 0x7E, 0x00, 0x05, 0, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, WsError::NonMinimalLength);
    }

    #[test]
    fn decode_rejects_text_frame() {
        let mut d = WsFrameDecoder::new();
        let err = d.feed(&server_frame(WS_OPCODE_TEXT, true, b"hi")).unwrap_err();
        assert_eq!(err, WsError::TextFrame);
    }

    #[test]
    fn decode_rejects_continuation_without_initial() {
        let mut d = WsFrameDecoder::new();
        let err = d
            .feed(&server_frame(WS_OPCODE_CONTINUATION, true, b"x"))
            .unwrap_err();
        assert_eq!(err, WsError::BadControlFrame);
    }

    #[test]
    fn decode_rejects_oversized_control_payload() {
        let mut d = WsFrameDecoder::new();
        let err = d
            .feed(&server_frame(WS_OPCODE_PING, true, &[0u8; 126]))
            .unwrap_err();
        assert_eq!(err, WsError::BadControlFrame);
    }

    // ── encode_close_payload ──

    #[test]
    fn encode_close_payload_with_code_and_reason() {
        let p = encode_close_payload(Some(WS_CLOSE_NORMAL), "bye");
        assert_eq!(p, vec![0x03, 0xE8, b'b', b'y', b'e']);
    }

    #[test]
    fn encode_close_payload_empty() {
        let p = encode_close_payload(None, "");
        assert!(p.is_empty());
    }
}
