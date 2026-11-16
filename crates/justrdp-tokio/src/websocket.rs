//! The WebSocket client the RD Gateway transport rides (RFC 6455): the upgrade request, the
//! check of the server's 101 response, and the frame reader and writer. No extension and no
//! subprotocol is offered.
//!
//! [`FrameDecoder`] reads the server's frames from bytes in any split. Payload of binary frames
//! goes to the caller as it arrives, so a frame of any length is never held whole.

/// The GUID a server appends to the key before hashing it (RFC 6455 section 1.3).
const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The most bytes of an upgrade response read while looking for the end of its header.
pub const MAX_UPGRADE_RESPONSE_LEN: usize = 16 * 1024;

/// The longest payload a control frame carries (RFC 6455 section 5.5).
const MAX_CONTROL_PAYLOAD: u8 = 125;

/// The opcode of a continuation frame.
const OPCODE_CONTINUATION: u8 = 0x0;
/// The opcode of a text frame.
const OPCODE_TEXT: u8 = 0x1;
/// The opcode of a binary frame.
pub const OPCODE_BINARY: u8 = 0x2;
/// The opcode of a close frame.
pub const OPCODE_CLOSE: u8 = 0x8;
/// The opcode of a ping frame.
const OPCODE_PING: u8 = 0x9;
/// The opcode of a pong frame.
pub const OPCODE_PONG: u8 = 0xA;

/// `bytes` in base64 with padding (RFC 4648 section 4).
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = u32::from(chunk[0]) << 16
            | u32::from(chunk.get(1).copied().unwrap_or(0)) << 8
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        for position in 0..4 {
            if position <= chunk.len() {
                let index = (group >> (18 - 6 * position)) & 0x3F;
                out.push(char::from(ALPHABET[index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The `Sec-WebSocket-Accept` value a server derives from `key` (RFC 6455 section 4.2.2).
pub fn accept_for(key: &str) -> String {
    let mut context = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(key.as_bytes());
    context.update(ACCEPT_GUID.as_bytes());
    base64(context.finish().as_ref())
}

/// The RD Gateway's WebSocket upgrade request for PAA (MS-TSGU 3.3.5.1): the `RDG_OUT_DATA`
/// method on `/remoteDesktopGateway/`, accepting `*/*` and disallowing caching, with
/// `RDG-Auth-Scheme: PAA` and no `Authorization`.
/// `host` is the `Host` header's value, `key` the `Sec-WebSocket-Key`, and `connection_id` the
/// GUID of `RDG-Connection-Id`, without braces.
pub fn upgrade_request(host: &str, key: &str, connection_id: &str) -> Vec<u8> {
    format!(
        "RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n\
         Host: {host}\r\n\
         Accept: */*\r\n\
         Cache-Control: no-cache\r\n\
         Pragma: no-cache\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         RDG-Connection-Id: {{{connection_id}}}\r\n\
         RDG-Auth-Scheme: PAA\r\n\
         \r\n"
    )
    .into_bytes()
}

/// Why a server's answer to the upgrade request is not a WebSocket upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeError {
    /// No end of header within the first 16 KiB.
    TooLong,
    /// The bytes do not start with an HTTP/1.x status line.
    NotHttp,
    /// The server answered with a status other than 101.
    Status(u16),
    /// A 101 response that RFC 6455 section 4.1 does not admit.
    NotWebSocket(&'static str),
}

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpgradeError::TooLong => write!(
                f,
                "the response header is longer than {MAX_UPGRADE_RESPONSE_LEN} bytes"
            ),
            UpgradeError::NotHttp => f.write_str("the response is not HTTP"),
            UpgradeError::Status(status) => write!(f, "the server answered HTTP {status}"),
            UpgradeError::NotWebSocket(reason) => {
                write!(f, "the 101 response is not a WebSocket upgrade: {reason}")
            }
        }
    }
}

impl std::error::Error for UpgradeError {}

/// Check the server's answer to the upgrade request at the front of `buf`. `Ok(None)` means the
/// header has not ended yet; `Ok(Some(n))` means a valid upgrade whose header is the first `n`
/// bytes, so WebSocket frames start at `buf[n..]`. `expected_accept` is `accept_for` the key
/// that was sent.
pub fn parse_upgrade_response(
    buf: &[u8],
    expected_accept: &str,
) -> Result<Option<usize>, UpgradeError> {
    let window = &buf[..buf.len().min(MAX_UPGRADE_RESPONSE_LEN)];
    let Some(end) = window.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() >= MAX_UPGRADE_RESPONSE_LEN {
            Err(UpgradeError::TooLong)
        } else {
            Ok(None)
        };
    };
    let mut lines = buf[..end]
        .split(|b| *b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let status = lines
        .next()
        .and_then(parse_status_line)
        .ok_or(UpgradeError::NotHttp)?;
    if status != 101 {
        return Err(UpgradeError::Status(status));
    }

    let mut upgrade = false;
    let mut connection = false;
    let mut accept = false;
    for line in lines {
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = line[colon + 1..].trim_ascii();
        if name.eq_ignore_ascii_case(b"Upgrade") {
            upgrade |= value.eq_ignore_ascii_case(b"websocket");
        } else if name.eq_ignore_ascii_case(b"Connection") {
            connection |= value
                .split(|b| *b == b',')
                .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"upgrade"));
        } else if name.eq_ignore_ascii_case(b"Sec-WebSocket-Accept") {
            if value != expected_accept.as_bytes() {
                return Err(UpgradeError::NotWebSocket(
                    "Sec-WebSocket-Accept does not match the key",
                ));
            }
            accept = true;
        } else if name.eq_ignore_ascii_case(b"Sec-WebSocket-Extensions") {
            return Err(UpgradeError::NotWebSocket(
                "the server selected an extension that was not offered",
            ));
        } else if name.eq_ignore_ascii_case(b"Sec-WebSocket-Protocol") {
            return Err(UpgradeError::NotWebSocket(
                "the server selected a subprotocol that was not offered",
            ));
        }
    }
    if !upgrade {
        return Err(UpgradeError::NotWebSocket("no Upgrade: websocket header"));
    }
    if !connection {
        return Err(UpgradeError::NotWebSocket("no Connection: Upgrade header"));
    }
    if !accept {
        return Err(UpgradeError::NotWebSocket("no Sec-WebSocket-Accept header"));
    }
    Ok(Some(end + 4))
}

/// The status code of an `HTTP/1.x` status line.
fn parse_status_line(line: &[u8]) -> Option<u16> {
    let rest = line.strip_prefix(b"HTTP/1.")?;
    let (version, rest) = rest.split_first()?;
    if !version.is_ascii_digit() {
        return None;
    }
    let rest = rest.strip_prefix(b" ")?;
    let code = rest.get(..3)?;
    if !code.iter().all(u8::is_ascii_digit) || rest.get(3).is_some_and(|b| *b != b' ') {
        return None;
    }
    Some(
        code.iter()
            .fold(0u16, |acc, digit| acc * 10 + u16::from(digit - b'0')),
    )
}

/// Append one final frame with `opcode` and `payload`, masked with `mask` as every client frame
/// is (RFC 6455 section 5.3).
pub fn encode_frame(opcode: u8, payload: &[u8], mask: [u8; 4], out: &mut Vec<u8>) {
    out.reserve(payload.len() + 14);
    out.push(0x80 | opcode);
    match payload.len() {
        len @ 0..=125 => out.push(0x80 | len as u8),
        len @ 126..=0xFFFF => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(&mask);
    out.extend(
        payload
            .iter()
            .zip(mask.iter().cycle())
            .map(|(byte, key)| byte ^ key),
    );
}

/// A control frame the server sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// A ping, with the payload the pong echoes.
    Ping(Vec<u8>),
    /// A close frame. [`FrameDecoder`] reads nothing after it.
    Close,
}

/// A frame RFC 6455 does not admit from a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// A reserved bit is set, and no extension was negotiated (section 5.2).
    ReservedBits,
    /// The frame is masked; a server's frames are not (section 5.1).
    Masked,
    /// A reserved opcode (section 5.2).
    ReservedOpcode(u8),
    /// A control frame that is fragmented or longer than 125 bytes (section 5.5).
    BadControlFrame,
    /// A continuation frame with no message to continue, or a new message inside an unfinished
    /// one (section 5.4).
    BadFragmentation,
    /// A 64-bit payload length with its top bit set (section 5.2).
    LengthOutOfRange,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::ReservedBits => f.write_str("a WebSocket frame sets a reserved bit"),
            FrameError::Masked => f.write_str("the server sent a masked WebSocket frame"),
            FrameError::ReservedOpcode(opcode) => {
                write!(f, "a WebSocket frame has the reserved opcode {opcode:#x}")
            }
            FrameError::BadControlFrame => {
                f.write_str("a WebSocket control frame is fragmented or over 125 bytes")
            }
            FrameError::BadFragmentation => {
                f.write_str("a WebSocket message is fragmented out of order")
            }
            FrameError::LengthOutOfRange => {
                f.write_str("a WebSocket frame length has its top bit set")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Where a frame's payload goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sink {
    /// A binary message: to the caller.
    Data,
    /// A text message or a pong: nowhere.
    Dropped,
    /// A ping or a close: into the control buffer.
    Control(u8),
}

/// The server's WebSocket frames, read from bytes in any split.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    /// The header bytes of the frame being read: two, then the extended length.
    header: [u8; 10],
    header_len: usize,
    /// The payload bytes still to come of the frame being read, and where they go.
    payload: Option<(u64, Sink)>,
    /// The sink of the fragmented data message in progress.
    message: Option<Sink>,
    /// The payload of the control frame being read.
    control: Vec<u8>,
    closed: bool,
    /// The error that ended the stream; every later call returns it.
    failed: Option<FrameError>,
}

impl FrameDecoder {
    /// A decoder at the start of the frame stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read `input`: the payload of binary messages is appended to `data`, and each ping or
    /// close to `control`. Bytes after a close frame are not read. After an error nothing more
    /// is read, and every call returns that error.
    pub fn feed(
        &mut self,
        mut input: &[u8],
        data: &mut Vec<u8>,
        control: &mut Vec<Control>,
    ) -> Result<(), FrameError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        while !self.closed && !input.is_empty() {
            let Some((remaining, sink)) = self.payload else {
                input = match self.read_header(input) {
                    Ok(rest) => rest,
                    Err(error) => {
                        self.failed = Some(error);
                        return Err(error);
                    }
                };
                if let Some((0, sink)) = self.payload {
                    self.finish_frame(sink, control);
                }
                continue;
            };
            let take = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(input.len());
            let (chunk, rest) = input.split_at(take);
            match sink {
                Sink::Data => data.extend_from_slice(chunk),
                Sink::Dropped => {}
                Sink::Control(_) => self.control.extend_from_slice(chunk),
            }
            input = rest;
            let remaining = remaining - take as u64;
            self.payload = Some((remaining, sink));
            if remaining == 0 {
                self.finish_frame(sink, control);
            }
        }
        Ok(())
    }

    /// Take header bytes from the front of `input`, and once the header is whole set
    /// `self.payload`. Returns the input after the bytes taken.
    fn read_header<'a>(&mut self, mut input: &'a [u8]) -> Result<&'a [u8], FrameError> {
        while let Some((byte, rest)) = input.split_first() {
            self.header[self.header_len] = *byte;
            self.header_len += 1;
            input = rest;

            if self.header_len == 1 && self.header[0] & 0x70 != 0 {
                return Err(FrameError::ReservedBits);
            }
            if self.header_len < 2 {
                continue;
            }
            if self.header[1] & 0x80 != 0 {
                return Err(FrameError::Masked);
            }
            let len7 = self.header[1] & 0x7F;
            let extended = match len7 {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            if self.header_len < 2 + extended {
                continue;
            }
            let len = match extended {
                0 => u64::from(len7),
                2 => u64::from(u16::from_be_bytes([self.header[2], self.header[3]])),
                _ => {
                    let mut be = [0u8; 8];
                    be.copy_from_slice(&self.header[2..10]);
                    u64::from_be_bytes(be)
                }
            };
            if len >> 63 != 0 {
                return Err(FrameError::LengthOutOfRange);
            }
            let fin = self.header[0] & 0x80 != 0;
            let opcode = self.header[0] & 0x0F;
            let sink = self.sink_for(opcode, fin, len7)?;
            self.header_len = 0;
            self.payload = Some((len, sink));
            break;
        }
        Ok(input)
    }

    /// Where the payload of a frame with this header goes, tracking message fragmentation.
    fn sink_for(&mut self, opcode: u8, fin: bool, len7: u8) -> Result<Sink, FrameError> {
        if opcode & 0x8 != 0 {
            if !fin || len7 > MAX_CONTROL_PAYLOAD {
                return Err(FrameError::BadControlFrame);
            }
            return match opcode {
                OPCODE_CLOSE | OPCODE_PING => Ok(Sink::Control(opcode)),
                OPCODE_PONG => Ok(Sink::Dropped),
                _ => Err(FrameError::ReservedOpcode(opcode)),
            };
        }
        let sink = match (opcode, self.message) {
            (OPCODE_CONTINUATION, Some(sink)) => sink,
            (OPCODE_BINARY, None) => Sink::Data,
            (OPCODE_TEXT, None) => {
                tracing::debug!("dropping a WebSocket text message from the RD Gateway");
                Sink::Dropped
            }
            (OPCODE_CONTINUATION | OPCODE_BINARY | OPCODE_TEXT, _) => {
                return Err(FrameError::BadFragmentation);
            }
            _ => return Err(FrameError::ReservedOpcode(opcode)),
        };
        self.message = (!fin).then_some(sink);
        Ok(sink)
    }

    /// The frame's last payload byte was read.
    fn finish_frame(&mut self, sink: Sink, control: &mut Vec<Control>) {
        self.payload = None;
        match sink {
            Sink::Control(OPCODE_PING) => {
                control.push(Control::Ping(std::mem::take(&mut self.control)));
            }
            Sink::Control(_) => {
                self.control.clear();
                self.closed = true;
                control.push(Control::Close);
            }
            Sink::Data | Sink::Dropped => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// RFC 4648 section 10.
    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        let vectors = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in vectors {
            assert_eq!(base64(plain.as_bytes()), encoded);
        }
        assert_eq!(base64(&[0xFB, 0xFF, 0xFE]), "+//+");
    }

    /// RFC 6455 section 1.3's worked example.
    #[test]
    fn accept_matches_the_rfc_6455_example() {
        assert_eq!(
            accept_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// The request mstsc sends for PAA (#613): the `RDG_OUT_DATA` method, the WebSocket
    /// upgrade, `RDG-Auth-Scheme: PAA`, and no `Authorization` header. MS-TSGU 3.3.5.1 adds the
    /// accept type and the two headers that disallow caching.
    #[test]
    fn the_upgrade_request_is_rdg_out_data_with_the_paa_scheme() {
        let request = upgrade_request(
            "gw.example",
            "dGhlIHNhbXBsZSBub25jZQ==",
            "0f8fad5b-d9cb-469f-a165-70867728950e",
        );
        assert_eq!(
            String::from_utf8(request).unwrap(),
            "RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n\
             Host: gw.example\r\n\
             Accept: */*\r\n\
             Cache-Control: no-cache\r\n\
             Pragma: no-cache\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             RDG-Connection-Id: {0f8fad5b-d9cb-469f-a165-70867728950e}\r\n\
             RDG-Auth-Scheme: PAA\r\n\
             \r\n"
        );
    }

    const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    fn response(status_line: &str, headers: &[&str]) -> Vec<u8> {
        let mut text = format!("{status_line}\r\n");
        for header in headers {
            text.push_str(header);
            text.push_str("\r\n");
        }
        text.push_str("\r\n");
        text.into_bytes()
    }

    const SWITCHING: &str = "HTTP/1.1 101 Switching Protocols";
    const UPGRADE_HEADERS: [&str; 3] = [
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
    ];

    #[test]
    fn a_101_with_the_matching_accept_is_an_upgrade_and_frames_follow_its_header() {
        let mut bytes = response(SWITCHING, &UPGRADE_HEADERS);
        let header_len = bytes.len();
        bytes.extend([0x82, 0x01, 0xFF]);
        assert_eq!(parse_upgrade_response(&bytes, ACCEPT), Ok(Some(header_len)));
    }

    #[test]
    fn header_names_and_tokens_match_in_any_case_and_other_headers_are_passed_over() {
        let bytes = response(
            "HTTP/1.1 101 Switching Protocols",
            &[
                "Server: Microsoft-HTTPAPI/2.0",
                "UPGRADE:   WebSocket  ",
                "connection: keep-alive, UPGRADE",
                "sec-websocket-accept:s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
                "a line with no colon",
            ],
        );
        assert_eq!(
            parse_upgrade_response(&bytes, ACCEPT),
            Ok(Some(bytes.len()))
        );
    }

    #[test]
    fn a_response_whose_header_has_not_ended_asks_for_more() {
        let bytes = response(SWITCHING, &UPGRADE_HEADERS);
        for cut in 0..bytes.len() {
            assert_eq!(parse_upgrade_response(&bytes[..cut], ACCEPT), Ok(None));
        }
    }

    #[test]
    fn a_status_other_than_101_is_reported_with_its_code() {
        let bytes = response(
            "HTTP/1.1 401 Unauthorized",
            &["WWW-Authenticate: Negotiate"],
        );
        assert_eq!(
            parse_upgrade_response(&bytes, ACCEPT),
            Err(UpgradeError::Status(401))
        );
    }

    #[test]
    fn bytes_that_are_not_an_http_status_line_are_refused() {
        for status_line in [
            "",
            "HTTP/2 101",
            "HTTP/1.1 10",
            "HTTP/1.1 1010 x",
            "SSH-2.0",
        ] {
            assert_eq!(
                parse_upgrade_response(&response(status_line, &UPGRADE_HEADERS), ACCEPT),
                Err(UpgradeError::NotHttp),
                "{status_line:?}"
            );
        }
    }

    #[test]
    fn a_101_missing_any_upgrade_header_or_with_a_wrong_accept_is_refused() {
        let cases: [(&[&str], &str); 6] = [
            (
                &["Connection: Upgrade", UPGRADE_HEADERS[2]],
                "no Upgrade: websocket header",
            ),
            (
                &["Upgrade: websocket", UPGRADE_HEADERS[2]],
                "no Connection: Upgrade header",
            ),
            (
                &["Upgrade: websocket", "Connection: Upgrade"],
                "no Sec-WebSocket-Accept header",
            ),
            (
                &[
                    "Upgrade: websocket",
                    "Connection: Upgrade",
                    "Sec-WebSocket-Accept: S3PPLMBITXAQ9KYGZZHZRBK+XOO=",
                ],
                "Sec-WebSocket-Accept does not match the key",
            ),
            (
                &[
                    UPGRADE_HEADERS[0],
                    UPGRADE_HEADERS[1],
                    UPGRADE_HEADERS[2],
                    "Sec-WebSocket-Extensions: permessage-deflate",
                ],
                "the server selected an extension that was not offered",
            ),
            (
                &[
                    UPGRADE_HEADERS[0],
                    UPGRADE_HEADERS[1],
                    UPGRADE_HEADERS[2],
                    "Sec-WebSocket-Protocol: chat",
                ],
                "the server selected a subprotocol that was not offered",
            ),
        ];
        for (headers, reason) in cases {
            assert_eq!(
                parse_upgrade_response(&response(SWITCHING, headers), ACCEPT),
                Err(UpgradeError::NotWebSocket(reason))
            );
        }
    }

    #[test]
    fn a_header_that_never_ends_is_refused_at_the_limit() {
        let mut bytes = b"HTTP/1.1 101 Switching Protocols\r\nX: ".to_vec();
        bytes.resize(MAX_UPGRADE_RESPONSE_LEN - 1, b'a');
        assert_eq!(parse_upgrade_response(&bytes, ACCEPT), Ok(None));
        bytes.push(b'a');
        assert_eq!(
            parse_upgrade_response(&bytes, ACCEPT),
            Err(UpgradeError::TooLong)
        );
        // An end of header past the limit does not count.
        bytes.extend(b"\r\n\r\n");
        assert_eq!(
            parse_upgrade_response(&bytes, ACCEPT),
            Err(UpgradeError::TooLong)
        );
    }

    /// RFC 6455 section 5.7: "A single-frame masked text message" containing "Hello".
    #[test]
    fn a_client_frame_is_masked_as_the_rfc_example() {
        let mut out = Vec::new();
        encode_frame(OPCODE_TEXT, b"Hello", [0x37, 0xFA, 0x21, 0x3D], &mut out);
        assert_eq!(
            out,
            [
                0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58
            ]
        );
    }

    /// RFC 6455 section 5.7's length forms: 256 bytes behind `0x7E 0x0100`, and 65536 bytes
    /// behind `0x7F 0x0000000000010000`.
    #[test]
    fn a_client_frame_uses_the_length_form_its_payload_needs() {
        let mut out = Vec::new();
        encode_frame(OPCODE_BINARY, &[0; 125], [0; 4], &mut out);
        assert_eq!(out[..2], [0x82, 0x80 | 125]);
        assert_eq!(out.len(), 2 + 4 + 125);

        out.clear();
        encode_frame(OPCODE_BINARY, &[0; 256], [0; 4], &mut out);
        assert_eq!(out[..4], [0x82, 0x80 | 0x7E, 0x01, 0x00]);
        assert_eq!(out.len(), 4 + 4 + 256);

        out.clear();
        encode_frame(OPCODE_BINARY, &[0; 65536], [0; 4], &mut out);
        assert_eq!(out[..10], [0x82, 0x80 | 0x7F, 0, 0, 0, 0, 0, 1, 0, 0]);
        assert_eq!(out.len(), 10 + 4 + 65536);
    }

    /// Feed `input` whole and return what came out.
    fn decode(input: &[u8]) -> Result<(Vec<u8>, Vec<Control>), FrameError> {
        let mut decoder = FrameDecoder::new();
        let mut data = Vec::new();
        let mut control = Vec::new();
        decoder.feed(input, &mut data, &mut control)?;
        Ok((data, control))
    }

    /// RFC 6455 section 5.7's unmasked "Hello" frame, as a binary frame.
    #[test]
    fn a_binary_frame_yields_its_payload() {
        let frame = [0x82, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F];
        assert_eq!(decode(&frame), Ok((b"Hello".to_vec(), vec![])));
    }

    /// RFC 6455 section 5.7: "A fragmented unmasked text message", as a binary message.
    #[test]
    fn a_fragmented_binary_message_yields_every_fragment() {
        let frames = [0x02, 0x03, 0x48, 0x65, 0x6C, 0x80, 0x02, 0x6C, 0x6F];
        assert_eq!(decode(&frames), Ok((b"Hello".to_vec(), vec![])));
    }

    #[test]
    fn the_extended_length_forms_are_read() {
        let mut frame = vec![0x82, 0x7E, 0x01, 0x00];
        frame.extend([7; 256]);
        assert_eq!(decode(&frame), Ok((vec![7; 256], vec![])));

        let mut frame = vec![0x82, 0x7F, 0, 0, 0, 0, 0, 1, 0, 0];
        frame.extend([9; 65536]);
        assert_eq!(decode(&frame), Ok((vec![9; 65536], vec![])));
    }

    /// RFC 6455 section 5.7's unmasked ping, between the fragments of a message (section 5.4
    /// allows control frames there).
    #[test]
    fn a_ping_between_fragments_is_reported_and_the_message_continues() {
        let frames = [
            0x02, 0x03, 0x48, 0x65, 0x6C, // first fragment
            0x89, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F, // ping "Hello"
            0x8A, 0x01, 0xEE, // pong, dropped
            0x80, 0x02, 0x6C, 0x6F, // last fragment
        ];
        assert_eq!(
            decode(&frames),
            Ok((b"Hello".to_vec(), vec![Control::Ping(b"Hello".to_vec())]))
        );
    }

    #[test]
    fn an_empty_ping_is_reported_with_an_empty_payload() {
        assert_eq!(
            decode(&[0x89, 0x00, 0x82, 0x01, 0x55]),
            Ok((vec![0x55], vec![Control::Ping(vec![])]))
        );
    }

    #[test]
    fn a_text_message_is_dropped() {
        let frames = [0x01, 0x02, b'a', b'b', 0x80, 0x01, b'c', 0x82, 0x01, 0x55];
        assert_eq!(decode(&frames), Ok((vec![0x55], vec![])));
    }

    #[test]
    fn nothing_is_read_after_a_close_frame() {
        let frames = [0x88, 0x02, 0x03, 0xE8, 0x82, 0x01, 0x55, 0xFF, 0xFF];
        assert_eq!(decode(&frames), Ok((vec![], vec![Control::Close])));

        let mut decoder = FrameDecoder::new();
        let (mut data, mut control) = (Vec::new(), Vec::new());
        decoder
            .feed(&[0x88, 0x00], &mut data, &mut control)
            .unwrap();
        decoder.feed(&[0xFF; 8], &mut data, &mut control).unwrap();
        assert_eq!((data, control), (vec![], vec![Control::Close]));
    }

    /// A refused frame ends the stream: later bytes are not read as frames.
    #[test]
    fn nothing_is_read_after_a_refused_frame() {
        let mut decoder = FrameDecoder::new();
        let (mut data, mut control) = (Vec::new(), Vec::new());
        // The 64-bit length's top bit is refused once all ten header bytes are in.
        let refused = decoder.feed(
            &[0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0],
            &mut data,
            &mut control,
        );
        assert_eq!(refused, Err(FrameError::LengthOutOfRange));
        for _ in 0..3 {
            let again = decoder.feed(&[0x82, 0x01, 0x55], &mut data, &mut control);
            assert_eq!(again, Err(FrameError::LengthOutOfRange));
        }
        assert_eq!((data, control), (vec![], vec![]));
    }

    #[test]
    fn frames_a_server_may_not_send_are_refused() {
        let cases: [(&[u8], FrameError); 10] = [
            (&[0xC2, 0x00], FrameError::ReservedBits),
            (&[0x92], FrameError::ReservedBits),
            (&[0x82, 0x81, 1, 2, 3, 4, 5], FrameError::Masked),
            (&[0x83, 0x00], FrameError::ReservedOpcode(3)),
            (&[0x8B, 0x00], FrameError::ReservedOpcode(0xB)),
            (&[0x09, 0x00], FrameError::BadControlFrame),
            (&[0x89, 0x7E, 0x00, 0x7E], FrameError::BadControlFrame),
            (&[0x80, 0x00], FrameError::BadFragmentation),
            (&[0x02, 0x00, 0x82, 0x00], FrameError::BadFragmentation),
            (
                &[0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0],
                FrameError::LengthOutOfRange,
            ),
        ];
        for (frames, error) in cases {
            assert_eq!(decode(frames), Err(error), "{frames:02X?}");
        }
    }

    /// One server frame: mostly well formed, with every header field also drawn from its whole
    /// range so the refusals are reached, and lengths that do and do not match the payload.
    fn server_frame() -> impl Strategy<Value = Vec<u8>> {
        let first = prop_oneof![
            8 => prop_oneof![Just(0x82u8), Just(0x02), Just(0x80), Just(0x00), Just(0x89),
                Just(0x8A), Just(0x88), Just(0x81), Just(0x01)],
            1 => any::<u8>(),
        ];
        let length = prop_oneof![
            6 => (0u8..=125).prop_map(|len| vec![len]),
            1 => any::<u16>().prop_map(|len| {
                let mut bytes = vec![126];
                bytes.extend(len.to_be_bytes());
                bytes
            }),
            1 => (0u64..=512).prop_map(|len| {
                let mut bytes = vec![127];
                bytes.extend(len.to_be_bytes());
                bytes
            }),
            1 => any::<u64>().prop_map(|len| {
                let mut bytes = vec![127];
                bytes.extend(len.to_be_bytes());
                bytes
            }),
            1 => any::<u8>().prop_map(|byte| vec![byte]),
        ];
        (
            first,
            length,
            proptest::collection::vec(any::<u8>(), 0..=140),
            any::<bool>(),
        )
            .prop_map(|(first, length, mut payload, exact)| {
                if exact && length.len() == 1 {
                    payload.resize(usize::from(length[0] & 0x7F), 0xA5);
                }
                let mut frame = vec![first];
                frame.extend(length);
                frame.extend(payload);
                frame
            })
    }

    fn server_stream() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            4 => proptest::collection::vec(server_frame(), 0..=8).prop_map(|f| f.concat()),
            1 => proptest::collection::vec(any::<u8>(), 0..=256),
        ]
    }

    /// A response to the upgrade request: a valid one with lines replaced, bytes overwritten
    /// and the end cut, or arbitrary bytes.
    fn upgrade_response_bytes() -> impl Strategy<Value = Vec<u8>> {
        let line = prop_oneof![
            Just("Upgrade: websocket".to_string()),
            Just("Connection: Upgrade".to_string()),
            Just(format!("Sec-WebSocket-Accept: {ACCEPT}")),
            Just("Sec-WebSocket-Accept: AAAA".to_string()),
            Just("Sec-WebSocket-Extensions: x".to_string()),
            "[ -~]{0,40}",
        ];
        let status = prop_oneof![
            4 => Just(SWITCHING.to_string()),
            2 => r"HTTP/1\.[0-9a] ?[0-9]{0,4}[ -~]{0,3}",
            1 => "[ -~]{0,24}",
        ];
        let shaped = (
            status,
            proptest::collection::vec(line, 0..=6),
            proptest::option::of((any::<usize>(), any::<u8>())),
            proptest::option::of(any::<usize>()),
        )
            .prop_map(|(status, lines, overwrite, cut)| {
                let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
                let mut bytes = response(&status, &lines);
                if let Some((at, value)) = overwrite {
                    let at = at % bytes.len();
                    bytes[at] = value;
                }
                if let Some(cut) = cut {
                    bytes.truncate(cut % (bytes.len() + 1));
                }
                bytes
            });
        prop_oneof![
            4 => shaped,
            1 => proptest::collection::vec(any::<u8>(), 0..=256),
        ]
    }

    proptest! {
        // ADR-0008: the frames and the upgrade response are the gateway's bytes.
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// The frame reader never panics, and reads the same thing from a stream however the
        /// stream is split.
        #[test]
        fn feed_never_panics_and_does_not_depend_on_the_split(
            stream in server_stream(),
            cuts in proptest::collection::vec(any::<usize>(), 0..=6),
        ) {
            let whole = decode(&stream);

            let mut cuts: Vec<usize> = cuts.iter().map(|cut| cut % (stream.len() + 1)).collect();
            cuts.sort_unstable();
            let mut decoder = FrameDecoder::new();
            let (mut data, mut control) = (Vec::new(), Vec::new());
            let mut from = 0;
            let mut split = Ok(());
            for cut in cuts.into_iter().chain([stream.len()]) {
                split = decoder.feed(&stream[from..cut], &mut data, &mut control);
                if split.is_err() {
                    // A refused stream stays refused, whatever follows.
                    prop_assert_eq!(decoder.feed(&stream, &mut data, &mut control), split);
                    break;
                }
                from = cut;
            }
            prop_assert_eq!(split.map(|()| (data, control)), whole);
        }

        /// The response check never panics, and a header it accepts ends inside the buffer.
        #[test]
        fn parse_upgrade_response_never_panics(bytes in upgrade_response_bytes()) {
            if let Ok(Some(header_len)) = parse_upgrade_response(&bytes, ACCEPT) {
                prop_assert!(header_len <= bytes.len());
                prop_assert!(bytes[..header_len].ends_with(b"\r\n\r\n"));
            }
        }
    }
}
